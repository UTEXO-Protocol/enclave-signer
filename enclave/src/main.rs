// `TcpListener` is only used in dev mode (TCP fallback). Gating the import
// matches the `cfg(not(all(feature = "vsock", target_os = "linux")))` block
// at the bottom of `main` so the production-combo build (with vsock on
// Linux) doesn't emit an unused-import warning.
#[cfg(not(all(feature = "vsock", target_os = "linux")))]
use std::net::TcpListener;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::server::{self, ServerContext};
use utexo_bridge_enclave::spv::{checkpoint_for, HeaderChain, Network};
use utexo_bridge_enclave::state::EnclaveState;

/// Witness-resolver endpoint. `ELECTRUM_URL` (e.g. `ssl://host:50002`) is the
/// production path; `ESPLORA_URL` is the legacy REST fallback. Default targets
/// the legacy esplora forwarder port for backwards compatibility.
#[allow(dead_code)]
fn indexer_url_from_env() -> String {
    std::env::var("ELECTRUM_URL")
        .or_else(|_| std::env::var("ESPLORA_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:3443".into())
}

/// Map an indexer URL to (local forwarder listen port, optional hostname to pin
/// to loopback). For `ssl://host:port` / `tcp://host:port` we listen on the
/// URL's own port and return the host so it can be pinned to 127.0.0.1 (keeps
/// in-enclave TLS validating the real cert). For http(s)/legacy esplora we keep
/// the historical port 3443 and pin nothing.
#[cfg(all(feature = "vsock", target_os = "linux"))]
fn forwarder_target(url: &str) -> (u16, Option<String>) {
    for scheme in ["ssl://", "tcp://"] {
        if let Some(rest) = url.strip_prefix(scheme) {
            let hostport = rest.split('/').next().unwrap_or(rest);
            if let Some((host, port)) = hostport.rsplit_once(':') {
                if let Ok(p) = port.parse::<u16>() {
                    return (p, Some(host.to_string()));
                }
            }
        }
    }
    (3443, None)
}

/// Append `127.0.0.1 <host>` to /etc/hosts (idempotent) so the enclave's
/// outbound connection to `host` lands on the local vsock forwarder while the
/// TLS layer still validates against `host`'s real certificate.
#[cfg(all(feature = "vsock", target_os = "linux"))]
fn pin_host_to_loopback(host: &str) -> std::io::Result<()> {
    use std::io::Write;
    let existing = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    if existing
        .lines()
        .any(|l| l.split_whitespace().any(|tok| tok == host))
    {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/etc/hosts")?;
    writeln!(f, "127.0.0.1 {host}")
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("starting utexo-bridge-enclave");

    let bitcoin_network_str = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "bitcoin".into());
    let bitcoin_network = match bitcoin_network_str.as_str() {
        "bitcoin" | "mainnet" => bitcoin::Network::Bitcoin,
        "testnet" | "testnet3" => bitcoin::Network::Testnet,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
        other => {
            tracing::warn!("unknown BITCOIN_NETWORK '{other}', defaulting to mainnet");
            bitcoin::Network::Bitcoin
        }
    };
    tracing::info!(%bitcoin_network_str, "bitcoin network configured");

    let state = EnclaveState::new(bitcoin_network);

    // Pinned bridge config from env. Folded into the attestation `user_data`
    // commitment and cross-checked on every SignEvm. Production deployments
    // must set EVM_CHAIN_ID, BRIDGE_CONTRACT, RGB_ASSET_ID — a misconfigured
    // production enclave is detectable externally via the attestation bundle.
    let bridge_config = BridgeConfig::from_env();
    if bridge_config.is_configured() {
        tracing::info!(
            chain_id = bridge_config.chain_id,
            bridge_contract = %hex::encode(bridge_config.bridge_contract),
            rgb_asset_id = %bridge_config.rgb_asset_id,
            "bridge config pinned from env"
        );
    } else {
        tracing::warn!(
            "bridge config unconfigured (EVM_CHAIN_ID / BRIDGE_CONTRACT / RGB_ASSET_ID unset) — \
             SignEvm cross-check will fall back to legacy behaviour and the attestation bundle \
             will commit to empty values"
        );
    }

    // Donor-side cloning secret. Preferred delivery is at runtime via the
    // `InitializeKey` message (`cloning_secret`), so the secret never lands in
    // the EIF or the PCRs. The `UTEXO_CLONING_SECRET` env var is kept only as
    // a legacy/dev fallback and is NOT set by the production Dockerfile; do not
    // bake it into a release EIF. Never logged; wrapped in `SecretBox`.
    if let Ok(secret) = std::env::var("UTEXO_CLONING_SECRET") {
        if !secret.is_empty() {
            if let Err(e) = state.set_donor_cloning_secret(secret) {
                tracing::error!("failed to set donor cloning secret: {e}");
            } else {
                tracing::warn!(
                    "donor cloning secret configured from UTEXO_CLONING_SECRET env \
                     (legacy fallback; prefer the InitializeKey cloning_secret field)"
                );
            }
        }
    }

    // Start the vsock-to-TCP forwarder so the in-enclave witness resolver can
    // reach the host-side indexer. The host must run:
    //   vsock-proxy <ESPLORA_VSOCK_PORT> <indexer-host> <indexer-port>
    // We forward 127.0.0.1:<local_port> -> vsock:<vsock_port>. For an Electrum
    // ssl:// endpoint we listen on the URL's own port and pin its hostname to
    // 127.0.0.1 in /etc/hosts, so the TLS handshake terminates INSIDE the
    // enclave and validates the real server cert — the host relays ciphertext
    // only and cannot MITM the witness data.
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    {
        let vsock_port: u32 = std::env::var("ESPLORA_VSOCK_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8001);
        let (local_port, host_pin) = forwarder_target(&indexer_url_from_env());
        if let Some(host) = host_pin {
            match pin_host_to_loopback(&host) {
                Ok(()) => tracing::info!(
                    "pinned {host} -> 127.0.0.1 for in-enclave TLS over the vsock forwarder"
                ),
                Err(e) => tracing::error!("failed to pin {host} in /etc/hosts: {e}"),
            }
        }
        tracing::info!(
            local_port,
            vsock_port,
            "starting indexer vsock forwarder (host must run: vsock-proxy {vsock_port} <indexer-host> <indexer-port>)"
        );
        if let Err(e) =
            utexo_bridge_enclave::vsock_forwarder::start_forwarder(local_port, vsock_port)
        {
            tracing::error!("failed to start vsock forwarder: {e}");
        }
    }

    // Build RGB consignment validator (when feature enabled).
    #[cfg(feature = "rgb-validation")]
    let rgb_validator = {
        let indexer_url = indexer_url_from_env();
        let network = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "bitcoin".into());
        match utexo_bridge_enclave::validation::rgb::RgbValidator::new(indexer_url, &network) {
            Ok(v) => {
                tracing::info!("RGB validator initialized");
                Some(v)
            }
            Err(e) => {
                tracing::error!("failed to create RGB validator: {e}");
                None
            }
        }
    };

    // Initialise the in-enclave Bitcoin header chain at boot, anchored to
    // the compile-time checkpoint for the active network. The chain starts
    // empty; the Listener will populate it via SubmitHeaders.
    let spv_network = Network::from_env_str(&bitcoin_network_str).unwrap_or_else(|e| {
        tracing::warn!(
            "spv: unknown BITCOIN_NETWORK '{bitcoin_network_str}' ({e}); defaulting to mainnet"
        );
        Network::Mainnet
    });
    let checkpoint = checkpoint_for(spv_network);
    if let Err(msg) = checkpoint.assert_real_in_release() {
        // In a release production build this is fatal — placeholder
        // checkpoints would mean the listener can never push headers that
        // chain to anything real. Crash early and loud.
        panic!("{msg}");
    }
    if !checkpoint.is_real {
        tracing::warn!(
            ?spv_network,
            "spv: using PLACEHOLDER checkpoint (zeros) — header validation will reject any real chain. \
             Replace the constant in enclave/src/spv/checkpoint.rs before deploying."
        );
    } else {
        tracing::info!(
            ?spv_network,
            checkpoint_height = checkpoint.height,
            "spv: header chain initialised at checkpoint"
        );
    }
    let header_chain = std::sync::Mutex::new(HeaderChain::new(spv_network, checkpoint));

    let ctx = ServerContext {
        state,
        bridge_config,
        #[cfg(feature = "rgb-validation")]
        rgb_validator,
        header_chain,
    };

    #[cfg(all(feature = "vsock", target_os = "linux"))]
    {
        use vsock::VsockListener;

        let listener = VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, 5000)
            .expect("failed to bind vsock port 5000");
        tracing::info!("listening on vsock port 5000");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    tracing::debug!("accepted vsock connection");
                    server::handle_connection(stream, &ctx);
                }
                Err(e) => tracing::error!("accept error: {}", e),
            }
        }
    }

    #[cfg(not(all(feature = "vsock", target_os = "linux")))]
    {
        let listen_addr =
            std::env::var("ENCLAVE_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:5000".into());
        let listener = TcpListener::bind(&listen_addr)
            .unwrap_or_else(|_| panic!("failed to bind TCP {listen_addr}"));
        tracing::info!(%listen_addr, "listening on TCP");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer = stream
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "unknown".into());
                    tracing::debug!(%peer, "accepted TCP connection");
                    server::handle_connection(stream, &ctx);
                }
                Err(e) => tracing::error!("accept error: {}", e),
            }
        }
    }
}
