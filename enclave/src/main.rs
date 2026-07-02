// `TcpListener` is only used in dev mode (TCP fallback). Gating the import
// matches the `cfg(not(all(feature = "vsock", target_os = "linux")))` block
// at the bottom of `main` so the production-combo build (with vsock on
// Linux) doesn't emit an unused-import warning.
#[cfg(not(all(feature = "vsock", target_os = "linux")))]
use std::net::TcpListener;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
#[cfg(feature = "rgb-validation")]
use utexo_bridge_enclave::networks::rgb::validation::RgbValidator;
use utexo_bridge_enclave::server::{self, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;

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

    // Donor-side cloning secret. Optional: only required for enclaves that
    // will serve `GetClone` requests. Pre-shared across the operator's
    // cluster. Never logged, wrapped in `SecretBox` for zeroize-on-drop.
    if let Ok(secret) = std::env::var("UTEXO_CLONING_SECRET") {
        if let Err(e) = state.set_donor_cloning_secret(secret) {
            tracing::error!("failed to set donor cloning secret: {e}");
        } else {
            tracing::info!("donor cloning secret configured from UTEXO_CLONING_SECRET");
        }
    }

    // Start vsock-to-TCP forwarder for Esplora access (production only).
    // The host must run: vsock-proxy <ESPLORA_VSOCK_PORT> <esplora-host> <esplora-port>
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    {
        let vsock_port: u32 = std::env::var("ESPLORA_VSOCK_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8001);
        tracing::info!(
            vsock_port,
            "starting Esplora vsock forwarder (host must run: vsock-proxy {vsock_port} <esplora-host> <esplora-port>)"
        );
        if let Err(e) = utexo_bridge_enclave::vsock_forwarder::start_forwarder(3443, vsock_port) {
            tracing::error!("failed to start vsock forwarder: {e}");
        }
    }

    // Build RGB consignment validator (when feature enabled).
    #[cfg(feature = "rgb-validation")]
    let rgb_validator = {
        let esplora_url =
            std::env::var("ESPLORA_URL").unwrap_or_else(|_| "http://127.0.0.1:3443".into());
        let network = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "bitcoin".into());
        match RgbValidator::new(esplora_url, &network) {
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
             Replace the constant in enclave/src/networks/rgb/spv/checkpoint.rs before deploying."
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
