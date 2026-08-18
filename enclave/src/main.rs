// `TcpListener` is only used in the dev-mode TCP fallback. The import is gated
// to match the block at the bottom of `main`, so the production build emits no
// unused-import warning.
#[cfg(not(all(feature = "vsock", target_os = "linux")))]
use std::net::TcpListener;

use utexo_bridge_enclave::config::BridgeConfig;
#[cfg(feature = "spv")]
use utexo_bridge_enclave::networks::rgb::spv::{
    resolve_checkpoint, CheckpointSource, HeaderChain, Network, CHECKPOINT_ENV,
};
#[cfg(feature = "rgb-validation")]
use utexo_bridge_enclave::networks::rgb::validation::RgbValidator;
use utexo_bridge_enclave::policy::{BuildContext, EvmDataSource, SecurityPolicy};
use utexo_bridge_enclave::server::{self, ServerContext};
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
#[cfg(all(feature = "vsock", feature = "spv", target_os = "linux"))]
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
#[cfg(all(feature = "vsock", feature = "spv", target_os = "linux"))]
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
    // must set EVM_CHAIN_ID, EVM_PROXY_CONTRACT_ADDRESS, RGB_ASSET_ID - a misconfigured
    // production enclave is detectable externally via the attestation bundle.
    let bridge_config = BridgeConfig::from_env();
    if bridge_config.is_configured() {
        tracing::info!(
            chain_id = bridge_config.chain_id,
            bridge_contract = %hex::encode(bridge_config.bridge_contract),
            rgb_asset_id = %bridge_config.rgb_asset_id,
            "bridge config pinned from env"
        );
    } else if bridge_config.is_partially_configured() {
        // Some-but-not-all pin fields set: a botched production config. SignEvm
        // fails closed on this (audit 4th M-03 / #94); log it before the boot
        // gate below turns it fatal in a production build.
        tracing::error!(
            chain_id = bridge_config.chain_id,
            bridge_contract = %hex::encode(bridge_config.bridge_contract),
            rgb_asset_id = %bridge_config.rgb_asset_id,
            "bridge config PARTIALLY set - EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID must all \
             be set (non-zero) or all unset; SignEvm will refuse to sign with this ambiguous pin"
        );
    } else {
        tracing::warn!(
            "bridge config unconfigured (EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID unset) - \
             SignEvm cross-check will fall back to legacy behaviour and the attestation bundle \
             will commit to empty values"
        );
    }

    // Which EVM `FundsIn` deposit-verification source this build/deployment
    // uses (audit C-01 "allowed data sources"). Determined the same way the RPC
    // client is selected below: `evm-rpc` off => none; `helios` +
    // HELIOS_EXECUTION_RPC set => trustless; otherwise the raw host-relayed RPC.
    #[cfg(not(feature = "evm-rpc"))]
    let (evm_source, evm_checkpoint) = (EvmDataSource::Disabled, None);
    #[cfg(all(feature = "evm-rpc", not(feature = "helios")))]
    let (evm_source, evm_checkpoint) = (EvmDataSource::RawRpc, None);
    #[cfg(all(feature = "evm-rpc", feature = "helios"))]
    let (evm_source, evm_checkpoint) = if std::env::var("HELIOS_EXECUTION_RPC").is_ok() {
        // The pinned weak-subjectivity checkpoint is Helios's trust root, so
        // it is committed into the attested policy: a verifier confirms which
        // checkpoint the enclave synced from, not just that it is in Helios
        // mode (audit M-06). A missing or malformed value yields `None`, and
        // the boot gate below then refuses to boot.
        let checkpoint = std::env::var("HELIOS_CHECKPOINT")
            .ok()
            .and_then(|s| hex::decode(s.strip_prefix("0x").unwrap_or(&s)).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        (EvmDataSource::HeliosVerified, checkpoint)
    } else {
        (EvmDataSource::RawRpc, None)
    };

    // Resolve the security posture once (audit C-01) from the build context,
    // pinned config, and selected data source. This is what gets committed into
    // attestation `user_data` and what the signing handlers consult.
    let build_ctx = BuildContext::current();
    let policy = SecurityPolicy::resolve(&build_ctx, &bridge_config, evm_source, evm_checkpoint);
    match &policy {
        SecurityPolicy::Production(p) => tracing::info!(
            chain_id = p.chain_id,
            allow_vanilla_psbt = p.allow_vanilla_psbt,
            evm_source = ?p.evm_source,
            btc_source = ?p.btc_source,
            "resolved PRODUCTION security policy (committed into attestation user_data)"
        ),
        SecurityPolicy::Development { reason } => tracing::warn!(
            ?reason,
            "resolved DEVELOPMENT security policy — this is NOT a production bridge signer"
        ),
    }

    // Fail closed at boot (audit C-01): a release rgb-validation build that
    // does not resolve to a valid Production policy must never become
    // reachable. Debug / test / non-bridge builds are exempt.
    if let Err(msg) = policy.assert_valid_for_build(&build_ctx) {
        panic!("{msg}");
    }

    // Donor-side cloning secret, delivered at runtime via `InitializeKey` so it
    // never lands in the EIF or the PCRs. `UTEXO_CLONING_SECRET` is a legacy/dev
    // fallback only and must not be baked into a release EIF. Needed only by
    // enclaves that serve `GetClone`. Never logged; `SecretBox` zeroizes it.
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
    // 127.0.0.1:<local_port> is forwarded to vsock:<vsock_port>. For an Electrum
    // ssl:// endpoint we listen on the URL's own port and pin its hostname to
    // 127.0.0.1 in /etc/hosts, so TLS terminates inside the enclave against the
    // real server cert and the host relays ciphertext only. Untrusted egress
    // (audit I-01); see `vsock_forwarder`'s trust-boundary note.
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    {
        // Esplora egress is only needed by the RGB/BTC stack (consignment
        // resolver + SPV). A `ccd`-only build starts no Esplora forwarder.
        #[cfg(feature = "spv")]
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

        // Second forwarder for the EVM JSON-RPC used by in-enclave FundsIn
        // verification (#60). Distinct loopback/vsock ports from Esplora
        // (3443/8001). Untrusted, host-controlled egress boundary (audit I-01);
        // the host must run: vsock-proxy <EVM_RPC_VSOCK_PORT> <evm-rpc-host> <port>.
        #[cfg(feature = "evm-rpc")]
        {
            let evm_vsock_port: u32 = std::env::var("EVM_RPC_VSOCK_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8002);
            tracing::info!(
                evm_vsock_port,
                "starting EVM RPC vsock forwarder (host must run: vsock-proxy {evm_vsock_port} <evm-rpc-host> <evm-rpc-port>)"
            );
            if let Err(e) =
                utexo_bridge_enclave::vsock_forwarder::start_forwarder(3444, evm_vsock_port)
            {
                tracing::error!("failed to start EVM RPC vsock forwarder: {e}");
            }
        }

        // Helios execution + consensus RPC forwarders (#77, trustless EVM
        // verification). Helios verifies these UNTRUSTED upstreams against a
        // pinned checkpoint. Local ports mirror HeliosConfig defaults
        // (18545/18550); the host must run one vsock-proxy per upstream.
        #[cfg(feature = "helios")]
        {
            let exec_local: u16 = std::env::var("HELIOS_EXECUTION_LOCAL_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(18545);
            let exec_vsock: u32 = std::env::var("HELIOS_EXECUTION_VSOCK_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8003);
            let cons_local: u16 = std::env::var("HELIOS_CONSENSUS_LOCAL_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(18550);
            let cons_vsock: u32 = std::env::var("HELIOS_CONSENSUS_VSOCK_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8004);
            tracing::info!(
                exec_local,
                exec_vsock,
                cons_local,
                cons_vsock,
                "starting Helios execution + consensus vsock forwarders (#77)"
            );
            if let Err(e) =
                utexo_bridge_enclave::vsock_forwarder::start_forwarder(exec_local, exec_vsock)
            {
                tracing::error!("failed to start Helios execution RPC forwarder: {e}");
            }
            if let Err(e) =
                utexo_bridge_enclave::vsock_forwarder::start_forwarder(cons_local, cons_vsock)
            {
                tracing::error!("failed to start Helios consensus RPC forwarder: {e}");
            }
        }
    }

    // Build RGB consignment validator (when feature enabled).
    #[cfg(feature = "rgb-validation")]
    let rgb_validator = {
        let indexer_url = indexer_url_from_env();
        let network = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "bitcoin".into());
        match RgbValidator::new(indexer_url, &network) {
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
    // empty; the Listener will populate it via SubmitHeaders. SPV/RGB-only:
    // a `ccd`-only build has no header chain (and no SubmitHeaders handler).
    #[cfg(feature = "spv")]
    let header_chain = {
        let spv_network = Network::from_env_str(&bitcoin_network_str).unwrap_or_else(|e| {
            tracing::warn!(
                "spv: unknown BITCOIN_NETWORK '{bitcoin_network_str}' ({e}); defaulting to mainnet"
            );
            Network::Mainnet
        });
        // Compiled-in anchor, or the dev-only `SPV_CHECKPOINT` override. A
        // production-shaped build refuses to boot when that var is set, and a
        // malformed spec is fatal rather than silently ignored.
        let (checkpoint, checkpoint_source) =
            resolve_checkpoint(spv_network).unwrap_or_else(|msg| {
                panic!("{msg}");
            });
        if checkpoint_source == CheckpointSource::Env {
            tracing::warn!(
                ?spv_network,
                checkpoint_height = checkpoint.height,
                "spv: checkpoint OVERRIDDEN from {} — dev builds only; headers below this height are \
                 not verifiable by this enclave",
                CHECKPOINT_ENV
            );
        }
        if let Err(msg) = checkpoint.assert_real_in_release() {
            // Fatal in a release build: with a placeholder checkpoint the
            // listener can never push headers that chain to anything real.
            panic!("{msg}");
        }
        if let Err(msg) = checkpoint.assert_retarget_aligned(spv_network) {
            // A misaligned PoW-network checkpoint wedges the chain at the first
            // retarget boundary above it, since the epoch-start lookup falls
            // below the checkpoint. A build-time misconfiguration.
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
        std::sync::Mutex::new(HeaderChain::new(spv_network, checkpoint))
    };

    // Build the in-enclave EVM RPC client for independent FundsIn verification
    // (#60). The URL must be the loopback forwarder; responses are host-relayed
    // and treated as evidence (verified fail-closed), not trusted input.
    #[cfg(feature = "evm-rpc")]
    let (evm_rpc_client, evm_rpc_config) = {
        use utexo_bridge_enclave::networks::evm::evm_event::{AlloyEvmClient, EvmReceiptProvider};
        let cfg = utexo_bridge_enclave::config::EvmRpcConfig::from_env();
        type Boxed = Box<dyn EvmReceiptProvider + Send + Sync>;

        // Raw alloy provider (#60): host-relayed, unverified.
        let build_alloy = || -> Option<Boxed> {
            match AlloyEvmClient::new(&cfg.rpc_url) {
                Ok(c) => {
                    tracing::info!(
                        rpc_url = %cfg.rpc_url,
                        min_confirmations = cfg.min_confirmations,
                        "EVM FundsIn verification: raw alloy path (#60, host-relayed/unverified)"
                    );
                    Some(Box::new(c) as Boxed)
                }
                Err(e) => {
                    tracing::error!("failed to init EVM RPC client: {e}");
                    None
                }
            }
        };

        // #77 runtime-selectable: HELIOS_EXECUTION_RPC set selects the
        // Helios-verified path, else raw alloy. Fail closed on the selected
        // provider - a Helios sync failure leaves the client unset so bridge
        // signing refuses, never downgrading to the unverified path.
        #[cfg(feature = "helios")]
        let client: Option<Boxed> = match utexo_bridge_enclave::config::HeliosConfig::from_env() {
            Some(hcfg) => {
                // Pass the pinned EVM_CHAIN_ID so Helios rejects a
                // HELIOS_NETWORK inconsistent with it (#77 predicate 1).
                match utexo_bridge_enclave::networks::evm::evm_event::HeliosEvmClient::new(
                    &hcfg,
                    bridge_config.chain_id,
                ) {
                    Ok(c) => {
                        tracing::info!(
                            network = %hcfg.network,
                            min_confirmations = cfg.min_confirmations,
                            "EVM FundsIn verification: Helios-verified path (#77, trustless)"
                        );
                        Some(Box::new(c) as Boxed)
                    }
                    Err(e) => {
                        tracing::error!(
                            "Helios client init/sync failed: {e} - bridge signing will fail closed"
                        );
                        None
                    }
                }
            }
            None => build_alloy(),
        };
        #[cfg(not(feature = "helios"))]
        let client: Option<Boxed> = build_alloy();

        (client, cfg)
    };

    let ctx = ServerContext {
        state,
        bridge_config,
        policy,
        #[cfg(feature = "rgb-validation")]
        rgb_validator,
        #[cfg(feature = "evm-rpc")]
        evm_rpc_client,
        #[cfg(feature = "evm-rpc")]
        evm_rpc_config,
        #[cfg(feature = "spv")]
        header_chain,
        #[cfg(feature = "spv")]
        submit_rate_limiter: std::sync::Mutex::new(server::SubmitRateLimiter::default()),
    };

    #[cfg(all(feature = "vsock", target_os = "linux"))]
    {
        use vsock::VsockListener;

        let listener = VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, 5000)
            .expect("failed to bind vsock port 5000");
        tracing::info!("listening on vsock port 5000");

        serve(listener.incoming(), ctx);
    }

    #[cfg(not(all(feature = "vsock", target_os = "linux")))]
    {
        let listen_addr =
            std::env::var("ENCLAVE_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:5000".into());
        let listener = TcpListener::bind(&listen_addr)
            .unwrap_or_else(|_| panic!("failed to bind TCP {listen_addr}"));
        tracing::info!(%listen_addr, "listening on TCP");

        serve(listener.incoming(), ctx);
    }
}

/// Accept loop with bounded concurrency and per-request deadlines (audit M-03 /
/// #83). Each accepted socket is wrapped in a [`DeadlineStream`] (idle + total
/// request timeouts) and handed to a fixed worker pool via a bounded queue;
/// over-cap connections are dropped (closed) so one slow request can't starve
/// the others. Generic over the socket type so the vsock and TCP branches share
/// one implementation.
fn serve<I, S>(incoming: I, ctx: ServerContext)
where
    I: IntoIterator<Item = std::io::Result<S>>,
    S: std::io::Read + std::io::Write + utexo_bridge_enclave::conn::SocketTimeout + Send + 'static,
{
    use std::sync::mpsc::{sync_channel, TrySendError};
    use std::sync::{Arc, Mutex};
    use utexo_bridge_enclave::conn::{
        DeadlineStream, IO_IDLE_TIMEOUT, MAX_QUEUED_CONNECTIONS, TOTAL_REQUEST_TIMEOUT,
        WORKER_THREADS,
    };

    let ctx = Arc::new(ctx);
    // Bounded queue doubles as the connection cap: a full queue means all
    // workers are busy and the backlog is at its limit.
    let (tx, rx) = sync_channel::<S>(MAX_QUEUED_CONNECTIONS);
    let rx = Arc::new(Mutex::new(rx));

    for worker_id in 0..WORKER_THREADS {
        let rx = Arc::clone(&rx);
        let ctx = Arc::clone(&ctx);
        std::thread::spawn(move || loop {
            // Hold the queue lock only to dequeue; handling happens unlocked so
            // workers run concurrently.
            let next = {
                let guard = match rx.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        tracing::error!(worker_id, "worker queue mutex poisoned; worker exiting");
                        break;
                    }
                };
                guard.recv()
            };
            match next {
                Ok(stream) => {
                    let stream =
                        DeadlineStream::new(stream, TOTAL_REQUEST_TIMEOUT, IO_IDLE_TIMEOUT);
                    server::handle_connection(stream, &ctx);
                }
                // All senders dropped: the listener is gone, so is the process.
                Err(_) => break,
            }
        });
    }

    for stream in incoming {
        match stream {
            Ok(stream) => match tx.try_send(stream) {
                Ok(()) => tracing::debug!("connection queued"),
                Err(TrySendError::Full(_)) => tracing::warn!(
                    cap = MAX_QUEUED_CONNECTIONS,
                    "connection queue full; dropping connection (slow-request backpressure)"
                ),
                Err(TrySendError::Disconnected(_)) => {
                    tracing::error!("no workers available; stopping accept loop");
                    break;
                }
            },
            Err(e) => tracing::error!("accept error: {e}"),
        }
    }
}
