// `TcpListener` is only used in the non-vsock TCP fallback. The import is gated
// to match the block at the bottom of `main`, so the production build emits no
// unused-import warning.
#[cfg(not(all(feature = "vsock", target_os = "linux")))]
use std::net::TcpListener;

use utexo_bridge_enclave::bootstrap;
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::policy::{BuildContext, SecurityPolicy};
use utexo_bridge_enclave::server::{self, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;

/// The boot sequence, in order. Each step is one call into
/// [`utexo_bridge_enclave::bootstrap`]; nothing here does work itself.
fn main() {
    bootstrap::init_tracing();
    tracing::info!("starting utexo-bridge-enclave");

    // Start disciplining the clock from the hypervisor PTP source ASAP. Nitro
    // enclaves free-run without NTP after boot (drift ~1s/day), which otherwise
    // makes long-lived enclaves reject freshly-issued attestation/TLS certs as
    // "not yet valid" (the clone clock-skew bug). Fail-soft: no-op if unavailable.
    #[cfg(target_os = "linux")]
    utexo_bridge_enclave::clocksync::spawn();

    let bitcoin_network_str = bootstrap::bitcoin_network_str();
    let state = EnclaveState::new(bootstrap::resolve_bitcoin_network(&bitcoin_network_str));

    // Pinned bridge config from env. Folded into the attestation `user_data`
    // commitment and cross-checked on every SignEvm.
    let bridge_config = BridgeConfig::from_env();
    bootstrap::log_bridge_config(&bridge_config);

    // Resolve the security posture once from the build context, pinned config,
    // and selected data source. This is what gets committed into attestation
    // `user_data` and what the signing handlers consult.
    let (evm_source, evm_checkpoint) = bootstrap::resolve_evm_data_source();
    #[cfg(feature = "evm-rpc")]
    let evm_rpc_config = utexo_bridge_enclave::config::EvmRpcConfig::from_env();
    #[cfg(feature = "evm-rpc")]
    let evm_min_confirmations = evm_rpc_config.min_confirmations;
    #[cfg(not(feature = "evm-rpc"))]
    let evm_min_confirmations = 0;
    let build_ctx = BuildContext::current();
    let policy = SecurityPolicy::resolve(
        &build_ctx,
        &bridge_config,
        evm_source,
        evm_checkpoint,
        evm_min_confirmations,
    );
    bootstrap::log_policy(&policy);

    // Fail closed at boot: a release rgb-validation build that does not resolve
    // to a valid Production policy must never become reachable. Debug / test /
    // non-bridge builds are exempt.
    if let Err(msg) = policy.assert_valid_for_build(&build_ctx) {
        panic!("{msg}");
    }

    bootstrap::install_env_cloning_secret(&state);
    bootstrap::start_vsock_forwarders();

    #[cfg(feature = "rgb-validation")]
    let rgb_validator = bootstrap::build_rgb_validator();
    #[cfg(feature = "rgb-validation")]
    let header_chain = bootstrap::build_header_chain(&bitcoin_network_str);
    #[cfg(feature = "evm-rpc")]
    let evm_rpc_client = bootstrap::build_evm_rpc_client(&bridge_config, &evm_rpc_config);

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
        #[cfg(feature = "rgb-validation")]
        header_chain,
        #[cfg(feature = "rgb-validation")]
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

/// Accept loop: a fixed worker pool behind a bounded queue. The deadline starts
/// at accept, so queue wait counts and an expired connection fails its first
/// read. Excess connections are dropped. Generic over the socket type.
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
    let (tx, rx) = sync_channel::<DeadlineStream<S>>(MAX_QUEUED_CONNECTIONS);
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
                Ok(stream) => server::handle_connection(stream, &ctx),
                // All senders dropped: the listener is gone, so is the process.
                Err(_) => break,
            }
        });
    }

    for stream in incoming {
        match stream {
            Ok(stream) => match tx.try_send(DeadlineStream::new(
                stream,
                TOTAL_REQUEST_TIMEOUT,
                IO_IDLE_TIMEOUT,
            )) {
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
