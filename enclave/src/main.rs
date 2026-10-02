// Used only by the non-vsock TCP fallback at the end of `main`.
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

    // Start first. Without NTP the enclave clock drifts (about 1 s/day) and then
    // rejects new certs as "not yet valid". No-op if PTP is not available.
    #[cfg(target_os = "linux")]
    utexo_bridge_enclave::clocksync::spawn();

    let bitcoin_network_str = bootstrap::bitcoin_network_str();
    let state = EnclaveState::new(bootstrap::resolve_bitcoin_network(&bitcoin_network_str));

    // Pinned bridge config. Committed in attestation `user_data` and checked on
    // every signing request.
    let bridge_config = BridgeConfig::from_env();
    bootstrap::log_bridge_config(&bridge_config);

    // Fail closed: a release rgb-validation build without a valid Production
    // policy does not start. Debug, test and non-bridge builds are exempt.
    // `SetEndpoints` checks the full policy later.
    #[cfg(feature = "evm-rpc")]
    let evm_min_confirmations =
        utexo_bridge_enclave::config::EvmRpcConfig::from_env().min_confirmations;
    #[cfg(not(feature = "evm-rpc"))]
    let evm_min_confirmations = 0;
    let build_ctx = BuildContext::current();
    let policy = SecurityPolicy::resolve(
        &build_ctx,
        &bridge_config,
        utexo_bridge_enclave::policy::EvmDataSource::Disabled,
        None,
        None,
        "",
        evm_min_confirmations,
    );
    if let Err(msg) = policy.assert_valid_at_boot(&build_ctx) {
        panic!("{msg}");
    }

    // No cloning with KMS persistence: every replica recovers its seed from KMS.
    #[cfg(not(feature = "kms-persistence"))]
    bootstrap::install_env_cloning_secret(&state);
    bootstrap::start_vsock_forwarders();

    // The policy and chain clients come with `SetEndpoints`. Until then the
    // enclave signs nothing.
    let ctx = ServerContext::awaiting_launch(
        state,
        bridge_config,
        #[cfg(feature = "rgb-validation")]
        bootstrap::build_header_chain(&bitcoin_network_str),
        build_ctx,
    );

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

/// Accept loop: a fixed worker pool behind a bounded queue.
/// The deadline starts at accept, so queue wait counts. Excess connections are
/// dropped.
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
    // The bounded queue is also the connection cap.
    let (tx, rx) = sync_channel::<(S, std::time::Instant)>(MAX_QUEUED_CONNECTIONS);
    let rx = Arc::new(Mutex::new(rx));

    for worker_id in 0..WORKER_THREADS {
        let rx = Arc::clone(&rx);
        let ctx = Arc::clone(&ctx);
        std::thread::spawn(move || loop {
            // Hold the queue lock only to dequeue, so workers run concurrently.
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
                Ok((stream, deadline)) => {
                    // Keep the accept-time budget for framing, dispatch and seed init.
                    let stream = DeadlineStream::with_deadline(stream, deadline, IO_IDLE_TIMEOUT);
                    server::handle_connection_until(stream, &ctx, deadline);
                }
                // All senders dropped: the listener is gone.
                Err(_) => break,
            }
        });
    }

    for stream in incoming {
        match stream {
            // Queue wait counts in the budget, so no work starts after the
            // parent timed out.
            Ok(stream) => {
                match tx.try_send((stream, std::time::Instant::now() + TOTAL_REQUEST_TIMEOUT)) {
                    Ok(()) => tracing::debug!("connection queued"),
                    Err(TrySendError::Full(_)) => tracing::warn!(
                        cap = MAX_QUEUED_CONNECTIONS,
                        "connection queue full; dropping connection (slow-request backpressure)"
                    ),
                    Err(TrySendError::Disconnected(_)) => {
                        tracing::error!("no workers available; stopping accept loop");
                        break;
                    }
                }
            }
            Err(e) => tracing::error!("accept error: {e}"),
        }
    }
}
