use std::net::TcpListener;

use utexo_bridge_enclave::keys::EnclaveState;
use utexo_bridge_enclave::server;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("starting utexo-bridge-enclave");

    let state = EnclaveState::new();

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
                    server::handle_connection(stream, &state);
                }
                Err(e) => tracing::error!("accept error: {}", e),
            }
        }
    }

    #[cfg(not(all(feature = "vsock", target_os = "linux")))]
    {
        let listener =
            TcpListener::bind("127.0.0.1:5000").expect("failed to bind TCP 127.0.0.1:5000");
        tracing::info!("listening on TCP 127.0.0.1:5000");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer = stream
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "unknown".into());
                    tracing::debug!(%peer, "accepted TCP connection");
                    server::handle_connection(stream, &state);
                }
                Err(e) => tracing::error!("accept error: {}", e),
            }
        }
    }
}
