use std::net::TcpListener;

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
        match utexo_bridge_enclave::validation::rgb::RgbValidator::new(esplora_url, &network) {
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

    let ctx = ServerContext {
        state,
        #[cfg(feature = "rgb-validation")]
        rgb_validator,
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
        let listen_addr = std::env::var("ENCLAVE_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:5000".into());
        let listener =
            TcpListener::bind(&listen_addr).unwrap_or_else(|_| panic!("failed to bind TCP {listen_addr}"));
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
