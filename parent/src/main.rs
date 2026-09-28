use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use utexo_bridge_parent::config::Config;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env();
    let target = enclave_target(&cfg)?;

    tracing::info!(evm_network_ids = ?cfg.evm_network_ids, "EVM network IDs for TRANSACTION routing");
    let service = ParentAdapterService::new(target, cfg.evm_network_ids);
    let listen_addr = format!("{}:{}", cfg.grpc_host, cfg.grpc_port).parse()?;

    tracing::info!(%listen_addr, "starting gRPC server");

    Server::builder()
        .add_service(ParentServiceServer::new(service))
        .serve(listen_addr)
        .await?;

    Ok(())
}

/// Pick the enclave transport the configuration asks for.
fn enclave_target(cfg: &Config) -> Result<EnclaveTarget, Box<dyn std::error::Error>> {
    if cfg.use_vsock {
        #[cfg(target_os = "linux")]
        {
            tracing::info!(
                cid = cfg.enclave_vsock_cid,
                port = cfg.enclave_vsock_port,
                "enclave target: vsock"
            );
            Ok(EnclaveTarget::Vsock {
                cid: cfg.enclave_vsock_cid,
                port: cfg.enclave_vsock_port,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("vsock is only supported on Linux".into())
        }
    } else {
        tracing::info!(addr = %cfg.enclave_addr, "enclave target: TCP");
        Ok(EnclaveTarget::Tcp(cfg.enclave_addr.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(use_vsock: bool) -> Config {
        Config {
            grpc_host: "127.0.0.1".into(),
            grpc_port: 1,
            enclave_addr: "10.1.2.3:5000".into(),
            enclave_vsock_cid: 18,
            enclave_vsock_port: 6000,
            use_vsock,
            evm_network_ids: Default::default(),
        }
    }

    #[test]
    fn tcp_target_carries_the_configured_address() {
        match enclave_target(&cfg(false)).unwrap() {
            EnclaveTarget::Tcp(addr) => assert_eq!(addr, "10.1.2.3:5000"),
            #[cfg(target_os = "linux")]
            other => panic!(
                "unexpected {}",
                matches!(other, EnclaveTarget::Vsock { .. })
            ),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn vsock_target_carries_cid_and_port() {
        match enclave_target(&cfg(true)).unwrap() {
            EnclaveTarget::Vsock { cid, port } => assert_eq!((cid, port), (18, 6000)),
            EnclaveTarget::Tcp(addr) => panic!("unexpected TCP target {addr}"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn vsock_target_is_refused_off_linux() {
        assert!(enclave_target(&cfg(true)).is_err());
    }
}
