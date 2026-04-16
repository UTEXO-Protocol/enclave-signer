use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use utexo_bridge_parent::config::Config;
use utexo_bridge_parent::grpc_proto::enclave_service_server::EnclaveServiceServer;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env();

    let target = if cfg.use_vsock {
        #[cfg(target_os = "linux")]
        {
            tracing::info!(
                cid = cfg.enclave_vsock_cid,
                port = cfg.enclave_vsock_port,
                "enclave target: vsock"
            );
            EnclaveTarget::Vsock {
                cid: cfg.enclave_vsock_cid,
                port: cfg.enclave_vsock_port,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err("vsock is only supported on Linux".into());
        }
    } else {
        tracing::info!(addr = %cfg.enclave_addr, "enclave target: TCP");
        EnclaveTarget::Tcp(cfg.enclave_addr)
    };

    let service = ParentAdapterService::new(target);
    let listen_addr = format!("{}:{}", cfg.grpc_host, cfg.grpc_port).parse()?;

    tracing::info!(%listen_addr, "starting gRPC server");

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(utexo_bridge_parent::grpc_proto::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    Server::builder()
        .add_service(reflection)
        .add_service(EnclaveServiceServer::new(service))
        .serve(listen_addr)
        .await?;

    Ok(())
}
