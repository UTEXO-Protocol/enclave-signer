use std::time::Duration;

use tonic::transport::Server;
use tower::limit::GlobalConcurrencyLimitLayer;
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
    let security = utexo_bridge_parent::transport_security::ServerSecurity::from_env(
        cfg.grpc_host
            .parse()
            .map_err(|_| "GRPC_HOST must be an IP address")?,
    )?;

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

    tracing::info!(evm_network_ids = ?cfg.evm_network_ids, "EVM network IDs for TRANSACTION routing");
    let service = ParentAdapterService::new(target, cfg.evm_network_ids);
    let listen_addr = std::net::SocketAddr::new(cfg.grpc_host.parse()?, cfg.grpc_port);

    // Limit active requests across all connections. (F03-AF-13)
    // Also limit requests per connection and handler duration.
    // Clone authentication still applies inside the enclave.
    let per_conn = cfg.grpc_max_concurrent_per_conn;
    tracing::info!(
        %listen_addr,
        max_concurrent = cfg.grpc_max_concurrent,
        max_concurrent_per_conn = per_conn,
        request_timeout_secs = cfg.grpc_request_timeout_secs,
        "starting gRPC server"
    );

    let incoming = utexo_bridge_parent::transport_security::LimitedIncoming::bind(
        listen_addr,
        security.max_connections,
    )
    .await?;
    let mut server = Server::builder();
    if let Some(tls) = security.tls {
        server = server.tls_config(tls)?;
    }
    server
        .layer(security.access)
        .layer(GlobalConcurrencyLimitLayer::new(cfg.grpc_max_concurrent))
        .load_shed(true)
        .max_connection_age(Duration::from_secs(300))
        .max_connection_age_grace(Duration::from_secs(30))
        .concurrency_limit_per_connection(per_conn)
        .max_concurrent_streams(Some(per_conn as u32))
        .timeout(Duration::from_secs(cfg.grpc_request_timeout_secs))
        .add_service(ParentServiceServer::new(service))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
