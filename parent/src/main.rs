use std::time::Duration;

use tonic::transport::Server;
use tower::limit::GlobalConcurrencyLimitLayer;
use tracing_subscriber::{prelude::*, EnvFilter};

use utexo_bridge_parent::config::Config;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::header_sync::HeaderSync;
use utexo_bridge_parent::health;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed_configured = utexo_bridge_parent::seed_persistence::configured();
    tracing_subscriber::registry()
        // SDK debug and trace events can contain signed requests. When the
        // broker is configured, drop those levels for the AWS and HTTP stacks.
        // Keep info, warn and error: the gRPC and mTLS server also use hyper
        // and rustls. Broker diagnostics use fixed categories and are safe.
        .with(
            tracing_subscriber::fmt::layer()
                .with_filter(EnvFilter::from_default_env())
                .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
                    !seed_configured
                        || *metadata.level() < tracing::Level::DEBUG
                        || !["aws_", "hyper", "h2", "rustls"]
                            .iter()
                            .any(|prefix| metadata.target().starts_with(prefix))
                })),
        )
        .init();

    let cfg = Config::from_env();
    let security = utexo_bridge_parent::transport_security::ServerSecurity::from_env(
        cfg.grpc_host
            .parse()
            .map_err(|_| "GRPC_HOST must be an IP address")?,
    )?;
    let (header_source, header_interval) = utexo_bridge_parent::config::header_sync(
        std::env::var("HEADER_ELECTRUM_URL").ok(),
        std::env::var("HEADER_SYNC_INTERVAL_SECS").ok(),
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
        EnclaveTarget::Tcp(cfg.enclave_addr.clone())
    };

    let listen_addr = std::net::SocketAddr::new(cfg.grpc_host.parse()?, cfg.grpc_port);
    let health_addr = format!("{}:{}", cfg.health_host, cfg.health_port).parse()?;

    // Limit active requests across all connections (F03-AF-13), requests per
    // connection, and handler duration. The enclave still authenticates clones.
    let per_conn = cfg.grpc_max_concurrent_per_conn;
    tracing::info!(
        %listen_addr,
        max_concurrent = cfg.grpc_max_concurrent,
        max_concurrent_per_conn = per_conn,
        request_timeout_secs = cfg.grpc_request_timeout_secs,
        "starting gRPC server"
    );

    // Bind the probe first, so a bad HEALTH_PORT fails at boot.
    let health_listener = health::bind(health_addr).await?;
    let service = ParentAdapterService::new(target);

    // The enclave accepts headers in every phase, so sync starts before keys
    // and endpoints. A failed step or a bad HEADER_ELECTRUM_URL does not stop
    // the gRPC server. `/health` reports both as `header_sync`.
    let (header_sync, sync_status) =
        HeaderSync::new(service.clone(), header_source, header_interval);
    tokio::spawn(header_sync.run());

    let broker = utexo_bridge_parent::seed_persistence::start(&cfg).await?;

    // A failed health server must not stop signing: these parents hold a
    // 2-of-3 quorum.
    let health_service = service.clone();
    tokio::spawn(async move {
        if let Err(e) = health::serve(health_listener, health_service, sync_status).await {
            tracing::error!(error = %e, "health server stopped; signing continues");
        }
    });

    let incoming = utexo_bridge_parent::transport_security::LimitedIncoming::bind(
        listen_addr,
        security.max_connections,
    )
    .await?;
    let mut server = Server::builder();
    if let Some(tls) = security.tls {
        server = server.tls_config(tls)?;
    }
    let server = server
        .layer(security.access)
        .layer(GlobalConcurrencyLimitLayer::new(cfg.grpc_max_concurrent))
        .load_shed(true)
        .max_connection_age(Duration::from_secs(300))
        .max_connection_age_grace(Duration::from_secs(30))
        .concurrency_limit_per_connection(per_conn)
        .max_concurrent_streams(Some(per_conn as u32))
        .timeout(Duration::from_secs(cfg.grpc_request_timeout_secs))
        // tonic refuses requests above 4 MiB by default. Accept the same
        // size as the enclave frame.
        .add_service(
            ParentServiceServer::new(service)
                .max_decoding_message_size(utexo_bridge_parent::framing::MAX_MESSAGE_SIZE as usize),
        )
        .serve_with_incoming(incoming);
    if let Some(broker) = broker {
        tokio::select! {
            result = server => result?,
            _ = broker => return Err("seed persistence listener stopped".into()),
        }
    } else {
        server.await?;
    }

    Ok(())
}
