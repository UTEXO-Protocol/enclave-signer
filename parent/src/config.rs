use std::collections::HashSet;

/// Parent Adapter configuration, populated from environment variables.
pub struct Config {
    /// Host for the gRPC server to bind (default 127.0.0.1; use 0.0.0.0 in Docker).
    pub grpc_host: String,

    /// Port for the gRPC server (Listener connects here).
    pub grpc_port: u16,

    /// Enclave TCP address for local dev.
    pub enclave_addr: String,

    /// Enclave vsock CID (production, Nitro enclave).
    pub enclave_vsock_cid: u32,

    /// Enclave vsock port.
    pub enclave_vsock_port: u32,

    /// Use vsock instead of TCP.
    pub use_vsock: bool,

    /// EVM network IDs - TRANSACTION with these network_ids routes to signEVM.
    pub evm_network_ids: HashSet<u32>,

    /// Host for the `GET /health` readiness endpoint. Loopback by default:
    /// deploy polls it from the parent host, and it must not be exposed
    /// off-host. Unlike `grpc_host`, do NOT set this to 0.0.0.0 in Docker.
    pub health_host: String,

    /// Port for the health endpoint. Separate from `grpc_port`: the gRPC
    /// listener speaks h2 only, and the probe is plain HTTP/1.1 so a shell
    /// script can curl it.
    pub health_port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            grpc_host: std::env::var("GRPC_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            grpc_port: env_or("GRPC_PORT", 5000),
            enclave_addr: std::env::var("ENCLAVE_ADDR").unwrap_or_else(|_| "127.0.0.1:5000".into()),
            enclave_vsock_cid: env_or("ENCLAVE_VSOCK_CID", 16),
            enclave_vsock_port: env_or("ENCLAVE_VSOCK_PORT", 5000),
            use_vsock: std::env::var("USE_VSOCK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            evm_network_ids: std::env::var("EVM_NETWORK_IDS")
                .unwrap_or_default()
                .split(',')
                .filter_map(|s| s.trim().parse::<u32>().ok())
                .collect(),
            health_host: std::env::var("HEALTH_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            health_port: env_or("HEALTH_PORT", 5001),
        }
    }
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
