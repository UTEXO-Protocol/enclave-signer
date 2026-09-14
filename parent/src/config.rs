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

    /// Global cap on in-flight gRPC requests across ALL connections. Bounds the
    /// work an unauthenticated peer can pin on the donor adapter regardless of
    /// how many connections it opens (F03-AF-13, defense-in-depth).
    pub grpc_max_concurrent: usize,

    /// Per-connection cap on concurrent in-flight gRPC requests / HTTP/2 streams.
    pub grpc_max_concurrent_per_conn: usize,

    /// Hard per-request timeout for the gRPC server. Sheds requests that hang
    /// the handler (e.g. a slow enclave leg) instead of holding a permit forever.
    pub grpc_request_timeout_secs: u64,
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
            grpc_max_concurrent: env_or("GRPC_MAX_CONCURRENT", 128usize).max(1),
            grpc_max_concurrent_per_conn: env_or("GRPC_MAX_CONCURRENT_PER_CONN", 32usize).max(1),
            grpc_request_timeout_secs: env_or("GRPC_REQUEST_TIMEOUT_SECS", 120u64).max(1),
        }
    }
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
