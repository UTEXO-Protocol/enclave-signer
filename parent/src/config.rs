/// Parent Adapter configuration, populated from environment variables.
pub struct Config {
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
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            grpc_port: env_or("GRPC_PORT", 5000),
            enclave_addr: std::env::var("ENCLAVE_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:5000".into()),
            enclave_vsock_cid: env_or("ENCLAVE_VSOCK_CID", 16),
            enclave_vsock_port: env_or("ENCLAVE_VSOCK_PORT", 5000),
            use_vsock: std::env::var("USE_VSOCK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        }
    }
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
