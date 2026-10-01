use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;

use crate::header_source::ElectrumSource;

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

    /// Maximum active gRPC requests across all connections. (F03-AF-13)
    pub grpc_max_concurrent: usize,

    /// Per-connection cap on concurrent in-flight gRPC requests / HTTP/2 streams.
    pub grpc_max_concurrent_per_conn: usize,

    /// Time limit for each gRPC handler.
    pub grpc_request_timeout_secs: u64,

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
            grpc_max_concurrent: env_or("GRPC_MAX_CONCURRENT", 128usize).max(1),
            grpc_max_concurrent_per_conn: env_or("GRPC_MAX_CONCURRENT_PER_CONN", 32usize).max(1),
            grpc_request_timeout_secs: env_or("GRPC_REQUEST_TIMEOUT_SECS", 120u64).max(1),
            health_host: std::env::var("HEALTH_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            health_port: env_or("HEALTH_PORT", 5001),
        }
    }
}

/// Parse `HEADER_ELECTRUM_URL` and `HEADER_SYNC_INTERVAL_SECS`. An unset or
/// empty value takes its default. A malformed value is an error.
pub fn header_sync(
    url: Option<String>,
    interval_secs: Option<String>,
) -> anyhow::Result<(Option<ElectrumSource>, Duration)> {
    let source = match url.as_deref() {
        None | Some("") => None,
        Some(url) => Some(ElectrumSource::new(url).context("HEADER_ELECTRUM_URL")?),
    };
    let secs = match interval_secs.as_deref() {
        None | Some("") => 10,
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|s| (1..=600).contains(s))
            .with_context(|| format!("HEADER_SYNC_INTERVAL_SECS must be 1..=600, got {v:?}"))?,
    };
    Ok((source, Duration::from_secs(secs)))
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: Option<&str>, secs: Option<&str>) -> anyhow::Result<(bool, u64)> {
        header_sync(url.map(Into::into), secs.map(Into::into))
            .map(|(source, interval)| (source.is_some(), interval.as_secs()))
    }

    #[test]
    fn header_sync_settings() {
        assert_eq!(parse(None, None).unwrap(), (false, 10));
        assert_eq!(parse(Some(""), Some("")).unwrap(), (false, 10));
        assert_eq!(
            parse(Some("ssl://e.example.com:50002"), Some("1")).unwrap(),
            (true, 1)
        );
        assert_eq!(
            parse(Some("tcp://127.0.0.1:50001"), Some("600")).unwrap(),
            (true, 600)
        );
        assert!(parse(Some("tcp://192.0.2.1:50001"), None).is_err());
        assert!(parse(Some("electrum:50002"), None).is_err());
        for secs in ["0", "601", "-1", "ten"] {
            assert!(parse(None, Some(secs)).is_err(), "{secs}");
        }
    }
}
