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
        }
    }
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
    use std::sync::{Mutex, MutexGuard};

    /// Process-wide environment: serialise the tests that touch it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const VARS: [&str; 7] = [
        "GRPC_HOST",
        "GRPC_PORT",
        "ENCLAVE_ADDR",
        "ENCLAVE_VSOCK_CID",
        "ENCLAVE_VSOCK_PORT",
        "USE_VSOCK",
        "EVM_NETWORK_IDS",
    ];

    struct EnvScope {
        _guard: MutexGuard<'static, ()>,
    }

    impl EnvScope {
        fn new(vars: &[(&str, &str)]) -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            for v in VARS {
                std::env::remove_var(v);
            }
            for (k, v) in vars {
                std::env::set_var(k, v);
            }
            Self { _guard: guard }
        }
    }

    impl Drop for EnvScope {
        fn drop(&mut self) {
            for v in VARS {
                std::env::remove_var(v);
            }
        }
    }

    #[test]
    fn defaults_when_nothing_is_set() {
        let _scope = EnvScope::new(&[]);
        let c = Config::from_env();
        assert_eq!(c.grpc_host, "127.0.0.1");
        assert_eq!(c.grpc_port, 5000);
        assert_eq!(c.enclave_addr, "127.0.0.1:5000");
        assert_eq!(c.enclave_vsock_cid, 16);
        assert_eq!(c.enclave_vsock_port, 5000);
        assert!(!c.use_vsock);
        assert!(c.evm_network_ids.is_empty());
    }

    #[test]
    fn every_variable_overrides_its_default() {
        let _scope = EnvScope::new(&[
            ("GRPC_HOST", "0.0.0.0"),
            ("GRPC_PORT", "50051"),
            ("ENCLAVE_ADDR", "10.0.0.5:7000"),
            ("ENCLAVE_VSOCK_CID", "18"),
            ("ENCLAVE_VSOCK_PORT", "6000"),
            ("USE_VSOCK", "1"),
            ("EVM_NETWORK_IDS", "84,1"),
        ]);
        let c = Config::from_env();
        assert_eq!(c.grpc_host, "0.0.0.0");
        assert_eq!(c.grpc_port, 50051);
        assert_eq!(c.enclave_addr, "10.0.0.5:7000");
        assert_eq!(c.enclave_vsock_cid, 18);
        assert_eq!(c.enclave_vsock_port, 6000);
        assert!(c.use_vsock);
        assert_eq!(c.evm_network_ids, HashSet::from([84, 1]));
    }

    #[test]
    fn use_vsock_accepts_1_and_case_insensitive_true_only() {
        for (value, want) in [
            ("1", true),
            ("true", true),
            ("TRUE", true),
            ("True", true),
            ("0", false),
            ("yes", false),
            ("", false),
            (" true", false),
            ("11", false),
        ] {
            let _scope = EnvScope::new(&[("USE_VSOCK", value)]);
            assert_eq!(Config::from_env().use_vsock, want, "USE_VSOCK={value:?}");
        }
    }

    #[test]
    fn evm_network_ids_parses_a_comma_list_and_drops_junk() {
        let _scope = EnvScope::new(&[("EVM_NETWORK_IDS", " 84 , 1,junk,,2,-5,84")]);
        assert_eq!(
            Config::from_env().evm_network_ids,
            HashSet::from([84, 1, 2])
        );
    }

    #[test]
    fn evm_network_ids_empty_or_all_junk_is_empty() {
        {
            let _scope = EnvScope::new(&[("EVM_NETWORK_IDS", "")]);
            assert!(Config::from_env().evm_network_ids.is_empty());
        }
        {
            let _scope = EnvScope::new(&[("EVM_NETWORK_IDS", "a, b ,,")]);
            assert!(Config::from_env().evm_network_ids.is_empty());
        }
    }

    #[test]
    fn unparseable_numbers_fall_back_to_defaults() {
        {
            let _scope = EnvScope::new(&[
                ("GRPC_PORT", "notaport"),
                ("ENCLAVE_VSOCK_CID", "-1"),
                ("ENCLAVE_VSOCK_PORT", ""),
            ]);
            let c = Config::from_env();
            assert_eq!(c.grpc_port, 5000);
            assert_eq!(c.enclave_vsock_cid, 16);
            assert_eq!(c.enclave_vsock_port, 5000);
        }
        {
            // Out of range for u16.
            let _scope = EnvScope::new(&[("GRPC_PORT", "70000")]);
            assert_eq!(Config::from_env().grpc_port, 5000);
        }
    }

    #[test]
    fn env_or_returns_the_default_only_when_missing_or_invalid() {
        let _scope = EnvScope::new(&[("GRPC_PORT", "6001"), ("ENCLAVE_VSOCK_CID", "x")]);
        assert_eq!(env_or::<u16>("GRPC_PORT", 1), 6001);
        assert_eq!(env_or::<u32>("ENCLAVE_VSOCK_CID", 9), 9);
        assert_eq!(env_or::<u32>("GRPC_HOST", 7), 7);
    }
}
