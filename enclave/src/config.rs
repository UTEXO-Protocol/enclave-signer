//! Enclave-side bridge configuration pinned at boot.
//!
//! The chain, bridge contract, and RGB asset the enclave is willing to sign
//! for are loaded once from the environment at startup and then folded into
//! the attestation `user_data` commitment (see `canonical_pubkey_bundle` in
//! `server.rs`). Two consequences:
//!
//!   1. A verifier that fetches `GetAttestedPublicKey` can prove this
//!      enclave was provisioned for a specific (chain_id, contract, asset)
//!      tuple — operator-level pinning becomes cryptographically observable.
//!   2. `SignEvm` cross-checks the listener-supplied fields against this
//!      config and rejects on mismatch, so a compromised listener cannot
//!      redirect signatures to a different chain or contract.
//!
//! Production deployments MUST set all three env vars. Dev / mock builds
//! may leave them unset, in which case the config is "unconfigured" — the
//! cross-check is skipped and the canonical bundle commits to the empty
//! values. That makes a missing-env production deploy externally visible
//! to anyone running the attestation verifier.

use crate::error::{EnclaveError, Result};

/// Bridge config pinned at enclave boot from env. See module docs.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub chain_id: u64,
    pub bridge_contract: [u8; 20],
    pub rgb_asset_id: String,
    /// Operator-pinned allowed destination for **gas-key** transactions
    /// (`GAS_TX_ALLOWED_TO`). When set, `SignRawDigest` only signs a gas tx
    /// whose `to` equals this address (and whose `value` is 0) — audit
    /// TEE-XC-09. `None` = unset, which fails gas-tx signing closed in
    /// release builds.
    ///
    /// The pinned address should be an EOA, or a contract with no function
    /// the gas key could be coerced into calling to the operator's
    /// detriment: the transaction calldata is not inspected (see
    /// `networks::evm::gas_tx`).
    ///
    /// Unlike the three fields above, this is **not** folded into the
    /// attestation `user_data` bundle (`canonical_pubkey_bundle` in
    /// `server.rs`): it is an operational signing-policy pin, not part of
    /// the enclave's committed identity. It can be added to the bundle in a
    /// follow-up if external verifiability of the gas-tx policy is wanted.
    pub gas_tx_allowed_to: Option<[u8; 20]>,
}

impl BridgeConfig {
    /// Load from `EVM_CHAIN_ID` (decimal), `BRIDGE_CONTRACT` (0x-prefixed or
    /// bare 40-hex), `RGB_ASSET_ID` (string). Any missing/invalid field
    /// degrades to its zero/empty value; `is_configured()` reports whether
    /// the operator supplied anything at all.
    pub fn from_env() -> Self {
        let chain_id = std::env::var("EVM_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let bridge_contract = std::env::var("BRIDGE_CONTRACT")
            .ok()
            .and_then(|s| parse_eth_address(&s).ok())
            .unwrap_or([0u8; 20]);

        let rgb_asset_id = std::env::var("RGB_ASSET_ID").unwrap_or_default();

        let gas_tx_allowed_to = std::env::var("GAS_TX_ALLOWED_TO")
            .ok()
            .and_then(|s| parse_eth_address(&s).ok());

        Self {
            chain_id,
            bridge_contract,
            rgb_asset_id,
            gas_tx_allowed_to,
        }
    }

    /// True only when **all three** fields are set to non-zero / non-empty
    /// values (audit 4th M-03 / #94). Used to gate the strict cross-check:
    /// only a fully-pinned config authorises bridge signing.
    ///
    /// This is deliberately an AND, not an OR. The previous OR let a
    /// partially-pinned enclave report "configured" while a field was still
    /// zero, which had two bad consequences in `validate_evm_request`:
    /// a zero `chain_id` can never match a real request (rejected as
    /// `chain_id must be > 0`), so the enclave was permanently un-signable yet
    /// claimed configured; and a zero `bridge_contract` meant an EVM request
    /// for the **zero address** matched the pin and was accepted.
    ///
    /// Requiring all three closes both: a zero `chain_id` or zero
    /// `bridge_contract` is never treated as a valid pin. A fully-empty
    /// config (dev / mock builds) still degrades to the legacy
    /// "trust the request" path; a *partial* config is a misconfiguration —
    /// see [`is_partially_configured`](Self::is_partially_configured).
    pub fn is_configured(&self) -> bool {
        self.chain_id != 0 && self.bridge_contract != [0u8; 20] && !self.rgb_asset_id.is_empty()
    }

    /// True when the operator set **some but not all** pin fields. This is a
    /// botched production config (e.g. `EVM_CHAIN_ID` set but `BRIDGE_CONTRACT`
    /// left at the zero address), distinct from a fully-empty config that
    /// intentionally selects the legacy dev path. Callers fail closed on this
    /// rather than silently falling back to listener-trusting mode
    /// (audit 4th M-03 / #94).
    pub fn is_partially_configured(&self) -> bool {
        let any = self.chain_id != 0
            || self.bridge_contract != [0u8; 20]
            || !self.rgb_asset_id.is_empty();
        any && !self.is_configured()
    }
}

/// Parse `0xABCD…` (40 hex chars) or bare 40-hex into 20 bytes.
fn parse_eth_address(s: &str) -> Result<[u8; 20]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped)
        .map_err(|e| EnclaveError::InvalidRequest(format!("BRIDGE_CONTRACT not hex: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        EnclaveError::InvalidRequest(format!(
            "BRIDGE_CONTRACT must decode to 20 bytes, got {}",
            v.len()
        ))
    })
}

/// EVM JSON-RPC config for in-enclave `FundsIn` event verification (#60),
/// loaded at boot when the `evm-rpc` feature is built.
///
/// This is operational signing-plumbing, NOT part of the enclave's committed
/// identity: like [`BridgeConfig::gas_tx_allowed_to`], it is deliberately
/// **not** folded into the attestation `user_data` bundle.
///
/// TRUST BOUNDARY: `rpc_url` MUST be loopback. The enclave has no direct
/// network; it reaches the EVM RPC only through the loopback -> vsock
/// forwarder ([`crate::vsock_forwarder`]), so the responses are relayed by the
/// UNTRUSTED host. `verify_funds_in_event` treats them as evidence and fails
/// closed; full trustlessness needs Helios (#77).
#[cfg(feature = "evm-rpc")]
#[derive(Debug, Clone)]
pub struct EvmRpcConfig {
    /// Loopback URL of the in-enclave EVM RPC forwarder
    /// (`EVM_RPC_URL`, default `http://127.0.0.1:3444`).
    pub rpc_url: String,
    /// Minimum confirmation depth a `FundsIn` receipt must have, measured
    /// against the RPC head block (`EVM_MIN_CONFIRMATIONS`, default 12).
    pub min_confirmations: u64,
}

#[cfg(feature = "evm-rpc")]
impl EvmRpcConfig {
    /// Default loopback RPC URL - the enclave side of the EVM vsock forwarder.
    const DEFAULT_RPC_URL: &'static str = "http://127.0.0.1:3444";
    /// Default confirmation depth (~a safe head distance for most EVM chains).
    const DEFAULT_MIN_CONFIRMATIONS: u64 = 12;

    /// Load from `EVM_RPC_URL` and `EVM_MIN_CONFIRMATIONS`. Both fall back to
    /// safe defaults. A non-loopback `EVM_RPC_URL` is rejected back to the
    /// default and logged: routing EVM RPC anywhere but the vsock forwarder
    /// would bypass the only sanctioned egress path.
    pub fn from_env() -> Self {
        let rpc_url = match std::env::var("EVM_RPC_URL") {
            Ok(url) if is_loopback_url(&url) => url,
            Ok(url) => {
                tracing::error!(
                    %url,
                    "EVM_RPC_URL is not loopback - ignoring and using the default vsock-forwarder \
                     URL; the enclave must reach the EVM RPC only via the loopback forwarder"
                );
                Self::DEFAULT_RPC_URL.to_string()
            }
            Err(_) => Self::DEFAULT_RPC_URL.to_string(),
        };
        let min_confirmations = std::env::var("EVM_MIN_CONFIRMATIONS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(Self::DEFAULT_MIN_CONFIRMATIONS);
        Self {
            rpc_url,
            min_confirmations,
        }
    }
}

#[cfg(feature = "evm-rpc")]
impl Default for EvmRpcConfig {
    fn default() -> Self {
        Self {
            rpc_url: Self::DEFAULT_RPC_URL.to_string(),
            min_confirmations: Self::DEFAULT_MIN_CONFIRMATIONS,
        }
    }
}

/// True if `url`'s host is exactly a loopback literal (`127.0.0.1`, `[::1]`, or
/// `localhost`). A deliberately narrow, dependency-free check - the enclave only
/// ever points this at its own loopback forwarder. Matches the host *exactly*
/// (after stripping scheme, userinfo, path, and port) so a look-alike authority
/// like `127.0.0.1.evil.com` or `localhost.evil.com` is NOT treated as loopback.
#[cfg(feature = "evm-rpc")]
fn is_loopback_url(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    // Drop path/query/fragment, then any `userinfo@` prefix.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // Strip the port. IPv6 literals are bracketed (`[::1]:8545`), so split off
    // the `]` first; otherwise the host is everything before the first `:`.
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        match rest.split_once(']') {
            // Valid IPv6 authority: `]` is followed by nothing or `:port`.
            Some((inner, after)) => {
                return inner == "::1" && (after.is_empty() || after.starts_with(':'))
            }
            None => hostport,
        }
    } else {
        hostport.split(':').next().unwrap_or(hostport)
    };
    host == "127.0.0.1" || host == "localhost"
}

/// Helios light-client config for TRUSTLESS in-enclave EVM event verification
/// (#77), loaded at boot when the `helios` feature is built.
///
/// Selection is runtime: [`HeliosConfig::from_env`] returns `Some` only when
/// `HELIOS_EXECUTION_RPC` is set - that is the signal to use the Helios-verified
/// provider instead of the raw alloy path (#60). Like [`EvmRpcConfig`], the RPC
/// URLs MUST be loopback (reached through vsock forwarders); Helios treats those
/// upstreams as untrusted and verifies them against the pinned checkpoint.
#[cfg(feature = "helios")]
#[derive(Debug, Clone)]
pub struct HeliosConfig {
    /// Untrusted execution RPC Helios verifies against (`HELIOS_EXECUTION_RPC`,
    /// required - typically the local exec forwarder `http://127.0.0.1:18545`).
    /// Its presence is the signal to select the Helios-verified path.
    pub execution_rpc: String,
    /// Consensus (beacon) RPC for light-client sync (`HELIOS_CONSENSUS_RPC`,
    /// loopback forwarder, default `http://127.0.0.1:18550`).
    pub consensus_rpc: String,
    /// Helios network name: `mainnet` | `sepolia` | `holesky`
    /// (`HELIOS_NETWORK`, default `mainnet`).
    pub network: String,
    /// Weak-subjectivity checkpoint: 0x-prefixed 32-byte beacon block root
    /// (`HELIOS_CHECKPOINT`). Required for a trustless build - without it Helios
    /// would fall back to an untrusted community checkpoint list, which the
    /// enclave never enables. `None` here fails client init closed.
    pub checkpoint: Option<String>,
    /// Reject a checkpoint older than the safe weak-subjectivity window
    /// (`HELIOS_STRICT_CHECKPOINT_AGE`, default `true`).
    pub strict_checkpoint_age: bool,
}

#[cfg(feature = "helios")]
impl HeliosConfig {
    const DEFAULT_CONSENSUS_RPC: &'static str = "http://127.0.0.1:18550";

    /// Load from `HELIOS_*` env. Returns `None` when `HELIOS_EXECUTION_RPC` is
    /// unset (the raw alloy path is used instead). A non-loopback RPC URL is
    /// logged as an error but kept - the enclave has no direct egress, so a
    /// non-loopback URL simply won't connect.
    pub fn from_env() -> Option<Self> {
        let execution_rpc = std::env::var("HELIOS_EXECUTION_RPC").ok()?;
        warn_if_not_loopback("HELIOS_EXECUTION_RPC", &execution_rpc);

        let consensus_rpc = std::env::var("HELIOS_CONSENSUS_RPC")
            .unwrap_or_else(|_| Self::DEFAULT_CONSENSUS_RPC.to_string());
        warn_if_not_loopback("HELIOS_CONSENSUS_RPC", &consensus_rpc);

        let network = std::env::var("HELIOS_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        let checkpoint = std::env::var("HELIOS_CHECKPOINT").ok();
        let strict_checkpoint_age = std::env::var("HELIOS_STRICT_CHECKPOINT_AGE")
            .ok()
            .map(|s| s != "false" && s != "0")
            .unwrap_or(true);

        Some(Self {
            execution_rpc,
            consensus_rpc,
            network,
            checkpoint,
            strict_checkpoint_age,
        })
    }
}

#[cfg(feature = "helios")]
fn warn_if_not_loopback(var: &str, url: &str) {
    if !is_loopback_url(url) {
        tracing::error!(
            %var, %url,
            "Helios RPC URL is not loopback - the enclave reaches upstreams only via the vsock \
             forwarder; a non-loopback URL will not connect"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eth_address_with_prefix() {
        let a = parse_eth_address("0x0102030405060708090a0b0c0d0e0f1011121314").unwrap();
        assert_eq!(
            a,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        );
    }

    #[test]
    fn parse_eth_address_without_prefix() {
        let a = parse_eth_address("0102030405060708090a0b0c0d0e0f1011121314").unwrap();
        assert_eq!(a[0], 1);
        assert_eq!(a[19], 20);
    }

    #[test]
    fn parse_eth_address_rejects_wrong_length() {
        assert!(parse_eth_address("0xabcd").is_err());
    }

    #[test]
    fn parse_eth_address_rejects_non_hex() {
        assert!(parse_eth_address("0xzz02030405060708090a0b0c0d0e0f1011121314").is_err());
    }

    #[test]
    fn unconfigured_when_all_unset() {
        let c = BridgeConfig {
            chain_id: 0,
            bridge_contract: [0u8; 20],
            rgb_asset_id: String::new(),
            gas_tx_allowed_to: None,
        };
        assert!(!c.is_configured());
        assert!(!c.is_partially_configured());
    }

    #[test]
    fn configured_only_when_all_three_set() {
        let c = BridgeConfig {
            chain_id: 1,
            bridge_contract: [1u8; 20],
            rgb_asset_id: "rgb:asset".into(),
            gas_tx_allowed_to: None,
        };
        assert!(c.is_configured());
        assert!(!c.is_partially_configured());
    }

    #[test]
    fn partial_config_is_not_configured() {
        // chain_id set, contract still zero, asset set: a botched pin. The
        // OR-logic bug (#94) used to report this "configured" and then accept
        // an EVM request for the zero address.
        let c = BridgeConfig {
            chain_id: 1,
            bridge_contract: [0u8; 20],
            rgb_asset_id: "rgb:asset".into(),
            gas_tx_allowed_to: None,
        };
        assert!(!c.is_configured());
        assert!(c.is_partially_configured());
    }

    #[test]
    fn zero_chain_id_is_not_configured() {
        let c = BridgeConfig {
            chain_id: 0,
            bridge_contract: [1u8; 20],
            rgb_asset_id: "rgb:asset".into(),
            gas_tx_allowed_to: None,
        };
        assert!(!c.is_configured());
        assert!(c.is_partially_configured());
    }

    #[cfg(feature = "evm-rpc")]
    #[test]
    fn loopback_url_accepts_real_loopback() {
        assert!(is_loopback_url("http://127.0.0.1:3444"));
        assert!(is_loopback_url("http://127.0.0.1"));
        assert!(is_loopback_url("http://localhost:8545"));
        assert!(is_loopback_url("http://[::1]:18545/path"));
        assert!(is_loopback_url("http://[::1]"));
        assert!(is_loopback_url("http://user:pass@127.0.0.1:3444"));
    }

    #[cfg(feature = "evm-rpc")]
    #[test]
    fn loopback_url_rejects_lookalike_authorities() {
        // The old `starts_with` check accepted all of these.
        assert!(!is_loopback_url("http://127.0.0.1.evil.com"));
        assert!(!is_loopback_url("http://localhost.evil.com/rpc"));
        assert!(!is_loopback_url("http://127.0.0.1@evil.com"));
        assert!(!is_loopback_url("http://[::1].evil.com"));
        assert!(!is_loopback_url("http://10.0.0.1:8545"));
        assert!(!is_loopback_url("http://evil.com/127.0.0.1"));
    }
}
