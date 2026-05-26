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

        Self {
            chain_id,
            bridge_contract,
            rgb_asset_id,
        }
    }

    /// True if any of the three fields was set via env. Used to gate the
    /// strict cross-check: when no operator config is present we fall back
    /// to the legacy "trust the request" behaviour so dev / mock builds
    /// keep working without ceremony.
    pub fn is_configured(&self) -> bool {
        self.chain_id != 0 || self.bridge_contract != [0u8; 20] || !self.rgb_asset_id.is_empty()
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
        };
        assert!(!c.is_configured());
    }

    #[test]
    fn configured_when_any_set() {
        let c = BridgeConfig {
            chain_id: 1,
            bridge_contract: [0u8; 20],
            rgb_asset_id: String::new(),
        };
        assert!(c.is_configured());
    }
}
