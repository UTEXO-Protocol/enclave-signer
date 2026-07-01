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
    /// `validation::evm_gas_tx`).
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
    /// bare 40-hex), `RGB_ASSET_ID` (string), and `GAS_TX_ALLOWED_TO`
    /// (0x-prefixed or bare 40-hex). Any missing/invalid field degrades to
    /// its zero/empty/`None` value; `is_configured()` reports whether the
    /// operator supplied any of the three identity pins at all.
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
}
