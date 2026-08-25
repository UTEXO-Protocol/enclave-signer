//! Canonical encoding of the enclave's attested security policy.
//!
//! The enclave's posture is resolved once at boot, serialized here, and folded
//! into the attestation `user_data` commitment alongside the public-key bundle
//! (see `enclave/src/server.rs::handle_get_attested_public_key`).
//!
//! This module is the single source of truth for that serialization, so the
//! enclave and every verifier (the `attest-verify` CLI, the cloning peer check)
//! produce identical bytes. Both build an [`AttestedPolicy`] and call
//! [`AttestedPolicy::to_bytes`]; a posture mismatch shows up as a `user_data`
//! hash mismatch.
//!
//! Wire contract: the discriminants and field order are load-bearing. Never
//! renumber a variant or reorder fields - bump [`POLICY_COMMITMENT_V2`] and add
//! a new arm instead.
//!
//! V2 extends the `Production` arm with the gas-tx signing rule,
//! so the whole `SignRawDigest` policy is externally verifiable.

/// Version tag prepended to every policy commitment. Lets a verifier reject a
/// document produced by an enclave speaking a different policy-encoding version
/// instead of silently mis-hashing it.
///
/// V2 added the gas-tx rule to the `Production` arm; V1 predated
/// it. Bumping the tag means a V1 verifier and a V2 enclave never silently
/// agree on a hash.
pub const POLICY_COMMITMENT_V2: u8 = 2;

/// Where the enclave gets the EVM `FundsIn` deposit evidence it verifies before
/// signing an EVM->RGB bridge PSBT. Attested so a verifier can tell a trustless
/// deployment (Helios) apart from a host-relayed one (raw RPC) - the shipped
/// image currently uses [`RawRpc`](EvmDataSource::RawRpc).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmDataSource {
    /// No in-enclave EVM verification compiled in (`evm-rpc` off). Bridge
    /// EVM->RGB signing fails closed per request.
    Disabled = 0,
    /// Host-relayed JSON-RPC (`evm-rpc`): treated as evidence, verified
    /// fail-closed, but NOT trustless - the host relays the responses.
    RawRpc = 1,
    /// Helios light client (`helios`): the RPC is cryptographically verified
    /// against a pinned weak-subjectivity checkpoint before use (trustless).
    HeliosVerified = 2,
}

/// Where the enclave gets the Bitcoin anchor evidence for RGB consignment
/// witness txs. Only the SPV-verified source is safe, so a
/// production build always reports [`SpvVerified`](BtcDataSource::SpvVerified).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcDataSource {
    /// Witness txids re-anchored against the enclave's own PoW-verified header
    /// chain (`spv`), not the host-controlled Esplora resolver.
    SpvVerified = 1,
}

/// Whether the attestation root of trust is a real NSM device or the zero-PCR
/// mock. Mock is a `compile_error!` in release builds, so a production policy is
/// always [`Real`](AttestationMode::Real); committed anyway so the posture is
/// one self-contained value.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationMode {
    Mock = 0,
    Real = 1,
}

/// The enclave's whole security posture in commitment form.
///
/// [`Production`](AttestedPolicy::Production) is the fail-closed bridge-signing
/// posture: fully pinned, real attestation, SPV-anchored, with an explicit EVM
/// data source. A debug build, a dev feature, or an unpinned or non-bridge build
/// is [`Development`](AttestedPolicy::Development), which a verifier of a
/// production enclave must reject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestedPolicy {
    Production {
        allow_vanilla_psbt: bool,
        attestation: AttestationMode,
        evm_source: EvmDataSource,
        btc_source: BtcDataSource,
        chain_id: u64,
        bridge_contract: [u8; 20],
        rgb_asset_id: String,
        /// The Helios weak-subjectivity checkpoint (beacon block root) EVM
        /// verification trust-roots on. `Some` only for
        /// [`EvmDataSource::HeliosVerified`], and pinned here so a verifier
        /// confirms which checkpoint the enclave synced from.
        evm_checkpoint: Option<[u8; 32]>,
        /// Gas-tx (`SignRawDigest`) rule. Pinned destination
        /// (all-zero when the operator left `GAS_TX_ALLOWED_TO` unset, which
        /// fails the gas path closed), the gas/fee ceilings, and the allowlisted
        /// calldata selectors. Committed so a verifier confirms the gas policy
        /// the enclave enforces.
        gas_tx_allowed_to: [u8; 20],
        gas_tx_max_gas_limit: u64,
        gas_tx_max_fee_per_gas: u128,
        /// Ceiling (wei) on the native value a gas tx may carry, for the
        /// payable `lzFundsOutCall` carve-out. `0` commits "no non-zero value is
        /// signable", the same posture an unset `GAS_TX_MAX_VALUE_WEI` enforces,
        /// so being unpinned is itself attested.
        gas_tx_max_value_wei: u128,
        /// Permitted 4-byte calldata selectors. Canonicalised (sorted + deduped)
        /// by [`to_bytes`](AttestedPolicy::to_bytes) so the operator's env order
        /// never changes the commitment.
        gas_tx_allowed_selectors: Vec<[u8; 4]>,
    },
    Development,
}

impl AttestedPolicy {
    /// Deterministic, length-prefixed encoding folded into attestation
    /// `user_data`. Layout (see the WIRE CONTRACT note in the module docs):
    ///
    /// ```text
    /// [POLICY_COMMITMENT_V2]
    /// Production:  [0x01][allow_vanilla u8][attestation u8][evm_source u8]
    ///              [btc_source u8][chain_id u64 BE][bridge_contract 20]
    ///              [len(asset) u32 BE][asset bytes]
    ///              [evm_checkpoint: 0x00 | 0x01 ++ 32 bytes]
    ///              [gas_tx_allowed_to 20][gas_tx_max_gas_limit u64 BE]
    ///              [gas_tx_max_fee_per_gas u128 BE]
    ///              [gas_tx_max_value_wei u128 BE]
    ///              [len(selectors) u32 BE][selector 4]...   (sorted, deduped)
    /// Development: [0x00]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(POLICY_COMMITMENT_V2);
        match self {
            AttestedPolicy::Production {
                allow_vanilla_psbt,
                attestation,
                evm_source,
                btc_source,
                chain_id,
                bridge_contract,
                rgb_asset_id,
                evm_checkpoint,
                gas_tx_allowed_to,
                gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas,
                gas_tx_max_value_wei,
                gas_tx_allowed_selectors,
            } => {
                out.push(0x01);
                out.push(*allow_vanilla_psbt as u8);
                out.push(*attestation as u8);
                out.push(*evm_source as u8);
                out.push(*btc_source as u8);
                out.extend_from_slice(&chain_id.to_be_bytes());
                out.extend_from_slice(bridge_contract);
                out.extend_from_slice(&(rgb_asset_id.len() as u32).to_be_bytes());
                out.extend_from_slice(rgb_asset_id.as_bytes());
                // EVM verification checkpoint: a presence byte plus, when
                // present, the 32-byte Helios beacon block root. Pins which
                // checkpoint, so an attacker-chosen trust root cannot hide
                // behind an identical mode byte.
                match evm_checkpoint {
                    Some(cp) => {
                        out.push(0x01);
                        out.extend_from_slice(cp);
                    }
                    None => out.push(0x00),
                }
                // Gas-tx rule.
                out.extend_from_slice(gas_tx_allowed_to);
                out.extend_from_slice(&gas_tx_max_gas_limit.to_be_bytes());
                out.extend_from_slice(&gas_tx_max_fee_per_gas.to_be_bytes());
                out.extend_from_slice(&gas_tx_max_value_wei.to_be_bytes());
                // Canonicalise the selector set: sort + dedup so the operator's
                // env ordering (or duplicates) never changes the commitment.
                let mut selectors = gas_tx_allowed_selectors.clone();
                selectors.sort_unstable();
                selectors.dedup();
                out.extend_from_slice(&(selectors.len() as u32).to_be_bytes());
                for sel in &selectors {
                    out.extend_from_slice(sel);
                }
            }
            AttestedPolicy::Development => {
                out.push(0x00);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parametrized production policy so each test varies exactly one field.
    /// Gas-tx fields are fixed here; the gas-specific tests below vary them.
    fn prod(
        vanilla: bool,
        evm: EvmDataSource,
        chain_id: u64,
        contract: u8,
        asset: &str,
    ) -> AttestedPolicy {
        AttestedPolicy::Production {
            allow_vanilla_psbt: vanilla,
            attestation: AttestationMode::Real,
            evm_source: evm,
            btc_source: BtcDataSource::SpvVerified,
            chain_id,
            bridge_contract: [contract; 20],
            rgb_asset_id: asset.into(),
            evm_checkpoint: None,
            gas_tx_allowed_to: [0xAA; 20],
            gas_tx_max_gas_limit: 21_000,
            gas_tx_max_fee_per_gas: 1_000,
            gas_tx_max_value_wei: 0,
            gas_tx_allowed_selectors: vec![[0xde, 0xad, 0xbe, 0xef]],
        }
    }

    fn base() -> AttestedPolicy {
        prod(false, EvmDataSource::RawRpc, 1, 0x11, "rgb:asset")
    }

    /// `base()` with the gas-tx fields overridden, for the gas tests.
    fn base_with_gas(
        to: [u8; 20],
        max_gas: u64,
        max_fee: u128,
        max_value: u128,
        selectors: Vec<[u8; 4]>,
    ) -> AttestedPolicy {
        match base() {
            AttestedPolicy::Production {
                allow_vanilla_psbt,
                attestation,
                evm_source,
                btc_source,
                chain_id,
                bridge_contract,
                rgb_asset_id,
                evm_checkpoint,
                ..
            } => AttestedPolicy::Production {
                allow_vanilla_psbt,
                attestation,
                evm_source,
                btc_source,
                chain_id,
                bridge_contract,
                rgb_asset_id,
                evm_checkpoint,
                gas_tx_allowed_to: to,
                gas_tx_max_gas_limit: max_gas,
                gas_tx_max_fee_per_gas: max_fee,
                gas_tx_max_value_wei: max_value,
                gas_tx_allowed_selectors: selectors,
            },
            AttestedPolicy::Development => unreachable!(),
        }
    }

    #[test]
    fn every_encoding_starts_with_the_version_tag() {
        assert_eq!(base().to_bytes()[0], POLICY_COMMITMENT_V2);
        assert_eq!(
            AttestedPolicy::Development.to_bytes()[0],
            POLICY_COMMITMENT_V2
        );
    }

    #[test]
    fn production_and_development_never_collide() {
        assert_ne!(base().to_bytes(), AttestedPolicy::Development.to_bytes());
    }

    #[test]
    fn every_posture_field_changes_the_bytes() {
        let cases = [
            prod(true, EvmDataSource::RawRpc, 1, 0x11, "rgb:asset"),
            prod(false, EvmDataSource::HeliosVerified, 1, 0x11, "rgb:asset"),
            prod(false, EvmDataSource::RawRpc, 2, 0x11, "rgb:asset"),
            prod(false, EvmDataSource::RawRpc, 1, 0x22, "rgb:asset"),
            prod(false, EvmDataSource::RawRpc, 1, 0x11, "rgb:other"),
        ];
        for c in cases {
            assert_ne!(
                c.to_bytes(),
                base().to_bytes(),
                "posture change must alter the commitment"
            );
        }
    }

    #[test]
    fn evm_checkpoint_presence_and_value_change_the_bytes() {
        // No checkpoint vs a pinned checkpoint must differ: a verifier
        // expecting a specific trust root rejects one that pins none.
        let none = base();
        let mut with_cp = base();
        if let AttestedPolicy::Production {
            ref mut evm_checkpoint,
            ..
        } = with_cp
        {
            *evm_checkpoint = Some([0xAB; 32]);
        }
        assert_ne!(none.to_bytes(), with_cp.to_bytes());

        // Two different checkpoints must also differ - the value is bound, not
        // just its presence.
        let mut other_cp = base();
        if let AttestedPolicy::Production {
            ref mut evm_checkpoint,
            ..
        } = other_cp
        {
            *evm_checkpoint = Some([0xCD; 32]);
        }
        assert_ne!(with_cp.to_bytes(), other_cp.to_bytes());
    }

    #[test]
    fn asset_is_length_prefixed_not_ambiguous() {
        // The u32 length prefix means a longer asset id can never be confused
        // with a shorter one that happens to share a prefix.
        let a = prod(false, EvmDataSource::RawRpc, 1, 0x11, "ab");
        let b = prod(false, EvmDataSource::RawRpc, 1, 0x11, "abc");
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    // ---- gas-tx rule commitment ----

    #[test]
    fn every_gas_tx_field_changes_the_bytes() {
        let base_gas = base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![[1, 2, 3, 4]]);
        let cases = [
            base_with_gas([0xBB; 20], 21_000, 1_000, 0, vec![[1, 2, 3, 4]]), // destination
            base_with_gas([0xAA; 20], 30_000, 1_000, 0, vec![[1, 2, 3, 4]]), // gas cap
            base_with_gas([0xAA; 20], 21_000, 2_000, 0, vec![[1, 2, 3, 4]]), // fee cap
            base_with_gas([0xAA; 20], 21_000, 1_000, 5, vec![[1, 2, 3, 4]]), // value ceiling
            base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![[9, 9, 9, 9]]), // selector
            base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![]),             // no selectors
        ];
        for c in cases {
            assert_ne!(
                c.to_bytes(),
                base_gas.to_bytes(),
                "a gas-tx rule change must alter the commitment"
            );
        }
    }

    #[test]
    fn selector_allowlist_is_order_and_dup_independent() {
        // The commitment canonicalises selectors, so operator env ordering and
        // duplicate entries never change the attested bytes.
        let a = base_with_gas(
            [0xAA; 20],
            21_000,
            1_000,
            0,
            vec![[1, 1, 1, 1], [2, 2, 2, 2]],
        );
        let b = base_with_gas(
            [0xAA; 20],
            21_000,
            1_000,
            0,
            vec![[2, 2, 2, 2], [1, 1, 1, 1], [1, 1, 1, 1]],
        );
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn selector_count_is_length_prefixed() {
        // A different number of selectors changes the length prefix, so a set
        // can never be confused with a longer one sharing a prefix.
        let one = base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![[1, 1, 1, 1]]);
        let two = base_with_gas(
            [0xAA; 20],
            21_000,
            1_000,
            0,
            vec![[1, 1, 1, 1], [2, 2, 2, 2]],
        );
        assert_ne!(one.to_bytes(), two.to_bytes());
    }
}
