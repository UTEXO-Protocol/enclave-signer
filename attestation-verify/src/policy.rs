//! Canonical encoding of the enclave's attested security policy (audit C-01).
//!
//! The enclave has ONE explicit security posture, resolved once at boot, that a
//! verifier can check as a single value. That posture is serialized here and
//! folded into the attestation `user_data` commitment alongside the public-key
//! bundle (see `enclave/src/server.rs::handle_get_attested_public_key`).
//!
//! This module is the SINGLE source of truth for that serialization so the
//! enclave (which commits it) and every verifier (the parent `attest-verify`
//! CLI, the cloning peer check) produce byte-identical bytes. Both sides build
//! an [`AttestedPolicy`] and call [`AttestedPolicy::to_bytes`]; if the enclave's
//! committed posture differs from the one the verifier expects, the `user_data`
//! hash will not match and verification fails.
//!
//! WIRE CONTRACT: the discriminants and field order below are load-bearing.
//! Never renumber an existing variant or reorder fields — bump
//! [`POLICY_COMMITMENT_V1`] and add a new arm to evolve the format.

/// Version tag prepended to every policy commitment. Lets a verifier reject a
/// document produced by an enclave speaking a different policy-encoding version
/// instead of silently mis-hashing it.
pub const POLICY_COMMITMENT_V1: u8 = 1;

/// Where the enclave gets the EVM `FundsIn` deposit evidence it verifies before
/// signing an EVM->RGB bridge PSBT. Attested so a verifier can tell a trustless
/// deployment (Helios) apart from a host-relayed one (raw RPC) — the shipped
/// image currently uses [`RawRpc`](EvmDataSource::RawRpc).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmDataSource {
    /// No in-enclave EVM verification compiled in (`evm-rpc` off). Bridge
    /// EVM->RGB signing fails closed per request.
    Disabled = 0,
    /// Host-relayed JSON-RPC (`evm-rpc`): treated as evidence, verified
    /// fail-closed, but NOT trustless — the host relays the responses.
    RawRpc = 1,
    /// Helios light client (`helios`): the RPC is cryptographically verified
    /// against a pinned weak-subjectivity checkpoint before use (trustless).
    HeliosVerified = 2,
}

/// Where the enclave gets the Bitcoin anchor evidence for RGB consignment
/// witness txs. Only the SPV-verified source is safe (audit M-01 / #61), so a
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
/// always [`Real`](AttestationMode::Real); the value is committed anyway so the
/// posture stands alone as one attested value.
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
/// data source. Anything else — a debug build, a dev feature, an unpinned or
/// non-bridge build — is [`Development`](AttestedPolicy::Development), which a
/// verifier of a production enclave must reject.
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
    },
    Development,
}

impl AttestedPolicy {
    /// Deterministic, length-prefixed encoding folded into attestation
    /// `user_data`. Layout (see the WIRE CONTRACT note in the module docs):
    ///
    /// ```text
    /// [POLICY_COMMITMENT_V1]
    /// Production:  [0x01][allow_vanilla u8][attestation u8][evm_source u8]
    ///              [btc_source u8][chain_id u64 BE][bridge_contract 20]
    ///              [len(asset) u32 BE][asset bytes]
    /// Development: [0x00]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(POLICY_COMMITMENT_V1);
        match self {
            AttestedPolicy::Production {
                allow_vanilla_psbt,
                attestation,
                evm_source,
                btc_source,
                chain_id,
                bridge_contract,
                rgb_asset_id,
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
        }
    }

    fn base() -> AttestedPolicy {
        prod(false, EvmDataSource::RawRpc, 1, 0x11, "rgb:asset")
    }

    #[test]
    fn every_encoding_starts_with_the_version_tag() {
        assert_eq!(base().to_bytes()[0], POLICY_COMMITMENT_V1);
        assert_eq!(
            AttestedPolicy::Development.to_bytes()[0],
            POLICY_COMMITMENT_V1
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
    fn asset_is_length_prefixed_not_ambiguous() {
        // The u32 length prefix means a longer asset id can never be confused
        // with a shorter one that happens to share a prefix.
        let a = prod(false, EvmDataSource::RawRpc, 1, 0x11, "ab");
        let b = prod(false, EvmDataSource::RawRpc, 1, 0x11, "abc");
        assert_ne!(a.to_bytes(), b.to_bytes());
    }
}
