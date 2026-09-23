//! RGB source validation: everything owned by the `RgbSource` payload, from
//! field shape through to the SPV cross-check of its witness transactions.

use super::asset_bind::{assert_asset_binding, AssetBindMode};
use super::types::ValidatedConsignment;
use crate::config::BridgeConfig;
use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::rgb::spv_crosscheck;
use crate::networks::ValidationContext;
use crate::proto::RgbSource;
use sha3::{Digest, Keccak256};
use std::time::SystemTime;

/// Validate all fields and source-chain evidence owned by an RGB source.
///
/// Does not inspect the destination network. The source-chain proof is:
///
/// 1. raw consignment bytes must be present, hash-bound, and pass full
///    in-enclave RGB validation;
/// 2. the validated consignment asset must match the listener-declared
///    `asset_id` and, when configured, the operator-pinned `RGB_ASSET_ID`;
/// 3. when built with `spv`, every consignment witness tx must have a matching
///    Merkle proof against the in-enclave Bitcoin header chain with sufficient
///    confirmations;
/// 4. when built without `spv`, reject any supplied Merkle proofs so build
///    mismatches fail closed instead of silently ignoring host-provided SPV
///    evidence.
pub fn validate_source(
    source: &RgbSource,
    ctx: &ValidationContext<'_>,
) -> Result<ValidatedConsignment> {
    validate_source_payload(source, ctx.bridge_config)?;

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "RGB source validation requires rgb_validator to be configured".into(),
        )
    })?;

    // A burn consignment carries its whole mint ancestry, and every one of those
    // mint transitions ends in `cea` - consensus re-runs them, so it needs the
    // locks the enclave verified for itself.
    let validated = validator.validate_consignment(&source.consignment, ctx.bridge_events)?;

    assert_asset_binding(
        &validated.contract_id,
        &source.asset_id,
        ctx.bridge_config,
        AssetBindMode::Source,
    )?;

    {
        let chain = ctx
            .header_chain
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("SPV header chain lock poisoned: {e}")))?;
        spv_crosscheck::validate_source_chain(
            &chain,
            Some(&validated),
            &source.merkle_proofs,
            SystemTime::now(),
            ctx.chain_pins,
        )?;
    }

    Ok(validated)
}

/// Aggregate size/compute cap (operator-configurable via
/// `MAX_CONSIGNMENT_BYTES`), enforced before the keccak hash and the rgbstd
/// parse so a request cannot force disproportionate work while staying under
/// every per-field cap.
///
/// `label` names the direction in the rejection, e.g. `"RGB source"` or
/// `"send-RGB"`. Shared so that lowering the cap cannot produce a different
/// message depending on which caller happens to run first.
pub fn assert_consignment_size(consignment: &[u8], cfg: &BridgeConfig, label: &str) -> Result<()> {
    if consignment.len() > cfg.max_consignment_bytes {
        return Err(EnclaveError::CrossCheck(format!(
            "{label} consignment too large: {} bytes (max {})",
            consignment.len(),
            cfg.max_consignment_bytes
        )));
    }
    Ok(())
}

pub(super) fn validate_source_payload(source: &RgbSource, cfg: &BridgeConfig) -> Result<()> {
    if source.consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB source requires raw consignment bytes; consignment_valid is not authoritative"
                .into(),
        ));
    }
    assert_consignment_size(&source.consignment, cfg, "RGB source")?;
    if source.merkle_proofs.len() > cfg.max_merkle_proofs {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source carries too many merkle proofs: {} (max {})",
            source.merkle_proofs.len(),
            cfg.max_merkle_proofs
        )));
    }
    let total_proof_bytes: usize = source
        .merkle_proofs
        .iter()
        .map(|p| p.txid.len() + p.merkle_path.iter().map(|s| s.len()).sum::<usize>())
        .sum();
    if total_proof_bytes > cfg.max_total_proof_bytes {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source merkle proofs too large in aggregate: {total_proof_bytes} bytes (max {})",
            cfg.max_total_proof_bytes
        )));
    }
    // Integrity, NOT authorization: the listener
    // controls both `consignment` and `consignment_hash`, so a match only
    // proves the wire copy was not corrupted. Authorization comes from the
    // in-enclave RGB validation, SPV anchoring, and the binding of validated
    // facts (contract_id / op_id / amount).
    if source.consignment_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "consignment present but consignment_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(&source.consignment);
    if computed[..] != source.consignment_hash {
        return Err(EnclaveError::CrossCheck(
            "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
        ));
    }
    if source.asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB source asset_id is empty".into(),
        ));
    }

    Ok(())
}
