//! RGB source validation: all checks on the `RgbSource` payload, from field
//! shape to the SPV cross-check of its witness transactions.

#[cfg(rgb_to_evm)]
use super::asset_bind::{assert_asset_binding, AssetBindMode};
#[cfg(rgb_to_evm)]
use super::types::ValidatedConsignment;
use crate::config::BridgeConfig;
use crate::error::EnclaveError;
use crate::error::Result;
#[cfg(rgb_to_evm)]
use crate::networks::rgb::spv_crosscheck;
#[cfg(rgb_to_evm)]
use crate::networks::ValidationContext;
#[cfg(rgb_to_evm)]
use crate::proto::RgbSource;
#[cfg(rgb_to_evm)]
use sha3::{Digest, Keccak256};
#[cfg(rgb_to_evm)]
use std::time::SystemTime;

/// Validates all fields and source-chain evidence of an RGB source.
///
/// It does not examine the destination network. The source-chain proof is:
///
/// 1. raw consignment bytes are present, hash-bound, and pass full
///    in-enclave RGB validation;
/// 2. the validated asset matches the listener-declared `asset_id` and, if
///    configured, the operator-pinned `RGB_ASSET_ID`;
/// 3. each witness tx has a Merkle proof against the in-enclave header chain
///    with enough confirmations (`rgb-validation` requires `spv`).
#[cfg(rgb_to_evm)]
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

    // A burn consignment contains its full mint ancestry. Each mint transition
    // ends in `cea`, and consensus runs them again. Thus it needs the EVM locks
    // that the enclave verified.
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

/// Total size cap (`MAX_CONSIGNMENT_BYTES`, set by the operator). It runs
/// before the keccak hash and the rgbstd parse. Thus a request under each
/// per-field cap cannot force too much work.
///
/// `label` names the direction in the rejection, for example `"RGB source"`
/// or `"send-RGB"`. Both directions share it, so the message is the same.
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

#[cfg(rgb_to_evm)]
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
    // Integrity, NOT authorization. The listener controls both `consignment`
    // and `consignment_hash`, so a match only proves the wire copy is intact.
    // Authorization comes from RGB validation, SPV anchoring, and the bind of
    // validated facts (contract_id / op_id / amount).
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
