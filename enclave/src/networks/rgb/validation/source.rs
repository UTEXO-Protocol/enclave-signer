//! RGB source validation: all checks on the `RgbSource` payload, from field
//! shape to the SPV cross-check of its witness transactions.

#[cfg(rgb_to_evm)]
use super::asset_bind::{assert_asset_binding, AssetBindMode};
#[cfg(rgb_to_evm)]
use super::reject_list::ListAccess;
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

/// Validates the source payload, asset binding, mint backing and RGB history.
///
/// Every witness needs a proof at `SPV_MIN_CONFIRMATIONS` depth in the
/// enclave's header chain, with those blocks pinned until signing. An unmined
/// or shallow witness rejects the history.
///
/// The asset is bound before external reads. For listed assets, rgb-lib also
/// checks the burn and companion transfers for rejected ancestry.
/// Destination checks run separately.
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

    let proven = {
        let chain = lock_chain(ctx)?;
        spv_crosscheck::proven_witnesses(
            &chain,
            &source.merkle_proofs,
            ctx.bridge_config.spv_min_confirmations,
        )?
    };
    let bind_asset = |contract_id: &str| {
        assert_asset_binding(
            contract_id,
            &source.asset_id,
            ctx.bridge_config,
            AssetBindMode::Source,
        )
    };
    let lists = ListAccess {
        bind_asset: &bind_asset,
        read: ctx.reject_list_reader,
    };
    // A burn consignment contains its full mint ancestry. Each mint leaves an
    // anchor that only a bound lock confirms.
    let validated =
        validator.validate_consignment(&source.consignment, ctx.anchor_binder, &proven, &lists)?;

    {
        let chain = lock_chain(ctx)?;
        spv_crosscheck::validate_source_chain(
            &chain,
            Some(&validated),
            &source.merkle_proofs,
            SystemTime::now(),
            ctx.chain_pins,
            ctx.bridge_config.spv_min_confirmations,
        )?;
    }

    Ok(validated)
}

#[cfg(rgb_to_evm)]
fn lock_chain<'a>(
    ctx: &'a ValidationContext<'_>,
) -> Result<std::sync::MutexGuard<'a, crate::networks::rgb::spv::HeaderChain>> {
    ctx.header_chain
        .lock()
        .map_err(|e| EnclaveError::Internal(format!("SPV header chain lock poisoned: {e}")))
}

/// Total size cap (`MAX_CONSIGNMENT_BYTES`, set by the operator). It runs
/// before the keccak hash and the RGB parse. Thus a request under each
/// per-field cap cannot force too much work.
///
/// `label` names the consignment in the rejection, for example `"RGB source"`.
pub fn assert_consignment_size(consignment: &[u8], cfg: &BridgeConfig, label: &str) -> Result<()> {
    let max = crate::limits::in_force(cfg).max_consignment_bytes;
    if consignment.len() as u64 > max {
        return Err(EnclaveError::CrossCheck(format!(
            "{label} consignment too large: {} bytes (max {max})",
            consignment.len()
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
    let limits = crate::limits::in_force(cfg);
    if source.merkle_proofs.len() as u64 > limits.max_merkle_proofs {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source carries too many merkle proofs: {} (max {})",
            source.merkle_proofs.len(),
            limits.max_merkle_proofs
        )));
    }
    let total_proof_bytes: usize = source
        .merkle_proofs
        .iter()
        .map(|p| p.txid.len() + p.merkle_path.iter().map(|s| s.len()).sum::<usize>())
        .sum();
    if total_proof_bytes as u64 > limits.max_total_proof_bytes {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source merkle proofs too large in aggregate: {total_proof_bytes} bytes (max {})",
            limits.max_total_proof_bytes
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
