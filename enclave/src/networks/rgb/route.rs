//! Route-level RGB validation: the entry points that `networks::route` calls.
//!
//! This layer only selects the check for this build. The checks are in the
//! sibling modules: consignment parsing and rgb-lib validation in
//! [`super::validation`], PSBT anchoring in [`super::psbt_validation`], the
//! mint signer's PSBT core in [`super::psbt_commit`] and
//! [`super::parent_proof`], and per-flow rules in [`super::flow`].
//!
//! The mint signer validates from the PSBT, its fascia and its parent's fascia
//! alone. Every other RGB build validates a consignment.

#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
use super::flow;
#[cfg(evm_to_rgb)]
use super::psbt_validation;
#[cfg(feature = "rgb-validation")]
use super::validation;
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
use super::{parent_proof, psbt_commit};
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
use crate::config::BridgeConfig;
#[cfg(all(not(feature = "rgb-validation"), rgb_to_evm))]
use crate::error::EnclaveError;
use crate::error::Result;
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
use crate::networks::RouteProof;
use crate::networks::ValidationContext;
#[cfg(evm_to_rgb)]
use crate::proto::RgbDestination;
#[cfg(rgb_to_evm)]
use crate::proto::RgbSource;
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
use crate::proto::SignRightsRefillRequest;

/// Validates an RGB source. The route amount comes from the consignment,
/// never from the wire. The checks are in [`super::validation`].
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
pub fn validate_source(
    source: &RgbSource,
    ctx: &ValidationContext<'_>,
) -> Result<crate::networks::SourceProof> {
    let validated = validation::validate_source(source, ctx)?;
    let proof = route_proof_from_validated_consignment(&validated)?;
    Ok(crate::networks::SourceProof {
        proof,
        rgb_consignment: Some(validated),
    })
}

/// A build without RGB validation refuses every RGB source.
#[cfg(all(not(feature = "rgb-validation"), rgb_to_evm))]
pub fn validate_source(
    _source: &RgbSource,
    _ctx: &ValidationContext<'_>,
) -> Result<crate::networks::SourceProof> {
    Err(EnclaveError::CrossCheck(
        "RGB source validation requires the enclave to be built with --features rgb-validation"
            .into(),
    ))
}

#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
fn route_proof_from_validated_consignment(
    validated: &validation::ValidatedConsignment,
) -> Result<RouteProof> {
    use crate::error::EnclaveError;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "RGB source requires a consignment with at least one transition".into(),
        )
    })?;

    // The flow decides which transition proves the withdrawal and where its
    // amount is.
    let amount = flow::funds_out_source_amount(last)?;

    Ok(RouteProof { amount })
}

/// Validate fields owned by an RGB destination before route-level validation.
#[cfg(evm_to_rgb)]
pub fn validate_destination(
    destination: &RgbDestination,
    _ctx: &ValidationContext<'_>,
) -> Result<()> {
    psbt_validation::validate_psbt_bytes(&destination.psbt_bytes)
}

/// The mint its PSBT and fascia commit, bound to the deposit and the right's UTXO
/// (F1-F7, PP, M1-M8). Returns the units and the `utxob:` seal of a blinded mint.
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
pub fn validate_destination_anchor(
    destination: &RgbDestination,
    source_amount: u64,
    source_commission: u64,
    ctx: &ValidationContext<'_>,
) -> Result<(u64, Vec<String>)> {
    let psbt = psbt_validation::parse_psbt_shape(&destination.psbt_bytes)?;
    psbt_validation::assert_mint_shape(&psbt)?;
    psbt_validation::assert_txid_and_sighash_fixed(&psbt)?;
    let (pin, committed) = pinned_commitment(
        &psbt,
        &destination.fascia,
        &destination.asset_id,
        ctx.bridge_config,
    )?;
    let mint = psbt_validation::mint_facts(&committed)?;
    psbt_validation::assert_mints_net_deposit(&mint, source_amount, source_commission)?;
    let colored = mint_inputs(&psbt, ctx)?;
    parent_proof::right_input(&psbt, &destination.parent_fascia, mint.right, pin)?;
    // Pinned fee policy, shared with the plain-BTC path. No fee estimate is
    // fetched: the host controls that egress.
    psbt_validation::check_psbt_fee(&psbt, &colored, "mint")?;
    let mint_sats = ctx.mint_sats.ok_or_else(|| {
        crate::error::EnclaveError::CrossCheck(
            "mint cannot be signed: no sats check is wired in".into(),
        )
    })?;
    mint_sats(&psbt, &mint.recipient)?;
    // Last: the only network read on this path.
    let bind = ctx.mint_binder.ok_or_else(|| {
        crate::error::EnclaveError::CrossCheck(
            "mint cannot be bound: no deposit binder is wired in".into(),
        )
    })?;
    bind(&mint)?;
    Ok((mint.issued, mint.recipient.blinded_seals()))
}

/// F3-F6 on the PSBT's tx and its `fascia` under the `RGB_ASSET_ID` pin, which
/// `asset_id` must name too. Returns the pin and the committed transition.
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
fn pinned_commitment(
    psbt: &bitcoin::psbt::Psbt,
    fascia: &[u8],
    asset_id: &str,
    cfg: &BridgeConfig,
) -> Result<(rgbstd::ContractId, psbt_commit::Committed)> {
    let pin = psbt_commit::pinned_contract(cfg)?;
    let fascia = psbt_commit::parse_fascia(fascia, "fascia")?;
    let committed = psbt_commit::committed_transition(&psbt.unsigned_tx, &fascia, pin)?;
    validation::assert_asset_binding(
        &pin.to_string(),
        asset_id,
        cfg,
        validation::AssetBindMode::Destination,
    )?;
    Ok((pin, committed))
}

/// F7: the mint spends its right alone ([`psbt_validation::MINT_INPUTS`]), a
/// Colored key-path input of this enclave. Returns it, for the fee bound.
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
fn mint_inputs(psbt: &bitcoin::psbt::Psbt, ctx: &ValidationContext<'_>) -> Result<Vec<usize>> {
    use crate::error::EnclaveError;

    let inputs = psbt.unsigned_tx.input.len();
    if inputs != psbt_validation::MINT_INPUTS {
        return Err(EnclaveError::CrossCheck(format!(
            "mint PSBT spends {inputs} inputs - a mint spends its right alone, and that UTXO's \
             sats pay the fee"
        )));
    }
    let resolve_colored = ctx.psbt_fee_key_paths.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "mint cannot be bound: no key-path resolver is wired in, so the enclave cannot tell \
             which inputs it signs"
                .into(),
        )
    })?;
    let colored = resolve_colored(psbt)?;
    psbt_validation::assert_only_colored_inputs(psbt, &colored, "mint")?;
    Ok(colored)
}

/// A refill from its PSBT and the two fascias alone (F2-F6, RR6-RR8, RR11), no
/// network. Returns the new rights' vouts, which the caller proves ours (RR9).
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
pub fn validate_rights_refill(
    req: &SignRightsRefillRequest,
    psbt: &bitcoin::psbt::Psbt,
    cfg: &BridgeConfig,
) -> Result<Vec<u32>> {
    psbt_validation::assert_txid_and_sighash_fixed(psbt)?;
    let (pin, committed) = pinned_commitment(psbt, &req.fascia, &req.asset_id, cfg)?;
    let (right, vouts) = psbt_validation::refill_rights(&committed)?;
    parent_proof::right_input(psbt, &req.parent_fascia, right, pin)?;
    Ok(vouts)
}

#[cfg(all(test, feature = "rgb-validation"))]
mod tests;
