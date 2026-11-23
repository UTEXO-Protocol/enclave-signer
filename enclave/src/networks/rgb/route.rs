//! Route-level RGB validation: the entry points that `networks::route` calls.
//!
//! This layer only selects the check for this build. The checks are in the
//! sibling modules: consignment parsing and rgb-lib validation in
//! [`super::validation`], PSBT anchoring in [`super::psbt_validation`], the
//! mint signer's PSBT core in [`super::psbt_commit`], and per-flow rules in
//! [`super::flow`].
//!
//! The mint signer validates from the PSBT and its fascia alone. Every other
//! RGB build validates a consignment.

#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
use super::flow;
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
use super::psbt_commit;
#[cfg(evm_to_rgb)]
use super::psbt_validation;
#[cfg(feature = "rgb-validation")]
use super::validation;
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
use crate::config::BridgeConfig;
#[cfg(not(feature = "rgb-validation"))]
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
pub fn validate_destination(destination: &RgbDestination) -> Result<()> {
    psbt_validation::validate_psbt_bytes(&destination.psbt_bytes)
}

/// Without `rgb-validation` no fascia proves the minted units, so an RGB destination is refused.
#[cfg(all(not(feature = "rgb-validation"), evm_to_rgb))]
pub fn validate_destination_anchor(
    _destination: &RgbDestination,
    _source_amount: u64,
    _source_commission: u64,
    _ctx: &ValidationContext<'_>,
) -> Result<u64> {
    Err(EnclaveError::CrossCheck(
        "an RGB destination needs rgb-validation to prove its minted units".into(),
    ))
}

/// The mint its PSBT and fascia commit, bound to the deposit (F1-F7, M1-M9).
/// Returns the minted units.
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
pub fn validate_destination_anchor(
    destination: &RgbDestination,
    source_amount: u64,
    source_commission: u64,
    ctx: &ValidationContext<'_>,
) -> Result<u64> {
    let psbt = psbt_validation::parse_psbt_shape(&destination.psbt_bytes)?;
    psbt_validation::assert_mint_shape(&psbt)?;
    psbt_validation::assert_txid_and_sighash_fixed(&psbt)?;
    let committed = pinned_commitment(
        &psbt,
        &destination.fascia,
        &destination.asset_id,
        ctx.bridge_config,
        schemata::TS_MINT,
        psbt_commit::MAX_SIDE_TRANSITIONS,
    )?;
    let mint = psbt_validation::mint_facts(&committed)?;
    psbt_validation::assert_mints_net_deposit(&mint, source_amount, source_commission)?;
    let colored = mint_inputs(&psbt, ctx)?;
    // Pinned fee policy, shared with the plain-BTC path. No fee estimate is
    // fetched: the host controls that egress.
    psbt_validation::check_psbt_fee(&psbt, &colored, "mint")?;
    let mint_outputs = ctx.mint_outputs.ok_or_else(|| {
        crate::error::EnclaveError::CrossCheck(
            "mint cannot be signed: no outputs check is wired in".into(),
        )
    })?;
    mint_outputs(&psbt, &mint.recipient, &committed.moved_to)?;
    // Last: the only network read on this path.
    let bind = ctx.mint_binder.ok_or_else(|| {
        crate::error::EnclaveError::CrossCheck(
            "mint cannot be bound: no deposit binder is wired in".into(),
        )
    })?;
    bind(&mint)?;
    Ok(mint.issued)
}

/// F3-F6 on the PSBT's tx and its `fascia` under the `RGB_ASSET_ID` pin, which
/// `asset_id` must name too. Returns what the tx commits around its one
/// transition of type `main`, with at most `max_side` side transitions.
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
fn pinned_commitment(
    psbt: &bitcoin::psbt::Psbt,
    fascia: &[u8],
    asset_id: &str,
    cfg: &BridgeConfig,
    main: rgbstd::TransitionType,
    max_side: usize,
) -> Result<psbt_commit::Committed> {
    let pin = psbt_commit::Pin::of(cfg)?;
    let parsed = psbt_commit::parse_fascia(fascia, "fascia")?;
    let committed =
        psbt_commit::committed_transition(psbt, parsed, fascia, "fascia", pin, main, max_side)?;
    validation::assert_asset_binding(
        &pin.contract.to_string(),
        asset_id,
        cfg,
        validation::AssetBindMode::Destination,
    )?;
    Ok(committed)
}

/// F7: the mint spends [`psbt_validation::MINT_INPUTS`] inputs, all Colored
/// key-path inputs of this enclave. Returns them, for the fee bound.
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
fn mint_inputs(psbt: &bitcoin::psbt::Psbt, ctx: &ValidationContext<'_>) -> Result<Vec<usize>> {
    use crate::error::EnclaveError;

    let inputs = psbt.unsigned_tx.input.len();
    if inputs != psbt_validation::MINT_INPUTS {
        return Err(EnclaveError::CrossCheck(format!(
            "mint PSBT spends {inputs} inputs - F7 allows {} input, and its sats pay the fee",
            psbt_validation::MINT_INPUTS
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

/// A refill from its PSBT and its fascia alone (F2-F6, RR6-RR8), no network.
/// Returns the new rights' vouts, which the caller proves ours (RR9).
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
pub fn validate_rights_refill(
    req: &SignRightsRefillRequest,
    psbt: &bitcoin::psbt::Psbt,
    cfg: &BridgeConfig,
) -> Result<Vec<u32>> {
    psbt_validation::assert_txid_and_sighash_fixed(psbt)?;
    // RR3: a refill commits its propagate only.
    let propagate = schemata::TS_PROPAGATE;
    let committed = pinned_commitment(psbt, &req.fascia, &req.asset_id, cfg, propagate, 0)?;
    psbt_validation::refill_rights(&committed)
}

#[cfg(all(test, feature = "rgb-validation"))]
mod tests;
