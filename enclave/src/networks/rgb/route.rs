//! Route-level RGB validation: the entry points `networks::route` calls.
//!
//! This is the dispatch layer only. It decides which check runs for this
//! build, then hands off. The checks themselves live in the sibling modules:
//! consignment parsing and rgbstd validation in [`super::validation`], PSBT
//! anchoring in [`super::psbt_validation`], per-flow rules in [`super::flow`].

#[cfg(feature = "rgb-validation")]
use super::flow;
use super::psbt_validation;
#[cfg(feature = "rgb-validation")]
use super::validation;
#[cfg(not(feature = "rgb-validation"))]
use crate::error::EnclaveError;
use crate::error::Result;
#[cfg(feature = "rgb-validation")]
use crate::networks::RouteProof;
use crate::networks::ValidationContext;
use crate::proto::{RgbDestination, RgbSource};
#[cfg(feature = "rgb-validation")]
use sha3::{Digest, Keccak256};

/// Validate an RGB source. The route amount is the consignment's, never the
/// wire's. Field-level checks, consignment validation, asset binding, and SPV
/// verification live in `validation.rs`.
#[cfg(feature = "rgb-validation")]
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
#[cfg(not(feature = "rgb-validation"))]
pub fn validate_source(
    _source: &RgbSource,
    _ctx: &ValidationContext<'_>,
) -> Result<crate::networks::SourceProof> {
    Err(EnclaveError::CrossCheck(
        "RGB source validation requires the enclave to be built with --features rgb-validation"
            .into(),
    ))
}

#[cfg(feature = "rgb-validation")]
fn route_proof_from_validated_consignment(
    validated: &validation::ValidatedConsignment,
) -> Result<RouteProof> {
    use crate::error::EnclaveError;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "RGB source requires a consignment with at least one transition".into(),
        )
    })?;

    // Which transition proves the withdrawal, and where its amount lives, is
    // the flow's business - see `flow/`.
    let amount = flow::funds_out_source_amount(last)?;

    Ok(RouteProof {
        amount,
        operation_id: Some(normalize_rgb_operation_id(&last.op_id)?),
    })
}

#[cfg(feature = "rgb-validation")]
fn normalize_rgb_operation_id(op_id: &str) -> Result<String> {
    use crate::error::EnclaveError;

    let normalized = op_id.strip_prefix("0x").unwrap_or(op_id);
    if normalized.len() != 64 {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB operation_id must be 32-byte hex, got {} hex chars",
            normalized.len()
        )));
    }
    if !normalized.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(EnclaveError::CrossCheck(
            "RGB operation_id is not hex-decodable".into(),
        ));
    }

    Ok(normalized.to_ascii_lowercase())
}

/// Validate fields owned by an RGB destination before route-level validation.
pub fn validate_destination(
    destination: &RgbDestination,
    _ctx: &ValidationContext<'_>,
) -> Result<()> {
    psbt_validation::validate_psbt_bytes(&destination.psbt_bytes)
}

/// Returns the **recipient leg** of the bound consignment in asset units - see
/// [`psbt_validation::validate_psbt_anchors_transition`]. This is the
/// enclave-derived destination amount the route-level cross-check uses, in
/// place of the host-supplied `psbt_output_amount`.
#[cfg(feature = "rgb-validation")]
pub fn validate_destination_anchor(
    destination: &RgbDestination,
    source_amount: u64,
    source_commission: u64,
    ctx: &ValidationContext<'_>,
) -> Result<(u64, Vec<String>)> {
    use crate::error::EnclaveError;

    if destination.consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "send-RGB PSBT signing requires a consignment to bind the PSBT to the RGB transition"
                .into(),
        ));
    }
    // The destination consignment is otherwise bounded only by the generic
    // 4 MB wire frame.
    validation::assert_consignment_size(&destination.consignment, ctx.bridge_config, "send-RGB")?;
    // Integrity, not authorization: the listener
    // controls both `consignment` and `consignment_hash`, so a match only
    // proves the wire copy is intact. Authorization is the rgbstd validation
    // plus the witness-txid bind below.
    if destination.consignment_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "consignment present but consignment_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(&destination.consignment);
    if computed[..] != destination.consignment_hash {
        return Err(EnclaveError::CrossCheck(
            "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
        ));
    }
    if destination.asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB destination asset_id is empty".into(),
        ));
    }

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT carries a consignment but the RGB validator is not configured".into(),
        )
    })?;
    // A BFA mint cannot be validated at all without the event `cea` checks it
    // against, so the caller verified the EVM lock before reaching here.
    let validated = validator.validate_consignment(&destination.consignment, ctx.bridge_events)?;

    // Fail-closed on a missing pin, unlike the source direction: an
    // unconfigured yet rgb-validation-enabled enclave must not sign in
    // listener-trusting mode. Mirrors the EVM funds-out `!is_configured()` gate.
    validation::assert_asset_binding(
        &validated.contract_id,
        &destination.asset_id,
        ctx.bridge_config,
        validation::AssetBindMode::Destination,
    )?;

    let psbt = bitcoin::psbt::Psbt::deserialize(&destination.psbt_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("psbt_bytes is not a valid PSBT: {e}")))?;
    // Fail closed: the per-output recipient bind needs to tell a
    // bridge change output from a payout, and it cannot do that without the
    // enclave's own keys. No resolver means no bind, so refuse to sign.
    let self_owned = ctx.self_owned_psbt_outputs.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT cannot be bound: no self-owned-output resolver is wired in, so the \
             enclave cannot distinguish bridge change from a payout to a third party"
                .into(),
        )
    })?;
    // `legs.recipient_seals` is surfaced, not compared here: the invoice is
    // only authenticated once the FundsIn receipt is verified, in `handle_sign`.
    let legs = psbt_validation::validate_psbt_anchors_transition(
        &psbt,
        &validated,
        source_amount,
        source_commission,
        self_owned,
    )?;

    // Fee-rate sanity, after the pure anchor checks so the cached Esplora
    // round-trip is the last thing that can reject. Fail-closed when the
    // estimate is unavailable, since the host controls that egress.
    let recommended = validator.recommended_fee_rate_sat_vb()?;
    psbt_validation::check_psbt_fee_rate(&psbt, recommended)?;

    Ok((legs.recipient, legs.recipient_seals))
}

#[cfg(all(test, feature = "rgb-validation"))]
mod tests;
