//! Mint/burn flow rules. The bridge owns the contract's inflation rights: a
//! deposit mints with an IFA `Inflation`, a withdrawal destroys units with an
//! IFA `Burn`.
//!
//! See [`super`] for why this lives in its own file. Item names here mirror
//! [`super::swap`] exactly.

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::validation::{ifa, TransitionSummary};

/// Human-readable flow name, used in rejection messages so an operator can
/// tell "wrong shape" from "wrong enclave".
pub const FLOW_NAME: &str = "mint/burn";

/// Is this the transition type a deposit PSBT may finalize?
///
/// Also decides whether the consignment parser bothers extracting the last
/// bundle's witness prevouts ([`crate::networks::rgb::validation`]).
pub fn is_signing_transition(transition_type: u16) -> bool {
    transition_type == ifa::TS_INFLATION
}

/// Gate on the consignment's last transition before the PSBT is bound to it.
pub fn assert_signing_transition(last: &TransitionSummary) -> Result<()> {
    if !is_signing_transition(last.transition_type) {
        return Err(EnclaveError::CrossCheck(format!(
            "mint-RGB PSBT requires an Inflation transition (last transition_type = {}, want {}) \
             - this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            ifa::TS_INFLATION
        )));
    }
    Ok(())
}

/// Gate on every transition the signed tx commits, not just the last one: a
/// Bitcoin tx commits a bundle, and a sibling of the wrong type would move
/// value under a rule that was never applied to it. In particular a `Transfer`
/// smuggled into a mint bundle would get the mint's equality rule, which does
/// not account for change.
pub fn assert_committed_group(committed: &[&TransitionSummary]) -> Result<()> {
    for t in committed {
        if !is_signing_transition(t.transition_type) {
            return Err(EnclaveError::CrossCheck(format!(
                "mint-RGB PSBT commits transition {} of type {} - the {FLOW_NAME} flow requires \
                 Inflation ({})",
                t.op_id,
                t.transition_type,
                ifa::TS_INFLATION
            )));
        }
    }
    Ok(())
}

/// Aggregate amount bind over the committed group.
///
/// Exact equality, unlike the send/receive floor: a mint has no pre-existing
/// allocation to return as change, so every minted unit must be accounted for
/// by the credit. Any surplus is an over-mint - free supply the bridge never
/// received a deposit for.
///
/// `committed_asset_output` counts `OS_ASSET` only; the `OS_INFLATION`
/// allowance riding along is remaining mint capacity, not minted value.
pub fn assert_group_amount(
    committed_asset_output: u64,
    net_credited: u64,
    source_amount: u64,
    source_commission: u64,
) -> Result<()> {
    if committed_asset_output != net_credited {
        return Err(EnclaveError::CrossCheck(format!(
            "mint-RGB amount mismatch: consignment asset_output_amount \
             ({committed_asset_output}) != net credited (source_amount {source_amount} - \
             source_commission {source_commission} = {net_credited})"
        )));
    }
    Ok(())
}

/// The asset amount a withdrawal (`fundsOut`) consignment proves was
/// destroyed, and the shape gate that makes it meaningful.
///
/// A `Burn` has no output assignments carrying the destroyed value, so the
/// figure comes from the IFA `MS_BURNED_ASSET` metadata that
/// [`crate::networks::rgb::validation`] reads off the rgbstd `Transfer`.
/// Missing metadata on a burn implies a schema mismatch - fail closed rather
/// than release against an unknown amount.
pub fn funds_out_source_amount(last: &TransitionSummary) -> Result<u64> {
    if last.transition_type != ifa::TS_BURN {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut requires a Burn transition (last transition_type = {}, want {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            ifa::TS_BURN
        )));
    }
    last.burned_asset_amount.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "burn transition is missing MS_BURNED_ASSET metadata - cannot validate amount".into(),
        )
    })
}
