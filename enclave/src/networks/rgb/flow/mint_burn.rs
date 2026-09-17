//! Mint/burn flow rules. The bridge owns the contract's mint right: a
//! deposit mints with a BFA `Bridge`, a withdrawal destroys units with a
//! BFA `Burn`.
//!
//! See [`super`] for why this lives in its own file, and for the mirrored-name
//! contract these items keep.

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::validation::{bfa, is_mint_transition, TransitionSummary};

/// Human-readable flow name, used in rejection messages so an operator can
/// tell "wrong shape" from "wrong enclave".
pub const FLOW_NAME: &str = "mint/burn";

/// Is this the transition type a deposit PSBT may finalize?
///
/// Also decides whether the consignment parser bothers extracting the last
/// bundle's witness prevouts ([`crate::networks::rgb::validation`]).
///
/// The signing shape of this flow *is* the mint shape, so this is
/// [`is_mint_transition`] rather than a second list that could drift from it.
/// BFA's `TS_BRIDGE` is the only mint shape, and it takes the mint rules below
/// - notably the exact-equality amount bind that refuses an over-mint.
pub fn is_signing_transition(transition_type: u16) -> bool {
    is_mint_transition(transition_type)
}

/// Gate on the consignment's last transition before the PSBT is bound to it.
pub fn assert_signing_transition(last: &TransitionSummary) -> Result<()> {
    if !is_signing_transition(last.transition_type) {
        return Err(EnclaveError::CrossCheck(format!(
            "mint-RGB PSBT requires a Bridge transition (last transition_type = {}, want {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            bfa::TS_BRIDGE
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
                 Bridge ({})",
                t.op_id,
                t.transition_type,
                bfa::TS_BRIDGE
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
/// `committed_asset_output` counts `OS_ASSET` only; an `OS_BRIDGE` output
/// riding along is the declarative mint right, not minted value.
pub fn assert_group_amount(
    committed_asset_output: u64,
    source_amount: u64,
    source_commission: u64,
) -> Result<()> {
    let net_credited = source_amount.saturating_sub(source_commission);
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
/// figure comes from the BFA `MS_BURNED_ASSET` metadata that
/// [`crate::networks::rgb::validation`] reads off the rgbstd `Transfer`.
/// Missing metadata on a burn implies a schema mismatch - fail closed rather
/// than release against an unknown amount.
pub fn funds_out_source_amount(last: &TransitionSummary) -> Result<u64> {
    if last.transition_type != bfa::TS_BURN {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut requires a Burn transition (last transition_type = {}, want {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            bfa::TS_BURN
        )));
    }
    last.burned_asset_amount.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "burn transition is missing MS_BURNED_ASSET metadata - cannot validate amount".into(),
        )
    })
}

/// Bind the EVM release amount to what the consignment proves.
///
/// Exact equality: a burn destroys one figure and has no change leg, and
/// `fundsOut.amount` is gross (commission is taken on-chain from it). A
/// release below the burn strands units; one above it is unbacked.
pub fn assert_funds_out_amount(source_amount: u64, calldata_amount: u64) -> Result<()> {
    if source_amount != calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut amount mismatch: consignment proves {source_amount} asset units were \
             burned, calldata amount is {calldata_amount} - the {FLOW_NAME} flow requires \
             exact equality"
        )));
    }
    Ok(())
}
