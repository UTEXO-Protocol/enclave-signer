//! Mint/burn flow rules. The bridge owns the mint right of the contract. A
//! deposit mints with a BFA `Bridge`. A withdrawal destroys units with a
//! BFA `Burn`.
//!
//! See [`super`] for the reason for a separate file and the shared item names.

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::validation::{bfa, is_mint_transition, TransitionSummary};

/// Flow name for rejection messages. It lets an operator tell "wrong shape"
/// from "wrong enclave".
pub const FLOW_NAME: &str = "mint/burn";

/// Returns true if a deposit PSBT can finalize this transition type.
///
/// The consignment parser also uses it to decide whether to extract the
/// witness prevouts of the last bundle ([`crate::networks::rgb::validation`]).
///
/// The signing shape of this flow is the mint shape. Thus it calls
/// [`is_mint_transition`], so that no second list can drift from it.
/// BFA `TS_BRIDGE` is the only mint shape. It gets the mint rules below,
/// which include the exact-equality amount bind that refuses an over-mint.
pub fn is_signing_transition(transition_type: u16) -> bool {
    is_mint_transition(transition_type)
}

/// Checks the last transition of the consignment before the PSBT bind.
#[cfg(evm_to_rgb)]
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

/// Checks every transition that the signed tx commits, not only the last one.
/// A Bitcoin tx commits a full bundle. A sibling of the wrong type would move
/// value under a rule that the enclave did not apply to it. For example, a
/// `Transfer` in a mint bundle gets the mint equality rule, which ignores change.
#[cfg(evm_to_rgb)]
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

/// Total amount bind over the committed group.
///
/// This is exact equality, not the send/receive lower bound. A mint has no
/// prior allocation to return as change, so the credit must cover every
/// minted unit. A surplus is an over-mint: supply with no deposit.
///
/// `committed_asset_output` counts `OS_ASSET` only. An `OS_BRIDGE` output is
/// the declarative mint right, not minted value.
#[cfg(evm_to_rgb)]
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

/// Returns the asset amount that a withdrawal (`fundsOut`) consignment
/// destroys, after a check of the transition type.
///
/// A `Burn` has no output assignment with the destroyed value. The amount
/// comes from the BFA `MS_BURNED_ASSET` metadata that
/// [`crate::networks::rgb::validation`] reads from the rgbstd `Transfer`.
/// Missing metadata means a schema mismatch. Fail closed, because the amount
/// is unknown.
#[cfg(rgb_to_evm)]
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

/// Binds the EVM release amount to the amount that the consignment proves.
///
/// This is exact equality. A burn destroys one amount and has no change leg.
/// `fundsOut.amount` is gross: the contract takes the commission on-chain.
/// A release below the burn strands units. A release above it is unbacked.
#[cfg(rgb_to_evm)]
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
