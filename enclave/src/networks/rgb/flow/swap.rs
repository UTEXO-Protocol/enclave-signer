//! Send/receive (pool) flow rules. The bridge holds an allocation of the
//! asset and moves it with BFA `Transfer` transitions in both directions.
//!
//! See [`super`] for the reason for a separate file and the shared item names.

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::validation::{bfa, TransitionSummary};

/// Flow name for rejection messages. It lets an operator tell "wrong shape"
/// from "wrong enclave".
pub const FLOW_NAME: &str = "send/receive";

/// Returns true if a deposit PSBT can finalize this transition type.
///
/// The consignment parser also uses it to decide whether to extract the
/// witness prevouts of the last bundle ([`crate::networks::rgb::validation`]).
pub fn is_signing_transition(transition_type: u16) -> bool {
    transition_type == bfa::TS_TRANSFER
}

/// Checks the last transition of the consignment before the PSBT bind.
pub fn assert_signing_transition(last: &TransitionSummary) -> Result<()> {
    if !is_signing_transition(last.transition_type) {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB PSBT requires a Transfer transition (last transition_type = {}, want {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            bfa::TS_TRANSFER
        )));
    }
    Ok(())
}

/// Checks every transition that the signed tx commits, not only the last one.
/// A Bitcoin tx commits a full bundle. A sibling of the wrong type would move
/// value under a rule that the enclave did not apply to it.
pub fn assert_committed_group(committed: &[&TransitionSummary]) -> Result<()> {
    for t in committed {
        if !is_signing_transition(t.transition_type) {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB PSBT commits transition {} of type {} - the {FLOW_NAME} flow requires \
                 Transfer ({})",
                t.op_id,
                t.transition_type,
                bfa::TS_TRANSFER
            )));
        }
    }
    Ok(())
}

/// Total amount bind over the committed group.
///
/// This is a lower bound, not equality. On a Transfer, `asset_output_amount`
/// is the recipient leg plus the bridge change. The per-output recipient bind
/// in [`crate::networks::rgb::psbt_validation`] pins the recipient leg exactly.
pub fn assert_group_amount(
    committed_asset_output: u64,
    source_amount: u64,
    source_commission: u64,
) -> Result<()> {
    let net_credited = source_amount.saturating_sub(source_commission);
    if committed_asset_output < net_credited {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB amount mismatch: consignment asset_output_amount \
             ({committed_asset_output}) < net credited (source_amount {source_amount} - \
             source_commission {source_commission} = {net_credited})"
        )));
    }
    Ok(())
}

/// Returns the asset amount that a withdrawal (`fundsOut`) consignment moves
/// to the bridge, after a check of the transition type.
///
/// A `Transfer` keeps its value in the output assignments, so the amount is
/// `total_output_amount`. The route proof and the EVM calldata amount check
/// both use it.
pub fn funds_out_source_amount(last: &TransitionSummary) -> Result<u64> {
    if !is_signing_transition(last.transition_type) {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut requires a Transfer transition (last transition_type = {}, want {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            bfa::TS_TRANSFER
        )));
    }
    Ok(last.total_output_amount)
}

/// Binds the EVM release amount to the amount that the consignment proves.
///
/// This is a lower bound, not equality. On a Transfer, `total_output_amount`
/// is the bridge leg plus the sender change, so it can be more than the
/// release.
pub fn assert_funds_out_amount(source_amount: u64, calldata_amount: u64) -> Result<()> {
    if source_amount < calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut amount mismatch: consignment proves {source_amount} asset units left the \
             source, below the calldata amount ({calldata_amount})"
        )));
    }
    Ok(())
}
