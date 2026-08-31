//! Send/receive (pools) flow rules. The bridge holds an allocation of the
//! asset and moves it with IFA `Transfer` transitions in both directions.
//!
//! See [`super`] for why this lives in its own file. Item names here mirror
//! [`super::mint_burn`] exactly.

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::validation::{ifa, TransitionSummary};

/// Human-readable flow name, used in rejection messages so an operator can
/// tell "wrong shape" from "wrong enclave".
pub const FLOW_NAME: &str = "send/receive";

/// Is this the transition type a deposit PSBT may finalize?
///
/// Also decides whether the consignment parser bothers extracting the last
/// bundle's witness prevouts ([`crate::networks::rgb::validation`]).
pub fn is_signing_transition(transition_type: u16) -> bool {
    transition_type == ifa::TS_TRANSFER
}

/// Gate on the consignment's last transition before the PSBT is bound to it.
pub fn assert_signing_transition(last: &TransitionSummary) -> Result<()> {
    if !is_signing_transition(last.transition_type) {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB PSBT requires a Transfer transition (last transition_type = {}, want {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            ifa::TS_TRANSFER
        )));
    }
    Ok(())
}

/// Gate on every transition the signed tx commits, not just the last one: a
/// Bitcoin tx commits a bundle, and a sibling of the wrong type would move
/// value under a rule that was never applied to it.
pub fn assert_committed_group(committed: &[&TransitionSummary]) -> Result<()> {
    for t in committed {
        if !is_signing_transition(t.transition_type) {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB PSBT commits transition {} of type {} - the {FLOW_NAME} flow requires \
                 Transfer ({})",
                t.op_id,
                t.transition_type,
                ifa::TS_TRANSFER
            )));
        }
    }
    Ok(())
}

/// Aggregate amount bind over the committed group.
///
/// A coverage lower bound, not equality: `asset_output_amount` on a Transfer
/// is recipient + bridge change, and the change is legitimately ours. The
/// per-output recipient bind in [`crate::networks::rgb::psbt_validation`] is
/// what pins the recipient leg exactly.
pub fn assert_group_amount(
    committed_asset_output: u64,
    net_credited: u64,
    source_amount: u64,
    source_commission: u64,
) -> Result<()> {
    if committed_asset_output < net_credited {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB amount mismatch: consignment asset_output_amount \
             ({committed_asset_output}) < net credited (source_amount {source_amount} - \
             source_commission {source_commission} = {net_credited})"
        )));
    }
    Ok(())
}

/// The asset amount a withdrawal (`fundsOut`) consignment proves moved to the
/// bridge, and the shape gate that makes it meaningful.
///
/// A `Transfer` carries its value in the output assignments, so
/// `total_output_amount` is the figure. Used both for the route proof and for
/// the EVM calldata amount cross-check.
pub fn funds_out_source_amount(last: &TransitionSummary) -> Result<u64> {
    if last.transition_type != ifa::TS_TRANSFER {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut requires a Transfer transition (last transition_type = {}, want {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            ifa::TS_TRANSFER
        )));
    }
    Ok(last.total_output_amount)
}
