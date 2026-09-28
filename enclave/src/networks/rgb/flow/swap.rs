//! Send/receive (pools) flow rules. The bridge holds an allocation of the
//! asset and moves it with IFA `Transfer` transitions in both directions.
//!
//! See [`super`] for why this lives in its own file, and for the mirrored-name
//! contract these items keep.

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

/// Bind the EVM release amount to what the consignment proves.
///
/// Coverage, not equality: `total_output_amount` on a Transfer is the
/// bridge's leg plus the sender's change, so it may legitimately exceed the
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

#[cfg(test)]
mod tests {
    use super::*;

    fn transition(op_id: &str, transition_type: u16, total: u64) -> TransitionSummary {
        TransitionSummary {
            op_id: op_id.into(),
            transition_type,
            total_output_amount: total,
            asset_output_amount: total,
            outputs: Vec::new(),
            burned_asset_amount: None,
            burn_recipient: None,
        }
    }

    #[test]
    fn only_transfer_is_the_signing_transition() {
        assert!(is_signing_transition(ifa::TS_TRANSFER));
        assert!(!is_signing_transition(ifa::TS_INFLATION));
        assert!(!is_signing_transition(ifa::TS_BURN));
        assert!(!is_signing_transition(0));
        assert_eq!(FLOW_NAME, "send/receive");
    }

    #[test]
    fn signing_transition_gate_names_the_flow_on_rejection() {
        assert!(assert_signing_transition(&transition("t", ifa::TS_TRANSFER, 1)).is_ok());
        let err = assert_signing_transition(&transition("m", ifa::TS_INFLATION, 1)).unwrap_err();
        assert!(matches!(err, EnclaveError::CrossCheck(_)), "{err}");
        let msg = err.to_string();
        assert!(
            msg.contains("requires a Transfer") && msg.contains(FLOW_NAME),
            "{msg}"
        );
        assert!(msg.contains(&ifa::TS_INFLATION.to_string()), "{msg}");
    }

    #[test]
    fn committed_group_must_be_all_transfers() {
        let a = transition("a", ifa::TS_TRANSFER, 1);
        let b = transition("b", ifa::TS_TRANSFER, 2);
        let burn = transition("burn-op", ifa::TS_BURN, 0);
        assert!(
            assert_committed_group(&[]).is_ok(),
            "an empty group is the caller's problem"
        );
        assert!(assert_committed_group(&[&a, &b]).is_ok());
        let err = assert_committed_group(&[&a, &burn, &b])
            .unwrap_err()
            .to_string();
        assert!(err.contains("burn-op") && err.contains("requires"), "{err}");
    }

    #[test]
    fn group_amount_is_a_coverage_lower_bound() {
        assert!(assert_group_amount(900, 1_000, 100).is_ok(), "exact");
        assert!(
            assert_group_amount(5_000, 1_000, 100).is_ok(),
            "surplus is change"
        );
        let err = assert_group_amount(899, 1_000, 100)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("(899) < net credited") && err.contains("= 900"),
            "{err}"
        );
        // Commission above the amount saturates to a zero credit.
        assert!(assert_group_amount(0, 10, 50).is_ok());
        assert!(assert_group_amount(u64::MAX, u64::MAX, 0).is_ok());
    }

    #[test]
    fn funds_out_source_amount_reads_the_transfer_total() {
        assert_eq!(
            funds_out_source_amount(&transition("t", ifa::TS_TRANSFER, 777)).unwrap(),
            777
        );
        let err = funds_out_source_amount(&transition("b", ifa::TS_BURN, 0)).unwrap_err();
        assert!(
            err.to_string().contains("requires a Transfer transition"),
            "{err}"
        );
        let err = funds_out_source_amount(&transition("m", ifa::TS_INFLATION, 5)).unwrap_err();
        assert!(err.to_string().contains(FLOW_NAME), "{err}");
    }

    #[test]
    fn funds_out_amount_is_covered_not_equal() {
        assert!(assert_funds_out_amount(1_000, 1_000).is_ok());
        assert!(assert_funds_out_amount(1_001, 1_000).is_ok());
        assert!(assert_funds_out_amount(0, 0).is_ok());
        let err = assert_funds_out_amount(999, 1_000).unwrap_err().to_string();
        assert!(
            err.contains("proves 999") && err.contains("(1000)"),
            "{err}"
        );
    }
}
