//! Mint/burn flow rules. The bridge owns the contract's inflation rights: a
//! deposit mints with an IFA `Inflation`, a withdrawal destroys units with an
//! IFA `Burn`.
//!
//! See [`super`] for why this lives in its own file, and for the mirrored-name
//! contract these items keep.

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::validation::{ifa, is_mint_transition, TransitionSummary};

/// The mint shapes this build signs, spelled out for rejection messages.
#[cfg(feature = "bfa-mint")]
const MINT_SHAPES: &str = "Inflation or Bridge";
#[cfg(not(feature = "bfa-mint"))]
const MINT_SHAPES: &str = "Inflation";

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
/// In particular BFA's `TS_BRIDGE`, which joins IFA `Inflation` only in a
/// `bfa-mint` build, takes the mint rules below - notably the exact-equality
/// amount bind that refuses an over-mint. A build without the feature has no
/// code path that admits it at all.
pub fn is_signing_transition(transition_type: u16) -> bool {
    is_mint_transition(transition_type)
}

/// Gate on the consignment's last transition before the PSBT is bound to it.
pub fn assert_signing_transition(last: &TransitionSummary) -> Result<()> {
    if !is_signing_transition(last.transition_type) {
        return Err(EnclaveError::CrossCheck(format!(
            "mint-RGB PSBT requires a {MINT_SHAPES} transition (last transition_type = {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type
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
                 {MINT_SHAPES}",
                t.op_id, t.transition_type
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

#[cfg(test)]
mod tests {
    use super::*;

    fn transition(op_id: &str, transition_type: u16, asset: u64) -> TransitionSummary {
        TransitionSummary {
            op_id: op_id.into(),
            transition_type,
            total_output_amount: asset,
            asset_output_amount: asset,
            outputs: Vec::new(),
            burned_asset_amount: None,
            burn_recipient: None,
        }
    }

    fn burn(op_id: &str, burned: Option<u64>) -> TransitionSummary {
        TransitionSummary {
            op_id: op_id.into(),
            transition_type: ifa::TS_BURN,
            total_output_amount: 0,
            asset_output_amount: 0,
            outputs: Vec::new(),
            burned_asset_amount: burned,
            burn_recipient: None,
        }
    }

    #[test]
    fn mint_shapes_are_the_signing_transitions() {
        assert!(is_signing_transition(ifa::TS_INFLATION));
        assert!(!is_signing_transition(ifa::TS_TRANSFER));
        assert!(!is_signing_transition(ifa::TS_BURN));
        assert_eq!(
            is_signing_transition(crate::networks::rgb::validation::bfa::TS_BRIDGE),
            cfg!(feature = "bfa-mint"),
            "the BFA bridge mint is a signing shape only with the feature"
        );
        assert_eq!(FLOW_NAME, "mint/burn");
    }

    #[test]
    fn signing_transition_gate_names_the_flow_on_rejection() {
        assert!(assert_signing_transition(&transition("m", ifa::TS_INFLATION, 1)).is_ok());
        let err = assert_signing_transition(&transition("t", ifa::TS_TRANSFER, 1)).unwrap_err();
        assert!(matches!(err, EnclaveError::CrossCheck(_)), "{err}");
        let msg = err.to_string();
        assert!(
            msg.contains(MINT_SHAPES) && msg.contains(FLOW_NAME),
            "{msg}"
        );
    }

    #[test]
    fn committed_group_rejects_a_smuggled_transfer() {
        let m1 = transition("m1", ifa::TS_INFLATION, 1);
        let m2 = transition("m2", ifa::TS_INFLATION, 2);
        let t = transition("transfer-op", ifa::TS_TRANSFER, 3);
        assert!(assert_committed_group(&[]).is_ok());
        assert!(assert_committed_group(&[&m1, &m2]).is_ok());
        let err = assert_committed_group(&[&m1, &t]).unwrap_err().to_string();
        assert!(
            err.contains("transfer-op") && err.contains(MINT_SHAPES),
            "{err}"
        );
    }

    #[test]
    fn group_amount_must_equal_the_net_credit_exactly() {
        assert!(assert_group_amount(900, 1_000, 100).is_ok());
        let over = assert_group_amount(901, 1_000, 100)
            .unwrap_err()
            .to_string();
        assert!(
            over.contains("(901) != net credited") && over.contains("= 900"),
            "{over}"
        );
        let under = assert_group_amount(899, 1_000, 100)
            .unwrap_err()
            .to_string();
        assert!(under.contains("mint-RGB amount mismatch"), "{under}");
        // Saturating credit: commission above the amount means nothing may mint.
        assert!(assert_group_amount(0, 10, 50).is_ok());
        assert!(assert_group_amount(1, 10, 50).is_err());
    }

    #[test]
    fn funds_out_source_amount_reads_burn_metadata_only() {
        assert_eq!(funds_out_source_amount(&burn("b", Some(700))).unwrap(), 700);
        assert_eq!(funds_out_source_amount(&burn("b", Some(0))).unwrap(), 0);
        let err = funds_out_source_amount(&burn("b", None)).unwrap_err();
        assert!(err.to_string().contains("missing MS_BURNED_ASSET"), "{err}");
        let err = funds_out_source_amount(&transition("t", ifa::TS_TRANSFER, 5)).unwrap_err();
        assert!(
            err.to_string().contains("requires a Burn transition"),
            "{err}"
        );
        let err = funds_out_source_amount(&transition("m", ifa::TS_INFLATION, 5)).unwrap_err();
        assert!(err.to_string().contains(FLOW_NAME), "{err}");
    }

    #[test]
    fn funds_out_amount_requires_exact_equality() {
        assert!(assert_funds_out_amount(1_000, 1_000).is_ok());
        for (source, calldata) in [(999u64, 1_000u64), (1_001, 1_000), (0, 1), (1, 0)] {
            let err = assert_funds_out_amount(source, calldata)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("exact equality"),
                "{source} vs {calldata}: {err}"
            );
        }
    }
}
