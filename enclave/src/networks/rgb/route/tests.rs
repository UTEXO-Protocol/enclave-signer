use super::*;
#[cfg(rgb_to_evm)]
use crate::test_support::bfa_ids;
#[cfg(rgb_to_evm)]
use validation::{TransitionSummary, ValidatedConsignment};

#[cfg(rgb_to_evm)]
fn validated_consignment(
    transition_type: u16,
    total_output_amount: u64,
    burned_asset_amount: Option<u64>,
    op_id: &str,
) -> ValidatedConsignment {
    ValidatedConsignment {
        contract_id: "rgb:test-asset".into(),
        chain_net: "bc:regtest".into(),
        witness_txids: vec![],
        last_transition: Some(TransitionSummary {
            op_id: op_id.into(),
            transition_type,
            total_output_amount,
            asset_output_amount: total_output_amount,
            outputs: vec![],
            burned_asset_amount,
            burn_reason: None,
        }),
        last_witness_txid: None,
        last_transfer_witness_prevouts: vec![],
        last_transfer_op_id: None,
        non_mined_witness_txids: vec![],
        // These cases do not reach the PSBT bind.
        transitions_by_witness: vec![],
        ..Default::default()
    }
}

#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
fn funds_out_consignment(amount: u64, op_id: &str) -> ValidatedConsignment {
    validated_consignment(bfa_ids::TS_BURN, 0, Some(amount), op_id)
}

#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
#[test]
fn route_proof_uses_burn_metadata_amount() {
    let op_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let proof = route_proof_from_validated_consignment(&validated_consignment(
        bfa_ids::TS_BURN,
        0,
        Some(700),
        op_id,
    ))
    .unwrap();

    assert_eq!(proof.amount, 700);
    assert_eq!(proof.operation_id.as_deref(), Some(op_id));
}

#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
#[test]
fn route_proof_rejects_burn_without_burned_amount() {
    let err = route_proof_from_validated_consignment(&validated_consignment(
        bfa_ids::TS_BURN,
        0,
        None,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ))
    .unwrap_err();

    assert!(err.to_string().contains("no burnedAsset"), "{err}");
}

#[cfg(rgb_to_evm)]
#[test]
fn route_proof_rejects_non_hex_operation_id() {
    let err = route_proof_from_validated_consignment(&funds_out_consignment(
        100,
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ))
    .unwrap_err();

    assert!(err.to_string().contains("not hex-decodable"));
}

/// A plain transfer must not authorize a release.
#[cfg(rgb_to_evm)]
#[test]
fn route_proof_rejects_a_transfer() {
    let op_id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let wrong = validated_consignment(bfa_ids::TS_TRANSFER, 700, None, op_id);

    let err = route_proof_from_validated_consignment(&wrong).unwrap_err();
    assert!(
        err.to_string().contains("this enclave is built for the"),
        "expected flow-shape rejection, got: {err}"
    );
}

/// The mint signer's routes, from the PSBT, its fascia and its parent's alone.
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
mod psbt_path;
