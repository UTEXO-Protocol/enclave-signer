use super::*;
#[cfg(feature = "ccd")]
use crate::proto::CcdSource;
use crate::proto::{EvmDestination, EvmSource, RgbDestination, RgbSource};

fn evm_source(commission: u64) -> SourceNetwork {
    SourceNetwork::EvmSource(EvmSource {
        tx_hash: vec![0xAA; 32],
        event_valid: true,
        event_finalized: true,
        token: vec![0x11; 20],
        recipient: vec![0x22; 20],
        commission,
        funds_in_operation_id: vec![0x33; 32],
    })
}

fn rgb_destination(destination_amount: u64) -> DestinationNetwork {
    DestinationNetwork::RgbDestination(RgbDestination {
        operation_idx: 1,
        psbt_bytes: vec![0x70, 0x73, 0x62, 0x74, 0xff],
        psbt_output_amount: destination_amount,
        asset_id: "rgb:test-asset".into(),
        consignment: vec![],
        mint_ancestors: Vec::new(),
        consignment_hash: vec![],
    })
}

fn rgb_source() -> SourceNetwork {
    SourceNetwork::RgbSource(RgbSource {
        consignment_valid: true,
        asset_id: "rgb:test-asset".into(),
        consignment: vec![0x01],
        consignment_hash: vec![0x02; 32],
        merkle_proofs: vec![],
        commission: 20,
        mint_ancestors: vec![],
    })
}

#[cfg(feature = "ccd")]
fn ccd_source(commission: u64) -> SourceNetwork {
    SourceNetwork::CcdSource(CcdSource {
        tx_hash: vec![0xCC; 32],
        commission,
    })
}

fn evm_destination(destination_amount: u64, commission: u64) -> DestinationNetwork {
    DestinationNetwork::EvmDestination(EvmDestination {
        call_data: vec![0x00; 4],
        nonce: 1,
        deadline: 1,
        chain_id: 1,
        proxy_contract: vec![0x33; 20],
        calldata_amount: destination_amount,
        calldata_commission: commission,
        lz_release: None,
    })
}

fn proof(amount: u64, operation_id: Option<&str>) -> RouteProof {
    RouteProof {
        amount,
        operation_id: operation_id.map(str::to_string),
    }
}

#[test]
fn route_proofs_accept_exact_match_to_rgb_destination() {
    assert!(validate_route_proofs(
        &evm_source(20),
        &rgb_destination(90),
        &proof(90, None),
        &proof(90, None),
    )
    .is_ok());
}

#[cfg(feature = "ccd")]
#[test]
fn route_proofs_accept_ccd_source_to_evm_destination() {
    assert!(validate_route_proofs(
        &ccd_source(10),
        &evm_destination(990, 10),
        &proof(990, None),
        &proof(990, None),
    )
    .is_ok());
}

#[cfg(feature = "ccd")]
#[test]
fn route_proofs_reject_underfunded_ccd_to_evm_destination() {
    let err = validate_route_proofs(
        &ccd_source(10),
        &evm_destination(990, 10),
        &proof(980, None), // source amount < destination amount
        &proof(990, None),
    );
    assert!(err.is_err());
}

#[cfg(feature = "ccd")]
#[test]
fn ccd_validate_source_trusts_and_binds_amount() {
    let proof = ccd::validate_source(
        990,
        &CcdSource {
            tx_hash: vec![0xCC; 32],
            commission: 10,
        },
    )
    .expect("trusted CCD source");
    assert_eq!(proof.amount, 990);
}

#[cfg(feature = "ccd")]
#[test]
fn ccd_validate_source_rejects_bad_tx_hash() {
    let err = ccd::validate_source(
        990,
        &CcdSource {
            tx_hash: vec![0xCC; 31],
            commission: 10,
        },
    );
    assert!(err.is_err());
}

#[test]
fn route_proofs_reject_underfunded_rgb_destination() {
    let err = validate_route_proofs(
        &evm_source(20),
        &rgb_destination(90),
        &proof(89, None),
        &proof(90, None),
    )
    .unwrap_err();
    assert!(err.to_string().contains("amount mismatch"));
}

#[test]
fn route_proofs_accept_rgb_to_evm_match() {
    assert!(validate_route_proofs(
        &rgb_source(),
        &evm_destination(90, 20),
        &proof(90, Some("op")),
        &proof(90, Some("op")),
    )
    .is_ok());
}

#[test]
fn route_proofs_reject_underfunded_evm_destination() {
    let err = validate_route_proofs(
        &rgb_source(),
        &evm_destination(90, 20),
        &proof(89, Some("op")),
        &proof(90, Some("op")),
    )
    .unwrap_err();
    assert!(err.to_string().contains("amount mismatch"));
}

#[test]
fn route_proofs_do_not_compare_rgb_to_evm_operation_id_yet() {
    assert!(validate_route_proofs(
        &rgb_source(),
        &evm_destination(90, 20),
        &proof(90, Some("source-op")),
        &proof(90, Some("destination-op")),
    )
    .is_ok());
}

#[test]
fn route_proofs_accept_rgb_to_evm_missing_operation_id_for_now() {
    assert!(validate_route_proofs(
        &rgb_source(),
        &evm_destination(90, 20),
        &proof(90, None),
        &proof(90, Some("destination-op")),
    )
    .is_ok());
}

#[test]
fn route_proofs_reject_unsupported_pair() {
    let err = validate_route_proofs(
        &rgb_source(),
        &rgb_destination(90),
        &proof(90, None),
        &proof(90, None),
    )
    .unwrap_err();
    assert!(err.to_string().contains("unsupported"));
}
