use super::*;
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

fn rgb_destination() -> DestinationNetwork {
    DestinationNetwork::RgbDestination(RgbDestination {
        psbt_bytes: vec![0x70, 0x73, 0x62, 0x74, 0xff],
        asset_id: "rgb:test-asset".into(),
        fascia: vec![],
        parent_fascia: vec![],
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
        burn_destination: None,
    })
}

fn proof(amount: u64) -> RouteProof {
    RouteProof { amount }
}

#[test]
fn route_proofs_accept_exact_match_to_rgb_destination() {
    assert!(
        validate_route_proofs(&evm_source(20), &rgb_destination(), &proof(90), &proof(90),).is_ok()
    );
}

#[test]
fn route_proofs_reject_underfunded_rgb_destination() {
    let err = validate_route_proofs(&evm_source(20), &rgb_destination(), &proof(89), &proof(90))
        .unwrap_err();
    assert!(err.to_string().contains("amount mismatch"));
}

#[test]
fn route_proofs_accept_rgb_to_evm_match() {
    assert!(validate_route_proofs(
        &rgb_source(),
        &evm_destination(90, 20),
        &proof(90),
        &proof(90),
    )
    .is_ok());
}

#[test]
fn route_proofs_reject_underfunded_evm_destination() {
    let err = validate_route_proofs(
        &rgb_source(),
        &evm_destination(90, 20),
        &proof(89),
        &proof(90),
    )
    .unwrap_err();
    assert!(err.to_string().contains("amount mismatch"));
}

#[test]
fn route_proofs_reject_unsupported_pair() {
    let err = validate_route_proofs(&rgb_source(), &rgb_destination(), &proof(90), &proof(90))
        .unwrap_err();
    assert!(err.to_string().contains("unsupported"));
}
