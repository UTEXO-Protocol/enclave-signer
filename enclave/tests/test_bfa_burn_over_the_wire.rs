//! Real BFA mint ancestry and burn bytes through the framed Sign handler.
//!
//! RGB consensus, SPV inclusion, BtcRelay agreement, the issuer's reject list,
//! release bindings and the final EIP-712 signature all run. Only the external
//! reject-list transport is a fixture; no validated consignment is injected.
#![cfg(all(feature = "spv", rgb_to_evm))]

#[path = "support/bfa_burn.rs"]
mod burn_fixture;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolValue;
use bitcoin::hashes::Hash;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::SourceNetwork;
use utexo_bridge_enclave::proto::EnclaveResponse;

use burn_fixture::{
    bfa_consignment, burn_id, exchange, mint_deposit_id, Fixture, FundsOutParams, Route, BURNED,
};

fn assert_refusal(response: EnclaveResponse, reason: &str) {
    let Some(Response::Error(error)) = response.response else {
        panic!("expected {reason:?} refusal and no signature: {response:?}");
    };
    assert!(
        error.message.contains(reason),
        "expected {reason:?}, got {error:?}"
    );
}

#[test]
fn signs_real_burn_and_verifies_direct_eip712_signature() {
    Fixture::new(Route::Direct).control();
}

#[test]
fn signs_real_burn_and_verifies_layerzero_eip712_signature() {
    Fixture::new(Route::LayerZero).control();
}

#[test]
fn refuses_settlement_ids_derived_from_the_bare_opid_or_another_mint_transaction() {
    for route in [Route::Direct, Route::LayerZero] {
        let fixture = Fixture::new(route);
        fixture.control();
        let mut other_txid = fixture.mint.witness_id.to_byte_array();
        other_txid[0] ^= 1;
        for wrong_lock in [
            bfa_consignment::opid_bytes(fixture.mint.opid),
            bfa_consignment::lock_id_bytes(
                fixture.mint.opid,
                bitcoin::Txid::from_byte_array(other_txid),
            ),
        ] {
            let mut params = fixture.params.clone();
            params.settlementData = (vec![mint_deposit_id(wrong_lock)],)
                .abi_encode_params()
                .into();
            assert_refusal(
                exchange(&fixture.ctx, fixture.request(params)),
                "settlementData mismatch",
            );
        }
    }
}

#[test]
fn refuses_release_fields_not_authorized_by_the_validated_burn() {
    for route in [Route::Direct, Route::LayerZero] {
        let fixture = Fixture::new(route);
        fixture.control();
        type ReleaseEdit = (&'static str, fn(&mut FundsOutParams));
        let edits: [ReleaseEdit; 5] = [
            ("recipient mismatch", |p| {
                p.recipient = Address::from([0x99; 20])
            }),
            ("exact equality", |p| p.amount -= U256::from(1u64)),
            ("sourceBurnTxId mismatch", |p| p.sourceBurnTxId[0] ^= 1),
            ("settlementData mismatch", |p| {
                p.settlementData = (vec![B256::from([0xee; 32])],).abi_encode_params().into()
            }),
            ("relay commitment mismatch at source height", |p| {
                let mut proof = p.proof.to_vec();
                proof[32] ^= 1;
                p.proof = proof.into();
            }),
        ];
        for (reason, edit) in edits {
            let mut params = fixture.params.clone();
            edit(&mut params);
            // Keep the derived replay ID consistent so the targeted burn
            // bind, not an incidental InvalidBurnId, must reject the edit.
            params.burnId = burn_id(&params);
            assert_refusal(exchange(&fixture.ctx, fixture.request(params)), reason);
        }
    }
}

#[test]
fn refuses_a_burn_with_an_invalid_spv_inclusion_proof() {
    let fixture = Fixture::new(Route::Direct);
    fixture.control();
    let mut request = fixture.request(fixture.params.clone());
    let Some(SourceNetwork::RgbSource(source)) = &mut request.source_network else {
        unreachable!()
    };
    source.merkle_proofs[1].merkle_path.push(vec![0x99; 32]);
    assert_refusal(exchange(&fixture.ctx, request), "!= header root");
}

#[test]
fn refuses_host_claimed_validity_when_rgb_consensus_rejects_the_burn() {
    Fixture::new(Route::Direct).control();
    let fixture = Fixture::with_claimed_burn(Route::Direct, BURNED + 1);
    let mut request = fixture.request(fixture.params.clone());
    let Some(SourceNetwork::RgbSource(source)) = &mut request.source_network else {
        unreachable!()
    };
    source.consignment_valid = true;
    assert_refusal(exchange(&fixture.ctx, request), "validation failed");
}

#[test]
fn refuses_unconfigured_proxy_after_real_rgb_source_validation() {
    let mut fixture = Fixture::new(Route::Direct);
    fixture.control();
    fixture.ctx.bridge_config.bridge_contract = [0; 20];
    assert_refusal(
        exchange(&fixture.ctx, fixture.request(fixture.params.clone())),
        "bridge config unconfigured",
    );
}
