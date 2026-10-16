use super::*;
use crate::config::BridgeConfig;
use crate::networks::evm::reject_list::{entriesCall, lengthCall};
use crate::networks::rgb::validation::{OpoutKey, RejectListEntry, RgbValidator};
use crate::proto::enclave_request::Request;
use crate::proto::enclave_response::Response;
use crate::state::EnclaveState;
use crate::test_support::bfa_consignment::{self as gen, History, Issue};
use crate::test_support::{far_deadline, ListEvm};
use alloy_sol_types::SolCall;
use sha3::{Digest, Keccak256};

const BRIDGE: [u8; 20] = [0xB1; 20];
const CHAIN: u64 = 42161;
const LIST: [u8; 20] = [0x4e; 20];

/// A listed asset: a mint of 100_000, then a burn of all of it. Returns the
/// history and the genesis right the mint spent.
fn listed_burn() -> (History, OpoutKey) {
    let utxo = gen::outpoint(0xA0, 0);
    let mut history = History::issue(Issue {
        reject_list: Some(gen::evm_reject_list(CHAIN, LIST)),
        ..Issue::new(CHAIN, BRIDGE, vec![utxo])
    });
    let right = history.genesis_right(0, utxo);
    let units = history.mint_owned(right, 100_000, 90);
    history.burn(units, 100_000, Some(100_000), Some([0; 32]));
    (history, right.opout.into())
}

/// Sends the listed burn, every witness proven 6 deep, to an enclave whose
/// pinned EVM client holds `entries`. Returns the refusal and the `eth_call`
/// selectors the client saw.
fn sign_listed(entries: Vec<RejectListEntry>) -> (String, Vec<[u8; 4]>) {
    let (history, _) = listed_burn();
    let consignment = history.consignment(vec![]);
    let witnesses: Vec<[u8; 32]> = history
        .bundles
        .iter()
        .map(|wb| {
            let mut txid = bitcoin::hashes::Hash::to_byte_array(wb.witness_id());
            txid.reverse();
            txid
        })
        .collect();
    let (chain, merkle_proofs) = crate::test_support::chain_with_witnesses(&witnesses, 5);
    let cfg = BridgeConfig {
        funds_in_contract: BRIDGE,
        token_contract: [0x7e; 20],
        chain_id: CHAIN,
        rgb_asset_id: history.contract_id.to_string(),
        ..BridgeConfig::default()
    };
    let state = EnclaveState::default();
    state.initialize_from_seed([7; 64]).unwrap();
    let mut ctx = ServerContext::new(state, cfg, chain);
    let rpc = ListEvm::new(CHAIN, entries);
    let calls = rpc.calls.clone();
    let launch = ctx.launch.get_mut().unwrap();
    launch.rgb_validator =
        Some(RgbValidator::new("tcp://indexer.invalid:1".into(), "regtest").unwrap());
    launch.evm_rpc_client = Some(Box::new(rpc));

    let request = EnclaveRequest {
        request: Some(Request::Sign(SignRequest {
            amount: 100_000,
            source_network: Some(SourceNetwork::RgbSource(RgbSource {
                consignment_hash: Keccak256::digest(&consignment).to_vec(),
                consignment,
                asset_id: history.contract_id.to_string(),
                merkle_proofs,
                ..Default::default()
            })),
            destination_network: Some(
                DestinationNetwork::EvmDestination(EvmDestination::default()),
            ),
        })),
    };
    let response = super::super::dispatch::dispatch(request, &ctx, far_deadline())
        .0
        .response
        .unwrap();
    let Response::Error(err) = response else {
        panic!("expected a refusal, got {response:?}");
    };
    let selectors = calls.lock().unwrap().iter().map(|(s, _)| *s).collect();
    (err.message, selectors)
}

fn entry(opout: OpoutKey) -> RejectListEntry {
    RejectListEntry {
        opout,
        reject: true,
    }
}

/// The mint the burn descends from spent a rejected genesis right.
#[test]
fn a_burn_of_a_rejected_lineage_is_refused_through_the_pinned_client() {
    let (_, right) = listed_burn();
    let (err, selectors) = sign_listed(vec![entry(right)]);
    assert!(err.contains("reject list: opout"), "{err}");
    assert!(selectors.contains(&lengthCall::SELECTOR));
    assert!(selectors.contains(&entriesCall::SELECTOR));
}

/// Control: the list is read, and the burn goes on to the destination.
/// Only the mint/burn flow lets a burn reach the destination.
#[cfg(feature = "rgb-mint-burn")]
#[test]
fn a_burn_with_only_unrelated_entries_passes_the_list() {
    let unrelated = OpoutKey {
        op: [0x99; 32],
        ty: 4000,
        no: 0,
    };
    let (err, selectors) = sign_listed(vec![entry(unrelated)]);
    // The source passed, so the empty EVM destination is what refuses.
    assert!(err.contains("call_data too short"), "{err}");
    assert!(selectors.contains(&entriesCall::SELECTOR));
}
