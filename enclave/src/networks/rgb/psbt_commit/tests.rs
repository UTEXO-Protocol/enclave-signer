use std::collections::BTreeMap;

use bitcoin::blockdata::script::Builder;
use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use psrgbt::{OpoutAndOpids, RgbPropKeyExt};
use rgbstd::contract::AllocatedState;
use rgbstd::GraphSeal;
use strict_encoding::StrictSerialize;

use super::*;
use crate::networks::rgb::btc_ownership::tests as fx;
use crate::test_support::bfa_consignment::{self as gen, History, Issue, Utxo};

const ENTROPY: u64 = 0x7a11;

fn right_outpoint(tag: u8) -> OutPoint {
    gen::outpoint(tag, 0)
}

/// An asset with a genesis right on each of `tags`, and those rights.
fn issued(bridge: u8, tags: &[u8]) -> (History, Vec<Utxo>) {
    let outpoints: Vec<OutPoint> = tags.iter().map(|&t| right_outpoint(t)).collect();
    let history = History::issue(Issue::new(42161, [bridge; 20], outpoints.clone()));
    let rights = (0u16..)
        .zip(outpoints)
        .map(|(no, outpoint)| history.genesis_right(no, outpoint))
        .collect();
    (history, rights)
}

fn p2tr(tag: u8) -> TxOut {
    TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: fx::foreign_address(tag),
    }
}

/// A rights send of the one genesis right to vouts 1 and 2, both P2TR.
fn rights_send() -> (History, gen::Committed) {
    let (mut history, rights) = issued(0xB1, &[0xA0]);
    let sent = history.send_rights(rights[0], &[1, 2], vec![], vec![p2tr(1), p2tr(2)]);
    (history, sent)
}

fn refusal(psbt: &Psbt, pin: ContractId) -> String {
    committed_transition(psbt, pin).unwrap_err().to_string()
}

/// A PSBT that spends `inputs`, with RGB data `craft` writes, then committed
/// with the OP_RETURN on vout 0.
fn crafted(inputs: Vec<OutPoint>, craft: impl FnOnce(&mut Psbt)) -> Psbt {
    let mut psbt = gen::witness_psbt(inputs, vec![p2tr(1), p2tr(2)]);
    craft(&mut psbt);
    gen::rgb_commit(&mut psbt, 0, ENTROPY);
    psbt
}

/// The rights send of `right` to vouts 1 and 2, built on `history`.
fn send_of(history: &mut History, right: Utxo) -> Transition {
    history.rights_transition(right, &[1, 2])
}

// ===== the happy path =====

#[test]
fn reads_the_one_transition_a_rights_send_commits() {
    let (history, sent) = rights_send();
    let committed = committed_transition(&sent.psbt, history.contract_id).unwrap();
    assert_eq!(committed.opid, sent.opid);
    assert_eq!(committed.txid, sent.tx.compute_txid());
    assert_eq!(committed.transition.id(), sent.opid);
}

#[test]
fn reads_a_mint_to_a_blinded_seal() {
    let (mut history, rights) = issued(0xB1, &[0xA0]);
    let to = GraphSeal::with_blinding(right_outpoint(0xC0).txid, 0u32, 7);
    let minted = history.mint(
        rights[0],
        5_000,
        90,
        rgbstd::BuilderSeal::Concealed(to.to_secret_seal()),
        vec![],
        vec![gen::dust(1)],
    );
    let committed = committed_transition(&minted.psbt, history.contract_id).unwrap();
    assert_eq!(committed.opid, minted.opid);
}

// ===== F3: the close method =====

/// Inserts `out` before the OP_RETURN, then commits with the host on vout 1.
fn with_output_before_the_op_return(out: TxOut) -> (History, Psbt) {
    let (mut history, rights) = issued(0xB1, &[0xA0]);
    let send = send_of(&mut history, rights[0]);
    let mut psbt = gen::witness_psbt(vec![rights[0].outpoint], vec![p2tr(1), p2tr(2)]);
    psbt.unsigned_tx.output.insert(0, out);
    psbt.outputs.insert(0, Default::default());
    psbt.push_rgb_transition(send).unwrap();
    gen::rgb_commit(&mut psbt, 1, ENTROPY);
    (history, psbt)
}

#[test]
fn refuses_p2tr_output_before_the_op_return() {
    let (history, psbt) = with_output_before_the_op_return(p2tr(9));
    let err = refusal(&psbt, history.contract_id);
    assert!(
        err.contains("output 0 is a P2TR before the OP_RETURN"),
        "{err}"
    );
}

#[test]
fn accepts_p2tr_after_the_op_return() {
    let (history, sent) = rights_send();
    assert!(sent.psbt.unsigned_tx.output[1].script_pubkey.is_p2tr());
    committed_transition(&sent.psbt, history.contract_id).unwrap();
}

/// P2A is witness v1 but not P2TR, so consensus does not read it as a host.
#[test]
fn p2a_output_before_the_op_return_is_not_a_host() {
    let anchor = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_p2a(),
    };
    let (history, psbt) = with_output_before_the_op_return(anchor);
    committed_transition(&psbt, history.contract_id).unwrap();
}

#[test]
fn refuses_a_tx_without_an_op_return() {
    let (mut history, rights) = issued(0xB1, &[0xA0]);
    let outputs = vec![gen::dust(1), gen::dust(2)];
    let mut sent = history.send_rights(rights[0], &[1, 2], vec![], outputs);
    sent.psbt.unsigned_tx.output.remove(0);
    sent.psbt.outputs.remove(0);
    let err = refusal(&sent.psbt, history.contract_id);
    assert!(err.contains("no OP_RETURN"), "{err}");
}

#[test]
fn refuses_op_return_that_is_not_34_bytes() {
    let (history, mut sent) = rights_send();
    let script = &mut sent.psbt.unsigned_tx.output[0].script_pubkey;
    let mut longer = script.to_bytes();
    longer.push(0x00);
    *script = ScriptBuf::from_bytes(longer);
    let err = refusal(&sent.psbt, history.contract_id);
    assert!(err.contains("does not commit exactly"), "{err}");
}

// ===== F4: the pinned contract =====

/// Our rights send and another contract's, in one PSBT and one commitment.
fn two_contracts() -> (History, History, Psbt) {
    let (mut ours, our_rights) = issued(0xB1, &[0xA0]);
    let (mut theirs, their_rights) = issued(0xB2, &[0xA1]);
    let our_send = send_of(&mut ours, our_rights[0]);
    let their_send = send_of(&mut theirs, their_rights[0]);
    let inputs = vec![our_rights[0].outpoint, their_rights[0].outpoint];
    let psbt = crafted(inputs, |psbt| {
        psbt.push_rgb_transition(our_send).unwrap();
        psbt.push_rgb_transition(their_send).unwrap();
    });
    (ours, theirs, psbt)
}

#[test]
fn refuses_second_contract_bundle() {
    let (ours, _, psbt) = two_contracts();
    let err = refusal(&psbt, ours.contract_id);
    assert!(err.contains("commits 2 contract bundles"), "{err}");
}

#[test]
fn refuses_bundle_of_unpinned_contract() {
    let (_, sent) = rights_send();
    let (other, _) = issued(0xB2, &[0xA1]);
    let err = refusal(&sent.psbt, other.contract_id);
    assert!(err.contains("not of the pinned RGB_ASSET_ID"), "{err}");
}

#[test]
fn refuses_a_missing_or_invalid_pin() {
    assert!(pinned_contract(&BridgeConfig::default())
        .unwrap_err()
        .to_string()
        .contains("pin missing"));
    let cfg = BridgeConfig {
        rgb_asset_id: "rgb:not-a-contract".into(),
        ..BridgeConfig::default()
    };
    assert!(pinned_contract(&cfg)
        .unwrap_err()
        .to_string()
        .contains("is not a contract id"));
}

#[test]
fn parses_the_pin_rgb_asset_id_names() {
    let (history, _) = rights_send();
    let cfg = BridgeConfig {
        rgb_asset_id: history.contract_id.to_string(),
        ..BridgeConfig::default()
    };
    assert_eq!(pinned_contract(&cfg).unwrap(), history.contract_id);
}

// ===== F5: the commitment covers exactly the disclosed bundles =====

/// The tx commits both bundles; the PSBT drops the other contract's keys.
#[test]
fn refuses_bundle_hidden_from_the_psbt() {
    let (ours, theirs, mut psbt) = two_contracts();
    psbt.proprietary
        .remove(&ProprietaryKey::rgb_consumed_by(theirs.contract_id));
    let err = refusal(&psbt, ours.contract_id);
    assert!(err.contains("does not commit exactly"), "{err}");
}

#[test]
fn refuses_missing_entropy() {
    let (history, mut sent) = rights_send();
    sent.psbt.outputs[0]
        .proprietary
        .remove(&ProprietaryKey::mpc_entropy());
    let err = refusal(&sent.psbt, history.contract_id);
    assert!(err.contains("carries no MPC entropy"), "{err}");
}

#[test]
fn refuses_wrong_entropy() {
    let (history, mut sent) = rights_send();
    let entropy = sent.psbt.outputs[0].mpc_entropy().unwrap();
    sent.psbt.outputs[0].proprietary.insert(
        ProprietaryKey::mpc_entropy(),
        (entropy + 1).to_le_bytes().to_vec(),
    );
    let err = refusal(&sent.psbt, history.contract_id);
    assert!(err.contains("does not commit exactly"), "{err}");
}

/// The PSBT's own MPC keys are not read: a forged commitment key changes
/// nothing.
#[test]
fn ignores_the_psbt_mpc_commitment_key() {
    let (history, mut sent) = rights_send();
    sent.psbt.outputs[0]
        .proprietary
        .insert(ProprietaryKey::mpc_commitment(), vec![0x11; 32]);
    committed_transition(&sent.psbt, history.contract_id).unwrap();
}

// ===== F6: one disclosed transition, exactly the input map =====

#[test]
fn refuses_two_known_transitions() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let a = send_of(&mut history, rights[0]);
    let b = send_of(&mut history, rights[1]);
    let psbt = crafted(vec![rights[0].outpoint, rights[1].outpoint], |psbt| {
        psbt.push_rgb_transition(a).unwrap();
        psbt.push_rgb_transition(b).unwrap();
    });
    let err = refusal(&psbt, history.contract_id);
    assert!(err.contains("discloses 2 transitions"), "{err}");
}

#[test]
fn refuses_transition_stored_under_a_forged_opid() {
    let (mut history, rights) = issued(0xB1, &[0xA0]);
    let send = send_of(&mut history, rights[0]);
    let forged = OpId::from([0x77; 32]);
    let cid = history.contract_id;
    let psbt = crafted(vec![rights[0].outpoint], |psbt| {
        let bytes = send
            .to_strict_serialized::<{ u32::MAX as usize }>()
            .unwrap();
        psbt.proprietary
            .insert(ProprietaryKey::rgb_transition(forged), bytes.release());
        psbt.set_rgb_contract_consumer(cid, rights[0].opout, forged)
            .unwrap();
    });
    let err = refusal(&psbt, cid);
    assert!(err.contains("under opid"), "{err}");
}

#[test]
fn refuses_input_map_extra_key() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let send = send_of(&mut history, rights[0]);
    let cid = history.contract_id;
    let psbt = crafted(vec![rights[0].outpoint, rights[1].outpoint], |psbt| {
        let id = send.id();
        psbt.push_rgb_transition(send).unwrap();
        psbt.set_rgb_contract_consumer(cid, rights[1].opout, id)
            .unwrap();
    });
    let err = refusal(&psbt, cid);
    assert!(err.contains("input map closes 2 seal(s)"), "{err}");
}

/// A transition that spends both rights, whose second seal the input map
/// gives to a transition the PSBT does not disclose.
#[test]
fn refuses_input_map_foreign_opid() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let both = history
        .transition("transfer")
        .add_input(rights[0].opout, AllocatedState::Void)
        .unwrap()
        .add_input(rights[1].opout, AllocatedState::Void)
        .unwrap()
        .add_rights("mintRight", GraphSeal::with_blinded_vout(1u32, 1))
        .unwrap()
        .complete_transition()
        .unwrap();
    let cid = history.contract_id;
    let hidden = OpId::from([0x66; 32]);
    let psbt = crafted(vec![rights[0].outpoint, rights[1].outpoint], |psbt| {
        let id = both.id();
        psbt.push_rgb_transition(both).unwrap();
        let map = BTreeMap::from([(rights[0].opout, id), (rights[1].opout, hidden)]);
        psbt.proprietary.insert(
            ProprietaryKey::rgb_consumed_by(cid),
            OpoutAndOpids::new(map).serialize(),
        );
    });
    let err = refusal(&psbt, cid);
    assert!(err.contains(&format!("to transition {hidden}")), "{err}");
}

/// Another contract's transition filed under the pinned contract's bundle.
#[test]
fn refuses_transition_of_other_contract() {
    let (ours, our_rights) = issued(0xB1, &[0xA0]);
    let (mut theirs, their_rights) = issued(0xB2, &[0xA1]);
    let send = send_of(&mut theirs, their_rights[0]);
    let psbt = crafted(vec![our_rights[0].outpoint], |psbt| {
        let id = send.id();
        psbt.push_rgb_transition(send).unwrap();
        psbt.proprietary
            .remove(&ProprietaryKey::rgb_consumed_by(theirs.contract_id));
        psbt.set_rgb_contract_consumer(ours.contract_id, their_rights[0].opout, id)
            .unwrap();
    });
    let err = refusal(&psbt, ours.contract_id);
    assert!(err.contains("belongs to contract"), "{err}");
}

/// No RGB data at all: nothing to read a transition from.
#[test]
fn refuses_a_psbt_without_rgb_data() {
    let (history, _) = rights_send();
    let mut psbt = gen::witness_psbt(vec![right_outpoint(0xA0)], vec![p2tr(1)]);
    psbt.unsigned_tx.output[0].script_pubkey = Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_slice([0u8; 32])
        .into_script();
    let err = refusal(&psbt, history.contract_id);
    assert!(err.contains("exactly one"), "{err}");
}
