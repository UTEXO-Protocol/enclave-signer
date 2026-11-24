use std::collections::BTreeMap;

use amplify::confinement::NonEmptyOrdMap;
use bitcoin::hashes::Hash as _;
use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use psrgbt::{OpoutAndOpids, RgbPropKeyExt, RgbPsbtExt};
use rgb_lib::TypeOfTransition;
use rgbstd::containers::{Fascia, SealWitness};
use rgbstd::contract::AllocatedState;
use rgbstd::rgbcore::commit_verify::mpc::{
    MerkleBlock, MerkleTree, Message, MultiSource, ProtocolId,
};
use rgbstd::rgbcore::commit_verify::TryCommitVerify;
use rgbstd::{ContractId, GraphSeal, OpId, Operation, Transition, TransitionBundle};
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

/// The core on `tx` and `fascia`, with the fascia sent over the wire as
/// rgb-lib writes it. The fixtures build unsigned transactions, as rgb-lib
/// commits one.
/// No output of these fixtures is this enclave's: they carry no key origins,
/// so a transfer beside the signing transition is never its own change here.
/// [`super::super::route::tests`] covers the fascia with one.
fn not_ours(_: &Psbt, _: u32) -> bool {
    false
}

fn read(tx: &Transaction, fascia: &Fascia, pin: ContractId) -> Result<Committed> {
    let psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    let bytes = gen::fascia_bytes(fascia);
    committed_transition(&psbt, &bytes, "fascia", Pin::for_test(pin), &not_ours)
}

fn refusal(tx: &Transaction, fascia: &Fascia, pin: ContractId) -> String {
    read(tx, fascia, pin).unwrap_err().to_string()
}

/// The core on `tx` and raw `bytes`, for the fascia bytes no fixture builds.
fn read_bytes(tx: &Transaction, bytes: &[u8], pin: ContractId) -> Result<Committed> {
    let psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    committed_transition(&psbt, bytes, "fascia", Pin::for_test(pin), &not_ours)
}

/// A PSBT that spends `inputs`, with RGB data `craft` writes, then committed
/// with the OP_RETURN on vout 0. Returns its tx and fascia.
fn crafted(inputs: Vec<OutPoint>, craft: impl FnOnce(&mut Psbt)) -> (Transaction, Fascia) {
    let mut psbt = gen::witness_psbt(inputs, vec![p2tr(1), p2tr(2)]);
    craft(&mut psbt);
    let fascia = gen::rgb_commit(&mut psbt, 0, ENTROPY);
    (psbt.unsigned_tx, fascia)
}

/// The rights send of `right` to vouts 1 and 2, built on `history`.
fn send_of(history: &mut History, right: Utxo) -> Transition {
    history.rights_transition(right, &[1, 2])
}

/// `fascia` with its seal witness edited.
fn with_witness(fascia: &Fascia, edit: impl FnOnce(&mut SealWitness)) -> Fascia {
    let mut witness = fascia.seal_witness().clone();
    edit(&mut witness);
    Fascia::new(witness, fascia.bundles().clone())
}

/// `fascia` disclosing `bundles` instead of its own.
fn with_bundles(fascia: &Fascia, bundles: BTreeMap<ContractId, TransitionBundle>) -> Fascia {
    let bundles = NonEmptyOrdMap::try_from(bundles).unwrap();
    Fascia::new(fascia.seal_witness().clone(), bundles)
}

/// The one bundle of contract `cid` that `fascia` discloses.
fn bundle(fascia: &Fascia, cid: ContractId) -> TransitionBundle {
    fascia.bundles().get(&cid).unwrap().clone()
}

// ===== the happy path =====

#[test]
fn reads_the_one_propagate_a_rights_send_commits() {
    let (history, sent) = rights_send();
    let committed = read(&sent.tx, &sent.fascia, history.contract_id).unwrap();
    assert_eq!(committed.opid, sent.opid);
    assert_eq!(committed.txid, sent.tx.compute_txid());
    assert_eq!(committed.transition.opid, sent.opid.to_string());
    assert_eq!(committed.transition.r#type, TypeOfTransition::Propagate);
}

/// rgb-lib strips every RGB key; the fascia alone carries the mint.
#[test]
fn reads_a_mint_from_a_psbt_stripped_of_rgb_keys() {
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
    let psbt = &minted.psbt;
    assert!(psbt.proprietary.is_empty());
    assert!(psbt.outputs.iter().all(|o| o.proprietary.is_empty()));
    assert!(psbt.rgb_bundles().unwrap().is_empty());
    let committed = read(&psbt.unsigned_tx, &minted.fascia, history.contract_id).unwrap();
    assert_eq!(committed.opid, minted.opid);
    assert_eq!(committed.transition.r#type, TypeOfTransition::Mint);
}

// ===== the fascia itself =====

#[test]
fn refuses_an_empty_fascia() {
    let (history, sent) = rights_send();
    let err = read_bytes(&sent.tx, &[], history.contract_id)
        .unwrap_err()
        .to_string();
    assert!(err.contains("fascia required"), "{err}");
}

/// Junk, and a PSBT in place of the fascia. rgb-lib is the only decoder, so
/// its refusal is the one the core reports.
#[test]
fn refuses_a_fascia_that_does_not_decode() {
    let (history, sent) = rights_send();
    for bytes in [b"junk".to_vec(), sent.psbt.serialize()] {
        let err = read_bytes(&sent.tx, &bytes, history.contract_id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("rgb-lib refused the fascia"), "{err}");
    }
}

/// rgb-lib reads the whole file, so a fascia with anything after it is not one.
#[test]
fn refuses_a_fascia_with_trailing_bytes() {
    let (history, sent) = rights_send();
    let mut bytes = sent.fascia_bytes();
    bytes.push(0);
    let err = read_bytes(&sent.tx, &bytes, history.contract_id)
        .unwrap_err()
        .to_string();
    assert!(err.contains("rgb-lib refused the fascia"), "{err}");
}

#[test]
fn refuses_a_fascia_of_another_tx() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let ours = history.send_rights(rights[0], &[1, 2], vec![], vec![p2tr(1), p2tr(2)]);
    let other = history.send_rights(rights[1], &[1, 2], vec![], vec![p2tr(3), p2tr(4)]);
    let err = refusal(&ours.tx, &other.fascia, history.contract_id);
    assert!(
        err.contains(&format!(
            "fascia witness ID {} does not match PSBT TXID {}",
            other.tx.compute_txid(),
            ours.tx.compute_txid()
        )),
        "{err}"
    );
}

/// A sibling tx commits the same bundles, so only the witness id check refuses it.
#[test]
fn refuses_a_fascia_of_a_sibling_tx_with_the_same_commitment() {
    let (history, sent) = rights_send();
    let fascia = with_witness(&sent.fascia, |witness| {
        witness.tx.lock_time = bitcoin::absolute::LockTime::from_consensus(7);
    });
    let err = refusal(&sent.tx, &fascia, history.contract_id);
    assert!(err.contains("does not match PSBT TXID"), "{err}");
}

/// The size bound runs before the bytes reach a scratch file or rgb-lib: it
/// is what bounds the work of the MPC rebuild.
#[test]
fn refuses_a_fascia_over_the_psbt_size_limit() {
    let (history, sent) = rights_send();
    let bytes = vec![0u8; crate::config::MAX_PSBT_BYTES + 1];
    let err = read_bytes(&sent.tx, &bytes, history.contract_id)
        .unwrap_err()
        .to_string();
    assert!(err.contains("the limit is"), "{err}");
}

// ===== F3: the close method =====

/// Inserts `out` before the OP_RETURN, then commits with the host on vout 1.
fn with_output_before_the_op_return(out: TxOut) -> (History, Transaction, Fascia) {
    let (mut history, rights) = issued(0xB1, &[0xA0]);
    let send = send_of(&mut history, rights[0]);
    let mut psbt = gen::witness_psbt(vec![rights[0].outpoint], vec![p2tr(1), p2tr(2)]);
    psbt.unsigned_tx.output.insert(0, out);
    psbt.outputs.insert(0, Default::default());
    psbt.push_rgb_transition(send).unwrap();
    let fascia = gen::rgb_commit(&mut psbt, 1, ENTROPY);
    (history, psbt.unsigned_tx, fascia)
}

/// `sent` with its tx edited, and a fascia of that tx, so only the edit fails.
fn edited_tx(sent: &gen::Committed, edit: impl FnOnce(&mut Transaction)) -> (Transaction, Fascia) {
    let mut tx = sent.tx.clone();
    edit(&mut tx);
    let fascia = with_witness(&sent.fascia, |witness| witness.tx = tx.clone());
    (tx, fascia)
}

#[test]
fn refuses_p2tr_output_before_the_op_return() {
    let (history, tx, fascia) = with_output_before_the_op_return(p2tr(9));
    let err = refusal(&tx, &fascia, history.contract_id);
    assert!(
        err.contains("output 0 is a P2TR before the OP_RETURN"),
        "{err}"
    );
}

/// P2A is witness v1 but not P2TR, so consensus does not read it as a host.
#[test]
fn p2a_output_before_the_op_return_is_not_a_host() {
    let anchor = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_p2a(),
    };
    let (history, tx, fascia) = with_output_before_the_op_return(anchor);
    read(&tx, &fascia, history.contract_id).unwrap();
}

#[test]
fn refuses_a_tx_without_an_op_return() {
    let (mut history, rights) = issued(0xB1, &[0xA0]);
    let outputs = vec![gen::dust(1), gen::dust(2)];
    let sent = history.send_rights(rights[0], &[1, 2], vec![], outputs);
    let (tx, fascia) = edited_tx(&sent, |tx| {
        tx.output.remove(0);
    });
    let err = refusal(&tx, &fascia, history.contract_id);
    assert!(err.contains("no OP_RETURN"), "{err}");
}

#[test]
fn refuses_op_return_that_is_not_34_bytes() {
    let (history, sent) = rights_send();
    let (tx, fascia) = edited_tx(&sent, |tx| {
        let script = &mut tx.output[0].script_pubkey;
        let mut longer = script.to_bytes();
        longer.push(0x00);
        *script = ScriptBuf::from_bytes(longer);
    });
    let err = refusal(&tx, &fascia, history.contract_id);
    assert!(err.contains("doesn't commit to"), "{err}");
}

// ===== F4: the pinned contract =====

/// Our rights send and another contract's right moved to `their_vouts`, in one
/// PSBT and one commitment.
fn two_contracts_moving(their_vouts: &[u32]) -> (History, History, Transaction, Fascia) {
    let (mut ours, our_rights) = issued(0xB1, &[0xA0]);
    let (mut theirs, their_rights) = issued(0xB2, &[0xA1]);
    let our_send = send_of(&mut ours, our_rights[0]);
    let their_send = theirs.rights_transition(their_rights[0], their_vouts);
    let inputs = vec![our_rights[0].outpoint, their_rights[0].outpoint];
    let (tx, fascia) = crafted(inputs, |psbt| {
        psbt.push_rgb_transition(our_send).unwrap();
        psbt.push_rgb_transition(their_send).unwrap();
    });
    (ours, theirs, tx, fascia)
}

/// Our rights send and another contract's, to vouts 1 and 2.
fn two_contracts() -> (History, History, Transaction, Fascia) {
    two_contracts_moving(&[1, 2])
}

/// The core on `tx` with vout 2 this enclave's own output.
fn read_owning_vout_2(tx: &Transaction, fascia: &Fascia, pin: ContractId) -> Result<Committed> {
    let psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    let bytes = gen::fascia_bytes(fascia);
    let own = |_: &Psbt, vout: u32| vout == 2;
    committed_transition(&psbt, &bytes, "fascia", Pin::for_test(pin), &own)
}

/// Another contract's bundle is read past wherever it moves its state: to
/// our output, to an output that is not ours, or as two rights made of one.
#[test]
fn reads_past_a_second_contract_bundle_wherever_it_moves_state() {
    for their_vouts in [&[2][..], &[1], &[2, 2]] {
        let (ours, _, tx, fascia) = two_contracts_moving(their_vouts);
        let committed = read_owning_vout_2(&tx, &fascia, ours.contract_id).unwrap();
        assert_eq!(committed.transition.outputs.len(), 2, "{their_vouts:?}");
    }
}

/// The seal rgb-lib assigns when the change is full: a blinded one, on a UTXO
/// the wallet already holds.
#[test]
fn reads_past_a_second_contract_bundle_that_moves_state_to_a_blinded_seal() {
    let (mut ours, our_rights) = issued(0xB1, &[0xA0]);
    let (mut theirs, their_rights) = issued(0xB2, &[0xA1]);
    let our_send = send_of(&mut ours, our_rights[0]);
    let held = GraphSeal::with_blinded_vout(0u32, 7).to_secret_seal();
    let their_move = theirs
        .transition("propagate")
        .add_input(their_rights[0].opout, AllocatedState::Void)
        .unwrap()
        .add_rights("mintRight", rgbstd::BuilderSeal::Concealed(held))
        .unwrap()
        .complete_transition()
        .unwrap();
    let inputs = vec![our_rights[0].outpoint, their_rights[0].outpoint];
    let (tx, fascia) = crafted(inputs, |psbt| {
        psbt.push_rgb_transition(our_send).unwrap();
        psbt.push_rgb_transition(their_move).unwrap();
    });
    let committed = read_owning_vout_2(&tx, &fascia, ours.contract_id).unwrap();
    assert_eq!(committed.transition.outputs.len(), 2);
}

/// Another contract's bundle that is no move, here a mint, is read past too:
/// the transition the signer reads is of the pinned asset.
#[test]
fn reads_past_a_second_contract_bundle_that_is_not_a_move() {
    let (mut ours, our_rights) = issued(0xB1, &[0xA0]);
    let (mut theirs, their_rights) = issued(0xB2, &[0xA1]);
    let our_send = send_of(&mut ours, our_rights[0]);
    let their_mint = theirs
        .transition("mint")
        .add_input(their_rights[0].opout, AllocatedState::Void)
        .unwrap()
        .add_metadata("beforeBlock", rgbstd::stl::BlockNumber::from(90u64))
        .unwrap()
        .add_global_state("issuedSupply", rgbstd::Amount::from(5_000u64))
        .unwrap()
        .add_fungible_state(
            "assetOwner",
            GraphSeal::with_blinded_vout(2u32, 7),
            5_000u64,
        )
        .unwrap()
        .complete_transition()
        .unwrap();
    let inputs = vec![our_rights[0].outpoint, their_rights[0].outpoint];
    let (tx, fascia) = crafted(inputs, |psbt| {
        psbt.push_rgb_transition(our_send).unwrap();
        psbt.push_rgb_transition(their_mint).unwrap();
    });
    let committed = read_owning_vout_2(&tx, &fascia, ours.contract_id).unwrap();
    assert_eq!(committed.transition.outputs.len(), 2);
}

#[test]
fn refuses_bundle_of_unpinned_contract() {
    let (_, sent) = rights_send();
    let (other, _) = issued(0xB2, &[0xA1]);
    let err = refusal(&sent.tx, &sent.fascia, other.contract_id);
    assert!(
        err.contains("no transition of the pinned RGB_ASSET_ID"),
        "{err}"
    );
}

#[test]
fn refuses_a_missing_or_invalid_pin() {
    assert!(Pin::of(&BridgeConfig::default())
        .unwrap_err()
        .to_string()
        .contains("pin missing"));
    let cfg = BridgeConfig {
        rgb_asset_id: "rgb:not-a-contract".into(),
        ..BridgeConfig::default()
    };
    assert!(Pin::of(&cfg)
        .unwrap_err()
        .to_string()
        .contains("is not a contract id"));
}

// ===== F5: the tx commits exactly the bundles the fascia discloses =====

/// The tx commits both bundles; the fascia drops the other contract's.
#[test]
fn refuses_a_bundle_hidden_from_the_fascia() {
    let (ours, _, tx, fascia) = two_contracts();
    let only_ours = BTreeMap::from([(ours.contract_id, bundle(&fascia, ours.contract_id))]);
    let err = refusal(&tx, &with_bundles(&fascia, only_ours), ours.contract_id);
    assert!(err.contains("doesn't commit to"), "{err}");
}

/// The fascia of our tx, but with the bundle of another send of the asset.
#[test]
fn refuses_a_fascia_whose_bundle_the_tx_does_not_commit() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let cid = history.contract_id;
    let ours = history.send_rights(rights[0], &[1, 2], vec![], vec![p2tr(1), p2tr(2)]);
    let other = history.send_rights(rights[1], &[1, 2], vec![], vec![p2tr(3), p2tr(4)]);
    let swapped = BTreeMap::from([(cid, bundle(&other.fascia, cid))]);
    let err = refusal(&ours.tx, &with_bundles(&ours.fascia, swapped), cid);
    assert!(err.contains("doesn't commit to"), "{err}");
}

/// A concealed MPC block drops the entropy, so the root cannot be rebuilt.
/// The core passes none of its own, so rgb-lib has no source for it either.
#[test]
fn refuses_a_fascia_without_entropy() {
    let (history, sent) = rights_send();
    let fascia = with_witness(&sent.fascia, |witness| {
        let protocol = ProtocolId::from(history.contract_id);
        witness.mpc_merkle_block.conceal_other(protocol).unwrap();
    });
    assert_eq!(fascia.seal_witness().mpc_merkle_block.entropy(), None);
    let err = refusal(&sent.tx, &fascia, history.contract_id);
    assert!(err.contains("doesn't carry the entropy"), "{err}");
}

#[test]
fn refuses_a_fascia_whose_entropy_does_not_give_the_op_return() {
    let (history, sent) = rights_send();
    let cid = history.contract_id;
    let entropy = sent
        .fascia
        .seal_witness()
        .mpc_merkle_block
        .entropy()
        .unwrap();
    let mut source = MultiSource::with_static_entropy(entropy + 1);
    source
        .messages
        .insert(
            ProtocolId::from(cid),
            Message::from(bundle(&sent.fascia, cid).bundle_id()),
        )
        .unwrap();
    let block = MerkleBlock::from(MerkleTree::try_commit(&source).unwrap());
    let fascia = with_witness(&sent.fascia, |witness| witness.mpc_merkle_block = block);
    let err = refusal(&sent.tx, &fascia, cid);
    assert!(err.contains("doesn't commit to"), "{err}");
}

// ===== F6: one transition to read, moves beside it, exactly the input maps =====

#[test]
fn refuses_two_known_transitions() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let a = send_of(&mut history, rights[0]);
    let b = send_of(&mut history, rights[1]);
    let (tx, fascia) = crafted(vec![rights[0].outpoint, rights[1].outpoint], |psbt| {
        psbt.push_rgb_transition(a).unwrap();
        psbt.push_rgb_transition(b).unwrap();
    });
    let err = refusal(&tx, &fascia, history.contract_id);
    assert!(
        err.contains("neither a move of state to this enclave's own outputs"),
        "{err}"
    );
}

#[test]
fn refuses_transition_stored_under_a_forged_opid() {
    let (mut history, rights) = issued(0xB1, &[0xA0]);
    let send = send_of(&mut history, rights[0]);
    let forged = OpId::from([0x77; 32]);
    let cid = history.contract_id;
    let (tx, fascia) = crafted(vec![rights[0].outpoint], |psbt| {
        let bytes = send
            .to_strict_serialized::<{ u32::MAX as usize }>()
            .unwrap();
        psbt.proprietary
            .insert(ProprietaryKey::rgb_transition(forged), bytes.release());
        psbt.set_rgb_contract_consumer(cid, rights[0].opout, forged)
            .unwrap();
    });
    let err = refusal(&tx, &fascia, cid);
    assert!(
        err.contains(&format!("transition {forged} is not committed")),
        "{err}"
    );
}

#[test]
fn refuses_input_map_extra_key() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let send = send_of(&mut history, rights[0]);
    let cid = history.contract_id;
    let (tx, fascia) = crafted(vec![rights[0].outpoint, rights[1].outpoint], |psbt| {
        let id = send.id();
        psbt.push_rgb_transition(send).unwrap();
        psbt.set_rgb_contract_consumer(cid, rights[1].opout, id)
            .unwrap();
    });
    let err = refusal(&tx, &fascia, cid);
    assert!(
        err.contains("closes 2 seal(s), but the transitions it discloses spend 1"),
        "{err}"
    );
}

/// A transition that spends both rights, whose second seal the input map
/// gives to a transition the fascia does not disclose. The bundle then
/// commits that other transition for a seal the disclosed one closes.
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
    let both_id = both.id();
    let (tx, fascia) = crafted(vec![rights[0].outpoint, rights[1].outpoint], |psbt| {
        let id = both.id();
        psbt.push_rgb_transition(both).unwrap();
        let map = BTreeMap::from([(rights[0].opout, id), (rights[1].opout, hidden)]);
        psbt.proprietary.insert(
            ProprietaryKey::rgb_consumed_by(cid),
            OpoutAndOpids::new(map).serialize(),
        );
    });
    let err = refusal(&tx, &fascia, cid);
    assert!(
        err.contains(&format!("transition {} is not committed", both_id)),
        "{err}"
    );
}

/// The input map names a transition the fascia does not disclose, for a seal
/// the disclosed transition does not close. The bundle commits that other
/// transition, so a signature would commit a state move the enclave never saw.
#[test]
fn refuses_an_input_map_that_names_a_hidden_transition() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let send = send_of(&mut history, rights[0]);
    let cid = history.contract_id;
    let hidden = OpId::from([0x66; 32]);
    let (tx, fascia) = crafted(vec![rights[0].outpoint, rights[1].outpoint], |psbt| {
        psbt.push_rgb_transition(send).unwrap();
        psbt.set_rgb_contract_consumer(cid, rights[1].opout, hidden)
            .unwrap();
    });
    let err = refusal(&tx, &fascia, cid);
    assert!(
        err.contains("commits 2 transitions of asset") && err.contains("and discloses 1"),
        "{err}"
    );
}

/// A fascia must disclose every transition its bundle commits, unlike a
/// consignment, whose export conceals the history a later holder does not
/// need. It cannot do otherwise: `rgb_commit` builds the bundle from the input
/// map, so a transition the map does not name is not in the bundle at all.
/// Pushing one the map omits leaves the seals of F6 to refuse the fascia.
#[test]
fn refuses_a_fascia_whose_map_does_not_name_every_transition_pushed() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let first = send_of(&mut history, rights[0]);
    let second = history.rights_transition(rights[1], &[1, 2]);
    let cid = history.contract_id;
    let (tx, fascia) = crafted(vec![rights[0].outpoint, rights[1].outpoint], |psbt| {
        let only = first.id();
        psbt.push_rgb_transition(first).unwrap();
        psbt.push_rgb_transition(second).unwrap();
        // Both seals filed under the first transition, so the map names one.
        let map = BTreeMap::from([(rights[0].opout, only), (rights[1].opout, only)]);
        psbt.proprietary.insert(
            ProprietaryKey::rgb_consumed_by(cid),
            OpoutAndOpids::new(map).serialize(),
        );
    });
    let err = refusal(&tx, &fascia, cid);
    assert!(err.contains("closes 2 seal(s)"), "{err}");
}

/// Another contract's transition filed under the pinned contract's bundle.
#[test]
fn refuses_transition_of_other_contract() {
    let (ours, our_rights) = issued(0xB1, &[0xA0]);
    let (mut theirs, their_rights) = issued(0xB2, &[0xA1]);
    let send = send_of(&mut theirs, their_rights[0]);
    let (tx, fascia) = crafted(vec![our_rights[0].outpoint], |psbt| {
        let id = send.id();
        psbt.push_rgb_transition(send).unwrap();
        psbt.proprietary
            .remove(&ProprietaryKey::rgb_consumed_by(theirs.contract_id));
        psbt.set_rgb_contract_consumer(ours.contract_id, their_rights[0].opout, id)
            .unwrap();
    });
    let err = refusal(&tx, &fascia, ours.contract_id);
    assert!(err.contains("is of contract"), "{err}");
}

// ===== the rules the core puts around the inspection =====

/// rgb-lib's inspection of `sent`'s fascia, and what the core read from it.
/// The core accepts it, so each refusal below needs an edited inspection.
fn inspected(sent: &gen::Committed, pin: ContractId) -> (RgbInspection, Committed) {
    let bytes = sent.fascia_bytes();
    let psbt = Psbt::from_unsigned_tx(sent.tx.clone()).unwrap();
    let inspection = inspect(&psbt, &bytes, "fascia", Pin::for_test(pin)).unwrap();
    let committed = read(&sent.tx, &sent.fascia, pin).unwrap();
    (inspection, committed)
}

fn agrees(inspection: &RgbInspection, committed: &Committed, pin: ContractId) -> Result<()> {
    let psbt = Psbt::from_unsigned_tx(bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    })
    .unwrap();
    pinned_transition(
        inspection,
        "fascia",
        Pin::for_test(pin),
        committed.txid,
        &psbt,
        &not_ours,
    )
    .map(|_| ())
}

/// rgb-lib verifies the commitment with the DBC proof the fascia carries. A
/// tapret proof commits in a P2TR output, which F3 does not read, so the core
/// signs an opret commitment only.
#[test]
fn refuses_a_close_method_that_is_not_opret() {
    let (history, sent) = rights_send();
    let cid = history.contract_id;
    let (mut inspection, committed) = inspected(&sent, cid);
    agrees(&inspection, &committed, cid).unwrap();
    inspection.close_method = rgb_lib::CloseMethod::TapretFirst;
    let err = agrees(&inspection, &committed, cid)
        .unwrap_err()
        .to_string();
    assert!(err.contains("opret commitment only"), "{err}");
}

/// The inspection must be of the PSBT's tx and of the pinned asset. rgb-lib
/// proves the commitment; which tx and which asset it may commit for is the
/// enclave's rule, so it is checked on what the inspection reports.
#[test]
fn refuses_an_inspection_that_names_another_tx_or_asset() {
    let (history, sent) = rights_send();
    let cid = history.contract_id;
    let (inspection, committed) = inspected(&sent, cid);

    let mut other_tx = inspection.clone();
    other_tx.txid = bitcoin::Txid::from_byte_array([0x11; 32]).to_string();
    let err = agrees(&other_tx, &committed, cid).unwrap_err().to_string();
    assert!(err.contains("not the PSBT's tx"), "{err}");

    let mut other_asset = inspection.clone();
    other_asset.operations[0].asset_id = issued(0xB2, &[0xA1]).0.contract_id.to_string();
    let err = agrees(&other_asset, &committed, cid)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("no transition of the pinned RGB_ASSET_ID"),
        "{err}"
    );
}

/// The densest fascia measured: one propagate of 43 681 rights that share an
/// output, about 14 bytes each.
fn widest_fascia() -> (History, gen::Committed) {
    let (mut history, rights) = issued(0xB1, &[0xA0]);
    let mut send = history
        .transition("propagate")
        .add_input(rights[0].opout, AllocatedState::Void)
        .unwrap();
    for no in 0..43_681u64 {
        let seal = GraphSeal::with_blinded_vout(1u32, 0x10_0000 + no);
        send = send.add_rights("mintRight", seal).unwrap();
    }
    let send = send.complete_transition().unwrap();
    let sent = history.commit_psbt(vec![send], vec![rights[0].outpoint], vec![p2tr(1)]);
    (history, sent)
}

/// The whole core on that fascia: rgb-lib's parse of the scratch file and the
/// inspection it builds, which holds a record for each right. Only rgb-lib
/// decodes a fascia, so one decoded fascia is live at a time. The peak is
/// above the request memory factor, so the check is the one `memory.rs` names
/// for such a parser: a fascia at its size limit fits the request bound of a
/// frame of that size.
#[test]
fn the_fascia_core_stays_within_the_bound_of_its_size_limit() {
    use crate::memory::peak;

    let (history, sent) = widest_fascia();
    let (bytes, committed, peak) = peak::measure(
        || sent.fascia_bytes(),
        |bytes| {
            let psbt = Psbt::from_unsigned_tx(sent.tx.clone()).unwrap();
            committed_transition(
                &psbt,
                bytes,
                "fascia",
                Pin::for_test(history.contract_id),
                &not_ours,
            )
        },
    );
    assert!(bytes.len() > 600_000, "the fascia is not wide");
    committed.unwrap();
    println!(
        "fascia core: {} input bytes, peak heap {peak} bytes, factor {:.2}",
        bytes.len(),
        peak as f64 / bytes.len() as f64
    );
    // The peak grows with the fascia, so the bound is checked at the limit.
    let limit = crate::config::MAX_PSBT_BYTES;
    let at_limit = peak * limit / bytes.len();
    peak::assert_within_request_bound("fascia core at the PSBT limit", limit, at_limit);
}
