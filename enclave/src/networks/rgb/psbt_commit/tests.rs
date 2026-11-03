use std::collections::BTreeMap;

use amplify::confinement::NonEmptyOrdMap;
use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use psrgbt::{OpoutAndOpids, RgbPropKeyExt, RgbPsbtExt};
use rgbstd::containers::SealWitness;
use rgbstd::contract::AllocatedState;
use rgbstd::rgbcore::commit_verify::mpc::MerkleBlock;
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

/// The core on `tx` and `fascia`, with the fascia sent over the wire as
/// rgb-lib writes it.
fn read(tx: &Transaction, fascia: &Fascia, pin: ContractId) -> Result<Committed> {
    let wire = parse_fascia(&gen::fascia_bytes(fascia), "fascia")?;
    committed_transition(tx, &wire, pin)
}

fn refusal(tx: &Transaction, fascia: &Fascia, pin: ContractId) -> String {
    read(tx, fascia, pin).unwrap_err().to_string()
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
    assert_eq!(committed.transition.id(), sent.opid);
    assert_eq!(committed.transition.transition_type, schemata::TS_PROPAGATE);
}

/// rgb-lib f3975623 strips every RGB key; the fascia alone carries the mint.
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
    assert_eq!(committed.transition.transition_type, schemata::TS_MINT);
}

#[test]
fn decodes_the_fascia_bytes_rgb_lib_writes() {
    let (_, sent) = rights_send();
    let decoded = parse_fascia(&sent.fascia_bytes(), "fascia").unwrap();
    assert_eq!(decoded, sent.fascia);
}

// ===== the fascia itself =====

#[test]
fn refuses_an_empty_fascia() {
    let err = parse_fascia(&[], "fascia").unwrap_err().to_string();
    assert!(err.contains("fascia required"), "{err}");
}

/// Junk, and the PSBT an old listener would put in the field.
#[test]
fn refuses_a_fascia_that_does_not_decode() {
    let (_, sent) = rights_send();
    for bytes in [b"junk".to_vec(), sent.psbt.serialize()] {
        let err = parse_fascia(&bytes, "fascia").unwrap_err().to_string();
        assert!(err.contains("fascia is not an rgb-lib fascia"), "{err}");
    }
}

/// rgb-lib reads the whole file; so does the enclave.
#[test]
fn refuses_a_fascia_with_trailing_bytes() {
    let (_, sent) = rights_send();
    let mut bytes = sent.fascia_bytes();
    bytes.push(0);
    let err = parse_fascia(&bytes, "fascia").unwrap_err().to_string();
    assert!(err.contains("not an rgb-lib fascia"), "{err}");
}

#[test]
fn refuses_a_fascia_of_another_tx() {
    let (mut history, rights) = issued(0xB1, &[0xA0, 0xA1]);
    let ours = history.send_rights(rights[0], &[1, 2], vec![], vec![p2tr(1), p2tr(2)]);
    let other = history.send_rights(rights[1], &[1, 2], vec![], vec![p2tr(3), p2tr(4)]);
    let err = refusal(&ours.tx, &other.fascia, history.contract_id);
    assert!(
        err.contains(&format!("fascia is of tx {}", other.tx.compute_txid())),
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
    assert!(err.contains("fascia is of tx"), "{err}");
}

#[test]
fn refuses_a_fascia_over_16_mib() {
    let err = parse_fascia(&vec![0u8; U24 + 1], "fascia")
        .unwrap_err()
        .to_string();
    assert!(err.contains("fascia is too large"), "{err}");
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

#[test]
fn accepts_p2tr_after_the_op_return() {
    let (history, sent) = rights_send();
    assert!(sent.tx.output[1].script_pubkey.is_p2tr());
    read(&sent.tx, &sent.fascia, history.contract_id).unwrap();
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
    assert!(err.contains("does not commit exactly"), "{err}");
}

// ===== F4: the pinned contract =====

/// Our rights send and another contract's, in one PSBT and one commitment.
fn two_contracts() -> (History, History, Transaction, Fascia) {
    let (mut ours, our_rights) = issued(0xB1, &[0xA0]);
    let (mut theirs, their_rights) = issued(0xB2, &[0xA1]);
    let our_send = send_of(&mut ours, our_rights[0]);
    let their_send = send_of(&mut theirs, their_rights[0]);
    let inputs = vec![our_rights[0].outpoint, their_rights[0].outpoint];
    let (tx, fascia) = crafted(inputs, |psbt| {
        psbt.push_rgb_transition(our_send).unwrap();
        psbt.push_rgb_transition(their_send).unwrap();
    });
    (ours, theirs, tx, fascia)
}

#[test]
fn refuses_second_contract_bundle() {
    let (ours, _, tx, fascia) = two_contracts();
    let err = refusal(&tx, &fascia, ours.contract_id);
    assert!(err.contains("discloses 2 contract bundles"), "{err}");
}

#[test]
fn refuses_bundle_of_unpinned_contract() {
    let (_, sent) = rights_send();
    let (other, _) = issued(0xB2, &[0xA1]);
    let err = refusal(&sent.tx, &sent.fascia, other.contract_id);
    assert!(err.contains("not of the pinned RGB_ASSET_ID"), "{err}");
}

/// The tx commits our bundle alone; the fascia adds another contract's.
#[test]
fn refuses_a_fascia_with_an_extra_contract() {
    let (history, sent) = rights_send();
    let (mut theirs, their_rights) = issued(0xB2, &[0xA1]);
    let their_send = theirs.send_rights(their_rights[0], &[1], vec![], vec![p2tr(3)]);
    let mut bundles = BTreeMap::from([(
        history.contract_id,
        bundle(&sent.fascia, history.contract_id),
    )]);
    bundles.insert(
        theirs.contract_id,
        bundle(&their_send.fascia, theirs.contract_id),
    );
    let fascia = with_bundles(&sent.fascia, bundles);
    let err = refusal(&sent.tx, &fascia, history.contract_id);
    assert!(err.contains("discloses 2 contract bundles"), "{err}");
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

// ===== F5: the tx commits exactly the bundles the fascia discloses =====

/// The tx commits both bundles; the fascia drops the other contract's.
#[test]
fn refuses_a_bundle_hidden_from_the_fascia() {
    let (ours, _, tx, fascia) = two_contracts();
    let only_ours = BTreeMap::from([(ours.contract_id, bundle(&fascia, ours.contract_id))]);
    let err = refusal(&tx, &with_bundles(&fascia, only_ours), ours.contract_id);
    assert!(err.contains("does not commit exactly"), "{err}");
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
    assert!(err.contains("does not commit exactly"), "{err}");
}

/// A concealed MPC block drops the entropy, so the root cannot be rebuilt.
#[test]
fn refuses_a_fascia_without_entropy() {
    let (history, sent) = rights_send();
    let fascia = with_witness(&sent.fascia, |witness| {
        let protocol = ProtocolId::from(history.contract_id);
        witness.mpc_merkle_block.conceal_other(protocol).unwrap();
    });
    assert_eq!(fascia.seal_witness().mpc_merkle_block.entropy(), None);
    let err = refusal(&sent.tx, &fascia, history.contract_id);
    assert!(err.contains("carries no MPC entropy"), "{err}");
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
    assert!(err.contains("does not commit exactly"), "{err}");
}

// ===== F6: one disclosed transition, exactly the input map =====

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
    assert!(err.contains("discloses 2 transitions"), "{err}");
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
    assert!(err.contains("under opid"), "{err}");
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
    assert!(err.contains("input map closes 2 seal(s)"), "{err}");
}

/// A transition that spends both rights, whose second seal the input map
/// gives to a transition the fascia does not disclose.
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
    assert!(err.contains(&format!("to transition {hidden}")), "{err}");
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
    assert!(err.contains("belongs to contract"), "{err}");
}
