use bitcoin::{Amount, TxOut};
use psrgbt::RgbPsbtExt;
use rgbstd::containers::Fascia;
use rgbstd::contract::AllocatedState;
use rgbstd::{GraphSeal, Transition};

use super::*;
use crate::networks::rgb::btc_ownership::tests as fx;
use crate::test_support::bfa_consignment::{self as gen, Committed as Made, History, Issue, Utxo};

fn p2tr(tag: u8) -> TxOut {
    TxOut {
        value: Amount::from_sat(3_000),
        script_pubkey: fx::foreign_address(tag),
    }
}

/// An asset with genesis rights on `tags`, and those rights.
fn issued(tags: &[u8]) -> (History, Vec<Utxo>) {
    let outpoints: Vec<_> = tags.iter().map(|&t| gen::outpoint(t, 0)).collect();
    let history = History::issue(Issue::new(42161, [0xB1; 20], outpoints.clone()));
    let rights = (0u16..)
        .zip(outpoints)
        .map(|(no, outpoint)| history.genesis_right(no, outpoint))
        .collect();
    (history, rights)
}

/// The issuer's seed: the genesis right sent to rights on vouts 1 and 2.
fn seeded() -> (History, Made, Vec<Utxo>) {
    let (mut history, rights) = issued(&[0xA0]);
    let seed = history.send_rights(rights[0], &[1, 2], vec![], vec![p2tr(1), p2tr(2)]);
    let made = gen::rights_made(&seed, &[1, 2]);
    (history, seed, made)
}

/// A refill of `right`: two rights on vouts 1 and 2.
fn refill(history: &mut History, right: Utxo) -> Made {
    history.send_rights(right, &[1, 2], vec![], vec![p2tr(3), p2tr(4)])
}

fn proof(child: &Made, parent: &Made, right: Utxo, history: &History) -> Result<usize> {
    right_input(
        &child.psbt,
        &parent.fascia_bytes(),
        right.opout,
        history.contract_id,
    )
}

fn refusal(child: &Made, parent: &Made, right: Utxo, history: &History) -> String {
    proof(child, parent, right, history)
        .unwrap_err()
        .to_string()
}

/// The seed's PSBT is stripped, so the right is proved from its fascia alone.
#[test]
fn accepts_issuer_seed_right() {
    let (mut history, seed, rights) = seeded();
    assert!(seed.psbt.rgb_bundles().unwrap().is_empty());
    let child = refill(&mut history, rights[1]);
    assert_eq!(proof(&child, &seed, rights[1], &history).unwrap(), 0);
}

#[test]
fn accepts_refill_made_right() {
    let (mut history, _, rights) = seeded();
    let first = refill(&mut history, rights[0]);
    let made = gen::rights_made(&first, &[1, 2]);
    let child = refill(&mut history, made[0]);
    assert_eq!(proof(&child, &first, made[0], &history).unwrap(), 0);
}

/// A refill spends a fee input beside the right: the proof finds the right.
#[test]
fn finds_the_right_after_a_fee_input() {
    let (mut history, seed, rights) = seeded();
    let fee = gen::outpoint(0xF1, 0);
    let mut child = refill(&mut history, rights[0]);
    child
        .psbt
        .unsigned_tx
        .input
        .insert(0, child.psbt.unsigned_tx.input[0].clone());
    child.psbt.unsigned_tx.input[0].previous_output = fee;
    child.psbt.inputs.insert(0, Default::default());
    assert_eq!(proof(&child, &seed, rights[0], &history).unwrap(), 1);
}

#[test]
fn refuses_missing_parent_fascia() {
    let (mut history, _, rights) = seeded();
    let child = refill(&mut history, rights[0]);
    let err = right_input(&child.psbt, &[], rights[0].opout, history.contract_id).unwrap_err();
    assert!(err.to_string().contains("parent_fascia required"), "{err}");
}

/// Junk, and the parent PSBT an old connector sends.
#[test]
fn refuses_a_parent_that_is_not_a_fascia() {
    let (mut history, seed, rights) = seeded();
    let child = refill(&mut history, rights[0]);
    for parent in [b"junk".to_vec(), seed.psbt.serialize()] {
        let err =
            right_input(&child.psbt, &parent, rights[0].opout, history.contract_id).unwrap_err();
        let err = err.to_string();
        assert!(
            err.contains("parent_fascia is not an rgb-lib fascia"),
            "{err}"
        );
    }
}

/// The seed's bundle on the child's tx: that tx does not commit it.
#[test]
fn refuses_a_parent_fascia_whose_tx_does_not_commit_it() {
    let (mut history, seed, rights) = seeded();
    let child = refill(&mut history, rights[0]);
    let mut witness = seed.fascia.seal_witness().clone();
    witness.tx = child.tx.clone();
    let parent = Made {
        fascia: Fascia::new(witness, seed.fascia.bundles().clone()),
        ..seed
    };
    let err = refusal(&child, &parent, rights[0], &history);
    assert!(err.contains("does not commit exactly"), "{err}");
}

/// A sibling of the seed tx commits the same bundle; only PP7 tells them apart.
#[test]
fn refuses_a_parent_fascia_of_a_sibling_tx() {
    let (mut history, seed, rights) = seeded();
    let child = refill(&mut history, rights[0]);
    let mut witness = seed.fascia.seal_witness().clone();
    witness.tx.lock_time = bitcoin::absolute::LockTime::from_consensus(7);
    let parent = Made {
        fascia: Fascia::new(witness, seed.fascia.bundles().clone()),
        ..seed
    };
    let err = refusal(&child, &parent, rights[0], &history);
    assert!(err.contains("does not spend"), "{err}");
}

/// The fascia of another tx: here, the right's own child.
#[test]
fn refuses_parent_that_does_not_commit_the_input_op() {
    let (mut history, _, rights) = seeded();
    let child = refill(&mut history, rights[0]);
    let err = refusal(&child, &child, rights[0], &history);
    assert!(err.contains("did not make the mintRight"), "{err}");
}

/// An old-form mint passed its right on. The right's child names the mint
/// as its parent.
#[test]
fn refuses_mint_parent() {
    let (mut history, _, rights) = seeded();
    let to = rgbstd::BuilderSeal::from(GraphSeal::with_blinded_vout(2u32, 7));
    let outputs = vec![p2tr(1), p2tr(2)];
    let (mint, kept) = history.mint_keeping_right(rights[0], 100, 90, to, vec![], outputs);
    let child = refill(&mut history, kept);
    let err = refusal(&child, &mint, kept, &history);
    assert!(err.contains("not a propagate"), "{err}");
}

/// No PSBT commits a genesis, so a genesis right has no parent to show.
#[test]
fn refuses_genesis_parent() {
    let (mut history, rights) = issued(&[0xA0, 0xA1]);
    let sibling = refill(&mut history, rights[1]);
    let child = refill(&mut history, rights[0]);
    let err = refusal(&child, &sibling, rights[0], &history);
    assert!(err.contains("did not make the mintRight"), "{err}");
}

/// A parent propagate that sends one right to the seals `seals`, and its first right.
fn parent_with_seals(seals: Vec<GraphSeal>) -> (History, Made, Utxo) {
    parent_made_by("propagate", &[0xA0], seals)
}

/// A parent `name` transition that spends the genesis rights on `tags` and
/// makes rights on `seals`, and its first right.
fn parent_made_by(name: &'static str, tags: &[u8], seals: Vec<GraphSeal>) -> (History, Made, Utxo) {
    let (mut history, rights) = issued(tags);
    let mut send = history.transition(name);
    for right in &rights {
        send = send.add_input(right.opout, AllocatedState::Void).unwrap();
    }
    for seal in seals {
        send = send.add_rights("mintRight", seal).unwrap();
    }
    let send: Transition = send.complete_transition().unwrap();
    let inputs = rights.iter().map(|r| r.outpoint).collect();
    let parent = history.commit_psbt(vec![send], inputs, vec![p2tr(1), p2tr(2)]);
    let right = Utxo {
        opout: Opout::new(parent.opid, schemata::OS_MINT, 0),
        outpoint: OutPoint::new(parent.tx.compute_txid(), 1),
    };
    (history, parent, right)
}

fn two_rights() -> Vec<GraphSeal> {
    vec![
        GraphSeal::with_blinded_vout(1u32, 1),
        GraphSeal::with_blinded_vout(2u32, 2),
    ]
}

#[test]
fn accepts_a_propagate_parent() {
    let (mut history, parent, right) = parent_with_seals(two_rights());
    let child = refill(&mut history, right);
    assert_eq!(proof(&child, &parent, right, &history).unwrap(), 0);
}

/// Before rgb-lib f3975623 rights moved by transfer; the schema now refuses it.
#[test]
fn refuses_a_transfer_parent() {
    let (mut history, parent, right) = parent_made_by("transfer", &[0xA0], two_rights());
    let child = refill(&mut history, right);
    let err = refusal(&child, &parent, right, &history);
    assert!(err.contains("not a propagate"), "{err}");
}

/// A propagate moves one right: one with two in is not a valid parent.
#[test]
fn refuses_a_parent_propagate_of_two_rights() {
    let (mut history, parent, right) = parent_made_by("propagate", &[0xA0, 0xA1], two_rights());
    let child = refill(&mut history, right);
    let err = refusal(&child, &parent, right, &history);
    assert!(
        err.contains("the parent propagate must close exactly one mintRight"),
        "{err}"
    );
}

/// An explicit seal in an invalid parent could name any UTXO.
#[test]
fn refuses_parent_right_with_explicit_txid_seal() {
    let elsewhere = gen::outpoint(0xE0, 0);
    let seal = GraphSeal::with_blinding(elsewhere.txid, 0u32, 1);
    let (mut history, parent, right) = parent_with_seals(vec![seal]);
    let child = refill(
        &mut history,
        Utxo {
            outpoint: elsewhere,
            ..right
        },
    );
    let err = refusal(&child, &parent, right, &history);
    assert!(err.contains("of another transaction"), "{err}");
}

#[test]
fn refuses_parent_with_a_second_assignment_on_the_right_vout() {
    let seals = vec![
        GraphSeal::with_blinded_vout(1u32, 1),
        GraphSeal::with_blinded_vout(1u32, 2),
    ];
    let (mut history, parent, right) = parent_with_seals(seals);
    let child = refill(&mut history, right);
    let err = refusal(&child, &parent, right, &history);
    assert!(err.contains("on the spent right's UTXO"), "{err}");
}

/// The child spends the parent's other output, not the right's.
#[test]
fn refuses_parent_right_on_another_vout() {
    let (mut history, seed, rights) = seeded();
    let wrong = Utxo {
        outpoint: rights[1].outpoint,
        ..rights[0]
    };
    let child = refill(&mut history, wrong);
    let err = refusal(&child, &seed, rights[0], &history);
    assert!(err.contains("does not spend"), "{err}");
}

/// Review P1: a mined mint's transition, committed again in a tx that spends
/// another Colored UTXO. Every F and M rule would pass; PP7 does not.
#[test]
fn refuses_replay_spending_another_colored_utxo() {
    let (mut history, seed, rights) = seeded();
    let to = rgbstd::BuilderSeal::from(GraphSeal::with_blinded_vout(1u32, 9));
    let mint = history.mint(rights[0], 100, 90, to, vec![], vec![p2tr(5)]);
    let mut replay = gen::witness_psbt(vec![rights[1].outpoint], vec![p2tr(5)]);
    replay.push_rgb_transition(mint.transition()).unwrap();
    let fascia = gen::rgb_commit(&mut replay, 0, 0x0bad);
    let replay = Made {
        opid: mint.opid,
        tx: replay.unsigned_tx.clone(),
        psbt: replay,
        fascia,
    };
    assert_eq!(proof(&mint, &seed, rights[0], &history).unwrap(), 0);
    let err = refusal(&replay, &seed, rights[0], &history);
    assert!(err.contains("does not spend"), "{err}");
}
