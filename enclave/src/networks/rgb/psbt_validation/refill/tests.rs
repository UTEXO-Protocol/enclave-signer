use bitcoin::bip32::ChildNumber;
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf};
use rgbstd::contract::AllocatedState;
use rgbstd::{GlobalValues, GraphSeal, OpId, Operation, RevealedData, RevealedValue};

use super::super::MAX_FEE_SATS;
use super::*;
use crate::networks::rgb::btc_ownership::tests as fx;
use crate::test_support::bfa_consignment::{self as gen, History, Issue, Utxo};

/// Sats on each new right's output.
const RIGHT_SATS: u64 = 1_000;
/// Fee the right's input pays on top of the rights.
const FEE: u64 = 1_000;
/// Value of each fee input, paid back as change.
const FEE_INPUT_SATS: u64 = 10_000;

fn normal(i: u32) -> ChildNumber {
    ChildNumber::from_normal_idx(i).unwrap()
}

fn hardened(i: u32) -> ChildNumber {
    ChildNumber::from_hardened_idx(i).unwrap()
}

fn op_return() -> ScriptBuf {
    Builder::new().push_opcode(OP_RETURN).into_script()
}

/// A refill PSBT. Input 0 is our Colored right UTXO, then `fee_inputs` more
/// Colored inputs. Vout 0 is the OP_RETURN, vouts 1..=k the rights at
/// `[0, i]`, then one change output for the fee inputs.
fn refill_with(keys: &KeyManager, k: u32, fee_inputs: u32) -> Psbt {
    let rights = (1..=k).map(|_| (ScriptBuf::new(), RIGHT_SATS));
    let change =
        (fee_inputs > 0).then(|| (ScriptBuf::new(), FEE_INPUT_SATS * u64::from(fee_inputs)));
    let outputs: Vec<_> = std::iter::once((op_return(), 0))
        .chain(rights)
        .chain(change)
        .collect();
    let mut psbt = fx::psbt_with_n(1 + fee_inputs as usize, &outputs);
    let right_value = RIGHT_SATS * u64::from(k) + FEE;
    fx::anchor_input(&mut psbt, 0, keys, AccountType::Colored, 0, 0, right_value);
    for i in 1..=fee_inputs {
        fx::anchor_input(
            &mut psbt,
            i as usize,
            keys,
            AccountType::Colored,
            0,
            100 + i,
            FEE_INPUT_SATS,
        );
    }
    for i in 1..=k {
        fx::claim_output(
            &mut psbt,
            i as usize,
            keys,
            AccountType::Colored,
            &[normal(0), normal(i)],
        );
    }
    if fee_inputs > 0 {
        let change = k as usize + 1;
        fx::claim_output(
            &mut psbt,
            change,
            keys,
            AccountType::Colored,
            &[normal(0), normal(99)],
        );
    }
    psbt
}

fn refill(keys: &KeyManager, k: u32) -> Psbt {
    refill_with(keys, k, 0)
}

fn error_text<T: std::fmt::Debug>(result: Result<T>) -> String {
    result.expect_err("the refill must be refused").to_string()
}

// ===== the gate: G1, RR10, RR12, RR13 =====

#[test]
fn the_gate_accepts_a_refill_of_our_own_coins() {
    let keys = fx::km();
    refill_gate(&refill(&keys, 2), &keys).unwrap();
    refill_gate(&refill_with(&keys, 3, 1), &keys).unwrap();
}

#[test]
fn the_gate_refuses_two_fee_inputs() {
    let keys = fx::km();
    let err = error_text(refill_gate(&refill_with(&keys, 2, 2), &keys));
    assert!(err.contains("spends 3 inputs"), "{err}");
}

#[test]
fn the_gate_refuses_a_foreign_input() {
    let keys = fx::km();
    let mut psbt = refill_with(&keys, 2, 1);
    let input = &mut psbt.inputs[1];
    input.witness_utxo.as_mut().unwrap().script_pubkey = fx::foreign_address(0xB1);
    input.tap_internal_key = None;
    input.tap_key_origins.clear();
    let err = error_text(refill_gate(&psbt, &keys));
    assert!(
        err.contains("input 1 is not a Colored key-path input"),
        "{err}"
    );
}

/// A Vanilla input is ours, but this path never signs it.
#[test]
fn the_gate_refuses_a_vanilla_input() {
    let keys = fx::km();
    let mut psbt = refill_with(&keys, 2, 1);
    fx::anchor_input(
        &mut psbt,
        1,
        &keys,
        AccountType::Vanilla,
        0,
        0,
        FEE_INPUT_SATS,
    );
    let err = error_text(refill_gate(&psbt, &keys));
    assert!(
        err.contains("input 1 is not a Colored key-path input"),
        "{err}"
    );
}

#[test]
fn the_gate_refuses_change_to_a_foreign_output() {
    let keys = fx::km();
    let mut psbt = refill_with(&keys, 2, 1);
    psbt.unsigned_tx.output[3].script_pubkey = fx::foreign_address(0xB2);
    psbt.outputs[3] = Default::default();
    let err = error_text(refill_gate(&psbt, &keys));
    assert!(err.contains(&format!("pays {FEE_INPUT_SATS} sat")), "{err}");
}

/// No rule A here: change on an input's script still needs rule C metadata.
#[test]
fn the_gate_refuses_change_back_to_an_input_script_without_rule_c() {
    let keys = fx::km();
    let mut psbt = refill_with(&keys, 2, 1);
    let fee_input_script = psbt.inputs[1]
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey
        .clone();
    psbt.unsigned_tx.output[3].script_pubkey = fee_input_script;
    psbt.outputs[3] = Default::default();
    let err = error_text(refill_gate(&psbt, &keys));
    assert!(err.contains(&format!("pays {FEE_INPUT_SATS} sat")), "{err}");
}

#[test]
fn the_gate_refuses_an_op_return_with_value() {
    let keys = fx::km();
    let mut psbt = refill(&keys, 2);
    psbt.unsigned_tx.output[0].value = Amount::from_sat(1);
    let err = error_text(refill_gate(&psbt, &keys));
    assert!(err.contains("pays 1 sat"), "{err}");
}

#[test]
fn the_gate_refuses_a_fee_over_the_cap() {
    let keys = fx::km();
    let mut psbt = refill(&keys, 2);
    let right = psbt.inputs[0].witness_utxo.as_mut().unwrap();
    right.value = Amount::from_sat(2 * RIGHT_SATS + MAX_FEE_SATS + 1);
    let err = error_text(refill_gate(&psbt, &keys));
    assert!(err.contains("rights-refill PSBT fee too high"), "{err}");
}

// ===== RR9: each right on our Colored keychain at [0, i] =====

#[test]
fn rights_at_colored_zero_i_are_ours() {
    let keys = fx::km();
    assert_refill_rights_owned(&refill(&keys, 3), &[1, 2, 3], &keys).unwrap();
}

/// Moves the right on vout 1 to `child` below `account`.
fn right_moved_to(account: AccountType, child: &[ChildNumber]) -> String {
    let keys = fx::km();
    let mut psbt = refill(&keys, 2);
    psbt.outputs[1] = Default::default();
    fx::claim_output(&mut psbt, 1, &keys, account, child);
    error_text(assert_refill_rights_owned(&psbt, &[1, 2], &keys))
}

#[test]
fn refuses_a_right_on_a_foreign_output() {
    let keys = fx::km();
    let mut psbt = refill(&keys, 2);
    psbt.unsigned_tx.output[1].script_pubkey = fx::foreign_address(0xB3);
    psbt.outputs[1] = Default::default();
    let err = error_text(assert_refill_rights_owned(&psbt, &[1, 2], &keys));
    assert!(err.contains("vout 1"), "{err}");
}

/// rgb-lib would not see it, and `SignBtc` could spend it.
#[test]
fn refuses_a_right_on_a_vanilla_output() {
    let err = right_moved_to(AccountType::Vanilla, &[normal(0), normal(1)]);
    assert!(err.contains("not a Colored key-path output"), "{err}");
}

#[test]
fn refuses_a_right_at_a_hardened_child_path() {
    let err = right_moved_to(AccountType::Colored, &[normal(0), hardened(1)]);
    assert!(err.contains("child path [0, i]"), "{err}");
}

#[test]
fn refuses_a_right_at_a_three_step_child_path() {
    let err = right_moved_to(AccountType::Colored, &[normal(0), normal(1), normal(0)]);
    assert!(err.contains("child path [0, i]"), "{err}");
}

#[test]
fn refuses_a_right_off_the_colored_keychain() {
    let err = right_moved_to(AccountType::Colored, &[normal(1), normal(1)]);
    assert!(err.contains("child path [0, i]"), "{err}");
}

#[test]
fn refuses_a_right_past_the_last_output() {
    let keys = fx::km();
    let err = error_text(assert_refill_rights_owned(&refill(&keys, 2), &[9], &keys));
    assert!(err.contains("vout 9"), "{err}");
}

// ===== RR6-RR8 on the committed transition =====

/// `transition` as the core reads it from a PSBT.
fn committed(transition: Transition) -> Committed {
    Committed {
        txid: bitcoin::Txid::all_zeros(),
        opid: transition.id(),
        transition,
    }
}

/// An asset with one genesis right per tag, and those rights.
fn issued(tags: &[u8]) -> (History, Vec<Utxo>) {
    let outpoints: Vec<OutPoint> = tags.iter().map(|&t| gen::outpoint(t, 0)).collect();
    let history = History::issue(Issue::new(42161, [0xB1; 20], outpoints.clone()));
    let rights = (0u16..)
        .zip(outpoints)
        .map(|(no, outpoint)| history.genesis_right(no, outpoint))
        .collect();
    (history, rights)
}

/// A rights send of one genesis right to `vouts`.
fn rights_send(vouts: &[u32]) -> (Utxo, Transition) {
    let (mut history, rights) = issued(&[0xA0]);
    (rights[0], history.rights_transition(rights[0], vouts))
}

fn refusal_of(transition: Transition) -> String {
    error_text(refill_rights(&committed(transition)))
}

fn on_witness(vout: u32) -> OutputSeal {
    OutputSeal::Revealed { txid: None, vout }
}

#[test]
fn reads_one_right_sent_to_two_and_to_three() {
    for k in [2u32, 3] {
        let vouts: Vec<u32> = (1..=k).collect();
        let (right, send) = rights_send(&vouts);
        let (spent, made) = refill_rights(&committed(send)).unwrap();
        assert_eq!(spent, right.opout);
        assert_eq!(made, vouts);
    }
}

#[test]
fn refuses_zero_one_and_256_rights() {
    for k in [0u32, 1, 256] {
        let seals: Vec<OutputSeal> = (1..=k).map(on_witness).collect();
        let err = error_text(assert_refill_rights(&seals));
        assert!(err.contains(&format!("makes {k} right(s)")), "{err}");
    }
}

#[test]
fn refuses_a_right_on_a_blinded_seal() {
    let host = OutputSeal::Confidential {
        secret_seal: "utxob:host".into(),
    };
    let err = error_text(assert_refill_rights(&[on_witness(1), host]));
    assert!(err.contains("blinded seal utxob:host"), "{err}");
}

/// A right on an outpoint this PSBT spends is destroyed at broadcast.
#[test]
fn refuses_a_right_on_another_transaction() {
    let elsewhere = OutputSeal::Revealed {
        txid: Some([0x77; 32]),
        vout: 0,
    };
    let err = error_text(assert_refill_rights(&[on_witness(1), elsewhere]));
    assert!(err.contains("of another transaction"), "{err}");
}

#[test]
fn refuses_two_rights_on_one_vout() {
    let err = error_text(assert_refill_rights(&[on_witness(1), on_witness(1)]));
    assert!(err.contains("two rights on vout 1"), "{err}");
}

/// The same check on a transition: rights built on one vout.
#[test]
fn refuses_a_transition_that_puts_two_rights_on_one_vout() {
    let (mut history, rights) = issued(&[0xA0]);
    let send = history
        .transition("propagate")
        .add_input(rights[0].opout, AllocatedState::Void)
        .unwrap()
        .add_rights("mintRight", GraphSeal::with_blinded_vout(1u32, 1))
        .unwrap()
        .add_rights("mintRight", GraphSeal::with_blinded_vout(1u32, 2))
        .unwrap()
        .complete_transition()
        .unwrap();
    assert!(refusal_of(send).contains("two rights on vout 1"));
}

/// Rights move only by propagate: TS_TRANSFER takes units only now.
#[test]
fn refuses_a_transfer_a_mint_or_a_burn_as_the_refill() {
    for transition_type in [schemata::TS_TRANSFER, schemata::TS_MINT, schemata::TS_BURN] {
        let (_, mut send) = rights_send(&[1, 2]);
        send.transition_type = transition_type;
        let err = refusal_of(send);
        assert!(err.contains("requires a propagate transition"), "{err}");
    }
}

#[test]
fn refuses_an_asset_input() {
    let (mut history, _) = issued(&[0xA0]);
    let units = Opout::new(OpId::from([0x55; 32]), schemata::OS_ASSET, 0);
    let send = history
        .transition("propagate")
        .add_input(units, AllocatedState::from(RevealedValue::from(5u64)))
        .unwrap()
        .add_rights("mintRight", GraphSeal::with_blinded_vout(1u32, 1))
        .unwrap()
        .add_rights("mintRight", GraphSeal::with_blinded_vout(2u32, 1))
        .unwrap()
        .complete_transition()
        .unwrap();
    let err = refusal_of(send);
    assert!(err.contains("exactly one mintRight"), "{err}");
}

#[test]
fn refuses_two_rights_in() {
    let (mut history, rights) = issued(&[0xA0, 0xA1]);
    let send = history
        .transition("propagate")
        .add_input(rights[0].opout, AllocatedState::Void)
        .unwrap()
        .add_input(rights[1].opout, AllocatedState::Void)
        .unwrap()
        .add_rights("mintRight", GraphSeal::with_blinded_vout(1u32, 1))
        .unwrap()
        .add_rights("mintRight", GraphSeal::with_blinded_vout(2u32, 1))
        .unwrap()
        .complete_transition()
        .unwrap();
    let err = refusal_of(send);
    assert!(err.contains("exactly one mintRight"), "{err}");
}

#[test]
fn refuses_units_on_the_propagate() {
    let (mut history, rights) = issued(&[0xA0]);
    let send = history
        .transition("propagate")
        .add_input(rights[0].opout, AllocatedState::Void)
        .unwrap()
        .add_rights("mintRight", GraphSeal::with_blinded_vout(1u32, 1))
        .unwrap()
        .add_rights("mintRight", GraphSeal::with_blinded_vout(2u32, 1))
        .unwrap()
        .add_fungible_state("assetOwner", GraphSeal::with_blinded_vout(3u32, 1), 5u64)
        .unwrap()
        .complete_transition()
        .unwrap();
    let err = refusal_of(send);
    assert!(err.contains("moves rights only"), "{err}");
}

/// Consensus refuses a right with an amount, so the spent right would die.
#[test]
fn refuses_rights_that_carry_an_amount() {
    let (mut history, rights) = issued(&[0xA0]);
    let mut send = history
        .transition("propagate")
        .add_input(rights[0].opout, AllocatedState::Void)
        .unwrap()
        .add_fungible_state("assetOwner", GraphSeal::with_blinded_vout(1u32, 1), 1u64)
        .unwrap()
        .add_fungible_state("assetOwner", GraphSeal::with_blinded_vout(2u32, 1), 1u64)
        .unwrap()
        .complete_transition()
        .unwrap();
    let legs = send.assignments.remove(&schemata::OS_ASSET).unwrap();
    send.assignments
        .insert(schemata::OS_MINT, legs.unwrap())
        .unwrap();
    let err = refusal_of(send);
    assert!(err.contains("carry state"), "{err}");
}

#[test]
fn refuses_a_global_on_the_propagate() {
    let (_, mut send) = rights_send(&[1, 2]);
    let value = GlobalValues::with(RevealedData::new(
        amplify::confinement::SmallBlob::try_from(vec![0u8; 8]).unwrap(),
    ));
    send.globals
        .insert(schemata::GS_BURNED_ASSET, value)
        .unwrap();
    let err = refusal_of(send);
    assert!(err.contains("moves rights only"), "{err}");
}
