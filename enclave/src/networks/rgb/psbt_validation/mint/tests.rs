//! M8 here; M1-M7 run end to end in `route/tests/psbt_path.rs`.

use bitcoin::bip32::ChildNumber;
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::Builder;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, ScriptBuf};

use super::{assert_mint_sats, MintRecipient};
use crate::config::DEFAULT_MINT_WITNESS_SAT as W;
use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::btc_ownership::tests as fx;

/// Our change path `[0, 99]` on the Colored keychain.
fn change_path() -> [ChildNumber; 2] {
    [
        ChildNumber::from_normal_idx(0).unwrap(),
        ChildNumber::from_normal_idx(99).unwrap(),
    ]
}

fn op_return() -> ScriptBuf {
    Builder::new().push_opcode(OP_RETURN).into_script()
}

/// A mint PSBT: our right in, the OP_RETURN, then change to our `[0, 99]`.
fn mint_psbt(keys: &KeyManager) -> Psbt {
    let mut psbt = fx::psbt_with_n(1, &[(op_return(), 0), (ScriptBuf::new(), 2_000)]);
    fx::anchor_input(&mut psbt, 0, keys, AccountType::Colored, 0, 1, 3_000);
    fx::claim_output(&mut psbt, 1, keys, AccountType::Colored, &change_path());
    psbt
}

/// A witness mint PSBT: our right in, the OP_RETURN, `witness_sats` to the
/// depositor on vout 1, then change to our `[0, 99]` if `with_change`.
fn witness_psbt(keys: &KeyManager, witness_sats: u64, with_change: bool) -> Psbt {
    let mut outputs = vec![(op_return(), 0), (fx::foreign_address(0xD1), witness_sats)];
    if with_change {
        outputs.push((ScriptBuf::new(), 1_200));
    }
    let mut psbt = fx::psbt_with_n(1, &outputs);
    fx::anchor_input(&mut psbt, 0, keys, AccountType::Colored, 0, 1, 3_000);
    if with_change {
        fx::claim_output(&mut psbt, 2, keys, AccountType::Colored, &change_path());
    }
    psbt
}

fn blinded() -> MintRecipient {
    MintRecipient::Blinded("utxob:recipient".into())
}

fn witness_at(vout: u32) -> MintRecipient {
    MintRecipient::Witness { vout }
}

fn refusal(psbt: &Psbt, keys: &KeyManager, recipient: &MintRecipient) -> String {
    assert_mint_sats(psbt, keys, recipient, W)
        .unwrap_err()
        .to_string()
}

// ===== a blinded mint keeps every sat =====

#[test]
fn an_honest_mint_keeps_every_sat() {
    let keys = fx::km();
    assert_mint_sats(&mint_psbt(&keys), &keys, &blinded(), W).unwrap();
}

#[test]
fn refuses_unowned_sats() {
    let keys = fx::km();
    let mut psbt = mint_psbt(&keys);
    psbt.unsigned_tx.output[1].script_pubkey = fx::foreign_address(0xB2);
    psbt.outputs[1] = Default::default();
    let err = refusal(&psbt, &keys, &blinded());
    assert!(err.contains("mint PSBT pays 2000 sat"), "{err}");
}

/// No rule A: change back to the right's own script still needs rule C.
#[test]
fn refuses_change_to_the_input_script_without_its_metadata() {
    let keys = fx::km();
    let mut psbt = mint_psbt(&keys);
    let input_script = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey
        .clone();
    psbt.unsigned_tx.output[1].script_pubkey = input_script;
    psbt.outputs[1] = Default::default();
    let err = refusal(&psbt, &keys, &blinded());
    assert!(err.contains("pays 2000 sat"), "{err}");
}

#[test]
fn refuses_sats_in_the_op_return() {
    let keys = fx::km();
    let mut psbt = mint_psbt(&keys);
    psbt.unsigned_tx.output[0].value = Amount::from_sat(1);
    let err = refusal(&psbt, &keys, &blinded());
    assert!(err.contains("pays 1 sat"), "{err}");
}

/// The witness amount does not open a blinded mint: its recipient has no output.
#[test]
fn a_blinded_mint_may_not_pay_the_witness_amount_out() {
    let keys = fx::km();
    let err = refusal(&witness_psbt(&keys, W, true), &keys, &blinded());
    assert!(err.contains("pays 1500 sat"), "{err}");
}

// ===== a witness mint pays exactly MINT_WITNESS_SAT to its seal =====

#[test]
fn a_witness_mint_pays_exactly_mint_witness_sat() {
    let keys = fx::km();
    assert_mint_sats(&witness_psbt(&keys, W, true), &keys, &witness_at(1), W).unwrap();
}

/// BDK drops change below dust; the rest goes to the miner, under the fee caps.
#[test]
fn a_witness_mint_without_change_passes() {
    let keys = fx::km();
    assert_mint_sats(&witness_psbt(&keys, W, false), &keys, &witness_at(1), W).unwrap();
}

#[test]
fn refuses_a_witness_output_not_worth_exactly_mint_witness_sat() {
    let keys = fx::km();
    for sats in [W - 1, W + 1] {
        let err = refusal(&witness_psbt(&keys, sats, true), &keys, &witness_at(1));
        assert!(
            err.contains(&format!("pays {sats} sat to its recipient's vout 1"))
                && err.contains("MINT_WITNESS_SAT (1500 sat)"),
            "{sats}: {err}"
        );
    }
}

#[test]
fn refuses_a_second_unowned_output_beside_the_witness() {
    let keys = fx::km();
    let mut extra = witness_psbt(&keys, W, true);
    extra.unsigned_tx.output.push(bitcoin::TxOut {
        value: Amount::from_sat(1),
        script_pubkey: fx::foreign_address(0xB3),
    });
    extra.outputs.push(Default::default());
    let mut stripped = witness_psbt(&keys, W, true);
    stripped.outputs[2] = Default::default();
    let mut op_return_sats = witness_psbt(&keys, W, true);
    op_return_sats.unsigned_tx.output[0].value = Amount::from_sat(1);
    for (psbt, total) in [(extra, 1_501), (stripped, 2_700), (op_return_sats, 1_501)] {
        let err = refusal(&psbt, &keys, &witness_at(1));
        assert!(
            err.contains(&format!(
                "pays {total} sat to outputs this enclave does not derive"
            )),
            "{total}: {err}"
        );
    }
}

#[test]
fn refuses_a_witness_vout_outside_the_tx() {
    let keys = fx::km();
    let err = refusal(&witness_psbt(&keys, W, true), &keys, &witness_at(3));
    assert!(err.contains("vout 3, but its tx has 3 outputs"), "{err}");
}

#[test]
fn refuses_a_witness_vout_on_the_op_return() {
    let keys = fx::km();
    let mut psbt = witness_psbt(&keys, W, false);
    psbt.unsigned_tx.output[0].value = Amount::from_sat(W);
    psbt.unsigned_tx.output[1].value = Amount::ZERO;
    let err = refusal(&psbt, &keys, &witness_at(0));
    assert!(err.contains("vout 0, the OP_RETURN"), "{err}");
}

/// Rule C on either account: units on our own output never reach the user.
#[test]
fn refuses_a_witness_output_the_enclave_derives() {
    let keys = fx::km();
    let paths = [
        (AccountType::Colored, 0, 5),
        (AccountType::Vanilla, 0, 5),
        (AccountType::Vanilla, 1, 5),
    ];
    for (account, chain, index) in paths {
        let mut psbt = witness_psbt(&keys, W, true);
        let child = [
            ChildNumber::from_normal_idx(chain).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ];
        fx::claim_output(&mut psbt, 1, &keys, account, &child);
        let err = refusal(&psbt, &keys, &witness_at(1));
        assert!(
            err.contains("an output of this enclave"),
            "{account:?}: {err}"
        );
    }
}

/// The units sit on our rule C output while a foreign output takes W: the total
/// check alone passes this, so rule C on the seal is what refuses it.
#[test]
fn refuses_units_on_our_output_while_a_foreign_output_takes_the_witness_sats() {
    let keys = fx::km();
    let mut psbt = witness_psbt(&keys, W, false);
    psbt.unsigned_tx.output.push(bitcoin::TxOut {
        value: Amount::from_sat(W),
        script_pubkey: fx::foreign_address(0xB4),
    });
    psbt.outputs.push(Default::default());
    let ours = [
        ChildNumber::from_normal_idx(0).unwrap(),
        ChildNumber::from_normal_idx(5).unwrap(),
    ];
    fx::claim_output(&mut psbt, 1, &keys, AccountType::Colored, &ours);
    let err = refusal(&psbt, &keys, &witness_at(1));
    assert!(err.contains("vout 1, an output of this enclave"), "{err}");
}

/// Rule A: the right's own script needs no metadata to be ours.
#[test]
fn refuses_a_witness_output_on_the_right_input_script() {
    let keys = fx::km();
    let mut psbt = witness_psbt(&keys, W, true);
    let input_script = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey
        .clone();
    psbt.unsigned_tx.output[1].script_pubkey = input_script;
    let err = refusal(&psbt, &keys, &witness_at(1));
    assert!(err.contains("an output of this enclave"), "{err}");
}
