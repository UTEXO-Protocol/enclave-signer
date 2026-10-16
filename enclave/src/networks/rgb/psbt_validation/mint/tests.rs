//! M8 here; M1-M7 run end to end in `route/tests/psbt_path.rs`.

use bitcoin::bip32::ChildNumber;
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::Builder;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, ScriptBuf};

use super::super::assert_keeps_all_sats;
use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::btc_ownership::tests as fx;

/// A mint PSBT: our right in, the OP_RETURN, then change to our `[0, 99]`.
fn mint_psbt(keys: &KeyManager) -> Psbt {
    let op_return = Builder::new().push_opcode(OP_RETURN).into_script();
    let mut psbt = fx::psbt_with_n(1, &[(op_return, 0), (ScriptBuf::new(), 2_000)]);
    fx::anchor_input(&mut psbt, 0, keys, AccountType::Colored, 0, 1, 3_000);
    let change = [
        ChildNumber::from_normal_idx(0).unwrap(),
        ChildNumber::from_normal_idx(99).unwrap(),
    ];
    fx::claim_output(&mut psbt, 1, keys, AccountType::Colored, &change);
    psbt
}

#[test]
fn an_honest_mint_keeps_every_sat() {
    let keys = fx::km();
    assert_keeps_all_sats(&mint_psbt(&keys), &keys, "mint").unwrap();
}

#[test]
fn refuses_unowned_sats() {
    let keys = fx::km();
    let mut psbt = mint_psbt(&keys);
    psbt.unsigned_tx.output[1].script_pubkey = fx::foreign_address(0xB2);
    psbt.outputs[1] = Default::default();
    let err = assert_keeps_all_sats(&psbt, &keys, "mint").unwrap_err();
    assert!(err.to_string().contains("mint PSBT pays 2000 sat"), "{err}");
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
    let err = assert_keeps_all_sats(&psbt, &keys, "mint").unwrap_err();
    assert!(err.to_string().contains("pays 2000 sat"), "{err}");
}

#[test]
fn refuses_sats_in_the_op_return() {
    let keys = fx::km();
    let mut psbt = mint_psbt(&keys);
    psbt.unsigned_tx.output[0].value = Amount::from_sat(1);
    let err = assert_keeps_all_sats(&psbt, &keys, "mint").unwrap_err();
    assert!(err.to_string().contains("pays 1 sat"), "{err}");
}
