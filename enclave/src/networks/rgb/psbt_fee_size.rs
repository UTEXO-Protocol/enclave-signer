use bitcoin::blockdata::opcodes::all::{
    OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL,
};
use bitcoin::psbt::{Input, Psbt};
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::LeafVersion;
use bitcoin::{Script, ScriptBuf};

use crate::error::{EnclaveError, Result};

/// Estimate supported native-witness satisfactions, including all inputs.
/// Hidden Taproot leaves and later finalizer changes are not bounded here;
/// the finalizer must also check the actual transaction's fee rate.
pub(super) fn estimated_signed_vsize(psbt: &Psbt, key_path_inputs: &[usize]) -> Result<u64> {
    if psbt.inputs.is_empty() || psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err(size_error("inconsistent or empty PSBT"));
    }

    let key_path_inputs: std::collections::HashSet<_> = key_path_inputs.iter().copied().collect();
    let mut weight = (psbt.unsigned_tx.base_size() as u64)
        .checked_mul(4)
        .and_then(|n| n.checked_add(2)) // Segwit marker and flag.
        .ok_or_else(|| size_error("weight overflow"))?;
    // Use the same funding outputs as Psbt::fee().
    for (index, prevout) in psbt.iter_funding_utxos().enumerate() {
        let input = &psbt.inputs[index];
        let fail = |reason: &str| size_error(&format!("input {index}: {reason}"));
        let txin = &psbt.unsigned_tx.input[index];
        if !txin.script_sig.is_empty() || !txin.witness.is_empty() {
            return Err(fail("unsigned transaction already contains unlocking data"));
        }
        if input
            .final_script_sig
            .as_ref()
            .is_some_and(|script| !script.is_empty())
        {
            return Err(fail(
                "nonempty scriptSig is not supported for native witness inputs",
            ));
        }

        let prevout = prevout.map_err(|err| fail(&format!("funding output unavailable: {err}")))?;
        let script = &prevout.script_pubkey;
        let estimated = if script.is_p2tr() {
            taproot_witness_size(input, script, key_path_inputs.contains(&index)).map_err(&fail)?
        } else if script.is_p2wpkh() {
            // Standard P2WPKH: DER signature plus sighash, compressed public key.
            witness_size(&[73, 33])
        } else if script.is_p2wsh() {
            let witness_script = input
                .witness_script
                .as_ref()
                .ok_or_else(|| fail("P2WSH witness_script is missing"))?;
            if witness_script.to_p2wsh() != *script {
                return Err(fail("P2WSH witness_script does not match the prevout"));
            }
            let required = multisig_threshold(witness_script)
                .ok_or_else(|| fail("unsupported P2WSH script; expected standard CHECKMULTISIG"))?;
            // CHECKMULTISIG includes an empty dummy stack item.
            compact_size(required + 2) + 1 + required * 74 + item_size(witness_script.len() as u64)
        } else {
            return Err(fail("unsupported prevout script type"));
        };

        // An unfinished or tiny supplied witness must not lower the estimate.
        let supplied = input
            .final_script_witness
            .as_ref()
            .map_or(0, |witness| witness.size() as u64);
        weight = weight
            .checked_add(estimated.max(supplied))
            .ok_or_else(|| fail("weight overflow"))?;
    }
    Ok(weight.div_ceil(4))
}

fn taproot_witness_size(
    input: &Input,
    script: &Script,
    key_path: bool,
) -> std::result::Result<u64, &'static str> {
    let secp = Secp256k1::verification_only();
    // Only the trusted signer resolver can select key-path despite disclosed leaves.
    if key_path || input.tap_scripts.is_empty() {
        let internal_key = input
            .tap_internal_key
            .ok_or("Taproot spend metadata is missing")?;
        // A Tapret root changes the output key, not the key-path witness.
        if ScriptBuf::new_p2tr(&secp, internal_key, input.tap_merkle_root).as_script() != script {
            return Err("Taproot internal key/merkle root does not match the prevout");
        }
        // DEFAULT omits the sighash byte; an existing ALL signature still needs it.
        let has_sighash_byte = input.sighash_type.is_some_and(|ty| ty.to_u32() != 0)
            || input
                .tap_key_sig
                .is_some_and(|sig| sig.sighash_type != TapSighashType::Default);
        return Ok(witness_size(&[if has_sighash_byte { 65 } else { 64 }]));
    }

    let output_key = XOnlyPublicKey::from_slice(&script.as_bytes()[2..])
        .map_err(|_| "invalid Taproot output key")?;
    let mut largest = 0;
    for (control, (leaf, version)) in &input.tap_scripts {
        if *version != LeafVersion::TapScript || control.leaf_version != *version {
            return Err("unsupported or inconsistent Taproot leaf version");
        }
        if !control.verify_taproot_commitment(&secp, output_key, leaf) {
            return Err("Taproot script/control block does not commit to the prevout");
        }
        let (slots, required) = tapscript_threshold(leaf)
            .ok_or("unsupported Taproot script; expected CHECKSIG or multi_a")?;
        // Empty multi_a slots also occupy witness bytes; signatures may include sighash.
        let size = compact_size(slots + 2)
            + required * 66
            + (slots - required)
            + item_size(leaf.len() as u64)
            + item_size(control.size() as u64);
        largest = largest.max(size);
    }
    Ok(largest)
}

fn tapscript_threshold(script: &Script) -> Option<(u64, u64)> {
    let bytes = script.as_bytes();
    let mut offset = 0;
    let mut slots = 0;
    while bytes.len().saturating_sub(offset) >= 34 {
        let expected = if slots == 0 {
            OP_CHECKSIG
        } else {
            OP_CHECKSIGADD
        };
        if bytes[offset] != 32 || bytes[offset + 33] != expected.to_u8() {
            break;
        }
        XOnlyPublicKey::from_slice(&bytes[offset + 1..offset + 33]).ok()?;
        slots += 1;
        offset += 34;
    }
    if slots == 1 && offset == bytes.len() {
        return Some((1, 1));
    }
    if slots == 0 || slots > 1000 {
        return None;
    }
    let (required, consumed) = positive_script_number(&bytes[offset..])?;
    (required <= slots && bytes.get(offset + consumed..) == Some(&[OP_NUMEQUAL.to_u8()][..]))
        .then_some((slots, required))
}

fn multisig_threshold(script: &Script) -> Option<u64> {
    let bytes = script.as_bytes();
    let (required, mut offset) = positive_script_number(bytes)?;
    let mut keys = 0;
    while bytes.len().saturating_sub(offset) >= 34 && bytes[offset] == 33 {
        let key = bitcoin::PublicKey::from_slice(&bytes[offset + 1..offset + 34]).ok()?;
        if !key.compressed {
            return None;
        }
        keys += 1;
        offset += 34;
    }
    let (declared, consumed) = positive_script_number(&bytes[offset..])?;
    (keys <= 20
        && required <= keys
        && declared == keys
        && bytes.get(offset + consumed..) == Some(&[OP_CHECKMULTISIG.to_u8()][..]))
    .then_some(required)
}

fn positive_script_number(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    if (0x51..=0x60).contains(&first) {
        return Some((u64::from(first - 0x50), 1));
    }
    if !(1..=4).contains(&first) {
        return None;
    }
    let data = bytes.get(1..=usize::from(first))?;
    let last = *data.last()?;
    if last & 0x80 != 0 || (last == 0 && (data.len() == 1 || data[data.len() - 2] & 0x80 == 0)) {
        return None;
    }
    let value = data
        .iter()
        .enumerate()
        .fold(0u64, |n, (i, byte)| n | (u64::from(*byte) << (i * 8)));
    (value > 16).then_some((value, data.len() + 1))
}

fn compact_size(value: u64) -> u64 {
    match value {
        0..=252 => 1,
        253..=0xffff => 3,
        0x10000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn item_size(len: u64) -> u64 {
    compact_size(len) + len
}

fn witness_size(lengths: &[u64]) -> u64 {
    compact_size(lengths.len() as u64) + lengths.iter().map(|len| item_size(*len)).sum::<u64>()
}

fn size_error(reason: &str) -> EnclaveError {
    EnclaveError::CrossCheck(format!("cannot estimate signed PSBT size: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::taproot::TaprootBuilder;
    use bitcoin::{Amount, OutPoint, PublicKey, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    fn public_key(byte: u8) -> PublicKey {
        PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[byte; 32]).unwrap(),
        ))
    }

    fn psbt_with_script(script_pubkey: ScriptBuf) -> Psbt {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: script_pubkey.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        });
        psbt
    }

    fn taproot_psbt(script: ScriptBuf, depth: u8) -> (Psbt, Vec<u8>) {
        let internal = public_key(1).inner.x_only_public_key().0;
        let mut builder = TaprootBuilder::new();
        for level in 1..=depth {
            builder = builder
                .add_leaf(level, ScriptBuf::from_bytes(vec![0x51]))
                .unwrap();
        }
        let info = builder
            .add_leaf(depth, script.clone())
            .unwrap()
            .finalize(&Secp256k1::new(), internal)
            .unwrap();
        let control = info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap();
        let serialized_control = control.serialize();
        let mut psbt = psbt_with_script(ScriptBuf::new_p2tr_tweaked(info.output_key()));
        psbt.inputs[0]
            .tap_scripts
            .insert(control, (script, LeafVersion::TapScript));
        (psbt, serialized_control)
    }

    fn multi_a(keys: u8, required: u8) -> ScriptBuf {
        let mut builder = Builder::new();
        for index in 0..keys {
            builder = builder
                .push_x_only_key(&public_key(index + 2).inner.x_only_public_key().0)
                .push_opcode(if index == 0 {
                    OP_CHECKSIG
                } else {
                    OP_CHECKSIGADD
                });
        }
        builder
            .push_int(i64::from(required))
            .push_opcode(OP_NUMEQUAL)
            .into_script()
    }

    fn assert_matches_serialization(psbt: &Psbt, witnesses: Vec<Witness>) {
        // Placeholder signatures test serialized size, not spend validity.
        let mut signed = psbt.unsigned_tx.clone();
        assert_eq!(signed.input.len(), witnesses.len());
        for (input, witness) in signed.input.iter_mut().zip(witnesses) {
            input.witness = witness;
        }
        assert_eq!(
            estimated_signed_vsize(psbt, &[]).unwrap(),
            signed.vsize() as u64
        );
        assert!(signed.vsize() > psbt.unsigned_tx.vsize());
    }

    fn assert_error(psbt: &Psbt, reason: &str) {
        let error = estimated_signed_vsize(psbt, &[]).unwrap_err().to_string();
        assert!(
            error.contains("cannot estimate signed PSBT size"),
            "{error}"
        );
        assert!(error.contains(reason), "{error}");
    }

    #[test]
    fn checksig_counts_signature_script_control_block_and_marker() {
        let script = Builder::new()
            .push_x_only_key(&public_key(2).inner.x_only_public_key().0)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let (psbt, control) = taproot_psbt(script.clone(), 0);
        assert_matches_serialization(
            &psbt,
            vec![Witness::from_slice(&[
                vec![1; 65],
                script.into_bytes(),
                control,
            ])],
        );
    }

    #[test]
    fn multi_a_counts_empty_slots_and_long_script_and_control_block_prefixes() {
        let script = multi_a(8, 2);
        let (psbt, control) = taproot_psbt(script.clone(), 7);
        assert!(script.len() > 252 && control.len() > 252);
        let mut stack = vec![vec![1; 65]; 2];
        stack.extend(vec![Vec::new(); 6]);
        stack.push(script.into_bytes());
        stack.push(control);
        let witness = Witness::from_slice(&stack);
        // Rounding must not hide a missing two-byte length prefix extension.
        assert_ne!((witness.size() + 2).div_ceil(4), witness.size().div_ceil(4));
        assert_matches_serialization(&psbt, vec![witness]);
    }

    #[test]
    fn multi_a_counts_compact_size_boundary_for_witness_stack_items() {
        let script = multi_a(251, 19);
        let (psbt, control) = taproot_psbt(script.clone(), 0);
        let mut stack = vec![vec![1; 65]; 19];
        stack.extend(vec![Vec::new(); 232]);
        stack.push(script.into_bytes());
        stack.push(control);
        assert_eq!(stack.len(), 253);
        let witness = Witness::from_slice(&stack);
        // Rounding must not hide a missing two-byte stack-count extension.
        assert_ne!((witness.size() + 2).div_ceil(4), witness.size().div_ceil(4));
        assert_matches_serialization(&psbt, vec![witness]);
    }

    #[test]
    fn selects_largest_of_all_supplied_committed_leaves() {
        let small = multi_a(1, 1);
        let large = multi_a(4, 3);
        let internal = public_key(1).inner.x_only_public_key().0;
        let info = TaprootBuilder::new()
            .add_leaf(1, small.clone())
            .unwrap()
            .add_leaf(1, large.clone())
            .unwrap()
            .finalize(&Secp256k1::new(), internal)
            .unwrap();
        let mut psbt = psbt_with_script(ScriptBuf::new_p2tr_tweaked(info.output_key()));
        for script in [small, large.clone()] {
            let control = info
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .unwrap();
            psbt.inputs[0]
                .tap_scripts
                .insert(control, (script, LeafVersion::TapScript));
        }
        let control = info
            .control_block(&(large.clone(), LeafVersion::TapScript))
            .unwrap();
        assert_matches_serialization(
            &psbt,
            vec![Witness::from_slice(&[
                vec![1; 65],
                vec![1; 65],
                vec![1; 65],
                Vec::new(),
                large.into_bytes(),
                control.serialize(),
            ])],
        );
    }

    #[test]
    fn counts_mixed_native_witness_inputs() {
        let script = multi_a(2, 1);
        let (mut psbt, control) = taproot_psbt(script.clone(), 0);
        let auxiliary = psbt_with_script(ScriptBuf::new_p2wpkh(
            &public_key(3).wpubkey_hash().unwrap(),
        ));
        psbt.unsigned_tx
            .input
            .push(auxiliary.unsigned_tx.input[0].clone());
        psbt.unsigned_tx.input[1].previous_output.vout = 1;
        psbt.inputs.push(auxiliary.inputs[0].clone());
        assert_matches_serialization(
            &psbt,
            vec![
                Witness::from_slice(&[vec![1; 65], Vec::new(), script.into_bytes(), control]),
                Witness::from_slice(&[vec![1; 73], public_key(3).to_bytes()]),
            ],
        );
    }

    #[test]
    fn counts_native_wsh_multisig_dummy_and_signatures() {
        let script = Builder::new()
            .push_int(2)
            .push_key(&public_key(2))
            .push_key(&public_key(3))
            .push_key(&public_key(4))
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let mut psbt = psbt_with_script(script.to_p2wsh());
        psbt.inputs[0].witness_script = Some(script.clone());
        assert_matches_serialization(
            &psbt,
            vec![Witness::from_slice(&[
                Vec::new(),
                vec![1; 73],
                vec![1; 73],
                script.into_bytes(),
            ])],
        );
    }

    #[test]
    fn tiny_supplied_final_witness_cannot_lower_estimate() {
        let mut psbt = psbt_with_script(ScriptBuf::new_p2wpkh(
            &public_key(2).wpubkey_hash().unwrap(),
        ));
        let expected = estimated_signed_vsize(&psbt, &[]).unwrap();
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[vec![1]]));
        assert_eq!(estimated_signed_vsize(&psbt, &[]).unwrap(), expected);
    }

    #[test]
    fn larger_supplied_final_witness_is_counted() {
        let script = multi_a(1, 1);
        let (mut psbt, control) = taproot_psbt(script.clone(), 0);
        let witness =
            Witness::from_slice(&[vec![1; 65], script.into_bytes(), control, vec![0x50; 400]]);
        psbt.inputs[0].final_script_witness = Some(witness.clone());
        assert_matches_serialization(&psbt, vec![witness]);
    }

    #[test]
    fn permits_key_path_with_matching_tweak() {
        let key = public_key(1).inner.x_only_public_key().0;
        for root in [
            None,
            Some(bitcoin::taproot::TapNodeHash::from_byte_array([0x77; 32])),
        ] {
            let mut psbt = psbt_with_script(ScriptBuf::new_p2tr(&Secp256k1::new(), key, root));
            assert_error(&psbt, "metadata is missing");
            psbt.inputs[0].tap_internal_key = Some(key);
            psbt.inputs[0].tap_merkle_root = root;
            assert_matches_serialization(&psbt, vec![Witness::from_slice(&[vec![1; 64]])]);
            psbt.inputs[0].tap_internal_key = Some(public_key(2).inner.x_only_public_key().0);
            assert_error(&psbt, "does not match the prevout");
            psbt.inputs[0].tap_internal_key = Some(key);
            psbt.inputs[0].tap_merkle_root =
                Some(bitcoin::taproot::TapNodeHash::from_byte_array([0x88; 32]));
            assert_error(&psbt, "does not match the prevout");
        }
    }

    #[test]
    fn key_path_counts_requested_and_existing_signature_sizes() {
        let key = public_key(1).inner.x_only_public_key().0;
        let mut psbt = psbt_with_script(ScriptBuf::new_p2tr(&Secp256k1::new(), key, None));
        psbt.inputs[0].tap_internal_key = Some(key);
        for (requested, signature_len) in [
            (None, 64),
            (Some(TapSighashType::Default), 64),
            (Some(TapSighashType::All), 65),
        ] {
            psbt.inputs[0].sighash_type = requested.map(Into::into);
            assert_eq!(
                taproot_witness_size(
                    &psbt.inputs[0],
                    &psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey,
                    false,
                )
                .unwrap(),
                Witness::from_slice(&[vec![1; signature_len]]).size() as u64,
            );
        }
        // An existing signature must not be sized as a shorter DEFAULT signature.
        psbt.inputs[0].sighash_type = None;
        psbt.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
            signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&[1; 64]).unwrap(),
            sighash_type: TapSighashType::All,
        });
        assert_eq!(
            taproot_witness_size(
                &psbt.inputs[0],
                &psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey,
                false,
            )
            .unwrap(),
            Witness::from_slice(&[vec![1; 65]]).size() as u64,
        );
    }

    #[test]
    fn rejects_missing_tree_instead_of_assuming_key_path_size() {
        let (mut psbt, _) = taproot_psbt(multi_a(2, 1), 0);
        psbt.inputs[0].tap_scripts.clear();
        psbt.inputs[0].tap_internal_key = Some(public_key(1).inner.x_only_public_key().0);
        assert_error(&psbt, "does not match the prevout");
    }

    #[test]
    fn finalized_script_inputs_still_require_signing_metadata() {
        let script = multi_a(1, 1);
        let (mut psbt, control) = taproot_psbt(script.clone(), 0);
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[
            vec![1; 65],
            script.into_bytes(),
            control,
        ]));
        estimated_signed_vsize(&psbt, &[]).expect("complete Taproot metadata");
        psbt.inputs[0].tap_scripts.clear();
        assert_error(&psbt, "metadata is missing");

        let script = Builder::new()
            .push_int(1)
            .push_key(&public_key(2))
            .push_int(1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let mut psbt = psbt_with_script(script.to_p2wsh());
        psbt.inputs[0].witness_script = Some(script.clone());
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[
            Vec::new(),
            vec![1; 73],
            script.into_bytes(),
        ]));
        estimated_signed_vsize(&psbt, &[]).expect("complete P2WSH metadata");
        psbt.inputs[0].witness_script = None;
        assert_error(&psbt, "witness_script is missing");
    }

    #[test]
    fn rejects_unknown_script_even_with_small_final_witness() {
        let (mut psbt, _) = taproot_psbt(ScriptBuf::from_bytes(vec![0x51]), 0);
        psbt.inputs[0].final_script_witness = Some(Witness::new());
        assert_error(&psbt, "unsupported Taproot script");
        let mut psbt = psbt_with_script(ScriptBuf::new());
        assert_error(&psbt, "unsupported prevout script type");
        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
            ScriptBuf::from_bytes(vec![0x51]).to_p2wsh();
        assert_error(&psbt, "witness_script is missing");
    }

    #[test]
    fn rejects_uncommitted_or_version_mismatched_taproot_metadata() {
        let (mut psbt, _) = taproot_psbt(multi_a(2, 1), 0);
        let (control, _) = psbt.inputs[0].tap_scripts.pop_first().unwrap();
        psbt.inputs[0]
            .tap_scripts
            .insert(control.clone(), (multi_a(3, 1), LeafVersion::TapScript));
        assert_error(&psbt, "does not commit to the prevout");
        psbt.inputs[0].tap_scripts.insert(
            control,
            (multi_a(2, 1), LeafVersion::from_consensus(0xc2).unwrap()),
        );
        assert_error(&psbt, "leaf version");
    }

    #[test]
    fn rejects_wsh_commitment_and_unsupported_script() {
        let script = Builder::new()
            .push_int(1)
            .push_key(&public_key(2))
            .push_int(1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let mut psbt = psbt_with_script(script.to_p2wsh());
        psbt.inputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x51]));
        assert_error(&psbt, "does not match the prevout");
        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
            psbt.inputs[0].witness_script.as_ref().unwrap().to_p2wsh();
        assert_error(&psbt, "unsupported P2WSH script");
    }

    #[test]
    fn estimates_non_witness_utxo_and_rejects_unavailable_funding_output() {
        let mut psbt = psbt_with_script(ScriptBuf::new_p2wpkh(
            &public_key(2).wpubkey_hash().unwrap(),
        ));
        let mut previous = psbt.unsigned_tx.clone();
        previous.output[0] = psbt.inputs[0].witness_utxo.clone().unwrap();
        psbt.unsigned_tx.input[0].previous_output.txid = previous.compute_txid();
        psbt.inputs[0].non_witness_utxo = Some(previous);
        let estimate = estimated_signed_vsize(&psbt, &[]).unwrap();
        psbt.inputs[0].witness_utxo = None;
        assert_eq!(estimated_signed_vsize(&psbt, &[]).unwrap(), estimate);
        psbt.unsigned_tx.input[0].previous_output.vout = 1;
        assert_error(&psbt, "funding output unavailable");
        psbt.inputs[0].non_witness_utxo = None;
        assert_error(&psbt, "funding output unavailable");
    }

    #[test]
    fn rejects_shape_mismatch_and_native_script_sig() {
        let mut psbt = psbt_with_script(ScriptBuf::new_p2wpkh(
            &public_key(2).wpubkey_hash().unwrap(),
        ));
        psbt.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x51]));
        assert_error(&psbt, "nonempty scriptSig");
        psbt.inputs[0].final_script_sig = None;
        psbt.unsigned_tx.input[0].witness = Witness::from_slice(&[vec![1]]);
        assert_error(&psbt, "already contains unlocking data");
        psbt.inputs.clear();
        assert_error(&psbt, "inconsistent or empty PSBT");
    }

    #[test]
    fn parser_rejects_extra_operations_bad_thresholds_and_nonminimal_numbers() {
        assert!(tapscript_threshold(&multi_a(2, 3)).is_none());
        assert!(tapscript_threshold(&multi_a(2, 0)).is_none());
        let mut extra = multi_a(2, 1).into_bytes();
        extra.push(0x51);
        assert!(tapscript_threshold(Script::from_bytes(&extra)).is_none());
        assert_eq!(positive_script_number(&[1, 17]), Some((17, 2)));
        assert_eq!(positive_script_number(&[2, 0x80, 0]), Some((128, 3)));
        for invalid in [&[1, 1][..], &[1, 0], &[1, 0x81], &[2, 17, 0], &[2, 1]] {
            assert!(positive_script_number(invalid).is_none());
        }
    }
}
