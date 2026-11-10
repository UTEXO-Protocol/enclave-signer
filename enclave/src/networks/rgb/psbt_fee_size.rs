use bitcoin::blockdata::opcodes::all::{
    OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL,
};
use bitcoin::psbt::{Input, Psbt};
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::LeafVersion;
use bitcoin::{Script, ScriptBuf};

use crate::error::{EnclaveError, Result};

/// Estimated signed vsize, with a witness estimate for every input. Only
/// native-witness spends are supported. Hidden Taproot leaves and later
/// finalizer changes are not bounded, so the finalizer must check the real fee
/// rate too.
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
    // With disclosed leaves, only the trusted signer resolver can select key-path.
    if key_path || input.tap_scripts.is_empty() {
        let internal_key = input
            .tap_internal_key
            .ok_or("Taproot spend metadata is missing")?;
        // A Tapret root changes the output key, not the key-path witness.
        if ScriptBuf::new_p2tr(&secp, internal_key, input.tap_merkle_root).as_script() != script {
            return Err("Taproot internal key/merkle root does not match the prevout");
        }
        // DEFAULT has no sighash byte. An existing ALL signature still has it.
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
        // Empty multi_a slots also use witness bytes. A signature can have a
        // sighash byte.
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
mod tests;
