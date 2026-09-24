use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{ScriptBuf, WScriptHash};

/// Decision returned by [`should_sign_segwit_input`].
///
/// A `SignP2wsh` carries the validated `witness_script` so callers don't have
/// to re-fetch and re-trust the PSBT field.
pub enum SegwitSignDecision {
    Skip,
    SignP2wsh { witness_script: ScriptBuf },
}

/// Decide whether to sign a PSBT input as P2WSH for `our_pubkey`.
///
/// Authorization is anchored to `witness_utxo.script_pubkey` - the only PSBT
/// field committed to by the BIP-143 sighash and therefore the only one we
/// can trust. We require:
///
///   1. `witness_utxo` is present and its `script_pubkey` is P2WSH.
///   2. `partial_sigs` does not already contain our key.
///   3. `witness_script` is present and `sha256(witness_script)` matches the
///      witness program in `script_pubkey` - closing the "fabricated
///      witness_script" hole.
///   4. `our_pubkey` appears as an exact 33-byte push (opcode-aware) inside
///      `witness_script` - closing the "key bytes hidden inside a larger
///      push" hole.
///
/// Hint fields (`bip32_derivation`, etc.) are coordinator-supplied and are
/// not consulted: their presence is necessary neither nor sufficient.
pub fn should_sign_segwit_input(
    psbt: &Psbt,
    input_index: usize,
    our_pubkey: &PublicKey,
) -> SegwitSignDecision {
    let input = &psbt.inputs[input_index];

    let Some(witness_utxo) = input.witness_utxo.as_ref() else {
        return SegwitSignDecision::Skip;
    };

    let our_bitcoin_pubkey = bitcoin::PublicKey::new(*our_pubkey);
    if input.partial_sigs.contains_key(&our_bitcoin_pubkey) {
        return SegwitSignDecision::Skip;
    }

    let Some(witness_script) = input.witness_script.as_ref() else {
        return SegwitSignDecision::Skip;
    };

    let expected = ScriptBuf::new_p2wsh(&WScriptHash::hash(witness_script.as_bytes()));
    if witness_utxo.script_pubkey != expected {
        return SegwitSignDecision::Skip;
    }

    let our_bytes = our_pubkey.serialize();
    let found = witness_script
        .instructions()
        .filter_map(Result::ok)
        .any(|insn| matches!(insn, Instruction::PushBytes(b) if b.as_bytes() == our_bytes));

    if found {
        SegwitSignDecision::SignP2wsh {
            witness_script: witness_script.clone(),
        }
    } else {
        SegwitSignDecision::Skip
    }
}

#[cfg(test)]
mod tests;
