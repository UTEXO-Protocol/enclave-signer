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
mod tests {
    use super::*;
    use bitcoin::blockdata::opcodes::all::*;
    use bitcoin::blockdata::script::Builder as ScriptBuilder;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WScriptHash,
    };

    fn pk_from_byte(b: u8) -> bitcoin::PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[b; 32]).unwrap();
        bitcoin::PublicKey::new(sk.public_key(&secp))
    }

    fn ours() -> (PublicKey, bitcoin::PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let pk = sk.public_key(&secp);
        (pk, bitcoin::PublicKey::new(pk))
    }

    fn build_2of3_witness_script(keys: &[bitcoin::PublicKey; 3]) -> ScriptBuf {
        let mut sorted = *keys;
        sorted.sort_by_key(|k| k.to_bytes());
        ScriptBuilder::new()
            .push_int(2)
            .push_key(&sorted[0])
            .push_key(&sorted[1])
            .push_key(&sorted[2])
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    fn p2wsh_for(script: &ScriptBuf) -> ScriptBuf {
        ScriptBuf::new_p2wsh(&WScriptHash::hash(script.as_bytes()))
    }

    fn build_psbt(witness_script: ScriptBuf, script_pubkey: ScriptBuf) -> Psbt {
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xAA; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [0xBB; 20],
                )),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        });
        psbt.inputs[0].witness_script = Some(witness_script);
        psbt
    }

    fn dummy_ecdsa_sig() -> bitcoin::ecdsa::Signature {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x55; 32]).unwrap();
        let msg = bitcoin::secp256k1::Message::from_digest([0u8; 32]);
        bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa(&msg, &sk),
            sighash_type: bitcoin::sighash::EcdsaSighashType::All,
        }
    }

    #[test]
    fn signs_when_pubkey_in_legitimate_2of3_script() {
        let (pk, btc_pk) = ours();
        let ws = build_2of3_witness_script(&[btc_pk, pk_from_byte(0x02), pk_from_byte(0x03)]);
        let spk = p2wsh_for(&ws);
        let psbt = build_psbt(ws, spk);
        assert!(matches!(
            should_sign_segwit_input(&psbt, 0, &pk),
            SegwitSignDecision::SignP2wsh { .. }
        ));
    }

    #[test]
    fn skips_when_witness_utxo_missing() {
        let (pk, btc_pk) = ours();
        let ws = build_2of3_witness_script(&[btc_pk, pk_from_byte(0x02), pk_from_byte(0x03)]);
        let spk = p2wsh_for(&ws);
        let mut psbt = build_psbt(ws, spk);
        psbt.inputs[0].witness_utxo = None;
        assert!(matches!(
            should_sign_segwit_input(&psbt, 0, &pk),
            SegwitSignDecision::Skip
        ));
    }

    #[test]
    fn skips_when_witness_script_missing() {
        let (pk, btc_pk) = ours();
        let ws = build_2of3_witness_script(&[btc_pk, pk_from_byte(0x02), pk_from_byte(0x03)]);
        let spk = p2wsh_for(&ws);
        let mut psbt = build_psbt(ws, spk);
        psbt.inputs[0].witness_script = None;
        assert!(matches!(
            should_sign_segwit_input(&psbt, 0, &pk),
            SegwitSignDecision::Skip
        ));
    }

    #[test]
    fn skips_when_already_partial_signed() {
        let (pk, btc_pk) = ours();
        let ws = build_2of3_witness_script(&[btc_pk, pk_from_byte(0x02), pk_from_byte(0x03)]);
        let spk = p2wsh_for(&ws);
        let mut psbt = build_psbt(ws, spk);
        psbt.inputs[0]
            .partial_sigs
            .insert(btc_pk, dummy_ecdsa_sig());
        assert!(matches!(
            should_sign_segwit_input(&psbt, 0, &pk),
            SegwitSignDecision::Skip
        ));
    }

    /// Attacker ships a `witness_script` containing our key but
    /// `witness_utxo.script_pubkey` commits to a different script.
    #[test]
    fn skips_when_witness_script_does_not_hash_to_script_pubkey() {
        let (pk, btc_pk) = ours();
        let real_ws = build_2of3_witness_script(&[
            pk_from_byte(0x02),
            pk_from_byte(0x03),
            pk_from_byte(0x04),
        ]);
        let real_spk = p2wsh_for(&real_ws);
        let fake_ws = build_2of3_witness_script(&[btc_pk, pk_from_byte(0x02), pk_from_byte(0x03)]);
        let psbt = build_psbt(fake_ws, real_spk);
        assert!(matches!(
            should_sign_segwit_input(&psbt, 0, &pk),
            SegwitSignDecision::Skip
        ));
    }

    #[test]
    fn skips_when_script_pubkey_is_p2wpkh() {
        let (pk, btc_pk) = ours();
        let ws = build_2of3_witness_script(&[btc_pk, pk_from_byte(0x02), pk_from_byte(0x03)]);
        let p2wpkh = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xCC; 20]));
        let psbt = build_psbt(ws, p2wpkh);
        assert!(matches!(
            should_sign_segwit_input(&psbt, 0, &pk),
            SegwitSignDecision::Skip
        ));
    }

    /// Our pubkey bytes appear inside a 64-byte push but never as a 33-byte
    /// push on their own. A sliding-window byte search would falsely match.
    #[test]
    fn skips_when_pubkey_bytes_only_appear_inside_a_larger_push() {
        let (pk, _) = ours();
        let our = pk.serialize();
        let mut blob = Vec::with_capacity(64);
        blob.extend_from_slice(&our);
        blob.extend_from_slice(&[0xFFu8; 31]);
        let push: &bitcoin::script::PushBytes = blob.as_slice().try_into().unwrap();

        let mut others = [pk_from_byte(0x02), pk_from_byte(0x03), pk_from_byte(0x04)];
        others.sort_by_key(|k| k.to_bytes());
        let ws = ScriptBuilder::new()
            .push_slice(push)
            .push_opcode(OP_DROP)
            .push_int(2)
            .push_key(&others[0])
            .push_key(&others[1])
            .push_key(&others[2])
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let spk = p2wsh_for(&ws);
        let psbt = build_psbt(ws, spk);
        assert!(matches!(
            should_sign_segwit_input(&psbt, 0, &pk),
            SegwitSignDecision::Skip
        ));
    }

    /// The boss's exact bug: 2-of-3 multisig of three OTHER keys, but
    /// `bip32_derivation` lists our pubkey. Must NOT sign.
    #[test]
    fn skips_when_bip32_derivation_lies_and_script_excludes_us() {
        let (pk, _) = ours();
        let ws = build_2of3_witness_script(&[
            pk_from_byte(0x02),
            pk_from_byte(0x03),
            pk_from_byte(0x04),
        ]);
        let spk = p2wsh_for(&ws);
        let mut psbt = build_psbt(ws, spk);
        let fp = bitcoin::bip32::Fingerprint::from([0u8; 4]);
        let path = bitcoin::bip32::DerivationPath::from(vec![]);
        psbt.inputs[0].bip32_derivation.insert(pk, (fp, path));
        assert!(matches!(
            should_sign_segwit_input(&psbt, 0, &pk),
            SegwitSignDecision::Skip
        ));
    }
}
