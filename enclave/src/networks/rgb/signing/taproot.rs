use std::collections::HashSet;

use bitcoin::bip32::Fingerprint;
use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{self, TapLeafHash};
use bitcoin::TxOut;
use bitcoin::XOnlyPublicKey;

use crate::error::{EnclaveError, Result};
use crate::keys::{AccountType, KeyManager};

/// Info about a single taproot signature we need to produce for one input.
pub struct TaprootSignJob {
    pub input_index: usize,
    pub xonly_pubkey: XOnlyPublicKey,
    pub leaf_hash: TapLeafHash,
    pub account_type: AccountType,
    pub child_path: Vec<bitcoin::bip32::ChildNumber>,
}

/// Scan all PSBT inputs for taproot script-path leaves whose script contains
/// one of our keys, and emit a sign job per (input, leaf, xonly) triple.
///
/// Authorization is anchored to `witness_utxo.script_pubkey` — for each
/// `(control_block, script)` entry in `tap_scripts`, the control block must
/// prove the script's inclusion under the on-chain output key (BIP-341). The
/// candidate xonly key must (1) appear as a 32-byte push inside the verified
/// leaf script, (2) be claimed by a `tap_key_origins` entry whose fingerprint
/// matches ours, (3) appear in that entry's `leaf_hashes` for *this* leaf,
/// and (4) match the xonly pubkey our claimed BIP-86 derivation actually
/// derives — closing the gap where a coordinator could forge `tap_key_origins`
/// to point our fingerprint at someone else's key.
pub fn find_taproot_sign_jobs(
    psbt: &Psbt,
    master_fingerprint: &Fingerprint,
    key_manager: &KeyManager,
) -> Vec<TaprootSignJob> {
    let secp = Secp256k1::new();
    let mut jobs = Vec::new();
    let mut emitted: HashSet<(usize, TapLeafHash, XOnlyPublicKey)> = HashSet::new();

    for (input_idx, input) in psbt.inputs.iter().enumerate() {
        let Some(witness_utxo) = input.witness_utxo.as_ref() else {
            continue;
        };
        if !witness_utxo.script_pubkey.is_p2tr() {
            continue;
        }
        let spk_bytes = witness_utxo.script_pubkey.as_bytes();
        // P2TR is exactly OP_1 (0x51) + 0x20 + 32-byte program.
        if spk_bytes.len() != 34 {
            continue;
        }
        let Ok(output_key) = XOnlyPublicKey::from_slice(&spk_bytes[2..34]) else {
            continue;
        };

        for (control_block, (script, leaf_version)) in &input.tap_scripts {
            if !control_block.verify_taproot_commitment(&secp, output_key, script) {
                continue;
            }
            let leaf_hash = TapLeafHash::from_script(script, *leaf_version);

            for insn in script.instructions().filter_map(|r| r.ok()) {
                let Instruction::PushBytes(bytes) = insn else {
                    continue;
                };
                if bytes.as_bytes().len() != 32 {
                    continue;
                }
                let Ok(xonly_pk) = XOnlyPublicKey::from_slice(bytes.as_bytes()) else {
                    continue;
                };

                let Some((leaf_hashes, (fingerprint, derivation_path))) =
                    input.tap_key_origins.get(&xonly_pk)
                else {
                    continue;
                };
                if fingerprint != master_fingerprint {
                    continue;
                }
                if !leaf_hashes.contains(&leaf_hash) {
                    continue;
                }

                let Some((account_type, child_path)) =
                    key_manager.resolve_account_and_child_path(derivation_path)
                else {
                    continue;
                };

                let Ok(child_secret) = key_manager.derive_btc_child(account_type, &child_path)
                else {
                    continue;
                };
                let kp = Keypair::from_secret_key(&secp, &child_secret);
                let (derived_xonly, _) = XOnlyPublicKey::from_keypair(&kp);
                if derived_xonly != xonly_pk {
                    continue;
                }

                if input.tap_script_sigs.contains_key(&(xonly_pk, leaf_hash)) {
                    continue;
                }

                if !emitted.insert((input_idx, leaf_hash, xonly_pk)) {
                    continue;
                }

                jobs.push(TaprootSignJob {
                    input_index: input_idx,
                    xonly_pubkey: xonly_pk,
                    leaf_hash,
                    account_type,
                    child_path,
                });
            }
        }
    }

    jobs
}

/// Sign taproot script-path inputs in the PSBT.
/// Returns the number of signatures added.
pub fn sign_taproot_inputs(
    psbt: &mut Psbt,
    key_manager: &KeyManager,
    jobs: &[TaprootSignJob],
) -> Result<usize> {
    if jobs.is_empty() {
        return Ok(0);
    }

    let secp = Secp256k1::new();

    // BIP-341 requires ALL prevouts for taproot sighash computation
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|input| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| EnclaveError::Signing("missing witness_utxo for taproot".into()))
        })
        .collect::<Result<Vec<_>>>()?;

    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut sighash_cache = SighashCache::new(&unsigned_tx);

    let mut signed_count = 0;

    for job in jobs {
        // Derive the child secret key for this input
        let child_secret = key_manager.derive_btc_child(job.account_type, &job.child_path)?;

        // Compute taproot script-path sighash
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                job.input_index,
                &Prevouts::All(&prevouts),
                job.leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| EnclaveError::Signing(format!("taproot sighash: {e}")))?;

        let msg = Message::from_digest(*sighash.as_byte_array());

        // Create keypair for Schnorr signing (no tweak for script-path spend)
        let keypair = Keypair::from_secret_key(&secp, &child_secret);
        let schnorr_sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        // Insert tap_script_sig with Default sighash (empty sighash byte)
        let tap_sig = taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::Default,
        };
        psbt.inputs[job.input_index]
            .tap_script_sigs
            .insert((job.xonly_pubkey, job.leaf_hash), tap_sig);

        signed_count += 1;
    }

    Ok(signed_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{ChildNumber, DerivationPath};
    use bitcoin::blockdata::opcodes::all::*;
    use bitcoin::blockdata::script::Builder as ScriptBuilder;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};

    /// NUMS internal key used for unspendable key-path.
    const NUMS_INTERNAL: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];

    fn xonly_from_byte(b: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[b; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        XOnlyPublicKey::from_keypair(&kp).0
    }

    fn our_xonly(km: &KeyManager) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = km
            .derive_btc_child(
                AccountType::Vanilla,
                &[
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .unwrap();
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0
    }

    fn our_full_path() -> DerivationPath {
        DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(), // testnet
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ])
    }

    fn multi_a_2_of_3(keys: &[XOnlyPublicKey; 3]) -> ScriptBuf {
        let mut sorted = *keys;
        sorted.sort();
        ScriptBuilder::new()
            .push_x_only_key(&sorted[0])
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&sorted[1])
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&sorted[2])
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script()
    }

    /// Build a taproot P2TR PSBT for testing.
    /// Returns: (psbt, output_internal_key, leaf_script, leaf_hash, control_block).
    fn build_legit_taproot_psbt(
        km: &KeyManager,
    ) -> (Psbt, XOnlyPublicKey, ScriptBuf, TapLeafHash, ControlBlock) {
        let secp = Secp256k1::new();
        let our = our_xonly(km);
        let other1 = xonly_from_byte(0xA1);
        let other2 = xonly_from_byte(0xA2);
        let leaf_script = multi_a_2_of_3(&[our, other1, other2]);
        let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

        let internal_key = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let builder = TaprootBuilder::new()
            .add_leaf(0, leaf_script.clone())
            .unwrap();
        let spend_info = builder.finalize(&secp, internal_key).unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, spend_info.merkle_root());
        let control_block = spend_info
            .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
            .unwrap();

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
                script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        });
        psbt.inputs[0].tap_internal_key = Some(internal_key);
        psbt.inputs[0].tap_scripts.insert(
            control_block.clone(),
            (leaf_script.clone(), LeafVersion::TapScript),
        );
        psbt.inputs[0].tap_key_origins.insert(
            our,
            (vec![leaf_hash], (*km.master_fingerprint(), our_full_path())),
        );

        (psbt, internal_key, leaf_script, leaf_hash, control_block)
    }

    #[test]
    fn emits_one_job_for_legit_multi_a_leaf() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let (psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km);
        let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].leaf_hash, leaf_hash);
        assert_eq!(jobs[0].xonly_pubkey, our_xonly(&km));
    }

    /// `tap_scripts` advertises a leaf that does NOT actually sit under
    /// `script_pubkey`'s output key. Control block fails to verify.
    #[test]
    fn skips_when_control_block_does_not_verify() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let secp = Secp256k1::new();

        // Build the legit PSBT (anchored output key).
        let (mut psbt, _, _, _, _) = build_legit_taproot_psbt(&km);

        // Build an UNRELATED tree whose control_block we'll splice in.
        let our = our_xonly(&km);
        let unrelated_leaf = multi_a_2_of_3(&[our, xonly_from_byte(0xB1), xonly_from_byte(0xB2)]);
        let unrelated_internal = xonly_from_byte(0xC0);
        let unrelated_builder = TaprootBuilder::new()
            .add_leaf(0, unrelated_leaf.clone())
            .unwrap();
        let unrelated_info = unrelated_builder
            .finalize(&secp, unrelated_internal)
            .unwrap();
        let bad_control = unrelated_info
            .control_block(&(unrelated_leaf.clone(), LeafVersion::TapScript))
            .unwrap();

        psbt.inputs[0].tap_scripts.clear();
        psbt.inputs[0].tap_scripts.insert(
            bad_control,
            (unrelated_leaf.clone(), LeafVersion::TapScript),
        );
        // Update tap_key_origins to claim the unrelated leaf's hash.
        let bad_leaf_hash = TapLeafHash::from_script(&unrelated_leaf, LeafVersion::TapScript);
        psbt.inputs[0].tap_key_origins.insert(
            our,
            (
                vec![bad_leaf_hash],
                (*km.master_fingerprint(), our_full_path()),
            ),
        );

        let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
        assert!(jobs.is_empty());
    }

    #[test]
    fn skips_when_origins_fingerprint_wrong() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km);
        let our = our_xonly(&km);
        psbt.inputs[0].tap_key_origins.insert(
            our,
            (
                vec![leaf_hash],
                (Fingerprint::from([0xDE, 0xAD, 0xBE, 0xEF]), our_full_path()),
            ),
        );
        let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
        assert!(jobs.is_empty());
    }

    /// `tap_key_origins` claims OUR fingerprint at a real BIP-86 path, but
    /// keys it with someone else's xonly. Without the cryptographic anchor
    /// (derived xonly == claimed xonly) the signer would sign for a key it
    /// doesn't own.
    #[test]
    fn skips_when_origins_path_derives_to_different_xonly() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km);
        // Replace origins with a foreign xonly under our fingerprint+path.
        let foreign = xonly_from_byte(0xEE);
        psbt.inputs[0].tap_key_origins.clear();
        psbt.inputs[0].tap_key_origins.insert(
            foreign,
            (vec![leaf_hash], (*km.master_fingerprint(), our_full_path())),
        );
        // Note: leaf script does not push `foreign`, so even pubkey-in-leaf
        // catches this. Switch the leaf to one that DOES push `foreign` to
        // exercise the derivation-mismatch branch specifically.
        let secp = Secp256k1::new();
        let foreign_leaf = multi_a_2_of_3(&[foreign, xonly_from_byte(0xB1), xonly_from_byte(0xB2)]);
        let foreign_leaf_hash = TapLeafHash::from_script(&foreign_leaf, LeafVersion::TapScript);
        let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(0, foreign_leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let cb = info
            .control_block(&(foreign_leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        psbt.inputs[0].tap_scripts.clear();
        psbt.inputs[0]
            .tap_scripts
            .insert(cb, (foreign_leaf.clone(), LeafVersion::TapScript));
        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
            ScriptBuf::new_p2tr_tweaked(info.output_key());
        psbt.inputs[0].tap_key_origins.clear();
        psbt.inputs[0].tap_key_origins.insert(
            foreign,
            (
                vec![foreign_leaf_hash],
                (*km.master_fingerprint(), our_full_path()),
            ),
        );

        let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
        assert!(jobs.is_empty());
    }

    /// `tap_key_origins` claims our key under our fingerprint, but the verified
    /// leaf doesn't push our xonly key.
    #[test]
    fn skips_when_xonly_in_origins_not_pushed_in_committed_leaf() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let secp = Secp256k1::new();

        // Build a leaf that does NOT contain our xonly.
        let leaf = multi_a_2_of_3(&[
            xonly_from_byte(0xB1),
            xonly_from_byte(0xB2),
            xonly_from_byte(0xB3),
        ]);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let cb = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();

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
            output: vec![],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
        });
        psbt.inputs[0]
            .tap_scripts
            .insert(cb, (leaf, LeafVersion::TapScript));
        // Lying entry: claims our key participates in this leaf.
        let our = our_xonly(&km);
        psbt.inputs[0].tap_key_origins.insert(
            our,
            (vec![leaf_hash], (*km.master_fingerprint(), our_full_path())),
        );

        let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
        assert!(jobs.is_empty());
    }

    #[test]
    fn skips_when_already_signed_for_leaf() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km);
        let our = our_xonly(&km);
        // Insert any tap_script_sig under (our, leaf_hash); content doesn't matter.
        let secp = Secp256k1::new();
        let dummy_kp =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x77; 32]).unwrap());
        let msg = Message::from_digest([0u8; 32]);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &dummy_kp);
        psbt.inputs[0].tap_script_sigs.insert(
            (our, leaf_hash),
            taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            },
        );
        let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
        assert!(jobs.is_empty());
    }

    #[test]
    fn skips_when_path_outside_bip86_accounts() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km);
        let our = our_xonly(&km);
        // Replace path with m/44'/0'/...
        let bad_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        psbt.inputs[0].tap_key_origins.clear();
        psbt.inputs[0]
            .tap_key_origins
            .insert(our, (vec![leaf_hash], (*km.master_fingerprint(), bad_path)));
        let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
        assert!(jobs.is_empty());
    }

    #[test]
    fn skips_when_witness_utxo_missing() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let (mut psbt, _, _, _, _) = build_legit_taproot_psbt(&km);
        psbt.inputs[0].witness_utxo = None;
        let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
        assert!(jobs.is_empty());
    }

    #[test]
    fn skips_when_witness_utxo_not_p2tr() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let (mut psbt, _, _, _, _) = build_legit_taproot_psbt(&km);
        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xCC; 20]));
        let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
        assert!(jobs.is_empty());
    }

    // === Account-scoped signing (plain-BTC path guard, M-01/#69) ===

    fn our_xonly_colored(km: &KeyManager) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = km
            .derive_btc_child(
                AccountType::Colored,
                &[
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .unwrap();
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0
    }

    fn our_colored_full_path() -> DerivationPath {
        DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(827167).unwrap(), // RGB coin type → Colored
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ])
    }

    /// Like [`build_legit_taproot_psbt`] but the leaf + tap_key_origins use the
    /// COLORED (RGB) account key/path, so the resolved job is `AccountType::Colored`.
    fn build_colored_taproot_psbt(km: &KeyManager) -> Psbt {
        let secp = Secp256k1::new();
        let our = our_xonly_colored(km);
        let leaf_script = multi_a_2_of_3(&[our, xonly_from_byte(0xA1), xonly_from_byte(0xA2)]);
        let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

        let internal_key = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf_script.clone())
            .unwrap()
            .finalize(&secp, internal_key)
            .unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, spend_info.merkle_root());
        let control_block = spend_info
            .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
            .unwrap();

        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xBB; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        });
        psbt.inputs[0].tap_internal_key = Some(internal_key);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf_script, LeafVersion::TapScript));
        psbt.inputs[0].tap_key_origins.insert(
            our,
            (
                vec![leaf_hash],
                (*km.master_fingerprint(), our_colored_full_path()),
            ),
        );
        psbt
    }

    #[test]
    fn scoped_vanilla_signs_a_vanilla_input() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let (psbt, _, _, _, _) = build_legit_taproot_psbt(&km);
        let bytes = psbt.serialize();
        let (_, signed) = km
            .sign_psbt_scoped(&bytes, Some(AccountType::Vanilla))
            .unwrap();
        assert_eq!(
            signed, 1,
            "vanilla-scoped signing must sign a vanilla input"
        );
    }

    #[test]
    fn scoped_vanilla_refuses_a_colored_input() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let bytes = build_colored_taproot_psbt(&km).serialize();

        // Unscoped: the colored input IS signable (sanity check the fixture).
        let (_, unscoped) = km.sign_psbt_scoped(&bytes, None).unwrap();
        assert_eq!(unscoped, 1, "fixture: colored input should sign unscoped");

        // Vanilla-scoped: the colored (RGB-allocated) input must NOT be signed.
        let (_, scoped) = km
            .sign_psbt_scoped(&bytes, Some(AccountType::Vanilla))
            .unwrap();
        assert_eq!(
            scoped, 0,
            "plain-BTC (vanilla-scoped) signing must refuse a colored input"
        );
    }
}
