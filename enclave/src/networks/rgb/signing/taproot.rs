use std::collections::HashSet;

use bitcoin::bip32::Fingerprint;
use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{self, TapLeafHash, TapNodeHash};
use bitcoin::TxOut;
use bitcoin::XOnlyPublicKey;

use crate::error::{EnclaveError, Result};
use crate::keys::{AccountType, KeyManager};

/// Info about a single taproot signature we need to produce for one input.
pub struct TaprootSignJob {
    pub input_index: usize,
    pub xonly_pubkey: XOnlyPublicKey,
    /// `Some` for a script-path leaf, `None` for a BIP-86 key-path spend.
    pub leaf_hash: Option<TapLeafHash>,
    /// Tapret / script-tree root a key-path spend was tweaked with, if any.
    pub merkle_root: Option<TapNodeHash>,
    pub account_type: AccountType,
    pub child_path: Vec<bitcoin::bip32::ChildNumber>,
}

/// Scan all PSBT inputs for taproot spends we own: one entry per script-path
/// (input, leaf, xonly) triple, and one per BIP-86 key-path input.
///
/// This is the custody anchor. It checks control-block and derivation
/// structure only, never `tap_script_sigs`. An input stays ours after we
/// merge a signature into it.
///
/// Authorization is anchored to `witness_utxo.script_pubkey` - for each
/// `(control_block, script)` entry in `tap_scripts`, the control block must
/// prove the script's inclusion under the on-chain output key (BIP-341). The
/// candidate xonly key must (1) appear as a 32-byte push inside the verified
/// leaf script, (2) be claimed by a `tap_key_origins` entry whose fingerprint
/// matches ours, (3) appear in that entry's `leaf_hashes` for *this* leaf,
/// and (4) match the xonly pubkey our claimed BIP-86 derivation actually
/// derives - closing the gap where a coordinator could forge `tap_key_origins`
/// to point our fingerprint at someone else's key. A key-path entry has the
/// same anchors, with the tweak check in place of the control block.
pub fn find_controlled_taproot_leaves(
    psbt: &Psbt,
    master_fingerprint: &Fingerprint,
    key_manager: &KeyManager,
) -> Vec<TaprootSignJob> {
    let secp = Secp256k1::new();
    let mut jobs = Vec::new();
    let mut emitted: HashSet<(usize, Option<TapLeafHash>, XOnlyPublicKey)> = HashSet::new();

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

                if !emitted.insert((input_idx, Some(leaf_hash), xonly_pk)) {
                    continue;
                }

                jobs.push(TaprootSignJob {
                    input_index: input_idx,
                    xonly_pubkey: xonly_pk,
                    leaf_hash: Some(leaf_hash),
                    merkle_root: None,
                    account_type,
                    child_path,
                });
            }
        }

        if let Some(job) = key_path_job(
            &secp,
            input,
            input_idx,
            output_key,
            master_fingerprint,
            key_manager,
        ) {
            if emitted.insert((input_idx, None, job.xonly_pubkey)) {
                jobs.push(job);
            }
        }
    }

    jobs
}

/// Key-path entry when the claimed internal key is ours and, tweaked with
/// `tap_merkle_root`, reproduces the output key; the control-block check's twin.
/// Like the leaf scan, it never looks at `tap_key_sig`.
fn key_path_job(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    input: &bitcoin::psbt::Input,
    input_idx: usize,
    output_key: XOnlyPublicKey,
    master_fingerprint: &Fingerprint,
    key_manager: &KeyManager,
) -> Option<TaprootSignJob> {
    let internal_key = input.tap_internal_key?;
    let (_, (fingerprint, derivation_path)) = input.tap_key_origins.get(&internal_key)?;
    if fingerprint != master_fingerprint {
        return None;
    }
    let (account_type, child_path) = key_manager.resolve_account_and_child_path(derivation_path)?;
    let child_secret = key_manager
        .derive_btc_child(account_type, &child_path)
        .ok()?;
    let (derived_xonly, _) =
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(secp, &child_secret));
    if derived_xonly != internal_key {
        return None;
    }
    let (tweaked, _) = internal_key.tap_tweak(secp, input.tap_merkle_root);
    if tweaked.to_x_only_public_key() != output_key {
        return None;
    }
    Some(TaprootSignJob {
        input_index: input_idx,
        xonly_pubkey: internal_key,
        leaf_hash: None,
        merkle_root: input.tap_merkle_root,
        account_type,
        child_path,
    })
}

/// The signing work left on this PSBT: the controlled spends that do not yet
/// carry an entry under our key, whatever that entry contains.
pub fn find_taproot_sign_jobs(
    psbt: &Psbt,
    master_fingerprint: &Fingerprint,
    key_manager: &KeyManager,
) -> Vec<TaprootSignJob> {
    find_controlled_taproot_leaves(psbt, master_fingerprint, key_manager)
        .into_iter()
        .filter(|job| {
            let input = &psbt.inputs[job.input_index];
            match job.leaf_hash {
                Some(leaf_hash) => !input
                    .tap_script_sigs
                    .contains_key(&(job.xonly_pubkey, leaf_hash)),
                None => input.tap_key_sig.is_none(),
            }
        })
        .collect()
}

/// Input indices of [`find_taproot_sign_jobs`], used only by tests to check
/// signing work left on a PSBT. Custody code must never call the job
/// resolver: that would be a regression.
#[cfg(all(test, evm_to_rgb))]
pub(crate) fn outstanding_job_inputs(psbt: &Psbt, key_manager: &KeyManager) -> Vec<usize> {
    find_taproot_sign_jobs(psbt, key_manager.master_fingerprint(), key_manager)
        .into_iter()
        .map(|job| job.input_index)
        .collect()
}

/// Sign taproot inputs in the PSBT: script-path jobs get a `tap_script_sig`,
/// key-path jobs a `tap_key_sig`. Returns the number of signatures added.
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
        let requested = psbt.inputs[job.input_index]
            .sighash_type
            .map(|ty| ty.to_u32())
            .unwrap_or(0);

        let sighash_type = match requested {
            0x00 => TapSighashType::Default,
            0x01 => TapSighashType::All,
            _ => {
                return Err(EnclaveError::Signing(format!(
                    "unsupported taproot sighash 0x{requested:02x} for input {}: expected DEFAULT or ALL",
                    job.input_index
                )));
            }
        };

        let child_secret = key_manager.derive_btc_child(job.account_type, &job.child_path)?;
        let keypair = Keypair::from_secret_key(&secp, &child_secret);

        match job.leaf_hash {
            Some(leaf_hash) => {
                let sighash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        job.input_index,
                        &Prevouts::All(&prevouts),
                        leaf_hash,
                        sighash_type,
                    )
                    .map_err(|e| EnclaveError::Signing(format!("taproot sighash: {e}")))?;
                // No tweak: a script-path spend signs with the untweaked child key.
                let signature = secp.sign_schnorr_no_aux_rand(
                    &Message::from_digest(*sighash.as_byte_array()),
                    &keypair,
                );
                psbt.inputs[job.input_index].tap_script_sigs.insert(
                    (job.xonly_pubkey, leaf_hash),
                    taproot::Signature {
                        signature,
                        sighash_type,
                    },
                );
            }
            None => {
                let sighash = sighash_cache
                    .taproot_key_spend_signature_hash(
                        job.input_index,
                        &Prevouts::All(&prevouts),
                        sighash_type,
                    )
                    .map_err(|e| EnclaveError::Signing(format!("taproot sighash: {e}")))?;
                // A key-path spend signs with the child key tweaked like the output.
                let tweaked = keypair.tap_tweak(&secp, job.merkle_root);
                let signature = secp.sign_schnorr_no_aux_rand(
                    &Message::from_digest(*sighash.as_byte_array()),
                    &tweaked.to_keypair(),
                );
                psbt.inputs[job.input_index].tap_key_sig = Some(taproot::Signature {
                    signature,
                    sighash_type,
                });
            }
        }

        signed_count += 1;
    }

    Ok(signed_count)
}

#[cfg(test)]
mod tests;
