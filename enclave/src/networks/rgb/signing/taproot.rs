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
/// one of our keys, and emit one entry per (input, leaf, xonly) triple.
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
/// to point our fingerprint at someone else's key.
pub fn find_controlled_taproot_leaves(
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

/// The signing work left on this PSBT: the controlled leaves that do not yet
/// carry an entry under our key, whatever that entry contains.
pub fn find_taproot_sign_jobs(
    psbt: &Psbt,
    master_fingerprint: &Fingerprint,
    key_manager: &KeyManager,
) -> Vec<TaprootSignJob> {
    find_controlled_taproot_leaves(psbt, master_fingerprint, key_manager)
        .into_iter()
        .filter(|job| {
            !psbt.inputs[job.input_index]
                .tap_script_sigs
                .contains_key(&(job.xonly_pubkey, job.leaf_hash))
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

        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                job.input_index,
                &Prevouts::All(&prevouts),
                job.leaf_hash,
                sighash_type,
            )
            .map_err(|e| EnclaveError::Signing(format!("taproot sighash: {e}")))?;

        let msg = Message::from_digest(*sighash.as_byte_array());

        // No tweak: a script-path spend signs with the untweaked child key.
        let keypair = Keypair::from_secret_key(&secp, &child_secret);
        let schnorr_sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        let tap_sig = taproot::Signature {
            signature: schnorr_sig,
            sighash_type,
        };
        psbt.inputs[job.input_index]
            .tap_script_sigs
            .insert((job.xonly_pubkey, job.leaf_hash), tap_sig);

        signed_count += 1;
    }

    Ok(signed_count)
}

#[cfg(test)]
mod tests;
