use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{self, TapNodeHash};
use bitcoin::TxOut;
use bitcoin::XOnlyPublicKey;

use crate::error::{EnclaveError, Result};
use crate::keys::{AccountType, KeyManager};

/// One BIP-86 key-path input this enclave controls and can sign.
pub struct TaprootSignJob {
    pub input_index: usize,
    /// The untweaked internal key, derived from our seed.
    pub xonly_pubkey: XOnlyPublicKey,
    /// Tapret / script-tree root the output key was tweaked with, if any.
    pub merkle_root: Option<TapNodeHash>,
    pub account_type: AccountType,
    pub child_path: Vec<bitcoin::bip32::ChildNumber>,
}

/// Scan all PSBT inputs for BIP-86 key-path spends we own, one entry per input.
///
/// This is the custody anchor. An input is ours when its claimed
/// `tap_internal_key` is (1) listed in `tap_key_origins` under our fingerprint,
/// (2) at a BIP-86 path of one of our accounts that (3) derives exactly that
/// key, and (4) tweaked with `tap_merkle_root` reproduces the output key in
/// `witness_utxo.script_pubkey` (BIP-341). A forged origins entry cannot pass
/// (3) and a foreign coin cannot pass (4). Script-path spends are never ours:
/// the bridge wallet is singlesig. It never reads `tap_key_sig`, so an input
/// stays ours after we merge a signature into it.
pub fn find_controlled_taproot_inputs(
    psbt: &Psbt,
    master_fingerprint: &Fingerprint,
    key_manager: &KeyManager,
) -> Vec<TaprootSignJob> {
    let secp = Secp256k1::new();

    psbt.inputs
        .iter()
        .enumerate()
        .filter_map(|(input_idx, input)| {
            let witness_utxo = input.witness_utxo.as_ref()?;
            if !witness_utxo.script_pubkey.is_p2tr() {
                return None;
            }
            let spk_bytes = witness_utxo.script_pubkey.as_bytes();
            // P2TR is exactly OP_1 (0x51) + 0x20 + 32-byte program.
            if spk_bytes.len() != 34 {
                return None;
            }
            let output_key = XOnlyPublicKey::from_slice(&spk_bytes[2..34]).ok()?;
            key_path_job(
                &secp,
                input,
                input_idx,
                output_key,
                master_fingerprint,
                key_manager,
            )
        })
        .collect()
}

/// Key-path entry when the claimed internal key is ours and, tweaked with
/// `tap_merkle_root`, reproduces the output key. Never looks at `tap_key_sig`.
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
        merkle_root: input.tap_merkle_root,
        account_type,
        child_path,
    })
}

/// The signing work left on this PSBT: the controlled inputs that carry no
/// key-path signature yet, whatever an existing one contains.
pub fn find_taproot_sign_jobs(
    psbt: &Psbt,
    master_fingerprint: &Fingerprint,
    key_manager: &KeyManager,
) -> Vec<TaprootSignJob> {
    find_controlled_taproot_inputs(psbt, master_fingerprint, key_manager)
        .into_iter()
        .filter(|job| psbt.inputs[job.input_index].tap_key_sig.is_none())
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

/// Sign key-path taproot inputs: each job gets a `tap_key_sig`. Returns the
/// number of signatures added.
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

        signed_count += 1;
    }

    Ok(signed_count)
}

#[cfg(test)]
mod tests;
