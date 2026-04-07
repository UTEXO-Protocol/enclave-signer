use bitcoin::bip32::Fingerprint;
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

/// Scan all PSBT inputs for taproot inputs our key can sign.
/// Returns a list of sign jobs.
pub fn find_taproot_sign_jobs(
    psbt: &Psbt,
    master_fingerprint: &Fingerprint,
    key_manager: &KeyManager,
) -> Vec<TaprootSignJob> {
    let mut jobs = Vec::new();

    for (i, input) in psbt.inputs.iter().enumerate() {
        // Iterate tap_key_origins looking for our fingerprint
        for (xonly_pubkey, (leaf_hashes, (fingerprint, derivation_path))) in &input.tap_key_origins
        {
            if fingerprint != master_fingerprint {
                continue;
            }

            // Resolve account type and child path from the full derivation path
            let resolved = key_manager.resolve_account_and_child_path(derivation_path);
            let (account_type, child_path) = match resolved {
                Some(r) => r,
                None => continue, // Path doesn't match our BIP-86 accounts
            };

            // Sign for each leaf hash where our key participates
            for leaf_hash in leaf_hashes {
                // Skip if already signed for this (pubkey, leaf_hash) pair
                if input
                    .tap_script_sigs
                    .contains_key(&(*xonly_pubkey, *leaf_hash))
                {
                    continue;
                }

                jobs.push(TaprootSignJob {
                    input_index: i,
                    xonly_pubkey: *xonly_pubkey,
                    leaf_hash: *leaf_hash,
                    account_type,
                    child_path: child_path.clone(),
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
