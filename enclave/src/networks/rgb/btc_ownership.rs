//! Proof that a PSBT output pays back to keys this enclave controls.
//!
//! The proof uses no operator-pinned script list. Such scripts derive from a
//! seed that exists only after boot, and putting them in the image changes
//! PCR0.
//!
//! An output is the enclave's own when it is a BIP-86 key-path output of one
//! of its accounts: the claimed internal key derives from the seed at the
//! claimed path, the output has no script tree, and the key tweaked with an
//! empty tree gives the script. The metadata only names the path. A forged
//! claim cannot match the script. Only the enclave can spend such an output.
//! This covers change and `create_utxo` allocations.
//!
//! The script of a spent input is no such proof: an output that pays back to
//! it without this metadata is not counted as owned. A taproot leaf that names
//! our key proves nothing about the rest of the tree or its internal key, so
//! an output with a tree is refused too.
//!
//! A refusal cannot rely on that metadata, since the host that builds the PSBT
//! supplies it. So a witness mint, which must not put its units on an output of
//! the enclave, also compares that one output with the scripts of the inputs the
//! enclave controls ([`controlled_input_scripts`]). That comparison needs no
//! metadata, and it matches a tapret-tweaked input too. The change of the mint is
//! the enclave's own output.

use std::collections::HashSet;

use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::signing::taproot::find_controlled_taproot_inputs;

/// The `script_pubkey`s of the PSBT inputs this enclave controls, on either
/// BIP-86 account.
///
/// Each entry comes from the custody resolver: a Taproot key-path input whose
/// internal key derives from a BIP-86 account and, tweaked with its merkle
/// root, gives the output key. It serves the refusal of a witness mint only,
/// and exempts nothing.
pub fn controlled_input_scripts(psbt: &Psbt, keys: &KeyManager) -> HashSet<Vec<u8>> {
    find_controlled_taproot_inputs(psbt, keys.master_fingerprint(), keys)
        .iter()
        .filter_map(|job| psbt.inputs.get(job.input_index))
        .filter_map(|input| input.witness_utxo.as_ref())
        .map(|utxo| utxo.script_pubkey.as_bytes().to_vec())
        .collect()
}

/// True when output `index` is on one of `input_scripts`, the scripts of the
/// inputs the enclave controls. The caller resolves them once for all outputs.
pub fn output_repays_controlled_input(
    psbt: &Psbt,
    index: usize,
    input_scripts: &HashSet<Vec<u8>>,
) -> bool {
    let Some(txout) = psbt.unsigned_tx.output.get(index) else {
        return false;
    };
    input_scripts.contains(txout.script_pubkey.as_bytes())
}

/// True when output `index` is the enclave's own: the claimed internal key is
/// ours at the claimed BIP-86 path, there is no script tree, and the empty-tree
/// tweak of that key is the script. It is the key-path sign job check, applied
/// to an output. The path must be a wallet path, so the wallet can find the
/// output again.
/// `allowed_account` is `Some(_)` for one BIP-86 account, `None` for either.
pub fn output_is_self_derived(
    psbt: &Psbt,
    index: usize,
    keys: &KeyManager,
    allowed_account: Option<AccountType>,
) -> bool {
    let (Some(output), Some(txout)) = (psbt.outputs.get(index), psbt.unsigned_tx.output.get(index))
    else {
        return false;
    };
    if output.tap_tree.is_some() {
        return false;
    }
    let Some(internal_key) = output.tap_internal_key else {
        return false;
    };
    let Some((leaf_hashes, (fingerprint, derivation_path))) =
        output.tap_key_origins.get(&internal_key)
    else {
        return false;
    };
    if !leaf_hashes.is_empty() || fingerprint != keys.master_fingerprint() {
        return false;
    }
    let Some((account_type, child_path)) = keys.resolve_account_and_child_path(derivation_path)
    else {
        return false;
    };
    if allowed_account.is_some_and(|want| account_type != want) {
        return false;
    }
    if !crate::keys::is_wallet_child_path(account_type, &child_path) {
        return false;
    }
    let Ok(child_secret) = keys.derive_btc_child(account_type, &child_path) else {
        return false;
    };
    let secp = Secp256k1::new();
    let (derived, _) =
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &child_secret));
    if derived != internal_key {
        return false;
    }
    let (tweaked, _) = internal_key.tap_tweak(&secp, None);
    txout.script_pubkey == ScriptBuf::new_p2tr_tweaked(tweaked)
}

/// Sats that the outputs pay to scripts the enclave cannot prove its own. An
/// output that [`output_is_self_derived`] accepts is exempt in full. `None` on
/// overflow.
pub fn unowned_output_sats(psbt: &Psbt, keys: &KeyManager) -> Option<u64> {
    let mut unowned: u64 = 0;
    for (index, txout) in psbt.unsigned_tx.output.iter().enumerate() {
        if output_is_self_derived(psbt, index, keys, None) {
            continue;
        }
        unowned = unowned.checked_add(txout.value.to_sat())?;
    }
    Some(unowned)
}

#[cfg(test)]
pub(crate) mod tests;
