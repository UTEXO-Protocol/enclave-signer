//! Proof that a PSBT output pays back to keys this enclave controls.
//!
//! The proof uses no operator-pinned script list. Such scripts derive from a
//! seed that exists only after boot, and putting them in the image changes
//! PCR0.
//!
//! An output is accepted on one of two rules.
//!
//! (A) Its `script_pubkey` equals that of an input this enclave controls, as
//! resolved by
//! [`find_controlled_taproot_inputs`](crate::networks::rgb::signing::taproot::find_controlled_taproot_inputs):
//! a Taproot key-path input whose internal key derives from a BIP-86 account and,
//! tweaked with its merkle root, gives the output key. The sighash commits to
//! the script. A tapret-tweaked input can commit to a script tree with foreign
//! spend paths. Thus outputs on its script are exempt only up to the input
//! value on that script. Bridge change passes because the wallet reuses
//! addresses.
//!
//! (C) It is a BIP-86 key-path output of one of our accounts: the claimed
//! internal key derives from our seed at the claimed path, the output has no
//! script tree, and the key tweaked with an empty tree gives the script. The
//! metadata only names the path. A forged claim cannot match the script. Only
//! we can spend it, so it is exempt in full. This covers fresh change and
//! `create_utxo` allocations.
//!
//! A taproot leaf that names our key proves nothing about the rest of the tree
//! or its internal key, so no rule accepts it. For the same reason, (C) refuses
//! any output with a tree. [`crate::networks::rgb::btc_crosscheck`] bounds by
//! value what neither rule proves.

use std::collections::{HashMap, HashSet};

use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::signing::taproot::{find_controlled_taproot_inputs, TaprootSignJob};

/// The `script_pubkey`s of the PSBT inputs this enclave provably controls.
///
/// Each entry comes from the custody resolver, so a real BIP-86 derivation
/// gives its output key. `allowed_account` is `Some(_)` for one BIP-86
/// account, `None` for either. The mint sats check (M8) passes `None`.
/// A wider filter changes only which scripts count as ours, never what is
/// signed. `sign_psbt_scoped` controls signing.
pub fn self_controlled_input_scripts_scoped(
    psbt: &Psbt,
    keys: &KeyManager,
    allowed_account: Option<AccountType>,
) -> HashSet<Vec<u8>> {
    let jobs = find_controlled_taproot_inputs(psbt, keys.master_fingerprint(), keys);
    controlled_input_scripts(psbt, &jobs, allowed_account)
}

/// [`self_controlled_input_scripts_scoped`] over resolved jobs, so a caller
/// that also needs the jobs (fee sizing) derives each input once.
/// `jobs` must come from [`find_controlled_taproot_inputs`] on this `psbt`.
pub fn controlled_input_scripts(
    psbt: &Psbt,
    jobs: &[TaprootSignJob],
    allowed_account: Option<AccountType>,
) -> HashSet<Vec<u8>> {
    jobs.iter()
        .filter(|job| allowed_account.is_none_or(|want| job.account_type == want))
        .filter_map(|job| psbt.inputs.get(job.input_index))
        .filter_map(|input| input.witness_utxo.as_ref())
        .map(|utxo| utxo.script_pubkey.as_bytes().to_vec())
        .collect()
}

/// True when output `index` pays back to one of `input_scripts` (rule A).
/// The caller resolves `input_scripts` once for all outputs.
pub fn output_is_self_owned(psbt: &Psbt, index: usize, input_scripts: &HashSet<Vec<u8>>) -> bool {
    let Some(txout) = psbt.unsigned_tx.output.get(index) else {
        return false;
    };
    input_scripts.contains(txout.script_pubkey.as_bytes())
}

/// Rule (C): the claimed internal key is ours at the claimed BIP-86 path, there
/// is no script tree, and the empty-tree tweak of that key is the script. It is
/// the key-path sign job check, applied to an output. The path must be a wallet
/// path, so the wallet can find the output again.
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

/// Sats that the outputs pay outside the custody of the inputs. An output on a
/// script in `input_scripts` is exempt up to the input value on that script
/// (rule A). A rule (C) output is exempt in full. `None` on overflow.
pub fn unowned_output_sats(
    psbt: &Psbt,
    input_scripts: &HashSet<Vec<u8>>,
    keys: &KeyManager,
) -> Option<u64> {
    let mut room: HashMap<&[u8], u64> = HashMap::new();
    for utxo in psbt.inputs.iter().filter_map(|i| i.witness_utxo.as_ref()) {
        let spk = utxo.script_pubkey.as_bytes();
        if input_scripts.contains(spk) {
            let r = room.entry(spk).or_default();
            *r = r.checked_add(utxo.value.to_sat())?;
        }
    }
    let mut unowned: u64 = 0;
    for (index, txout) in psbt.unsigned_tx.output.iter().enumerate() {
        if output_is_self_derived(psbt, index, keys, None) {
            continue;
        }
        let mut sat = txout.value.to_sat();
        if let Some(r) = room.get_mut(txout.script_pubkey.as_bytes()) {
            let exempt = sat.min(*r);
            *r -= exempt;
            sat -= exempt;
        }
        unowned = unowned.checked_add(sat)?;
    }
    Some(unowned)
}

#[cfg(test)]
pub(crate) mod tests;
