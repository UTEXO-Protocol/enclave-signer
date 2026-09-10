//! Proof that a plain-BTC PSBT output pays back to keys this enclave controls.
//!
//! Replaces the operator-pinned `BTC_ALLOWED_SCRIPTS` allowlist, which could
//! not work in production: the scripts to pin derive from a seed that only
//! exists after the enclave boots, and baking them into the image changes the
//! PCR0 identity that seed is bound to.
//!
//! An output is accepted on one rule: its `script_pubkey` equals that of an
//! input for which
//! [`find_taproot_sign_jobs`](crate::networks::rgb::signing::taproot::find_taproot_sign_jobs)
//! produced a job. That job is control-block and derivation anchored, and the
//! segwit sighash commits to the script.
//!
//! It proves custody is unchanged, not that only we can spend: the bridge is a
//! multisig, and the other signers can move funds without us either way. It
//! holds for bridge change because the wallet reuses addresses.
//!
//! A previous rule (B) accepted an output whose taproot tree held any leaf
//! pushing a key we derive. That proves nothing - a P2TR output is spendable by
//! its internal key alone, and one leaf says nothing about the rest of the tree
//! or its threshold. Removed. What it used to cover (fresh change indices,
//! `create_utxo` dust) is bounded by value in
//! [`crate::networks::rgb::btc_crosscheck`] instead.
//!
//! Scope: this makes the plain-BTC path structurally self-pay. Withdrawals to
//! an arbitrary user address remain out of scope.

use std::collections::HashSet;

use bitcoin::psbt::Psbt;

use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::signing::taproot::find_taproot_sign_jobs;

/// The `script_pubkey`s of every PSBT input this enclave provably co-controls
/// on the plain-BTC (Vanilla) account.
///
/// Membership comes from the signing-job resolver, so each entry carries the
/// full input-side anchor chain: control block verified against the input's own
/// output key, claimed key present in that leaf, and the claimed BIP-86
/// derivation actually producing it.
pub fn self_controlled_input_scripts(psbt: &Psbt, keys: &KeyManager) -> HashSet<Vec<u8>> {
    self_controlled_input_scripts_scoped(psbt, keys, Some(AccountType::Vanilla))
}

/// [`self_controlled_input_scripts`] with the account filter made explicit.
///
/// `allowed_account` is `Some(_)` for one BIP-86 account, `None` for either.
/// The plain-BTC path pins `Vanilla`; the send-RGB change-leg proof
/// passes `None`, since bridge change there sits on the Colored account.
/// Widening the filter only widens which scripts count as ours, never what gets
/// signed - that is `sign_psbt_scoped`'s job.
pub fn self_controlled_input_scripts_scoped(
    psbt: &Psbt,
    keys: &KeyManager,
    allowed_account: Option<AccountType>,
) -> HashSet<Vec<u8>> {
    find_taproot_sign_jobs(psbt, keys.master_fingerprint(), keys)
        .into_iter()
        .filter(|job| allowed_account.is_none_or(|want| job.account_type == want))
        .filter_map(|job| psbt.inputs.get(job.input_index))
        .filter_map(|input| input.witness_utxo.as_ref())
        .map(|utxo| utxo.script_pubkey.as_bytes().to_vec())
        .collect()
}

/// Indices of every PSBT output that provably pays back to this enclave, on
/// **either** BIP-86 account. Hoists the input resolution once and applies
/// [`output_is_self_owned`] to each output.
///
/// The change-leg oracle for the send-RGB per-output amount bind:
/// a revealed RGB seal counts as bridge change only when the Bitcoin output it
/// names is one we control.
pub fn self_owned_output_indices(psbt: &Psbt, keys: &KeyManager) -> HashSet<u32> {
    let input_scripts = self_controlled_input_scripts_scoped(psbt, keys, None);
    (0..psbt.unsigned_tx.output.len())
        .filter(|&i| output_is_self_owned(psbt, i, &input_scripts))
        .map(|i| i as u32)
        .collect()
}

/// Whether output `index` pays back into the custody its inputs were already in.
/// `input_scripts` is hoisted so a multi-output PSBT resolves its inputs once.
pub fn output_is_self_owned(psbt: &Psbt, index: usize, input_scripts: &HashSet<Vec<u8>>) -> bool {
    let Some(txout) = psbt.unsigned_tx.output.get(index) else {
        return false;
    };
    input_scripts.contains(txout.script_pubkey.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{ChildNumber, DerivationPath};
    use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
    use bitcoin::blockdata::script::Builder as ScriptBuilder;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::taproot::TapLeafHash;
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::ScriptBuf;
    use bitcoin::{
        Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        XOnlyPublicKey,
    };

    /// NUMS internal key - unspendable key-path, as the bridge's multisig
    /// addresses use.
    const NUMS_INTERNAL: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];

    fn km() -> KeyManager {
        KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap()
    }

    fn foreign_xonly(b: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[b; 32]).unwrap();
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0
    }

    /// Our derived key at m/86'/1'/0'/`chain`/`index` (testnet coin type).
    fn our_key(keys: &KeyManager, chain: u32, index: u32) -> (XOnlyPublicKey, DerivationPath) {
        let child = [
            ChildNumber::Normal { index: chain },
            ChildNumber::Normal { index },
        ];
        let secp = Secp256k1::new();
        let sk = keys.derive_btc_child(AccountType::Vanilla, &child).unwrap();
        let xonly = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0;
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            child[0],
            child[1],
        ]);
        (xonly, path)
    }

    /// Colored-account key at m/86'/827167'/0'/0/0 - ours, on the RGB account
    /// that `create_utxo` funds fresh allocation UTXOs on.
    fn our_colored_key(keys: &KeyManager) -> (XOnlyPublicKey, DerivationPath) {
        let child = [
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ];
        let secp = Secp256k1::new();
        let sk = keys.derive_btc_child(AccountType::Colored, &child).unwrap();
        let xonly = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0;
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(827167).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            child[0],
            child[1],
        ]);
        (xonly, path)
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

    /// A 2-of-3 taproot address containing `participant`: returns its
    /// `script_pubkey`, the leaf, its hash, and the internal (NUMS) key.
    fn multisig_address(
        participant: XOnlyPublicKey,
    ) -> (ScriptBuf, ScriptBuf, TapLeafHash, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let leaf = multi_a_2_of_3(&[participant, foreign_xonly(0xA1), foreign_xonly(0xA2)]);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let spk = ScriptBuf::new_p2tr(&secp, internal, info.merkle_root());
        (spk, leaf, leaf_hash, internal)
    }

    /// One-input, one-output PSBT. The input spends `input_spk`; the output
    /// pays `output_spk`. Output metadata is left empty for the caller to fill.
    fn psbt_with(input_spk: ScriptBuf, output_spk: ScriptBuf) -> Psbt {
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xAA; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: output_spk,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: input_spk,
        });
        psbt
    }

    /// Fully populate input 0 as a spendable-by-us 2-of-3 multisig input.
    fn make_input_ours(psbt: &mut Psbt, keys: &KeyManager) -> ScriptBuf {
        let secp = Secp256k1::new();
        let (our, path) = our_key(keys, 0, 0);
        let leaf = multi_a_2_of_3(&[our, foreign_xonly(0xA1), foreign_xonly(0xA2)]);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let spk = ScriptBuf::new_p2tr(&secp, internal, info.merkle_root());
        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();

        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: spk.clone(),
        });
        psbt.inputs[0].tap_internal_key = Some(internal);
        psbt.inputs[0]
            .tap_scripts
            .insert(control, (leaf, LeafVersion::TapScript));
        psbt.inputs[0]
            .tap_key_origins
            .insert(our, (vec![leaf_hash], (*keys.master_fingerprint(), path)));
        spk
    }

    fn owned(psbt: &Psbt, keys: &KeyManager) -> bool {
        let inputs = self_controlled_input_scripts(psbt, keys);
        output_is_self_owned(psbt, 0, &inputs)
    }

    // === Rule (A): repaying an input we co-control ===

    #[test]
    fn accepts_output_repaying_a_co_controlled_input() {
        let keys = km();
        let mut psbt = psbt_with(ScriptBuf::new(), ScriptBuf::new());
        let spk = make_input_ours(&mut psbt, &keys);
        // Pay straight back to the input's own script - no output metadata at all.
        psbt.unsigned_tx.output[0].script_pubkey = spk;
        assert!(owned(&psbt, &keys));
    }

    /// Rule (A) must key off inputs we can actually sign, not merely inputs
    /// present in the PSBT. An input whose leaf holds someone else's key
    /// produces no sign job, so repaying it proves nothing.
    #[test]
    fn rejects_output_repaying_an_input_we_do_not_control() {
        let keys = km();
        let (foreign_spk, _, _, _) = multisig_address(foreign_xonly(0xB1));
        let psbt = psbt_with(foreign_spk.clone(), foreign_spk);
        assert!(!owned(&psbt, &keys));
    }

    /// Rule (A) anchors on inputs we co-sign, and this path signs Vanilla only,
    /// so repaying a Colored input with no output metadata proves nothing. A
    /// Colored destination is fine, but must come via rule (B).
    #[test]
    fn rejects_bare_output_repaying_a_colored_input() {
        let keys = km();
        let secp = Secp256k1::new();
        let (colored, colored_path) = our_colored_key(&keys);
        let leaf = multi_a_2_of_3(&[colored, foreign_xonly(0xA1), foreign_xonly(0xA2)]);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let spk = ScriptBuf::new_p2tr(&secp, internal, info.merkle_root());
        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();

        let mut psbt = psbt_with(spk.clone(), spk);
        psbt.inputs[0].tap_internal_key = Some(internal);
        psbt.inputs[0]
            .tap_scripts
            .insert(control, (leaf, LeafVersion::TapScript));
        psbt.inputs[0].tap_key_origins.insert(
            colored,
            (vec![leaf_hash], (*keys.master_fingerprint(), colored_path)),
        );

        assert!(!owned(&psbt, &keys));
    }

    // === Rule (B) is gone: metadata is not a proof of control ===
    //
    // Shapes rule (B) accepted, now rejected. Not a loss of function: change
    // reuses the address, and `create_utxo` dust is bounded by value in
    // `btc_crosscheck`.

    /// The finding's shape: a leaf naming our key, in a tree we do not control.
    #[test]
    fn a_leaf_mentioning_our_key_is_not_ownership() {
        let keys = km();
        let (our, path) = our_key(&keys, 1, 7);
        let (spk, leaf, leaf_hash, internal) = multisig_address(our);

        let mut psbt = psbt_with(ScriptBuf::new(), spk);
        make_input_ours(&mut psbt, &keys);
        psbt.outputs[0].tap_internal_key = Some(internal);
        psbt.outputs[0].tap_tree = Some(
            TaprootBuilder::new()
                .add_leaf(0, leaf)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        psbt.outputs[0]
            .tap_key_origins
            .insert(our, (vec![leaf_hash], (*keys.master_fingerprint(), path)));

        assert!(
            !owned(&psbt, &keys),
            "a tap_tree leaf holding our key is not proof we control the output"
        );
    }

    /// Genuinely ours, but indistinguishable from a forged claim without
    /// trusting the metadata. Address reuse removes the need to.
    #[test]
    fn a_fresh_change_index_is_not_ownership() {
        let keys = km();
        let secp = Secp256k1::new();
        let (our, path) = our_key(&keys, 1, 3);
        let spk = ScriptBuf::new_p2tr(&secp, our, None);

        let mut psbt = psbt_with(ScriptBuf::new(), spk);
        make_input_ours(&mut psbt, &keys);
        psbt.outputs[0].tap_internal_key = Some(our);
        psbt.outputs[0]
            .tap_key_origins
            .insert(our, (vec![], (*keys.master_fingerprint(), path)));

        assert!(
            !owned(&psbt, &keys),
            "change must land on a script the transaction already spends"
        );
    }

    /// Non-taproot outputs can never be reconstructed from BIP-371 metadata, so
    /// they are only accepted via rule (A) - which a P2WPKH input can't satisfy
    /// either (the enclave co-controls taproot inputs only).
    #[test]
    fn rejects_non_taproot_output() {
        let keys = km();
        let p2wpkh = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xCC; 20]));
        let mut psbt = psbt_with(ScriptBuf::new(), p2wpkh);
        make_input_ours(&mut psbt, &keys);
        assert!(!owned(&psbt, &keys));
    }
}
