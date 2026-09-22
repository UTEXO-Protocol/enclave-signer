//! Proof that a plain-BTC PSBT output pays back to keys this enclave controls.
//!
//! Replaces the operator-pinned `BTC_ALLOWED_SCRIPTS` allowlist, which could
//! not work in production: the scripts to pin derive from a seed that only
//! exists after the enclave boots, and baking them into the image changes the
//! PCR0 identity that seed is bound to.
//!
//! An output is accepted on one rule: its `script_pubkey` equals that of an
//! input this enclave co-controls, as resolved by
//! [`find_controlled_taproot_leaves`](crate::networks::rgb::signing::taproot::find_controlled_taproot_leaves).
//! That leaf is control-block and derivation anchored, and the segwit sighash
//! commits to the script. Custody does not change when the PSBT merges one of
//! our signatures.
//!
//! A qualified script may have foreign spend paths. Outputs on it are exempt
//! only up to the input value on that script.
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

use std::collections::{HashMap, HashSet};

use bitcoin::psbt::Psbt;

use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::signing::taproot::find_controlled_taproot_leaves;

/// The `script_pubkey`s of every PSBT input this enclave provably co-controls
/// on the plain-BTC (Vanilla) account.
///
/// Membership comes from the custody resolver, so each entry carries the
/// full input-side anchor chain: control block verified against the input's own
/// output key, claimed key present in that leaf, and the claimed BIP-86
/// derivation actually producing it.
pub fn self_controlled_input_scripts(psbt: &Psbt, keys: &KeyManager) -> HashSet<Vec<u8>> {
    self_controlled_input_scripts_scoped(psbt, keys, Some(AccountType::Vanilla))
}

/// [`self_controlled_input_scripts`] with the account filter made explicit.
///
/// `allowed_account` is `Some(_)` for one BIP-86 account, `None` for either.
/// The plain-BTC path pins `Vanilla`; the send-RGB sats budget passes `None`,
/// and the asset change oracle pins `Colored`.
/// Widening the filter only widens which scripts count as ours, never what gets
/// signed - that is `sign_psbt_scoped`'s job.
pub fn self_controlled_input_scripts_scoped(
    psbt: &Psbt,
    keys: &KeyManager,
    allowed_account: Option<AccountType>,
) -> HashSet<Vec<u8>> {
    find_controlled_taproot_leaves(psbt, keys.master_fingerprint(), keys)
        .into_iter()
        .filter(|job| allowed_account.is_none_or(|want| job.account_type == want))
        .filter_map(|job| psbt.inputs.get(job.input_index))
        .filter_map(|input| input.witness_utxo.as_ref())
        .map(|utxo| utxo.script_pubkey.as_bytes().to_vec())
        .collect()
}

/// The Colored input script that can take bridge asset change. Empty unless the
/// PSBT spends exactly one. A qualified input can have foreign spend paths, so a
/// second Colored script makes custody ambiguous.
pub fn asset_change_scripts(psbt: &Psbt, keys: &KeyManager) -> HashSet<Vec<u8>> {
    let scripts = self_controlled_input_scripts_scoped(psbt, keys, Some(AccountType::Colored));
    if scripts.len() == 1 {
        scripts
    } else {
        HashSet::new()
    }
}

/// Indices of every PSBT output on an [`asset_change_scripts`] script.
///
/// The change-leg oracle for the send-RGB per-output amount bind:
/// a revealed RGB seal counts as bridge change only when the Bitcoin output it
/// names is one we control.
pub fn self_owned_output_indices(psbt: &Psbt, keys: &KeyManager) -> HashSet<u32> {
    let input_scripts = asset_change_scripts(psbt, keys);
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

/// Sats that the outputs pay outside the custody of the inputs. An output on a
/// script in `input_scripts` is exempt up to the input value on that script.
/// `None` on overflow.
pub fn unowned_output_sats(psbt: &Psbt, input_scripts: &HashSet<Vec<u8>>) -> Option<u64> {
    let mut room: HashMap<&[u8], u64> = HashMap::new();
    for utxo in psbt.inputs.iter().filter_map(|i| i.witness_utxo.as_ref()) {
        let spk = utxo.script_pubkey.as_bytes();
        if input_scripts.contains(spk) {
            let r = room.entry(spk).or_default();
            *r = r.checked_add(utxo.value.to_sat())?;
        }
    }
    let mut unowned: u64 = 0;
    for txout in &psbt.unsigned_tx.output {
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
pub(crate) mod tests {
    use super::*;
    use bitcoin::bip32::{ChildNumber, DerivationPath};
    use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
    use bitcoin::blockdata::script::Builder as ScriptBuilder;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::TapLeafHash;
    use bitcoin::taproot::{self, LeafVersion, TaprootBuilder};
    use bitcoin::ScriptBuf;
    use bitcoin::{
        Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        XOnlyPublicKey,
    };

    use crate::config::BridgeConfig;
    use crate::networks::rgb::btc_crosscheck::{validate_btc_request, validate_rgb_psbt_sats};
    use crate::networks::rgb::signing::taproot::{outstanding_job_inputs, sign_taproot_inputs};
    use crate::proto::SignBtcRequest;

    /// NUMS internal key - unspendable key-path, as the bridge's multisig
    /// addresses use.
    const NUMS_INTERNAL: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];

    pub(crate) fn km() -> KeyManager {
        KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap()
    }

    pub(crate) fn foreign_xonly(b: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[b; 32]).unwrap();
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0
    }

    /// Our derived key at m/86'/<coin>'/0'/`chain`/`index` on `account`
    /// (testnet coin types: 1 for Vanilla, 827167 for Colored).
    pub(crate) fn our_key_on(
        keys: &KeyManager,
        account: AccountType,
        chain: u32,
        index: u32,
    ) -> (XOnlyPublicKey, DerivationPath) {
        let child = [
            ChildNumber::Normal { index: chain },
            ChildNumber::Normal { index },
        ];
        let secp = Secp256k1::new();
        let sk = keys.derive_btc_child(account, &child).unwrap();
        let xonly = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0;
        let coin = match account {
            AccountType::Vanilla => 1,
            AccountType::Colored => 827167,
        };
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(coin).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            child[0],
            child[1],
        ]);
        (xonly, path)
    }

    /// Our derived key at m/86'/1'/0'/`chain`/`index` (testnet coin type).
    fn our_key(keys: &KeyManager, chain: u32, index: u32) -> (XOnlyPublicKey, DerivationPath) {
        our_key_on(keys, AccountType::Vanilla, chain, index)
    }

    /// Colored-account key at m/86'/827167'/0'/0/0 - ours, on the RGB account
    /// that `create_utxo` funds fresh allocation UTXOs on.
    fn our_colored_key(keys: &KeyManager) -> (XOnlyPublicKey, DerivationPath) {
        our_key_on(keys, AccountType::Colored, 0, 0)
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
    pub(crate) fn multisig_address(
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

    /// Unsigned PSBT with `n_inputs` distinct prevouts (no input metadata yet)
    /// and the given outputs. Output metadata is left empty for the caller.
    pub(crate) fn psbt_with_n(n_inputs: usize, outputs: &[(ScriptBuf, u64)]) -> Psbt {
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: (0..n_inputs)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([0xAA + i as u8; 32]),
                        vout: i as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .iter()
                .map(|(spk, value)| TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: spk.clone(),
                })
                .collect(),
        };
        Psbt::from_unsigned_tx(unsigned_tx).unwrap()
    }

    /// One-input, one-output PSBT. The input spends `input_spk`; the output
    /// pays `output_spk`. Output metadata is left empty for the caller to fill.
    fn psbt_with(input_spk: ScriptBuf, output_spk: ScriptBuf) -> Psbt {
        let mut psbt = psbt_with_n(1, &[(output_spk, 40_000)]);
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: input_spk,
        });
        psbt
    }

    /// Fully populate input `index` (worth `value` sats) as a 2-of-3 multisig
    /// input we co-sign with the key at `account`/`chain`/`child`.
    pub(crate) fn anchor_input(
        psbt: &mut Psbt,
        index: usize,
        keys: &KeyManager,
        account: AccountType,
        chain: u32,
        child: u32,
        value: u64,
    ) -> ScriptBuf {
        let secp = Secp256k1::new();
        let (our, path) = our_key_on(keys, account, chain, child);
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

        let input = &mut psbt.inputs[index];
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk.clone(),
        });
        input.tap_internal_key = Some(internal);
        input
            .tap_scripts
            .insert(control, (leaf, LeafVersion::TapScript));
        input
            .tap_key_origins
            .insert(our, (vec![leaf_hash], (*keys.master_fingerprint(), path)));
        spk
    }

    /// Fully populate input 0 as a spendable-by-us 2-of-3 multisig input.
    fn make_input_ours(psbt: &mut Psbt, keys: &KeyManager) -> ScriptBuf {
        anchor_input(psbt, 0, keys, AccountType::Vanilla, 0, 0, 50_000)
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

    /// A Colored input: `leaf` under `internal`, with our Colored key claimed
    /// in it. Returns its script and PSBT input.
    fn colored_input(
        keys: &KeyManager,
        leaf: ScriptBuf,
        internal: XOnlyPublicKey,
    ) -> (ScriptBuf, bitcoin::psbt::Input) {
        let secp = Secp256k1::new();
        let (our, path) = our_colored_key(keys);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let spk = ScriptBuf::new_p2tr(&secp, internal, info.merkle_root());
        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        let mut input = bitcoin::psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: spk.clone(),
            }),
            tap_internal_key: Some(internal),
            ..Default::default()
        };
        input
            .tap_scripts
            .insert(control, (leaf, LeafVersion::TapScript));
        input
            .tap_key_origins
            .insert(our, (vec![leaf_hash], (*keys.master_fingerprint(), path)));
        (spk, input)
    }

    /// The send-RGB change oracle: bridge asset change must not land on the
    /// script of an input that only names our key in one leaf.
    #[test]
    fn change_oracle_rejects_output_on_a_foreign_input_script() {
        let keys = km();
        let (our, _) = our_colored_key(&keys);

        // Input 0: the bridge 2-of-3 on the NUMS internal key.
        let bridge_leaf = multi_a_2_of_3(&[our, foreign_xonly(0xA1), foreign_xonly(0xA2)]);
        let nums = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let (bridge_spk, bridge) = colored_input(&keys, bridge_leaf, nums);
        let mut psbt = psbt_with(ScriptBuf::new(), bridge_spk);
        psbt.inputs[0] = bridge;
        assert!(self_owned_output_indices(&psbt, &keys).contains(&0));

        // Input 1: attacker-funded, internal key theirs, one leaf naming our key.
        let leaf = ScriptBuilder::new()
            .push_x_only_key(&our)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let (spk, input) = colored_input(&keys, leaf, foreign_xonly(0xB1));
        let mut txin = psbt.unsigned_tx.input[0].clone();
        txin.previous_output.vout = 1;
        psbt.unsigned_tx.input.push(txin);
        psbt.inputs.push(input);
        psbt.unsigned_tx.output[0].script_pubkey = spk;

        assert!(!self_owned_output_indices(&psbt, &keys).contains(&0));
    }

    // === custody must not depend on merge progress ===

    /// What the two sats gates and the ownership resolvers say about one PSBT.
    struct Gates {
        owned: HashSet<Vec<u8>>,
        indices: HashSet<u32>,
        rgb: Option<String>,
        btc: Option<String>,
    }

    /// Budgets pinned, so the permissive unset branch never applies; the
    /// plain-BTC gate only exists for the Vanilla account.
    fn gates(psbt: &Psbt, keys: &KeyManager, account: AccountType) -> Gates {
        let rgb_cfg = BridgeConfig {
            rgb_max_unowned_sats: 5_000,
            ..Default::default()
        };
        let btc_cfg = BridgeConfig {
            btc_max_total_sats: 1_000_000,
            btc_max_unowned_sats: 5_000,
            ..Default::default()
        };
        let req = SignBtcRequest {
            psbt_bytes: psbt.serialize(),
        };
        Gates {
            owned: self_controlled_input_scripts_scoped(psbt, keys, None),
            indices: self_owned_output_indices(psbt, keys),
            rgb: validate_rgb_psbt_sats(psbt, &rgb_cfg, keys)
                .err()
                .map(|e| e.to_string()),
            btc: (account == AccountType::Vanilla)
                .then(|| validate_btc_request(&req, &btc_cfg, keys).err())
                .flatten()
                .map(|e| e.to_string()),
        }
    }

    /// Check the entry under `key` on input `index` against that input's own
    /// script-spend sighash. Independent of the signer: rebuilds the message
    /// from the PSBT's transaction and prevouts.
    pub(crate) fn verify_own_signature(
        psbt: &Psbt,
        index: usize,
        key: (XOnlyPublicKey, TapLeafHash),
    ) -> Result<taproot::Signature, String> {
        let sig = *psbt.inputs[index]
            .tap_script_sigs
            .get(&key)
            .ok_or_else(|| format!("input {index}: no entry under our key"))?;
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .map(|i| i.witness_utxo.clone().unwrap())
            .collect();
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_script_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                key.1,
                TapSighashType::Default,
            )
            .unwrap();
        let msg = Message::from_digest(*sighash.as_byte_array());
        Secp256k1::verification_only()
            .verify_schnorr(&sig.signature, &msg, &key.0)
            .map_err(|e| format!("input {index}: {e}"))?;
        Ok(sig)
    }

    /// Sign input `index` with our one leaf there, as the enclave itself does,
    /// verify the signature independently, and return its map entry.
    pub(crate) fn merge_own_signature(
        psbt: &mut Psbt,
        keys: &KeyManager,
        index: usize,
    ) -> ((XOnlyPublicKey, TapLeafHash), taproot::Signature) {
        let jobs: Vec<_> = find_controlled_taproot_leaves(psbt, keys.master_fingerprint(), keys)
            .into_iter()
            .filter(|job| job.input_index == index)
            .collect();
        assert_eq!(jobs.len(), 1);
        assert!(psbt.inputs[index].tap_script_sigs.is_empty());
        assert_eq!(sign_taproot_inputs(psbt, keys, &jobs).unwrap(), 1);
        let key = (jobs[0].xonly_pubkey, jobs[0].leaf_hash);
        (key, verify_own_signature(psbt, index, key).unwrap())
    }

    struct MergeScenario {
        account: AccountType,
        a_spk: ScriptBuf,
        b_spk: ScriptBuf,
        before: Gates,
        after: Gates,
        jobs_after: Vec<usize>,
        tx_unchanged: bool,
        /// Second signing pass: signatures added, B's entry present, A's entry
        /// byte-identical to the one merged.
        second_pass: (usize, bool, bool),
        /// Why either surviving entry failed independent verification.
        unverified: Vec<String>,
    }

    /// Two eligible inputs A and B on `account`, change paying each script
    /// back plus a foreign dust output. Merge our own signature on A only,
    /// leaving B outstanding, and record every gate before and after. Never
    /// asserts on the finding itself so both accounts always run.
    fn merge_scenario(account: AccountType) -> MergeScenario {
        let keys = km();
        let (a_spk, _, _, _) = multisig_address(our_key_on(&keys, account, 0, 0).0);
        let (b_spk, _, _, _) = multisig_address(our_key_on(&keys, account, 0, 1).0);
        let (foreign, _, _, _) = multisig_address(foreign_xonly(0xB1));
        assert_ne!(a_spk, b_spk);
        let mut psbt = psbt_with_n(
            2,
            &[
                (a_spk.clone(), 90_000),
                (b_spk.clone(), 90_000),
                (foreign, 1_000),
            ],
        );
        assert_eq!(
            anchor_input(&mut psbt, 0, &keys, account, 0, 0, 100_000),
            a_spk
        );
        assert_eq!(
            anchor_input(&mut psbt, 1, &keys, account, 0, 1, 100_000),
            b_spk
        );

        let before = gates(&psbt, &keys, account);
        let tx_before = psbt.unsigned_tx.clone();
        let prevouts_before: Vec<_> = psbt.inputs.iter().map(|i| i.witness_utxo.clone()).collect();

        let (key_a, sig_a) = merge_own_signature(&mut psbt, &keys, 0);
        let jobs_after = outstanding_job_inputs(&psbt, &keys);
        let prevouts_after: Vec<_> = psbt.inputs.iter().map(|i| i.witness_utxo.clone()).collect();
        let tx_unchanged = psbt.unsigned_tx == tx_before && prevouts_after == prevouts_before;

        let after = gates(&psbt, &keys, account);

        let (bytes, signed) = keys
            .sign_psbt_scoped(&psbt.serialize(), Some(account))
            .unwrap();
        let signed_psbt = Psbt::deserialize(&bytes).unwrap();
        let second_pass = (
            signed,
            signed_psbt.inputs[1].tap_script_sigs.len() == 1,
            signed_psbt.inputs[0].tap_script_sigs.get(&key_a) == Some(&sig_a),
        );

        // A's merged entry and B's new one must both verify against their own
        // sighash of the very same transaction.
        let key_b = find_controlled_taproot_leaves(&signed_psbt, keys.master_fingerprint(), &keys)
            .into_iter()
            .find(|job| job.input_index == 1)
            .map(|job| (job.xonly_pubkey, job.leaf_hash));
        let unverified = [(0, Some(key_a)), (1, key_b)]
            .into_iter()
            .filter_map(|(index, key)| match key {
                Some(key) => verify_own_signature(&signed_psbt, index, key).err(),
                None => Some(format!("input {index}: no controlled leaf")),
            })
            .collect();

        MergeScenario {
            account,
            a_spk,
            b_spk,
            before,
            after,
            jobs_after,
            tx_unchanged,
            second_pass,
            unverified,
        }
    }

    /// Custody survives signature merging on both accounts.
    #[test]
    fn bfa_ownership_is_independent_of_merge_progress() {
        let mut failures = Vec::new();
        for s in [
            merge_scenario(AccountType::Vanilla),
            merge_scenario(AccountType::Colored),
        ] {
            let tag = format!("merge progress {:?}", s.account);
            // Sanity: the unsigned control passes, only B is outstanding, and
            // nothing else changed.
            let both = HashSet::from([s.a_spk.to_bytes(), s.b_spk.to_bytes()]);
            assert_eq!(s.before.owned, both, "{tag}: owned before");
            // No asset change either way: the Vanilla run spends no Colored
            // input, and the Colored run spends two Colored scripts, which the
            // bounded-change rule refuses. What this test pins is that the set
            // does not move when a signature merges; a non-empty change leg
            // under merge is covered by
            // `psbt_validation::tests::anchor::change_leg_survives_merging_our_own_signature`.
            assert_eq!(s.before.indices, HashSet::new(), "{tag}: indices before");
            assert_eq!(s.before.rgb, None, "{tag}: send-RGB gate before");
            assert_eq!(s.before.btc, None, "{tag}: plain-BTC gate before");
            assert_eq!(s.jobs_after, vec![1], "{tag}: only B outstanding");
            assert!(s.tx_unchanged, "{tag}: tx or prevouts changed");

            // Custody must survive merging A's signature.
            if let Some(err) = &s.after.rgb {
                failures.push(format!("{tag}: send-RGB gate after merging A: {err}"));
            }
            if let Some(err) = &s.after.btc {
                failures.push(format!("{tag}: plain-BTC gate after merging A: {err}"));
            }
            if s.after.owned != both {
                failures.push(format!(
                    "{tag}: owned scripts after merging A: {} of 2",
                    s.after.owned.len()
                ));
            }
            if s.after.indices != s.before.indices {
                failures.push(format!(
                    "{tag}: owned outputs after merging A: {:?}",
                    s.after.indices
                ));
            }
            if s.second_pass != (1, true, true) {
                failures.push(format!(
                    "{tag}: second pass (signed, B present, A intact): {:?}",
                    s.second_pass
                ));
            }
            for err in &s.unverified {
                failures.push(format!("{tag}: signature invalid after second pass: {err}"));
            }
        }
        assert!(
            failures.is_empty(),
            "custody depends on merge progress:\n{}",
            failures.join("\n")
        );
    }

    /// Custody is a function of the PSBT structure alone, checked over every
    /// signature subset on three mixed inputs. Only the remaining work moves
    /// as entries merge.
    #[test]
    fn custody_is_invariant_under_every_signature_subset() {
        let keys = km();
        let inputs = [
            (AccountType::Vanilla, 0u32, 0u32),
            (AccountType::Vanilla, 0, 1),
            (AccountType::Colored, 0, 0),
        ];
        let spks: Vec<ScriptBuf> = inputs
            .iter()
            .map(|&(a, c, i)| multisig_address(our_key_on(&keys, a, c, i).0).0)
            .collect();
        let (foreign, _, _, _) = multisig_address(foreign_xonly(0xB1));
        let mut outputs: Vec<(ScriptBuf, u64)> =
            spks.iter().map(|spk| (spk.clone(), 90_000)).collect();
        outputs.push((foreign, 1_000));

        let mut unsigned = psbt_with_n(inputs.len(), &outputs);
        for (idx, &(a, c, i)) in inputs.iter().enumerate() {
            assert_eq!(
                anchor_input(&mut unsigned, idx, &keys, a, c, i, 100_000),
                spks[idx]
            );
        }

        let owned_all = self_controlled_input_scripts_scoped(&unsigned, &keys, None);
        let owned_vanilla =
            self_controlled_input_scripts_scoped(&unsigned, &keys, Some(AccountType::Vanilla));
        let indices = self_owned_output_indices(&unsigned, &keys);
        let txid = unsigned.unsigned_tx.compute_txid();
        assert_eq!(owned_all.len(), 3);
        assert_eq!(owned_vanilla.len(), 2);
        // Only output 2 sits on the single Colored input script; asset change
        // is bounded to that script, so the Vanilla outputs are not change.
        assert_eq!(indices, HashSet::from([2]));

        // Sign every input once, then replay each subset of those entries.
        let mut signed = unsigned.clone();
        let jobs = find_controlled_taproot_leaves(&signed, keys.master_fingerprint(), &keys);
        assert_eq!(jobs.len(), inputs.len());
        assert_eq!(sign_taproot_inputs(&mut signed, &keys, &jobs).unwrap(), 3);

        for mask in 0..(1 << inputs.len()) {
            let mut psbt = unsigned.clone();
            for idx in 0..inputs.len() {
                if mask & (1 << idx) != 0 {
                    psbt.inputs[idx].tap_script_sigs = signed.inputs[idx].tap_script_sigs.clone();
                }
            }

            assert_eq!(
                self_controlled_input_scripts_scoped(&psbt, &keys, None),
                owned_all,
                "subset {mask:03b}: controlled scripts moved"
            );
            assert_eq!(
                self_controlled_input_scripts_scoped(&psbt, &keys, Some(AccountType::Vanilla)),
                owned_vanilla,
                "subset {mask:03b}: Vanilla-scoped scripts moved"
            );
            assert_eq!(
                self_owned_output_indices(&psbt, &keys),
                indices,
                "subset {mask:03b}: owned outputs moved"
            );
            assert_eq!(psbt.unsigned_tx.compute_txid(), txid);

            let remaining = outstanding_job_inputs(&psbt, &keys);
            let outstanding: Vec<usize> = (0..inputs.len())
                .filter(|idx| mask & (1 << idx) == 0)
                .collect();
            assert_eq!(remaining, outstanding, "subset {mask:03b}: wrong work left");
        }
    }
}
