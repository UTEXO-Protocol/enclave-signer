//! Plain-BTC (`SignBtc`) signing cross-check.
//!
//! Authorization gate for the plain-BTC signing path: bridge ops with no RGB
//! consignment and no EVM correlation (`create_utxo`, plain BTC withdrawals).
//! A request type distinct from `SignPsbt` so plain-BTC ops cannot be reached
//! by omitting the bridge fields on a bridge request.
//!
//! Funds-safety is layered:
//!
//!   * Account scope, enforced in the signer, not here: the handler calls
//!     `sign_psbt_scoped(.., Some(Vanilla))`, so only Vanilla-account inputs
//!     are co-signed, never a Colored (RGB-allocated) one.
//!   * Output self-ownership ([`crate::networks::rgb::btc_ownership`]): every
//!     output must pay back to a script this enclave co-controls, proven from
//!     the PSBT and our own derivation. Either BIP-86 account counts, since
//!     `create_utxo` funds Colored UTXOs from vanilla inputs; the rule is
//!     about which inputs we spend. Replaces the `BTC_ALLOWED_SCRIPTS` allowlist,
//!     which was unbootstrappable in production.
//!   * Amount cap (`BTC_MAX_TOTAL_SATS`) on total input value spent, not
//!     output value, so it also bounds value routed to miner fees.
//!
//! Scope: this path is structurally self-pay. Withdrawals to an arbitrary user
//! address need a destination bound to verified evidence and remain out of
//! scope.
//!
//! Fail-closed posture: the output check needs no configuration and runs in
//! every build. The amount cap is operator-supplied, so a production
//! (`rgb-validation`) build refuses to sign while it is unset; default /
//! `cfg(test)` builds fall back to a permissive dev path. `dev-mode` skips this
//! function entirely. The witness_utxo requirement runs in all builds.

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::keys::KeyManager;
use crate::networks::rgb::btc_ownership::{output_is_self_owned, self_controlled_input_scripts};
use crate::proto::SignBtcRequest;

/// Validate a plain-BTC `SignBtcRequest` before signing: output self-ownership
/// plus the operator-pinned value-spent cap. Account scoping - never sign a
/// Colored input - is enforced separately in the signer; see the module docs.
///
/// Returns `Ok(())` when authorized, a `CrossCheck` error otherwise.
pub fn validate_btc_request(
    req: &SignBtcRequest,
    cfg: &BridgeConfig,
    keys: &KeyManager,
) -> Result<()> {
    // 0. Shape whitelist (shared with the bridge path).
    let psbt = crate::networks::rgb::psbt_validation::parse_psbt_shape(&req.psbt_bytes)?;

    // 1. Sum the value spent (for the cap). Every input must carry its
    //    witness_utxo; without it the value cannot be bounded.
    let mut total_in_sat: u64 = 0;
    for (i, input) in psbt.inputs.iter().enumerate() {
        let Some(witness_utxo) = input.witness_utxo.as_ref() else {
            return Err(EnclaveError::CrossCheck(format!(
                "plain-BTC input {i} is missing witness_utxo - cannot bound the value spent; \
                 refusing (the bridge populates witness_utxo on every segwit input it spends)"
            )));
        };
        total_in_sat = total_in_sat
            .checked_add(witness_utxo.value.to_sat())
            .ok_or_else(|| {
                EnclaveError::CrossCheck("plain-BTC total input value overflow".into())
            })?;
    }

    // 2. Reject an empty output set: all input value would go to fees, and the
    //    per-output check below would have nothing to inspect.
    if psbt.unsigned_tx.output.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "plain-BTC PSBT has no outputs - refusing (would route all input value to fees)".into(),
        ));
    }

    // 3. Output self-ownership: every output must pay back to a script this
    //    enclave co-controls. Needs no operator configuration, so it runs
    //    unconditionally. Anchored to the unsigned tx's outputs, which the
    //    segwit sighash commits to.
    let input_scripts = self_controlled_input_scripts(&psbt, keys);
    let mut unowned_sat: u64 = 0;
    for i in 0..psbt.unsigned_tx.output.len() {
        if output_is_self_owned(&psbt, i, &input_scripts) {
            continue;
        }
        unowned_sat = unowned_sat
            .checked_add(psbt.unsigned_tx.output[i].value.to_sat())
            .ok_or_else(|| {
                EnclaveError::CrossCheck("plain-BTC unowned output value overflow".into())
            })?;
    }

    if unowned_sat > 0 {
        if cfg.btc_max_unowned_sats == 0 {
            // Unset must never read as "no limit".
            #[cfg(all(feature = "rgb-validation", not(test)))]
            {
                return Err(EnclaveError::CrossCheck(format!(
                    "plain-BTC PSBT pays {unowned_sat} sats to outputs the enclave cannot prove \
                     pay back into the same custody, and BTC_MAX_UNOWNED_SATS is not pinned - \
                     refusing to sign"
                )));
            }
            #[cfg(not(all(feature = "rgb-validation", not(test))))]
            tracing::warn!(
                unowned_sat,
                "plain-BTC signing: no BTC_MAX_UNOWNED_SATS pinned (non-production build) - \
                 skipping the unowned-output budget"
            );
        } else if unowned_sat > cfg.btc_max_unowned_sats {
            return Err(EnclaveError::CrossCheck(format!(
                "plain-BTC PSBT pays {unowned_sat} sats to outputs the enclave cannot prove pay \
                 back into the same custody, over the pinned budget of {} sats - refusing to \
                 sign. `create_utxo` allocation dust fits this budget; a redirect does not. An \
                 output is proven when its script equals that of an input this enclave co-signs, \
                 which is what address reuse guarantees for change.",
                cfg.btc_max_unowned_sats
            )));
        }
    }

    // 4. Amount cap on value spent (sum of input values), which also bounds
    //    value routed to fees. Operator-supplied, so this dimension keeps the
    //    production fail-closed / dev-fallback split.
    if cfg.btc_max_total_sats == 0 {
        // Production must not sign plain BTC without the cap: nothing else
        // bounds what a host can route to miner fees.
        #[cfg(all(feature = "rgb-validation", not(test)))]
        {
            return Err(EnclaveError::CrossCheck(
                "plain-BTC signing requires BTC_MAX_TOTAL_SATS to be pinned - refusing to sign \
                 without a bound on the value a single plain-BTC transaction can spend"
                    .into(),
            ));
        }
        // Default / test builds: no cap to enforce. Dev path only.
        #[cfg(not(all(feature = "rgb-validation", not(test))))]
        {
            tracing::warn!(
                "plain-BTC signing: no BTC_MAX_TOTAL_SATS pinned (non-production build) - \
                 skipping the value-spent cap"
            );
            return Ok(());
        }
    }

    if total_in_sat > cfg.btc_max_total_sats {
        return Err(EnclaveError::CrossCheck(format!(
            "plain-BTC total input value {total_in_sat} sats exceeds pinned cap {} sats",
            cfg.btc_max_total_sats
        )));
    }

    Ok(())
}

/// Bound the Bitcoin value a send-RGB PSBT moves to destinations this enclave
/// cannot prove it controls.
///
/// Every other send-RGB bind is denominated in RGB asset units, so a witness tx
/// can satisfy the ledger exactly and still sweep the bridge's Bitcoin backing.
/// `check_psbt_fee_rate` misses it: a diverted sat is an output, not a fee, so
/// diversion *lowers* the implied rate.
///
/// Plain-BTC requires every output to be self-owned; send-RGB cannot, because
/// it pays the recipient a witness output and that seal is blinded. It bounds
/// the total instead - dust fits, a sweep does not.
///
/// Ownership is the single rule in [`super::btc_ownership`]: no metadata is
/// trusted.
pub fn validate_rgb_psbt_sats(
    psbt: &bitcoin::psbt::Psbt,
    cfg: &BridgeConfig,
    keys: &KeyManager,
) -> Result<()> {
    // `None` scope: change sits on Colored, vanilla funding on Vanilla. Widens
    // what counts as ours, never what is signed.
    let input_scripts =
        crate::networks::rgb::btc_ownership::self_controlled_input_scripts_scoped(psbt, keys, None);

    let mut unowned_sat: u64 = 0;
    for (i, txout) in psbt.unsigned_tx.output.iter().enumerate() {
        if input_scripts.contains(txout.script_pubkey.as_bytes()) {
            continue;
        }
        unowned_sat = unowned_sat
            .checked_add(txout.value.to_sat())
            .ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "send-RGB unowned output value overflow at output {i}"
                ))
            })?;
    }

    if cfg.rgb_max_unowned_sats == 0 {
        // Unset must never read as "no limit".
        #[cfg(all(feature = "rgb-validation", not(test)))]
        {
            return Err(EnclaveError::CrossCheck(
                "send-RGB signing requires RGB_MAX_UNOWNED_SATS to be pinned - refusing to \
                 sign without a bound on the Bitcoin value payable to destinations the \
                 enclave cannot prove it controls"
                    .into(),
            ));
        }
        #[cfg(not(all(feature = "rgb-validation", not(test))))]
        {
            tracing::warn!(
                unowned_sat,
                "send-RGB signing: no RGB_MAX_UNOWNED_SATS pinned (non-production build) - \
                 skipping the unowned-output budget"
            );
            return Ok(());
        }
    }

    if unowned_sat > cfg.rgb_max_unowned_sats {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB PSBT pays {unowned_sat} sats to outputs this enclave cannot prove it \
             controls, over the pinned budget of {} sats - refusing to sign (a \
             recipient witness output is dust; this is the Bitcoin backing leaving \
             the bridge)",
            cfg.rgb_max_unowned_sats
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{ChildNumber, DerivationPath};
    use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
    use bitcoin::blockdata::script::Builder as ScriptBuilder;
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
    use bitcoin::{
        Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        WPubkeyHash, Witness, XOnlyPublicKey,
    };

    use crate::keys::AccountType;

    /// NUMS internal key - unspendable key-path, as the bridge's taproot
    /// multisig addresses use.
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

    /// The enclave's own 2-of-3 taproot address at m/86'/1'/0'/0/0, plus the
    /// leaf, control block, and key origin an input needs to be recognised as
    /// co-controlled.
    struct OurAddress {
        spk: ScriptBuf,
        leaf: ScriptBuf,
        leaf_hash: TapLeafHash,
        internal: XOnlyPublicKey,
        control: bitcoin::taproot::ControlBlock,
        xonly: XOnlyPublicKey,
        path: DerivationPath,
    }

    fn our_address(keys: &KeyManager) -> OurAddress {
        let secp = Secp256k1::new();
        let child = [
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ];
        let sk = keys.derive_btc_child(AccountType::Vanilla, &child).unwrap();
        let xonly = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0;
        let leaf = multi_a_2_of_3(&[xonly, foreign_xonly(0xA1), foreign_xonly(0xA2)]);
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        OurAddress {
            spk: ScriptBuf::new_p2tr(&secp, internal, info.merkle_root()),
            control: info
                .control_block(&(leaf.clone(), LeafVersion::TapScript))
                .unwrap(),
            leaf,
            leaf_hash,
            internal,
            xonly,
            path: DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(86).unwrap(),
                ChildNumber::from_hardened_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                child[0],
                child[1],
            ]),
        }
    }

    /// A taproot address the enclave has nothing to do with.
    fn foreign_address() -> ScriptBuf {
        let secp = Secp256k1::new();
        let leaf = multi_a_2_of_3(&[
            foreign_xonly(0xB1),
            foreign_xonly(0xB2),
            foreign_xonly(0xB3),
        ]);
        let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf)
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        ScriptBuf::new_p2tr(&secp, internal, info.merkle_root())
    }

    /// Plain-BTC PSBT spending `input_sats` per input from the enclave's own
    /// address, paying `outputs`. Inputs carry full taproot metadata, so rule
    /// (A) recognises any output paying back to that address.
    fn psbt_from_our_address(
        keys: &KeyManager,
        inputs: &[u64],
        outputs: &[(ScriptBuf, u64)],
    ) -> Vec<u8> {
        psbt_inner(keys, inputs, outputs, true)
    }

    /// Like [`psbt_from_our_address`] but leaves witness_utxo unset (for the
    /// missing-witness_utxo guard test).
    fn psbt_without_witness_utxo(
        keys: &KeyManager,
        inputs: &[u64],
        outputs: &[(ScriptBuf, u64)],
    ) -> Vec<u8> {
        psbt_inner(keys, inputs, outputs, false)
    }

    fn psbt_inner(
        keys: &KeyManager,
        inputs: &[u64],
        outputs: &[(ScriptBuf, u64)],
        set_witness_utxo: bool,
    ) -> Vec<u8> {
        let ours = our_address(keys);
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: (0..inputs.len().max(1))
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                            [i as u8; 32],
                        )),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .iter()
                .map(|(spk, sat)| TxOut {
                    value: Amount::from_sat(*sat),
                    script_pubkey: spk.clone(),
                })
                .collect(),
        };
        let mut p = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
        for (i, sat) in inputs.iter().enumerate() {
            if set_witness_utxo {
                p.inputs[i].witness_utxo = Some(TxOut {
                    value: Amount::from_sat(*sat),
                    script_pubkey: ours.spk.clone(),
                });
            }
            p.inputs[i].tap_internal_key = Some(ours.internal);
            p.inputs[i].tap_scripts.insert(
                ours.control.clone(),
                (ours.leaf.clone(), LeafVersion::TapScript),
            );
            p.inputs[i].tap_key_origins.insert(
                ours.xonly,
                (
                    vec![ours.leaf_hash],
                    (*keys.master_fingerprint(), ours.path.clone()),
                ),
            );
        }
        p.serialize()
    }

    fn cfg_with_cap(cap: u64) -> BridgeConfig {
        BridgeConfig {
            btc_max_total_sats: cap,
            // Sized for `create_utxo` allocation dust (1000 sats x 5).
            btc_max_unowned_sats: 5_000,
            ..Default::default()
        }
    }

    /// Budget config for the send-RGB sats gate.
    fn rgb_cfg(budget: u64) -> BridgeConfig {
        BridgeConfig {
            rgb_max_unowned_sats: budget,
            ..Default::default()
        }
    }

    // --- send-RGB unowned-output budget (the BTC value-diversion PoC) ---

    /// **The attack.** Two 5_000_000-sat bridge UTXOs are spent. The RGB legs
    /// can be impeccable - recipient dust, change dust on a self-owned vout -
    /// while the whole residual goes to an attacker script on an output that
    /// carries no RGB assignment, so every asset-denominated bind ignores it.
    /// The budget is what sees it.
    #[test]
    fn rgb_sats_gate_rejects_a_treasury_sweep() {
        let keys = km();
        let ours = our_address(&keys);
        let psbt_bytes = psbt_from_our_address(
            &keys,
            &[5_000_000, 5_000_000],
            &[
                (foreign_address(), 546),       // recipient witness dust
                (ours.spk.clone(), 546),        // bridge change, self-owned
                (foreign_address(), 9_997_908), // the sweep
            ],
        );
        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).unwrap();
        let err = validate_rgb_psbt_sats(&psbt, &rgb_cfg(5_000), &keys).unwrap_err();
        assert!(
            err.to_string().contains("cannot prove it controls"),
            "got: {err}"
        );
    }

    /// The genuine shape still signs: recipient dust is well inside the budget
    /// and the bridge change pays back to an input script (rule (A)).
    #[test]
    fn rgb_sats_gate_accepts_recipient_dust_with_self_owned_change() {
        let keys = km();
        let ours = our_address(&keys);
        let psbt_bytes = psbt_from_our_address(
            &keys,
            &[5_000_000],
            &[(foreign_address(), 1_500), (ours.spk.clone(), 4_998_000)],
        );
        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).unwrap();
        assert!(validate_rgb_psbt_sats(&psbt, &rgb_cfg(5_000), &keys).is_ok());
    }

    /// The budget counts the whole unowned set, not the largest single output:
    /// splitting the sweep across many outputs must not slip under it.
    #[test]
    fn rgb_sats_gate_sums_unowned_outputs() {
        let keys = km();
        let outputs: Vec<_> = (0..6).map(|_| (foreign_address(), 1_000)).collect();
        let psbt_bytes = psbt_from_our_address(&keys, &[5_000_000], &outputs);
        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).unwrap();
        // 6 x 1_000 = 6_000 > 5_000, though every single output is under it.
        let err = validate_rgb_psbt_sats(&psbt, &rgb_cfg(5_000), &keys).unwrap_err();
        assert!(err.to_string().contains("6000 sats"), "got: {err}");
    }

    /// Rule (B) is not consulted: an output whose taproot tree merely mentions
    /// one of our keys is NOT proof of control (the bridge script is a multisig
    /// whose signer set the enclave does not know), so it counts against the
    /// budget like any other unowned script.
    #[test]
    fn rgb_sats_gate_does_not_trust_a_leaf_mentioning_our_key() {
        use bitcoin::psbt::Psbt;
        let keys = km();
        let ours = our_address(&keys);

        // A script the enclave does not co-control, but whose tree holds a leaf
        // naming our key alongside two attacker keys.
        let secp = Secp256k1::new();
        let leaf = multi_a_2_of_3(&[ours.xonly, foreign_xonly(0xC1), foreign_xonly(0xC2)]);
        let internal = foreign_xonly(0xC3);
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let spk = ScriptBuf::new_p2tr(&secp, internal, info.merkle_root());

        let psbt_bytes = psbt_from_our_address(&keys, &[5_000_000], &[(spk, 4_999_000)]);
        let mut psbt = Psbt::deserialize(&psbt_bytes).unwrap();
        // Full BIP-371 output metadata - exactly what rule (B) would have accepted.
        psbt.outputs[0].tap_internal_key = Some(internal);
        psbt.outputs[0].tap_tree = Some(
            TaprootBuilder::new()
                .add_leaf(0, leaf.clone())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        psbt.outputs[0].tap_key_origins.insert(
            ours.xonly,
            (
                vec![TapLeafHash::from_script(&leaf, LeafVersion::TapScript)],
                (*keys.master_fingerprint(), ours.path.clone()),
            ),
        );

        let err = validate_rgb_psbt_sats(&psbt, &rgb_cfg(5_000), &keys).unwrap_err();
        assert!(
            err.to_string().contains("cannot prove it controls"),
            "a leaf naming our key must not count as control; got: {err}"
        );
    }

    #[test]
    fn rejects_empty_psbt() {
        let keys = km();
        let req = SignBtcRequest { psbt_bytes: vec![] };
        let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
        assert!(err.to_string().contains("psbt_bytes is empty"));
    }

    // --- witness_utxo required (needed to bound value spent) ---

    #[test]
    fn rejects_missing_witness_utxo() {
        let keys = km();
        let ours = our_address(&keys);
        let req = SignBtcRequest {
            psbt_bytes: psbt_without_witness_utxo(&keys, &[50_000], &[(ours.spk, 40_000)]),
        };
        let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
        assert!(
            err.to_string().contains("missing witness_utxo"),
            "got: {err}"
        );
    }

    // --- Output self-ownership + value-spent cap ---

    #[test]
    fn accepts_self_paying_output_under_cap() {
        let keys = km();
        let ours = our_address(&keys);
        let req = SignBtcRequest {
            psbt_bytes: psbt_from_our_address(&keys, &[60_000], &[(ours.spk, 50_000)]),
        };
        assert!(validate_btc_request(&req, &cfg_with_cap(100_000), &keys).is_ok());
    }

    #[test]
    fn accepts_input_value_at_exact_cap() {
        let keys = km();
        let ours = our_address(&keys);
        let req = SignBtcRequest {
            // input value 100_000 == cap; output pays back to us
            psbt_bytes: psbt_from_our_address(&keys, &[100_000], &[(ours.spk, 99_000)]),
        };
        assert!(validate_btc_request(&req, &cfg_with_cap(100_000), &keys).is_ok());
    }

    #[test]
    fn rejects_output_the_enclave_does_not_control() {
        let keys = km();
        let req = SignBtcRequest {
            psbt_bytes: psbt_from_our_address(&keys, &[50_000], &[(foreign_address(), 10_000)]),
        };
        let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
        assert!(err.to_string().contains("same custody"), "got: {err}");
    }

    #[test]
    fn rejects_one_foreign_output_among_self_paying_ones() {
        let keys = km();
        let ours = our_address(&keys);
        let req = SignBtcRequest {
            psbt_bytes: psbt_from_our_address(
                &keys,
                &[50_000],
                &[(ours.spk, 10_000), (foreign_address(), 10_000)],
            ),
        };
        let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
        assert!(
            err.to_string().contains("10000 sats"),
            "only the foreign output counts against the budget; got: {err}"
        );
    }

    /// A non-taproot output can never be proven ours: the enclave co-controls
    /// taproot scripts only, and BIP-371 metadata cannot describe a P2WPKH.
    #[test]
    fn rejects_non_taproot_output() {
        let keys = km();
        let p2wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0xCC; 20]));
        let req = SignBtcRequest {
            psbt_bytes: psbt_from_our_address(&keys, &[50_000], &[(p2wpkh, 10_000)]),
        };
        assert!(validate_btc_request(&req, &cfg_with_cap(100_000), &keys).is_err());
    }

    #[test]
    fn rejects_empty_output_set() {
        let keys = km();
        let req = SignBtcRequest {
            psbt_bytes: psbt_from_our_address(&keys, &[50_000], &[]),
        };
        let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
        assert!(err.to_string().contains("no outputs"), "got: {err}");
    }

    #[test]
    fn rejects_input_value_over_cap() {
        let keys = km();
        let ours = our_address(&keys);
        let req = SignBtcRequest {
            // input value 100_001 > cap; output pays back to us (so we reach the cap)
            psbt_bytes: psbt_from_our_address(&keys, &[100_001], &[(ours.spk, 50_000)]),
        };
        let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
        assert!(err.to_string().contains("exceeds pinned cap"), "got: {err}");
    }

    #[test]
    fn rejects_summed_input_value_over_cap() {
        let keys = km();
        let ours = our_address(&keys);
        let req = SignBtcRequest {
            // two inputs, 70_000 + 50_000 = 120_000 > cap
            psbt_bytes: psbt_from_our_address(&keys, &[70_000, 50_000], &[(ours.spk, 100_000)]),
        };
        let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
        assert!(err.to_string().contains("exceeds pinned cap"), "got: {err}");
    }

    /// The self-pay rule needs no configuration, so an unset cap does not
    /// excuse a foreign output in any build profile.
    #[test]
    fn foreign_output_over_budget_is_rejected_whatever_the_value_cap_says() {
        let keys = km();
        let req = SignBtcRequest {
            psbt_bytes: psbt_from_our_address(&keys, &[100_000], &[(foreign_address(), 90_000)]),
        };
        // Well inside `btc_max_total_sats`, far outside the unowned budget.
        let err = validate_btc_request(&req, &cfg_with_cap(1_000_000), &keys).unwrap_err();
        assert!(err.to_string().contains("same custody"), "got: {err}");
    }

    /// The shape rule (B) used to wave through, now bounded by value: five
    /// 1000-sat colored allocations funded out of vanilla inputs, with the
    /// vanilla change returning to the script being spent (address reuse).
    #[test]
    fn create_utxo_allocation_dust_fits_the_budget() {
        let keys = km();
        let ours = our_address(&keys);
        let mut outputs: Vec<_> = (0..5).map(|_| (foreign_address(), 1_000)).collect();
        outputs.push((ours.spk.clone(), 40_000));
        let req = SignBtcRequest {
            psbt_bytes: psbt_from_our_address(&keys, &[50_000], &outputs),
        };
        assert!(validate_btc_request(&req, &cfg_with_cap(100_000), &keys).is_ok());
    }

    /// With the cap unset, a production build fails closed on the amount
    /// dimension; default / test builds fall back to the dev path (the
    /// structural guards above having already passed).
    #[test]
    fn unpinned_cap_behaviour_matches_build_profile() {
        let keys = km();
        let ours = our_address(&keys);
        let req = SignBtcRequest {
            psbt_bytes: psbt_from_our_address(&keys, &[1_000], &[(ours.spk, 900)]),
        };
        let result = validate_btc_request(&req, &BridgeConfig::default(), &keys);
        #[cfg(all(feature = "rgb-validation", not(test)))]
        assert!(result.is_err());
        // Unit tests are always cfg(test): the dev fallback returns Ok.
        #[cfg(not(all(feature = "rgb-validation", not(test))))]
        assert!(result.is_ok());
    }
}
