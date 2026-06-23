//! Plain-BTC (`SignBtc`) signing cross-check.
//!
//! This is the authorization gate for the *plain-BTC* signing path — the ops
//! the bridge legitimately performs that carry no RGB consignment and no EVM
//! correlation (e.g. `create_utxo` UTXO management, plain BTC withdrawals).
//! It exists as a request type distinct from `SignPsbt` (the bridge/RGB-send
//! path) precisely so plain-BTC ops can no longer be reached by *omitting*
//! the bridge fields on a bridge request — the M-01/#69 anti-pattern.
//!
//! Funds-safety on this path is layered:
//!
//!   * **Account scope (enforced in the signer, not here):** the handler signs
//!     a plain-BTC PSBT via `EnclaveState::sign_psbt_scoped(.., Some(Vanilla))`,
//!     so the enclave will only co-sign inputs that resolve to the **Vanilla**
//!     (plain-BTC) BIP-86 account and never a **Colored** (RGB-allocated) input.
//!     Plain-BTC ops (`create_utxo`, `sendBtc`) spend only vanilla-account
//!     UTXOs, while RGB-allocated value lives in the colored account and moves
//!     only via the consignment-bound `SignPsbt` path. That scoping is what
//!     keeps the M-01 fix from being reopened on this sibling path; this
//!     validator adds the operator-pinned destination + amount policy on top:
//!   * **Output allowlist** (`BTC_ALLOWED_SCRIPTS`): every output's
//!     `script_pubkey` must be one the operator pinned (e.g. the bridge's own
//!     change / UTXO-management scripts). A listener cannot redirect funds to
//!     an address the operator did not pre-authorize.
//!   * **Amount cap** (`BTC_MAX_TOTAL_SATS`): the **total input value spent**
//!     must not exceed the pinned cap. Capping *value spent* (not output value)
//!     bounds the real blast radius — including value routed to miner fees — so
//!     a host can't burn bridge funds by under-paying the outputs.
//!
//! Scope note: a *static* pinned allowlist cannot express a withdrawal to an
//! arbitrary user address (`sendBtc`); this path serves self-pay / UTXO-
//! management (`create_utxo`) where destinations are bridge-controlled and
//! pinnable. Dynamic-destination withdrawals are out of scope for #69.
//!
//! Fail-closed posture (mirrors `evm_crosscheck`): a production build
//! (`rgb-validation`) refuses to sign on this path when the allowlist/cap are
//! unconfigured. Default / `cfg(test)` builds, which are never production
//! (production is `--features vsock,rgb-validation,spv`), fall back to a
//! permissive dev path when nothing is pinned so local tooling keeps working.
//! `dev-mode` skips this function entirely (the handler is
//! `cfg(not(dev-mode))`). The witness_utxo requirement below runs in ALL builds
//! (it is needed to bound value, not a tunable policy).

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::proto::SignBtcRequest;

/// Validate a plain-BTC `SignBtcRequest` before signing: the operator-pinned
/// output allowlist + value-spent cap. (Account scoping — never sign a Colored
/// input — is enforced separately in the signer; see the module docs.) Returns
/// `Ok(())` when authorized, a `CrossCheck` error otherwise.
pub fn validate_btc_request(req: &SignBtcRequest, cfg: &BridgeConfig) -> Result<()> {
    // 0. Shape whitelist (shared with the bridge path).
    let psbt = crate::networks::rgb::psbt_validation::parse_psbt_shape(&req.psbt_bytes)?;

    // 1. Sum the value spent (for the cap). Every input must carry its
    //    witness_utxo — the bridge populates it on every segwit input it spends,
    //    and without it we cannot bound the value, so refuse fail-closed.
    let mut total_in_sat: u64 = 0;
    for (i, input) in psbt.inputs.iter().enumerate() {
        let Some(witness_utxo) = input.witness_utxo.as_ref() else {
            return Err(EnclaveError::CrossCheck(format!(
                "plain-BTC input {i} is missing witness_utxo — cannot bound the value spent; \
                 refusing (the bridge populates witness_utxo on every segwit input it spends)"
            )));
        };
        total_in_sat = total_in_sat
            .checked_add(witness_utxo.value.to_sat())
            .ok_or_else(|| {
                EnclaveError::CrossCheck("plain-BTC total input value overflow".into())
            })?;
    }

    // 2. A usable pin requires BOTH an allowlist and a cap. A half-pin is
    //    treated as unconfigured (fail-closed in production) rather than
    //    enforcing one dimension while silently ignoring the other.
    let pinned = !cfg.btc_allowed_scripts.is_empty() && cfg.btc_max_total_sats != 0;

    if !pinned {
        // Production (rgb-validation, not test) must not sign plain BTC without
        // an enclave-verifiable policy — otherwise a misprovisioned-but-running
        // enclave silently degrades to "sign any output the host asks for".
        #[cfg(all(feature = "rgb-validation", not(test)))]
        {
            return Err(EnclaveError::CrossCheck(
                "plain-BTC signing requires BTC_ALLOWED_SCRIPTS and BTC_MAX_TOTAL_SATS to be \
                 pinned — refusing to sign without an enclave-verifiable output allowlist + \
                 amount cap"
                    .into(),
            ));
        }
        // Default / test builds: nothing pinned, no operator policy to enforce
        // (the input guard above still ran). Dev path only.
        #[cfg(not(all(feature = "rgb-validation", not(test))))]
        {
            tracing::warn!(
                "plain-BTC signing: no BTC_ALLOWED_SCRIPTS / BTC_MAX_TOTAL_SATS pinned \
                 (non-production build) — skipping output/amount policy"
            );
            return Ok(());
        }
    }

    // 3. Reject an empty output set — every input value would go to fees, which
    //    the output allowlist would not catch. The cap below bounds value spent,
    //    but a no-output PSBT is never a legitimate plain-BTC op.
    if psbt.unsigned_tx.output.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "plain-BTC PSBT has no outputs — refusing (would route all input value to fees)".into(),
        ));
    }

    // 4. Output allowlist. Authorization is anchored to the unsigned tx's
    //    outputs, which the segwit sighash commits to — the same bytes the
    //    signature will cover.
    for (i, out) in psbt.unsigned_tx.output.iter().enumerate() {
        let spk = out.script_pubkey.as_bytes();
        let allowed = cfg
            .btc_allowed_scripts
            .iter()
            .any(|allowed_spk| allowed_spk.as_slice() == spk);
        if !allowed {
            return Err(EnclaveError::CrossCheck(format!(
                "plain-BTC output {i} pays a non-allowlisted script_pubkey ({}) — refusing to \
                 sign toward a destination the operator did not pin",
                hex::encode(spk)
            )));
        }
    }

    // 5. Amount cap on VALUE SPENT (sum of input values), bounding the blast
    //    radius including any value routed to fees.
    if total_in_sat > cfg.btc_max_total_sats {
        return Err(EnclaveError::CrossCheck(format!(
            "plain-BTC total input value {total_in_sat} sats exceeds pinned cap {} sats",
            cfg.btc_max_total_sats
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::Psbt;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash, Witness,
    };

    /// A P2WPKH script_pubkey seeded deterministically — a NON-P2WSH script,
    /// stands in for a bridge-controlled plain output/input script.
    fn script_for(seed: u8) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20]))
    }

    /// Build a PSBT from `inputs` (witness_utxo script + value sats, per input)
    /// and `outputs` (script + value sats). Every input gets its witness_utxo
    /// populated so the validator can classify and value it.
    fn psbt(inputs: &[(ScriptBuf, u64)], outputs: &[(ScriptBuf, u64)]) -> Vec<u8> {
        psbt_inner(inputs, outputs, true)
    }

    /// Like [`psbt`] but leaves witness_utxo unset on every input (for the
    /// missing-witness_utxo guard test).
    fn psbt_without_witness_utxo(
        inputs: &[(ScriptBuf, u64)],
        outputs: &[(ScriptBuf, u64)],
    ) -> Vec<u8> {
        psbt_inner(inputs, outputs, false)
    }

    fn psbt_inner(
        inputs: &[(ScriptBuf, u64)],
        outputs: &[(ScriptBuf, u64)],
        set_witness_utxo: bool,
    ) -> Vec<u8> {
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
        if set_witness_utxo {
            for (i, (spk, sat)) in inputs.iter().enumerate() {
                p.inputs[i].witness_utxo = Some(TxOut {
                    value: Amount::from_sat(*sat),
                    script_pubkey: spk.clone(),
                });
            }
        }
        p.serialize()
    }

    fn cfg_pinned(allowed: &[ScriptBuf], cap: u64) -> BridgeConfig {
        BridgeConfig {
            btc_allowed_scripts: allowed.iter().map(|s| s.as_bytes().to_vec()).collect(),
            btc_max_total_sats: cap,
            ..Default::default()
        }
    }

    #[test]
    fn rejects_empty_psbt() {
        let cfg = cfg_pinned(&[script_for(0x11)], 100_000);
        let req = SignBtcRequest { psbt_bytes: vec![] };
        let err = validate_btc_request(&req, &cfg).unwrap_err();
        assert!(err.to_string().contains("psbt_bytes is empty"));
    }

    // --- witness_utxo required (needed to bound value spent) ---

    #[test]
    fn rejects_missing_witness_utxo() {
        let allowed = script_for(0x11);
        let cfg = cfg_pinned(std::slice::from_ref(&allowed), 100_000);
        let req = SignBtcRequest {
            psbt_bytes: psbt_without_witness_utxo(
                &[(script_for(0x11), 50_000)],
                &[(allowed, 40_000)],
            ),
        };
        let err = validate_btc_request(&req, &cfg).unwrap_err();
        assert!(
            err.to_string().contains("missing witness_utxo"),
            "got: {err}"
        );
    }

    // --- Output allowlist + value-spent cap (pinned policy) ---

    #[test]
    fn accepts_allowlisted_output_under_cap() {
        let allowed = script_for(0x11);
        let cfg = cfg_pinned(std::slice::from_ref(&allowed), 100_000);
        let req = SignBtcRequest {
            psbt_bytes: psbt(&[(script_for(0x11), 60_000)], &[(allowed, 50_000)]),
        };
        assert!(validate_btc_request(&req, &cfg).is_ok());
    }

    #[test]
    fn accepts_input_value_at_exact_cap() {
        let allowed = script_for(0x11);
        let cfg = cfg_pinned(std::slice::from_ref(&allowed), 100_000);
        let req = SignBtcRequest {
            // input value 100_000 == cap; outputs allowlisted
            psbt_bytes: psbt(&[(script_for(0x11), 100_000)], &[(allowed, 99_000)]),
        };
        assert!(validate_btc_request(&req, &cfg).is_ok());
    }

    #[test]
    fn rejects_output_not_in_allowlist() {
        let allowed = script_for(0x11);
        let cfg = cfg_pinned(&[allowed], 100_000);
        let req = SignBtcRequest {
            // input fine, but pays 0x99 which is not pinned
            psbt_bytes: psbt(&[(script_for(0x11), 50_000)], &[(script_for(0x99), 10_000)]),
        };
        let err = validate_btc_request(&req, &cfg).unwrap_err();
        assert!(
            err.to_string().contains("non-allowlisted script_pubkey"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_one_bad_output_among_allowed() {
        let a = script_for(0x11);
        let cfg = cfg_pinned(std::slice::from_ref(&a), 100_000);
        let req = SignBtcRequest {
            psbt_bytes: psbt(
                &[(script_for(0x11), 50_000)],
                &[(a, 10_000), (script_for(0x99), 10_000)],
            ),
        };
        let err = validate_btc_request(&req, &cfg).unwrap_err();
        assert!(err.to_string().contains("non-allowlisted"), "got: {err}");
    }

    #[test]
    fn rejects_empty_output_set() {
        let allowed = script_for(0x11);
        let cfg = cfg_pinned(std::slice::from_ref(&allowed), 100_000);
        let req = SignBtcRequest {
            psbt_bytes: psbt(&[(script_for(0x11), 50_000)], &[]),
        };
        let err = validate_btc_request(&req, &cfg).unwrap_err();
        assert!(err.to_string().contains("no outputs"), "got: {err}");
    }

    #[test]
    fn rejects_input_value_over_cap() {
        let allowed = script_for(0x11);
        let cfg = cfg_pinned(std::slice::from_ref(&allowed), 100_000);
        let req = SignBtcRequest {
            // input value 100_001 > cap; output allowlisted (so we reach the cap)
            psbt_bytes: psbt(&[(script_for(0x11), 100_001)], &[(allowed, 50_000)]),
        };
        let err = validate_btc_request(&req, &cfg).unwrap_err();
        assert!(err.to_string().contains("exceeds pinned cap"), "got: {err}");
    }

    #[test]
    fn rejects_summed_input_value_over_cap() {
        let allowed = script_for(0x11);
        let cfg = cfg_pinned(std::slice::from_ref(&allowed), 100_000);
        let req = SignBtcRequest {
            // two inputs, 70_000 + 50_000 = 120_000 > cap
            psbt_bytes: psbt(
                &[(script_for(0x11), 70_000), (script_for(0x11), 50_000)],
                &[(allowed, 100_000)],
            ),
        };
        let err = validate_btc_request(&req, &cfg).unwrap_err();
        assert!(err.to_string().contains("exceeds pinned cap"), "got: {err}");
    }

    /// In a production build, an unpinned policy fails closed (after the input
    /// guard passes). In default / test builds it falls back to the dev path.
    #[test]
    fn unpinned_policy_behaviour_matches_build_profile() {
        let cfg = BridgeConfig::default(); // nothing pinned
        let req = SignBtcRequest {
            psbt_bytes: psbt(&[(script_for(0x11), 1_000)], &[(script_for(0x99), 900)]),
        };
        let result = validate_btc_request(&req, &cfg);
        #[cfg(all(feature = "rgb-validation", not(test)))]
        assert!(result.is_err());
        // Unit tests are always cfg(test): the dev fallback returns Ok.
        #[cfg(not(all(feature = "rgb-validation", not(test))))]
        assert!(result.is_ok());
    }

    /// A half-pin (allowlist but no cap, or vice-versa) is treated as
    /// unconfigured — never "enforce one dimension, ignore the other".
    #[test]
    fn half_pin_is_treated_as_unconfigured() {
        let allowed = script_for(0x11);
        // allowlist set, cap == 0 (unset)
        let cfg = cfg_pinned(std::slice::from_ref(&allowed), 0);
        let req = SignBtcRequest {
            psbt_bytes: psbt(&[(script_for(0x11), 50_000)], &[(allowed, 40_000)]),
        };
        // In test builds the unconfigured path returns Ok (dev fallback);
        // the point of the test is that it does NOT enforce the partial pin.
        assert!(validate_btc_request(&req, &cfg).is_ok());
    }
}
