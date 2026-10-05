//! Plain-BTC (`SignBtc`) signing cross-check.
//!
//! Authorization gate for plain-BTC bridge ops: no RGB consignment and no EVM
//! correlation (`create_utxo`, plain BTC withdrawals). It is a separate request
//! type from `Sign` with an RGB destination. A request without bridge fields cannot
//! reach this path.
//!
//! Funds-safety layers:
//!
//!   * Account scope, in the signer: the handler calls
//!     `sign_psbt_scoped(.., Some(Vanilla))`. Only Vanilla inputs are
//!     co-signed, never a Colored (RGB-allocated) one.
//!   * Output self-ownership ([`crate::networks::rgb::btc_ownership`]): outputs
//!     must pay back to a script this enclave co-controls, proven from the PSBT
//!     and our own derivation. Unproven outputs must fit the pinned
//!     `BTC_MAX_UNOWNED_SATS` budget. Both BIP-86 accounts count, because
//!     `create_utxo` funds Colored UTXOs from vanilla inputs.
//!   * Fee policy ([`crate::networks::rgb::psbt_validation::check_psbt_fee`]):
//!     the pinned maximum fee rate and absolute fee of the send-RGB path. All
//!     checks here bound one transaction only. Nothing here rate-limits
//!     `SignBtc`, so the aggregate bound is outside the enclave. Every input
//!     must be sizeable: a P2TR input with no Taproot spend metadata or a
//!     non-CHECKMULTISIG P2WSH input fails the whole request.
//!   * Amount cap (`BTC_MAX_TOTAL_SATS`) on total input value, not output
//!     value, so it also bounds value sent to miner fees.
//!
//! This path can fund enclave outputs or unproven outputs within the configured
//! budget. It does not verify bridge evidence for a withdrawal recipient.
//!
//! Fail-closed: the fee policy and the witness_utxo rule need no config and run
//! in every build. The amount cap and the unowned budget are operator values.
//! Non-test `rgb-validation` builds require a non-zero total-input cap.
//! A zero unowned-output budget rejects unproven outputs but permits self-pay.
//! Unit tests and builds without `rgb-validation` skip these unset-budget checks.

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::btc_ownership::{controlled_input_scripts, unowned_output_sats};
use crate::networks::rgb::psbt_validation;
use crate::networks::rgb::signing::taproot::find_controlled_taproot_inputs;
use crate::proto::SignBtcRequest;

/// Validates a plain-BTC `SignBtcRequest` before signing: output
/// self-ownership, the pinned fee policy, and the value-spent cap. The signer
/// applies the account scope (see module docs).
///
/// Returns `Ok(())` when authorized, a `CrossCheck` error otherwise.
pub fn validate_btc_request(
    req: &SignBtcRequest,
    cfg: &BridgeConfig,
    keys: &KeyManager,
) -> Result<()> {
    // 0. Shape allowlist (same as the bridge path).
    let psbt = psbt_validation::parse_psbt_shape(&req.psbt_bytes)?;

    // 1. Sum the value spent (for the cap). Every input needs witness_utxo,
    //    else the value has no bound.
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

    // 2. No outputs: all input value would go to fees.
    if psbt.unsigned_tx.output.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "plain-BTC PSBT has no outputs - refusing (would route all input value to fees)".into(),
        ));
    }

    // 3. Output self-ownership on the unsigned tx outputs, which the segwit
    //    sighash commits to. Unproven value must fit `btc_max_unowned_sats`.
    //    The controlled-input lookup (BIP32 derivation and tap tweak) runs
    //    once and step 4 uses it again.
    let jobs = find_controlled_taproot_inputs(&psbt, keys.master_fingerprint(), keys);
    let input_scripts = controlled_input_scripts(&psbt, &jobs, Some(AccountType::Vanilla));
    let unowned_sat = unowned_output_sats(&psbt, &input_scripts, keys).ok_or_else(|| {
        EnclaveError::CrossCheck("plain-BTC unowned output value overflow".into())
    })?;

    if unowned_sat > 0 {
        if cfg.btc_max_unowned_sats == 0 {
            // Unset never means "no limit".
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
                 sign. An output is proven when its script equals that of an input this enclave \
                 co-signs (address reuse for change) or when it is a BIP-86 key-path output of \
                 one of the enclave's own accounts; a redirect is neither.",
                cfg.btc_max_unowned_sats
            )));
        }
    }

    // 4. Pinned fee policy (same as send-RGB). It runs before the amount cap,
    //    because the cap's dev fallback returns early. Key-path sizing uses the
    //    Vanilla account, which the signer co-signs on this path.
    let key_path_inputs = psbt_validation::fee_key_path_inputs_of(&jobs, AccountType::Vanilla);
    psbt_validation::check_psbt_fee(&psbt, &key_path_inputs, "plain-BTC")?;

    // 5. Amount cap on the sum of input values. It also bounds fees.
    if cfg.btc_max_total_sats == 0 {
        // Production must not sign without the cap. Nothing else bounds what
        // a host can send to miner fees.
        #[cfg(all(feature = "rgb-validation", not(test)))]
        {
            return Err(EnclaveError::CrossCheck(
                "plain-BTC signing requires BTC_MAX_TOTAL_SATS to be pinned - refusing to sign \
                 without a bound on the value a single plain-BTC transaction can spend"
                    .into(),
            ));
        }
        // Builds without rgb-validation, and test builds: dev path only.
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

/// Bounds the Bitcoin value a send-RGB PSBT sends to destinations this enclave
/// cannot prove it controls.
///
/// All other send-RGB binds use RGB asset units. Thus a witness tx can match
/// the ledger and still sweep the Bitcoin backing of the bridge.
/// `check_psbt_fee` does not see it: a diverted sat is an output, not a fee,
/// so it *lowers* the implied rate.
///
/// Send-RGB cannot require self-owned outputs, because the recipient witness
/// output has a blinded seal. It bounds the total: dust fits, a sweep does not.
///
/// Ownership follows [`super::btc_ownership`]: metadata only names a path, the
/// script check is the proof.
pub fn validate_rgb_psbt_sats(
    psbt: &bitcoin::psbt::Psbt,
    cfg: &BridgeConfig,
    keys: &KeyManager,
) -> Result<()> {
    // `None` scope: change is on Colored, vanilla funding on Vanilla. This
    // widens what counts as ours, never what is signed.
    let input_scripts =
        crate::networks::rgb::btc_ownership::self_controlled_input_scripts_scoped(psbt, keys, None);

    let unowned_sat = unowned_output_sats(psbt, &input_scripts, keys)
        .ok_or_else(|| EnclaveError::CrossCheck("send-RGB unowned output value overflow".into()))?;

    if cfg.rgb_max_unowned_sats == 0 {
        // Unset never means "no limit".
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
mod tests;
