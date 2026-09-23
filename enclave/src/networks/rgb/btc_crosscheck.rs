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
//! `cfg(test)` builds fall back to a permissive dev path. The witness_utxo requirement runs in all builds.

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::keys::KeyManager;
use crate::networks::rgb::btc_ownership::{self_controlled_input_scripts, unowned_output_sats};
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
    let unowned_sat = unowned_output_sats(&psbt, &input_scripts).ok_or_else(|| {
        EnclaveError::CrossCheck("plain-BTC unowned output value overflow".into())
    })?;

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

    let unowned_sat = unowned_output_sats(psbt, &input_scripts)
        .ok_or_else(|| EnclaveError::CrossCheck("send-RGB unowned output value overflow".into()))?;

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
mod tests;
