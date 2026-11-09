use bitcoin::psbt::Psbt;

use crate::error::{EnclaveError, Result};

// The mint signer's rules, on the transition its PSBT commits. Only it holds
// mint rights to mint with or refill.
#[cfg(feature = "rgb-validation")]
mod mint;
#[cfg(feature = "rgb-validation")]
mod refill;
#[cfg(feature = "rgb-validation")]
pub use mint::*;
#[cfg(feature = "rgb-validation")]
pub use refill::*;

/// Soft-dedup key for an EVM->RGB bridge PSBT operation.
///
/// 32-byte keccak over `(chain_id, bridge_contract, evm_tx_hash,
/// funds_in_operation_id, rgb_asset_id)`. `chain_id` and `bridge_contract` come
/// from the pinned [`crate::config::BridgeConfig`], not the request.
/// `funds_in_operation_id` is the on-chain `BridgeFundsIn.operationId`, verified
/// by [`crate::networks::evm::events::verify_funds_in_event`].
/// A domain tag and length prefixes on variable-length fields prevent
/// concatenation collisions.
///
/// The in-memory replay guard
/// ([`crate::state::EnclaveState::op_replay_guard`]) uses it. That guard is
/// defense in depth only, not a full double-spend control.
pub fn psbt_operation_key(
    chain_id: u64,
    bridge_contract: &[u8; 20],
    evm_tx_hash: &[u8],
    funds_in_operation_id: &[u8],
    rgb_asset_id: &str,
) -> [u8; 32] {
    use sha3::{Digest, Keccak256};

    let mut h = Keccak256::new();
    h.update(b"utexo:psbt-op:v1");
    h.update(chain_id.to_be_bytes());
    h.update(bridge_contract);
    h.update((evm_tx_hash.len() as u64).to_be_bytes());
    h.update(evm_tx_hash);
    h.update((funds_in_operation_id.len() as u64).to_be_bytes());
    h.update(funds_in_operation_id);
    h.update((rgb_asset_id.len() as u64).to_be_bytes());
    h.update(rgb_asset_id.as_bytes());
    h.finalize().into()
}

/// Shape allowlist for a raw PSBT, before all other checks. It rejects:
///
///   (a) empty bytes,
///   (b) bytes that are not valid BIP-174,
///   (c) PSBTs with no inputs (nothing to sign).
///
/// The signer would also fail on these, but with a less clear error. Returns
/// the parsed PSBT so callers do not parse it again. Used by the `SignPsbt`
/// path ([`validate_psbt_bytes`]) and the `SignBtc` path
/// ([`crate::networks::rgb::btc_crosscheck`]).
pub(crate) fn parse_psbt_shape(psbt_bytes: &[u8]) -> Result<Psbt> {
    if psbt_bytes.is_empty() {
        return Err(EnclaveError::CrossCheck("psbt_bytes is empty".into()));
    }
    crate::config::check_psbt_size("psbt_bytes", psbt_bytes)?;
    let psbt = Psbt::deserialize(psbt_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("psbt_bytes is not a valid PSBT: {e}")))?;
    if psbt.unsigned_tx.input.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "psbt has no inputs - nothing to sign".into(),
        ));
    }

    Ok(psbt)
}

/// Validates the shape of a serialized PSBT for an RGB destination.
pub fn validate_psbt_bytes(psbt_bytes: &[u8]) -> Result<()> {
    parse_psbt_shape(psbt_bytes).map(|_| ())
}

/// F2: the txid the enclave signs is the txid that confirms, and no signature
/// can be spliced into another tx.
#[cfg(feature = "rgb-validation")]
pub fn assert_txid_and_sighash_fixed(psbt: &Psbt) -> Result<()> {
    assert_native_segwit_inputs(psbt)?;
    assert_sighash_all(psbt)
}

/// Every input finalizes with an empty `scriptSig`, so the unsigned txid is
/// the final txid. A P2SH-wrapped or legacy input would change it.
#[cfg(feature = "rgb-validation")]
fn assert_native_segwit_inputs(psbt: &Psbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        let Some(utxo) = input.witness_utxo.as_ref() else {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB PSBT input {i} carries no witness_utxo - cannot prove it finalizes \
                 without a scriptSig"
            )));
        };
        if !utxo.script_pubkey.is_witness_program() {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB PSBT input {i} spends a non-native-SegWit output; its finalized \
                 scriptSig would change the txid ({}) - refusing to sign",
                psbt.unsigned_tx.compute_txid()
            )));
        }
    }
    Ok(())
}

/// 0x00 = taproot SIGHASH_DEFAULT, 0x01 = SIGHASH_ALL. Others are spliceable.
#[cfg(feature = "rgb-validation")]
fn assert_sighash_all(psbt: &Psbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(sht) = input.sighash_type {
            let raw = sht.to_u32();
            if raw != 0x00 && raw != 0x01 {
                return Err(EnclaveError::CrossCheck(format!(
                    "PSBT input {i} requests non-ALL sighash 0x{raw:02x}; refusing to sign a \
                     send-RGB PSBT under a spliceable sighash"
                )));
            }
        }
    }
    Ok(())
}

/// F7 and RR10: every input is one of `colored`, our Colored key-path inputs.
/// The sats rules see only our inputs' value.
#[cfg(feature = "rgb-validation")]
pub fn assert_only_colored_inputs(psbt: &Psbt, colored: &[usize], path: &str) -> Result<()> {
    if let Some(i) = (0..psbt.inputs.len()).find(|i| !colored.contains(i)) {
        return Err(EnclaveError::CrossCheck(format!(
            "{path} PSBT input {i} is not a Colored key-path input of this enclave - it spends \
             only the mint wallet's own coins"
        )));
    }
    Ok(())
}

/// M8 of a blinded mint and RR12: no sat leaves. With no rule A exemption, each
/// output must be a rule C output of ours or carry 0 sat, as the OP_RETURN must.
#[cfg(feature = "rgb-validation")]
pub fn assert_keeps_all_sats(
    psbt: &Psbt,
    keys: &crate::keys::KeyManager,
    path: &str,
) -> Result<()> {
    let no_inputs = std::collections::HashSet::new();
    match super::btc_ownership::unowned_output_sats(psbt, &no_inputs, keys) {
        Some(0) => Ok(()),
        Some(sats) => Err(EnclaveError::CrossCheck(format!(
            "{path} PSBT pays {sats} sat to outputs this enclave does not derive - it keeps \
             every sat on its own outputs"
        ))),
        None => Err(EnclaveError::CrossCheck(format!(
            "{path} PSBT output total overflows u64"
        ))),
    }
}

/// Pinned maximum fee rate (sat/vB) for every PSBT this enclave signs
/// (`SignBtc` and `SignPsbt`). It is compile-time and in PCR0, so the host
/// cannot change it. A change needs a new image that the federation agrees to.
/// It is high on purpose: a safety limit against fee burn, not a fee estimator.
/// The bridge checks the real rate before it locks user funds, so a fee market
/// move before signing cannot strand a mint.
pub const MAX_FEE_RATE_SAT_VB: u64 = 200;

/// Pinned maximum absolute miner fee (sats) for every PSBT this enclave signs.
/// It bounds the fee of one request at any transaction size.
///
/// At the maximum rate, this cap applies first above
/// [`MAX_FEE_CAP_CROSSOVER_VB`] unsigned vB. A `create_utxos` batch above that
/// size at a high rate must be split. The error names the crossover, so the
/// operator can tell a size problem from a rate problem.
pub const MAX_FEE_SATS: u64 = 100_000;

/// Unsigned vsize above which [`MAX_FEE_SATS`] applies before
/// [`MAX_FEE_RATE_SAT_VB`].
pub const MAX_FEE_CAP_CROSSOVER_VB: u64 = MAX_FEE_SATS / MAX_FEE_RATE_SAT_VB;

/// Minimum signed fee rate for bridge PSBTs. The caller cannot change it.
const MIN_FEE_RATE_SAT_VB: u64 = 1;

/// Resolves the key-path inputs using enclave keys, not caller-supplied claims.
pub type FeeKeyPathResolver<'a> = &'a dyn Fn(&Psbt) -> Result<Vec<usize>>;

/// Key-path inputs of `account` that this enclave controls, signed or not.
/// Resolved from enclave keys, never from the request. `account` is the scope
/// the signer co-signs: Colored for send-RGB, Vanilla for plain-BTC. Only the
/// send-RGB resolver calls it. Plain-BTC uses [`fee_key_path_inputs_of`].
#[cfg(feature = "rgb-validation")]
pub(crate) fn fee_key_path_inputs_scoped(
    psbt: &Psbt,
    keys: &crate::keys::KeyManager,
    account: crate::keys::AccountType,
) -> Vec<usize> {
    let jobs = super::signing::taproot::find_controlled_taproot_inputs(
        psbt,
        keys.master_fingerprint(),
        keys,
    );
    fee_key_path_inputs_of(&jobs, account)
}

/// [`fee_key_path_inputs_scoped`] over resolved jobs, for a caller that
/// already resolved the controlled inputs for another check.
pub(crate) fn fee_key_path_inputs_of(
    jobs: &[super::signing::taproot::TaprootSignJob],
    account: crate::keys::AccountType,
) -> Vec<usize> {
    jobs.iter()
        .filter(|job| job.account_type == account)
        .map(|job| job.input_index)
        .collect()
}

/// Pinned fee policy for every PSBT the enclave signs. `path` names the
/// signing path in errors (`"send-RGB"` / `"plain-BTC"`).
///
/// Three compile-time bounds:
///
///   * the absolute fee is at most [`MAX_FEE_SATS`];
///   * the fee rate is at most [`MAX_FEE_RATE_SAT_VB`] over
///     `unsigned_tx.vsize()`. The unsigned size has no witnesses, so the host
///     cannot pad it to lower the rate. It overstates the signed rate by the
///     witness share (under a fifth for key-path Taproot). The high limit
///     allows for that;
///   * the fee pays at least [`MIN_FEE_RATE_SAT_VB`] over the estimated signed
///     size (with witnesses), so the transaction can relay.
///
/// Fail-closed: a `Psbt::fee()` error (no `witness_utxo` / `non_witness_utxo`),
/// zero vsize, or a spend shape with no size estimate all fail. If the
/// finalizer uses a different witness or spend path, it must check the fee
/// rate again. `key_path_inputs` must come from [`fee_key_path_inputs_scoped`]
/// or [`fee_key_path_inputs_of`], never from the request.
pub fn check_psbt_fee(psbt: &Psbt, key_path_inputs: &[usize], path: &str) -> Result<()> {
    let fee = psbt
        .fee()
        .map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "cannot compute PSBT fee (every input needs witness_utxo or \
                 non_witness_utxo): {e}"
            ))
        })?
        .to_sat();
    let vsize = psbt.unsigned_tx.vsize() as u64;
    if vsize == 0 {
        return Err(EnclaveError::CrossCheck(
            "PSBT unsigned tx has zero vsize - cannot bound its fee rate".into(),
        ));
    }

    if fee > MAX_FEE_SATS {
        let rate = fee as f64 / vsize as f64;
        return Err(EnclaveError::CrossCheck(format!(
            "{path} PSBT fee too high: {fee} sat > the pinned maximum of {MAX_FEE_SATS} sat \
             ({rate:.2} sat/vB over {vsize} unsigned vB; above {MAX_FEE_CAP_CROSSOVER_VB} vB \
             the absolute cap binds before the {MAX_FEE_RATE_SAT_VB} sat/vB rate cap, so split \
             a wider batch) - refusing to burn custody BTC as fees"
        )));
    }

    let max_fee_for_size = vsize
        .checked_mul(MAX_FEE_RATE_SAT_VB)
        .ok_or_else(|| EnclaveError::CrossCheck("maximum PSBT fee calculation overflow".into()))?;
    if fee > max_fee_for_size {
        let rate = fee as f64 / vsize as f64;
        return Err(EnclaveError::CrossCheck(format!(
            "{path} PSBT fee rate too high: {rate:.2} sat/vB over {vsize} unsigned vB > the \
             pinned maximum of {MAX_FEE_RATE_SAT_VB} sat/vB - refusing to burn custody BTC as \
             fees"
        )));
    }

    let signed_vsize = super::psbt_fee_size::estimated_signed_vsize(psbt, key_path_inputs)?;
    let minimum_fee = signed_vsize
        .checked_mul(MIN_FEE_RATE_SAT_VB)
        .ok_or_else(|| EnclaveError::CrossCheck("minimum PSBT fee calculation overflow".into()))?;
    if fee < minimum_fee {
        return Err(EnclaveError::CrossCheck(format!(
            "{path} PSBT fee rate too low: {fee} sat for estimated signed size {signed_vsize} \
             vB; need at least {minimum_fee} sat ({MIN_FEE_RATE_SAT_VB} sat/vB)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
