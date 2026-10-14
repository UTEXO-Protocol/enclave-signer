use bitcoin::psbt::Psbt;

#[cfg(feature = "rgb-validation")]
use super::flow;
#[cfg(feature = "rgb-validation")]
use super::validation::{bfa, ValidatedConsignment};
use crate::error::{EnclaveError, Result};

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

/// Binds a PSBT to the RGB consignment it claims to finalize.
///
/// The PSBT is the witness transaction of the RGB transfer. It spends the
/// bridge UTXOs with the RGB allocation and carries the tapret/opret DBC
/// commitment to the transition bundle. Without this bind, a compromised host
/// could get a signature that moves bridge BTC without the claimed RGB state.
///
/// Run it only after
/// [`crate::networks::rgb::validation::RgbValidator::validate_consignment`],
/// which proves the commitment is anchored.
///
/// The build's RGB flow ([`crate::networks::rgb::flow`]) owns the type and
/// amount rules (1, 5, 6). A `rgb-swap` enclave accepts only BFA `Transfer`, a
/// `rgb-mint-burn` enclave only BFA `Bridge`. The rest is shared PSBT logic.
///
/// Checks, fail-closed:
///   1. The settling transition of the consignment is the type this flow signs.
///   2. Identity bind: `psbt.unsigned_tx.compute_txid()` equals the last
///      witness txid, and every input spends a native witness program. Such an
///      input finalizes with an empty `scriptSig` (BIP-141), so the unsigned
///      txid is the final txid. A `scriptSig` input (P2SH-wrapped SegWit,
///      legacy) changes the txid, so it is refused.
///   3. Per-input canary: when the consignment has the full witness tx, the
///      PSBT input outpoints must equal its prevout set. Redundant with (2). A
///      mismatch means a broken consignment invariant.
///   4. Sighash guard: only ALL or taproot DEFAULT, so a host cannot splice our
///      signature into a different tx.
///   5. Whole-bundle scope: both amount binds cover every transition the
///      signed txid commits. The group must not be empty, must contain the
///      settling transition, and every member must be the type this flow signs.
///   6. Aggregate amount bind: the summed `asset_output_amount` of the group
///      (`OS_ASSET` only, not the `OS_BRIDGE` mint right) against
///      `source_amount - source_commission`, under the flow rule: equality for
///      a mint, a lower bound for a transfer (its total includes change).
///   7. Per-output recipient bind: the seal classifies each `OS_ASSET` output.
///      A confidential (`utxob:`) seal is a recipient leg. A revealed
///      (`txid:vout`) seal is bridge change only if `self_owned` proves the
///      outpoint is ours. All else is rejected. The recipient total must equal
///      `net_credited`.
///
///      The outpoint can be off the signed tx: with no BTC change, rgb-lib puts
///      the RGB change on an existing wallet UTXO. That needs an indexer call,
///      capped at [`MAX_OFF_TX_CHANGE_OUTPOINTS`] per PSBT.
///
/// `self_owned` resolves whether an outpoint pays back to this enclave. It is a
/// callback, not a `&KeyManager`, so the key lock is not held across the
/// network calls of consignment validation.
///
/// Returns the classified [`AssetLegs`]. The route-level amount cross-check
/// uses its recipient amount, not the wire `psbt_output_amount`.
#[cfg(feature = "rgb-validation")]
pub fn validate_psbt_anchors_transition(
    psbt: &Psbt,
    validated: &ValidatedConsignment,
    source_amount: u64,
    source_commission: u64,
    self_owned: SelfOwnedOutpoint<'_>,
) -> Result<AssetLegs> {
    use std::collections::BTreeSet;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT requires a consignment with at least one transition".into(),
        )
    })?;
    flow::assert_signing_transition(last)?;

    // Use the txid of `unsigned_tx`, never a finalized tx. The input check
    // below makes the two equal.
    let expected = validated.last_witness_txid.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "consignment carries no witness txid for its last transition - \
             cannot anchor the PSBT"
                .into(),
        )
    })?;
    let psbt_txid = psbt.unsigned_tx.compute_txid();
    if psbt_txid != expected {
        return Err(EnclaveError::CrossCheck(format!(
            "PSBT does not finalize the consignment's transition: unsigned txid {psbt_txid} != \
             consignment witness txid {expected}"
        )));
    }

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
                 scriptSig would change the txid the consignment binds ({psbt_txid}) - \
                 refusing to sign"
            )));
        }
    }

    if let Some(ref prevouts) = validated.last_transfer_witness_prevouts {
        let expected_set: BTreeSet<bitcoin::OutPoint> = prevouts.iter().copied().collect();
        let psbt_set: BTreeSet<bitcoin::OutPoint> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect();
        if psbt_set != expected_set {
            return Err(EnclaveError::CrossCheck(
                "PSBT input outpoints do not match the consignment witness tx inputs \
                 (txid matched but input set differs - broken consignment invariant)"
                    .into(),
            ));
        }
    }

    // 0x00 = taproot SIGHASH_DEFAULT, 0x01 = SIGHASH_ALL. Others are spliceable.
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

    // A Bitcoin tx commits a bundle, which can hold several transitions.
    let committed = validated.transitions_committed_by(psbt_txid);
    if committed.is_empty() {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB consignment commits no transition to the transaction being signed \
             ({psbt_txid}) - refusing to sign an unbound witness"
        )));
    }
    // Canary: this tx must commit the settling transition. Else the flat parser
    // and the rgbstd walk disagree, and the binds below check a different
    // operation.
    if !committed.iter().any(|t| t.op_id == last.op_id) {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB consignment inconsistency: settling transition {} is not committed by the \
             transaction being signed ({psbt_txid})",
            last.op_id
        )));
    }
    flow::assert_committed_group(&committed)?;

    // `asset_output_amount`, not `total_output_amount`: `OS_BRIDGE` outputs
    // are mint capacity, not minted value. The sum covers the whole group, so
    // a sibling transition cannot move value outside the bind.
    let committed_asset_output: u64 = committed
        .iter()
        .try_fold(0u64, |acc, t| acc.checked_add(t.asset_output_amount))
        .ok_or_else(|| {
            EnclaveError::CrossCheck(
                "send-RGB committed asset_output_amount total overflows u64".into(),
            )
        })?;

    let net_credited = source_amount.saturating_sub(source_commission);
    flow::assert_group_amount(committed_asset_output, source_amount, source_commission)?;

    // Per-output recipient bind. It runs last because only it uses the
    // enclave keys.
    let legs = split_asset_legs(psbt, psbt_txid, &committed, self_owned)?;
    if legs.recipient != net_credited {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB recipient amount mismatch: consignment pays {} asset units to \
             confidential (recipient) seals, but the source credited {net_credited} \
             (source_amount {source_amount} - source_commission {source_commission}); \
             {} units return to bridge-owned change seals",
            legs.recipient, legs.change
        )));
    }

    Ok(legs)
}

/// Resolves whether a Bitcoin outpoint pays back to this enclave.
///
/// A callback, not a `&KeyManager`, so the key lock is not held across the
/// network calls of consignment validation. Two cases:
///
///   * on this PSBT: from PSBT metadata only, via
///     [`crate::networks::rgb::btc_ownership::self_owned_output_indices`];
///   * on an earlier tx: the tx is fetched and verified by
///     [`crate::networks::rgb::validation::RgbValidator::fetch_transaction`],
///     then its `script_pubkey` must be in
///     [`crate::networks::rgb::btc_ownership::asset_change_scripts`].
#[cfg(feature = "rgb-validation")]
pub type SelfOwnedOutpoint<'a> = &'a dyn Fn(&Psbt, bitcoin::OutPoint) -> Result<bool>;

/// Cap on distinct off-transaction outpoints per PSBT. Each one costs an
/// indexer call, so no cap lets one request cause many egress calls. A real
/// transfer uses one. The rest is for bundles.
#[cfg(feature = "rgb-validation")]
pub const MAX_OFF_TX_CHANGE_OUTPOINTS: usize = 4;

/// The two legs an `OS_ASSET` output assignment can belong to, in asset units.
#[cfg(feature = "rgb-validation")]
#[derive(Debug)]
pub struct AssetLegs {
    /// Paid to confidential (blinded) seals: the recipient.
    pub recipient: u64,
    /// Paid to revealed seals on Bitcoin outputs this enclave provably
    /// controls: bridge change.
    pub change: u64,
    /// The `utxob:...` seals behind `recipient`, in consignment order. The
    /// amount bind and the [`crate::networks::rgb::invoice`] identity bind use
    /// this one walk, so they cannot classify a leg differently.
    pub recipient_seals: Vec<String>,
}

/// Splits the `OS_ASSET` outputs of all committed transitions into recipient
/// and change. Rejects an output that is not provably one of them.
///
/// It takes the whole committed group, so a sibling transition cannot move
/// value outside the bind. It skips `OS_BRIDGE`, because that amount is mint
/// capacity, not delivered value.
#[cfg(feature = "rgb-validation")]
fn split_asset_legs(
    psbt: &Psbt,
    psbt_txid: bitcoin::Txid,
    committed: &[&super::validation::TransitionSummary],
    self_owned: SelfOwnedOutpoint<'_>,
) -> Result<AssetLegs> {
    use super::validation::OutputSeal;
    use bitcoin::hashes::Hash;

    let asset_outputs: Vec<&super::validation::TransitionOutput> = committed
        .iter()
        .flat_map(|t| t.outputs.iter())
        .filter(|o| o.assignment_type == bfa::OS_ASSET)
        .collect();
    if asset_outputs.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "send-RGB consignment's committed transitions carry no OS_ASSET output assignments - \
             nothing to bind the credited amount to"
                .into(),
        ));
    }

    // Cache per outpoint: change legs can share one UTXO, and each miss costs
    // a lookup. The cap applies only to off-PSBT misses.
    let mut verdicts: std::collections::HashMap<bitcoin::OutPoint, bool> =
        std::collections::HashMap::new();
    let mut off_tx_lookups = 0usize;

    let mut legs = AssetLegs {
        recipient: 0,
        change: 0,
        recipient_seals: Vec::new(),
    };
    for (i, out) in asset_outputs.iter().enumerate() {
        match &out.seal {
            OutputSeal::Confidential { secret_seal } => {
                legs.recipient = legs.recipient.checked_add(out.amount).ok_or_else(|| {
                    EnclaveError::CrossCheck(
                        "send-RGB recipient leg total overflows u64 asset units".into(),
                    )
                })?;
                legs.recipient_seals.push(secret_seal.clone());
            }
            OutputSeal::Revealed { txid, vout } => {
                // `None` is the witness tx of this bundle, which the identity
                // bind proved is the signed PSBT. Seal txids are display order
                // and `Txid` is internal order, so reverse the bytes here.
                let seal_txid = match txid {
                    Some(bytes) => {
                        let mut internal = *bytes;
                        internal.reverse();
                        bitcoin::Txid::from_byte_array(internal)
                    }
                    None => psbt_txid,
                };
                let outpoint = bitcoin::OutPoint {
                    txid: seal_txid,
                    vout: *vout,
                };

                let is_owned = match verdicts.get(&outpoint) {
                    Some(known) => *known,
                    None => {
                        if seal_txid != psbt_txid {
                            off_tx_lookups += 1;
                            if off_tx_lookups > MAX_OFF_TX_CHANGE_OUTPOINTS {
                                return Err(EnclaveError::CrossCheck(format!(
                                    "send-RGB consignment names more than \
                                     {MAX_OFF_TX_CHANGE_OUTPOINTS} distinct off-transaction \
                                     change outpoints - refusing to sign"
                                )));
                            }
                        }
                        let verdict = self_owned(psbt, outpoint)?;
                        verdicts.insert(outpoint, verdict);
                        verdict
                    }
                };

                if !is_owned {
                    return Err(EnclaveError::CrossCheck(format!(
                        "send-RGB OS_ASSET output {i} ({} units) has a revealed seal on outpoint \
                         {outpoint}, which this enclave cannot prove it controls - a revealed leg \
                         is only acceptable as bridge change, and an unprovable one is an \
                         unverifiable payout destination",
                        out.amount
                    )));
                }
                legs.change = legs.change.checked_add(out.amount).ok_or_else(|| {
                    EnclaveError::CrossCheck(
                        "send-RGB change leg total overflows u64 asset units".into(),
                    )
                })?;
            }
        }
    }

    Ok(legs)
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
/// [`MAX_FEE_CAP_CROSSOVER_VB`] unsigned vB (one key-path input and approx ten
/// P2TR outputs). A wider `create_utxos` batch at a high rate must be split.
/// The error names the crossover, so the operator can tell a size problem from
/// a rate problem.
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
