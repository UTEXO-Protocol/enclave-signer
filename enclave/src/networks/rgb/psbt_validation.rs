use bitcoin::psbt::Psbt;

#[cfg(feature = "rgb-validation")]
use super::flow;
#[cfg(feature = "rgb-validation")]
use super::validation::{bfa, ValidatedConsignment};
use crate::error::{EnclaveError, Result};

/// Derive the soft-dedup key for an EVM->RGB bridge PSBT operation.
///
/// 32-byte keccak over `(chain_id, bridge_contract, evm_tx_hash,
/// funds_in_operation_id, rgb_asset_id)`. `chain_id` and `bridge_contract` come
/// from the pinned [`crate::config::BridgeConfig`], not the request.
/// `funds_in_operation_id` is the on-chain `BridgeFundsIn.operationId`, already
/// verified by [`crate::networks::evm::events::verify_funds_in_event`].
/// Variable-length fields are length-prefixed and a domain tag is
/// mixed in, so distinct tuples cannot collide by concatenation ambiguity.
///
/// Consumed by the soft in-memory replay guard
/// ([`crate::state::EnclaveState::op_replay_guard`]), which is defense in depth
/// and not a sufficient double-spend control.
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

/// Shape whitelist for a raw PSBT: refuse payloads that aren't even a legitimate
/// PSBT before any other predicate runs. Catches three classes of garbage
/// up-front:
///
///   (a) empty bytes (handler tried to sign nothing),
///   (b) bytes that don't conform to BIP-174 (random/truncated/tampered),
///   (c) PSBTs with no inputs - there's literally nothing to sign, and the
///       unsigned-tx-must-be-non-empty rule is implicit in BIP-174's signing
///       semantics.
///
/// The signer would fail later on these too, but with a much noisier downstream
/// error; failing here gives the caller a single clear reason. Returns the
/// parsed PSBT so callers that need it (the plain-BTC `SignBtc` path) don't
/// re-parse. Shared by the bridge/RGB `SignPsbt` path ([`validate_psbt_bytes`])
/// and the plain-BTC `SignBtc` path ([`crate::networks::rgb::btc_crosscheck`]).
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

/// Validate the serialized PSBT shape owned by an RGB destination.
pub fn validate_psbt_bytes(psbt_bytes: &[u8]) -> Result<()> {
    parse_psbt_shape(psbt_bytes).map(|_| ())
}

/// Bind a PSBT to the RGB consignment it claims to finalize.
///
/// The PSBT being signed is the RGB transfer's witness transaction: it spends
/// the bridge UTXOs holding the RGB allocation and carries the tapret/opret DBC
/// commitment to the state-transition bundle. Without this bind, a compromised
/// host could have the enclave sign a PSBT that moves bridge BTC without
/// committing to the claimed RGB state.
///
/// Must run only after
/// [`crate::networks::rgb::validation::RgbValidator::validate_consignment`],
/// which is what proves the commitment is genuinely anchored.
///
/// The shape and amount rules (legs 1, 5, 6) belong to the build's RGB flow,
/// [`crate::networks::rgb::flow`]. A `rgb-swap` enclave admits only BFA
/// `Transfer`, a `rgb-mint-burn` enclave only BFA `Bridge`; everything else
/// here is shared PSBT mechanics.
///
/// Enforces, fail-closed:
///   1. The consignment's last transition is the type this flow signs.
///   2. Identity bind: `psbt.unsigned_tx.compute_txid()` equals the
///      consignment's last witness txid, and every input spends a native
///      witness program. A native witness program finalizes with an empty
///      `scriptSig` (BIP-141), so the unsigned txid is the final txid and
///      signing this PSBT finalizes the validated transition. An input that
///      finalizes with a `scriptSig` (P2SH-wrapped SegWit, legacy) moves the
///      txid off the one the consignment names, so it is refused here.
///   3. Per-input canary: when the consignment embeds the full witness tx, the
///      PSBT input outpoints must equal its prevout set. Redundant given (2);
///      a mismatch means a broken consignment invariant.
///   4. Sighash guard: only ALL / taproot-DEFAULT, so a host cannot splice our
///      signature into a different tx.
///   5. Whole-bundle scope: both amount binds run over every transition the
///      signed txid commits, not just the last one. The group must be
///      non-empty, must contain that last transition, and every member must be
///      the type this flow signs (which also rules out a mixed bundle).
///   6. Aggregate amount bind: the group's summed `asset_output_amount`
///      (`OS_ASSET` allocations only, excluding the `OS_BRIDGE` mint right)
///      against `source_amount - source_commission`, under the active flow's
///      rule - exact equality for a mint, a coverage lower bound for a
///      transfer (whose total includes bridge change).
///   7. Per-output recipient bind: each `OS_ASSET` output is
///      classified by its seal. A confidential (`utxob:`) seal is a recipient
///      leg; a revealed (`txid:vout`) seal counts as bridge change only if the
///      outpoint it names is provably ours (`self_owned`). Anything else is
///      rejected. The recipient total must equal `net_credited` exactly.
///
///      The outpoint need not sit on the tx being signed: with no BTC change,
///      rgb-lib parks the RGB change on an existing wallet UTXO. Same proof,
///      plus an indexer round-trip, capped at
///      [`MAX_OFF_TX_CHANGE_OUTPOINTS`] per PSBT.
///
/// `self_owned` resolves whether a Bitcoin outpoint pays back to this enclave. It is
/// a callback rather than a `&KeyManager` so the caller holds the key lock only
/// for that resolution, never across consignment validation's network calls.
///
/// Returns the [`AssetLegs`] this walk classified: the recipient leg in asset
/// units, which the route-level amount cross-check is built from rather than
/// the wire-supplied `psbt_output_amount`, and the seals it was paid to.
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

    // Derive the txid from `unsigned_tx`, never a finalized tx; the input
    // gate below makes the two equal. The transition gate above makes this
    // bundle's txid the transition's witness.
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

    // 0x00 = taproot SIGHASH_DEFAULT, 0x01 = SIGHASH_ALL; anything else is spliceable.
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

    // Every transition this tx commits, not just the last one: a Bitcoin tx
    // commits a bundle, which can hold several.
    let committed = validated.transitions_committed_by(psbt_txid);
    if committed.is_empty() {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB consignment commits no transition to the transaction being signed \
             ({psbt_txid}) - refusing to sign an unbound witness"
        )));
    }
    // Canary: the transition the pipeline calls "last" must be one this tx
    // commits, else the flat parser and the rgbstd walk disagree and every
    // downstream bind describes a different operation.
    if !committed.iter().any(|t| t.op_id == last.op_id) {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB consignment inconsistency: last transition {} is not committed by the \
             transaction being signed ({psbt_txid})",
            last.op_id
        )));
    }
    flow::assert_committed_group(&committed)?;

    // `asset_output_amount`, not `total_output_amount`: `OS_BRIDGE` outputs
    // are mint capacity, not minted value. Summed across the whole group so a
    // sibling transition cannot move value outside the bind.
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

    // Per-output recipient bind. Runs last: it is the only check
    // here that reaches for the enclave's keys.
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
/// A callback rather than a `&KeyManager` so the key lock is not held across
/// consignment validation's network round-trips. Two cases, two kinds of
/// evidence:
///
///   * on this PSBT - from PSBT metadata alone, via
///     [`crate::networks::rgb::btc_ownership::self_owned_output_indices`];
///   * on an earlier tx - the tx is fetched and verified by
///     [`crate::networks::rgb::validation::RgbValidator::fetch_transaction`],
///     then its `script_pubkey` must be in
///     [`crate::networks::rgb::btc_ownership::asset_change_scripts`].
#[cfg(feature = "rgb-validation")]
pub type SelfOwnedOutpoint<'a> = &'a dyn Fn(&Psbt, bitcoin::OutPoint) -> Result<bool>;

/// Cap on distinct off-transaction outpoints resolved per PSBT. Each costs an
/// indexer round-trip, so an unbounded count would let one request amplify into
/// many egress calls. A real transfer uses one; the slack is for bundles.
#[cfg(feature = "rgb-validation")]
pub const MAX_OFF_TX_CHANGE_OUTPOINTS: usize = 4;

/// The two legs an `OS_ASSET` output assignment can belong to, in asset units.
#[cfg(feature = "rgb-validation")]
#[derive(Debug)]
pub struct AssetLegs {
    /// Paid to confidential (blinded) seals - the recipient.
    pub recipient: u64,
    /// Returned to revealed seals on Bitcoin outputs this enclave provably
    /// controls - bridge change.
    pub change: u64,
    /// The `utxob:...` seals behind `recipient`, in consignment order. Carried
    /// out of this one walk so the amount bind and
    /// [`crate::networks::rgb::invoice`]'s identity bind cannot classify a leg
    /// differently.
    pub recipient_seals: Vec<String>,
}

/// Split the `OS_ASSET` outputs of every transition the signed tx commits into
/// recipient and change, rejecting anything that is provably neither.
///
/// Takes the whole committed group, not one transition: otherwise value routed
/// by a sibling transition escapes the bind. `OS_BRIDGE` entries are skipped
/// because their amount is mint capacity, not delivered value.
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

    // Memoised per outpoint: several change legs can share one UTXO, and every
    // miss costs a resolution. Only misses that leave the PSBT are capped.
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
                // `None` means the witness tx of this bundle, which the
                // identity bind already proved is the PSBT being signed. Seal
                // txids are display order, `Txid` is internal order: flip here,
                // the one place that footgun lives.
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

/// Maximum multiple of the recommended fee rate a send-RGB PSBT may pay.
/// Compile-time and PCR-attested, not host-tunable. 3x absorbs fee-market
/// movement within the estimate's TTL plus the unsigned-vsize overestimate.
#[cfg(feature = "rgb-validation")]
const FEE_RATE_HEADROOM: f64 = 3.0;

/// Fee-rate sanity check for send-RGB PSBTs: the implied fee rate must
/// not exceed [`FEE_RATE_HEADROOM`] x the enclave-fetched recommendation.
/// Without this, a compromised host could burn bridge BTC as miner fees on an
/// otherwise fully-validated PSBT.
///
/// Fail-closed on degenerate shapes: `Psbt::fee()` errors, zero vsize, and NaN
/// rates all reject. The rate is computed over `unsigned_tx.vsize()`, which
/// overestimates the implied rate; the headroom absorbs that.
#[cfg(feature = "rgb-validation")]
pub fn check_psbt_fee_rate(psbt: &Psbt, recommended_sat_vb: f64) -> Result<()> {
    let fee = psbt.fee().map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "cannot compute PSBT fee (every input needs witness_utxo or non_witness_utxo): {e}"
        ))
    })?;
    let vsize = psbt.unsigned_tx.vsize();
    if vsize == 0 {
        return Err(EnclaveError::CrossCheck(
            "PSBT unsigned tx has zero vsize - cannot bound its fee rate".into(),
        ));
    }
    let rate = fee.to_sat() as f64 / vsize as f64;
    let limit = FEE_RATE_HEADROOM * recommended_sat_vb;
    // `partial_cmp` (not `a > b`): an incomparable (NaN) rate or limit must
    // reject, never pass.
    let within_limit = matches!(
        rate.partial_cmp(&limit),
        Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
    );
    if !within_limit {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB PSBT fee rate too high: {rate:.2} sat/vB > {FEE_RATE_HEADROOM}x the \
             recommended {recommended_sat_vb:.2} sat/vB - refusing to burn bridge BTC as fees"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
