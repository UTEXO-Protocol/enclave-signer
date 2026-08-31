use bitcoin::psbt::Psbt;

#[cfg(feature = "bfa-mint")]
use super::validation::bfa;
#[cfg(feature = "rgb-validation")]
use super::validation::{ifa, is_mint_transition, ValidatedConsignment};
use crate::error::{EnclaveError, Result};

/// Transition types this bind knows an amount rule for. A BFA mint joins the
/// mint rule, never the transfer one - a surplus must not pass as change.
#[cfg(feature = "rgb-validation")]
fn binds_psbt_amounts(transition_type: u16) -> bool {
    #[cfg(feature = "bfa-mint")]
    {
        if transition_type == bfa::TS_BRIDGE {
            return true;
        }
    }
    matches!(transition_type, ifa::TS_TRANSFER | ifa::TS_INFLATION)
}

#[cfg(all(feature = "rgb-validation", feature = "bfa-mint"))]
const BOUND_TRANSITION_TYPES: &str = "Transfer, Inflation or Bridge";
#[cfg(all(feature = "rgb-validation", not(feature = "bfa-mint")))]
const BOUND_TRANSITION_TYPES: &str = "Transfer or Inflation";

/// Derive the soft-dedup key for an EVM->RGB bridge PSBT operation.
///
/// 32-byte keccak over `(chain_id, bridge_contract, evm_tx_hash,
/// funds_in_operation_id, rgb_asset_id)`. `chain_id` and `bridge_contract` come
/// from the pinned [`crate::config::BridgeConfig`], not the request.
/// `funds_in_operation_id` is the on-chain `BridgeFundsIn.operationId`, already
/// verified by [`crate::networks::evm::evm_event::verify_funds_in_event`].
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
/// Enforces, fail-closed:
///   1. The consignment's last transition is an IFA `Transfer`
///      (`ifa::TS_TRANSFER`) or an IFA `Inflation` (`ifa::TS_INFLATION`).
///   2. Identity bind: `psbt.unsigned_tx.compute_txid()` equals the
///      consignment's last witness txid. A segwit txid commits to every
///      non-witness field, so equality means signing this PSBT finalizes
///      exactly the validated transition.
///   3. Per-input canary: when the consignment embeds the full witness tx, the
///      PSBT input outpoints must equal its prevout set. Redundant given (2);
///      a mismatch means a broken consignment invariant.
///   4. Sighash guard: only ALL / taproot-DEFAULT, so a host cannot splice our
///      signature into a different tx.
///   5. Whole-bundle scope: both amount binds run over every transition the
///      signed txid commits, not just the last one. The group must be
///      non-empty, must contain that last transition, and must be all-Transfer
///      or all-Inflation.
///   6. Aggregate amount bind: the group's summed `asset_output_amount`
///      (`OS_ASSET` allocations only, excluding `OS_INFLATION` mint capacity)
///      against `source_amount - source_commission`. Exact equality for an
///      Inflation (any surplus is an over-mint), a coverage lower bound for a
///      Transfer (whose total includes bridge change).
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
/// Returns the recipient leg in asset units. The route-level amount
/// cross-check is built from this, not from the wire-supplied
/// `psbt_output_amount`.
#[cfg(feature = "rgb-validation")]
pub fn validate_psbt_anchors_transition(
    psbt: &Psbt,
    validated: &ValidatedConsignment,
    source_amount: u64,
    source_commission: u64,
    self_owned: SelfOwnedOutpoint<'_>,
) -> Result<u64> {
    use std::collections::BTreeSet;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT requires a consignment with at least one transition".into(),
        )
    })?;
    if !binds_psbt_amounts(last.transition_type) {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB PSBT requires a transition with a defined amount bind (last \
             transition_type = {}, want {BOUND_TRANSITION_TYPES})",
            last.transition_type
        )));
    }

    // Derive the txid from `unsigned_tx`, never a finalized/extracted tx
    // (a non-segwit input's scriptSig would change the txid post-signing).
    let expected = validated.last_transfer_witness_txid.ok_or_else(|| {
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
    // The per-shape amount rules below cover only the shapes `binds_psbt_amounts`
    // admits.
    for t in &committed {
        if !binds_psbt_amounts(t.transition_type) {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB PSBT commits transition {} of type {} - requires \
                 {BOUND_TRANSITION_TYPES}",
                t.op_id, t.transition_type
            )));
        }
    }

    // `asset_output_amount`, not `total_output_amount`: `OS_INFLATION` outputs
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

    // A mixed mint/transfer group has no single aggregate rule (equality vs
    // floor), and no known flow produces one. Refuse rather than guess.
    // Must be the same predicate validation uses, or a BFA mint would count as a
    // transfer here and inherit the lower-bound rule, which accepts an over-mint.
    let mints = committed
        .iter()
        .filter(|t| is_mint_transition(t.transition_type))
        .count();
    // The marker selects the amount RULE, not the literal transition type: every
    // mint shape, IFA or BFA, takes the equality branch below.
    let group_type = if mints == committed.len() {
        ifa::TS_INFLATION
    } else if mints == 0 {
        ifa::TS_TRANSFER
    } else {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB PSBT commits a mixed bundle ({mints} mint of {} transitions) - \
             refusing to sign a shape with no defined amount bind",
            committed.len()
        )));
    };

    let net_credited = source_amount.saturating_sub(source_commission);
    match group_type {
        // Inflation (mint-RGB): no pre-existing allocation to return as
        // change, so minted units must equal the credit. Surplus = over-mint.
        ifa::TS_INFLATION => {
            if committed_asset_output != net_credited {
                return Err(EnclaveError::CrossCheck(format!(
                    "mint-RGB amount mismatch: consignment asset_output_amount \
                     ({committed_asset_output}) != net credited (source_amount {source_amount} - \
                     source_commission {source_commission} = {net_credited})"
                )));
            }
        }
        // Transfer (pools send): `asset_output_amount` is recipient + bridge
        // change, so only a lower bound is meaningful here. The per-output bind
        // below pins the recipient leg.
        ifa::TS_TRANSFER => {
            if committed_asset_output < net_credited {
                return Err(EnclaveError::CrossCheck(format!(
                    "send-RGB amount mismatch: consignment asset_output_amount \
                     ({committed_asset_output}) < net credited (source_amount {source_amount} - \
                     source_commission {source_commission} = {net_credited})"
                )));
            }
        }
        // Unreachable: the gate above admits only the two shapes. Spelled out
        // so a new transition type cannot silently inherit the Transfer rule.
        other => {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB transition type {other} has no amount bind defined - refusing to sign"
            )));
        }
    }

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

    Ok(legs.recipient)
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
///     then its `script_pubkey` must be an input script we co-control.
#[cfg(feature = "rgb-validation")]
pub type SelfOwnedOutpoint<'a> = &'a dyn Fn(&Psbt, bitcoin::OutPoint) -> Result<bool>;

/// Cap on distinct off-transaction outpoints resolved per PSBT. Each costs an
/// indexer round-trip, so an unbounded count would let one request amplify into
/// many egress calls. A real transfer uses one; the slack is for bundles.
#[cfg(feature = "rgb-validation")]
pub const MAX_OFF_TX_CHANGE_OUTPOINTS: usize = 4;

/// The two legs an `OS_ASSET` output assignment can belong to, in asset units.
#[cfg(feature = "rgb-validation")]
struct AssetLegs {
    /// Paid to confidential (blinded) seals - the recipient.
    recipient: u64,
    /// Returned to revealed seals on Bitcoin outputs this enclave provably
    /// controls - bridge change.
    change: u64,
}

/// Split the `OS_ASSET` outputs of every transition the signed tx commits into
/// recipient and change, rejecting anything that is provably neither.
///
/// Takes the whole committed group, not one transition: otherwise value routed
/// by a sibling transition escapes the bind. `OS_INFLATION` entries are skipped
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
        .filter(|o| o.assignment_type == ifa::OS_ASSET)
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
    };
    for (i, out) in asset_outputs.iter().enumerate() {
        match &out.seal {
            OutputSeal::Confidential { .. } => {
                legs.recipient = legs.recipient.checked_add(out.amount).ok_or_else(|| {
                    EnclaveError::CrossCheck(
                        "send-RGB recipient leg total overflows u64 asset units".into(),
                    )
                })?;
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
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    /// Minimal BIP-174-valid PSBT: one dummy input, one dummy output, no
    /// signatures. Stand-in for tests that exercise the fields around the PSBT
    /// rather than its contents.
    fn minimal_valid_psbt_bytes() -> Vec<u8> {
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                        [0u8; 32],
                    )),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        Psbt::from_unsigned_tx(unsigned_tx)
            .expect("from_unsigned_tx")
            .serialize()
    }

    // PSBT shape whitelist tests

    #[test]
    fn accepts_valid_psbt_bytes() {
        assert!(validate_psbt_bytes(&minimal_valid_psbt_bytes()).is_ok());
    }

    #[test]
    fn rejects_empty_psbt_bytes() {
        let err = validate_psbt_bytes(&[]).unwrap_err();
        assert!(err.to_string().contains("psbt_bytes is empty"));
    }

    // PSBT shape whitelist rejection tests

    #[test]
    fn rejects_garbage_psbt_bytes() {
        // Long enough to clear the empty-bytes guard but not a BIP-174 PSBT.
        let err = validate_psbt_bytes(&[0xFF; 100]).unwrap_err();
        assert!(
            err.to_string().contains("not a valid PSBT"),
            "expected PSBT parse rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_truncated_psbt_below_magic() {
        // Shorter than the 5-byte BIP-174 magic prefix.
        let err = validate_psbt_bytes(&[0x70, 0x73]).unwrap_err();
        assert!(
            err.to_string().contains("not a valid PSBT"),
            "expected PSBT parse rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_psbt_with_no_inputs() {
        // Build a PSBT whose unsigned tx has zero inputs. BIP-174 lets us
        // serialise it; the validation layer is what enforces the
        // "something to sign" invariant.
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
        let err = validate_psbt_bytes(&psbt.serialize()).unwrap_err();
        assert!(
            err.to_string().contains("no inputs"),
            "expected no-inputs rejection, got: {err}"
        );
    }

    // Operation-dedup key - `psbt_operation_key`

    #[test]
    fn op_key_is_deterministic() {
        let a = psbt_operation_key(1, &[0x11; 20], &[0xAA; 32], &[0x07; 32], "rgb:asset");
        let b = psbt_operation_key(1, &[0x11; 20], &[0xAA; 32], &[0x07; 32], "rgb:asset");
        assert_eq!(a, b);
    }

    #[test]
    fn op_key_varies_with_every_field() {
        let base = psbt_operation_key(1, &[0x11; 20], &[0xAA; 32], &[0x07; 32], "rgb:asset");
        assert_ne!(
            base,
            psbt_operation_key(2, &[0x11; 20], &[0xAA; 32], &[0x07; 32], "rgb:asset"),
            "chain_id must change the key"
        );
        assert_ne!(
            base,
            psbt_operation_key(1, &[0x22; 20], &[0xAA; 32], &[0x07; 32], "rgb:asset"),
            "bridge_contract must change the key"
        );
        assert_ne!(
            base,
            psbt_operation_key(1, &[0x11; 20], &[0xBB; 32], &[0x07; 32], "rgb:asset"),
            "evm_tx_hash must change the key"
        );
        assert_ne!(
            base,
            psbt_operation_key(1, &[0x11; 20], &[0xAA; 32], &[0x08; 32], "rgb:asset"),
            "funds_in_operation_id must change the key"
        );
        assert_ne!(
            base,
            psbt_operation_key(1, &[0x11; 20], &[0xAA; 32], &[0x07; 32], "rgb:other"),
            "rgb_asset_id must change the key"
        );
    }

    #[test]
    fn op_key_length_prefix_blocks_concatenation_collision() {
        // Without length-prefixing the variable fields, moving a byte across a
        // field boundary would collide. The prefix must keep these distinct.
        // evm_tx_hash / operationId are fixed at 32 bytes in practice, but the
        // key fn must not rely on that for separation.
        let k1 = psbt_operation_key(1, &[0x11; 20], b"AB", b"X", "C");
        let k2 = psbt_operation_key(1, &[0x11; 20], b"A", b"X", "BC");
        assert_ne!(k1, k2);
    }

    // Operation dedup end-to-end - `psbt_operation_key` + the soft replay guard.
    // Encodes the properties the EVM->RGB path relies on the guard for.
    mod operation_dedup {
        use crate::error::EnclaveError;
        use crate::networks::rgb::psbt_validation::psbt_operation_key;
        use crate::state::NonceReplayGuard;
        use std::time::Duration;

        // A representative EVM->RGB operation key. Mirrors the server call site:
        // pinned chain/contract, the request tx hash, the canonical on-chain
        // `funds_in_operation_id`, and the RGB asset id.
        fn op_key(tx: &[u8], funds_in_operation_id: &[u8]) -> [u8; 32] {
            psbt_operation_key(1, &[0x11; 20], tx, funds_in_operation_id, "rgb:asset")
        }

        fn guard() -> NonceReplayGuard {
            NonceReplayGuard::with_capacity(1000, Duration::from_secs(24 * 60 * 60))
        }

        #[test]
        fn same_operation_is_rejected_within_one_instance() {
            // A deposit signed once is refused on a same-op resubmission while
            // the record is live (honest-listener-retry / naive-replay case).
            let g = guard();
            let k = op_key(&[0xAA; 32], &[0x07; 32]);
            g.reserve(k)
                .expect("first signing reserves the op")
                .commit();
            assert!(
                matches!(g.reserve(k), Err(EnclaveError::NonceReplay)),
                "the same operation must be refused as a replay"
            );
        }

        #[test]
        fn a_different_deposit_is_not_a_false_replay() {
            // A different canonical operationId is a different deposit and signs.
            let g = guard();
            g.reserve(op_key(&[0xAA; 32], &[0x07; 32]))
                .expect("first")
                .commit();
            g.reserve(op_key(&[0xAA; 32], &[0x08; 32]))
                .expect("a different funds_in_operation_id is a different op")
                .commit();
        }

        #[test]
        fn restart_or_sibling_instance_admits_the_same_operation_again() {
            // The guard is in-memory and per-instance: a fresh instance (an
            // enclave restart, or a sibling enclave the host routed the duplicate
            // to) has never seen the record and admits the same op again. This
            // documents WHY the durable cross-instance exactly-once anchor lives
            // on-chain (consumedBurnIds / fundsInRecords), not in this soft guard.
            let k = op_key(&[0xAA; 32], &[0x07; 32]);
            let first = guard();
            first.reserve(k).expect("instance A reserves").commit();
            assert!(matches!(first.reserve(k), Err(EnclaveError::NonceReplay)));

            let second = guard(); // restart / sibling enclave
            assert!(
                second.reserve(k).is_ok(),
                "a fresh instance does not share the soft guard - on-chain state \
                 is the durable anchor"
            );
        }
    }

    // send-RGB anchoring - `validate_psbt_anchors_transition`
    #[cfg(feature = "rgb-validation")]
    mod fee_rate {
        use super::*;

        /// One segwit-ish input carrying `witness_utxo` of `input_sats`, one
        /// output of `output_sats` - so `Psbt::fee()` = input - output.
        fn psbt_with_fee(input_sats: u64, output_sats: u64) -> Psbt {
            let unsigned_tx = Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                            [0x11; 32],
                        )),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(output_sats),
                    script_pubkey: ScriptBuf::new(),
                }],
            };
            let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
            psbt.inputs[0].witness_utxo = Some(TxOut {
                value: Amount::from_sat(input_sats),
                script_pubkey: ScriptBuf::new(),
            });
            psbt
        }

        #[test]
        fn accepts_fee_rate_at_headroom() {
            // rate == FEE_RATE_HEADROOM x recommended must pass (boundary is
            // inclusive: reject only strictly above the cap).
            let recommended = 10.0;
            let vsize = psbt_with_fee(100_000, 100_000).unsigned_tx.vsize() as u64;
            let fee_at_cap = (FEE_RATE_HEADROOM * recommended) as u64 * vsize;
            let psbt = psbt_with_fee(100_000, 100_000 - fee_at_cap);
            assert!(check_psbt_fee_rate(&psbt, recommended).is_ok());
        }

        #[test]
        fn rejects_fee_rate_above_headroom() {
            // One extra sat/vB above the cap -> reject; nothing else about the
            // PSBT is wrong, so the error must be the fee-rate one.
            let recommended = 10.0;
            let vsize = psbt_with_fee(100_000, 100_000).unsigned_tx.vsize() as u64;
            let fee_over_cap = ((FEE_RATE_HEADROOM * recommended) as u64 + 1) * vsize;
            let psbt = psbt_with_fee(100_000, 100_000 - fee_over_cap);
            let err = check_psbt_fee_rate(&psbt, recommended).unwrap_err();
            assert!(
                err.to_string().contains("fee rate too high"),
                "expected fee-rate rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_psbt_without_utxo_data() {
            // No witness_utxo/non_witness_utxo -> the fee is uncomputable and
            // the check must fail closed, not skip.
            let psbt = Psbt::deserialize(&minimal_valid_psbt_bytes()).unwrap();
            let err = check_psbt_fee_rate(&psbt, 10.0).unwrap_err();
            assert!(
                err.to_string().contains("cannot compute PSBT fee"),
                "expected uncomputable-fee rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_nan_recommendation() {
            // A NaN limit must reject (the comparison is written as
            // `!(rate <= limit)` so NaN can never pass). The recommendation
            // is validated upstream, but the check must not rely on that.
            let psbt = psbt_with_fee(100_000, 99_000);
            assert!(check_psbt_fee_rate(&psbt, f64::NAN).is_err());
        }
    }

    #[cfg(feature = "rgb-validation")]
    mod anchor {
        use super::*;
        use crate::networks::rgb::validation::{
            ifa, OutputSeal, TransitionOutput, TransitionSummary, ValidatedConsignment,
        };
        use bitcoin::psbt::PsbtSighashType;
        use bitcoin::{OutPoint, Txid};

        /// Build a two-input, one-output unsigned tx + its Psbt. The two
        /// prevouts are deterministic so a test can reproduce the exact
        /// witness-tx input set.
        fn psbt_with_two_inputs() -> Psbt {
            let mk_outpoint = |seed: u8, vout: u32| OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                    [seed; 32],
                )),
                vout,
            };
            let unsigned_tx = Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: mk_outpoint(0x11, 0),
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    },
                    TxIn {
                        previous_output: mk_outpoint(0x22, 1),
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    },
                ],
                // vout 0 is the recipient's Bitcoin payment, vout 1 the slot a
                // bridge change seal points at.
                output: vec![
                    TxOut {
                        value: Amount::from_sat(1_000),
                        script_pubkey: ScriptBuf::new(),
                    },
                    TxOut {
                        value: Amount::from_sat(2_000),
                        script_pubkey: ScriptBuf::new(),
                    },
                ],
            };
            Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx")
        }

        /// Stand-in ownership oracles. Fn items coerce to `SelfOwnedOutpoint`.
        fn owns_nothing(_: &Psbt, _: OutPoint) -> Result<bool> {
            Ok(false)
        }
        fn owns_vout_1(psbt: &Psbt, outpoint: OutPoint) -> Result<bool> {
            Ok(outpoint.txid == psbt.unsigned_tx.compute_txid() && outpoint.vout == 1)
        }
        /// Owns vout 0 of [`OFF_TX_SEED`] - an existing wallet UTXO.
        fn owns_off_tx_outpoint(_: &Psbt, outpoint: OutPoint) -> Result<bool> {
            Ok(outpoint == off_tx_outpoint())
        }

        /// A recipient leg: paid to a blinded (`utxob:...`) seal.
        fn confidential(amount: u64) -> TransitionOutput {
            TransitionOutput {
                assignment_type: ifa::OS_ASSET,
                amount,
                seal: OutputSeal::Confidential {
                    secret_seal: "utxob:test-seal".into(),
                },
            }
        }

        /// A change leg: revealed on `vout` of the witness tx being signed
        /// (`txid: None`, exactly as the in-tree transfer fixture encodes it).
        fn revealed(amount: u64, vout: u32) -> TransitionOutput {
            TransitionOutput {
                assignment_type: ifa::OS_ASSET,
                amount,
                seal: OutputSeal::Revealed { txid: None, vout },
            }
        }

        /// Display-order seal bytes for the off-transaction change UTXO.
        const OFF_TX_SEED: [u8; 32] = [0x77; 32];

        /// The same outpoint as a `bitcoin::OutPoint` (internal byte order).
        fn off_tx_outpoint() -> OutPoint {
            let mut internal = OFF_TX_SEED;
            internal.reverse();
            OutPoint {
                txid: Txid::from_byte_array(internal),
                vout: 0,
            }
        }

        /// A change leg on an existing wallet UTXO: an explicit txid that is
        /// NOT the tx being signed. Emitted when there is no BTC change.
        fn revealed_off_tx(amount: u64) -> TransitionOutput {
            TransitionOutput {
                assignment_type: ifa::OS_ASSET,
                amount,
                seal: OutputSeal::Revealed {
                    txid: Some(OFF_TX_SEED),
                    vout: 0,
                },
            }
        }

        fn transfer_summary(outputs: Vec<TransitionOutput>) -> TransitionSummary {
            summary("transfer-op", ifa::TS_TRANSFER, outputs)
        }

        fn summary(
            op_id: &str,
            transition_type: u16,
            outputs: Vec<TransitionOutput>,
        ) -> TransitionSummary {
            let asset_output_amount = outputs
                .iter()
                .filter(|o| o.assignment_type == ifa::OS_ASSET)
                .map(|o| o.amount)
                .sum();
            TransitionSummary {
                op_id: op_id.into(),
                transition_type,
                total_output_amount: outputs.iter().map(|o| o.amount).sum(),
                asset_output_amount,
                outputs,
                burned_asset_amount: None,
                burn_recipient: None,
            }
        }

        /// A ValidatedConsignment bound to `psbt`'s actual txid + prevouts,
        /// paying `recipient_amount` to a single blinded seal and nothing
        /// back as change. The "happy" baseline every test then mutates.
        fn validated_for(psbt: &Psbt, recipient_amount: u64) -> ValidatedConsignment {
            validated_with(psbt, vec![confidential(recipient_amount)])
        }

        /// [`validated_for`] with the output legs of a single transition given
        /// explicitly.
        fn validated_with(psbt: &Psbt, outputs: Vec<TransitionOutput>) -> ValidatedConsignment {
            validated_from(psbt, vec![transfer_summary(outputs)])
        }

        /// A ValidatedConsignment whose signed witness tx commits the whole
        /// `transitions` bundle - the multi-transition shape the per-output
        /// bind has to cover.
        fn validated_from(
            psbt: &Psbt,
            transitions: Vec<TransitionSummary>,
        ) -> ValidatedConsignment {
            let prevouts = psbt
                .unsigned_tx
                .input
                .iter()
                .map(|txin| txin.previous_output)
                .collect();
            let txid = psbt.unsigned_tx.compute_txid();
            ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: transitions.iter().map(|t| t.op_id.clone()).collect(),
                mint_op_ids: vec![],
                last_transition: transitions.last().cloned(),
                last_transfer_witness_txid: Some(txid),
                last_transfer_witness_prevouts: Some(prevouts),
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
                transitions_by_witness: vec![(txid, transitions)],
            }
        }

        /// Apply `f` to the signing transition everywhere the validated
        /// consignment records it. `last_transition` and
        /// `transitions_by_witness` are two views of the same data, so a test
        /// that edits only one would leave the binds reading stale values.
        fn edit_signing_transition(
            validated: &mut ValidatedConsignment,
            f: impl Fn(&mut TransitionSummary),
        ) {
            if let Some(ref mut last) = validated.last_transition {
                f(last);
            }
            for (_, transitions) in validated.transitions_by_witness.iter_mut() {
                for t in transitions.iter_mut() {
                    f(t);
                }
            }
        }

        #[test]
        fn passes_when_txid_inputs_and_amount_match() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_for(&psbt, 1_000);
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1).is_ok()
            );
        }

        /// The production pools-send shape: the recipient is paid exactly the
        /// credited amount on a blinded seal, and the rest of the bridge's
        /// allocation returns as change on a revealed seal pointing at an
        /// output we control. `asset_output_amount` (5_000) exceeding
        /// `net_credited` (900) is fine - the surplus is provably ours.
        #[test]
        fn passes_when_change_returns_to_a_bridge_owned_seal() {
            let psbt = psbt_with_two_inputs();
            // net credited = 1_000 - 100 = 900
            let validated = validated_with(&psbt, vec![confidential(900), revealed(4_100, 1)]);
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 100, &owns_vout_1)
                    .is_ok()
            );
        }

        /// The over-send this whole bind exists for: a genuine
        /// 1_000-unit deposit, and a consignment that is rgbstd-valid, anchored
        /// to this exact PSBT, and pays 10_000_000 units to a blinded seal the
        /// attacker controls. Every other leg of the cross-check passes; the
        /// aggregate bound (`asset_output_amount >= net_credited`) passes
        /// vacuously. Only the recipient bind catches it.
        #[test]
        fn rejects_over_send_to_a_blinded_seal() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_with(&psbt, vec![confidential(10_000_000)]);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("recipient amount mismatch"),
                "expected over-send rejection, got: {err}"
            );
        }

        /// The same drain routed through a *revealed* seal instead of a blinded
        /// one. Counting revealed legs as change unconditionally would let this
        /// through, so a revealed output we cannot prove is ours is refused.
        #[test]
        fn rejects_change_on_an_output_we_do_not_control() {
            let psbt = psbt_with_two_inputs();
            let validated =
                validated_with(&psbt, vec![confidential(1_000), revealed(10_000_000, 1)]);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_nothing)
                .unwrap_err();
            assert!(
                err.to_string().contains("cannot prove it controls"),
                "expected unowned-change rejection, got: {err}"
            );
        }

        /// A revealed seal naming a vout that does not exist on this tx is
        /// equally unownable, and must be refused rather than ignored.
        #[test]
        fn rejects_change_on_an_out_of_range_vout() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_with(&psbt, vec![confidential(1_000), revealed(500, 9)]);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("cannot prove it controls"),
                "expected out-of-range-vout rejection, got: {err}"
            );
        }

        /// With no BTC change, rgb-lib parks the RGB change on an existing
        /// UTXO. Legitimate, on the same terms: the outpoint must be ours.
        #[test]
        fn passes_when_change_lands_on_an_existing_bridge_utxo() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_with(&psbt, vec![confidential(900), revealed_off_tx(4_100)]);
            let recipient =
                validate_psbt_anchors_transition(&psbt, &validated, 900, 0, &owns_off_tx_outpoint)
                    .expect("off-tx change on a bridge-owned UTXO binds");
            assert_eq!(recipient, 900);
        }

        /// Same shape, outpoint we cannot prove. Accepting it unconditionally
        /// would hand the change to whoever the host names.
        #[test]
        fn rejects_off_tx_change_on_an_outpoint_we_cannot_prove() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_with(&psbt, vec![confidential(900), revealed_off_tx(4_100)]);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 900, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("cannot prove it controls"),
                "expected unprovable off-tx change rejection, got: {err}"
            );
        }

        /// A bundle naming more than [`MAX_OFF_TX_CHANGE_OUTPOINTS`] outpoints
        /// is refused before the egress, not after.
        #[test]
        fn rejects_too_many_distinct_off_tx_outpoints() {
            let psbt = psbt_with_two_inputs();
            let mut outputs = vec![confidential(900)];
            for i in 0..=(MAX_OFF_TX_CHANGE_OUTPOINTS as u8) {
                outputs.push(TransitionOutput {
                    assignment_type: ifa::OS_ASSET,
                    amount: 10,
                    seal: OutputSeal::Revealed {
                        txid: Some([0xB0 + i; 32]),
                        vout: 0,
                    },
                });
            }
            let validated = validated_with(&psbt, outputs);
            // Owns everything: the cap must bite on the count, not a verdict.
            let owns_everything = |_: &Psbt, _: OutPoint| Ok(true);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 900, 0, &owns_everything)
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("distinct off-transaction change outpoints"),
                "expected off-tx lookup cap rejection, got: {err}"
            );
        }

        /// Several change legs on one UTXO must hit the memo, not the indexer.
        #[test]
        fn resolves_a_repeated_off_tx_outpoint_only_once() {
            use std::cell::Cell;
            let psbt = psbt_with_two_inputs();
            let validated = validated_with(
                &psbt,
                vec![
                    confidential(900),
                    revealed_off_tx(2_000),
                    revealed_off_tx(2_100),
                ],
            );
            let calls = Cell::new(0usize);
            let oracle = |_: &Psbt, outpoint: OutPoint| {
                calls.set(calls.get() + 1);
                Ok(outpoint == off_tx_outpoint())
            };
            validate_psbt_anchors_transition(&psbt, &validated, 900, 0, &oracle)
                .expect("two legs on one owned UTXO bind");
            assert_eq!(calls.get(), 1, "the outpoint verdict should be memoised");
        }

        /// At per-output granularity: an `OS_INFLATION` entry is mint
        /// *capacity*, not value delivered, so it must not be able to stand in
        /// for the recipient leg.
        #[test]
        fn inflation_allowance_output_is_not_a_recipient_leg() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_with(&psbt, vec![confidential(1_000)]);
            edit_signing_transition(&mut validated, |t| {
                t.transition_type = ifa::TS_INFLATION;
                // Allowance rides along confidentially. It must be skipped by
                // the recipient sum, leaving 1_000 == net credited.
                t.outputs.push(TransitionOutput {
                    assignment_type: ifa::OS_INFLATION,
                    amount: 9_000_000,
                    seal: OutputSeal::Confidential {
                        secret_seal: "utxob:allowance".into(),
                    },
                });
                t.total_output_amount = 9_001_000;
            });
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1).is_ok(),
                "OS_INFLATION allowance must not count toward the recipient leg"
            );
        }

        /// A transition with no `OS_ASSET` assignments at all delivers nothing,
        /// so there is nothing to bind the credit to - fail closed rather than
        /// treat a zero recipient sum as satisfying a zero credit.
        #[test]
        fn rejects_transition_without_asset_outputs() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_with(&psbt, vec![confidential(1_000)]);
            edit_signing_transition(&mut validated, |t| t.outputs = vec![]);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("no OS_ASSET output assignments"),
                "expected no-asset-output rejection, got: {err}"
            );
        }

        /// One Bitcoin tx commits a *bundle*, which can hold several
        /// transitions. Binding only the consignment's last one lets an
        /// attacker park the drain in a sibling: here the last transition is
        /// perfectly sized (1_000 = the credit) while its sibling ships
        /// 10_000_000 to a blinded seal. Both are committed by the tx being
        /// signed, so both must be bound.
        #[test]
        fn rejects_over_send_in_a_sibling_transition() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_from(
                &psbt,
                vec![
                    summary("drain-op", ifa::TS_TRANSFER, vec![confidential(10_000_000)]),
                    summary("decoy-op", ifa::TS_TRANSFER, vec![confidential(1_000)]),
                ],
            );
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("recipient amount mismatch"),
                "expected sibling-transition rejection, got: {err}"
            );
        }

        /// The legitimate multi-transition shape: a send funded from two
        /// bridge UTXOs, so the bundle carries two transitions whose recipient
        /// legs sum to the credit and whose change returns to us.
        #[test]
        fn passes_when_a_bundle_splits_the_payout_across_transitions() {
            let psbt = psbt_with_two_inputs();
            // net credited = 1_000 - 100 = 900, paid 400 + 500.
            let validated = validated_from(
                &psbt,
                vec![
                    summary(
                        "leg-a",
                        ifa::TS_TRANSFER,
                        vec![confidential(400), revealed(2_000, 1)],
                    ),
                    summary("leg-b", ifa::TS_TRANSFER, vec![confidential(500)]),
                ],
            );
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 100, &owns_vout_1)
                    .is_ok()
            );
        }

        /// A bundle mixing mint and transfer has no single correct aggregate
        /// rule (equality vs floor), so it is refused rather than guessed at.
        #[test]
        fn rejects_mixed_mint_and_transfer_bundle() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_from(
                &psbt,
                vec![
                    summary("mint-op", ifa::TS_INFLATION, vec![confidential(500)]),
                    summary("send-op", ifa::TS_TRANSFER, vec![confidential(500)]),
                ],
            );
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("mixed bundle"),
                "expected mixed-bundle rejection, got: {err}"
            );
        }

        /// The txid bind can pass while the consignment commits its
        /// transitions to a different witness entry. Nothing would then be
        /// amount-bound, so an empty group is a rejection, not a free pass.
        #[test]
        fn rejects_when_no_transition_is_committed_by_the_signed_tx() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            let other =
                Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x77; 32]));
            validated.transitions_by_witness[0].0 = other;
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("commits no transition"),
                "expected uncommitted-witness rejection, got: {err}"
            );
        }

        /// The two consignment walks (flat parser vs rgbstd) must agree on
        /// which operation the signed tx carries. If `last_transition` is not
        /// in the committed group, every downstream bind describes a different
        /// operation than the one being signed.
        #[test]
        fn rejects_last_transition_not_in_the_committed_group() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transition.as_mut().unwrap().op_id = "some-other-op".into();
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("is not committed by the"),
                "expected walk-disagreement rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_txid_mismatch() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transfer_witness_txid = Some(Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xAB; 32]),
            ));
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("does not finalize the consignment's transition"),
                "expected txid-mismatch rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_missing_witness_txid() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transfer_witness_txid = None;
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("carries no witness txid"),
                "expected missing-txid rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_prevout_set_mismatch() {
            // txid still matches (we don't touch it), but the recorded prevout
            // set differs - the canary must fire.
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transfer_witness_prevouts = Some(vec![OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                    [0x99; 32],
                )),
                vout: 7,
            }]);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("input outpoints do not match"),
                "expected prevout-mismatch rejection, got: {err}"
            );
        }

        #[test]
        fn skips_prevout_canary_when_witness_tx_not_embedded() {
            // PubWitness::Txid only -> prevouts None -> txid bind alone carries.
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transfer_witness_prevouts = None;
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1).is_ok()
            );
        }

        /// The mint-RGB shape - an IFA Inflation last transition - binds
        /// through the same anchor path as the pools-mode Transfer.
        #[test]
        fn accepts_inflation_shape() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            edit_signing_transition(&mut validated, |t| t.transition_type = ifa::TS_INFLATION);
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1).is_ok()
            );
        }

        /// For a mint, only `OS_ASSET`-typed outputs (the actually
        /// minted units) may cover the credited amount - the `OS_INFLATION`
        /// allowance (mint capacity) counted in `total_output_amount` must
        /// not.
        #[test]
        fn inflation_allowance_does_not_cover_credited_amount() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            edit_signing_transition(&mut validated, |t| {
                t.transition_type = ifa::TS_INFLATION;
                // Minted 999 units; a large allowance rides along in the
                // total. Net credited is 1_000 - must be rejected on the
                // asset sum, not covered by the allowance-inflated total.
                t.asset_output_amount = 999;
                t.total_output_amount = 1_000_000;
            });
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("asset_output_amount (999)"),
                "expected asset-amount rejection, got: {err}"
            );
        }

        /// A mint whose `OS_ASSET` output EXCEEDS the credited amount is an
        /// over-mint and must be rejected. The old one-sided lower bound
        /// (`asset_output_amount < net_credited`) accepted this surplus; the
        /// inflation path now requires exact equality.
        #[test]
        fn rejects_mint_over_mint() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            edit_signing_transition(&mut validated, |t| {
                t.transition_type = ifa::TS_INFLATION;
                // Minted 1_500 against a 1_000 credit -> 500 over-mint.
                t.asset_output_amount = 1_500;
                t.total_output_amount = 1_500;
            });
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("mint-RGB amount mismatch"),
                "expected over-mint rejection, got: {err}"
            );
        }

        /// A BFA mint takes the mint rule, so a surplus over the credited amount is
        /// refused. Under the transfer rule it would pass as change.
        #[cfg(feature = "bfa-mint")]
        #[test]
        fn bfa_mint_surplus_is_refused_like_an_inflation_surplus() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            edit_signing_transition(&mut validated, |t| t.transition_type = bfa::TS_BRIDGE);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 900, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("mint-RGB amount mismatch"),
                "a bridge mint must use the equality rule, got: {err}"
            );
        }

        #[test]
        fn rejects_non_transfer_transition() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            edit_signing_transition(&mut validated, |t| t.transition_type = ifa::TS_BURN);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("defined amount bind"),
                "expected an amount-bind rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_amount_under_net_credited() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_for(&psbt, 999);
            // net credited = 1_000 - 0 = 1_000 > 999
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("amount mismatch"),
                "expected amount-mismatch rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_non_all_sighash() {
            let psbt = {
                let mut p = psbt_with_two_inputs();
                // SIGHASH_SINGLE | ANYONECANPAY = 0x83 - spliceable.
                p.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0x83));
                p
            };
            let validated = validated_for(&psbt, 1_000);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string().contains("non-ALL sighash"),
                "expected sighash rejection, got: {err}"
            );
        }

        #[test]
        fn accepts_sighash_all_and_default() {
            for raw in [0x00u32, 0x01u32] {
                let mut psbt = psbt_with_two_inputs();
                psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(raw));
                let validated = validated_for(&psbt, 1_000);
                assert!(
                    validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                        .is_ok(),
                    "sighash 0x{raw:02x} should be accepted"
                );
            }
        }
    }
}
