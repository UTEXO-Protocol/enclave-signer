use bitcoin::psbt::Psbt;

#[cfg(feature = "rgb-validation")]
use super::validation::{ifa, ValidatedConsignment};
use crate::error::{EnclaveError, Result};

/// Derive the soft-dedup key for an EVM→RGB bridge PSBT operation.
///
/// 32-byte keccak over `(chain_id, bridge_contract, evm_tx_hash,
/// funds_in_operation_id, rgb_asset_id)`. `chain_id` and `bridge_contract` come
/// from the enclave's **pinned** [`crate::config::BridgeConfig`] (not the
/// request), so they can't be varied per-call. `funds_in_operation_id` is the
/// canonical on-chain `BridgeFundsIn.operationId` (bytes32), already verified
/// against the deposit log by
/// [`crate::networks::evm::evm_event::verify_funds_in_event`] — so the key is
/// derived from an authentic, canonical identifier rather than the
/// host-supplied `operation_idx` (audit M-02). The variable-length fields are
/// length-prefixed and a domain tag is mixed in so two distinct tuples can't
/// hash to the same key by concatenation ambiguity.
///
/// Consumed by the **soft** in-memory replay guard
/// ([`crate::state::EnclaveState::op_replay_guard`]) — see its doc for why
/// this is defense-in-depth and not a sufficient double-spend control (#84).
/// The guard is in-memory and volatile, so the key changing when the operator
/// adds a deployment costs at most one TTL window of dedup, with nothing to
/// migrate.
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
///   (c) PSBTs with no inputs — there's literally nothing to sign, and the
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
            "psbt has no inputs — nothing to sign".into(),
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
/// In this flow the PSBT being signed **is** the RGB transfer's witness
/// transaction: the Bitcoin tx that spends the bridge's UTXOs holding the RGB
/// allocation and carries the tapret/opret DBC commitment to the
/// state-transition bundle. Without this check the signing path has no link
/// between the PSBT and the consignment, so a compromised host could get the
/// enclave to sign a PSBT that moves bridge BTC without committing to the
/// claimed RGB state.
///
/// Must be called only **after** [`crate::networks::rgb::validation::RgbValidator::
/// validate_consignment`] has run full rgbstd validation — the txid-identity
/// argument below is worthless otherwise (an attacker could put any tx in the
/// consignment and a matching `unsigned_tx`; only `validate()` proves the
/// commitment is genuinely anchored).
///
/// Enforces, fail-closed:
///   1. The consignment's last transition is an IFA `Transfer`
///      (`ifa::TS_TRANSFER`, the pools-mode send shape) or an IFA
///      `Inflation` (`ifa::TS_INFLATION`, the mint-RGB shape — #54).
///   2. **Identity bind:** `psbt.unsigned_tx.compute_txid()` equals the
///      consignment's last witness txid. A segwit txid commits to every
///      non-witness field (all inputs, all outputs incl. the commitment
///      output), and rgbstd proved that transition's commitment lives in the
///      tx with this txid — so equality means signing this PSBT finalizes
///      exactly the validated transition, and every input is anchored.
///   3. **Per-input canary:** when the consignment embeds the full witness tx,
///      the set of PSBT input outpoints must equal the witness tx's input
///      prevout set. Redundant given (2); a mismatch signals a broken
///      consignment/encoding invariant and is rejected loudly.
///   4. **Sighash guard:** refuse any input requesting a sighash other than
///      ALL / taproot-DEFAULT, so a host can't splice our signature into a
///      different tx (ANYONECANPAY / SINGLE / NONE).
///   5. **Whole-bundle scope:** a Bitcoin transaction commits a *bundle*, which
///      may hold several RGB transitions. Both amount binds below run over
///      **every** transition the signed txid commits, not just the consignment's
///      last one — otherwise a large transfer parked earlier in the bundle moves
///      value that nothing checks. The group must be non-empty, must contain the
///      transition the rest of the pipeline calls "last" (a canary against the
///      flat-parser and rgbstd walks disagreeing), must be all-Transfer or
///      all-Inflation, and every member must be one of those two shapes.
///   6. **Aggregate amount bind:** the group's summed `asset_output_amount` (the
///      `OS_ASSET`-typed allocations only — excluding the `OS_INFLATION`
///      mint-capacity outputs) is bound to the net amount credited by the
///      source side (`source_amount` minus `source_commission`): exact equality
///      for an Inflation (a fresh mint has no pre-existing allocation to return
///      as change, so any surplus is an over-mint), a coverage lower bound for a
///      Transfer (whose total legitimately includes bridge change).
///   7. **Per-output recipient bind (W-06 / #52):** the aggregate bind above
///      says nothing about *where* the value goes, so on its own it lets a
///      compromised host have the enclave sign an arbitrarily large payout as
///      long as the total merely covers the credit. Each `OS_ASSET` output
///      assignment is therefore classified by its seal and the legs are bound
///      separately:
///      * a **confidential** (`utxob:…` blinded) seal is a *recipient* leg —
///        the shape the bridge pays a user on;
///      * a **revealed** (`txid:vout`) seal is only credible as *bridge change*,
///        so it must name a vout of **this** witness tx **and** that Bitcoin
///        output must be provably ours (`self_owned`, which resolves through
///        [`crate::networks::rgb::btc_ownership`]). A revealed seal pointing
///        anywhere else is a payout to an unverifiable destination and is
///        rejected outright rather than silently counted as change.
///
///      The recipient total must then equal `net_credited` **exactly**, in both
///      directions.
///
/// `self_owned` resolves which of the PSBT's Bitcoin outputs pay back to this
/// enclave. It is a callback rather than a `&KeyManager` so the caller holds the
/// key lock only for that resolution, never across consignment validation's
/// Esplora/Electrum round-trips.
///
/// Returns the **recipient leg** in asset units — the amount this consignment
/// provably delivers to a destination that is not the bridge. The route-level
/// amount cross-check is built from this rather than from the wire-supplied
/// `psbt_output_amount`, so that field is no longer load-bearing anywhere.
#[cfg(feature = "rgb-validation")]
pub fn validate_psbt_anchors_transition(
    psbt: &Psbt,
    validated: &ValidatedConsignment,
    source_amount: u64,
    source_commission: u64,
    self_owned: SelfOwnedOutputs<'_>,
) -> Result<u64> {
    use std::collections::BTreeSet;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT requires a consignment with at least one transition".into(),
        )
    })?;
    if !matches!(last.transition_type, ifa::TS_TRANSFER | ifa::TS_INFLATION) {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB PSBT requires a Transfer or Inflation transition (last transition_type = \
             {}, want {} or {})",
            last.transition_type,
            ifa::TS_TRANSFER,
            ifa::TS_INFLATION
        )));
    }

    // Derive the txid from `unsigned_tx`, never a finalized/extracted tx
    // (a non-segwit input's scriptSig would change the txid post-signing).
    let expected = validated.last_transfer_witness_txid.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "consignment carries no witness txid for its last transition — \
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
                 (txid matched but input set differs — broken consignment invariant)"
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

    // Every transition this transaction commits, not just the last one. A
    // Bitcoin tx commits a *bundle*, which can hold several transitions; the
    // group is selected by the signed txid, which the identity bind above just
    // proved is the consignment's witness tx.
    let committed = validated.transitions_committed_by(psbt_txid);
    if committed.is_empty() {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB consignment commits no transition to the transaction being signed \
             ({psbt_txid}) — refusing to sign an unbound witness"
        )));
    }
    // Consistency canary between the two traversals: the transition the rest of
    // the pipeline calls "last" must be one of the ones this tx commits. A
    // disagreement means the flat parser and the rgbstd walk disagree about
    // which witness is last, and every bind downstream would be describing a
    // different operation than the one being signed.
    if !committed.iter().any(|t| t.op_id == last.op_id) {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB consignment inconsistency: last transition {} is not committed by the \
             transaction being signed ({psbt_txid})",
            last.op_id
        )));
    }
    // Each committed transition must be a shape we know how to bind. The
    // per-shape amount rules below only cover these two.
    for t in &committed {
        if !matches!(t.transition_type, ifa::TS_TRANSFER | ifa::TS_INFLATION) {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB PSBT commits transition {} of type {} — requires Transfer ({}) or \
                 Inflation ({})",
                t.op_id,
                t.transition_type,
                ifa::TS_TRANSFER,
                ifa::TS_INFLATION
            )));
        }
    }

    // `asset_output_amount`, not `total_output_amount`: only `OS_ASSET`-typed
    // allocations carry asset units; the `OS_INFLATION` allowance outputs are
    // mint *capacity*, not minted value, and are excluded. Summed across the
    // whole committed group, so a second transition in the same bundle cannot
    // move value outside the bind.
    let committed_asset_output: u64 = committed
        .iter()
        .try_fold(0u64, |acc, t| acc.checked_add(t.asset_output_amount))
        .ok_or_else(|| {
            EnclaveError::CrossCheck(
                "send-RGB committed asset_output_amount total overflows u64".into(),
            )
        })?;

    // A group that mixes mint and transfer has no single correct aggregate
    // rule — the mint arm wants equality and the transfer arm a floor. No
    // known flow produces one, so refuse rather than guess.
    let mints = committed
        .iter()
        .filter(|t| t.transition_type == ifa::TS_INFLATION)
        .count();
    let group_type = if mints == committed.len() {
        ifa::TS_INFLATION
    } else if mints == 0 {
        ifa::TS_TRANSFER
    } else {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB PSBT commits a mixed bundle ({mints} Inflation of {} transitions) — \
             refusing to sign a shape with no defined amount bind",
            committed.len()
        )));
    };

    let net_credited = source_amount.saturating_sub(source_commission);
    match group_type {
        // Inflation (mint-RGB): a fresh mint has no pre-existing allocation to
        // return as change, so the minted `OS_ASSET` units must EQUAL the
        // credited amount — any surplus is an over-mint. This closes the
        // over-mint gap the old one-sided lower bound left open.
        ifa::TS_INFLATION => {
            if committed_asset_output != net_credited {
                return Err(EnclaveError::CrossCheck(format!(
                    "mint-RGB amount mismatch: consignment asset_output_amount \
                     ({committed_asset_output}) != net credited (source_amount {source_amount} - \
                     source_commission {source_commission} = {net_credited})"
                )));
            }
        }
        // Transfer (pools send). `asset_output_amount` is recipient + bridge
        // change, so only a coverage lower bound is meaningful at the aggregate
        // level. The per-output bind below is what actually pins the recipient
        // leg.
        ifa::TS_TRANSFER => {
            if committed_asset_output < net_credited {
                return Err(EnclaveError::CrossCheck(format!(
                    "send-RGB amount mismatch: consignment asset_output_amount \
                     ({committed_asset_output}) < net credited (source_amount {source_amount} - \
                     source_commission {source_commission} = {net_credited})"
                )));
            }
        }
        // Unreachable today — the gate at the top of this function admits only
        // the two shapes above. Spelled out rather than left as a `_` arm so
        // that adding a third transition type to that gate cannot silently
        // inherit the Transfer rule: a new shape must state its own bind here
        // or be refused.
        other => {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB transition type {other} has no amount bind defined — refusing to sign"
            )));
        }
    }

    // Per-output recipient bind (W-06 / #52), over every transition the signed
    // tx commits. Runs last: it is the only check here that reaches for the
    // enclave's keys.
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

/// Resolves which of a PSBT's Bitcoin outputs pay back to this enclave, by
/// output index.
///
/// A callback rather than a `&KeyManager` so consignment validation never holds
/// the enclave's key lock across its network round-trips: the caller takes the
/// lock, answers, and releases. In production this is
/// [`crate::networks::rgb::btc_ownership::self_owned_output_indices`].
#[cfg(feature = "rgb-validation")]
pub type SelfOwnedOutputs<'a> = &'a dyn Fn(&Psbt) -> Result<std::collections::HashSet<u32>>;

/// The two legs an `OS_ASSET` output assignment can belong to, in asset units.
#[cfg(feature = "rgb-validation")]
struct AssetLegs {
    /// Paid to confidential (blinded) seals — the recipient.
    recipient: u64,
    /// Returned to revealed seals on Bitcoin outputs this enclave provably
    /// controls — bridge change.
    change: u64,
}

/// Split the `OS_ASSET` outputs of every transition the signed tx commits into
/// recipient and change, rejecting anything that is provably neither.
///
/// Takes the whole committed group, not one transition: a bundle can hold
/// several, and a per-transition split would let value routed by a sibling
/// transition escape the bind entirely.
///
/// `OS_INFLATION` entries are skipped for the same reason `asset_output_amount`
/// excludes them: their amount is remaining mint *capacity*, not value being
/// delivered (#54).
#[cfg(feature = "rgb-validation")]
fn split_asset_legs(
    psbt: &Psbt,
    psbt_txid: bitcoin::Txid,
    committed: &[&super::validation::TransitionSummary],
    self_owned: SelfOwnedOutputs<'_>,
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
            "send-RGB consignment's committed transitions carry no OS_ASSET output assignments — \
             nothing to bind the credited amount to"
                .into(),
        ));
    }

    // Seal txids are display-order bytes (see `OutputSeal::Revealed`); a
    // `bitcoin::Txid` is internal order. Flip once, here, so the byte-order
    // footgun lives in exactly one place.
    let mut psbt_txid_display = psbt_txid.to_byte_array();
    psbt_txid_display.reverse();

    // Only pay for the key-lock round-trip when a revealed seal actually needs
    // adjudicating; a mint typically has none.
    let has_revealed = asset_outputs
        .iter()
        .any(|o| matches!(o.seal, OutputSeal::Revealed { .. }));
    let owned = if has_revealed {
        self_owned(psbt)?
    } else {
        std::collections::HashSet::new()
    };

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
                // `None` means "the witness tx of this bundle", which the
                // identity bind already proved is the PSBT being signed. An
                // explicit txid must therefore say the same thing.
                if let Some(txid) = txid {
                    if *txid != psbt_txid_display {
                        return Err(EnclaveError::CrossCheck(format!(
                            "send-RGB OS_ASSET output {i} has a revealed seal on a different \
                             transaction ({}): a change leg must land on the witness tx being \
                             signed ({})",
                            hex::encode(txid),
                            hex::encode(psbt_txid_display)
                        )));
                    }
                }
                if !owned.contains(vout) {
                    return Err(EnclaveError::CrossCheck(format!(
                        "send-RGB OS_ASSET output {i} ({} units) has a revealed seal on vout \
                         {vout}, which this enclave does not control — a revealed leg is only \
                         acceptable as bridge change, and an unowned one is an unverifiable \
                         payout destination",
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

/// Maximum multiple of the recommended fee rate a send-RGB PSBT may pay
/// (#55). Compile-time (PCR-attested), deliberately not host-tunable: an
/// env knob would let the operator's host neutralize the check. 3x absorbs
/// fee-market movement within the estimate's TTL plus the unsigned-vsize
/// overestimate (see [`check_psbt_fee_rate`]).
#[cfg(feature = "rgb-validation")]
const FEE_RATE_HEADROOM: f64 = 3.0;

/// Fee-rate sanity check for send-RGB PSBTs (#55): the implied fee rate must
/// not exceed [`FEE_RATE_HEADROOM`] x the enclave-fetched recommendation.
/// Without this, a compromised host could burn bridge BTC as miner fees on an
/// otherwise fully-validated PSBT (the anchor bind pins inputs and the
/// commitment output, but the fee is whatever the outputs leave behind).
///
/// Fail-closed on every degenerate shape: `Psbt::fee()` errors (missing
/// `witness_utxo`/`non_witness_utxo`, value overflow) reject, a zero-vsize tx
/// rejects, and the comparison is written so a NaN rate rejects. The rate is
/// computed over `unsigned_tx.vsize()`, which is smaller than the final
/// witness-carrying vsize — the implied rate is therefore an OVERestimate,
/// i.e. conservative in the rejecting direction; the headroom absorbs it.
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
            "PSBT unsigned tx has zero vsize — cannot bound its fee rate".into(),
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
             recommended {recommended_sat_vb:.2} sat/vB — refusing to burn bridge BTC as fees"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    /// Minimal but BIP-174-valid PSBT: one dummy input, one dummy output, no
    /// signatures. Used as the "shape passes the whitelist" stand-in across
    /// the validation tests — the request fields under test are everything
    /// *around* the PSBT, not the PSBT contents themselves.
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

    // =========================================================================
    // PSBT shape whitelist tests
    // =========================================================================

    #[test]
    fn accepts_valid_psbt_bytes() {
        assert!(validate_psbt_bytes(&minimal_valid_psbt_bytes()).is_ok());
    }

    #[test]
    fn rejects_empty_psbt_bytes() {
        let err = validate_psbt_bytes(&[]).unwrap_err();
        assert!(err.to_string().contains("psbt_bytes is empty"));
    }

    // =========================================================================
    // PSBT shape whitelist rejection tests
    // =========================================================================

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

    // =========================================================================
    // Operation-dedup key — `psbt_operation_key` (audit W-02 / #84)
    // =========================================================================

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

    // =========================================================================
    // Operation dedup end-to-end — `psbt_operation_key` + the soft replay guard.
    // Encodes the M-02 properties the EVM->RGB path relies on the guard for.
    // =========================================================================
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
                "a fresh instance does not share the soft guard — on-chain state \
                 is the durable anchor"
            );
        }
    }

    // =========================================================================
    // send-RGB anchoring — `validate_psbt_anchors_transition`
    // =========================================================================
    #[cfg(feature = "rgb-validation")]
    mod fee_rate {
        use super::*;

        /// One segwit-ish input carrying `witness_utxo` of `input_sats`, one
        /// output of `output_sats` — so `Psbt::fee()` = input − output.
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
            // rate == FEE_RATE_HEADROOM × recommended must pass (boundary is
            // inclusive: reject only strictly above the cap).
            let recommended = 10.0;
            let vsize = psbt_with_fee(100_000, 100_000).unsigned_tx.vsize() as u64;
            let fee_at_cap = (FEE_RATE_HEADROOM * recommended) as u64 * vsize;
            let psbt = psbt_with_fee(100_000, 100_000 - fee_at_cap);
            assert!(check_psbt_fee_rate(&psbt, recommended).is_ok());
        }

        #[test]
        fn rejects_fee_rate_above_headroom() {
            // One extra sat/vB above the cap → reject; nothing else about the
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
            // No witness_utxo/non_witness_utxo → the fee is uncomputable and
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
        use std::collections::HashSet;

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

        /// Stand-in ownership oracles. Fn items coerce to `SelfOwnedOutputs`.
        fn owns_nothing(_: &Psbt) -> Result<HashSet<u32>> {
            Ok(HashSet::new())
        }
        fn owns_vout_1(_: &Psbt) -> Result<HashSet<u32>> {
            Ok(HashSet::from([1]))
        }

        /// A recipient leg: paid to a blinded (`utxob:…`) seal.
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
        /// `transitions` bundle — the multi-transition shape the per-output
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
        /// `net_credited` (900) is fine — the surplus is provably ours.
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

        /// **W-06 / #52.** The over-send this whole bind exists for: a genuine
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
                err.to_string().contains("this enclave does not control"),
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
                err.to_string().contains("this enclave does not control"),
                "expected out-of-range-vout rejection, got: {err}"
            );
        }

        /// A revealed seal carrying an explicit txid must name the witness tx
        /// being signed. Anything else parks the allocation on a transaction
        /// this signature does not commit to.
        #[test]
        fn rejects_revealed_seal_on_a_different_tx() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_with(&psbt, vec![confidential(1_000), revealed(500, 1)]);
            edit_signing_transition(&mut validated, |t| {
                t.outputs[1].seal = OutputSeal::Revealed {
                    txid: Some([0x99; 32]),
                    vout: 1,
                };
            });
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("revealed seal on a different transaction"),
                "expected wrong-tx-seal rejection, got: {err}"
            );
        }

        /// #54, at per-output granularity: an `OS_INFLATION` entry is mint
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
        /// so there is nothing to bind the credit to — fail closed rather than
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
            // set differs — the canary must fire.
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
            // PubWitness::Txid only → prevouts None → txid bind alone carries.
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transfer_witness_prevouts = None;
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1).is_ok()
            );
        }

        /// #54: the mint-RGB shape — an IFA Inflation last transition — binds
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

        /// #54: for a mint, only `OS_ASSET`-typed outputs (the actually
        /// minted units) may cover the credited amount — the `OS_INFLATION`
        /// allowance (mint capacity) counted in `total_output_amount` must
        /// not.
        #[test]
        fn inflation_allowance_does_not_cover_credited_amount() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            edit_signing_transition(&mut validated, |t| {
                t.transition_type = ifa::TS_INFLATION;
                // Minted 999 units; a large allowance rides along in the
                // total. Net credited is 1_000 — must be rejected on the
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
                // Minted 1_500 against a 1_000 credit → 500 over-mint.
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

        #[test]
        fn rejects_non_transfer_transition() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            edit_signing_transition(&mut validated, |t| t.transition_type = ifa::TS_BURN);
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0, &owns_vout_1)
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("requires a Transfer or Inflation transition"),
                "expected Transfer/Inflation-required rejection, got: {err}"
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
                // SIGHASH_SINGLE | ANYONECANPAY = 0x83 — spliceable.
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
