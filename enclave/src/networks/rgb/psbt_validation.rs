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
///   5. **Amount bind (coarse):** the transition's `asset_output_amount`
///      (the `OS_ASSET`-typed allocations only — for a mint, excluding the
///      `OS_INFLATION` allowance outputs) must cover the net amount credited
///      by the source side (`source_amount` minus `source_commission`). This
///      does not yet verify which output is the recipient leg (issue #58).
#[cfg(feature = "rgb-validation")]
pub fn validate_psbt_anchors_transition(
    psbt: &Psbt,
    validated: &ValidatedConsignment,
    source_amount: u64,
    source_commission: u64,
) -> Result<()> {
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

    let net_credited = source_amount.saturating_sub(source_commission);
    // `asset_output_amount`, not `total_output_amount`: only `OS_ASSET`-typed
    // allocations carry asset units. For a Transfer the two are equal; for an
    // Inflation the total also counts `OS_INFLATION` allowance outputs (mint
    // *capacity*), which must not cover the credited amount (#54).
    if last.asset_output_amount < net_credited {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB amount mismatch: consignment asset_output_amount ({}) < net credited \
             (source_amount {} - source_commission {} = {})",
            last.asset_output_amount, source_amount, source_commission, net_credited
        )));
    }

    Ok(())
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
        use crate::networks::rgb::validation::{ifa, TransitionSummary, ValidatedConsignment};
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
                output: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::new(),
                }],
            };
            Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx")
        }

        fn transfer_summary(total_output_amount: u64) -> TransitionSummary {
            TransitionSummary {
                op_id: "transfer-op".into(),
                transition_type: ifa::TS_TRANSFER,
                total_output_amount,
                // Transfers move only OS_ASSET, so the two sums are equal.
                asset_output_amount: total_output_amount,
                outputs: vec![],
                burned_asset_amount: None,
            }
        }

        /// A ValidatedConsignment bound to `psbt`'s actual txid + prevouts,
        /// with the given transfer total. The "happy" baseline every test
        /// then mutates.
        fn validated_for(psbt: &Psbt, total_output_amount: u64) -> ValidatedConsignment {
            let prevouts = psbt
                .unsigned_tx
                .input
                .iter()
                .map(|txin| txin.previous_output)
                .collect();
            ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: vec!["transfer-op".into()],
                mint_op_ids: vec![],
                last_transition: Some(transfer_summary(total_output_amount)),
                last_transfer_witness_txid: Some(psbt.unsigned_tx.compute_txid()),
                last_transfer_witness_prevouts: Some(prevouts),
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
            }
        }

        #[test]
        fn passes_when_txid_inputs_and_amount_match() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_for(&psbt, 1_000);
            assert!(validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).is_ok());
        }

        #[test]
        fn passes_when_total_output_exceeds_net_credited() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_for(&psbt, 5_000);
            // net credited = 1_000 - 100 = 900 <= 5_000
            assert!(validate_psbt_anchors_transition(&psbt, &validated, 1_000, 100).is_ok());
        }

        #[test]
        fn rejects_txid_mismatch() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transfer_witness_txid = Some(Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xAB; 32]),
            ));
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).unwrap_err();
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
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).unwrap_err();
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
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).unwrap_err();
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
            assert!(validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).is_ok());
        }

        /// #54: the mint-RGB shape — an IFA Inflation last transition — binds
        /// through the same anchor path as the pools-mode Transfer.
        #[test]
        fn accepts_inflation_shape() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transition.as_mut().unwrap().transition_type = ifa::TS_INFLATION;
            assert!(validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).is_ok());
        }

        /// #54: for a mint, only `OS_ASSET`-typed outputs (the actually
        /// minted units) may cover the credited amount — the `OS_INFLATION`
        /// allowance (mint capacity) counted in `total_output_amount` must
        /// not.
        #[test]
        fn inflation_allowance_does_not_cover_credited_amount() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            {
                let last = validated.last_transition.as_mut().unwrap();
                last.transition_type = ifa::TS_INFLATION;
                // Minted 999 units; a large allowance rides along in the
                // total. Net credited is 1_000 — must be rejected on the
                // asset sum, not covered by the allowance-inflated total.
                last.asset_output_amount = 999;
                last.total_output_amount = 1_000_000;
            }
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).unwrap_err();
            assert!(
                err.to_string().contains("asset_output_amount (999)"),
                "expected asset-amount rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_non_transfer_transition() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transition.as_mut().unwrap().transition_type = ifa::TS_BURN;
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).unwrap_err();
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
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).unwrap_err();
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
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).unwrap_err();
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
                    validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).is_ok(),
                    "sighash 0x{raw:02x} should be accepted"
                );
            }
        }
    }
}
