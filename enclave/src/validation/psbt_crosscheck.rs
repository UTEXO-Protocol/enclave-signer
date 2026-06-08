use bitcoin::psbt::Psbt;

use crate::error::{EnclaveError, Result};
use crate::proto::SignPsbtRequest;
#[cfg(feature = "rgb-validation")]
use crate::validation::rgb::{ifa, ValidatedConsignment};

/// Validate enriched SignPsbtRequest before signing.
///
/// Two modes:
/// - **Bridge mode** (evm_tx_hash is non-empty): Full cross-checks — EVM event
///   must be valid + finalized, amounts must match, tx hash must be 32 bytes.
///   Used for EVM→RGB bridge operations.
/// - **Vanilla mode** (evm_tx_hash is empty): Minimal checks — PSBT must be
///   present. Used for `create_utxo` and other plain BTC operations that don't
///   involve RGB state or EVM events.
pub fn validate_psbt_request(req: &SignPsbtRequest) -> Result<()> {
    // 0. Shape whitelist. Mirrors the EVM-side selector whitelist: refuse
    //    payloads that aren't even a legitimate PSBT before any other
    //    predicate runs. Catches three classes of garbage up-front:
    //
    //      (a) empty bytes (handler tried to sign nothing),
    //      (b) bytes that don't conform to BIP-174 (random/truncated/
    //          tampered),
    //      (c) PSBTs with no inputs — there's literally nothing to sign,
    //          and the unsigned-tx-must-be-non-empty rule is implicit in
    //          BIP-174's signing semantics.
    //
    //    The existing PSBT signer would have failed later on these too,
    //    but with a much noisier downstream error. Failing here gives the
    //    caller a single clear reason.
    if req.psbt_bytes.is_empty() {
        return Err(EnclaveError::CrossCheck("psbt_bytes is empty".into()));
    }
    let psbt = Psbt::deserialize(&req.psbt_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("psbt_bytes is not a valid PSBT: {e}")))?;
    if psbt.unsigned_tx.input.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "psbt has no inputs — nothing to sign".into(),
        ));
    }

    // Vanilla mode: no EVM enrichment → skip bridge cross-checks.
    if req.evm_tx_hash.is_empty() {
        tracing::info!("PSBT signing: vanilla mode (no evm_tx_hash, skipping EVM cross-checks)");
        return Ok(());
    }

    // Bridge mode: full EVM cross-checks.
    tracing::info!("PSBT signing: bridge mode (evm_tx_hash present, full cross-checks)");

    // 1. Tx hash must be exactly 32 bytes
    if req.evm_tx_hash.len() != 32 {
        return Err(EnclaveError::CrossCheck(format!(
            "evm_tx_hash must be 32 bytes, got {}",
            req.evm_tx_hash.len()
        )));
    }

    // 2. EVM event must be valid
    if !req.evm_event_valid {
        return Err(EnclaveError::CrossCheck(
            "EVM event not validated by Listener".into(),
        ));
    }

    // 3. EVM event must be finalized
    if !req.evm_event_finalized {
        return Err(EnclaveError::CrossCheck(
            "EVM event not yet finalized".into(),
        ));
    }

    // 4. Amount consistency: EVM deposit must cover PSBT output + commission
    let required = req
        .psbt_output_amount
        .checked_add(req.evm_commission)
        .ok_or_else(|| {
            EnclaveError::CrossCheck("psbt_output_amount + evm_commission overflow".into())
        })?;
    if req.evm_amount < required {
        return Err(EnclaveError::CrossCheck(format!(
            "amount mismatch: evm_amount ({}) < psbt_output_amount ({}) + evm_commission ({})",
            req.evm_amount, req.psbt_output_amount, req.evm_commission
        )));
    }

    Ok(())
}

/// Bind a PSBT to the RGB consignment it claims to finalize — the send-RGB
/// (EVM-lock → RGB-send) direction.
///
/// In this flow the PSBT being signed **is** the RGB transfer's witness
/// transaction: the Bitcoin tx that spends the bridge's UTXOs holding the RGB
/// allocation and carries the tapret/opret DBC commitment to the
/// state-transition bundle. Without this check the signing path has no link
/// between the PSBT and the consignment, so a compromised host could get the
/// enclave to sign a PSBT that moves bridge BTC without committing to the
/// claimed RGB state.
///
/// Must be called only **after** [`crate::validation::rgb::RgbValidator::
/// validate_consignment`] has run full rgbstd validation — the txid-identity
/// argument below is worthless otherwise (an attacker could put any tx in the
/// consignment and a matching `unsigned_tx`; only `validate()` proves the
/// commitment is genuinely anchored).
///
/// Enforces, fail-closed:
///   1. The consignment's last transition is an IFA `Transfer`
///      (`ifa::TS_TRANSFER`) — the pools-mode send shape.
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
///   5. **Amount bind (coarse):** the transfer's `total_output_amount` must
///      cover the net amount credited on the EVM side (`evm_amount` minus the
///      on-chain `evm_commission`). Mirrors `validate_funds_out_transfer`;
///      assumes RGB-USDT units are 1:1 with the EVM USDT base unit and does
///      not yet verify which output is the recipient leg (issue #58).
#[cfg(feature = "rgb-validation")]
pub fn validate_psbt_anchors_transition(
    psbt: &Psbt,
    validated: &ValidatedConsignment,
    evm_amount: u64,
    evm_commission: u64,
) -> Result<()> {
    use std::collections::BTreeSet;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT requires a consignment with at least one transition".into(),
        )
    })?;
    if last.transition_type != ifa::TS_TRANSFER {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB PSBT requires a Transfer transition (last transition_type = {}, want {})",
            last.transition_type,
            ifa::TS_TRANSFER
        )));
    }

    // Derive the txid from `unsigned_tx`, never a finalized/extracted tx
    // (a non-segwit input's scriptSig would change the txid post-signing).
    let expected = validated.last_transfer_witness_txid.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "consignment carries no witness txid for its Transfer transition — \
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

    let net_credited = evm_amount.saturating_sub(evm_commission);
    if last.total_output_amount < net_credited {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB amount mismatch: consignment total_output_amount ({}) < net credited \
             (evm_amount {} - evm_commission {} = {})",
            last.total_output_amount, evm_amount, evm_commission, net_credited
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

    fn valid_bridge_psbt_request() -> SignPsbtRequest {
        SignPsbtRequest {
            evm_tx_hash: vec![0xAA; 32],
            operation_idx: 0,
            evm_event_valid: true,
            evm_event_finalized: true,
            evm_token: vec![0x11; 20],
            evm_amount: 1000,
            evm_recipient: vec![0x22; 20],
            evm_commission: 50,
            psbt_bytes: minimal_valid_psbt_bytes(),
            psbt_output_amount: 900,
            rgb_asset_id: "rgb:test-asset".into(),
            consignment: vec![],
            consignment_hash: vec![],
        }
    }

    fn vanilla_psbt_request() -> SignPsbtRequest {
        SignPsbtRequest {
            evm_tx_hash: vec![], // empty = vanilla mode
            operation_idx: 0,
            evm_event_valid: false,
            evm_event_finalized: false,
            evm_token: vec![],
            evm_amount: 0,
            evm_recipient: vec![],
            evm_commission: 0,
            psbt_bytes: minimal_valid_psbt_bytes(),
            psbt_output_amount: 0,
            rgb_asset_id: String::new(),
            consignment: vec![],
            consignment_hash: vec![],
        }
    }

    // =========================================================================
    // Vanilla mode tests
    // =========================================================================

    #[test]
    fn vanilla_psbt_passes_with_minimal_fields() {
        assert!(validate_psbt_request(&vanilla_psbt_request()).is_ok());
    }

    #[test]
    fn vanilla_psbt_rejects_empty_psbt() {
        let mut req = vanilla_psbt_request();
        req.psbt_bytes = vec![];
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("psbt_bytes is empty"));
    }

    #[test]
    fn vanilla_psbt_ignores_evm_fields() {
        // Even though evm_event_valid is false, vanilla mode doesn't check it.
        let mut req = vanilla_psbt_request();
        req.evm_event_valid = false;
        req.evm_event_finalized = false;
        assert!(validate_psbt_request(&req).is_ok());
    }

    // =========================================================================
    // Bridge mode tests
    // =========================================================================

    #[test]
    fn bridge_psbt_passes() {
        assert!(validate_psbt_request(&valid_bridge_psbt_request()).is_ok());
    }

    #[test]
    fn bridge_psbt_rejects_invalid_evm_event() {
        let mut req = valid_bridge_psbt_request();
        req.evm_event_valid = false;
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("EVM event not validated"));
    }

    #[test]
    fn bridge_psbt_rejects_unfinalized_event() {
        let mut req = valid_bridge_psbt_request();
        req.evm_event_finalized = false;
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("not yet finalized"));
    }

    #[test]
    fn bridge_psbt_rejects_amount_mismatch() {
        let mut req = valid_bridge_psbt_request();
        req.evm_amount = 100;
        req.psbt_output_amount = 90;
        req.evm_commission = 20; // 90 + 20 = 110 > 100
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("amount mismatch"));
    }

    #[test]
    fn bridge_psbt_rejects_empty_psbt() {
        let mut req = valid_bridge_psbt_request();
        req.psbt_bytes = vec![];
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("psbt_bytes is empty"));
    }

    #[test]
    fn bridge_psbt_rejects_invalid_tx_hash_length() {
        let mut req = valid_bridge_psbt_request();
        req.evm_tx_hash = vec![0xAA; 16]; // wrong length
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("evm_tx_hash must be 32 bytes"));
    }

    #[test]
    fn bridge_psbt_accepts_exact_amount_match() {
        let mut req = valid_bridge_psbt_request();
        req.evm_amount = req.psbt_output_amount + req.evm_commission;
        assert!(validate_psbt_request(&req).is_ok());
    }

    // =========================================================================
    // PSBT shape whitelist tests — apply to both bridge and vanilla modes
    // =========================================================================

    #[test]
    fn rejects_garbage_psbt_bytes() {
        // Long enough to clear the empty-bytes guard but not a BIP-174 PSBT.
        let mut req = vanilla_psbt_request();
        req.psbt_bytes = vec![0xFF; 100];
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(
            err.to_string().contains("not a valid PSBT"),
            "expected PSBT parse rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_truncated_psbt_below_magic() {
        // Shorter than the 5-byte BIP-174 magic prefix.
        let mut req = vanilla_psbt_request();
        req.psbt_bytes = vec![0x70, 0x73];
        let err = validate_psbt_request(&req).unwrap_err();
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
        let mut req = vanilla_psbt_request();
        req.psbt_bytes = psbt.serialize();
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(
            err.to_string().contains("no inputs"),
            "expected no-inputs rejection, got: {err}"
        );
    }

    // =========================================================================
    // send-RGB anchoring — `validate_psbt_anchors_transition`
    // =========================================================================
    #[cfg(feature = "rgb-validation")]
    mod anchor {
        use super::*;
        use crate::validation::rgb::{
            ifa, TransitionSummary, ValidatedConsignment,
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
                last_transition: Some(transfer_summary(total_output_amount)),
                last_transfer_witness_txid: Some(psbt.unsigned_tx.compute_txid()),
                last_transfer_witness_prevouts: Some(prevouts),
            }
        }

        #[test]
        fn passes_when_txid_inputs_and_amount_match() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_for(&psbt, 1_000);
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).is_ok()
            );
        }

        #[test]
        fn passes_when_total_output_exceeds_net_credited() {
            let psbt = psbt_with_two_inputs();
            let validated = validated_for(&psbt, 5_000);
            // net credited = 1_000 - 100 = 900 <= 5_000
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 100).is_ok()
            );
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
                err.to_string().contains("does not finalize the consignment's transition"),
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
            assert!(
                validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).is_ok()
            );
        }

        #[test]
        fn rejects_non_transfer_transition() {
            let psbt = psbt_with_two_inputs();
            let mut validated = validated_for(&psbt, 1_000);
            validated.last_transition.as_mut().unwrap().transition_type = ifa::TS_BURN;
            let err = validate_psbt_anchors_transition(&psbt, &validated, 1_000, 0).unwrap_err();
            assert!(
                err.to_string().contains("requires a Transfer transition"),
                "expected Transfer-required rejection, got: {err}"
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
