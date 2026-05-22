use bitcoin::psbt::Psbt;

use crate::error::{EnclaveError, Result};
use crate::proto::SignPsbtRequest;

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
}
