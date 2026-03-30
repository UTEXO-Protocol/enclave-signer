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
    // PSBT must always be present regardless of mode.
    if req.psbt_bytes.is_empty() {
        return Err(EnclaveError::CrossCheck("psbt_bytes is empty".into()));
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
            psbt_bytes: vec![0xFF; 100],
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
            psbt_bytes: vec![0xFF; 100],
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
}
