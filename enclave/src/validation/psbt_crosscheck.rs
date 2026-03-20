use crate::error::{EnclaveError, Result};
use crate::proto::SignPsbtRequest;

/// Validate enriched SignPsbtRequest before signing.
/// Returns Ok(()) if all cross-checks pass, Err(EnclaveError::CrossCheck) if any fail.
pub fn validate_psbt_request(req: &SignPsbtRequest) -> Result<()> {
    // 1. EVM event must be valid
    if !req.evm_event_valid {
        return Err(EnclaveError::CrossCheck(
            "EVM event not validated by Listener".into(),
        ));
    }

    // 2. EVM event must be finalized
    if !req.evm_event_finalized {
        return Err(EnclaveError::CrossCheck(
            "EVM event not yet finalized".into(),
        ));
    }

    // 3. Amount consistency: EVM deposit must cover PSBT output + commission
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

    // 4. PSBT must be present
    if req.psbt_bytes.is_empty() {
        return Err(EnclaveError::CrossCheck("psbt_bytes is empty".into()));
    }

    // 5. Tx hash must be exactly 32 bytes
    if req.evm_tx_hash.len() != 32 {
        return Err(EnclaveError::CrossCheck(format!(
            "evm_tx_hash must be 32 bytes, got {}",
            req.evm_tx_hash.len()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_psbt_request() -> SignPsbtRequest {
        SignPsbtRequest {
            evm_tx_hash: vec![0xAA; 32],
            operation_idx: 0,
            evm_event_valid: true,
            evm_event_finalized: true,
            evm_token: vec![0x11; 20],
            evm_amount: 1000,
            evm_recipient: vec![0x22; 20],
            evm_commission: 50,
            psbt_bytes: vec![0xFF; 100], // placeholder, not a real PSBT
            psbt_output_amount: 900,
            rgb_asset_id: "rgb:test-asset".into(),
        }
    }

    #[test]
    fn valid_request_passes() {
        assert!(validate_psbt_request(&valid_psbt_request()).is_ok());
    }

    #[test]
    fn rejects_invalid_evm_event() {
        let mut req = valid_psbt_request();
        req.evm_event_valid = false;
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("EVM event not validated"));
    }

    #[test]
    fn rejects_unfinalized_event() {
        let mut req = valid_psbt_request();
        req.evm_event_finalized = false;
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("not yet finalized"));
    }

    #[test]
    fn rejects_amount_mismatch() {
        let mut req = valid_psbt_request();
        req.evm_amount = 100;
        req.psbt_output_amount = 90;
        req.evm_commission = 20; // 90 + 20 = 110 > 100
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("amount mismatch"));
    }

    #[test]
    fn rejects_empty_psbt() {
        let mut req = valid_psbt_request();
        req.psbt_bytes = vec![];
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("psbt_bytes is empty"));
    }

    #[test]
    fn rejects_invalid_tx_hash_length() {
        let mut req = valid_psbt_request();
        req.evm_tx_hash = vec![0xAA; 16]; // wrong length
        let err = validate_psbt_request(&req).unwrap_err();
        assert!(err.to_string().contains("evm_tx_hash must be 32 bytes"));
    }

    #[test]
    fn accepts_exact_amount_match() {
        let mut req = valid_psbt_request();
        req.evm_amount = req.psbt_output_amount + req.evm_commission;
        assert!(validate_psbt_request(&req).is_ok());
    }
}
