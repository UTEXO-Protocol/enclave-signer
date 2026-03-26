use std::time::{SystemTime, UNIX_EPOCH};

use sha3::{Digest, Keccak256};

use crate::error::{EnclaveError, Result};
use crate::proto::SignEvmRequest;

/// Validate enriched SignEvmRequest before signing.
/// Returns Ok(()) if all cross-checks pass, Err(EnclaveError::CrossCheck) if any fail.
pub fn validate_evm_request(req: &SignEvmRequest) -> Result<()> {
    // 1. Consignment must be validated by Listener
    if !req.consignment_valid {
        return Err(EnclaveError::CrossCheck(
            "consignment not validated by Listener".into(),
        ));
    }

    // 1b. If raw consignment bytes are present, verify hash integrity.
    //     This catches tampering between Listener and Enclave.
    //     Full RGB validation (rgb-lib) will be added in a follow-up PR.
    if !req.consignment.is_empty() {
        if req.consignment_hash.is_empty() {
            return Err(EnclaveError::CrossCheck(
                "consignment present but consignment_hash is missing".into(),
            ));
        }
        let computed = Keccak256::digest(&req.consignment);
        if &computed[..] != req.consignment_hash.as_slice() {
            return Err(EnclaveError::CrossCheck(
                "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
            ));
        }
    }

    // 2. Amount consistency: RGB amount must cover calldata amount + commission
    let required = req
        .calldata_amount
        .checked_add(req.calldata_commission)
        .ok_or_else(|| EnclaveError::CrossCheck("calldata amount + commission overflow".into()))?;
    if req.rgb_amount < required {
        return Err(EnclaveError::CrossCheck(format!(
            "amount mismatch: rgb_amount ({}) < calldata_amount ({}) + calldata_commission ({})",
            req.rgb_amount, req.calldata_amount, req.calldata_commission
        )));
    }

    // 3. Calldata verification: verify pre-extracted amounts match raw call_data bytes
    //    fundsOut(address token, address recipient, uint256 amount, uint256 commission, ...)
    //    Layout: [4 selector][32 token][32 recipient][32 amount][32 commission]...
    //    amount at offset 68, commission at offset 100
    let cd_amount = extract_uint256_as_u64(&req.call_data, 68)?;
    if cd_amount != req.calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "calldata amount mismatch: extracted {} != declared {}",
            cd_amount, req.calldata_amount
        )));
    }
    let cd_commission = extract_uint256_as_u64(&req.call_data, 100)?;
    if cd_commission != req.calldata_commission {
        return Err(EnclaveError::CrossCheck(format!(
            "calldata commission mismatch: extracted {} != declared {}",
            cd_commission, req.calldata_commission
        )));
    }

    // 4. Chain/domain present
    if req.chain_id == 0 {
        return Err(EnclaveError::CrossCheck("chain_id must be > 0".into()));
    }
    if req.proxy_contract.len() != 20 {
        return Err(EnclaveError::CrossCheck(format!(
            "proxy_contract must be 20 bytes, got {}",
            req.proxy_contract.len()
        )));
    }

    // 5. Deadline not expired
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::Internal(format!("system time error: {}", e)))?
        .as_secs();
    if req.deadline <= now {
        return Err(EnclaveError::CrossCheck("request deadline expired".into()));
    }

    Ok(())
}

/// Lightweight ABI extraction: read a uint256 from call_data at a given byte offset.
/// Returns the value as u64. Fails if call_data is too short or the value exceeds u64.
fn extract_uint256_as_u64(call_data: &[u8], offset: usize) -> Result<u64> {
    let end = offset + 32;
    if call_data.len() < end {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need {} bytes, got {}",
            end,
            call_data.len()
        )));
    }
    let slot = &call_data[offset..end];
    // High 24 bytes must be zero for value to fit in u64
    if slot[..24].iter().any(|&b| b != 0) {
        return Err(EnclaveError::CrossCheck(
            "uint256 value exceeds u64 range".into(),
        ));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&slot[24..32]);
    Ok(u64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a mock fundsOut calldata with the given amount and commission.
    fn mock_funds_out_calldata(amount: u64, commission: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 7 * 32);
        // 4-byte selector (placeholder)
        data.extend_from_slice(&[0xab, 0xcd, 0xef, 0x12]);
        // address token (32 bytes, left-padded)
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&[0x11; 20]);
        data.extend_from_slice(&padded);
        // address recipient (32 bytes, left-padded)
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&[0x22; 20]);
        data.extend_from_slice(&padded);
        // uint256 amount
        let mut padded = [0u8; 32];
        padded[24..].copy_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&padded);
        // uint256 commission
        let mut padded = [0u8; 32];
        padded[24..].copy_from_slice(&commission.to_be_bytes());
        data.extend_from_slice(&padded);
        // remaining params — zero-fill
        data.extend_from_slice(&[0u8; 32 * 3]);
        data
    }

    fn valid_evm_request() -> SignEvmRequest {
        let amount = 1000u64;
        let commission = 50u64;
        SignEvmRequest {
            call_data: mock_funds_out_calldata(amount, commission),
            nonce: 1,
            deadline: u64::MAX, // far future
            consignment_valid: true,
            rgb_amount: 1100, // >= amount + commission
            rgb_asset_id: "rgb:test-asset".into(),
            chain_id: 1,
            proxy_contract: vec![0xAA; 20],
            calldata_amount: amount,
            calldata_commission: commission,
            // Empty = skip hash check (backwards compatible)
            consignment: vec![],
            consignment_hash: vec![],
        }
    }

    #[test]
    fn valid_request_passes() {
        assert!(validate_evm_request(&valid_evm_request()).is_ok());
    }

    #[test]
    fn rejects_invalid_consignment() {
        let mut req = valid_evm_request();
        req.consignment_valid = false;
        let err = validate_evm_request(&req).unwrap_err();
        assert!(err.to_string().contains("consignment not validated"));
    }

    #[test]
    fn rejects_amount_mismatch_rgb_less_than_calldata() {
        let mut req = valid_evm_request();
        req.rgb_amount = 1049; // 1000 + 50 = 1050, so 1049 is insufficient
        let err = validate_evm_request(&req).unwrap_err();
        assert!(err.to_string().contains("amount mismatch"));
    }

    #[test]
    fn rejects_calldata_extraction_mismatch() {
        let mut req = valid_evm_request();
        // Declare a different amount than what's in the actual call_data bytes
        req.calldata_amount = 9999;
        // Bump rgb_amount so we pass the consignment amount check first
        req.rgb_amount = 99999;
        let err = validate_evm_request(&req).unwrap_err();
        assert!(err.to_string().contains("calldata amount mismatch"));
    }

    #[test]
    fn rejects_expired_deadline() {
        let mut req = valid_evm_request();
        req.deadline = 1; // Unix timestamp 1 is long expired
        let err = validate_evm_request(&req).unwrap_err();
        assert!(err.to_string().contains("deadline expired"));
    }

    #[test]
    fn rejects_missing_proxy_contract() {
        let mut req = valid_evm_request();
        req.proxy_contract = vec![];
        let err = validate_evm_request(&req).unwrap_err();
        assert!(err.to_string().contains("proxy_contract must be 20 bytes"));
    }

    #[test]
    fn rejects_zero_chain_id() {
        let mut req = valid_evm_request();
        req.chain_id = 0;
        let err = validate_evm_request(&req).unwrap_err();
        assert!(err.to_string().contains("chain_id must be > 0"));
    }

    #[test]
    fn accepts_exact_amount_match() {
        let mut req = valid_evm_request();
        // rgb_amount == calldata_amount + calldata_commission exactly
        req.rgb_amount = req.calldata_amount + req.calldata_commission;
        assert!(validate_evm_request(&req).is_ok());
    }

    #[test]
    fn extract_uint256_works() {
        let mut data = vec![0u8; 40];
        // Put value 42 at offset 8 (bytes 8..40)
        data[39] = 42;
        assert_eq!(extract_uint256_as_u64(&data, 8).unwrap(), 42);
    }

    #[test]
    fn extract_uint256_rejects_short_data() {
        let data = vec![0u8; 10];
        assert!(extract_uint256_as_u64(&data, 0).is_err());
    }

    #[test]
    fn extract_uint256_rejects_overflow() {
        let mut data = vec![0u8; 32];
        data[0] = 1; // high byte set — exceeds u64
        assert!(extract_uint256_as_u64(&data, 0).is_err());
    }

    #[test]
    fn accepts_valid_consignment_hash() {
        let mut req = valid_evm_request();
        let consignment = b"test-consignment-bytes";
        let hash = Keccak256::digest(consignment);
        req.consignment = consignment.to_vec();
        req.consignment_hash = hash.to_vec();
        assert!(validate_evm_request(&req).is_ok());
    }

    #[test]
    fn rejects_consignment_hash_mismatch() {
        let mut req = valid_evm_request();
        req.consignment = b"test-consignment-bytes".to_vec();
        req.consignment_hash = vec![0xDE; 32]; // wrong hash
        let err = validate_evm_request(&req).unwrap_err();
        assert!(err.to_string().contains("consignment hash mismatch"));
    }

    #[test]
    fn rejects_consignment_without_hash() {
        let mut req = valid_evm_request();
        req.consignment = b"test-consignment-bytes".to_vec();
        req.consignment_hash = vec![]; // missing hash
        let err = validate_evm_request(&req).unwrap_err();
        assert!(err.to_string().contains("consignment_hash is missing"));
    }

    #[test]
    fn skips_hash_check_when_consignment_empty() {
        // Default valid_evm_request has empty consignment — should still pass
        assert!(validate_evm_request(&valid_evm_request()).is_ok());
    }
}
