//! Concordium (CCD) source validation.
//!
//! Trust assumption: the enclave does not validate a Concordium source again.
//! The listener node confirms its finality and structure on-chain. This
//! matches the CCD-destination model, where the enclave signs the node hash.
//! The enclave binds only the release amount, so the destination amount
//! check still applies.

use crate::error::{EnclaveError, Result};
use crate::networks::RouteProof;
use crate::proto::CcdSource;

/// Validates a Concordium source for a fundsIn release. Trusts the node
/// validation and binds `amount` (SignRequest.amount) for the route amount
/// check. The source tx hash must be 32 bytes.
pub fn validate_source(amount: u64, source: &CcdSource) -> Result<RouteProof> {
    if source.tx_hash.len() != 32 {
        return Err(EnclaveError::CrossCheck(format!(
            "CCD source tx_hash must be 32 bytes, got {}",
            source.tx_hash.len()
        )));
    }

    Ok(RouteProof {
        amount,
        operation_id: None,
    })
}
