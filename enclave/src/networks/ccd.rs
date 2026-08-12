//! Concordium (CCD) source validation.
//!
//! Unlike EVM/RGB, the enclave does not independently re-validate a Concordium
//! source: the listener node has already confirmed the source transaction's
//! finality and structure on-chain (consistent with the CCD-destination
//! hash-signing model, where the enclave signs the node-derived hash). The
//! enclave trusts that validation and only binds the release amount into the
//! route proof so the destination amount check still applies.

use crate::error::{EnclaveError, Result};
use crate::networks::RouteProof;
use crate::proto::CcdSource;

/// Validate a Concordium source for an inbound (fundsIn) release. Trusts the
/// node's on-chain validation; binds `amount` (SignRequest.amount) for the
/// route amount check. A sanity check requires a 32-byte source tx hash.
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
