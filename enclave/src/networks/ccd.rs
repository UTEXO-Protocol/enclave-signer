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

/// Replay-guard key for a Concordium deposit released on EVM. One deposit
/// transaction authorises exactly one release, so the key binds the pinned
/// chain and proxy to the deposit's tx hash and nothing else: a retry under a
/// different nonce or calldata is still the same operation.
///
/// Consumed by the soft in-memory guard
/// ([`crate::state::EnclaveState::op_replay_guard`]); the proxy's `burnId` is
/// the durable guard.
pub fn release_operation_key(
    chain_id: u64,
    bridge_contract: &[u8; 20],
    ccd_tx_hash: &[u8],
) -> [u8; 32] {
    use sha3::{Digest, Keccak256};

    let mut h = Keccak256::new();
    h.update(b"utexo:ccd-release:v1");
    h.update(chain_id.to_be_bytes());
    h.update(bridge_contract);
    h.update((ccd_tx_hash.len() as u64).to_be_bytes());
    h.update(ccd_tx_hash);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(len: usize) -> CcdSource {
        CcdSource {
            tx_hash: vec![0xCC; len],
            commission: 5,
        }
    }

    #[test]
    fn exactly_32_byte_hash_is_accepted_and_binds_the_amount() {
        let proof = validate_source(1_234, &source(32)).unwrap();
        assert_eq!(
            proof,
            RouteProof {
                amount: 1_234,
                operation_id: None
            }
        );
    }

    #[test]
    fn amount_passes_through_untouched_including_edges() {
        assert_eq!(validate_source(0, &source(32)).unwrap().amount, 0);
        assert_eq!(
            validate_source(u64::MAX, &source(32)).unwrap().amount,
            u64::MAX
        );
    }

    #[test]
    fn commission_is_not_part_of_the_proof() {
        let a = validate_source(10, &source(32)).unwrap();
        let b = validate_source(
            10,
            &CcdSource {
                tx_hash: vec![0xCC; 32],
                commission: 999,
            },
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hash_of_any_other_length_is_a_cross_check_failure() {
        for len in [0usize, 1, 31, 33, 64] {
            match validate_source(10, &source(len)) {
                Err(EnclaveError::CrossCheck(msg)) => {
                    assert!(msg.contains("32 bytes"), "{len}: {msg}");
                    assert!(msg.contains(&format!("got {len}")), "{len}: {msg}");
                }
                other => panic!("{len}: expected CrossCheck, got {other:?}"),
            }
        }
    }

    #[test]
    fn rejection_is_a_validation_failure_on_the_wire() {
        let err = validate_source(10, &source(0)).unwrap_err();
        assert_eq!(err.error_code(), 3);
    }

    #[test]
    fn release_key_binds_chain_contract_and_deposit() {
        let base = release_operation_key(1, &[0xAA; 20], &[0xCC; 32]);
        assert_ne!(base, release_operation_key(2, &[0xAA; 20], &[0xCC; 32]));
        assert_ne!(base, release_operation_key(1, &[0xAB; 20], &[0xCC; 32]));
        assert_ne!(base, release_operation_key(1, &[0xAA; 20], &[0xCD; 32]));
        assert_eq!(base, release_operation_key(1, &[0xAA; 20], &[0xCC; 32]));
        // Distinct from the EVM->RGB key domain even on identical bytes.
        assert_ne!(
            base,
            crate::networks::rgb::psbt_validation::psbt_operation_key(
                1,
                &[0xAA; 20],
                &[0xCC; 32],
                &[],
                ""
            )
        );
    }
}
