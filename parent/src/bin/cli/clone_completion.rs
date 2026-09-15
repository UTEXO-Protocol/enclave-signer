//! Completion contract for the one-shot clone CLI (F03-AF-05).
//!
//! Blocking TCP/vsock/DNS calls run on at most two workers. The command exits
//! after reporting, terminating any outstanding I/O. Do not reuse this helper
//! in a long-lived service: a deadline does not cancel an in-flight SetClone.

use std::sync::mpsc;
use std::time::Duration;

use utexo_bridge_parent::client::EnclaveClient;
use utexo_bridge_parent::enclave_proto::{PublicKeysResponse, SetCloneRequest};
use utexo_bridge_parent::error::ParentError;
use utexo_bridge_parent::grpc_proto::AttestedPublicKeyResponse;

const SET_WAIT: Duration = Duration::from_millis(750);
const READ_WAIT: Duration = Duration::from_millis(750);

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    RecoveredSuccess,
    IdentityMismatch,
    NotInitialized,
    Unknown,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::RecoveredSuccess => "recovered_success",
            Self::IdentityMismatch => "identity_mismatch",
            Self::NotInitialized => "not_initialized",
            Self::Unknown => "unknown",
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success | Self::RecoveredSuccess)
    }
}

pub struct Completion {
    pub outcome: Outcome,
    pub keys: Option<PublicKeysResponse>,
    pub detail: String,
}

/// Send SetClone exactly once, then independently observe all 13 fields.
/// Both blocking legs are bounded for the CLI caller (1.5s total wait budget).
/// A timeout is uncertainty, never proof that a mutation did not happen.
pub fn complete(
    client: &EnclaveClient,
    request: SetCloneRequest,
    expected_evm: &[u8],
    donor: &AttestedPublicKeyResponse,
) -> Completion {
    let (set_tx, set_rx) = mpsc::channel();
    let set_client = client.clone();
    std::thread::spawn(move || {
        let result = set_client.set_clone(
            request.encrypted_seed,
            request.donor_pubkey,
            request.donor_attestation,
        );
        let _ = set_tx.send(result);
    });
    let set_result = set_rx.recv_timeout(SET_WAIT);
    let acknowledged = matches!(&set_result, Ok(Ok(())));
    let set_detail = match &set_result {
        Ok(Ok(())) => "SetClone acknowledged".to_string(),
        Ok(Err(e)) => format!("SetClone response unavailable or rejected: {e}"),
        Err(_) => "SetClone outcome pending/unknown at deadline".to_string(),
    };

    let (read_tx, read_rx) = mpsc::channel();
    let read_client = client.clone();
    std::thread::spawn(move || {
        let _ = read_tx.send(read_client.get_public_keys());
    });
    match read_rx.recv_timeout(READ_WAIT) {
        Ok(Ok(keys)) => {
            let mismatches = identity_field_mismatches(&keys, donor);
            let identity_matches = keys.evm_address == expected_evm && mismatches.is_empty();
            Completion {
                outcome: if !identity_matches {
                    Outcome::IdentityMismatch
                } else if acknowledged {
                    Outcome::Success
                } else {
                    Outcome::RecoveredSuccess
                },
                detail: if identity_matches {
                    format!("{set_detail}; requester matches expected EVM and all 13 donor fields")
                } else {
                    format!("{set_detail}; identity mismatch (expected EVM match: {}; differing donor fields: {})",
                        keys.evm_address == expected_evm, mismatches.join(", "))
                },
                keys: Some(keys),
            }
        }
        Ok(Err(ParentError::EnclaveError { code: 1, message }))
            if message == "key not initialized" && set_result.is_ok() && !acknowledged =>
        {
            Completion {
                outcome: Outcome::NotInitialized,
                keys: None,
                detail: format!("{set_detail}; requester reported no keys at observation time (Initial or Cloning). This is not a durable session status; do not blindly retry SetClone"),
            }
        }
        observation => Completion {
            outcome: Outcome::Unknown,
            keys: None,
            detail: format!("{set_detail}; identity could not be established: {observation:?}. Reconcile read-only; do not retry SetClone automatically"),
        },
    }
}

/// Equality against the donor's reported bundle. The CLI does not authenticate
/// this RPC; the enclave's AF-08 attested commitment is the trust gate.
pub fn identity_field_mismatches(
    local: &PublicKeysResponse,
    donor: &AttestedPublicKeyResponse,
) -> Vec<&'static str> {
    let mut diff = Vec::new();
    macro_rules! compare {
        ($($field:ident),+ $(,)?) => {$(
            if local.$field != donor.$field { diff.push(stringify!($field)); }
        )+};
    }
    compare!(
        evm_address,
        evm_uncompressed_pub,
        btc_compressed_pub,
        btc_xpub,
        master_fingerprint,
        account_xpub_vanilla,
        account_xpub_colored,
        chain_id,
        bridge_contract,
        rgb_asset_id,
        evm_gas_tx_uncompressed_pub,
        evm_gas_tx_address,
        ccd_ed25519_pub
    );
    diff
}
