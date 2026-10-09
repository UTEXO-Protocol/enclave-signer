use thiserror::Error;

/// Fixed custody diagnostics. Host/provider error strings never enter this API.
#[cfg(feature = "kms-persistence")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CustodyFailure {
    #[error("configuration_error; verify custody configuration")]
    Configuration,
    #[error("access_denied; verify credentials and custody policies")]
    AccessDenied,
    #[error("unavailable; retry the operation")]
    Unavailable,
    #[error("invalid_ciphertext; restore the saved ciphertext and verify the key")]
    InvalidCiphertext,
    #[error("key_or_ciphertext_error; verify the configured KMS key and persisted ciphertext")]
    KeyOrCiphertext,
    #[error("invalid_response; custody response was rejected")]
    InvalidResponse,
    #[error("internal_error; verify the enclave SDK and NSM runtime")]
    Internal,
}

#[derive(Debug, Error)]
pub enum EnclaveError {
    #[cfg(feature = "kms-persistence")]
    #[error("seed custody {service}: {failure}")]
    Custody {
        service: &'static str,
        failure: CustodyFailure,
    },

    #[error("key not initialized")]
    KeyNotInitialized,

    #[error("already initialized")]
    AlreadyInitialized,

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("framing error: {0}")]
    Framing(String),

    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("cross-check failed: {0}")]
    CrossCheck(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("not ready: enclave is in {state} state")]
    NotReady { state: String },

    #[error("attestation error: {0}")]
    Attestation(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("clone failed: {0}")]
    Clone(String),

    #[error("PCR mismatch: PCR{pcr} expected={expected}, actual={actual}")]
    PcrMismatch {
        pcr: u32,
        expected: String,
        actual: String,
    },

    #[error("nonce replay detected")]
    NonceReplay,

    #[error("seed-export hard cap reached ({used}/{cap}); export refused")]
    ExportCapReached { used: u64, cap: u64 },

    #[error("cloning digest mismatch")]
    DigestMismatch,

    #[error("pubkey mismatch: attestation pubkey does not match claimed pubkey")]
    PubkeyMismatch,

    #[error("identity mismatch: recovered seed does not derive to expected address")]
    IdentityMismatch,

    #[error("spv: {0}")]
    Spv(String),
}

impl From<crate::networks::rgb::spv::SpvError> for EnclaveError {
    fn from(e: crate::networks::rgb::spv::SpvError) -> Self {
        EnclaveError::Spv(e.to_string())
    }
}

impl EnclaveError {
    /// Map error to a proto error code.
    pub fn error_code(&self) -> u32 {
        match self {
            #[cfg(feature = "kms-persistence")]
            EnclaveError::Custody {
                failure: CustodyFailure::Unavailable,
                ..
            } => 2,
            EnclaveError::CrossCheck(_) => 3,   // validation failed
            EnclaveError::Spv(_) => 3,          // validation failed
            EnclaveError::NotReady { .. } => 2, // not ready
            _ => 1,
        }
    }

    /// Map a GetClone error to a proto error code. Other errors use `error_code`.
    pub fn clone_error_code(&self) -> u32 {
        match self {
            EnclaveError::InvalidRequest(_) => 4,
            EnclaveError::DigestMismatch
            | EnclaveError::PubkeyMismatch
            | EnclaveError::Attestation(_)
            | EnclaveError::Certificate(_)
            | EnclaveError::PcrMismatch { .. } => 5,
            EnclaveError::NonceReplay => 6,
            EnclaveError::ExportCapReached { .. } => 7,
            EnclaveError::KeyNotInitialized => 3,
            _ => self.error_code(),
        }
    }
}

pub type Result<T> = std::result::Result<T, EnclaveError>;

#[cfg(test)]
mod tests {
    use super::EnclaveError::*;

    #[test]
    fn clone_and_rpc_codes() {
        let pcr = PcrMismatch {
            pcr: 0,
            expected: String::new(),
            actual: String::new(),
        };
        let not_ready = NotReady {
            state: String::new(),
        };
        let cap = ExportCapReached { used: 1, cap: 1 };
        // (error, error_code, clone_error_code)
        let rows = [
            (InvalidRequest(String::new()), 1, 4),
            (DigestMismatch, 1, 5),
            (PubkeyMismatch, 1, 5),
            (Attestation(String::new()), 1, 5),
            (Certificate(String::new()), 1, 5),
            (pcr, 1, 5),
            (NonceReplay, 1, 6),
            (cap, 1, 7),
            (KeyNotInitialized, 1, 3),
            (not_ready, 2, 2),
            (Clone(String::new()), 1, 1),
            (Internal(String::new()), 1, 1),
            (CrossCheck(String::new()), 3, 3),
            (Spv(String::new()), 3, 3),
        ];
        for (e, rpc, clone) in rows {
            assert_eq!(e.error_code(), rpc, "{e:?}");
            assert_eq!(e.clone_error_code(), clone, "{e:?}");
        }
    }
}
