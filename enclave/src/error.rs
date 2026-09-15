use thiserror::Error;

/// Fixed custody diagnostics. Host/provider error strings never enter this API.
#[cfg(feature = "rgb-swap")]
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
    #[cfg(feature = "rgb-swap")]
    #[error("swap custody {service}: {failure}")]
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
            #[cfg(feature = "rgb-swap")]
            EnclaveError::Custody {
                failure: CustodyFailure::Unavailable,
                ..
            } => 2,
            EnclaveError::CrossCheck(_) => 3, // ERROR_CODE_VALIDATION_FAILED
            EnclaveError::Spv(_) => 3,        // ERROR_CODE_VALIDATION_FAILED
            EnclaveError::NotReady { .. } => 2, // ERROR_CODE_NOT_READY
            _ => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, EnclaveError>;
