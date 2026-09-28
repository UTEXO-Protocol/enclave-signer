use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnclaveError {
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

    #[error("identity mismatch: cloned seed does not derive to expected address")]
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
            EnclaveError::CrossCheck(_) => 3,   // ERROR_CODE_VALIDATION_FAILED
            EnclaveError::Spv(_) => 3,          // ERROR_CODE_VALIDATION_FAILED
            EnclaveError::NotReady { .. } => 2, // ERROR_CODE_NOT_READY
            _ => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, EnclaveError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networks::rgb::spv::SpvError;

    /// A real `prost::DecodeError`, produced by decoding bytes that are not a
    /// valid message (the constructor is internal to prost).
    fn decode_error() -> prost::DecodeError {
        <crate::proto::EnclaveRequest as prost::Message>::decode(&[0xffu8; 4][..])
            .expect_err("0xff bytes are not a valid message")
    }

    /// One instance of every variant, so a new variant added without a wire
    /// code mapping shows up here as a compile error in the exhaustive match.
    fn all_variants() -> Vec<EnclaveError> {
        vec![
            EnclaveError::KeyNotInitialized,
            EnclaveError::AlreadyInitialized,
            EnclaveError::InvalidKey("k".into()),
            EnclaveError::InvalidRequest("r".into()),
            EnclaveError::Framing("f".into()),
            EnclaveError::ProtobufDecode(decode_error()),
            EnclaveError::Io(std::io::Error::other("io")),
            EnclaveError::Signing("s".into()),
            EnclaveError::CrossCheck("c".into()),
            EnclaveError::Internal("i".into()),
            EnclaveError::NotReady {
                state: "initial".into(),
            },
            EnclaveError::Attestation("a".into()),
            EnclaveError::Certificate("ce".into()),
            EnclaveError::Clone("cl".into()),
            EnclaveError::PcrMismatch {
                pcr: 1,
                expected: "aa".into(),
                actual: "bb".into(),
            },
            EnclaveError::NonceReplay,
            EnclaveError::DigestMismatch,
            EnclaveError::PubkeyMismatch,
            EnclaveError::IdentityMismatch,
            EnclaveError::Spv("spv".into()),
        ]
    }

    #[test]
    fn validation_failures_map_to_code_3() {
        assert_eq!(EnclaveError::CrossCheck("x".into()).error_code(), 3);
        assert_eq!(EnclaveError::Spv("x".into()).error_code(), 3);
    }

    #[test]
    fn not_ready_maps_to_code_2() {
        assert_eq!(
            EnclaveError::NotReady {
                state: "cloning".into()
            }
            .error_code(),
            2
        );
    }

    #[test]
    fn every_other_variant_maps_to_code_1() {
        for e in all_variants() {
            let expected = match e {
                EnclaveError::CrossCheck(_) | EnclaveError::Spv(_) => 3,
                EnclaveError::NotReady { .. } => 2,
                EnclaveError::KeyNotInitialized
                | EnclaveError::AlreadyInitialized
                | EnclaveError::InvalidKey(_)
                | EnclaveError::InvalidRequest(_)
                | EnclaveError::Framing(_)
                | EnclaveError::ProtobufDecode(_)
                | EnclaveError::Io(_)
                | EnclaveError::Signing(_)
                | EnclaveError::Internal(_)
                | EnclaveError::Attestation(_)
                | EnclaveError::Certificate(_)
                | EnclaveError::Clone(_)
                | EnclaveError::PcrMismatch { .. }
                | EnclaveError::NonceReplay
                | EnclaveError::DigestMismatch
                | EnclaveError::PubkeyMismatch
                | EnclaveError::IdentityMismatch => 1,
            };
            assert_eq!(e.error_code(), expected, "{e}");
        }
    }

    #[test]
    fn display_texts_carry_the_payload() {
        assert_eq!(
            EnclaveError::KeyNotInitialized.to_string(),
            "key not initialized"
        );
        assert_eq!(
            EnclaveError::AlreadyInitialized.to_string(),
            "already initialized"
        );
        assert_eq!(
            EnclaveError::InvalidKey("bad".into()).to_string(),
            "invalid key: bad"
        );
        assert_eq!(
            EnclaveError::InvalidRequest("bad".into()).to_string(),
            "invalid request: bad"
        );
        assert_eq!(
            EnclaveError::Framing("bad".into()).to_string(),
            "framing error: bad"
        );
        assert_eq!(
            EnclaveError::Signing("bad".into()).to_string(),
            "signing error: bad"
        );
        assert_eq!(
            EnclaveError::CrossCheck("bad".into()).to_string(),
            "cross-check failed: bad"
        );
        assert_eq!(
            EnclaveError::Internal("bad".into()).to_string(),
            "internal error: bad"
        );
        assert_eq!(
            EnclaveError::NotReady {
                state: "cloning".into()
            }
            .to_string(),
            "not ready: enclave is in cloning state"
        );
        assert_eq!(
            EnclaveError::Attestation("bad".into()).to_string(),
            "attestation error: bad"
        );
        assert_eq!(
            EnclaveError::Certificate("bad".into()).to_string(),
            "certificate error: bad"
        );
        assert_eq!(
            EnclaveError::Clone("bad".into()).to_string(),
            "clone failed: bad"
        );
        assert_eq!(
            EnclaveError::PcrMismatch {
                pcr: 2,
                expected: "aa".into(),
                actual: "bb".into()
            }
            .to_string(),
            "PCR mismatch: PCR2 expected=aa, actual=bb"
        );
        assert_eq!(
            EnclaveError::NonceReplay.to_string(),
            "nonce replay detected"
        );
        assert_eq!(
            EnclaveError::DigestMismatch.to_string(),
            "cloning digest mismatch"
        );
        assert!(EnclaveError::PubkeyMismatch
            .to_string()
            .starts_with("pubkey mismatch"));
        assert!(EnclaveError::IdentityMismatch
            .to_string()
            .starts_with("identity mismatch"));
        assert_eq!(EnclaveError::Spv("bad".into()).to_string(), "spv: bad");
    }

    #[test]
    fn io_errors_convert_and_keep_their_message() {
        let e: EnclaveError = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof").into();
        assert!(
            matches!(e, EnclaveError::Io(ref inner) if inner.kind() == std::io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(e.to_string(), "io error: eof");
        assert_eq!(e.error_code(), 1);
    }

    #[test]
    fn protobuf_decode_errors_convert() {
        let e: EnclaveError = decode_error().into();
        assert!(matches!(e, EnclaveError::ProtobufDecode(_)));
        assert!(e.to_string().starts_with("protobuf decode error:"));
    }

    #[test]
    fn spv_errors_convert_to_spv_with_their_display_text() {
        let e: EnclaveError = SpvError::HeaderNotFound(42).into();
        match &e {
            EnclaveError::Spv(msg) => assert_eq!(msg, "no header at height 42"),
            other => panic!("expected Spv, got {other:?}"),
        }
        assert_eq!(e.error_code(), 3, "an SPV failure is a validation failure");

        let e: EnclaveError = SpvError::PowFailed { height: 7 }.into();
        assert_eq!(
            e.to_string(),
            "spv: header at height 7 fails PoW: hash > target"
        );
    }

    #[test]
    fn verify_errors_map_variant_for_variant() {
        use attestation_verify::VerifyError;
        let e: EnclaveError = VerifyError::Attestation("a".into()).into();
        assert!(matches!(e, EnclaveError::Attestation(ref s) if s == "a"));
        let e: EnclaveError = VerifyError::Certificate("c".into()).into();
        assert!(matches!(e, EnclaveError::Certificate(ref s) if s == "c"));
        let e: EnclaveError = VerifyError::PcrMismatch {
            pcr: 1,
            expected: "e".into(),
            actual: "a".into(),
        }
        .into();
        match e {
            EnclaveError::PcrMismatch {
                pcr,
                expected,
                actual,
            } => {
                assert_eq!(pcr, 1);
                assert_eq!(expected, "e");
                assert_eq!(actual, "a");
            }
            other => panic!("expected PcrMismatch, got {other:?}"),
        }
    }

    #[test]
    fn result_alias_carries_enclave_error() {
        fn f(fail: bool) -> Result<u8> {
            if fail {
                Err(EnclaveError::Internal("no".into()))
            } else {
                Ok(1)
            }
        }
        assert_eq!(f(false).unwrap(), 1);
        assert!(matches!(f(true), Err(EnclaveError::Internal(_))));
    }
}
