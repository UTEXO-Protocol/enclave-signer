use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParentError {
    #[error("connection failed: {0}")]
    Connection(String),

    #[error("framing error: {0}")]
    Framing(String),

    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("enclave returned error (code {code}): {message}")]
    EnclaveError { code: u32, message: String },
}

pub type Result<T> = std::result::Result<T, ParentError>;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn display_formats_each_variant() {
        assert_eq!(
            ParentError::Connection("refused".into()).to_string(),
            "connection failed: refused"
        );
        assert_eq!(
            ParentError::Framing("short".into()).to_string(),
            "framing error: short"
        );
        assert_eq!(
            ParentError::EnclaveError {
                code: 3,
                message: "cross-check".into()
            }
            .to_string(),
            "enclave returned error (code 3): cross-check"
        );
        let io: ParentError = std::io::Error::other("pipe").into();
        assert_eq!(io.to_string(), "io error: pipe");

        let decode = <crate::enclave_proto::EnclaveRequest as Message>::decode(&[0xffu8; 4][..])
            .expect_err("invalid protobuf must not decode");
        let e: ParentError = decode.into();
        assert!(matches!(e, ParentError::ProtobufDecode(_)), "{e}");
        assert!(e.to_string().starts_with("protobuf decode error: "));
    }

    #[test]
    fn io_errors_keep_their_kind() {
        let e: ParentError = std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into();
        match e {
            ParentError::Io(inner) => assert_eq!(inner.kind(), std::io::ErrorKind::UnexpectedEof),
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn result_alias_carries_parent_error() {
        fn f(fail: bool) -> Result<u8> {
            if fail {
                Err(ParentError::Framing("x".into()))
            } else {
                Ok(1)
            }
        }
        assert_eq!(f(false).unwrap(), 1);
        assert!(matches!(f(true), Err(ParentError::Framing(_))));
    }
}
