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
