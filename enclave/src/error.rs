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

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, EnclaveError>;
