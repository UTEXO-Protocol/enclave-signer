pub mod attest_verify;
pub mod client;
pub mod config;
pub mod error;
pub mod framing;
pub mod grpc_server;
pub mod health;

pub mod grpc_proto {
    pub use federated_signer_proto::parent::*;
    pub use federated_signer_proto::signer;
}

pub use federated_signer_proto::enclave as enclave_proto;
pub use federated_signer_proto::parent as enriched;
pub use federated_signer_proto::signer;
