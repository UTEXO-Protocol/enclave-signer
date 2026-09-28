pub mod attest_verify;
pub mod client;
pub mod config;
pub mod error;
pub mod framing;
pub mod grpc_server;

pub mod grpc_proto {
    pub use federated_signer_proto::parent::*;
    pub use federated_signer_proto::signer;
}

pub use federated_signer_proto::enclave as enclave_proto;
pub use federated_signer_proto::parent as enriched;
pub use federated_signer_proto::signer;

#[cfg(test)]
mod tests {
    /// The three aliases must name the same generated packages.
    #[test]
    fn aliases_resolve_to_one_schema() {
        assert_eq!(
            crate::grpc_proto::signer::DataType::EvmGasTx as i32,
            crate::signer::DataType::EvmGasTx as i32
        );
        let a = crate::grpc_proto::InitializeRequest {
            cloning_secret: "x".into(),
        };
        let b: crate::enriched::InitializeRequest = a.clone();
        assert_eq!(a, b);
        let _: crate::enclave_proto::EnclaveRequest = Default::default();
    }
}
