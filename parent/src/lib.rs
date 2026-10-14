// `insecure-dev` serves plaintext gRPC with no client auth on any address.
// A release build (`debug_assertions` off) with it fails to compile.
// `not(test)` exempts the unit-test compilation only. Dev images build in debug mode.
#[cfg(all(feature = "insecure-dev", not(debug_assertions), not(test)))]
compile_error!(
    "`insecure-dev` must not be enabled in a release build (debug_assertions off): \
     it serves plaintext gRPC with no client auth. Build dev images in debug mode."
);

pub mod attest_verify;
pub mod client;
pub mod config;
pub mod error;
pub mod framing;
pub mod grpc_server;
pub mod header_source;
pub mod header_sync;
pub mod health;
pub mod launch_check;
pub mod seed_persistence;
pub mod transport_security;

pub mod grpc_proto {
    pub use federated_signer_proto::parent::*;
    pub use federated_signer_proto::signer;
}

pub use federated_signer_proto::enclave as enclave_proto;
pub use federated_signer_proto::parent as enriched;
pub use federated_signer_proto::signer;
