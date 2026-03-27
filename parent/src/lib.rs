pub mod client;
pub mod config;
pub mod error;
pub mod framing;
pub mod grpc_server;

/// Enclave wire-protocol types (from enclave.proto / enriched-payload.proto).
/// Used by both the gRPC translation layer and the CLI.
pub mod enclave_proto {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enclave.rs"));
}

pub mod enriched {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enriched.rs"));
}

/// gRPC types generated from parentadapter.proto (tonic server + prost messages).
pub mod grpc_proto {
    tonic::include_proto!("boostylabs.parentadapter");
}
