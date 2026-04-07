pub mod client;
pub mod config;
pub mod error;
pub mod framing;
pub mod grpc_server;

/// Enclave wire-protocol types (from enclave.proto).
/// Used by both the gRPC translation layer and the CLI.
pub mod enclave_proto {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enclave.rs"));
}

/// Enriched payload types (from enriched-payload.proto).
/// Listener serializes these into SignRequest.data; we deserialize in the gRPC server.
pub mod enriched {
    include!(concat!(env!("OUT_DIR"), "/tricorn.enriched.rs"));
}

/// gRPC types generated from parentadapter.proto + signer/signer.proto (tonic server + prost messages).
/// This matches the federated-signer-node's listener-enclave.proto interface.
pub mod grpc_proto {
    tonic::include_proto!("tricorn");
}
