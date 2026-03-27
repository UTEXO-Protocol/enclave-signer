pub mod client;
pub mod error;
pub mod framing;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enclave.rs"));
}

pub mod enriched {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enriched.rs"));
}
