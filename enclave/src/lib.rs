#![deny(unsafe_code)]

pub mod error;
pub mod framing;
pub mod keys;
pub mod server;
pub mod signing;
pub mod validation;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enclave.rs"));
}

pub mod enriched {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enriched.rs"));
}
