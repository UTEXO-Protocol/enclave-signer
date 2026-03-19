pub mod client;
pub mod error;
pub mod framing;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enclave.rs"));
}
