#![deny(unsafe_code)]

pub mod error;
pub mod framing;
pub mod keys;
pub mod server;
pub mod signing;
pub mod validation;
#[cfg(all(feature = "vsock", target_os = "linux"))]
pub mod vsock_forwarder;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enclave.rs"));
}

pub mod enriched {
    include!(concat!(env!("OUT_DIR"), "/tricorn.enriched.rs"));
}
