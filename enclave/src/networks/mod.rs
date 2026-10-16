//! Per-network validation, one module per chain family.
//!
//! Wiring only. `route.rs` holds the source/destination dispatch and the
//! route amount bind. Each network module owns the checks for its payload.

// `ccd` is self-contained, so a feature gates it. `rgb` and `evm` always
// compile because shared code uses them (keys.rs PSBT signing, error.rs
// SpvError). Their heavy deps are behind `rgb-validation`.
#[cfg(feature = "ccd")]
pub mod ccd;
pub mod evm;
pub mod rgb;
mod route;

pub use route::{
    validate_destination, validate_route_proofs, validate_source, DestinationProof, RouteProof,
    SourceProof, ValidationContext,
};
