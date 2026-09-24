//! Per-network validation, one module per chain family.
//!
//! Wiring only. `route.rs` holds the source/destination dispatch and the
//! route-level amount binding; each network module owns the checks for its
//! own payload.

// `ccd` is self-contained, so its module is feature-gated. `rgb` and `evm` stay
// always-compiled: they are woven into shared code (keys.rs PSBT signing,
// error.rs SpvError), and their heavy deps sit behind `rgb-validation`.
#[cfg(feature = "ccd")]
pub mod ccd;
pub mod evm;
pub mod rgb;
mod route;

pub use route::{
    validate_destination, validate_route_proofs, validate_source, DestinationProof, RouteProof,
    SourceProof, ValidationContext,
};
