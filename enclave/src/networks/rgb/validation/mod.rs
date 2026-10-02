//! In-enclave RGB consignment validation using rgbstd plus a witness resolver.
//!
//! Wiring only. The pipeline reads left to right:
//!
//! - `source.rs`: validate an `RgbSource` payload and its SPV evidence.
//! - `indexer.rs`: the Esplora/Electrum client `RgbValidator` talks through.
//! - `consensus.rs`: run rgbstd validation over the consignment bytes.
//! - `consignment.rs`: decode the resulting `Transfer` into plain shapes.
//! - `types.rs`: those shapes.
//! - `asset_bind.rs`: bind the validated asset id to the operator pin.
//! - `bfa.rs`: the BFA schema keys and its mint/burn binding.
//! - `schema.rs`: the trusted type system a consignment is pinned against.
//!
//! This replaces trusting the listener's `consignment_valid` boolean.

mod asset_bind;
pub mod bfa;
mod consensus;
mod consignment;
mod indexer;
mod schema;
mod source;
mod types;

#[cfg(test)]
mod tests;

pub use asset_bind::{assert_asset_binding, AssetBindMode};
#[cfg(feature = "bfa-validation")]
pub use bfa::{bfa_binding, BfaBinding};
pub use consignment::is_mint_transition;
pub use indexer::RgbValidator;
pub use source::assert_consignment_size;
#[cfg(rgb_to_evm)]
pub use source::validate_source;
pub use types::{OutputSeal, TransitionOutput, TransitionSummary, ValidatedConsignment};
