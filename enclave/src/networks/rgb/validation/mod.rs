//! In-enclave RGB consignment validation using rgbstd.
//!
//! This module only wires the submodules:
//!
//! - `source.rs`: validate an `RgbSource` payload and its SPV evidence.
//! - `indexer.rs`: the indexer client and the consignment witness resolver.
//! - `consensus.rs`: run rgbstd validation over the consignment bytes.
//! - `consignment.rs`: decode the resulting `Transfer` into plain shapes.
//! - `types.rs`: those shapes.
//! - `asset_bind.rs`: bind the validated asset id to the operator pin.
//! - `bfa.rs`: the BFA mint anchors and their binding to EVM locks.
//! - `schema.rs`: the schema rules a consignment is validated under.
//!
//! The enclave does not trust the listener `consignment_valid` boolean.

mod asset_bind;
mod bfa;
mod consensus;
mod consignment;
mod indexer;
mod schema;
mod source;
mod types;

#[cfg(test)]
mod tests;

pub use asset_bind::{assert_asset_binding, AssetBindMode};
pub use bfa::{AnchorBinder, BfaBridge, BoundAnchors, MintAnchor, VerifiedLock};
pub use consignment::is_mint_transition;
pub use indexer::RgbValidator;
pub(crate) use schema::BFA_RULES;
pub use source::assert_consignment_size;
#[cfg(rgb_to_evm)]
pub use source::validate_source;
pub use types::{OutputSeal, TransitionOutput, TransitionSummary, ValidatedConsignment};
