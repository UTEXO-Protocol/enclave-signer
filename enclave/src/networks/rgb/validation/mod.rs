//! In-enclave RGB consignment validation through rgb-lib.
//!
//! This module only wires the submodules:
//!
//! - `source.rs`: validate an `RgbSource` payload and its SPV evidence.
//! - `indexer.rs`: the indexer client, and the mint path's witness source.
//! - `witness.rs`: the on-chain witness resolver consensus runs with.
//! - `consensus.rs`: run rgb-lib validation over the consignment bytes.
//! - `cost.rs`: the caps on the work rgb-lib does, checked before it runs.
//! - `scratch.rs`: the file rgb-lib reads the bytes from.
//! - `consignment.rs`: decode the validated `Transfer` into plain shapes.
//! - `transition.rs`: read one transition's globals and seals, for both paths.
//! - `types.rs`: those shapes.
//! - `asset_bind.rs`: bind the validated asset id to the operator pin.
//! - `bfa.rs`: the BFA mint anchors and their binding to EVM locks.
//! - `schema.rs`: the genesis gate and its reject list.
//! - `reject_list.rs`: the issuer's reject list decisions.
//!
//! The enclave does not trust the listener `consignment_valid` boolean.

mod asset_bind;
mod bfa;
mod consensus;
mod consignment;
mod cost;
mod indexer;
mod reject_list;
mod schema;
mod scratch;
mod source;
mod transition;
mod types;
mod witness;

#[cfg(test)]
mod tests;

pub use asset_bind::{assert_asset_binding, AssetBindMode};
pub use bfa::{AnchorBinder, BfaBridge, BoundAnchors, MintAnchor, VerifiedLock};
pub use consignment::is_mint_transition;
pub use indexer::{IndexerWitnesses, RgbValidator};
pub use reject_list::{
    decisions, Decisions, ListAccess, OpoutKey, RejectListContract, RejectListEntry,
    RejectListReader,
};
pub use source::assert_consignment_size;
#[cfg(rgb_to_evm)]
pub use source::validate_source;
pub use transition::{output_seal, single_global};
pub use types::{OutputSeal, TransitionOutput, TransitionSummary, ValidatedConsignment};
pub use witness::{ConfirmedWitnesses, WitnessCheck};
