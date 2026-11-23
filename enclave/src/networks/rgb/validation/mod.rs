//! In-enclave RGB consignment validation through rgb-lib.
//!
//! This module only wires the submodules:
//!
//! - `source.rs`: validate an `RgbSource` payload and its SPV evidence.
//! - `validator.rs`: the validator of one Bitcoin network.
//! - `witness.rs`: the resolver of SPV-verified witness positions.
//! - `consensus.rs`: run rgb-lib validation over a consignment file.
//! - `child.rs`: the validator child, which runs that validation for the burn
//!   signer and asks it for every resolver answer.
//! - `ipc.rs`: the frames between the burn signer and its validator child.
//! - `runner.rs`: run a burn validation in a validator child, answer its
//!   resolvers and end it before the request deadline.
//! - `cost.rs`: the caps on the work rgb-lib does, checked before it runs.
//! - `consignment.rs`: read rgb-lib's inspection of the accepted file into
//!   plain shapes.
//! - `types.rs`: those shapes.
//! - `asset_bind.rs`: bind the validated asset id to the operator pin.
//! - `bfa.rs`: the BFA mint claims and their binding to EVM locks by lockId.
//! - `schema.rs`: the reject list the genesis names.
//! - `reject_list.rs`: the issuer's reject list decisions.
//!
//! The enclave does not trust the listener `consignment_valid` boolean.

mod asset_bind;
mod bfa;
#[cfg(all(rgb_to_evm, unix))]
mod child;
mod consensus;
mod consignment;
mod cost;
#[cfg(all(rgb_to_evm, unix))]
mod ipc;
mod reject_list;
#[cfg(all(rgb_to_evm, unix))]
mod runner;
mod schema;
mod source;
mod types;
mod validator;
mod witness;

#[cfg(test)]
mod tests;

pub use asset_bind::{assert_asset_binding, AssetBindMode};
pub use bfa::{decode_opid, lock_id, AnchorBinder, BoundAnchors, MintAnchor, VerifiedLock};
#[cfg(all(rgb_to_evm, unix, any(test, debug_assertions, not(feature = "vsock"))))]
pub use child::run_if_test_child;
#[cfg(all(rgb_to_evm, unix))]
pub use child::{serve as serve_validator_child, CHILD_ARG};
pub use reject_list::{
    decisions, Decisions, ListAccess, OpoutKey, RejectListContract, RejectListEntry,
    RejectListReader,
};
#[cfg(all(rgb_to_evm, unix))]
pub use runner::{probe as probe_validator_child, ChildProgram, ChildReport};
pub use source::assert_consignment_size;
#[cfg(rgb_to_evm)]
pub use source::validate_source;
pub use types::{
    OutputSeal, TransitionOutput, TransitionSummary, ValidatedConsignment, WitnessBlock,
};
pub use validator::RgbValidator;
pub use witness::BuriedHeaders;
