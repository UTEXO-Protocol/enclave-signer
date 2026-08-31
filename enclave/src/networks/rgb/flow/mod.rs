//! Per-flow RGB validation rules.
//!
//! The bridge runs two RGB flows, and each ships as its own enclave instance
//! with its own PCR0:
//!
//!   * **send/receive** (`rgb-swap`) - the bridge holds a pool of the asset.
//!     A deposit pays the user with an IFA `Transfer`; a withdrawal is a
//!     `Transfer` back to the bridge.
//!   * **mint/burn** (`rgb-mint-burn`) - the bridge owns the contract's
//!     inflation rights. A deposit mints with an IFA `Inflation`; a withdrawal
//!     destroys units with an IFA `Burn`.
//!
//! The two differ only in which transition types they accept and how the
//! amounts bind, but those are exactly the checks that authorize value to
//! move. Splitting them per file (rather than branching at runtime) means a
//! send/receive enclave carries no mint rule at all: an attacker who gets a
//! mint-shaped consignment past every other check still cannot reach a code
//! path that would sign it.
//!
//! Exactly one of the two features must be enabled - see the `compile_error!`
//! pair in `lib.rs`. Both files expose the same item names, so every caller
//! writes `flow::...` and never a `cfg`.
//!
//! Everything NOT flow-specific stays shared: consignment parsing
//! ([`super::validation`]), SPV anchoring, and the PSBT mechanics in
//! [`super::psbt_validation`] (txid identity bind, prevout canary, sighash
//! guard, recipient/change leg split, fee-rate bound).

#[cfg(feature = "rgb-mint-burn")]
mod mint_burn;
#[cfg(feature = "rgb-swap")]
mod swap;

#[cfg(feature = "rgb-mint-burn")]
pub use mint_burn::*;
#[cfg(feature = "rgb-swap")]
pub use swap::*;
