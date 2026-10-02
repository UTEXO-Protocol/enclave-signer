//! Per-flow RGB validation rules.
//!
//! The bridge has two RGB flows. Each flow is a separate enclave build with
//! its own PCR0:
//!
//!   * **send/receive** (`rgb-swap`) - the bridge holds a pool of the asset.
//!     A deposit pays the user with a BFA `Transfer`. A withdrawal is a
//!     `Transfer` back to the bridge.
//!   * **mint/burn** (`rgb-mint-burn`) - the bridge owns the mint right of the
//!     contract. A deposit mints with a BFA `Bridge`. A withdrawal destroys
//!     units with a BFA `Burn`.
//!
//! The flows differ only in the accepted transition types and the amount
//! binds. These are the checks that authorize value to move. Thus each flow
//! is a separate file, not a runtime branch. A send/receive enclave contains
//! no mint rule, so a mint-shaped consignment has no code path that signs it.
//!
//! Exactly one of the two features must be on (see the `compile_error!` pair
//! in `lib.rs`). Both files export the same item names, so callers use
//! `flow::...` without a `cfg`.
//!
//! Shared code that is not flow-specific: consignment parsing
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
