//! Request handling, with one module for each request family.
//!
//! The flow is `wire.rs` -> `dispatch.rs` -> one handler module.

#[cfg(feature = "rgb-validation")]
mod bfa;
// KMS persistence disables cloning. All replicas recover the same seed from
// KMS, so the cloning handshake has no purpose.
#[cfg(not(feature = "kms-persistence"))]
mod cloning;
mod context;
mod dispatch;
mod endpoints;
mod health;
mod keys;
mod limits;
#[cfg(feature = "rgb-validation")]
mod rate_limit;
// Only a build that validates consignments reads the reject list.
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
mod reject_list;
// The mint signer's own rights send. No other role holds mint rights.
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
mod rights_refill;
mod sign;
mod signers;
#[cfg(feature = "rgb-validation")]
mod spv;
mod wire;

pub use context::ServerContext;
#[cfg(feature = "rgb-validation")]
pub use rate_limit::SubmitRateLimiter;
pub use wire::{handle_connection, handle_connection_until};
