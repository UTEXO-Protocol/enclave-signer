//! Request handling, with one module for each request family.
//!
//! The flow is `wire.rs` -> `dispatch.rs` -> one handler module.

#[cfg(feature = "bfa-validation")]
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
#[cfg(feature = "rgb-validation")]
mod rate_limit;
mod sign;
mod signers;
#[cfg(feature = "rgb-validation")]
mod spv;
mod wire;

pub use context::ServerContext;
#[cfg(feature = "rgb-validation")]
pub use rate_limit::SubmitRateLimiter;
pub use wire::{handle_connection, handle_connection_until};
