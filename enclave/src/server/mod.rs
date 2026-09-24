//! Request handling: one module per request family.
//!
//! Wiring only. The flow is `wire.rs` -> `dispatch.rs` -> one handler module.

#[cfg(feature = "bfa-validation")]
mod bfa;
mod cloning;
mod context;
mod dispatch;
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
pub use wire::handle_connection;
