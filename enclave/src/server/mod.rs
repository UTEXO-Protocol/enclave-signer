//! Request handling: one module per request family.
//!
//! Wiring only. The flow is `wire.rs` -> `dispatch.rs` -> one handler module.
//!
//! - `context.rs`: `ServerContext`, the boot-time state every handler reads.
//! - `wire.rs`: the framed read/dispatch/write connection loop.
//! - `dispatch.rs`: proto oneof variant to handler, and error mapping.
//! - `sign.rs`: the `Sign` bridge route, source/destination orchestration.
//! - `signers.rs`: the leaf signers each route ends in.
//! - `keys.rs`: `InitializeKey`, `GetPublicKey`, attested public key.
//! - `cloning.rs`: the donor/requester seed-cloning handshake.
//! - `health.rs`: the readiness probe.
//! - `spv.rs`: `SubmitHeaders` / `GetLastSavedBlock` (spv builds).
//! - `rate_limit.rs`: the cumulative `SubmitHeaders` budget (spv builds).
//! - `bfa.rs`: BFA mint lock verification (bfa-validation builds).

#[cfg(feature = "bfa-validation")]
mod bfa;
mod cloning;
mod context;
mod dispatch;
mod health;
mod keys;
#[cfg(feature = "spv")]
mod rate_limit;
mod sign;
mod signers;
#[cfg(feature = "spv")]
mod spv;
mod wire;

pub use context::ServerContext;
#[cfg(feature = "spv")]
pub use rate_limit::SubmitRateLimiter;
pub use wire::handle_connection;
