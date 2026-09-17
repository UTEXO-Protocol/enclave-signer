//! Enclave runtime state.
//!
//! Wiring only.
//!
//! - `enclave.rs`: the `Phase` machine and `EnclaveState`, the door every
//!   signing entry point goes through.
//! - `replay_guard.rs`: the in-memory nonce and bridge-operation guards.
//! - `cloning_session.rs`: per-handshake cloning state.

mod cloning_session;
mod enclave;
mod replay_guard;

#[cfg(test)]
mod tests;

pub use cloning_session::CloningSession;
pub use enclave::{EnclaveState, Phase};
pub use replay_guard::{NonceReplayGuard, ReplayReservation};
