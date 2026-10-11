//! Enclave runtime state.
//!
//! - `enclave.rs`: the `Phase` machine and `EnclaveState`. All signing entry
//!   points go through `EnclaveState`.
//! - `replay_guard.rs`: the in-memory nonce and bridge-operation guards.
//! - `cloning_session.rs`: per-handshake cloning state.

mod cloning_session;
mod enclave;
mod replay_guard;

#[cfg(test)]
mod tests;

pub use cloning_session::CloningSession;
pub use enclave::{EnclaveState, ExportQuotaReservation, Phase};
pub use replay_guard::{NonceReplayGuard, ReplayReservation, StoredOpResponse};
