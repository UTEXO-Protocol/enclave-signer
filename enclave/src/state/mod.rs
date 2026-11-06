//! Enclave runtime state.
//!
//! - `enclave.rs`: the `Phase` machine and `EnclaveState`. All signing entry
//!   points go through `EnclaveState`.
//! - `replay_guard.rs`: the in-memory nonce and bridge-operation guards.
//! - `cloning_session.rs`: per-handshake cloning state.
//! - `refill_rate.rs`: the mint signer's rights-refill rate limit.

mod cloning_session;
mod enclave;
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
mod refill_rate;
mod replay_guard;

#[cfg(test)]
mod tests;

pub use cloning_session::CloningSession;
pub use enclave::{EnclaveState, ExportQuotaReservation, Phase};
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
pub use refill_rate::{RefillRateLimit, MAX_REFILLS_PER_HOUR};
pub use replay_guard::{NonceReplayGuard, ReplayReservation};
