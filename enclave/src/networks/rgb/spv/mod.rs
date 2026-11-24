//! In-enclave Bitcoin SPV: the header chain.
//!
//! - `chain.rs`: in-memory header chain from a compile-time checkpoint, with
//!   bounded reorg support.
//! - `validation.rs`: PoW and retarget checks on mainnet and the testnets.
//!   Signet and regtest check chain linkage, the clock bound and the
//!   median-time-past rule only. BIP-325 signet signatures are not verified.
//! - `checkpoint.rs`: the compile-time checkpoint constants and the dev-only
//!   `SPV_CHECKPOINT` override.

pub mod chain;
pub mod checkpoint;
pub mod types;
pub mod validation;

pub use chain::{HeaderChain, SubmitOutcome};
pub use checkpoint::{
    checkpoint_for, resolve_checkpoint, Checkpoint, CheckpointSource, CHECKPOINT_ENV,
};
pub use types::{BlockHash, BlockHeight, Network, SpvError};
