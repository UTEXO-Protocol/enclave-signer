//! In-enclave Bitcoin SPV: header chain + Merkle inclusion proof
//! verification.
//!
//! - `chain.rs`: in-memory header chain anchored to a compile-time checkpoint,
//!   with bounded reorg support.
//! - `validation.rs`: mainnet PoW + retarget enforcement; signet and regtest
//!   are chain-linkage only. BIP-325 signet signature verification is not
//!   implemented - see that module's notes.
//! - `merkle.rs`: Bitcoin Merkle inclusion proof verifier.
//! - `checkpoint.rs`: the compile-time checkpoint constants.
//!
//! See docs/spv-review.md for the full design and open questions.

pub mod chain;
pub mod checkpoint;
pub mod merkle;
pub mod types;
pub mod validation;

pub use chain::{HeaderChain, SubmitOutcome};
pub use checkpoint::{
    checkpoint_for, resolve_checkpoint, Checkpoint, CheckpointSource, CHECKPOINT_ENV,
    UTEXO_SIGNET_BLOCK_TIME_SECS, UTEXO_SIGNET_CHALLENGE, UTEXO_SIGNET_MAGIC,
};
pub use merkle::{verify_merkle_proof, MerkleError, Sha256d};
pub use types::{BlockHash, BlockHeight, Network, SpvError};
