//! In-enclave Bitcoin SPV: header chain and Merkle inclusion proof checks.
//!
//! - `chain.rs`: in-memory header chain from a compile-time checkpoint, with
//!   bounded reorg support.
//! - `validation.rs`: PoW and retarget checks on mainnet and testnet3. Signet
//!   and regtest check chain linkage only. BIP-325 signet signatures are not
//!   verified.
//! - `merkle.rs`: Bitcoin Merkle inclusion proof verifier.
//! - `checkpoint.rs`: the compile-time checkpoint constants.

pub mod chain;
pub mod checkpoint;
// Merkle proofs anchor the witness txs of an RGB source (burn direction).
#[cfg(rgb_to_evm)]
pub mod merkle;
pub mod types;
pub mod validation;

pub use chain::{HeaderChain, SubmitOutcome};
pub use checkpoint::{
    checkpoint_for, resolve_checkpoint, Checkpoint, CheckpointSource, CHECKPOINT_ENV,
    UTEXO_SIGNET_BLOCK_TIME_SECS, UTEXO_SIGNET_CHALLENGE, UTEXO_SIGNET_MAGIC,
};
#[cfg(rgb_to_evm)]
pub use merkle::{verify_merkle_proof, MerkleError, Sha256d};
pub use types::{BlockHash, BlockHeight, Network, SpvError};
