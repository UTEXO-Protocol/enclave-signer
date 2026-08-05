//! In-enclave Bitcoin SPV: header chain + Merkle inclusion proof
//! verification.
//!
//! ## Scope (PR 2)
//!
//! - In-memory append-only header chain anchored to a compile-time checkpoint
//!   (`chain.rs`).
//! - Mainnet PoW + retarget enforcement, signet/regtest chain-linkage only
//!   (`validation.rs`). BIP-325 signet signature verification is NOT
//!   implemented here — see the module-level note in `validation.rs`.
//! - Bitcoin Merkle inclusion proof verifier (`merkle.rs`).
//! - Placeholder checkpoint constants (`checkpoint.rs`) — these MUST be
//!   replaced with real `(height, hash, bits, time)` values before the
//!   module is wired into the signing path in PR 3.
//!
//! ## What's NOT here
//!
//! - Wiring into `handle_sign_evm` / `ServerContext` — that's PR 3.
//! - Reorg handling — append-only for now.
//! - Header staleness rule (refuse to sign on stale tip) — PR 4.
//!
//! See docs/spv-review.md for the full design + open questions.

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
