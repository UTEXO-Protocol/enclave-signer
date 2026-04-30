//! Compile-time checkpoint constants — the trust anchors for the in-enclave
//! header chain.
//!
//! A checkpoint is `(height, block_hash)`. On boot the enclave starts empty;
//! the Listener feeds headers starting at `height + 1`, and the first header
//! must chain to `block_hash`. Every checkpoint here ends up in PCR0 because
//! it's compiled in, so changing one means re-attestation.
//!
//! All values below are PLACEHOLDERS pending the constants the team picks.
//! They MUST be replaced before this module is wired into the signing path
//! (PR 3). Building with placeholders is allowed for unit tests today, but
//! a release build for production will refuse to start (see `assert_real()`).

use crate::spv::types::{BlockHash, BlockHeight};

/// A trust anchor: the enclave only accepts headers that chain forward from
/// this point, in ascending height.
#[derive(Debug, Clone, Copy)]
pub struct Checkpoint {
    pub height: BlockHeight,
    pub hash: BlockHash,
    /// The compact-encoded `nBits` (difficulty target) at this block. Needed
    /// because the next header's `nBits` must equal this until the next
    /// retarget boundary.
    pub bits: u32,
    /// The block timestamp. Needed when this checkpoint coincides with a
    /// retarget boundary so we can drive `from_next_work_required()`.
    pub time: u32,
    /// Set to true once the values are real (not placeholders). Production
    /// builds refuse to start otherwise.
    pub is_real: bool,
}

/// Mainnet checkpoint. PLACEHOLDER — replace with a real recent finalized
/// block before production.
pub const MAINNET_CHECKPOINT: Checkpoint = Checkpoint {
    height: 0,
    hash: [0u8; 32],
    bits: 0,
    time: 0,
    is_real: false,
};

/// Signet checkpoint. PLACEHOLDER — replace once the team confirms
/// default-signet vs custom-signet (see docs/spv-review.md §4).
pub const SIGNET_CHECKPOINT: Checkpoint = Checkpoint {
    height: 0,
    hash: [0u8; 32],
    bits: 0,
    time: 0,
    is_real: false,
};

/// Testnet3 checkpoint. PLACEHOLDER — testnet3 isn't a target environment
/// today, but kept symmetric with the Network enum.
pub const TESTNET3_CHECKPOINT: Checkpoint = Checkpoint {
    height: 0,
    hash: [0u8; 32],
    bits: 0,
    time: 0,
    is_real: false,
};

/// Regtest checkpoint. Genesis is fine for regtest because anyone can mine.
pub const REGTEST_CHECKPOINT: Checkpoint = Checkpoint {
    height: 0,
    hash: [0u8; 32],
    bits: 0x207fffff, // regtest min difficulty (1d00ffff << for testnet, 0x207fffff for regtest)
    time: 1_296_688_602,
    is_real: false,
};

impl Checkpoint {
    /// Refuse to construct a `HeaderChain` against a placeholder checkpoint
    /// in production-shaped builds. Tests are exempt.
    pub fn assert_real_in_release(&self) -> Result<(), &'static str> {
        if cfg!(debug_assertions) || cfg!(test) {
            return Ok(());
        }
        if !self.is_real {
            return Err(
                "SPV checkpoint is a placeholder — refuse to start a release build. \
                 Update enclave/src/spv/checkpoint.rs before deploying.",
            );
        }
        Ok(())
    }
}
