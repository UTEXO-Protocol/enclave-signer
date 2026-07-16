//! Common types used across the SPV module.

use thiserror::Error;

/// Bitcoin block height. `u32` is enough for the foreseeable future
/// (Bitcoin would have to mine for ~80,000 years to overflow).
pub type BlockHeight = u32;

/// Block hash in Bitcoin internal byte order (32 bytes).
pub type BlockHash = [u8; 32];

/// Which Bitcoin network we are validating against. Determined at runtime
/// from the `BITCOIN_NETWORK` env var, but baked into PCR0 because the env
/// var is set in the Dockerfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    /// Default global signet OR a custom signet, distinguished only by the
    /// challenge script that's also a compile-time constant. Header
    /// validation behaviour is identical (signature in coinbase witness,
    /// not enforced in PR 2 — see `validation.rs`).
    Signet,
    Testnet3,
    Regtest,
}

impl Network {
    pub fn from_env_str(s: &str) -> std::result::Result<Self, &'static str> {
        match s {
            "bitcoin" | "mainnet" => Ok(Self::Mainnet),
            "signet" => Ok(Self::Signet),
            "testnet" | "testnet3" => Ok(Self::Testnet3),
            "regtest" => Ok(Self::Regtest),
            _ => Err("unknown network"),
        }
    }

    /// Maps to the `bitcoin` crate's network parameters.
    pub fn as_bitcoin_params(self) -> &'static bitcoin::consensus::params::Params {
        match self {
            Self::Mainnet => &bitcoin::consensus::params::MAINNET,
            Self::Signet => &bitcoin::consensus::params::SIGNET,
            Self::Testnet3 => &bitcoin::consensus::params::TESTNET3,
            Self::Regtest => &bitcoin::consensus::params::REGTEST,
        }
    }

    /// Whether real PoW is enforced. Mainnet + testnet3 yes; signet has
    /// trivial PoW (real validation is the BIP-325 signature, see comment
    /// in `validation.rs`); regtest is local-only and trivial.
    pub fn enforces_pow(self) -> bool {
        matches!(self, Self::Mainnet | Self::Testnet3)
    }
}

#[derive(Debug, Error)]
pub enum SpvError {
    #[error("header parse failed at index {index}: {message}")]
    HeaderParse { index: usize, message: String },

    #[error("chain linkage broken at height {height}: prev_blockhash mismatch")]
    ChainLinkage { height: BlockHeight },

    #[error("header at height {height} fails PoW: hash > target")]
    PowFailed { height: BlockHeight },

    #[error(
        "nBits at height {height} mismatch: header has {got:#010x}, expected {expected:#010x}"
    )]
    BitsMismatch {
        height: BlockHeight,
        got: u32,
        expected: u32,
    },

    #[error("batch start_height {got} leaves a gap above tip {tip}")]
    NonContiguous { got: BlockHeight, tip: BlockHeight },

    #[error("batch start_height {got} is at or below checkpoint {checkpoint}; refusing to rewrite history below the trust anchor")]
    BelowCheckpoint {
        got: BlockHeight,
        checkpoint: BlockHeight,
    },

    #[error("reorg depth {depth} exceeds maximum {max}; refusing to rewrite that far back")]
    ReorgTooDeep {
        depth: BlockHeight,
        max: BlockHeight,
    },

    #[error(
        "alternative chain has weaker or equal cumulative work; rejecting reorg \
         (this is normal — best chain wins)"
    )]
    WeakerChain,

    #[error("submitted batch has {len} headers, exceeding the per-call cap of {max}")]
    BatchTooLarge { len: usize, max: usize },

    #[error(
        "accepting this batch would retain {len} headers, exceeding the total-retention cap of \
         {max}; the compile-time checkpoint is too far below the tip and must be advanced"
    )]
    ChainTooLong { len: usize, max: usize },

    #[error("no header at height {0}")]
    HeaderNotFound(BlockHeight),

    #[error("checkpoint placeholder — refusing to operate")]
    CheckpointPlaceholder,
}

pub type Result<T> = std::result::Result<T, SpvError>;
