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
    /// not enforced in PR 2 - see `validation.rs`).
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
         (this is normal - best chain wins)"
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

    #[error("checkpoint placeholder - refusing to operate")]
    CheckpointPlaceholder,
}

pub type Result<T> = std::result::Result<T, SpvError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_str_accepts_every_documented_alias() {
        assert_eq!(Network::from_env_str("bitcoin"), Ok(Network::Mainnet));
        assert_eq!(Network::from_env_str("mainnet"), Ok(Network::Mainnet));
        assert_eq!(Network::from_env_str("signet"), Ok(Network::Signet));
        assert_eq!(Network::from_env_str("testnet"), Ok(Network::Testnet3));
        assert_eq!(Network::from_env_str("testnet3"), Ok(Network::Testnet3));
        assert_eq!(Network::from_env_str("regtest"), Ok(Network::Regtest));
    }

    #[test]
    fn from_env_str_is_exact_match_only() {
        for s in [
            "", "Bitcoin", "MAINNET", " mainnet", "mainnet ", "testnet4", "main", "reg", "sig",
        ] {
            assert_eq!(Network::from_env_str(s), Err("unknown network"), "{s:?}");
        }
    }

    #[test]
    fn pow_is_enforced_only_on_mainnet_and_testnet3() {
        assert!(Network::Mainnet.enforces_pow());
        assert!(Network::Testnet3.enforces_pow());
        assert!(!Network::Signet.enforces_pow());
        assert!(!Network::Regtest.enforces_pow());
    }

    #[test]
    fn bitcoin_params_map_to_the_matching_network() {
        assert_eq!(
            Network::Mainnet.as_bitcoin_params().network,
            bitcoin::Network::Bitcoin
        );
        assert_eq!(
            Network::Signet.as_bitcoin_params().network,
            bitcoin::Network::Signet
        );
        assert_eq!(
            Network::Testnet3.as_bitcoin_params().network,
            bitcoin::Network::Testnet
        );
        assert_eq!(
            Network::Regtest.as_bitcoin_params().network,
            bitcoin::Network::Regtest
        );
        // Regtest allows min-difficulty blocks; mainnet does not.
        assert!(
            Network::Regtest
                .as_bitcoin_params()
                .allow_min_difficulty_blocks
        );
        assert!(
            !Network::Mainnet
                .as_bitcoin_params()
                .allow_min_difficulty_blocks
        );
    }

    #[test]
    fn spv_error_messages_name_their_parameters() {
        let cases: Vec<(SpvError, &[&str])> = vec![
            (
                SpvError::HeaderParse {
                    index: 3,
                    message: "bad".into(),
                },
                &["index 3", "bad"],
            ),
            (SpvError::ChainLinkage { height: 5 }, &["height 5"]),
            (SpvError::PowFailed { height: 6 }, &["height 6", "PoW"]),
            (
                SpvError::BitsMismatch {
                    height: 7,
                    got: 0x1d00ffff,
                    expected: 0x1c00ffff,
                },
                &["height 7", "0x1d00ffff", "0x1c00ffff"],
            ),
            (
                SpvError::NonContiguous { got: 10, tip: 8 },
                &["10", "tip 8"],
            ),
            (
                SpvError::BelowCheckpoint {
                    got: 1,
                    checkpoint: 2,
                },
                &["start_height 1", "checkpoint 2"],
            ),
            (
                SpvError::ReorgTooDeep { depth: 9, max: 4 },
                &["depth 9", "maximum 4"],
            ),
            (SpvError::WeakerChain, &["weaker or equal"]),
            (
                SpvError::BatchTooLarge { len: 3, max: 2 },
                &["3 headers", "cap of 2"],
            ),
            (
                SpvError::ChainTooLong { len: 30, max: 20 },
                &["retain 30", "cap of 20"],
            ),
            (SpvError::HeaderNotFound(11), &["height 11"]),
            (SpvError::CheckpointPlaceholder, &["placeholder"]),
        ];
        for (err, needles) in cases {
            let text = err.to_string();
            for needle in needles {
                assert!(text.contains(needle), "{text:?} lacks {needle:?}");
            }
        }
    }
}
