//! Common types used across the SPV module.

use thiserror::Error;

/// Bitcoin block height. `u32` overflows only after approx 80,000 years.
pub type BlockHeight = u32;

/// Block hash in Bitcoin internal byte order (32 bytes).
pub type BlockHash = [u8; 32];

/// Bitcoin network for header validation. It comes from the `BITCOIN_NETWORK`
/// env var. The Dockerfile sets that var, so PCR0 includes it.
///
/// This is the one parser of `BITCOIN_NETWORK`: the key network, the RGB
/// chain-network and the SPV rules all come from it, so they cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    /// Default global signet or a custom signet. Only the compile-time
    /// challenge script makes them different. Header validation is the same:
    /// the BIP-325 coinbase signature is not verified (see `validation.rs`).
    Signet,
    /// The UTEXO custom signet as RGB names it (`sbc`). Same headers and
    /// checkpoint as [`Self::Signet`]; only the RGB chain-network differs.
    SignetCustom,
    Testnet3,
    /// Testnet4: the 20-minute min-difficulty rule plus BIP94.
    Testnet4,
    Regtest,
}

impl Network {
    pub fn from_env_str(s: &str) -> std::result::Result<Self, &'static str> {
        match s {
            "bitcoin" | "mainnet" => Ok(Self::Mainnet),
            "signet" => Ok(Self::Signet),
            "signetcustom" => Ok(Self::SignetCustom),
            "testnet" | "testnet3" => Ok(Self::Testnet3),
            "testnet4" => Ok(Self::Testnet4),
            "regtest" => Ok(Self::Regtest),
            _ => Err("unknown network"),
        }
    }

    /// The network of the keys and addresses.
    pub fn bitcoin_network(self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Signet | Self::SignetCustom => bitcoin::Network::Signet,
            Self::Testnet3 => bitcoin::Network::Testnet,
            Self::Testnet4 => bitcoin::Network::Testnet4,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }

    /// The RGB chain-network a consignment of this network commits to.
    #[cfg(feature = "rgb-validation")]
    pub fn chain_net(self) -> rgbstd::ChainNet {
        use rgbstd::ChainNet;
        match self {
            Self::Mainnet => ChainNet::BitcoinMainnet,
            Self::Signet => ChainNet::BitcoinSignet,
            Self::SignetCustom => ChainNet::BitcoinSignetCustom,
            Self::Testnet3 => ChainNet::BitcoinTestnet3,
            Self::Testnet4 => ChainNet::BitcoinTestnet4,
            Self::Regtest => ChainNet::BitcoinRegtest,
        }
    }

    /// The attested policy value. The match is exhaustive, so a new network
    /// needs its own wire value.
    pub fn attested(self) -> attestation_verify::BitcoinNetwork {
        use attestation_verify::BitcoinNetwork;
        match self {
            Self::Mainnet => BitcoinNetwork::Mainnet,
            Self::Signet => BitcoinNetwork::Signet,
            Self::SignetCustom => BitcoinNetwork::SignetCustom,
            Self::Testnet3 => BitcoinNetwork::Testnet3,
            Self::Testnet4 => BitcoinNetwork::Testnet4,
            Self::Regtest => BitcoinNetwork::Regtest,
        }
    }

    /// Maps to the `bitcoin` crate's network parameters.
    pub fn as_bitcoin_params(self) -> &'static bitcoin::consensus::params::Params {
        match self {
            Self::Mainnet => &bitcoin::consensus::params::MAINNET,
            Self::Signet | Self::SignetCustom => &bitcoin::consensus::params::SIGNET,
            Self::Testnet3 => &bitcoin::consensus::params::TESTNET3,
            Self::Testnet4 => &bitcoin::consensus::params::TESTNET4,
            Self::Regtest => &bitcoin::consensus::params::REGTEST,
        }
    }

    /// True when PoW is enforced (mainnet, testnets). Signet PoW is trivial
    /// because its real check is the BIP-325 signature. Regtest is local only.
    pub fn enforces_pow(self) -> bool {
        matches!(self, Self::Mainnet | Self::Testnet3 | Self::Testnet4)
    }

    /// True when a block more than 20 minutes after its parent may be mined
    /// at the minimum difficulty (testnet3 and testnet4).
    pub fn allows_min_difficulty(self) -> bool {
        self.enforces_pow() && self.as_bitcoin_params().allow_min_difficulty_blocks
    }

    /// True when BIP94 applies: retarget from the period's first block, and
    /// the timewarp rule on its first block.
    pub fn bip94(self) -> bool {
        matches!(self, Self::Testnet4)
    }

    /// `nBits` of a block mined at the minimum difficulty.
    pub fn pow_limit_bits(self) -> u32 {
        self.as_bitcoin_params()
            .max_attainable_target
            .to_compact_lossy()
            .to_consensus()
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

    #[error(
        "header at height {height} breaks the BIP94 timewarp rule: time {time} is more than \
         600s before its parent's {prev_time}"
    )]
    Timewarp {
        height: BlockHeight,
        time: u32,
        prev_time: u32,
    },

    #[error(
        "header at height {height} has time {time}, more than 2h after the enclave clock {now}"
    )]
    TimeTooNew {
        height: BlockHeight,
        time: u32,
        now: u64,
    },

    #[error(
        "header at height {height} has time {time}, at or before the median time past \
         {median_time_past} of the eleven blocks below it"
    )]
    TimeTooOld {
        height: BlockHeight,
        time: u32,
        median_time_past: u32,
    },

    #[error("no header at height {0}")]
    HeaderNotFound(BlockHeight),

    #[error("checkpoint placeholder - refusing to operate")]
    CheckpointPlaceholder,
}

pub type Result<T> = std::result::Result<T, SpvError>;
