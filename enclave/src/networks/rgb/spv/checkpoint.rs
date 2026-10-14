//! Compile-time checkpoints and network constants: the trust anchors for the
//! in-enclave header chain.
//!
//! A checkpoint is `(height, block_hash, bits, time, chain_work)`. The enclave
//! starts empty. The parent sends headers from `height + 1`, and the first
//! header must chain to `block_hash`. The checkpoints are compiled in, so they
//! are in PCR0. A change needs new attestation.
//!
//! - Mainnet: block 951_552 (2026-05-29), aligned to a retarget boundary
//!   (951_552 = 472 x 2016). The retarget lookup for the first boundary needs
//!   the block at `height - 2016`.
//! - Signet: UTEXO custom signet block 334_000 (2026-06-02). Local/dev builds
//!   can move it forward at boot with `SPV_CHECKPOINT` (see
//!   [`resolve_checkpoint`]). Production-shaped builds do not start when it is
//!   set.
//! - Signet challenge, magic, block time: real UTEXO custom signet values
//!   (3-of-3 multisig, 30s blocks). They are in PCR0, but BIP-325 signatures
//!   are not verified.
//! - Regtest: standard regtest constants.

use crate::networks::rgb::spv::types::{BlockHash, BlockHeight, Network};
use crate::networks::rgb::spv::validation::RETARGET_INTERVAL;

/// Trust anchor: the enclave accepts only headers that chain forward from it.
#[derive(Debug, Clone, Copy)]
pub struct Checkpoint {
    pub height: BlockHeight,
    pub hash: BlockHash,
    /// Compact `nBits` at this block. The next headers must have the same
    /// `nBits` until the next retarget boundary.
    pub bits: u32,
    /// Block timestamp. `from_next_work_required()` needs it when the checkpoint
    /// is on a retarget boundary.
    pub time: u32,
    /// True when the values are real, not placeholders. Production builds do
    /// not start otherwise.
    pub is_real: bool,
    /// Cumulative work up to and including this block, big-endian (the
    /// `chainwork` of Bitcoin Core `getblockheader`). The enclave needs it to
    /// rebuild BtcRelay records. `None` means unknown: every `fundsOut` fails.
    pub chain_work: Option<[u8; 32]>,
}

/// Mainnet checkpoint: block 951_552 (2026-05-29). It is on a retarget
/// boundary (`951_552 = 472 x 2016`), so the first boundary above it can find
/// its epoch start. See [`Checkpoint::assert_retarget_aligned`].
/// hash (display): 00000000000000000001b472f1922f86148c8286609fb14be39e12b8bd14bb64
pub const MAINNET_CHECKPOINT: Checkpoint = Checkpoint {
    height: 951_552,
    hash: [
        0x64, 0xbb, 0x14, 0xbd, 0xb8, 0x12, 0x9e, 0xe3, 0x4b, 0xb1, 0x9f, 0x60, 0x86, 0x82, 0x8c,
        0x14, 0x86, 0x2f, 0x92, 0xf1, 0x72, 0xb4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    bits: 0x1702_068f,
    time: 1_780_050_586,
    is_real: true,
    // getblockheader chainwork:
    // 00000000000000000000000000000000000000012bc52b13ac6c5ed1704149f2
    chain_work: Some([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x2b, 0xc5, 0x2b, 0x13, 0xac, 0x6c, 0x5e, 0xd1, 0x70, 0x41,
        0x49, 0xf2,
    ]),
};

/// UTEXO custom signet checkpoint: block 334_000 (2026-06-02).
/// hash (display): 000000ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66
pub const SIGNET_CHECKPOINT: Checkpoint = Checkpoint {
    height: 334_000,
    hash: [
        0x66, 0xeb, 0x3a, 0x9f, 0xc3, 0xa2, 0xc6, 0x39, 0x83, 0x9c, 0xf2, 0xc8, 0x90, 0x51, 0xb6,
        0x4f, 0x4b, 0x16, 0x2e, 0x95, 0x59, 0xf8, 0x3b, 0x6d, 0xa2, 0xb8, 0xcc, 0x5f, 0xac, 0x00,
        0x00, 0x00,
    ],
    bits: 0x1e03_77ae,
    time: 1_780_464_472,
    is_real: true,
    // Unknown: set it to the `getblockheader` chainwork from the UTEXO signet
    // node. Until then, signet `fundsOut` fails.
    chain_work: None,
};

/// Testnet3 checkpoint. PLACEHOLDER: testnet3 is not a target environment.
/// It exists to match the `Network` enum.
pub const TESTNET3_CHECKPOINT: Checkpoint = Checkpoint {
    height: 0,
    hash: [0u8; 32],
    bits: 0,
    time: 0,
    is_real: false,
    chain_work: None,
};

/// Regtest checkpoint: the regtest genesis block (height 0). Headers start at
/// height 1 and chain to this hash.
/// hash (display): 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
pub const REGTEST_CHECKPOINT: Checkpoint = Checkpoint {
    height: 0,
    hash: [
        0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b,
        0xbf, 0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88,
        0x91, 0x0f,
    ],
    bits: 0x207fffff, // regtest min difficulty
    time: 1_296_688_602,
    is_real: true,
    // Genesis work: 2.
    chain_work: Some([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ]),
};

impl Checkpoint {
    /// Fails on a placeholder checkpoint in production-shaped builds. Debug,
    /// test, and `allow-seed-import` builds are exempt.
    pub fn assert_real_in_release(&self) -> Result<(), &'static str> {
        // Local dev/test images are release builds with `allow-seed-import` and
        // can use placeholder checkpoints.
        if cfg!(debug_assertions) || cfg!(test) || cfg!(feature = "allow-seed-import") {
            return Ok(());
        }
        if !self.is_real {
            return Err(
                "SPV checkpoint is a placeholder - refuse to start a release build. \
                 Update enclave/src/networks/rgb/spv/checkpoint.rs before deploying.",
            );
        }
        Ok(())
    }

    /// Fails if a PoW network checkpoint is not on a retarget boundary.
    /// `HeaderChain::epoch_start_time` needs the block at `height - 2016` for
    /// the first boundary. If not aligned, that block is below the checkpoint,
    /// is not stored, and the chain stops.
    ///
    /// Signet and regtest have no retarget checks and are exempt.
    pub fn assert_retarget_aligned(&self, network: Network) -> Result<(), String> {
        if network.enforces_pow() && !self.height.is_multiple_of(RETARGET_INTERVAL) {
            return Err(format!(
                "SPV checkpoint for {network:?} is at height {} which is not on a retarget \
                 boundary (height % {RETARGET_INTERVAL} == {}); the chain would wedge at the \
                 first boundary above it. Pick a height that is a multiple of {RETARGET_INTERVAL}.",
                self.height,
                self.height % RETARGET_INTERVAL,
            ));
        }
        Ok(())
    }
}

/// Compile-time checkpoint for `network` (in PCR0).
///
/// Boot uses [`resolve_checkpoint`], which adds the dev-only `SPV_CHECKPOINT`
/// override.
pub fn checkpoint_for(network: Network) -> Checkpoint {
    match network {
        Network::Mainnet => MAINNET_CHECKPOINT,
        Network::Signet => SIGNET_CHECKPOINT,
        Network::Testnet3 => TESTNET3_CHECKPOINT,
        Network::Regtest => REGTEST_CHECKPOINT,
    }
}

/// Env var that moves the boot checkpoint forward in local/dev builds.
///
/// Format: `height:block_hash`, `height:block_hash:bits:time` or
/// `height:block_hash:bits:time:chainwork`
///   * `height` - decimal block height.
///   * `block_hash` - 64 hex chars in **display order** (as an explorer or
///     `getblockhash` shows it), optional `0x` prefix.
///   * `bits` - compact target, hex, `0x` prefix REQUIRED. A decimal value
///     from an Esplora JSON body then fails and is not read as hex.
///   * `time` - Unix timestamp, decimal.
///   * `chainwork` - 64 hex chars, as `getblockheader` prints it, optional
///     `0x` prefix.
///
/// Only the five-field form sets `chain_work`. The shorter forms set `None`,
/// and then every `fundsOut` fails.
///
/// The two-field form takes `bits`/`time` from the compiled-in checkpoint. That
/// is safe only where `nBits` is not checked. PoW networks (mainnet, testnet3)
/// must give all four.
pub const CHECKPOINT_ENV: &str = "SPV_CHECKPOINT";

/// Source of the boot checkpoint. The log shows it, so an operator value is
/// not shown as the compiled-in anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointSource {
    /// The compile-time constant for this network (PCR0-committed).
    Compiled,
    /// A dev-only `SPV_CHECKPOINT` override.
    Env,
}

/// True when this build may use [`CHECKPOINT_ENV`].
///
/// The checkpoint is the SPV trust anchor, so a production enclave uses only
/// the compiled-in constant in PCR0. The exemptions are the same as in
/// [`Checkpoint::assert_real_in_release`].
pub fn checkpoint_override_allowed() -> bool {
    cfg!(debug_assertions) || cfg!(test) || cfg!(feature = "allow-seed-import")
}

/// Boot checkpoint: the compiled-in constant, or the `SPV_CHECKPOINT` override
/// when this build allows it.
///
/// All errors stop the boot (`main` panics): the var set in a production
/// build, a malformed spec, or no `bits`/`time` on a PoW network. A silent
/// fallback would hide a dev mistake or an ignored operator value.
pub fn resolve_checkpoint(
    network: Network,
) -> std::result::Result<(Checkpoint, CheckpointSource), String> {
    let compiled = checkpoint_for(network);
    let Ok(spec) = std::env::var(CHECKPOINT_ENV) else {
        return Ok((compiled, CheckpointSource::Compiled));
    };
    if !checkpoint_override_allowed() {
        return Err(format!(
            "{CHECKPOINT_ENV} is set ({spec:?}) but this is a production-shaped build. The SPV \
             checkpoint is the trust anchor for every header the enclave accepts and must come \
             from the compiled-in constant that PCR0 commits to. Unset {CHECKPOINT_ENV}, or edit \
             enclave/src/networks/rgb/spv/checkpoint.rs and rebuild."
        ));
    }
    let checkpoint = parse_checkpoint_spec(&spec, network, &compiled)?;
    Ok((checkpoint, CheckpointSource::Env))
}

/// Parses a [`CHECKPOINT_ENV`] spec. `base` is the compiled-in checkpoint for
/// `network`. It gives `bits`/`time` in the two-field form.
///
/// Pure, for unit tests. [`resolve_checkpoint`] adds the env read and the
/// build-profile gate.
pub fn parse_checkpoint_spec(
    spec: &str,
    network: Network,
    base: &Checkpoint,
) -> std::result::Result<Checkpoint, String> {
    let fields: Vec<&str> = spec.trim().split(':').map(str::trim).collect();
    let (height_s, hash_s, bits_time, work_s) = match fields.as_slice() {
        [h, hash] => (*h, *hash, None, None),
        [h, hash, bits, time] => (*h, *hash, Some((*bits, *time)), None),
        [h, hash, bits, time, work] => (*h, *hash, Some((*bits, *time)), Some(*work)),
        _ => {
            return Err(format!(
                "{CHECKPOINT_ENV} must be `height:block_hash`, `height:block_hash:bits:time` or \
                 `height:block_hash:bits:time:chainwork`, got {} field(s) in {spec:?}",
                fields.len()
            ))
        }
    };

    let height: BlockHeight = height_s
        .parse()
        .map_err(|e| format!("{CHECKPOINT_ENV}: height {height_s:?} is not a block height: {e}"))?;

    // Input is display order. Store internal order.
    let hash_hex = hash_s.strip_prefix("0x").unwrap_or(hash_s);
    let hash_bytes = hex::decode(hash_hex)
        .map_err(|e| format!("{CHECKPOINT_ENV}: block_hash {hash_s:?} is not hex: {e}"))?;
    let mut hash: BlockHash = hash_bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "{CHECKPOINT_ENV}: block_hash must be 32 bytes (64 hex chars), got {}",
            v.len()
        )
    })?;
    hash.reverse();
    if hash == [0u8; 32] {
        return Err(format!(
            "{CHECKPOINT_ENV}: block_hash is all zeros - that is the placeholder, not a real \
             block; no header can ever chain to it"
        ));
    }

    let (bits, time) = match bits_time {
        Some((bits_s, time_s)) => {
            let bits_hex = bits_s.strip_prefix("0x").ok_or_else(|| {
                format!(
                    "{CHECKPOINT_ENV}: bits {bits_s:?} must be hex with an explicit `0x` prefix \
                     (an Esplora JSON body reports bits in decimal - convert it)"
                )
            })?;
            let bits = u32::from_str_radix(bits_hex, 16)
                .map_err(|e| format!("{CHECKPOINT_ENV}: bits {bits_s:?} is not hex u32: {e}"))?;
            let time: u32 = time_s.parse().map_err(|e| {
                format!("{CHECKPOINT_ENV}: time {time_s:?} is not a timestamp: {e}")
            })?;
            (bits, time)
        }
        None => {
            if network.enforces_pow() {
                return Err(format!(
                    "{CHECKPOINT_ENV}: {network:?} enforces PoW, so bits and time must be given \
                     explicitly (`height:block_hash:bits:time`) - inheriting them from the \
                     compiled checkpoint would make every nBits and retarget check wrong"
                ));
            }
            (base.bits, base.time)
        }
    };

    let chain_work = match work_s {
        Some(work_s) => {
            let work = hex::decode(work_s.strip_prefix("0x").unwrap_or(work_s))
                .map_err(|e| format!("{CHECKPOINT_ENV}: chainwork {work_s:?} is not hex: {e}"))?;
            Some(work.try_into().map_err(|v: Vec<u8>| {
                format!(
                    "{CHECKPOINT_ENV}: chainwork must be 32 bytes (64 hex chars), got {}",
                    v.len()
                )
            })?)
        }
        None => None,
    };

    Ok(Checkpoint {
        height,
        hash,
        bits,
        time,
        is_real: true,
        chain_work,
    })
}

// === UTEXO custom signet network parameters ===
//
// Compile-time consts, so they are in PCR0. BITCOIN_NETWORK selects the
// network at boot. The parameters of each network are fixed per binary.
//
// BIP-325 signatures are not verified. The signature is in the coinbase
// witness commitment, which SubmitHeadersRequest does not carry. That needs
// `repeated bytes coinbase_txs` on the proto. The constants are ready for it.

/// Signet challenge script for the UTEXO custom signet (BIP-325).
///
/// Layout:
/// - `6a 4c 09 01 1e 00 00 00 00 00 00 00 00` - OP_RETURN-prefixed block-time
///   spec (bitcoin#29365): 30s = `0x1e` little-endian u64.
/// - `4c 69 53 21 <33-byte pubkey> 21 <33-byte pubkey> 21 <33-byte pubkey>
///    53 ae` - `OP_PUSHDATA1 0x69 OP_3 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG`
///   = 3-of-3 multisig over three federation signing keys.
pub const UTEXO_SIGNET_CHALLENGE: &[u8] = &[
    0x6a, 0x4c, 0x09, 0x01, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x69, 0x53, 0x21,
    0x02, 0x24, 0xa5, 0x28, 0xaa, 0x14, 0x1b, 0x7d, 0x2e, 0xd0, 0x93, 0x57, 0x5b, 0x5d, 0x2c, 0x2c,
    0xee, 0x40, 0x65, 0xab, 0xc6, 0xf7, 0xf6, 0xb1, 0x9a, 0x97, 0x0a, 0x89, 0x75, 0xd3, 0x27, 0xf9,
    0x35, 0x21, 0x02, 0x49, 0xc6, 0xbf, 0x83, 0x38, 0xec, 0xda, 0x27, 0x49, 0xc3, 0xff, 0xad, 0x4b,
    0x8e, 0xc2, 0x2f, 0x71, 0x58, 0x19, 0x47, 0xc1, 0x0d, 0x17, 0x66, 0xd9, 0xce, 0x83, 0xd1, 0xbc,
    0xaf, 0xb9, 0x94, 0x21, 0x02, 0x4f, 0x3a, 0x83, 0x1f, 0xcb, 0x4d, 0xb4, 0x46, 0xb0, 0x7f, 0xe8,
    0x89, 0x7d, 0x19, 0x3b, 0x86, 0xf9, 0x13, 0x98, 0x4f, 0x6e, 0xb3, 0xab, 0x6e, 0x97, 0x45, 0xee,
    0xb6, 0x10, 0x17, 0xa3, 0xb5, 0x53, 0xae,
];

/// Network magic bytes for the UTEXO custom signet.
pub const UTEXO_SIGNET_MAGIC: [u8; 4] = [0x6f, 0x21, 0x61, 0x5a];

/// Block time for the UTEXO custom signet, in seconds. The challenge script
/// prefix encodes it (bitcoin#29365).
pub const UTEXO_SIGNET_BLOCK_TIME_SECS: u32 = 30;

#[cfg(test)]
mod tests;
