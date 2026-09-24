//! Compile-time checkpoint + network constants - the trust anchors for the
//! in-enclave header chain.
//!
//! A checkpoint is `(height, block_hash, bits, time)`. On boot the enclave
//! starts empty; the Listener feeds headers starting at `height + 1`, and
//! the first header must chain to `block_hash`. Every checkpoint here ends
//! up in PCR0 because it's compiled in, so changing one means re-attestation.
//!
//! Status:
//!
//! - Mainnet: block 951 552 (2026-05-29), retarget-boundary aligned
//!   (951 552 = 472 * 2016). Alignment is required, because the
//!   retarget-difficulty lookup needs the block at `height - 2016` for the
//!   first boundary above the checkpoint.
//! - Signet: UTEXO custom signet block 334 000 (2026-06-02). Local/dev builds
//!   can move this forward at boot with `SPV_CHECKPOINT` (see
//!   [`resolve_checkpoint`]); production-shaped builds refuse to start when it
//!   is set.
//! - Signet challenge / magic / block time: real values for UTEXO custom
//!   signet, 3-of-3 multisig, 30s blocks. Baked in so they land in PCR0, even
//!   though BIP-325 signature verification is deferred.
//! - Regtest: well-known regtest constants.

use crate::networks::rgb::spv::types::{BlockHash, BlockHeight, Network};
use crate::networks::rgb::spv::validation::RETARGET_INTERVAL;

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

/// Mainnet checkpoint - block 951 552 (2026-05-29). Retarget-boundary aligned
/// (`951 552 = 472 x 2016`), so `from_next_work_required()` at the first
/// boundary above the checkpoint can resolve its epoch start. See the
/// boundary-alignment invariant enforced in [`Checkpoint::assert_retarget_aligned`].
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
};

/// UTEXO custom signet checkpoint - block 334 000 (2026-06-02).
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
};

/// Testnet3 checkpoint. PLACEHOLDER - testnet3 isn't a target environment
/// today, but kept symmetric with the Network enum.
pub const TESTNET3_CHECKPOINT: Checkpoint = Checkpoint {
    height: 0,
    hash: [0u8; 32],
    bits: 0,
    time: 0,
    is_real: false,
};

/// Regtest checkpoint - the deterministic regtest genesis block (height 0).
/// Genesis is fine for regtest because anyone can mine; the listener feeds
/// headers from height 1, which chain to this hash.
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
};

impl Checkpoint {
    /// Refuse to construct a `HeaderChain` against a placeholder checkpoint
    /// in production-shaped builds. Tests are exempt.
    pub fn assert_real_in_release(&self) -> Result<(), &'static str> {
        // Local dev/test images build in release mode with `allow-seed-import`
        // and may still run against placeholder checkpoints, so that feature is
        // the escape hatch. Production-shaped builds keep the hard fail.
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

    /// Assert that a PoW-enforcing network's checkpoint sits on a retarget
    /// boundary. `HeaderChain::epoch_start_time` needs the block at
    /// `height - 2016` for the first boundary above the checkpoint; if the
    /// checkpoint is not aligned, that epoch start lands below it, is never
    /// stored, and the chain wedges.
    ///
    /// Signet and regtest do not enforce retargeting and are exempt.
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

/// Look up the compile-time checkpoint for a given network.
///
/// This is the PCR0-committed anchor. Boot goes through [`resolve_checkpoint`],
/// which layers the dev-only `SPV_CHECKPOINT` override on top.
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
/// Format: `height:block_hash` or `height:block_hash:bits:time`
///   * `height` - decimal block height.
///   * `block_hash` - 64 hex chars in **display order** (what an explorer or
///     `getblockhash` prints), optional `0x` prefix.
///   * `bits` - the block's compact target, hex, `0x` prefix REQUIRED (so a
///     decimal `bits` copied out of an Esplora JSON body errors instead of
///     being misread as hex).
///   * `time` - the block's Unix timestamp, decimal.
///
/// The two-field form inherits `bits`/`time` from the compiled-in checkpoint.
/// That is only sound where `nBits` is never checked and the epoch-start lookup
/// is never consulted, so PoW networks (mainnet, testnet3) must give all four.
pub const CHECKPOINT_ENV: &str = "SPV_CHECKPOINT";

/// Where the boot checkpoint came from. Reported so the log line can't imply a
/// compiled-in anchor when the operator supplied one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointSource {
    /// The compile-time constant for this network (PCR0-committed).
    Compiled,
    /// A dev-only `SPV_CHECKPOINT` override.
    Env,
}

/// True when this build may honour [`CHECKPOINT_ENV`].
///
/// The checkpoint is the SPV trust anchor, so a production enclave takes it
/// only from the compiled-in constant PCR0 commits to. Exemptions mirror
/// [`Checkpoint::assert_real_in_release`]: debug builds, tests, and the
/// local-E2E `allow-seed-import` feature.
pub fn checkpoint_override_allowed() -> bool {
    cfg!(debug_assertions) || cfg!(test) || cfg!(feature = "allow-seed-import")
}

/// Resolve the checkpoint to boot against: the compiled-in constant, or the
/// `SPV_CHECKPOINT` override when this build allows one.
///
/// Errors are boot-fatal (`main` panics) in all three cases: the var set in a
/// production build, a malformed spec, and a spec missing `bits`/`time` on a
/// PoW network. Falling back silently would hide both a dev mistake and a
/// production image ignoring operator intent.
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

/// Parse a [`CHECKPOINT_ENV`] spec against `base` (the compiled-in checkpoint
/// for `network`, supplying `bits`/`time` in the two-field form).
///
/// Pure so the format is directly unit-testable; [`resolve_checkpoint`] layers
/// the env read and the build-profile gate on top.
pub fn parse_checkpoint_spec(
    spec: &str,
    network: Network,
    base: &Checkpoint,
) -> std::result::Result<Checkpoint, String> {
    let fields: Vec<&str> = spec.trim().split(':').map(str::trim).collect();
    let (height_s, hash_s, bits_time) = match fields.as_slice() {
        [h, hash] => (*h, *hash, None),
        [h, hash, bits, time] => (*h, *hash, Some((*bits, *time))),
        _ => {
            return Err(format!(
                "{CHECKPOINT_ENV} must be `height:block_hash` or `height:block_hash:bits:time`, \
                 got {} field(s) in {spec:?}",
                fields.len()
            ))
        }
    };

    let height: BlockHeight = height_s
        .parse()
        .map_err(|e| format!("{CHECKPOINT_ENV}: height {height_s:?} is not a block height: {e}"))?;

    // Display order in, internal order stored - the same flip the constants
    // above document.
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

    Ok(Checkpoint {
        height,
        hash,
        bits,
        time,
        is_real: true,
    })
}

// === UTEXO custom signet network parameters ===
//
// Compile-time consts, so they end up in PCR0. The network is selected at boot
// via BITCOIN_NETWORK, but each network's parameters are immutable per binary.
//
// BIP-325 signature verification is not implemented: the signature lives in the
// coinbase witness commitment, which SubmitHeadersRequest does not carry. It
// would need `repeated bytes coinbase_txs` on the proto. The constants are
// baked in anyway so a later change can use them.

/// Signet challenge script for the UTEXO custom signet (BIP-325).
///
/// Layout (per Oleksandr's note):
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

/// Block time for the UTEXO custom signet, in seconds. Encoded into the
/// challenge script's prefix per bitcoin#29365.
pub const UTEXO_SIGNET_BLOCK_TIME_SECS: u32 = 30;

#[cfg(test)]
mod tests;
