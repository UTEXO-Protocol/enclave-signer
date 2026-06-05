//! Compile-time checkpoint + network constants — the trust anchors for the
//! in-enclave header chain.
//!
//! A checkpoint is `(height, block_hash, bits, time)`. On boot the enclave
//! starts empty; the Listener feeds headers starting at `height + 1`, and
//! the first header must chain to `block_hash`. Every checkpoint here ends
//! up in PCR0 because it's compiled in, so changing one means re-attestation.
//!
//! ## Status
//!
//! - **Mainnet checkpoint** — block 950 000 (2026-05-18). Verified via
//!   double-SHA256 of raw header from blockstream.info/api.
//! - **Signet checkpoint** — UTEXO custom signet block 334 000 (2026-06-02).
//!   Verified via double-SHA256 of raw header from esplora-api.utexo.com.
//! - **Signet challenge / magic / block time** — REAL values, provided by
//!   Oleksandr 2026-04-30. UTEXO custom signet, 3-of-3 multisig, 30s blocks.
//!   These are baked in now so they end up in PCR0 alongside everything
//!   else, even though BIP-325 signature verification itself is deferred
//!   (the signature lives in the coinbase witness, which the proto does not
//!   carry — see spv/validation.rs).
//! - **Regtest** — uses well-known regtest constants, fine as-is.

use crate::spv::types::{BlockHash, BlockHeight, Network};

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

/// Mainnet checkpoint — block 950 000 (2026-05-18).
/// hash (display): 000000000000000000010b93c9ea1c29fea277383f0f7d1f26de8b5802e885ff
pub const MAINNET_CHECKPOINT: Checkpoint = Checkpoint {
    height: 950_000,
    hash: [
        0xff, 0x85, 0xe8, 0x02, 0x58, 0x8b, 0xde, 0x26, 0x1f, 0x7d, 0x0f, 0x3f, 0x38, 0x77, 0xa2,
        0xfe, 0x29, 0x1c, 0xea, 0xc9, 0x93, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    bits: 0x1702_0f79,
    time: 1_779_141_269,
    is_real: true,
};

/// UTEXO custom signet checkpoint — block 334 000 (2026-06-02).
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
        // Local dev/test images intentionally build the enclave in release mode
        // with `allow-seed-import` so deterministic mnemonics can be loaded,
        // but they still run against placeholder signet checkpoints until the
        // real tuple is baked in. Keep the hard fail for production-shaped
        // builds while letting that testing-only feature act as the escape
        // hatch for local E2E.
        if cfg!(debug_assertions) || cfg!(test) || cfg!(feature = "allow-seed-import") {
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

/// Look up the checkpoint to use for a given network. Used at boot.
pub fn checkpoint_for(network: Network) -> Checkpoint {
    match network {
        Network::Mainnet => MAINNET_CHECKPOINT,
        Network::Signet => SIGNET_CHECKPOINT,
        Network::Testnet3 => TESTNET3_CHECKPOINT,
        Network::Regtest => REGTEST_CHECKPOINT,
    }
}

// === UTEXO custom signet network parameters ===
//
// Provided by Oleksandr Mihalatii on 2026-04-30. These describe the dev
// signet our enclaves will validate headers against. They are baked in
// (compile-time consts) so they end up in PCR0; the network is selected at
// boot via the BITCOIN_NETWORK env var, but the *parameters* of each
// network are immutable per binary.
//
// BIP-325 signature verification using these values is NOT implemented in
// PR 2/3 — the coinbase witness commitment (where the signature lives) is
// not carried by the current SubmitHeadersRequest proto. Strict signet
// validation requires extending the proto with `repeated bytes coinbase_txs`
// and is deferred. These constants are baked in regardless so a future PR
// can light up verification without re-collecting the values.

/// Signet challenge script for the UTEXO custom signet (BIP-325).
///
/// Layout (per Oleksandr's note):
/// - `6a 4c 09 01 1e 00 00 00 00 00 00 00 00` — OP_RETURN-prefixed block-time
///   spec (PR bitcoin#29365): 30s = `0x1e` little-endian u64.
/// - `4c 69 53 21 <33-byte pubkey> 21 <33-byte pubkey> 21 <33-byte pubkey>
///    53 ae` — `OP_PUSHDATA1 0x69 OP_3 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG`
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
mod tests {
    use super::*;

    #[test]
    fn signet_challenge_matches_oleksandrs_hex() {
        // Sanity: the byte array above should hex-encode to exactly the value
        // Oleksandr posted. If anyone touches the byte array, this catches a
        // typo before it ships to attestation.
        let hex = hex::encode(UTEXO_SIGNET_CHALLENGE);
        assert_eq!(
            hex,
            "6a4c09011e000000000000004c6953210224a528aa141b7d2ed093575b5d2c2cee4065abc6f7f6b19a970a8975d327f935210249c6bf8338ecda2749c3ffad4b8ec22f71581947c10d1766d9ce83d1bcafb99421024f3a831fcb4db446b07fe8897d193b86f913984f6eb3ab6e9745eeb61017a3b553ae"
        );
    }

    #[test]
    fn signet_challenge_decodes_as_3_of_3_multisig() {
        // Light structural check: the trailing bytes are OP_3 OP_CHECKMULTISIG.
        let len = UTEXO_SIGNET_CHALLENGE.len();
        assert_eq!(UTEXO_SIGNET_CHALLENGE[len - 2], 0x53); // OP_3 (n)
        assert_eq!(UTEXO_SIGNET_CHALLENGE[len - 1], 0xae); // OP_CHECKMULTISIG
    }

    #[test]
    fn signet_magic_is_four_bytes() {
        // Defensive: future refactors that reshape the magic must not silently
        // change its length.
        assert_eq!(UTEXO_SIGNET_MAGIC.len(), 4);
        assert_eq!(UTEXO_SIGNET_MAGIC, [0x6f, 0x21, 0x61, 0x5a]);
    }

    #[test]
    fn checkpoint_for_dispatches_on_network() {
        assert!(checkpoint_for(Network::Mainnet).is_real);
        assert!(checkpoint_for(Network::Signet).is_real);
        assert!(!checkpoint_for(Network::Testnet3).is_real);
        assert!(!checkpoint_for(Network::Regtest).is_real);
    }
}
