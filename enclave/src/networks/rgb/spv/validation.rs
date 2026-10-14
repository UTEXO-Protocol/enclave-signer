//! Per-header validation functions. They hold no chain state.
//!
//! `HeaderChain` gives the prior-header context. These functions check
//! linkage to the predecessor, PoW, and the `nBits` for the height.
//!
//! Per network:
//!
//! - Mainnet, testnet3: full PoW and retarget checks. `expected_bits`
//!   computes the required `nBits` again, so a low-difficulty chain fails.
//! - Signet: PoW is trivial and not checked. The real check is the BIP-325
//!   coinbase signature. `SubmitHeadersRequest` does not carry it, so only
//!   chain linkage is checked.
//! - Regtest: chain linkage only.
//!
//! The testnet3 20-minute min-difficulty rule is not implemented. Testnet3 is
//! not a target environment.

use bitcoin::block::Header;
use bitcoin::pow::CompactTarget;

use crate::networks::rgb::spv::types::{BlockHeight, Network, Result, SpvError};

/// Bitcoin's difficulty-retarget interval: every 2016 blocks.
pub const RETARGET_INTERVAL: BlockHeight = 2016;

/// Returns true when `height` is the start of a new retarget epoch.
pub fn is_retarget_height(height: BlockHeight) -> bool {
    height.is_multiple_of(RETARGET_INTERVAL)
}

/// Verifies that `header.prev_blockhash` equals `expected_prev_hash`
/// (internal byte order).
pub fn check_linkage(
    header: &Header,
    expected_prev_hash: &[u8; 32],
    height: BlockHeight,
) -> Result<()> {
    let prev_bytes: [u8; 32] = *header.prev_blockhash.as_ref();
    if &prev_bytes != expected_prev_hash {
        return Err(SpvError::ChainLinkage { height });
    }
    Ok(())
}

/// PoW check: `block_hash <= target_from_nBits(header.bits)`. Skipped on
/// signet and regtest (see module docs).
pub fn check_pow(header: &Header, height: BlockHeight, network: Network) -> Result<()> {
    if !network.enforces_pow() {
        return Ok(());
    }
    let target = header.target();
    header
        .validate_pow(target)
        .map_err(|_| SpvError::PowFailed { height })?;
    Ok(())
}

/// Computes the required `nBits` for the header at `height`.
///
/// `prev_bits` is the `nBits` of the block at `height - 1`.
/// `prev_time` is the `time` of the block at `height - 1`.
/// `epoch_start_time` is the `time` of the block at `height - RETARGET_INTERVAL`.
/// It is used only at retarget boundaries.
///
/// Returns `Ok(None)` on signet and regtest. The caller then skips the `nBits`
/// check.
pub fn expected_bits(
    height: BlockHeight,
    prev_bits: u32,
    prev_time: u32,
    epoch_start_time: u32,
    network: Network,
) -> Result<Option<u32>> {
    if !network.enforces_pow() {
        return Ok(None);
    }
    if !is_retarget_height(height) {
        // Non-boundary block: bits must equal the previous block's bits.
        return Ok(Some(prev_bits));
    }

    // Boundary block: compute the expected bits from the previous epoch.
    let actual_timespan = u64::from(prev_time.saturating_sub(epoch_start_time));
    let prev_compact = CompactTarget::from_consensus(prev_bits);
    let next = CompactTarget::from_next_work_required(
        prev_compact,
        actual_timespan,
        network.as_bitcoin_params(),
    );
    Ok(Some(next.to_consensus()))
}

/// Checks linkage, then `nBits` (if given), then PoW (if the network
/// enforces it). `HeaderChain::submit_headers` calls it.
pub fn validate_header_full(
    header: &Header,
    height: BlockHeight,
    expected_prev_hash: &[u8; 32],
    expected_bits_value: Option<u32>,
    network: Network,
) -> Result<()> {
    check_linkage(header, expected_prev_hash, height)?;

    if let Some(expected) = expected_bits_value {
        let got = header.bits.to_consensus();
        if got != expected {
            return Err(SpvError::BitsMismatch {
                height,
                got,
                expected,
            });
        }
    }

    check_pow(header, height, network)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;

    /// Real mainnet block 1 header (hex), to test the parser and mainnet PoW.
    /// https://blockstream.info/api/block/00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048/header
    const MAINNET_BLOCK_1_HEADER_HEX: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";

    /// Real mainnet block 0 (genesis) hash, internal byte order.
    const MAINNET_GENESIS_HASH_INTERNAL: [u8; 32] = [
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    fn parse_hex_header(hex: &str) -> Header {
        let bytes = hex::decode(hex).unwrap();
        deserialize::<Header>(&bytes).unwrap()
    }

    #[test]
    fn mainnet_block_1_links_to_genesis() {
        let h1 = parse_hex_header(MAINNET_BLOCK_1_HEADER_HEX);
        check_linkage(&h1, &MAINNET_GENESIS_HASH_INTERNAL, 1).unwrap();
    }

    #[test]
    fn mainnet_block_1_pow_passes() {
        let h1 = parse_hex_header(MAINNET_BLOCK_1_HEADER_HEX);
        check_pow(&h1, 1, Network::Mainnet).unwrap();
    }

    #[test]
    fn linkage_rejects_wrong_prev_hash() {
        let h1 = parse_hex_header(MAINNET_BLOCK_1_HEADER_HEX);
        let wrong = [0xAB; 32];
        let err = check_linkage(&h1, &wrong, 1).unwrap_err();
        assert!(matches!(err, SpvError::ChainLinkage { height: 1 }));
    }

    #[test]
    fn signet_skips_pow_check() {
        // A header whose hash exceeds the target: mainnet PoW fails, signet
        // and regtest pass. Built by mutating block 1's nonce.
        let mut bytes = hex::decode(MAINNET_BLOCK_1_HEADER_HEX).unwrap();
        // Flip the last nonce byte to break PoW.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let bad = deserialize::<Header>(&bytes).unwrap();

        assert!(check_pow(&bad, 1, Network::Mainnet).is_err());
        check_pow(&bad, 1, Network::Signet).unwrap();
        check_pow(&bad, 1, Network::Regtest).unwrap();
    }

    #[test]
    fn expected_bits_non_boundary_equals_prev() {
        let bits = 0x1d00ffff;
        let got = expected_bits(1, bits, 0, 0, Network::Mainnet).unwrap();
        assert_eq!(got, Some(bits));
    }

    #[test]
    fn expected_bits_signet_returns_none() {
        let got = expected_bits(2016, 0x1d00ffff, 0, 0, Network::Signet).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn expected_bits_regtest_returns_none() {
        let got = expected_bits(2016, 0x207fffff, 0, 0, Network::Regtest).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn is_retarget_height_boundaries() {
        assert!(is_retarget_height(0));
        assert!(is_retarget_height(2016));
        assert!(is_retarget_height(4032));
        assert!(!is_retarget_height(1));
        assert!(!is_retarget_height(2015));
        assert!(!is_retarget_height(2017));
    }

    #[test]
    fn block_hash_round_trip() {
        // Block 1 hash in display order. Internal order is the reverse.
        let h1 = parse_hex_header(MAINNET_BLOCK_1_HEADER_HEX);
        let internal = h1.block_hash().to_byte_array();
        let mut display = internal;
        display.reverse();
        assert_eq!(
            hex::encode(display),
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
        );
    }
}
