//! Per-header validation functions. They hold no chain state.
//!
//! `HeaderChain` gives the prior-header context. These functions check
//! linkage to the predecessor, the time against the enclave clock, the time
//! against the median time past of the eleven blocks below, PoW and the
//! `nBits` for the height. On testnet4 they also check the BIP94 timewarp
//! rule.
//!
//! Per network:
//!
//! - Mainnet: PoW and retarget checks. `expected_bits` computes the required
//!   `nBits`.
//! - Testnet3 and testnet4: the same, plus the 20-minute rule. A block more
//!   than 20 minutes after its parent may use the minimum difficulty. Other
//!   blocks carry the bits of the period's first block. Testnet4 adds BIP94:
//!   the retarget starts from the first block of the period, and that block
//!   may not be more than 600 s older than its parent.
//! - Signet: this implementation skips PoW and `nBits` checks. It also cannot
//!   verify the BIP-325 challenge because the request has no coinbase witness.
//!   Per-header validation checks only chain linkage and the clock bound.
//! - Regtest: chain linkage and the clock bound only.

use bitcoin::block::Header;
use bitcoin::pow::CompactTarget;

use crate::networks::rgb::spv::types::{BlockHeight, Network, Result, SpvError};

/// Bitcoin's difficulty-retarget interval: every 2016 blocks.
pub const RETARGET_INTERVAL: BlockHeight = 2016;

/// BIP94: how far a period's first block may be older than its parent.
pub const MAX_TIMEWARP_SECS: u32 = 600;

/// How far a header may be ahead of the enclave clock, as Bitcoin Core's
/// `MAX_FUTURE_BLOCK_TIME`.
pub const MAX_FUTURE_BLOCK_TIME_SECS: u64 = 2 * 60 * 60;

/// Blocks in Bitcoin Core's median-time-past window (`nMedianTimeSpan`).
pub const MEDIAN_TIME_SPAN: usize = 11;

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

/// What the `nBits` rule of a header reads from the chain below it.
#[derive(Debug, Clone, Copy, Default)]
pub struct BitsInput {
    pub height: BlockHeight,
    pub header_time: u32,
    /// `nBits` and `time` of the block at `height - 1`.
    pub prev_bits: u32,
    pub prev_time: u32,
    /// `nBits` of the period's first block (`height - height % 2016`). Read
    /// off a boundary on min-difficulty networks only.
    pub period_bits: u32,
    /// `nBits` and `time` of the block at `height - 2016`. Read at a boundary
    /// only.
    pub epoch_first_bits: u32,
    pub epoch_first_time: u32,
}

/// Computes the required `nBits` for a header, as Bitcoin Core
/// `GetNextWorkRequired` does.
///
/// Off a boundary, a min-difficulty network takes the minimum when the header
/// is more than 20 minutes after its parent. Otherwise Core walks back to the
/// last block not mined under that rule. In a valid period that block carries
/// the bits of the period's first block, which never takes the exception.
///
/// Returns `None` on signet and regtest. The caller then skips the `nBits`
/// check.
pub fn expected_bits(input: &BitsInput, network: Network) -> Option<u32> {
    if !network.enforces_pow() {
        return None;
    }
    let params = network.as_bitcoin_params();
    if !is_retarget_height(input.height) {
        if !network.allows_min_difficulty() {
            return Some(input.prev_bits);
        }
        let min_difficulty_after = u64::from(input.prev_time) + 2 * params.pow_target_spacing;
        if u64::from(input.header_time) > min_difficulty_after {
            return Some(network.pow_limit_bits());
        }
        return Some(input.period_bits);
    }

    // Boundary: BIP94 retargets from the period's first block, which cannot
    // be a min-difficulty block. Older networks use the last block.
    let base = if network.bip94() {
        input.epoch_first_bits
    } else {
        input.prev_bits
    };
    let actual_timespan = u64::from(input.prev_time.saturating_sub(input.epoch_first_time));
    let next = CompactTarget::from_next_work_required(
        CompactTarget::from_consensus(base),
        actual_timespan,
        params,
    );
    Some(next.to_consensus())
}

/// BIP94 timewarp rule: a period's first block may not be more than
/// [`MAX_TIMEWARP_SECS`] older than its parent.
pub fn check_timewarp(
    height: BlockHeight,
    time: u32,
    prev_time: u32,
    network: Network,
) -> Result<()> {
    if !network.bip94() || !is_retarget_height(height) {
        return Ok(());
    }
    if u64::from(time) + u64::from(MAX_TIMEWARP_SECS) < u64::from(prev_time) {
        return Err(SpvError::Timewarp {
            height,
            time,
            prev_time,
        });
    }
    Ok(())
}

/// Core's `time-too-new` rule against the enclave clock (`now_unix`). On the
/// testnets it also bounds how fast a host fork can retarget down: free
/// blocks cannot be dated ahead, so a 4x drop needs 8 weeks of real time.
pub fn check_future_time(height: BlockHeight, time: u32, now_unix: u64) -> Result<()> {
    if u64::from(time) > now_unix.saturating_add(MAX_FUTURE_BLOCK_TIME_SECS) {
        return Err(SpvError::TimeTooNew {
            height,
            time,
            now: now_unix,
        });
    }
    Ok(())
}

/// The median time past of one window of block times, as Bitcoin Core
/// computes it: the middle value of the sorted times. `times` holds at most
/// [`MEDIAN_TIME_SPAN`] values and at least one.
pub fn median_time_past(times: &mut [u32]) -> u32 {
    times.sort_unstable();
    times[times.len() / 2]
}

/// Core's `time-too-old` rule: a block's time is newer than the median time
/// past of the [`MEDIAN_TIME_SPAN`] blocks below it. It applies on every
/// network, as in Core. `None` skips the rule. The chain has no times below
/// its checkpoint, and a median of fewer blocks could be stricter than
/// Core's. So the rule starts where the chain holds all eleven times.
pub fn check_time_too_old(
    height: BlockHeight,
    time: u32,
    median_time_past: Option<u32>,
) -> Result<()> {
    if let Some(median_time_past) = median_time_past {
        if time <= median_time_past {
            return Err(SpvError::TimeTooOld {
                height,
                time,
                median_time_past,
            });
        }
    }
    Ok(())
}

/// The block below a header: its hash (internal byte order) and time.
#[derive(Debug, Clone, Copy)]
pub struct Predecessor {
    pub hash: [u8; 32],
    pub time: u32,
}

/// Checks linkage, the timewarp rule, the clock bound, the median-time-past
/// bound (if given), then `nBits` (if given), then PoW (if the network
/// enforces it). `HeaderChain::submit_headers` calls it.
pub fn validate_header_full(
    header: &Header,
    height: BlockHeight,
    prev: Predecessor,
    median_time_past: Option<u32>,
    expected_bits_value: Option<u32>,
    network: Network,
    now_unix: u64,
) -> Result<()> {
    check_linkage(header, &prev.hash, height)?;
    check_timewarp(height, header.time, prev.time, network)?;
    check_future_time(height, header.time, now_unix)?;
    check_time_too_old(height, header.time, median_time_past)?;

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
        let input = BitsInput {
            height: 1,
            prev_bits: bits,
            ..BitsInput::default()
        };
        assert_eq!(expected_bits(&input, Network::Mainnet), Some(bits));
    }

    #[test]
    fn expected_bits_signet_returns_none() {
        let input = BitsInput {
            height: 2016,
            prev_bits: 0x1d00ffff,
            ..BitsInput::default()
        };
        assert_eq!(expected_bits(&input, Network::Signet), None);
        assert_eq!(expected_bits(&input, Network::SignetCustom), None);
    }

    #[test]
    fn expected_bits_regtest_returns_none() {
        let input = BitsInput {
            height: 2016,
            prev_bits: 0x207fffff,
            ..BitsInput::default()
        };
        assert_eq!(expected_bits(&input, Network::Regtest), None);
    }

    // Real testnet4 blocks (mempool.emzy.de/testnet4). Boundary 155232 has
    // bits 0x19037e43, time 1791203299. Its parent 155231 is a min-difficulty
    // block at 1791203899. The period's first block 153216 has bits
    // 0x19033f6e, time 1789902886.
    const T4_BOUNDARY: BitsInput = BitsInput {
        height: 155_232,
        header_time: 1_791_203_299,
        prev_bits: 0x1d00ffff,
        prev_time: 1_791_203_899,
        period_bits: 0,
        epoch_first_bits: 0x1903_3f6e,
        epoch_first_time: 1_789_902_886,
    };

    #[test]
    fn testnet4_boundary_retargets_from_the_period_first_block() {
        assert_eq!(
            expected_bits(&T4_BOUNDARY, Network::Testnet4),
            Some(0x1903_7e43)
        );
    }

    /// The parent of 155232 is a min-difficulty block. The pre-BIP94 rule
    /// retargets from it and lands on the minimum, which the real block is not.
    #[test]
    fn a_block_storm_before_the_boundary_needs_bip94() {
        assert_eq!(
            expected_bits(&T4_BOUNDARY, Network::Testnet3),
            Some(0x1d00ffff)
        );
    }

    /// 155233 is 1201 s after 155232, so it may use the minimum difficulty.
    #[test]
    fn testnet4_block_more_than_20_minutes_late_takes_the_minimum() {
        let input = BitsInput {
            height: 155_233,
            header_time: 1_791_204_500,
            prev_bits: 0x1903_7e43,
            prev_time: 1_791_203_299,
            period_bits: 0x1903_7e43,
            ..BitsInput::default()
        };
        assert_eq!(expected_bits(&input, Network::Testnet4), Some(0x1d00ffff));
    }

    /// 155238 follows five min-difficulty blocks and is earlier than its
    /// parent: it carries the period bits, not its parent's.
    #[test]
    fn testnet4_block_after_min_difficulty_blocks_takes_the_period_bits() {
        let input = BitsInput {
            height: 155_238,
            header_time: 1_791_203_900,
            prev_bits: 0x1d00ffff,
            prev_time: 1_791_209_304,
            period_bits: 0x1903_7e43,
            ..BitsInput::default()
        };
        assert_eq!(expected_bits(&input, Network::Testnet4), Some(0x1903_7e43));
    }

    /// Exactly 1200 s is not "more than 20 minutes".
    #[test]
    fn exactly_20_minutes_late_keeps_the_period_bits() {
        let input = BitsInput {
            height: 155_233,
            header_time: 1_791_204_499,
            prev_time: 1_791_203_299,
            period_bits: 0x1903_7e43,
            ..BitsInput::default()
        };
        assert_eq!(expected_bits(&input, Network::Testnet4), Some(0x1903_7e43));
    }

    #[test]
    fn mainnet_ignores_the_20_minute_rule() {
        let input = BitsInput {
            height: 1,
            header_time: 10_000,
            prev_bits: 0x1702_068f,
            prev_time: 0,
            period_bits: 0x1d00ffff,
            ..BitsInput::default()
        };
        assert_eq!(expected_bits(&input, Network::Mainnet), Some(0x1702_068f));
    }

    /// 155232 is exactly 600 s older than its parent: the edge BIP94 allows.
    #[test]
    fn timewarp_allows_exactly_600_seconds_back() {
        check_timewarp(155_232, 1_791_203_299, 1_791_203_899, Network::Testnet4).unwrap();
    }

    #[test]
    fn timewarp_refuses_601_seconds_back() {
        let err =
            check_timewarp(155_232, 1_791_203_298, 1_791_203_899, Network::Testnet4).unwrap_err();
        assert!(matches!(
            err,
            SpvError::Timewarp {
                height: 155_232,
                ..
            }
        ));
    }

    #[test]
    fn timewarp_applies_only_to_testnet4_boundaries() {
        check_timewarp(155_233, 0, 1_791_203_899, Network::Testnet4).unwrap();
        check_timewarp(155_232, 0, 1_791_203_899, Network::Testnet3).unwrap();
        check_timewarp(155_232, 0, 1_791_203_899, Network::Mainnet).unwrap();
    }

    #[test]
    fn a_header_may_be_two_hours_ahead_of_the_clock() {
        check_future_time(1, 1_000_000 + 7_200, 1_000_000).unwrap();
        check_future_time(1, 0, 1_000_000).unwrap();
    }

    #[test]
    fn a_header_more_than_two_hours_ahead_of_the_clock_is_refused() {
        let err = check_future_time(7, 1_000_000 + 7_201, 1_000_000).unwrap_err();
        assert!(matches!(
            err,
            SpvError::TimeTooNew {
                height: 7,
                time: 1_007_201,
                now: 1_000_000
            }
        ));
    }

    #[test]
    fn the_median_time_past_is_the_sixth_smallest_of_eleven() {
        let mut times = [11, 1, 10, 2, 9, 3, 8, 4, 7, 5, 6];
        assert_eq!(median_time_past(&mut times), 6);
        let mut flat = [100; MEDIAN_TIME_SPAN];
        assert_eq!(median_time_past(&mut flat), 100);
        // A chain from genesis has fewer blocks: Core takes the middle one.
        assert_eq!(median_time_past(&mut [7]), 7);
        assert_eq!(median_time_past(&mut [9, 7]), 9);
        assert_eq!(median_time_past(&mut [3, 1, 2, 5, 4]), 3);
    }

    #[test]
    fn a_header_at_or_before_the_median_time_past_is_refused() {
        check_time_too_old(12, 101, Some(100)).unwrap();
        let err = check_time_too_old(12, 100, Some(100)).unwrap_err();
        assert!(matches!(
            err,
            SpvError::TimeTooOld {
                height: 12,
                time: 100,
                median_time_past: 100
            }
        ));
        assert!(check_time_too_old(12, 50, Some(100)).is_err());
        // No median: the rule does not apply.
        check_time_too_old(5, 0, None).unwrap();
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
