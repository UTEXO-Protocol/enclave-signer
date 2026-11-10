use super::*;
use bitcoin::consensus::deserialize;

/// Real mainnet block 1 header (hex), to test the parser and mainnet PoW.
/// https://blockstream.info/api/block/00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048/header
const MAINNET_BLOCK_1_HEADER_HEX: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";

/// Real mainnet block 0 (genesis) hash, internal byte order.
const MAINNET_GENESIS_HASH_INTERNAL: [u8; 32] = [
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
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
fn expected_bits_signet_returns_none() {
    let input = BitsInput {
        height: 2016,
        prev_bits: 0x1d00ffff,
        ..BitsInput::default()
    };
    assert_eq!(expected_bits(&input, Network::Signet), None);
    assert_eq!(expected_bits(&input, Network::SignetCustom), None);
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
    let err = check_timewarp(155_232, 1_791_203_298, 1_791_203_899, Network::Testnet4).unwrap_err();
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
