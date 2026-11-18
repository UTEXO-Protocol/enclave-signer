use super::*;
use crate::networks::rgb::spv::checkpoint::Checkpoint;
use crate::networks::rgb::spv::{HeaderChain, Network};
use crate::test_support::ANY_HEADER_CLOCK;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;

/// The depth these tests are written for: a target block and five burying blocks.
const MIN_CONFIRMATIONS: u32 = 6;

/// Synthetic regtest chain on a zero checkpoint. Regtest skips PoW. These
/// tests cover the SPV cross-check, not header validation (see chain.rs).
/// The checkpoint time is below every header time these tests use: on a chain
/// from genesis the median-time-past rule applies from block 1.
fn regtest_chain_with(headers: Vec<Header>) -> HeaderChain {
    let mut chain = HeaderChain::new(
        Network::Regtest,
        Checkpoint {
            height: 0,
            hash: [0u8; 32],
            bits: 0x207fffff,
            time: 1_699_999_000,
            is_real: false,
            chain_work: None,
        },
    );
    let raw_headers: Vec<Vec<u8>> = headers.iter().map(serialize).collect();
    chain
        .submit_headers(1, &raw_headers, ANY_HEADER_CLOCK)
        .unwrap();
    chain
}

/// N synthetic regtest headers from a zero prev_blockhash. Each header has a
/// distinct, fixed merkle_root, so proofs can use a known root.
fn synth_headers(count: u32) -> Vec<Header> {
    let mut prev = bitcoin::BlockHash::from_byte_array([0u8; 32]);
    let mut out = Vec::new();
    for i in 0..count {
        let mut root_bytes = [0u8; 32];
        root_bytes[0] = i as u8;
        root_bytes[1] = 0xAB;
        let header = Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(root_bytes),
            time: 1_700_000_001 + i,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: i,
        };
        prev = header.block_hash();
        out.push(header);
    }
    out
}

/// Chain with `target_header` at height 1 and `depth_above` filler headers
/// on top of it.
fn chain_burying(target_header: Header, depth_above: u32) -> HeaderChain {
    let base_time = target_header.time;
    let mut headers = vec![target_header];
    let mut prev = headers[0].block_hash();
    for i in 0..depth_above {
        let h = Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: base_time + 1 + i,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        prev = h.block_hash();
        headers.push(h);
    }
    regtest_chain_with(headers)
}

/// Real testnet4 headers 155_233..=155_262 on the compiled checkpoint.
fn testnet4_chain() -> HeaderChain {
    let raws: Vec<Vec<u8>> = include_str!("../spv/chain/testnet4_155233_155262.hex")
        .lines()
        .map(|line| hex::decode(line).unwrap())
        .collect();
    let mut chain = HeaderChain::new(
        Network::Testnet4,
        crate::networks::rgb::spv::checkpoint::TESTNET4_CHECKPOINT,
    );
    chain
        .submit_headers(155_233, &raws, ANY_HEADER_CLOCK)
        .unwrap();
    chain
}

/// The block validation placed a witness in at `height` of `chain`.
fn witness_block(chain: &HeaderChain, height: u32) -> WitnessBlock {
    WitnessBlock {
        txid: [0x11; 32],
        height,
        hash: chain.hash_at(height).unwrap(),
    }
}

/// A validated consignment whose witnesses sit at `heights` of `chain`.
fn validated_at(chain: &HeaderChain, heights: &[u32]) -> ValidatedConsignment {
    ValidatedConsignment {
        chain_net: Network::Regtest.chain_net().prefix().to_string(),
        witness_blocks: heights
            .iter()
            .map(|height| witness_block(chain, *height))
            .collect(),
        ..Default::default()
    }
}

// ===== Headers served to consignment validation =====

#[test]
fn a_header_six_deep_is_served() {
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);

    assert_eq!(buried_header(&chain, 1, MIN_CONFIRMATIONS).unwrap(), target);
    assert_eq!(
        safe_height(&chain, MIN_CONFIRMATIONS),
        NonZeroU32::new(1),
        "the only block that deep"
    );
}

/// A header more than 2122 blocks below the tip is served. Full retention
/// keeps it, so the lookup does not fail with "no header at height H".
#[test]
fn a_deep_header_is_served_with_full_retention() {
    let target = synth_headers(1).into_iter().next().unwrap();
    // Pruning to floor_2016(tip - 2122) would drop height 1 when
    // tip >= 4138. 4200 is past that, so a pruning chain fails this test.
    let chain = chain_burying(target, 4200);
    let tip = chain.tip_height();
    let depth = 100 + 2016 + 6;
    let floor = (tip.saturating_sub(depth) / 2016) * 2016;
    assert!(
        floor >= 1,
        "precondition: pruning to {floor} would drop the header at height 1 (tip={tip})"
    );

    assert_eq!(buried_header(&chain, 1, MIN_CONFIRMATIONS).unwrap(), target);
}

#[test]
fn a_header_short_of_the_depth_is_not_served() {
    let target = synth_headers(1).into_iter().next().unwrap();
    // 4 blocks above -> 5 confirmations < 6.
    let chain = chain_burying(target, 4);

    let err = buried_header(&chain, 1, MIN_CONFIRMATIONS).unwrap_err();
    assert_eq!(
        err.to_string(),
        "spv: witness proof: insufficient confirmations for block_height 1 (5 < 6)"
    );
    assert_eq!(safe_height(&chain, MIN_CONFIRMATIONS), None);
}

/// The bridge reads the height and the tip out of this text to wait for the
/// signer's headers.
#[test]
fn no_header_is_served_above_the_tip() {
    let chain = regtest_chain_with(synth_headers(7));

    let err = buried_header(&chain, 8, MIN_CONFIRMATIONS).unwrap_err();
    assert_eq!(
        err.to_string(),
        "spv: witness proof: no header at height 8 (chain tip = 7)"
    );
}

#[test]
fn no_header_is_served_at_the_checkpoint() {
    let chain = regtest_chain_with(synth_headers(7));

    let err = buried_header(&chain, 0, MIN_CONFIRMATIONS).unwrap_err();
    assert!(
        err.to_string().contains("no header at height 0"),
        "got: {err}"
    );
}

/// Min-difficulty blocks count on the testnets. The tip (155_262) is one, so
/// 155_257 is exactly six deep and 155_258 is five.
#[test]
fn min_difficulty_blocks_make_a_witness_deep() {
    let chain = testnet4_chain();
    buried_header(&chain, 155_257, MIN_CONFIRMATIONS).unwrap();
    assert_eq!(
        safe_height(&chain, MIN_CONFIRMATIONS),
        NonZeroU32::new(155_257)
    );

    let err = buried_header(&chain, 155_258, MIN_CONFIRMATIONS).unwrap_err();
    assert!(
        err.to_string().contains("insufficient confirmations"),
        "got: {err}"
    );
}

/// The depth is a parameter: the same header is served at 1 and not at 2.
#[test]
fn min_confirmations_is_a_parameter() {
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 0);
    buried_header(&chain, 1, 1).unwrap();
    let err = buried_header(&chain, 1, 2).unwrap_err();
    assert!(err.to_string().contains("(1 < 2)"), "got: {err}");
}

#[test]
fn the_safe_height_is_the_highest_block_at_the_depth() {
    let chain = regtest_chain_with(synth_headers(10));

    assert_eq!(safe_height(&chain, MIN_CONFIRMATIONS), NonZeroU32::new(5));
    assert_eq!(safe_height(&chain, 1), NonZeroU32::new(10));
    buried_header(&chain, 5, MIN_CONFIRMATIONS).unwrap();
    buried_header(&chain, 6, MIN_CONFIRMATIONS).unwrap_err();
}

// ===== Witness blocks, confirmed in one view of the chain =====

#[test]
fn a_witness_block_still_in_the_chain_is_confirmed() {
    let chain = regtest_chain_with(synth_headers(10));

    confirm_witness_block(&chain, &witness_block(&chain, 3), MIN_CONFIRMATIONS).unwrap();
}

/// Validation read the header under another lock. A header replaced since
/// then is not the one the SPV proof was checked against.
#[test]
fn a_witness_block_the_chain_replaced_is_refused() {
    let chain = regtest_chain_with(synth_headers(10));
    let mut block = witness_block(&chain, 3);
    block.hash = [0xEE; 32];

    let err = confirm_witness_block(&chain, &block, MIN_CONFIRMATIONS).unwrap_err();
    assert!(
        err.to_string()
            .contains("the header chain changed during validation"),
        "got: {err}"
    );
}

#[test]
fn a_witness_block_short_of_the_depth_is_refused() {
    let chain = regtest_chain_with(synth_headers(10));

    let err =
        confirm_witness_block(&chain, &witness_block(&chain, 6), MIN_CONFIRMATIONS).unwrap_err();
    assert!(err.to_string().contains("(5 < 6)"), "got: {err}");
}

#[test]
fn the_source_check_pins_every_witness_block() {
    let chain = regtest_chain_with(synth_headers(10));
    let pins = ChainPins::new();

    validate_source_chain(
        &chain,
        Some(&validated_at(&chain, &[2, 3])),
        unix(1_700_000_100),
        &pins,
        MIN_CONFIRMATIONS,
    )
    .unwrap();

    assert_eq!(pins.pinned_count(), 2);
    pins.assert_unchanged(&chain).unwrap();
}

#[test]
fn the_source_check_refuses_a_shallow_witness_block() {
    let chain = regtest_chain_with(synth_headers(10));
    let pins = ChainPins::new();

    let err = validate_source_chain(
        &chain,
        Some(&validated_at(&chain, &[6])),
        unix(1_700_000_100),
        &pins,
        MIN_CONFIRMATIONS,
    )
    .unwrap_err();

    assert!(
        err.to_string().contains("insufficient confirmations"),
        "got: {err}"
    );
    assert_eq!(pins.pinned_count(), 0);
}

// ===== Staleness tests =====
//
// These pass an explicit `now` to `assert_chain_not_stale`, so they do not
// depend on the wall clock. Synthetic headers have `time = 1_700_000_001 + i`.

/// Build a chain whose tip header has the given `time` (Unix seconds).
fn chain_with_tip_time(tip_time: u32) -> HeaderChain {
    let header = Header {
        version: Version::ONE,
        prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: tip_time,
        bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
        nonce: 0,
    };
    regtest_chain_with(vec![header])
}

fn unix(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

#[test]
fn staleness_tip_at_exact_max_age_passes() {
    let chain = chain_with_tip_time(1_700_000_000);
    // Now = tip + max_age. age == max_age passes; only age > max_age fails.
    assert_chain_not_stale(
        &chain,
        unix(1_700_000_000 + SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )
    .unwrap();
}

#[test]
fn staleness_old_tip_rejects() {
    let chain = chain_with_tip_time(1_700_000_000);
    // Now = tip + 3 hours. Past `SPV_MAX_TIP_AGE_SECS`.
    let err = assert_chain_not_stale(
        &chain,
        unix(1_700_000_000 + 3 * 60 * 60),
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )
    .unwrap_err();
    assert!(err.to_string().contains("too stale"), "got: {err}");
}

#[test]
fn staleness_far_future_tip_rejects() {
    let chain = chain_with_tip_time(1_700_000_000 + 4 * 60 * 60);
    // Tip is 4h ahead of now, past `SPV_MAX_TIP_FUTURE_SECS` of future skew.
    let err = assert_chain_not_stale(
        &chain,
        unix(1_700_000_000),
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )
    .unwrap_err();
    assert!(err.to_string().contains("in the future"), "got: {err}");
}

#[test]
fn staleness_near_future_tip_passes() {
    let chain = chain_with_tip_time(1_700_000_000 + 30 * 60);
    // Tip is 30 min ahead of now: within `SPV_MAX_TIP_FUTURE_SECS`.
    assert_chain_not_stale(
        &chain,
        unix(1_700_000_000),
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )
    .unwrap();
}

#[test]
fn staleness_uses_checkpoint_time_when_no_headers() {
    // No headers: the chain uses checkpoint.time (1_700_000_000).
    // Now = +1h -> fresh; now = +3h -> stale.
    let chain = HeaderChain::new(
        Network::Regtest,
        crate::networks::rgb::spv::checkpoint::Checkpoint {
            height: 0,
            hash: [0u8; 32],
            bits: 0x207fffff,
            time: 1_700_000_000,
            is_real: false,
            chain_work: None,
        },
    );
    assert_chain_not_stale(
        &chain,
        unix(1_700_000_000 + 60 * 60),
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )
    .unwrap();

    let err = assert_chain_not_stale(
        &chain,
        unix(1_700_000_000 + 3 * 60 * 60),
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )
    .unwrap_err();
    assert!(err.to_string().contains("too stale"), "got: {err}");
}

// ===== Pins, checked again at signing =====

/// The source check pins each witness block with the depth it required. A
/// replacement chain of fewer, heavier blocks above the witness block keeps its
/// hash, so only that depth refuses the signature. The test fails if the pin
/// records depth 1.
#[test]
fn a_shorter_heavier_reorg_above_a_witness_block_refuses_at_signing() {
    let headers = synth_headers(10);
    let mut chain = regtest_chain_with(headers.clone());
    let validated = validated_at(&chain, &[3]);
    let pins = ChainPins::new();
    validate_source_chain(
        &chain,
        Some(&validated),
        unix(1_700_000_100),
        &pins,
        MIN_CONFIRMATIONS,
    )
    .unwrap();
    pins.assert_unchanged(&chain).unwrap();

    // Two blocks of the mainnet genesis target from height 4 out-work the
    // seven regtest blocks that they replace. Regtest checks no proof of work.
    let mut prev = headers[2].block_hash();
    let mut raw = Vec::new();
    for height in 4..=5u32 {
        let header = Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xEE; 32]),
            time: 1_700_000_001 + height,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: height,
        };
        prev = header.block_hash();
        raw.push(serialize(&header));
    }
    chain.submit_headers(4, &raw, ANY_HEADER_CLOCK).unwrap();
    assert_eq!(chain.tip_height(), 5);
    assert_eq!(
        chain.hash_at(3),
        Some(headers[2].block_hash().to_byte_array()),
        "the witness block stays"
    );

    let err = pins.assert_unchanged(&chain).unwrap_err();
    assert!(
        err.to_string().contains("fewer confirmations"),
        "got: {err}"
    );
}
