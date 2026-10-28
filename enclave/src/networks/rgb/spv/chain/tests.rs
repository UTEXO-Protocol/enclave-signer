use super::*;
use crate::networks::rgb::spv::validation::MAX_FUTURE_BLOCK_TIME_SECS;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;

/// The enclave clock in these tests: the time of the newest real header here
/// (testnet4 155_262), so no header is too far ahead of it.
const NOW: u64 = 1_791_217_894;

/// Synthetic regtest chain: a checkpoint at 100 and 5 headers. Regtest checks
/// no proof of work, so the headers need no mining.
fn synthetic_regtest_setup() -> (HeaderChain, Vec<Vec<u8>>) {
    let mut prev_hash = [0u8; 32];
    prev_hash[0] = 0xAA; // arbitrary checkpoint hash

    let checkpoint = Checkpoint {
        height: 100,
        hash: prev_hash,
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
        chain_work: None,
    };
    let chain = HeaderChain::new(Network::Regtest, checkpoint);

    let mut raws: Vec<Vec<u8>> = Vec::new();
    let mut prev = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(prev_hash),
    );
    for i in 0..5 {
        let header = Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_700_000_001 + i,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: i,
        };
        raws.push(serialize(&header));
        prev = header.block_hash();
    }
    (chain, raws)
}

#[test]
fn empty_chain_tip_is_checkpoint() {
    let (chain, _) = synthetic_regtest_setup();
    assert_eq!(chain.tip_height(), 100);
    assert_eq!(chain.tip_hash()[0], 0xAA);
    assert_eq!(chain.len(), 0);
    assert!(chain.is_empty());
}

#[test]
fn submits_contiguous_batch() {
    let (mut chain, raws) = synthetic_regtest_setup();
    let outcome = chain.submit_headers(101, &raws, NOW).unwrap();
    assert_eq!(outcome.headers_accepted, 5);
    assert_eq!(outcome.last_block_height, 105);
    assert_eq!(outcome.reorg_depth, 0);
    assert_eq!(chain.tip_height(), 105);
    assert_eq!(chain.len(), 5);
}

#[test]
fn rejects_non_contiguous_batch() {
    let (mut chain, raws) = synthetic_regtest_setup();
    // Tip is at 100 (checkpoint). start_height 102 leaves a gap.
    let err = chain.submit_headers(102, &raws, NOW).unwrap_err();
    assert!(matches!(
        err,
        SpvError::NonContiguous { got: 102, tip: 100 }
    ));
}

#[test]
fn rejects_at_or_below_checkpoint() {
    let (mut chain, raws) = synthetic_regtest_setup();
    // start_height == checkpoint.height.
    let err = chain.submit_headers(100, &raws, NOW).unwrap_err();
    assert!(matches!(
        err,
        SpvError::BelowCheckpoint {
            got: 100,
            checkpoint: 100,
        }
    ));
    // start_height < checkpoint.height.
    let err = chain.submit_headers(50, &raws, NOW).unwrap_err();
    assert!(matches!(err, SpvError::BelowCheckpoint { got: 50, .. }));
}

#[test]
fn rejects_broken_linkage() {
    let (mut chain, raws) = synthetic_regtest_setup();
    chain.submit_headers(101, &raws[..1], NOW).unwrap();
    // The same header at 102: its prev_blockhash is the checkpoint, not 101.
    let err = chain.submit_headers(102, &raws[..1], NOW).unwrap_err();
    assert!(matches!(err, SpvError::ChainLinkage { height: 102 }));
}

#[test]
fn header_lookup_by_height() {
    let (mut chain, raws) = synthetic_regtest_setup();
    chain.submit_headers(101, &raws, NOW).unwrap();

    // Checkpoint height: no header, but the hash is the checkpoint hash.
    assert!(chain.header_at(100).is_none());
    assert_eq!(chain.hash_at(100).unwrap()[0], 0xAA);

    assert!(chain.header_at(101).is_some());
    assert!(chain.header_at(105).is_some());
    assert!(chain.header_at(106).is_none());
    assert!(chain.header_at(99).is_none());
}

#[test]
fn rejects_garbage_header_bytes() {
    let (mut chain, _) = synthetic_regtest_setup();
    let err = chain
        .submit_headers(101, &[vec![0u8; 79]], NOW) // 79 bytes != 80
        .unwrap_err();
    assert!(matches!(err, SpvError::HeaderParse { index: 0, .. }));
}

#[test]
fn batch_is_atomic_on_failure() {
    let (mut chain, mut raws) = synthetic_regtest_setup();
    // The third header does not parse.
    raws[2] = vec![0u8; 79];

    let pre_tip = chain.tip_height();
    let pre_len = chain.len();
    let err = chain.submit_headers(101, &raws, NOW).unwrap_err();
    assert!(matches!(err, SpvError::HeaderParse { index: 2, .. }));

    // No partial accept.
    assert_eq!(chain.tip_height(), pre_tip);
    assert_eq!(chain.len(), pre_len);
}

/// Mainnet PoW and bits checks: the real block 1 on a genesis checkpoint.
#[test]
fn mainnet_block_1_appends_after_genesis_checkpoint() {
    // Mainnet genesis: height 0, bits 0x1d00ffff, time 1231006505.
    let genesis_hash_internal: [u8; 32] = [
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let cp = Checkpoint {
        height: 0,
        hash: genesis_hash_internal,
        bits: 0x1d00ffff,
        time: 1_231_006_505,
        is_real: false,
        chain_work: None,
    };
    let mut chain = HeaderChain::new(Network::Mainnet, cp);

    let block_1_hex = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
    let raw = hex::decode(block_1_hex).unwrap();

    let outcome = chain.submit_headers(1, &[raw], NOW).unwrap();
    assert_eq!(outcome.last_block_height, 1);
    assert_eq!(outcome.headers_accepted, 1);
    assert_eq!(outcome.reorg_depth, 0);
}

// ===== Bounded-reorg tests =====
//
// Regtest headers have constant nBits, so chain length is a proxy for work.

/// Builds `count` regtest headers on `prev_hash` and `prev_time`. A different
/// `nonce_seed` gives a different fork. Returns raw 80-byte headers and the
/// tip hash.
fn synth_chain_from(
    prev_hash: [u8; 32],
    prev_time: u32,
    nonce_seed: u32,
    count: u32,
) -> (Vec<Vec<u8>>, [u8; 32]) {
    let mut raws: Vec<Vec<u8>> = Vec::new();
    let mut prev = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(prev_hash),
    );
    let mut last_hash = prev_hash;
    for i in 0..count {
        let header = Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: prev_time + 1 + i,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            // Seed and index make each fork's nonces unique.
            nonce: nonce_seed.wrapping_mul(1_000_000) + i,
        };
        raws.push(serialize(&header));
        prev = header.block_hash();
        last_hash = *bitcoin::hashes::Hash::as_byte_array(&header.block_hash());
    }
    (raws, last_hash)
}

#[test]
fn reorg_accepted_when_alt_chain_is_strictly_longer() {
    let (mut chain, original) = synthetic_regtest_setup();
    // Original: heights 101..=105.
    chain.submit_headers(101, &original, NOW).unwrap();
    let original_tip = chain.tip_hash();

    // Alternative from 101 with 6 blocks.
    let cp_hash = chain.checkpoint().hash;
    let (alt, _alt_tip) = synth_chain_from(cp_hash, 1_700_000_000, 7, 6);

    let outcome = chain.submit_headers(101, &alt, NOW).unwrap();
    assert_eq!(outcome.headers_accepted, 6);
    assert_eq!(outcome.reorg_depth, 5); // displaced 101..=105
    assert_eq!(outcome.last_block_height, 106);
    assert_ne!(chain.tip_hash(), original_tip);
    assert_eq!(chain.tip_height(), 106);
    assert_eq!(chain.len(), 6);
}

#[test]
fn reorg_rejected_when_alt_chain_is_equal_length() {
    let (mut chain, original) = synthetic_regtest_setup();
    chain.submit_headers(101, &original, NOW).unwrap();
    let original_tip = chain.tip_hash();
    let original_height = chain.tip_height();

    // Same length (5), different headers.
    let cp_hash = chain.checkpoint().hash;
    let (alt, _) = synth_chain_from(cp_hash, 1_700_000_000, 99, 5);

    let err = chain.submit_headers(101, &alt, NOW).unwrap_err();
    assert!(matches!(err, SpvError::WeakerChain));
    assert_eq!(chain.tip_hash(), original_tip);
    assert_eq!(chain.tip_height(), original_height);
}

#[test]
fn reorg_rejected_when_alt_chain_is_shorter() {
    let (mut chain, original) = synthetic_regtest_setup();
    chain.submit_headers(101, &original, NOW).unwrap();
    let original_tip = chain.tip_hash();

    // Reorg at 102 with 3 alt blocks. The original has 4 (102..=105).
    let pred_hash = chain.hash_at(101).unwrap();
    let (alt, _) = synth_chain_from(pred_hash, 1_700_000_002, 11, 3);

    let err = chain.submit_headers(102, &alt, NOW).unwrap_err();
    assert!(matches!(err, SpvError::WeakerChain));
    assert_eq!(chain.tip_hash(), original_tip);
}

#[test]
fn reorg_too_deep_rejected() {
    let (mut chain, _) = synthetic_regtest_setup();
    let cp_hash = chain.checkpoint().hash;
    let (long, _) = synth_chain_from(cp_hash, 1_700_000_000, 1, MAX_REORG_DEPTH + 50);
    chain.submit_headers(101, &long, NOW).unwrap();
    let tip_before = chain.tip_height();

    // depth = tip - start + 1 > MAX_REORG_DEPTH.
    let too_deep_start = chain.checkpoint().height + 5;
    let pred_hash = chain.hash_at(too_deep_start - 1).unwrap();
    let (alt, _) = synth_chain_from(pred_hash, 1_700_000_005, 50, MAX_REORG_DEPTH + 100);

    let err = chain.submit_headers(too_deep_start, &alt, NOW).unwrap_err();
    assert!(matches!(err, SpvError::ReorgTooDeep { .. }));
    assert_eq!(chain.tip_height(), tip_before);
}

#[test]
fn reorg_at_max_depth_is_allowed() {
    let (mut chain, _) = synthetic_regtest_setup();
    let cp_hash = chain.checkpoint().hash;
    // MAX_REORG_DEPTH headers, so a reorg from checkpoint + 1 has depth
    // MAX_REORG_DEPTH.
    let (orig, _) = synth_chain_from(cp_hash, 1_700_000_000, 1, MAX_REORG_DEPTH);
    chain.submit_headers(101, &orig, NOW).unwrap();

    // MAX_REORG_DEPTH + 1 alt headers from the checkpoint: more work.
    let (alt, _) = synth_chain_from(cp_hash, 1_700_000_000, 42, MAX_REORG_DEPTH + 1);
    let outcome = chain.submit_headers(101, &alt, NOW).unwrap();
    assert_eq!(outcome.reorg_depth, MAX_REORG_DEPTH);
    assert_eq!(outcome.headers_accepted, MAX_REORG_DEPTH + 1);
}

#[test]
fn reorg_atomic_on_validation_failure() {
    let (mut chain, original) = synthetic_regtest_setup();
    chain.submit_headers(101, &original, NOW).unwrap();
    let original_tip = chain.tip_hash();
    let original_height = chain.tip_height();

    // Longer alt from 102 (depth 4) with a header that does not parse.
    let pred_hash = chain.hash_at(101).unwrap();
    let (mut alt, _) = synth_chain_from(pred_hash, 1_700_000_002, 13, 6);
    alt[3] = vec![0u8; 79]; // not 80 bytes

    let err = chain.submit_headers(102, &alt, NOW).unwrap_err();
    assert!(matches!(err, SpvError::HeaderParse { index: 3, .. }));
    // No partial accept, no truncate.
    assert_eq!(chain.tip_hash(), original_tip);
    assert_eq!(chain.tip_height(), original_height);
    assert_eq!(chain.len(), 5);
}

#[test]
fn non_pow_network_skips_epoch_lookup_across_retarget_boundary() {
    // Regression: on a non-PoW network, an epoch start below the checkpoint
    // must not give HeaderNotFound. Checkpoint 4000, retarget 4032, start 2016.
    let cp_hash = {
        let mut h = [0u8; 32];
        h[0] = 0xBB;
        h
    };
    let checkpoint = Checkpoint {
        height: 4000,
        hash: cp_hash,
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
        chain_work: None,
    };
    let mut chain = HeaderChain::new(Network::Regtest, checkpoint);

    // Heights 4001..=4100, across the retarget at 4032.
    let (raws, _) = synth_chain_from(cp_hash, 1_700_000_000, 1, 100);
    let outcome = chain.submit_headers(4001, &raws, NOW).unwrap();
    assert_eq!(outcome.headers_accepted, 100);
    assert_eq!(outcome.last_block_height, 4100);
}

// ===== retarget-boundary epoch-start resolution =====
//
// A retarget boundary at height B needs the block at `B - RETARGET_INTERVAL`.
// With a misaligned checkpoint, that block is below the checkpoint and is not
// stored, so the chain stops. validation.rs tests the difficulty math.

/// TH-1: with an aligned checkpoint, the first boundary above it resolves its
/// epoch start to the checkpoint.
#[test]
fn th1_epoch_start_resolves_at_first_boundary_above_aligned_checkpoint() {
    let cp = Checkpoint {
        height: 951_552, // == 472 * RETARGET_INTERVAL (the real mainnet checkpoint)
        hash: [0x11; 32],
        bits: 0x1702_068f,
        time: 1_780_050_586,
        is_real: true,
        chain_work: None,
    };
    assert_eq!(cp.height % RETARGET_INTERVAL, 0, "precondition: aligned");
    let chain = HeaderChain::new(Network::Mainnet, cp);

    let first_boundary = cp.height + RETARGET_INTERVAL; // 953_568
    let input = chain
        .bits_input(first_boundary, 0, (0, 0), first_boundary, &[])
        .expect("aligned checkpoint must resolve the first boundary's epoch start");
    assert_eq!(
        (input.epoch_first_time, input.epoch_first_bits),
        (cp.time, cp.bits)
    );
}

/// TH-2: a misaligned checkpoint (950_000) stops the chain. The first boundary
/// (951_552) needs the epoch start 949_536, which is not stored. The load-time
/// check rejects such a checkpoint.
#[test]
fn th2_misaligned_checkpoint_wedges_at_first_boundary() {
    let cp = Checkpoint {
        height: 950_000, // 950_000 % 2016 == 464 -> NOT aligned
        hash: [0x22; 32],
        bits: 0x1702_0f79,
        time: 1_779_141_269,
        is_real: true,
        chain_work: None,
    };
    assert_ne!(cp.height % RETARGET_INTERVAL, 0, "precondition: misaligned");
    let chain = HeaderChain::new(Network::Mainnet, cp);

    // 951_552 = 472 * 2016.
    let first_boundary = 951_552;
    let err = chain
        .bits_input(first_boundary, 0, (0, 0), first_boundary, &[])
        .unwrap_err();
    assert!(matches!(err, SpvError::HeaderNotFound(949_536)));
}

// ===== full retention from the checkpoint =====

/// The base stays at the checkpoint, and `header_at` resolves anchors more
/// than 2122 blocks below the tip.
#[test]
fn retains_full_history_from_checkpoint() {
    // Checkpoint at height 0, so boundaries are multiples of 2016.
    let cp = Checkpoint {
        height: 0,
        hash: [0xCC; 32],
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
        chain_work: None,
    };
    let mut chain = HeaderChain::new(Network::Regtest, cp);

    // More than 2122 headers plus a full epoch.
    let count = 4200u32;
    let (raws, _) = synth_chain_from(cp.hash, cp.time, 1, count);
    let outcome = chain.submit_headers(1, &raws, NOW).unwrap();
    assert_eq!(outcome.last_block_height, count);
    assert_eq!(chain.tip_height(), count);

    // Nothing is pruned.
    assert_eq!(chain.base_height, 0, "base pinned at the checkpoint");
    assert_eq!(chain.headers.len(), count as usize);

    // The checkpoint header is not stored, but its hash is.
    assert!(chain.header_at(0).is_none(), "checkpoint header not stored");
    assert_eq!(chain.hash_at(0), Some(chain.base_hash));
    assert!(chain.header_at(1).is_some(), "oldest header retained");

    // An anchor at approx tip - 3200 is still present.
    let deep = 1000u32;
    assert!(
        (count - deep) > 2122,
        "precondition: deep anchor is below the old window"
    );
    assert!(
        chain.header_at(deep).is_some(),
        "deep-history header must be retained"
    );

    assert!(chain.header_at(count).is_some(), "tip is retained");
    assert_eq!(chain.header_at(count), chain.headers.last());

    // The chain still extends on top of the full history.
    let tip_hash = chain.tip_hash();
    let (more, _) = synth_chain_from(tip_hash, chain.tip_time(), 9, 10);
    let outcome = chain.submit_headers(count + 1, &more, NOW).unwrap();
    assert_eq!(outcome.headers_accepted, 10);
    assert_eq!(chain.tip_height(), count + 10);
}

/// Epoch-start lookup on retained history. A high boundary uses a stored
/// header. The first boundary above the checkpoint uses the checkpoint metadata.
#[test]
fn epoch_start_resolves_from_retained_history() {
    let cp = Checkpoint {
        height: 0,
        hash: [0xCC; 32],
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
        chain_work: None,
    };
    let mut chain = HeaderChain::new(Network::Regtest, cp);
    let (raws, _) = synth_chain_from(cp.hash, cp.time, 1, 4200);
    chain.submit_headers(1, &raws, NOW).unwrap();
    assert_eq!(chain.base_height, 0);

    // synth_chain_from gives the header at height h the time cp.time + h.
    let boundary = 2 * RETARGET_INTERVAL; // 4032
    let epoch_start_height = boundary - RETARGET_INTERVAL; // 2016
    let expected = chain.header_at(epoch_start_height).unwrap().time;
    assert_eq!(expected, cp.time + epoch_start_height);
    let got = chain
        .bits_input(boundary, 0, (0, 0), boundary, &[])
        .expect("epoch start from retained history must resolve");
    assert_eq!(got.epoch_first_time, expected);

    // The first boundary uses the checkpoint time.
    let first_boundary = RETARGET_INTERVAL; // 2016
    let got_base = chain
        .bits_input(first_boundary, 0, (0, 0), first_boundary, &[])
        .expect("epoch start at the checkpoint base must resolve");
    assert_eq!(got_base.epoch_first_time, cp.time);
}

/// A reorg near the tip with full retention. The truncate index comes from
/// the base, which stays at the checkpoint.
#[test]
fn reorg_near_tip_with_full_retention() {
    let cp = Checkpoint {
        height: 0,
        hash: [0xCC; 32],
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
        chain_work: None,
    };
    let mut chain = HeaderChain::new(Network::Regtest, cp);
    let (raws, _) = synth_chain_from(cp.hash, cp.time, 1, 4200);
    chain.submit_headers(1, &raws, NOW).unwrap();
    assert_eq!(chain.base_height, 0);

    // Reorg the last 5 blocks with a longer alt chain.
    let start = 4196;
    let pred_hash = chain.hash_at(start - 1).unwrap();
    let pred_time = chain.header_at(start - 1).unwrap().time;
    let (alt, _) = synth_chain_from(pred_hash, pred_time, 55, 10);
    let outcome = chain.submit_headers(start, &alt, NOW).unwrap();
    assert_eq!(outcome.reorg_depth, 5);
    assert_eq!(chain.tip_height(), start - 1 + 10);
    assert_eq!(
        chain.base_height, 0,
        "base pinned to the checkpoint; retention is full"
    );
}

/// `MAX_STORED_HEADERS` fails closed: a batch past the cap is rejected and the
/// chain is not pruned.
#[test]
fn rejects_extension_past_retention_cap() {
    let cp = Checkpoint {
        height: 0,
        hash: [0xCC; 32],
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
        chain_work: None,
    };
    let mut chain = HeaderChain::new(Network::Regtest, cp);
    let cap = 50usize;
    chain.set_max_stored_headers_for_test(cap);

    // Exactly at the cap is accepted.
    let (raws, tip_hash) = synth_chain_from(cp.hash, cp.time, 1, cap as u32);
    chain.submit_headers(1, &raws, NOW).unwrap();
    assert_eq!(chain.len(), cap);

    // One more header: 51 > 50.
    let (more, _) = synth_chain_from(tip_hash, chain.tip_time(), 9, 1);
    let err = chain
        .submit_headers(cap as u32 + 1, &more, NOW)
        .unwrap_err();
    assert!(matches!(
        err,
        SpvError::ChainTooLong { len, max } if len == cap + 1 && max == cap
    ));

    // Nothing was pruned.
    assert_eq!(chain.len(), cap);
    assert_eq!(chain.tip_height(), cap as u32);
    assert!(
        chain.header_at(1).is_some(),
        "oldest header must not be dropped"
    );
}

/// A batch over `MAX_HEADERS_PER_SUBMIT` is rejected before parsing.
#[test]
fn rejects_batch_over_per_call_cap() {
    let (mut chain, _) = synthetic_regtest_setup();
    let oversized = vec![vec![0u8; 80]; MAX_HEADERS_PER_SUBMIT + 1];
    let err = chain.submit_headers(101, &oversized, NOW).unwrap_err();
    assert!(matches!(
        err,
        SpvError::BatchTooLarge { len, max }
            if len == MAX_HEADERS_PER_SUBMIT + 1 && max == MAX_HEADERS_PER_SUBMIT
    ));
    assert_eq!(chain.len(), 0, "rejected batch leaves the chain unchanged");
}

/// An empty batch is a no-op success and must not panic in the reorg path.
#[test]
fn empty_batch_is_noop() {
    let (mut chain, raws) = synthetic_regtest_setup();
    chain.submit_headers(101, &raws, NOW).unwrap();
    let tip = chain.tip_height();
    let len = chain.len();
    // Extension height and reorg height.
    let outcome = chain.submit_headers(tip + 1, &[], NOW).unwrap();
    assert_eq!(outcome.headers_accepted, 0);
    assert_eq!(outcome.reorg_depth, 0);
    let outcome = chain.submit_headers(tip, &[], NOW).unwrap();
    assert_eq!(outcome.headers_accepted, 0);
    assert_eq!(chain.tip_height(), tip);
    assert_eq!(chain.len(), len);
}

#[test]
fn reorg_uses_correct_predecessor_not_tip() {
    // A reorg from 103 (depth 3) must link to 102, not to the tip at 105.
    let (mut chain, original) = synthetic_regtest_setup();
    chain.submit_headers(101, &original, NOW).unwrap();

    let pred_hash = chain.hash_at(102).unwrap();
    let (alt, _) = synth_chain_from(pred_hash, 1_700_000_003, 77, 5); // 5 > 3

    let outcome = chain.submit_headers(103, &alt, NOW).unwrap();
    assert_eq!(outcome.reorg_depth, 3); // displaced 103, 104, 105
    assert_eq!(outcome.last_block_height, 107);
    // Original heights 101 and 102 stay.
    assert!(chain.header_at(101).is_some());
    assert!(chain.header_at(102).is_some());
}

// ===== testnet4: the 20-minute rule on real headers =====

/// Real testnet4 headers 155_233..=155_262 (mempool.emzy.de/testnet4), on
/// top of the compiled checkpoint 155_232. Work blocks are at 155_238,
/// 155_244, 155_248 and 155_256. All others are min-difficulty blocks.
fn testnet4_headers() -> Vec<Vec<u8>> {
    include_str!("testnet4_155233_155262.hex")
        .lines()
        .map(|line| hex::decode(line).unwrap())
        .collect()
}

fn testnet4_chain() -> HeaderChain {
    let mut chain = HeaderChain::new(
        Network::Testnet4,
        crate::networks::rgb::spv::checkpoint::TESTNET4_CHECKPOINT,
    );
    chain
        .submit_headers(155_233, &testnet4_headers(), NOW)
        .unwrap();
    chain
}

#[test]
fn testnet4_accepts_real_headers_with_min_difficulty_blocks() {
    let chain = testnet4_chain();
    assert_eq!(chain.tip_height(), 155_262);
    let min_difficulty = (155_233..=155_262)
        .filter(|h| chain.header_at(*h).unwrap().bits.to_consensus() == 0x1d00ffff)
        .count();
    assert_eq!(min_difficulty, 26);
}

#[test]
fn testnet4_refuses_a_work_block_with_the_minimum_difficulty() {
    let mut raws = testnet4_headers();
    // 155_238 is earlier than its parent, so it must carry the period bits.
    let mut header: Header = bitcoin::consensus::deserialize(&raws[5]).unwrap();
    header.bits = bitcoin::CompactTarget::from_consensus(0x1d00ffff);
    raws[5] = serialize(&header);
    let mut chain = HeaderChain::new(
        Network::Testnet4,
        crate::networks::rgb::spv::checkpoint::TESTNET4_CHECKPOINT,
    );
    let err = chain.submit_headers(155_233, &raws, NOW).unwrap_err();
    assert!(
        matches!(
            err,
            SpvError::BitsMismatch {
                height: 155_238,
                got: 0x1d00ffff,
                expected: 0x1903_7e43
            }
        ),
        "{err}"
    );
}

/// Min-difficulty blocks count like any other block on the testnets.
#[test]
fn min_difficulty_blocks_confirm_on_testnets() {
    let chain = testnet4_chain();
    assert_eq!(chain.confirmations(155_233, 64), 30);
    assert_eq!(chain.confirmations(155_257, 6), 6);
    assert_eq!(chain.confirmations(155_262, 6), 1);
    assert_eq!(chain.confirmations(155_263, 6), 0);
}

#[test]
fn confirmations_stop_at_the_cap() {
    let chain = testnet4_chain();
    assert_eq!(chain.confirmations(155_233, 2), 2);
}

#[test]
fn every_block_confirms_where_min_difficulty_is_not_allowed() {
    let (mut chain, raws) = synthetic_regtest_setup();
    chain.submit_headers(101, &raws, NOW).unwrap();
    assert_eq!(chain.confirmations(101, 6), 5);
}

/// A free block dated weeks ahead would let a host fork retarget down without
/// real time passing. A header more than 2 h ahead of the clock is refused,
/// and the batch with it.
#[test]
fn refuses_a_header_more_than_two_hours_ahead_of_the_clock() {
    let lagging_clock = NOW - MAX_FUTURE_BLOCK_TIME_SECS - 1;
    let mut chain = HeaderChain::new(
        Network::Testnet4,
        crate::networks::rgb::spv::checkpoint::TESTNET4_CHECKPOINT,
    );
    let err = chain
        .submit_headers(155_233, &testnet4_headers(), lagging_clock)
        .unwrap_err();
    assert!(
        matches!(
            err,
            SpvError::TimeTooNew {
                height: 155_262,
                time: 1_791_217_894,
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(chain.tip_height(), 155_232, "the batch is atomic");
}

#[test]
fn accepts_a_header_exactly_two_hours_ahead_of_the_clock() {
    let mut chain = HeaderChain::new(
        Network::Testnet4,
        crate::networks::rgb::spv::checkpoint::TESTNET4_CHECKPOINT,
    );
    chain
        .submit_headers(
            155_233,
            &testnet4_headers(),
            NOW - MAX_FUTURE_BLOCK_TIME_SECS,
        )
        .unwrap();
    assert_eq!(chain.tip_height(), 155_262);
}

/// Signet and regtest check no work, but the clock bound still holds.
#[test]
fn the_clock_bound_holds_on_every_network() {
    let (mut chain, raws) = synthetic_regtest_setup();
    let first_time = 1_700_000_001;
    let lagging_clock = first_time - MAX_FUTURE_BLOCK_TIME_SECS - 1;
    let err = chain.submit_headers(101, &raws, lagging_clock).unwrap_err();
    assert!(
        matches!(err, SpvError::TimeTooNew { height: 101, .. }),
        "{err}"
    );
}

// ===== Core's time-too-old rule: the median time past =====

/// One regtest header on `prev` with the given `time`. Returns the raw header
/// and its hash.
fn header_with_time(prev: [u8; 32], time: u32, nonce: u32) -> (Vec<u8>, [u8; 32]) {
    let header = Header {
        version: bitcoin::block::Version::ONE,
        prev_blockhash: bitcoin::BlockHash::from_byte_array(prev),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time,
        bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
        nonce,
    };
    (serialize(&header), header.block_hash().to_byte_array())
}

/// Twenty regtest headers, then one dated at or before the median time past
/// of the eleven below it: refused, and the batch with it. One second above
/// the median passes.
#[test]
fn refuses_a_header_at_or_before_the_median_time_past() {
    let (mut chain, _) = synthetic_regtest_setup();
    let cp = *chain.checkpoint();
    // Heights 101..=120, the header at height h dated cp.time + (h - 100).
    let (raws, tip_hash) = synth_chain_from(cp.hash, cp.time, 1, 20);
    chain.submit_headers(101, &raws, NOW).unwrap();
    // Below 121 the window is 110..=120: times +10..=+20, median +15.
    let median = cp.time + 15;

    for too_old in [median, median - 5, cp.time] {
        let (raw, _) = header_with_time(tip_hash, too_old, 7);
        let err = chain.submit_headers(121, &[raw], NOW).unwrap_err();
        assert!(
            matches!(
                err,
                SpvError::TimeTooOld {
                    height: 121,
                    time,
                    median_time_past
                } if time == too_old && median_time_past == median
            ),
            "{err}"
        );
    }
    assert_eq!(chain.tip_height(), 120, "the batch is atomic");

    let (raw, _) = header_with_time(tip_hash, median + 1, 7);
    chain.submit_headers(121, &[raw], NOW).unwrap();
    assert_eq!(chain.tip_height(), 121);
}

/// Above a checkpoint that is not genesis, the rule starts at the eleventh
/// block above it, where the checkpoint is the lowest of the eleven. Below
/// that the window would need times the chain does not hold, and a median of
/// fewer blocks could be stricter than Core's. So those headers may carry any
/// time the clock bound allows.
#[test]
fn the_median_rule_starts_eleven_blocks_above_the_checkpoint() {
    // Ten headers above the checkpoint at 100. Height 111 has eleven blocks
    // below it, the checkpoint among them: window 100..=110, median +5.
    let (mut chain, _) = synthetic_regtest_setup();
    let cp = *chain.checkpoint();
    let (raws, tip_hash) = synth_chain_from(cp.hash, cp.time, 1, 10);
    chain.submit_headers(101, &raws, NOW).unwrap();
    let (old, _) = header_with_time(tip_hash, 1, 7);
    let err = chain.submit_headers(111, &[old], NOW).unwrap_err();
    assert!(
        matches!(
            err,
            SpvError::TimeTooOld {
                height: 111,
                time: 1,
                median_time_past
            } if median_time_past == cp.time + 5
        ),
        "{err}"
    );

    // Nine headers: height 110 would need the block below the checkpoint.
    let (mut chain, _) = synthetic_regtest_setup();
    let (raws, tip_hash) = synth_chain_from(cp.hash, cp.time, 1, 9);
    chain.submit_headers(101, &raws, NOW).unwrap();
    let (old, _) = header_with_time(tip_hash, 1, 7);
    chain.submit_headers(110, &[old], NOW).unwrap();
    assert_eq!(chain.tip_height(), 110);
}

/// A reorg batch is judged on the chain as it will be: the staged headers
/// first, then the kept ones below the batch.
#[test]
fn a_reorg_takes_the_median_from_the_new_chain() {
    let (mut chain, _) = synthetic_regtest_setup();
    let cp = *chain.checkpoint();
    let (raws, _) = synth_chain_from(cp.hash, cp.time, 1, 20);
    chain.submit_headers(101, &raws, NOW).unwrap();
    let pred = chain.hash_at(114).unwrap();

    // A fork from 115 (depth 6) of seven blocks, dated +10..=+15 and then
    // `last`. Each of the first six is above the median of its own window.
    // Below the last one the window is the kept 110..=114 (+10..=+14) and
    // the staged 115..=120 (+10..=+15): median +12. The displaced chain's
    // window 110..=120 had median +15.
    let fork = |last: u32| -> Vec<Vec<u8>> {
        let mut prev = pred;
        let mut raws = Vec::new();
        for (i, offset) in (10..=15).chain(std::iter::once(last)).enumerate() {
            let (raw, hash) = header_with_time(prev, cp.time + offset, 500 + i as u32);
            raws.push(raw);
            prev = hash;
        }
        raws
    };

    // At the new median: refused, and the error names that median.
    let err = chain.submit_headers(115, &fork(12), NOW).unwrap_err();
    assert!(
        matches!(
            err,
            SpvError::TimeTooOld {
                height: 121,
                median_time_past,
                ..
            } if median_time_past == cp.time + 12
        ),
        "{err}"
    );
    assert_eq!(chain.tip_height(), 120, "the batch is atomic");

    // Above the new median, though below the displaced chain's: accepted.
    let outcome = chain.submit_headers(115, &fork(13), NOW).unwrap();
    assert_eq!(outcome.reorg_depth, 6);
    assert_eq!(chain.tip_height(), 121);
}

/// A chain from genesis takes the median of the blocks it has, as Core does.
/// The first block must be newer than genesis. The fifth must be newer than
/// the median of the five below it.
#[test]
fn a_chain_from_genesis_takes_the_median_of_the_blocks_it_has() {
    let cp = Checkpoint {
        height: 0,
        hash: [0xCC; 32],
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
        chain_work: None,
    };
    let mut chain = HeaderChain::new(Network::Regtest, cp);

    // Block 1 at the genesis time: refused.
    let (raw, _) = header_with_time(cp.hash, cp.time, 1);
    let err = chain.submit_headers(1, &[raw], NOW).unwrap_err();
    assert!(
        matches!(
            err,
            SpvError::TimeTooOld {
                height: 1,
                median_time_past,
                ..
            } if median_time_past == cp.time
        ),
        "{err}"
    );

    // Blocks 1..=4 dated +1..=+4. Below 5 the window is 0..=4: median +2.
    let (raws, tip_hash) = synth_chain_from(cp.hash, cp.time, 1, 4);
    chain.submit_headers(1, &raws, NOW).unwrap();
    let (raw, _) = header_with_time(tip_hash, cp.time + 2, 7);
    let err = chain.submit_headers(5, &[raw], NOW).unwrap_err();
    assert!(
        matches!(
            err,
            SpvError::TimeTooOld {
                height: 5,
                median_time_past,
                ..
            } if median_time_past == cp.time + 2
        ),
        "{err}"
    );
    let (raw, _) = header_with_time(tip_hash, cp.time + 3, 7);
    chain.submit_headers(5, &[raw], NOW).unwrap();
    assert_eq!(chain.tip_height(), 5);
}

// ===== real headers above the compiled checkpoints =====

fn fixture_headers(hex_lines: &str) -> Vec<Vec<u8>> {
    hex_lines
        .lines()
        .map(|line| hex::decode(line).unwrap())
        .collect()
}

/// Real mainnet headers 951_553..=951_564 (blockstream.info) on the compiled
/// checkpoint 951_552. They pass linkage, PoW, nBits and the median rule.
/// Only 951_563 has the checkpoint in its window.
#[test]
fn real_mainnet_headers_above_the_checkpoint_pass() {
    let mut chain = HeaderChain::new(
        Network::Mainnet,
        crate::networks::rgb::spv::checkpoint::MAINNET_CHECKPOINT,
    );
    let outcome = chain
        .submit_headers(
            951_553,
            &fixture_headers(include_str!("mainnet_951553_951564.hex")),
            NOW,
        )
        .unwrap();
    assert_eq!(outcome.headers_accepted, 12);
    assert_eq!(chain.tip_height(), 951_564);
}

/// Real UTEXO signet headers 334_001..=334_012 (esplora-api.utexo.com) on the
/// compiled checkpoint 334_000. Signet checks no proof of work. So this test
/// pins the checkpoint hash to the real chain, through the link of 334_001. It
/// runs the median rule at 334_011 and 334_012. Only the window of 334_011
/// holds the checkpoint, and it passes with any checkpoint time, so the test
/// does not pin that time.
#[test]
fn real_signet_headers_above_the_checkpoint_pass() {
    let mut chain = HeaderChain::new(
        Network::Signet,
        crate::networks::rgb::spv::checkpoint::SIGNET_CHECKPOINT,
    );
    let outcome = chain
        .submit_headers(
            334_001,
            &fixture_headers(include_str!("signet_334001_334012.hex")),
            NOW,
        )
        .unwrap();
    assert_eq!(outcome.headers_accepted, 12);
    assert_eq!(chain.tip_height(), 334_012);
}

/// The real mainnet header 951_552 (blockstream.info) is the compiled
/// checkpoint: the same hash, time and bits.
#[test]
fn the_mainnet_checkpoint_is_the_real_block() {
    use crate::networks::rgb::spv::checkpoint::MAINNET_CHECKPOINT;

    let raw = &fixture_headers(include_str!("mainnet_951552.hex"))[0];
    let header: Header = bitcoin::consensus::deserialize(raw).unwrap();
    assert_eq!(MAINNET_CHECKPOINT.height, 951_552);
    assert_eq!(header.block_hash().to_byte_array(), MAINNET_CHECKPOINT.hash);
    assert_eq!(header.time, MAINNET_CHECKPOINT.time);
    assert_eq!(header.bits.to_consensus(), MAINNET_CHECKPOINT.bits);
}

/// A checkpoint moved forward with `SPV_CHECKPOINT` gives the time of its own
/// block. Block times can go down: here the moved block is an hour older than
/// the compiled checkpoint. With its real time, an honest header at the
/// eleventh block above it passes. With the compiled time, the median of its
/// window rises and refuses that header.
#[test]
fn a_moved_checkpoint_uses_the_real_time_of_its_block() {
    use crate::networks::rgb::spv::checkpoint::{parse_checkpoint_spec, SIGNET_CHECKPOINT};

    let base = SIGNET_CHECKPOINT.time;
    let height = SIGNET_CHECKPOINT.height + 100;
    let spec = format!(
        "{height}:{}:0x{:08x}:{}",
        hex::encode([0x5a_u8; 32]),
        SIGNET_CHECKPOINT.bits,
        base - 3_600
    );
    let moved = parse_checkpoint_spec(&spec).unwrap();
    // Ten blocks above the moved checkpoint, which the rule does not check:
    // five dated 2 000 s and five 500 s before the compiled time. `submit`
    // adds the eleventh block at the time `last`.
    let times: Vec<u32> = [base - 2_000; 5]
        .into_iter()
        .chain([base - 500; 5])
        .collect();
    let submit = |cp: Checkpoint, last: u32| {
        let mut chain = HeaderChain::new(Network::Signet, cp);
        let mut prev = cp.hash;
        let mut raws = Vec::new();
        for (i, &time) in times.iter().enumerate() {
            let (raw, hash) = header_with_time(prev, time, i as u32);
            raws.push(raw);
            prev = hash;
        }
        raws.push(header_with_time(prev, last, 99).0);
        chain.submit_headers(height + 1, &raws, NOW)
    };
    // The median time past that refused the eleventh block.
    let refusing_median = |result: Result<_>| match result {
        Err(SpvError::TimeTooOld {
            height: refused,
            median_time_past,
            ..
        }) if refused == height + 11 => median_time_past,
        other => panic!("expected TimeTooOld at the eleventh block, got {other:?}"),
    };

    // The window of the eleventh block is the checkpoint and the ten. With
    // the real time, its median is 2 000 s before the compiled time.
    submit(moved, base - 1_000).unwrap();
    assert_eq!(refusing_median(submit(moved, base - 2_000)), base - 2_000);
    // With the compiled time, the median is 500 s before it, and the chain
    // refuses the header.
    let compiled_time = Checkpoint {
        time: base,
        ..moved
    };
    assert_eq!(
        refusing_median(submit(compiled_time, base - 1_000)),
        base - 500
    );
}
