use super::*;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;

/// Synthetic mainnet-shaped chain: our own checkpoint + headers, each with
/// valid PoW under regtest rules. Avoids fixtures with real-difficulty PoW.
fn synthetic_regtest_setup() -> (HeaderChain, Vec<Vec<u8>>) {
    // Regtest is chain-linkage-only in our validator, so a synthetic chain
    // needs no mining.
    let mut prev_hash = [0u8; 32];
    prev_hash[0] = 0xAA; // arbitrary checkpoint hash

    let checkpoint = Checkpoint {
        height: 100,
        hash: prev_hash,
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
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
    let outcome = chain.submit_headers(101, &raws).unwrap();
    assert_eq!(outcome.headers_accepted, 5);
    assert_eq!(outcome.last_block_height, 105);
    assert_eq!(outcome.reorg_depth, 0);
    assert_eq!(chain.tip_height(), 105);
    assert_eq!(chain.len(), 5);
}

#[test]
fn rejects_non_contiguous_batch() {
    let (mut chain, raws) = synthetic_regtest_setup();
    // tip is at 100 (checkpoint), start_height 102 leaves a gap.
    let err = chain.submit_headers(102, &raws).unwrap_err();
    assert!(matches!(
        err,
        SpvError::NonContiguous { got: 102, tip: 100 }
    ));
}

#[test]
fn rejects_at_or_below_checkpoint() {
    let (mut chain, raws) = synthetic_regtest_setup();
    // start_height = 100 == checkpoint.height: refuses to rewrite below the trust anchor.
    let err = chain.submit_headers(100, &raws).unwrap_err();
    assert!(matches!(
        err,
        SpvError::BelowCheckpoint {
            got: 100,
            checkpoint: 100,
        }
    ));
    // start_height < checkpoint.height: same.
    let err = chain.submit_headers(50, &raws).unwrap_err();
    assert!(matches!(err, SpvError::BelowCheckpoint { got: 50, .. }));
}

#[test]
fn rejects_broken_linkage() {
    let (mut chain, raws) = synthetic_regtest_setup();
    // Submit the first one to advance the tip.
    chain.submit_headers(101, &raws[..1]).unwrap();
    // Now submit the FIRST raw again at height 102 - its prev_blockhash
    // points to the checkpoint, not to height 101's hash.
    let err = chain.submit_headers(102, &raws[..1]).unwrap_err();
    assert!(matches!(err, SpvError::ChainLinkage { height: 102 }));
}

#[test]
fn header_lookup_by_height() {
    let (mut chain, raws) = synthetic_regtest_setup();
    chain.submit_headers(101, &raws).unwrap();

    // Checkpoint height: header() returns None, but hash() returns the
    // checkpoint hash.
    assert!(chain.header_at(100).is_none());
    assert_eq!(chain.hash_at(100).unwrap()[0], 0xAA);

    // Validated heights: both lookups work.
    assert!(chain.header_at(101).is_some());
    assert!(chain.header_at(105).is_some());
    // Out of range:
    assert!(chain.header_at(106).is_none());
    assert!(chain.header_at(99).is_none());
}

#[test]
fn rejects_garbage_header_bytes() {
    let (mut chain, _) = synthetic_regtest_setup();
    let err = chain
        .submit_headers(101, &[vec![0u8; 79]]) // 79 bytes != 80
        .unwrap_err();
    assert!(matches!(err, SpvError::HeaderParse { index: 0, .. }));
}

#[test]
fn batch_is_atomic_on_failure() {
    let (mut chain, mut raws) = synthetic_regtest_setup();
    // Corrupt the third raw header so it won't parse.
    raws[2] = vec![0u8; 79];

    let pre_tip = chain.tip_height();
    let pre_len = chain.len();
    let err = chain.submit_headers(101, &raws).unwrap_err();
    assert!(matches!(err, SpvError::HeaderParse { index: 2, .. }));

    // Chain MUST be unchanged: no partial accept.
    assert_eq!(chain.tip_height(), pre_tip);
    assert_eq!(chain.len(), pre_len);
}

/// Mainnet PoW + bits checks: feed the real block 1 into a chain whose
/// checkpoint claims to be the genesis. Bits at non-boundary blocks must
/// equal previous block's bits, and PoW must hold.
#[test]
fn mainnet_block_1_appends_after_genesis_checkpoint() {
    // Mainnet genesis facts (well-known):
    // height=0, hash (internal) below, bits=0x1d00ffff, time=1231006505
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
    };
    let mut chain = HeaderChain::new(Network::Mainnet, cp);

    let block_1_hex = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
    let raw = hex::decode(block_1_hex).unwrap();

    let outcome = chain.submit_headers(1, &[raw]).unwrap();
    assert_eq!(outcome.last_block_height, 1);
    assert_eq!(outcome.headers_accepted, 1);
    assert_eq!(outcome.reorg_depth, 0);
}

// ===== Bounded-reorg tests =====
//
// Regtest headers have constant nBits, so every header contributes the same
// Work and chain length is a clean proxy for "more work".

/// Build `count` synthetic regtest headers starting from `prev_hash` and
/// `prev_time`, varying `nonce_seed` so different forks produce different
/// hashes. Returns the raw 80-byte serialisations + the final tip hash.
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
            // Combine seed + index so each fork's nonce sequence is unique.
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
    // Original: 5 blocks, heights 101..=105.
    chain.submit_headers(101, &original).unwrap();
    let original_tip = chain.tip_hash();

    // Alternative starting at 101 with 6 blocks (different nonce_seed
    // so the hashes diverge from block 1 of the alt chain).
    let cp_hash = chain.checkpoint().hash;
    let (alt, _alt_tip) = synth_chain_from(cp_hash, 1_700_000_000, 7, 6);

    let outcome = chain.submit_headers(101, &alt).unwrap();
    assert_eq!(outcome.headers_accepted, 6);
    assert_eq!(outcome.reorg_depth, 5); // displaced 101..=105
    assert_eq!(outcome.last_block_height, 106);
    // Tip MUST have changed.
    assert_ne!(chain.tip_hash(), original_tip);
    assert_eq!(chain.tip_height(), 106);
    assert_eq!(chain.len(), 6);
}

#[test]
fn reorg_rejected_when_alt_chain_is_equal_length() {
    let (mut chain, original) = synthetic_regtest_setup();
    chain.submit_headers(101, &original).unwrap();
    let original_tip = chain.tip_hash();
    let original_height = chain.tip_height();

    // Same length (5), different content.
    let cp_hash = chain.checkpoint().hash;
    let (alt, _) = synth_chain_from(cp_hash, 1_700_000_000, 99, 5);

    let err = chain.submit_headers(101, &alt).unwrap_err();
    assert!(matches!(err, SpvError::WeakerChain));
    // Chain unchanged.
    assert_eq!(chain.tip_hash(), original_tip);
    assert_eq!(chain.tip_height(), original_height);
}

#[test]
fn reorg_rejected_when_alt_chain_is_shorter() {
    let (mut chain, original) = synthetic_regtest_setup();
    chain.submit_headers(101, &original).unwrap();
    let original_tip = chain.tip_hash();

    // Reorg at 102 with only 3 alt blocks (vs original 4 from 102..=105).
    let pred_hash = chain.hash_at(101).unwrap();
    let (alt, _) = synth_chain_from(pred_hash, 1_700_000_002, 11, 3);

    let err = chain.submit_headers(102, &alt).unwrap_err();
    assert!(matches!(err, SpvError::WeakerChain));
    assert_eq!(chain.tip_hash(), original_tip);
}

#[test]
fn reorg_too_deep_rejected() {
    let (mut chain, _) = synthetic_regtest_setup();
    // Build a long chain so a deep reorg is possible.
    let cp_hash = chain.checkpoint().hash;
    let (long, _) = synth_chain_from(cp_hash, 1_700_000_000, 1, MAX_REORG_DEPTH + 50);
    chain.submit_headers(101, &long).unwrap();
    let tip_before = chain.tip_height();

    // Try to reorg from way back. depth = tip - start + 1 > MAX_REORG_DEPTH.
    let too_deep_start = chain.checkpoint().height + 5;
    let pred_hash = chain.hash_at(too_deep_start - 1).unwrap();
    let (alt, _) = synth_chain_from(pred_hash, 1_700_000_005, 50, MAX_REORG_DEPTH + 100);

    let err = chain.submit_headers(too_deep_start, &alt).unwrap_err();
    assert!(matches!(err, SpvError::ReorgTooDeep { .. }));
    assert_eq!(chain.tip_height(), tip_before);
}

#[test]
fn reorg_at_max_depth_is_allowed() {
    let (mut chain, _) = synthetic_regtest_setup();
    let cp_hash = chain.checkpoint().hash;
    // Build a chain of exactly MAX_REORG_DEPTH headers, so we can reorg
    // from height (checkpoint + 1) - depth == MAX_REORG_DEPTH exactly.
    let (orig, _) = synth_chain_from(cp_hash, 1_700_000_000, 1, MAX_REORG_DEPTH);
    chain.submit_headers(101, &orig).unwrap();

    // Alt of MAX_REORG_DEPTH + 1 headers from the SAME predecessor (the
    // checkpoint) - strictly more work than the original.
    let (alt, _) = synth_chain_from(cp_hash, 1_700_000_000, 42, MAX_REORG_DEPTH + 1);
    let outcome = chain.submit_headers(101, &alt).unwrap();
    assert_eq!(outcome.reorg_depth, MAX_REORG_DEPTH);
    assert_eq!(outcome.headers_accepted, MAX_REORG_DEPTH + 1);
}

#[test]
fn reorg_atomic_on_validation_failure() {
    let (mut chain, original) = synthetic_regtest_setup();
    chain.submit_headers(101, &original).unwrap();
    let original_tip = chain.tip_hash();
    let original_height = chain.tip_height();

    // Build alt starting at 102 (depth 4), longer than what we replace,
    // then corrupt the middle header so the BATCH itself fails to parse.
    let pred_hash = chain.hash_at(101).unwrap();
    let (mut alt, _) = synth_chain_from(pred_hash, 1_700_000_002, 13, 6);
    alt[3] = vec![0u8; 79]; // shorter than the 80-byte header - parse error

    let err = chain.submit_headers(102, &alt).unwrap_err();
    assert!(matches!(err, SpvError::HeaderParse { index: 3, .. }));
    // Chain MUST be unchanged: no partial accept, no truncate.
    assert_eq!(chain.tip_hash(), original_tip);
    assert_eq!(chain.tip_height(), original_height);
    assert_eq!(chain.len(), 5);
}

#[test]
fn non_pow_network_skips_epoch_lookup_across_retarget_boundary() {
    // Regression: a non-PoW network whose checkpoint sits above the
    // retarget epoch start must not fail with HeaderNotFound. Checkpoint at
    // 4000, first retarget at 4032, whose epoch start (2016) is below it.
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
    };
    let mut chain = HeaderChain::new(Network::Regtest, checkpoint);

    // Build 100 headers from 4001 to 4100, crossing retarget at 4032.
    let (raws, _) = synth_chain_from(cp_hash, 1_700_000_000, 1, 100);
    let outcome = chain.submit_headers(4001, &raws).unwrap();
    assert_eq!(outcome.headers_accepted, 100);
    assert_eq!(outcome.last_block_height, 4100);
}

// ===== retarget-boundary epoch-start resolution =====
//
// A retarget boundary at height B needs the block at `B -
// RETARGET_INTERVAL`. With a misaligned checkpoint, the first boundary
// above it references an epoch start below the checkpoint, which is never
// stored, and the chain wedges. Tested through the lookup directly; the
// difficulty math itself is covered in validation.rs.

/// With a boundary-aligned checkpoint, the first
/// retarget boundary above it resolves its epoch start to the checkpoint
/// instead of wedging.
#[test]
fn th1_epoch_start_resolves_at_first_boundary_above_aligned_checkpoint() {
    let cp = Checkpoint {
        height: 951_552, // == 472 * RETARGET_INTERVAL (the real mainnet checkpoint)
        hash: [0x11; 32],
        bits: 0x1702_068f,
        time: 1_780_050_586,
        is_real: true,
    };
    assert_eq!(cp.height % RETARGET_INTERVAL, 0, "precondition: aligned");
    let chain = HeaderChain::new(Network::Mainnet, cp);

    let first_boundary = cp.height + RETARGET_INTERVAL; // 953_568
                                                        // epoch start = first_boundary - RETARGET_INTERVAL = cp.height (the base).
    let epoch_start = chain
        .epoch_start_time(first_boundary, first_boundary, &[])
        .expect("aligned checkpoint must resolve the first boundary's epoch start");
    assert_eq!(epoch_start, cp.time);
}

/// TH-2: a misaligned checkpoint (950 000) wedges - the first boundary
/// above it (951 552) references an epoch start (949 536) below it, which
/// is never stored. The load-time assertion now rejects such a checkpoint.
#[test]
fn th2_misaligned_checkpoint_wedges_at_first_boundary() {
    let cp = Checkpoint {
        height: 950_000, // 950_000 % 2016 == 464 -> NOT aligned
        hash: [0x22; 32],
        bits: 0x1702_0f79,
        time: 1_779_141_269,
        is_real: true,
    };
    assert_ne!(cp.height % RETARGET_INTERVAL, 0, "precondition: misaligned");
    let chain = HeaderChain::new(Network::Mainnet, cp);

    // First retarget boundary above 950_000 is 951_552 (= 472 * 2016).
    let first_boundary = 951_552;
    let err = chain
        .epoch_start_time(first_boundary, first_boundary, &[])
        .unwrap_err();
    assert!(matches!(err, SpvError::HeaderNotFound(949_536)));
}

// ===== full retention from the checkpoint (no sliding window) =====

/// Core retention regression: the base stays pinned at the checkpoint and
/// `header_at` resolves anchors far below the old `HEADER_WINDOW` (~2122),
/// which used to be pruned.
#[test]
fn retains_full_history_from_checkpoint() {
    // Checkpoint at height 0 so boundaries fall on clean multiples of 2016.
    let cp = Checkpoint {
        height: 0,
        hash: [0xCC; 32],
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
    };
    let mut chain = HeaderChain::new(Network::Regtest, cp);

    // Build well past the former window (100 + 2016 + 6 = 2122) plus a
    // full epoch, so any leftover pruning logic would have fired.
    let count = 4200u32;
    let (raws, _) = synth_chain_from(cp.hash, cp.time, 1, count);
    let outcome = chain.submit_headers(1, &raws).unwrap();
    assert_eq!(outcome.last_block_height, count);
    assert_eq!(chain.tip_height(), count);

    // Base stays pinned at the checkpoint - nothing is pruned, so the whole
    // history is kept.
    assert_eq!(chain.base_height, 0, "base pinned at the checkpoint");
    assert_eq!(chain.headers.len(), count as usize);

    // The checkpoint header itself is not stored, but its hash is available
    // at its own height; every height above it resolves.
    assert!(chain.header_at(0).is_none(), "checkpoint header not stored");
    assert_eq!(chain.hash_at(0), Some(chain.base_hash));
    assert!(chain.header_at(1).is_some(), "oldest header retained");

    // A height far below `tip - 2122` is still present - exactly the case
    // that failed under the old sliding window (anchor at ~tip - 3200 here).
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

    // The chain still extends correctly on top of the full history.
    let tip_hash = chain.tip_hash();
    let (more, _) = synth_chain_from(tip_hash, chain.tip_time(), 9, 10);
    let outcome = chain.submit_headers(count + 1, &more).unwrap();
    assert_eq!(outcome.headers_accepted, 10);
    assert_eq!(chain.tip_height(), count + 10);
}

/// The retarget epoch-start lookup resolves off retained history. A high
/// boundary references a stored header; the first boundary above the
/// checkpoint references the base (checkpoint) metadata.
#[test]
fn epoch_start_resolves_from_retained_history() {
    let cp = Checkpoint {
        height: 0,
        hash: [0xCC; 32],
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
    };
    let mut chain = HeaderChain::new(Network::Regtest, cp);
    let (raws, _) = synth_chain_from(cp.hash, cp.time, 1, 4200);
    chain.submit_headers(1, &raws).unwrap();
    assert_eq!(chain.base_height, 0);

    // synth_chain_from sets the header at height h to time cp.time + h.
    // Boundary at 4032 references epoch start 2016 - a retained header.
    let boundary = 2 * RETARGET_INTERVAL; // 4032
    let epoch_start_height = boundary - RETARGET_INTERVAL; // 2016
    let expected = chain.header_at(epoch_start_height).unwrap().time;
    assert_eq!(expected, cp.time + epoch_start_height);
    let got = chain
        .epoch_start_time(boundary, boundary, &[])
        .expect("epoch start from retained history must resolve");
    assert_eq!(got, expected);

    // The first boundary above the checkpoint references the base itself,
    // whose timestamp is the checkpoint time.
    let first_boundary = RETARGET_INTERVAL; // 2016
    let got_base = chain
        .epoch_start_time(first_boundary, first_boundary, &[])
        .expect("epoch start at the checkpoint base must resolve");
    assert_eq!(got_base, cp.time);
}

/// A reorg near the tip validates with full retention - the truncate index
/// is computed off the base, which is pinned at the checkpoint.
#[test]
fn reorg_near_tip_with_full_retention() {
    let cp = Checkpoint {
        height: 0,
        hash: [0xCC; 32],
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
    };
    let mut chain = HeaderChain::new(Network::Regtest, cp);
    let (raws, _) = synth_chain_from(cp.hash, cp.time, 1, 4200);
    chain.submit_headers(1, &raws).unwrap();
    assert_eq!(chain.base_height, 0);

    // Reorg the last 5 blocks (depth 5) with a longer alt chain.
    let start = 4196;
    let pred_hash = chain.hash_at(start - 1).unwrap();
    let pred_time = chain.header_at(start - 1).unwrap().time;
    let (alt, _) = synth_chain_from(pred_hash, pred_time, 55, 10);
    let outcome = chain.submit_headers(start, &alt).unwrap();
    assert_eq!(outcome.reorg_depth, 5);
    assert_eq!(chain.tip_height(), start - 1 + 10);
    assert_eq!(
        chain.base_height, 0,
        "base pinned to the checkpoint; retention is full"
    );
}

/// The retention ceiling (`MAX_STORED_HEADERS`) is fail-closed: a batch
/// past the cap is rejected and the chain left unchanged, never pruned.
#[test]
fn rejects_extension_past_retention_cap() {
    let cp = Checkpoint {
        height: 0,
        hash: [0xCC; 32],
        bits: 0x207fffff,
        time: 1_700_000_000,
        is_real: false,
    };
    let mut chain = HeaderChain::new(Network::Regtest, cp);
    // Shrink the cap so we can hit it without building a million headers.
    let cap = 50usize;
    chain.set_max_stored_headers_for_test(cap);

    // Filling exactly to the cap is accepted (boundary: 50 == cap).
    let (raws, tip_hash) = synth_chain_from(cp.hash, cp.time, 1, cap as u32);
    chain.submit_headers(1, &raws).unwrap();
    assert_eq!(chain.len(), cap);

    // One more header would make 51 > 50 -> fail-closed rejection.
    let (more, _) = synth_chain_from(tip_hash, chain.tip_time(), 9, 1);
    let err = chain.submit_headers(cap as u32 + 1, &more).unwrap_err();
    assert!(matches!(
        err,
        SpvError::ChainTooLong { len, max } if len == cap + 1 && max == cap
    ));

    // Chain is unchanged - nothing was pruned to make room.
    assert_eq!(chain.len(), cap);
    assert_eq!(chain.tip_height(), cap as u32);
    assert!(
        chain.header_at(1).is_some(),
        "oldest header must not be dropped"
    );
}

/// Per-call cap: a batch larger than `MAX_HEADERS_PER_SUBMIT` is
/// rejected before any parsing, so the garbage vecs are never deserialised.
#[test]
fn rejects_batch_over_per_call_cap() {
    let (mut chain, _) = synthetic_regtest_setup();
    let oversized = vec![vec![0u8; 80]; MAX_HEADERS_PER_SUBMIT + 1];
    let err = chain.submit_headers(101, &oversized).unwrap_err();
    assert!(matches!(
        err,
        SpvError::BatchTooLarge { len, max }
            if len == MAX_HEADERS_PER_SUBMIT + 1 && max == MAX_HEADERS_PER_SUBMIT
    ));
    assert_eq!(chain.len(), 0, "rejected batch leaves the chain unchanged");
}

/// An empty batch is a no-op success: nothing to place, chain unchanged,
/// and it must not panic via the reorg path.
#[test]
fn empty_batch_is_noop() {
    let (mut chain, raws) = synthetic_regtest_setup();
    chain.submit_headers(101, &raws).unwrap();
    let tip = chain.tip_height();
    let len = chain.len();
    // Empty at an extension height and at a reorg height both no-op.
    let outcome = chain.submit_headers(tip + 1, &[]).unwrap();
    assert_eq!(outcome.headers_accepted, 0);
    assert_eq!(outcome.reorg_depth, 0);
    let outcome = chain.submit_headers(tip, &[]).unwrap();
    assert_eq!(outcome.headers_accepted, 0);
    assert_eq!(chain.tip_height(), tip);
    assert_eq!(chain.len(), len);
}

#[test]
fn reorg_uses_correct_predecessor_not_tip() {
    // A reorg from height 103 (depth 3) must validate against the
    // hash at 102, not the current tip at 105.
    let (mut chain, original) = synthetic_regtest_setup();
    chain.submit_headers(101, &original).unwrap();

    let pred_hash = chain.hash_at(102).unwrap();
    let (alt, _) = synth_chain_from(pred_hash, 1_700_000_003, 77, 5); // 5 > 3

    let outcome = chain.submit_headers(103, &alt).unwrap();
    assert_eq!(outcome.reorg_depth, 3); // displaced 103, 104, 105
    assert_eq!(outcome.last_block_height, 107);
    // Heights 101 and 102 from the ORIGINAL chain should still be there.
    assert!(chain.header_at(101).is_some());
    assert!(chain.header_at(102).is_some());
}
