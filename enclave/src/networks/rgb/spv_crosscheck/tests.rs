use super::*;
use crate::networks::rgb::spv::checkpoint::Checkpoint;
use crate::networks::rgb::spv::HeaderChain;
use crate::proto::MerkleProofEntry;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::serialize;
use bitcoin::hashes::{sha256d, Hash};

/// Builds a regtest synthetic chain rooted at a zero checkpoint. We use
/// regtest so PoW is skipped - these tests focus on the SPV crosscheck
/// logic, not header validation (2 covers that).
fn regtest_chain_with(headers: Vec<Header>) -> HeaderChain {
    let mut chain = HeaderChain::new(
        Network::Regtest,
        Checkpoint {
            height: 0,
            hash: [0u8; 32],
            bits: 0x207fffff,
            time: 1_700_000_000,
            is_real: false,
        },
    );
    let raw_headers: Vec<Vec<u8>> = headers.iter().map(serialize).collect();
    chain.submit_headers(1, &raw_headers).unwrap();
    chain
}

/// Build N synthetic regtest headers chaining from a zero prev_blockhash.
/// Each header has a deterministic, distinct merkle_root so we can test
/// proofs against a known root.
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

/// For a single-tx block, the Merkle root IS the txid (in internal
/// order). To make a working "happy path" proof we use this fact.
/// Returns (display-order txid, MerkleProofEntry).
fn single_tx_proof(header: &Header, block_height: u32) -> ([u8; 32], MerkleProofEntry) {
    // header.merkle_root is internal-order. The txid that produces it
    // (single-tx block, empty path) is the same bytes. Display-order
    // is the reverse.
    let internal: [u8; 32] = header.merkle_root.to_byte_array();
    let mut display = internal;
    display.reverse();
    let entry = MerkleProofEntry {
        txid: display.to_vec(),
        block_height,
        tx_position: 0,
        merkle_path: vec![],
    };
    (display, entry)
}

fn dsha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256d::Hash::hash(&buf).to_byte_array()
}

/// Bundle of test fixtures for a 2-tx block - used by both happy and
/// rejection paths. Factored into a struct to keep clippy happy with
/// the `type_complexity` lint (which would otherwise fire on a 5-tuple
/// return).
struct TwoTxBlock {
    header: Header,
    txid0_display: [u8; 32],
    txid1_display: [u8; 32],
    path_for_tx0: Vec<Vec<u8>>,
    path_for_tx1: Vec<Vec<u8>>,
}

/// Set up a 2-tx block: leaf0 + leaf1 -> root. Header points at root.
fn build_two_tx_block(
    leaf0_internal: [u8; 32],
    leaf1_internal: [u8; 32],
    prev_blockhash: bitcoin::BlockHash,
    time: u32,
) -> TwoTxBlock {
    let root_internal = dsha256_pair(&leaf0_internal, &leaf1_internal);
    let header = Header {
        version: Version::ONE,
        prev_blockhash,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(root_internal),
        time,
        bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
        nonce: 0,
    };
    let mut txid0_display = leaf0_internal;
    txid0_display.reverse();
    let mut txid1_display = leaf1_internal;
    txid1_display.reverse();
    let mut sib1_display = leaf1_internal;
    sib1_display.reverse();
    let mut sib0_display = leaf0_internal;
    sib0_display.reverse();
    TwoTxBlock {
        header,
        txid0_display,
        txid1_display,
        path_for_tx0: vec![sib1_display.to_vec()],
        path_for_tx1: vec![sib0_display.to_vec()],
    }
}

/// Helper: build a chain of `confirmations` headers where the header at
/// height 1 has the merkle commitment we care about; subsequent headers
/// are throwaway (they just bury the target block deep enough).
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

#[test]
fn happy_path_single_tx_block_with_six_confirmations() {
    // 1 target block + 5 burying = 6 confirmations.
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    let (txid_display, proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

    validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS).unwrap();
}

/// Regression: an anchor far below `tip - HEADER_WINDOW` (~2122)
/// still verifies. The old sliding window pruned the anchor's header, so
/// SPV rejected every RGB consignment whose oldest witness was older than
/// ~a day on 30s-block signet ("no header at height H (chain tip = T)").
/// With full retention from the checkpoint the header resolves and the
/// proof passes.
#[test]
fn deep_anchor_below_old_window_still_verifies() {
    let target = synth_headers(1).into_iter().next().unwrap();
    // Derive the proof from the target before it is moved into the chain.
    let (txid_display, proof) = single_tx_proof(&target, 1);
    // Bury the target deep enough that the OLD sliding window would have
    // pruned its header: prune_front advanced the base to
    // floor_2016(tip - 2122), dropping the anchor at height 1 once that
    // base >= 1 (tip >= 4138). 4200 buries it comfortably past that point,
    // so this test genuinely fails on the pruning code and guards against
    // its reintroduction.
    let chain = chain_burying(target, 4200);
    let tip = chain.tip_height();
    let old_window = 100 + 2016 + 6; // former HEADER_WINDOW
    let old_pruned_base = (tip.saturating_sub(old_window) / 2016) * 2016;
    assert!(
        old_pruned_base >= 1,
        "precondition: the old window would have pruned the anchor at height 1 \
         (tip={tip}, old_pruned_base={old_pruned_base})"
    );

    validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS).unwrap();
}

#[test]
fn rejects_insufficient_confirmations() {
    // Only 3 confirmations < 6.
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 2);
    let (txid_display, proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

    let err =
        validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS).unwrap_err();
    assert!(
        err.to_string().contains("insufficient confirmations"),
        "got: {err}"
    );
}

#[test]
fn rejects_block_height_beyond_tip() {
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    let (txid_display, mut proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);
    proof.block_height = chain.tip_height() + 100;

    let err =
        validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS).unwrap_err();
    // Either "no header at height" (because we don't store > tip) or
    // "beyond chain tip" (the explicit underflow catch). Both are
    // acceptable rejections.
    let msg = err.to_string();
    assert!(
        msg.contains("no header") || msg.contains("beyond"),
        "got: {msg}"
    );
}

#[test]
fn rejects_block_height_at_checkpoint_or_below() {
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    let (txid_display, mut proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);
    proof.block_height = 0; // checkpoint height - we don't store its header

    let err =
        validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS).unwrap_err();
    assert!(
        err.to_string().contains("no header at height"),
        "got: {err}"
    );
}

#[test]
fn rejects_extra_proof_for_unknown_txid() {
    // We expect ONE txid, listener supplies that one PLUS a second
    // unrelated proof. That extra proof must cause rejection - the
    // contract is set equality.
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    let (txid_display, proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

    let bogus_txid = [0xCC; 32];
    let bogus_proof = MerkleProofEntry {
        txid: bogus_txid.to_vec(),
        block_height: 1,
        tx_position: 0,
        merkle_path: vec![],
    };

    let err = validate_spv_proofs(
        &chain,
        &[txid_display],
        &[proof, bogus_proof],
        SPV_MIN_CONFIRMATIONS,
    )
    .unwrap_err();
    assert!(err.to_string().contains("does not match any"), "got: {err}");
}

#[test]
fn rejects_missing_proof_for_expected_txid() {
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    let (txid_display, _proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

    // Expected has TWO txids; listener provides ZERO proofs.
    let extra_txid = [0xEE; 32];
    let err = validate_spv_proofs(
        &chain,
        &[txid_display, extra_txid],
        &[],
        SPV_MIN_CONFIRMATIONS,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("missing merkle proofs"),
        "got: {err}"
    );
}

#[test]
fn rejects_duplicate_proof() {
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    let (txid_display, proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

    let err = validate_spv_proofs(
        &chain,
        &[txid_display],
        &[proof.clone(), proof],
        SPV_MIN_CONFIRMATIONS,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("duplicate merkle proof"),
        "got: {err}"
    );
}

#[test]
fn rejects_bad_merkle_path() {
    // Build a 2-tx block, supply the right proof shape but with a
    // wrong sibling - root reconstruction should mismatch.
    let leaf0 = [0x10u8; 32];
    let leaf1 = [0x20u8; 32];
    let prev = bitcoin::BlockHash::from_byte_array([0u8; 32]);
    let block = build_two_tx_block(leaf0, leaf1, prev, 1_700_000_001);

    let chain = chain_burying(block.header, 5);

    // Supply a path with the WRONG sibling (all zeros instead of leaf1).
    let proof = MerkleProofEntry {
        txid: block.txid0_display.to_vec(),
        block_height: 1,
        tx_position: 0,
        merkle_path: vec![vec![0u8; 32]],
    };

    let err = validate_spv_proofs(
        &chain,
        &[block.txid0_display],
        &[proof],
        SPV_MIN_CONFIRMATIONS,
    )
    .unwrap_err();
    assert!(err.to_string().contains("computed root"), "got: {err}");
}

#[test]
fn happy_path_two_tx_block() {
    let leaf0 = [0x10u8; 32];
    let leaf1 = [0x20u8; 32];
    let prev = bitcoin::BlockHash::from_byte_array([0u8; 32]);
    let block = build_two_tx_block(leaf0, leaf1, prev, 1_700_000_001);

    let chain = chain_burying(block.header, 5);

    let proof0 = MerkleProofEntry {
        txid: block.txid0_display.to_vec(),
        block_height: 1,
        tx_position: 0,
        merkle_path: block.path_for_tx0,
    };
    let proof1 = MerkleProofEntry {
        txid: block.txid1_display.to_vec(),
        block_height: 1,
        tx_position: 1,
        merkle_path: block.path_for_tx1,
    };

    validate_spv_proofs(
        &chain,
        &[block.txid0_display, block.txid1_display],
        &[proof0, proof1],
        SPV_MIN_CONFIRMATIONS,
    )
    .unwrap();
}

#[test]
fn rejects_short_txid_in_proof() {
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    let bad_proof = MerkleProofEntry {
        txid: vec![0u8; 16], // not 32 bytes
        block_height: 1,
        tx_position: 0,
        merkle_path: vec![],
    };

    let err =
        validate_spv_proofs(&chain, &[[0u8; 32]], &[bad_proof], SPV_MIN_CONFIRMATIONS).unwrap_err();
    assert!(err.to_string().contains("must be 32 bytes"), "got: {err}");
}

#[test]
fn rejects_short_merkle_path_entry() {
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    let (txid_display, _proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

    let bad_proof = MerkleProofEntry {
        txid: txid_display.to_vec(),
        block_height: 1,
        tx_position: 0,
        merkle_path: vec![vec![0u8; 16]], // not 32 bytes
    };

    let err = validate_spv_proofs(&chain, &[txid_display], &[bad_proof], SPV_MIN_CONFIRMATIONS)
        .unwrap_err();
    assert!(err.to_string().contains("must be 32 bytes"), "got: {err}");
}

#[test]
fn rejects_overdeep_merkle_path() {
    // A path deeper than any real block could produce is rejected before
    // any Merkle hashing runs. Siblings are well-formed
    // 32-byte hashes so the only failing predicate is the depth cap.
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    let (txid_display, _proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

    let bad_proof = MerkleProofEntry {
        txid: txid_display.to_vec(),
        block_height: 1,
        tx_position: 0,
        merkle_path: vec![vec![0u8; 32]; MAX_MERKLE_PATH_DEPTH + 1],
    };

    let err = validate_spv_proofs(&chain, &[txid_display], &[bad_proof], SPV_MIN_CONFIRMATIONS)
        .unwrap_err();
    assert!(err.to_string().contains("too deep"), "got: {err}");
}

#[test]
fn assert_chain_net_accepts_matching_pair() {
    // Literal prefixes on purpose (not derived from `ChainNet::prefix()`):
    // if an rgb-core upgrade ever changes the notation, this test must
    // fail loudly instead of the contract silently shifting.
    assert_chain_net("bc", Network::Mainnet).unwrap();
    assert_chain_net("sb", Network::Signet).unwrap();
    assert_chain_net("tb3", Network::Testnet3).unwrap();
    assert_chain_net("bcrt", Network::Regtest).unwrap();
}

#[test]
fn assert_chain_net_rejects_mismatch() {
    let err = assert_chain_net("bcrt", Network::Mainnet).unwrap_err();
    assert!(err.to_string().contains("does not match"), "got: {err}");

    let err = assert_chain_net("bc", Network::Signet).unwrap_err();
    assert!(err.to_string().contains("does not match"), "got: {err}");

    // Regression: "bc:signet"-style notation is not what consignments
    // carry (`genesis.chain_net.prefix()` yields `"sb"`); it used to be
    // hardcoded as the expected value and blocked every signet sign.
    let err = assert_chain_net("bc:signet", Network::Signet).unwrap_err();
    assert!(err.to_string().contains("does not match"), "got: {err}");
}

#[test]
fn empty_expected_and_empty_proofs_is_ok() {
    // A consignment with no witness bundles (degenerate) and no proofs
    // is trivially OK - there's nothing to verify. Useful sanity check
    // that we don't iterate an empty set into a panic.
    let target = synth_headers(1).into_iter().next().unwrap();
    let chain = chain_burying(target, 5);
    validate_spv_proofs(&chain, &[], &[], SPV_MIN_CONFIRMATIONS).unwrap();
}

// ===== Staleness tests =====
//
// These hand `assert_chain_not_stale` an explicit `now` so the test
// doesn't depend on wall clock. Synthetic headers in this file have
// `time = 1_700_000_001 + i`, so we anchor `now` relative to that.

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
fn staleness_fresh_tip_passes() {
    let chain = chain_with_tip_time(1_700_000_000);
    // Now = tip + 30 minutes. Well within 2h.
    assert_chain_not_stale(
        &chain,
        unix(1_700_000_000 + 30 * 60),
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )
    .unwrap();
}

#[test]
fn staleness_tip_at_exact_max_age_passes() {
    let chain = chain_with_tip_time(1_700_000_000);
    // Now = tip + exactly max_age. Boundary is inclusive (age == max_age
    // is allowed; only age > max_age rejects).
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
    // Now = tip + 3 hours. Past the 2-hour bound.
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
    // Tip is 4h ahead of now; we allow up to 2h future skew.
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
    // Tip 30 min in the future of now - within the consensus 2h grace.
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
    // No headers pushed. Chain falls back to checkpoint.time, which in
    // this test setup is 1_700_000_000. Now = +1h -> fresh; now = +3h
    // -> stale. Same logic as a populated chain - checkpoint is just a
    // header we don't store the body of.
    let chain = HeaderChain::new(
        Network::Regtest,
        crate::networks::rgb::spv::checkpoint::Checkpoint {
            height: 0,
            hash: [0u8; 32],
            bits: 0x207fffff,
            time: 1_700_000_000,
            is_real: false,
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

#[test]
fn staleness_thresholds_are_what_we_documented() {
    // Defensive: if anyone tightens these constants without
    // understanding why, the test catches it. 2h on each side is
    // deliberately generous; lowering is a security tradeoff that
    // should be a conscious decision, not an incidental edit.
    assert_eq!(SPV_MAX_TIP_AGE_SECS, 2 * 60 * 60);
    assert_eq!(SPV_MAX_TIP_FUTURE_SECS, 2 * 60 * 60);
}
