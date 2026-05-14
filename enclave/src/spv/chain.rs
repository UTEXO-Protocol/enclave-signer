//! In-memory Bitcoin header chain with bounded reorg support.
//!
//! The chain starts at a compile-time `Checkpoint` (height + hash + bits +
//! time) and grows forward as the Listener pushes batches of contiguous
//! 80-byte headers via `submit_headers`. Each header is validated against
//! its predecessor (chain linkage + PoW + nBits) before being appended.
//!
//! ## Three submission cases
//!
//! `submit_headers(start_height, batch)` handles three cases:
//!
//! 1. **Extension** (`start_height == tip + 1`): standard append. The first
//!    header chains to the current tip; subsequent headers chain among
//!    themselves; the chain grows.
//! 2. **Bounded reorg** (`checkpoint < start_height ≤ tip`): the listener is
//!    presenting an alternative chain that branches at `start_height - 1`.
//!    Accepted *only* if:
//!      - the depth (`tip - start_height + 1`) is ≤ `MAX_REORG_DEPTH`;
//!      - every header in the batch validates (linkage + PoW + nBits);
//!      - the alternative chain's cumulative work over the rewritten range
//!        is **strictly greater** than the existing chain's work over the
//!        same range. Equal-work-replace is not allowed (Bitcoin best-chain
//!        rule: ties go to the chain we already have).
//! 3. **Rejection**: a gap above the tip (`start_height > tip + 1`), or an
//!    attempt to rewrite history below the checkpoint, both fail.
//!
//! Reorgs are atomic: state is mutated only after the entire batch
//! validates *and* the cumulative-work check passes.
//!
//! ## What this module does NOT do (yet)
//!
//! - **BIP-325 signet signature.** See validation.rs — the signature lives
//!   in the coinbase witness commitment, which the proto doesn't carry.
//! - **Header staleness.** Refusing to use a stale tip for confirmation
//!   counts is PR 4.

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::pow::Work;

use crate::spv::checkpoint::Checkpoint;
use crate::spv::types::{BlockHash, BlockHeight, Network, Result, SpvError};
use crate::spv::validation::{
    expected_bits, is_retarget_height, validate_header_full, RETARGET_INTERVAL,
};

/// Maximum allowed reorg depth. Real-world Bitcoin reorgs are almost always
/// ≤ 2 blocks; signet can be a touch noisier; either way 100 is generous
/// and bounds the worst-case work the enclave does on a reorg attempt.
///
/// Anything deeper than this is treated as a chain split that needs operator
/// attention, not something the enclave silently absorbs.
pub const MAX_REORG_DEPTH: BlockHeight = 100;

/// Outcome of pushing a batch of headers.
#[derive(Debug, Clone, Copy)]
pub struct SubmitOutcome {
    pub last_block_height: BlockHeight,
    pub last_block_hash: BlockHash,
    /// Number of headers from the batch that were accepted. On success this
    /// equals the batch length (the implementation is strictly all-or-nothing
    /// — a single failure aborts the batch and leaves the chain unchanged).
    pub headers_accepted: u32,
    /// How many existing headers were displaced because the batch was a
    /// reorg. `0` for a plain extension; `> 0` means the listener pushed an
    /// alternative chain that overtook ours (Bitcoin best-chain semantics).
    pub reorg_depth: BlockHeight,
}

/// In-memory store of validated block headers, anchored to a checkpoint.
pub struct HeaderChain {
    network: Network,
    checkpoint: Checkpoint,
    /// Validated headers, in ascending height. Index `i` is the header at
    /// height `checkpoint.height + 1 + i`.
    headers: Vec<Header>,
    /// Cached hashes (internal byte order) parallel to `headers`. Avoids
    /// recomputing on every linkage check.
    hashes: Vec<BlockHash>,
}

impl HeaderChain {
    /// Initialise an empty chain anchored at `checkpoint`. Call
    /// `submit_headers` to populate.
    pub fn new(network: Network, checkpoint: Checkpoint) -> Self {
        Self {
            network,
            checkpoint,
            headers: Vec::new(),
            hashes: Vec::new(),
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Height of the most recent validated header (or the checkpoint, if no
    /// headers have been accepted yet).
    pub fn tip_height(&self) -> BlockHeight {
        self.checkpoint.height + self.headers.len() as BlockHeight
    }

    /// Hash of the most recent validated header (or the checkpoint hash).
    pub fn tip_hash(&self) -> BlockHash {
        if let Some(last) = self.hashes.last() {
            *last
        } else {
            self.checkpoint.hash
        }
    }

    /// Number of validated headers stored (excludes the checkpoint itself).
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Look up a stored header by height. The checkpoint height returns
    /// `None` because we don't keep the checkpoint header itself, only its
    /// metadata (we hardcode hash/bits/time).
    pub fn header_at(&self, height: BlockHeight) -> Option<&Header> {
        if height <= self.checkpoint.height {
            return None;
        }
        let idx = (height - self.checkpoint.height - 1) as usize;
        self.headers.get(idx)
    }

    /// Look up a stored hash by height. Returns the checkpoint hash for its
    /// own height — useful for chain-linkage checks across the boundary.
    pub fn hash_at(&self, height: BlockHeight) -> Option<BlockHash> {
        if height == self.checkpoint.height {
            return Some(self.checkpoint.hash);
        }
        if height < self.checkpoint.height {
            return None;
        }
        let idx = (height - self.checkpoint.height - 1) as usize;
        self.hashes.get(idx).copied()
    }

    /// Submit a batch of contiguous 80-byte headers starting at
    /// `start_height`. See module docs for the three-case dispatch
    /// (extension / bounded reorg / rejection).
    ///
    /// All-or-nothing: a single failure (parse, linkage, PoW, or
    /// weaker-chain) aborts the batch and leaves the chain unchanged.
    pub fn submit_headers(
        &mut self,
        start_height: BlockHeight,
        raw_headers: &[Vec<u8>],
    ) -> Result<SubmitOutcome> {
        let tip = self.tip_height();

        if start_height <= self.checkpoint.height {
            return Err(SpvError::BelowCheckpoint {
                got: start_height,
                checkpoint: self.checkpoint.height,
            });
        }
        if start_height > tip + 1 {
            return Err(SpvError::NonContiguous {
                got: start_height,
                tip,
            });
        }

        // 0 = pure extension (start_height == tip + 1).
        // > 0 = reorg of `reorg_depth` existing headers.
        let reorg_depth = (tip + 1).saturating_sub(start_height);
        if reorg_depth > MAX_REORG_DEPTH {
            return Err(SpvError::ReorgTooDeep {
                depth: reorg_depth,
                max: MAX_REORG_DEPTH,
            });
        }

        // Predecessor info at `start_height - 1`. Always exists by the bounds
        // check above (either the checkpoint itself or a stored header).
        let pred_height = start_height - 1;
        let (pred_hash, pred_bits, pred_time) = if pred_height == self.checkpoint.height {
            (
                self.checkpoint.hash,
                self.checkpoint.bits,
                self.checkpoint.time,
            )
        } else {
            let h = self
                .header_at(pred_height)
                .ok_or(SpvError::HeaderNotFound(pred_height))?;
            let hash = self
                .hash_at(pred_height)
                .ok_or(SpvError::HeaderNotFound(pred_height))?;
            (hash, h.bits.to_consensus(), h.time)
        };

        // Stage parsed headers + hashes. Only commit if the whole batch
        // validates AND, for reorgs, beats the existing chain on work.
        let mut staged: Vec<(Header, BlockHash)> = Vec::with_capacity(raw_headers.len());

        for (i, raw) in raw_headers.iter().enumerate() {
            let header: Header = deserialize(raw).map_err(|e| SpvError::HeaderParse {
                index: i,
                message: e.to_string(),
            })?;

            let height = start_height + i as BlockHeight;

            let (prev_hash, prev_bits, prev_time) = if let Some((prev_h, prev_hash)) = staged.last()
            {
                (*prev_hash, prev_h.bits.to_consensus(), prev_h.time)
            } else {
                (pred_hash, pred_bits, pred_time)
            };

            let epoch_start_time = self.epoch_start_time(height, start_height, &staged)?;

            let expected_bits_value =
                expected_bits(height, prev_bits, prev_time, epoch_start_time, self.network)?;

            validate_header_full(
                &header,
                height,
                &prev_hash,
                expected_bits_value,
                self.network,
            )?;

            let hash: [u8; 32] = *bitcoin::hashes::Hash::as_byte_array(&header.block_hash());
            staged.push((header, hash));
        }

        // Reorg case: require strictly greater cumulative work over the
        // rewritten range. Equal-work-replace is rejected (Bitcoin best-chain
        // rule: ties go to the chain we already have).
        if reorg_depth > 0 {
            let truncate_idx = (pred_height - self.checkpoint.height) as usize;
            let existing_work = sum_work(self.headers[truncate_idx..].iter())
                .expect("reorg implies non-empty existing range");
            let new_work = sum_work(staged.iter().map(|(h, _)| h))
                .expect("staged batch is non-empty when reorg_depth > 0");
            if new_work <= existing_work {
                return Err(SpvError::WeakerChain);
            }
            // Truncate the displaced tail. Done before append so we don't
            // briefly hold a chain that violates the linkage invariant.
            self.headers.truncate(truncate_idx);
            self.hashes.truncate(truncate_idx);
        }

        let accepted = staged.len() as u32;
        for (header, hash) in staged {
            self.headers.push(header);
            self.hashes.push(hash);
        }

        Ok(SubmitOutcome {
            last_block_height: self.tip_height(),
            last_block_hash: self.tip_hash(),
            headers_accepted: accepted,
            reorg_depth,
        })
    }

    /// Find the timestamp of the block at the start of the retarget epoch
    /// containing `height`. Looks first in the staged batch (whose first
    /// entry is at `batch_start_height`), then in the committed chain, then
    /// at the checkpoint.
    ///
    /// Only meaningful at retarget boundaries; on non-boundary heights the
    /// caller ignores the value.
    fn epoch_start_time(
        &self,
        height: BlockHeight,
        batch_start_height: BlockHeight,
        staged: &[(Header, BlockHash)],
    ) -> Result<u32> {
        if !is_retarget_height(height) {
            // Sentinel: any value, caller ignores it.
            return Ok(0);
        }

        // The epoch start is the block at `height - RETARGET_INTERVAL`.
        if height < RETARGET_INTERVAL {
            // Genesis epoch boundary on regtest etc. — ignore.
            return Ok(0);
        }
        let target_height = height - RETARGET_INTERVAL;

        // Staged batch? (May overlap committed chain on a reorg, in which
        // case the staged value is the right one — it's our pending future.)
        if target_height >= batch_start_height {
            let staged_idx = (target_height - batch_start_height) as usize;
            if let Some((h, _)) = staged.get(staged_idx) {
                return Ok(h.time);
            }
        }

        // Committed chain?
        if target_height > self.checkpoint.height {
            if let Some(h) = self.header_at(target_height) {
                return Ok(h.time);
            }
        }

        // Checkpoint?
        if target_height == self.checkpoint.height {
            return Ok(self.checkpoint.time);
        }

        Err(SpvError::HeaderNotFound(target_height))
    }
}

/// Sum the proof-of-work of an iterator of headers. Returns `None` if the
/// iterator is empty (we never want to pretend "no work" is meaningful).
fn sum_work<'a, I: IntoIterator<Item = &'a Header>>(headers: I) -> Option<Work> {
    let mut iter = headers.into_iter();
    let first = iter.next()?.work();
    Some(iter.fold(first, |acc, h| acc + h.work()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;

    /// Synthetic mainnet-shaped chain: we mint our own checkpoint + headers,
    /// each with valid PoW under regtest rules, and run through the chain
    /// linkage logic. Avoids the cost of fixtures with real-difficulty
    /// PoW for every block.
    fn synthetic_regtest_setup() -> (HeaderChain, Vec<Vec<u8>>) {
        // Regtest is "chain linkage only" in our validator — no PoW or bits
        // enforcement — so we can build a tiny synthetic chain without
        // actually mining anything.
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
        // Now submit the FIRST raw again at height 102 — its prev_blockhash
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
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
            0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
            0x00, 0x00, 0x00, 0x00,
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
    // Regtest headers have a constant nBits, so every header contributes the
    // same Work. That makes "more work" equivalent to "more blocks", which is
    // exactly what we want for these tests — chain length is a clean proxy.

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
        // from height (checkpoint + 1) — depth == MAX_REORG_DEPTH exactly.
        let (orig, _) = synth_chain_from(cp_hash, 1_700_000_000, 1, MAX_REORG_DEPTH);
        chain.submit_headers(101, &orig).unwrap();

        // Alt of MAX_REORG_DEPTH + 1 headers from the SAME predecessor (the
        // checkpoint) — strictly more work than the original.
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
        alt[3] = vec![0u8; 79]; // shorter than the 80-byte header — parse error

        let err = chain.submit_headers(102, &alt).unwrap_err();
        assert!(matches!(err, SpvError::HeaderParse { index: 3, .. }));
        // Chain MUST be unchanged: no partial accept, no truncate.
        assert_eq!(chain.tip_hash(), original_tip);
        assert_eq!(chain.tip_height(), original_height);
        assert_eq!(chain.len(), 5);
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
}
