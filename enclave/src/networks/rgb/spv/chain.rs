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

use crate::networks::rgb::spv::checkpoint::Checkpoint;
use crate::networks::rgb::spv::types::{BlockHash, BlockHeight, Network, Result, SpvError};
use crate::networks::rgb::spv::validation::{
    expected_bits, is_retarget_height, validate_header_full, RETARGET_INTERVAL,
};

/// Maximum allowed reorg depth. Real-world Bitcoin reorgs are almost always
/// ≤ 2 blocks; signet can be a touch noisier; either way 100 is generous
/// and bounds the worst-case work the enclave does on a reorg attempt.
///
/// Anything deeper than this is treated as a chain split that needs operator
/// attention, not something the enclave silently absorbs.
pub const MAX_REORG_DEPTH: BlockHeight = 100;

/// Confirmation depth the SPV cross-check requires before signing. Mirrors
/// `validation::spv_crosscheck::SPV_MIN_CONFIRMATIONS` (6); kept as a local
/// constant so `chain.rs` (always compiled) doesn't depend on the
/// `spv`-feature-gated cross-check module. Used only to size the retention
/// window so a proof at `tip − 5` still has its header.
const SPV_MIN_CONFIRMATIONS: BlockHeight = 6;

/// Sliding-window retention bound (#86). The in-memory chain keeps only the
/// most recent headers; everything older than the last retarget boundary
/// at/below `tip − HEADER_WINDOW` is pruned from the front.
///
/// The window must be large enough that:
///   - any reorg the enclave will accept (≤ `MAX_REORG_DEPTH` deep) stays
///     entirely inside the window, and the displaced range can be re-validated;
///   - any SPV proof the enclave will accept (≥ `SPV_MIN_CONFIRMATIONS` deep)
///     still has its committed header; and
///   - **critically**, the difficulty-retarget lookup still resolves: a
///     boundary block at height `B` (which can be as low as
///     `tip − MAX_REORG_DEPTH` on a reorg) needs the block at `B − 2016`. We
///     therefore retain at least one full retarget interval *below* the
///     reorg-reachable region, so `B − 2016` is never pruned.
///
/// `MAX_REORG_DEPTH + RETARGET_INTERVAL + SPV_MIN_CONFIRMATIONS` satisfies all
/// three with margin. With front-pruning aligned to retarget boundaries, the
/// retained span is between `HEADER_WINDOW` and `HEADER_WINDOW + 2015` headers
/// — a fixed, small bound (~450 KB) regardless of how long the enclave runs.
pub const HEADER_WINDOW: BlockHeight = MAX_REORG_DEPTH + RETARGET_INTERVAL + SPV_MIN_CONFIRMATIONS;

/// Maximum number of headers accepted in a single `submit_headers` call.
/// Bounds per-call validation work. Far above any legitimate batch (the
/// listener pushes incrementally) yet well under the ~52 k headers the 4 MB
/// `framing` cap would otherwise permit per message.
pub const MAX_HEADERS_PER_SUBMIT: usize = 10_000;

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

/// In-memory store of validated block headers, anchored to a checkpoint and
/// bounded by a sliding window (#86).
///
/// Headers are stored relative to a *window base* rather than the checkpoint.
/// The base starts at the checkpoint and advances as the front is pruned;
/// `headers[i]` is always the header at height `base_height + 1 + i`. The base
/// is kept on a retarget boundary so the epoch-start lookup stays resolvable
/// (see `HEADER_WINDOW`).
pub struct HeaderChain {
    network: Network,
    checkpoint: Checkpoint,
    /// Height of the block immediately preceding `headers[0]` — the anchor the
    /// first stored header chains to. Equals `checkpoint.height` until the
    /// front is first pruned, then advances (always to a retarget boundary).
    base_height: BlockHeight,
    /// Hash (internal byte order) of the block at `base_height`. Starts as the
    /// checkpoint hash; updated to the pruned-to header's hash on prune.
    base_hash: BlockHash,
    /// `nBits` of the block at `base_height` — the predecessor difficulty for
    /// `headers[0]`. Starts as `checkpoint.bits`.
    base_bits: u32,
    /// Timestamp of the block at `base_height`. Doubles as the epoch-start
    /// time when `base_height` is the boundary an incoming retarget block
    /// references. Starts as `checkpoint.time`.
    base_time: u32,
    /// Validated headers, in ascending height. Index `i` is the header at
    /// height `base_height + 1 + i`.
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
            base_height: checkpoint.height,
            base_hash: checkpoint.hash,
            base_bits: checkpoint.bits,
            base_time: checkpoint.time,
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
        self.base_height + self.headers.len() as BlockHeight
    }

    /// Hash of the most recent validated header (or the checkpoint hash).
    pub fn tip_hash(&self) -> BlockHash {
        if let Some(last) = self.hashes.last() {
            *last
        } else {
            self.checkpoint.hash
        }
    }

    /// Block timestamp (`time` field, Unix seconds) of the most recent
    /// validated header — or the checkpoint's `time` if no headers stored.
    /// Used by the SPV staleness check to detect "frozen-time" attacks
    /// where a hostile listener feeds real-but-old headers.
    pub fn tip_time(&self) -> u32 {
        if let Some(last) = self.headers.last() {
            last.time
        } else {
            self.checkpoint.time
        }
    }

    /// Number of validated headers stored (excludes the checkpoint itself).
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Look up a stored header by height. Heights at or below the window base
    /// return `None` — we don't keep the base block's header itself, only its
    /// metadata (hash/bits/time), and anything older has been pruned (#86).
    pub fn header_at(&self, height: BlockHeight) -> Option<&Header> {
        if height <= self.base_height {
            return None;
        }
        let idx = (height - self.base_height - 1) as usize;
        self.headers.get(idx)
    }

    /// Look up a stored hash by height. Returns the window-base hash for its
    /// own height — useful for chain-linkage checks across the base boundary.
    /// Heights below the base have been pruned and return `None`.
    pub fn hash_at(&self, height: BlockHeight) -> Option<BlockHash> {
        if height == self.base_height {
            return Some(self.base_hash);
        }
        if height < self.base_height {
            return None;
        }
        let idx = (height - self.base_height - 1) as usize;
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

        // Per-call cap (#86): bound the validation work a single submission
        // can demand. The `framing` 4 MB cap is per-message only — without
        // this an attacker could pack ~52 k headers into one call.
        if raw_headers.len() > MAX_HEADERS_PER_SUBMIT {
            return Err(SpvError::BatchTooLarge {
                len: raw_headers.len(),
                max: MAX_HEADERS_PER_SUBMIT,
            });
        }

        // Empty batch: nothing to place. Return a no-op outcome rather than
        // running the reorg path (which assumes a non-empty staged batch).
        if raw_headers.is_empty() {
            return Ok(SubmitOutcome {
                last_block_height: tip,
                last_block_hash: self.tip_hash(),
                headers_accepted: 0,
                reorg_depth: 0,
            });
        }

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

        // Predecessor info at `start_height - 1`. Either the window base
        // (checkpoint or pruned-to boundary) or a stored header. A start that
        // lands in the pruned region below the base is caught by the
        // `ReorgTooDeep` check above (the window always retains more than
        // `MAX_REORG_DEPTH` headers, so any acceptable reorg stays in range).
        let pred_height = start_height - 1;
        let (pred_hash, pred_bits, pred_time) = if pred_height == self.base_height {
            (self.base_hash, self.base_bits, self.base_time)
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

            let epoch_start_time = if self.network.enforces_pow() {
                self.epoch_start_time(height, start_height, &staged)?
            } else {
                0
            };

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
            let truncate_idx = (pred_height - self.base_height) as usize;
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

        // Bound forward growth (#86): prune the front to the window.
        self.prune_front();

        Ok(SubmitOutcome {
            last_block_height: self.tip_height(),
            last_block_hash: self.tip_hash(),
            headers_accepted: accepted,
            reorg_depth,
        })
    }

    /// Drop headers older than the retention window, advancing the window
    /// base (#86). The new base is the **last retarget boundary at/below
    /// `tip − HEADER_WINDOW`**, so:
    ///   - the base always lands on a multiple of `RETARGET_INTERVAL`, and
    ///   - the epoch-start block for any boundary the enclave might still
    ///     validate (down to `tip − MAX_REORG_DEPTH` on a reorg, whose epoch
    ///     start is `≥ tip − MAX_REORG_DEPTH − 2016 ≥ base`) is never pruned.
    ///
    /// No-op until the chain is long enough to prune past a boundary, so on
    /// regtest/signet (and early mainnet sync) nothing is dropped.
    fn prune_front(&mut self) {
        let tip = self.tip_height();
        let cutoff = tip.saturating_sub(HEADER_WINDOW);
        // Round down to the last retarget boundary at/below the cutoff.
        let new_base = (cutoff / RETARGET_INTERVAL) * RETARGET_INTERVAL;
        if new_base <= self.base_height {
            return;
        }

        // headers[i] is at height base_height + 1 + i, so the header at
        // new_base sits at index (new_base - base_height - 1). Everything up to
        // and including that index is pruned; that header becomes the new base.
        let drop = (new_base - self.base_height) as usize;
        let anchor_idx = drop - 1;
        let anchor = self.headers[anchor_idx];
        self.base_hash = self.hashes[anchor_idx];
        self.base_bits = anchor.bits.to_consensus();
        self.base_time = anchor.time;
        self.base_height = new_base;
        self.headers.drain(..drop);
        self.hashes.drain(..drop);
    }

    /// Find the timestamp of the block at the start of the retarget epoch
    /// containing `height`. Looks first in the staged batch (whose first
    /// entry is at `batch_start_height`), then in the committed chain, then
    /// at the window base (the pruned-to boundary, or the checkpoint).
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

        // Committed chain (strictly above the window base)?
        if let Some(h) = self.header_at(target_height) {
            return Ok(h.time);
        }

        // The window base itself: a retarget boundary (or the checkpoint)
        // whose timestamp we retain even after the header is pruned. The
        // window guarantees the epoch start for any boundary we still validate
        // is at or above this base (see `HEADER_WINDOW` / `prune_front`).
        if target_height == self.base_height {
            return Ok(self.base_time);
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
    fn non_pow_network_skips_epoch_lookup_across_retarget_boundary() {
        // Regression: a non-PoW network (signet/regtest) whose checkpoint is
        // ABOVE the retarget epoch start must NOT fail with HeaderNotFound.
        // Checkpoint at height 2020 means epoch_start for height 2016*2=4032
        // would be 4032-2016=2016, which IS stored. But the PREVIOUS epoch
        // start (height 0) is NOT stored. We test that crossing the 4032
        // boundary works without needing headers below checkpoint.
        //
        // Specifically: checkpoint at 4000, first retarget at 4032 needs
        // epoch start at 4032-2016=2016 which is below checkpoint (4000).
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

    // ===== #67: retarget-boundary epoch-start resolution =====
    //
    // The wedge bug is in `epoch_start_time`: a retarget boundary at height B
    // needs the block at `B - RETARGET_INTERVAL`. If the checkpoint isn't
    // boundary-aligned, the first boundary above it references an epoch start
    // *below* the checkpoint, which is never stored — `HeaderNotFound`, and the
    // chain wedges. We test the lookup directly: synthesising a real mainnet
    // chain across a boundary would need genuine min-difficulty PoW (not
    // feasible in a unit test), but the difficulty math itself is covered in
    // validation.rs — what #67 changes is purely epoch-start *availability*.

    /// TH-1: with a boundary-aligned checkpoint (the #67 fix), the first
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

    /// TH-2: the OLD, misaligned checkpoint (950 000) wedges — the first
    /// boundary above it (951 552) references an epoch start (949 536) below
    /// the checkpoint, which is never stored. This is the bug #67 fixes; the
    /// load-time assertion now rejects such a checkpoint outright.
    #[test]
    fn th2_misaligned_checkpoint_wedges_at_first_boundary() {
        let cp = Checkpoint {
            height: 950_000, // 950_000 % 2016 == 464 → NOT aligned
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

    // ===== #86: bounded header chain (sliding window) =====

    /// Front-pruning advances the window base to the last retarget boundary
    /// at/below `tip - HEADER_WINDOW`, bounds memory, and keeps the index math
    /// (`header_at`/`hash_at`) correct off the new base.
    #[test]
    fn prune_bounds_memory_and_rebases_index_math() {
        // Checkpoint at height 0 so boundaries fall on clean multiples of 2016.
        let cp = Checkpoint {
            height: 0,
            hash: [0xCC; 32],
            bits: 0x207fffff,
            time: 1_700_000_000,
            is_real: false,
        };
        let mut chain = HeaderChain::new(Network::Regtest, cp);

        // Build enough headers to prune past a boundary: need tip ≥ 2016 +
        // HEADER_WINDOW. HEADER_WINDOW = 100 + 2016 + 6 = 2122, so tip = 4200
        // gives new_base = floor_2016(4200 - 2122) = floor_2016(2078) = 2016.
        let count = 4200u32;
        let (raws, _) = synth_chain_from(cp.hash, cp.time, 1, count);
        let outcome = chain.submit_headers(1, &raws).unwrap();
        assert_eq!(outcome.last_block_height, count);
        assert_eq!(chain.tip_height(), count);

        // Base advanced to the retarget boundary at 2016; everything below was
        // pruned, so memory is bounded to the retained span.
        assert_eq!(chain.base_height, 2016);
        assert_eq!(chain.headers.len(), (count - 2016) as usize);
        assert!(
            (chain.headers.len() as BlockHeight) <= HEADER_WINDOW + RETARGET_INTERVAL,
            "retained span must stay within one window + one epoch"
        );

        // Index math is now relative to the new base.
        assert!(chain.header_at(2016).is_none(), "base header not stored");
        assert!(chain.hash_at(2015).is_none(), "below base is pruned");
        assert_eq!(chain.hash_at(2016), Some(chain.base_hash));
        assert!(chain.header_at(2017).is_some(), "first retained header");
        assert!(chain.header_at(count).is_some(), "tip is retained");
        assert_eq!(chain.header_at(count), chain.headers.last());

        // The chain still extends correctly after pruning (linkage to the tip
        // is unaffected by front-pruning).
        let tip_hash = chain.tip_hash();
        let (more, _) = synth_chain_from(tip_hash, chain.tip_time(), 9, 10);
        let outcome = chain.submit_headers(count + 1, &more).unwrap();
        assert_eq!(outcome.headers_accepted, 10);
        assert_eq!(chain.tip_height(), count + 10);
    }

    /// #86 critical gotcha: after pruning, the retarget epoch-start lookup must
    /// still resolve. A boundary one interval above the new base references
    /// exactly the base, whose timestamp we retain even though its header was
    /// pruned.
    #[test]
    fn epoch_start_resolves_at_new_base_after_prune() {
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
        assert_eq!(chain.base_height, 2016);

        // The header that became the base was height 2016 in the submitted
        // batch: synth_chain_from sets time = prev_time + 1 + i, so height
        // 2016 (batch index 2015) has time cp.time + 1 + 2015 = cp.time + 2016.
        let expected_base_time = cp.time + 2016;
        assert_eq!(chain.base_time, expected_base_time);

        // A boundary one interval above the base references the base itself —
        // resolves to base_time rather than HeaderNotFound.
        let boundary = chain.base_height + RETARGET_INTERVAL; // 4032
        let got = chain
            .epoch_start_time(boundary, boundary, &[])
            .expect("epoch start at the new base must resolve post-prune");
        assert_eq!(got, expected_base_time);
    }

    /// A reorg near the tip still validates after pruning — the truncate index
    /// is computed off the window base, not the checkpoint.
    #[test]
    fn reorg_near_tip_after_prune() {
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
        assert_eq!(chain.base_height, 2016);

        // Reorg the last 5 blocks (depth 5) with a longer alt chain.
        let start = 4196;
        let pred_hash = chain.hash_at(start - 1).unwrap();
        let pred_time = chain.header_at(start - 1).unwrap().time;
        let (alt, _) = synth_chain_from(pred_hash, pred_time, 55, 10);
        let outcome = chain.submit_headers(start, &alt).unwrap();
        assert_eq!(outcome.reorg_depth, 5);
        assert_eq!(chain.tip_height(), start - 1 + 10);
        assert_eq!(
            chain.base_height, 2016,
            "base unchanged by a tip-local reorg"
        );
    }

    /// Per-call cap (#86): a batch larger than `MAX_HEADERS_PER_SUBMIT` is
    /// rejected before any parsing work. We pass garbage vecs — the cap fires
    /// first, so they're never deserialised.
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
}
