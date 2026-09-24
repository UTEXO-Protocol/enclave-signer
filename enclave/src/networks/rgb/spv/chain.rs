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
//! 2. **Bounded reorg** (`checkpoint < start_height <= tip`): the listener is
//!    presenting an alternative chain that branches at `start_height - 1`.
//!    Accepted *only* if:
//!      - the depth (`tip - start_height + 1`) is <= `MAX_REORG_DEPTH`;
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
//! Not done here: the BIP-325 signet signature (it lives in the coinbase
//! witness commitment, which the proto does not carry - see validation.rs).

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::pow::Work;

use crate::networks::rgb::spv::checkpoint::Checkpoint;
use crate::networks::rgb::spv::types::{BlockHash, BlockHeight, Network, Result, SpvError};
use crate::networks::rgb::spv::validation::{
    expected_bits, is_retarget_height, validate_header_full, RETARGET_INTERVAL,
};

/// Maximum allowed reorg depth. Real reorgs are almost always <= 2 blocks, so
/// 100 is generous and bounds the worst-case work of a reorg attempt. Anything
/// deeper is a chain split needing operator attention.
pub const MAX_REORG_DEPTH: BlockHeight = 100;

// Retention policy: every validated header from the checkpoint forward
// is kept - there is no sliding window. The old window pruned below
// `tip - ~2122`, which broke the SPV invariant that a consignment must prove
// inclusion of all its witness anchors: those can sit tens of thousands of
// blocks below the tip, and once pruned the enclave refused to sign.
//
// Steady-state memory is `tip - checkpoint` headers at ~112 B each (80 B header
// + 32 B cached hash): ~9.5 MB for signet today, ~5.9 MB/year on mainnet. The
// checkpoint must sit below the oldest anchor of any bridgeable asset.
//
// Growth on PoW networks is throttled by real chain work, but production runs
// UTEXO custom signet, which does not enforce PoW - headers can be minted for
// free. `MAX_STORED_HEADERS` therefore caps absolute retention on every
// network.

/// Absolute cap on retained headers, the work-independent
/// memory backstop that replaced the sliding window. A batch that would push
/// the stored count past it is rejected fail-closed rather than pruned, so no
/// anchor is silently dropped; the operator advances the compile-time
/// checkpoint instead.
///
/// Sizing: worst case is `MAX_STORED_HEADERS` x ~112 B, about 112 MB. Runway
/// before the real chain reaches it is ~11 months on 30s-block signet and ~19
/// years on mainnet. Tune against the enclave's memory reservation.
pub const MAX_STORED_HEADERS: usize = 1_000_000;

/// Maximum headers accepted in one `submit_headers` call, bounding per-call
/// validation work. Far above any legitimate batch, well under the ~52k the
/// 4 MB `framing` cap would otherwise allow per message.
pub const MAX_HEADERS_PER_SUBMIT: usize = 10_000;

/// Outcome of pushing a batch of headers.
#[derive(Debug, Clone, Copy)]
pub struct SubmitOutcome {
    pub last_block_height: BlockHeight,
    pub last_block_hash: BlockHash,
    /// Headers from the batch that were accepted. Equals the batch length on
    /// success: submission is all-or-nothing.
    pub headers_accepted: u32,
    /// Existing headers displaced by a reorg. `0` for a plain extension.
    pub reorg_depth: BlockHeight,
}

/// In-memory store of validated block headers, anchored to a checkpoint.
///
/// Every header from the checkpoint forward is retained. Headers are
/// stored relative to a base that equals the checkpoint and never moves:
/// `headers[i]` is the header at height `base_height + 1 + i`. The base fields
/// are the checkpoint block's hash/bits/time, which the first stored header
/// chains to.
pub struct HeaderChain {
    network: Network,
    checkpoint: Checkpoint,
    /// Height of the block preceding `headers[0]`. With full retention
    /// this stays equal to `checkpoint.height` for the life of the chain.
    base_height: BlockHeight,
    /// Hash (internal byte order) of the block at `base_height` - the
    /// checkpoint hash.
    base_hash: BlockHash,
    /// `nBits` of the block at `base_height` - the predecessor difficulty for
    /// `headers[0]` (the checkpoint's `bits`).
    base_bits: u32,
    /// Timestamp of the block at `base_height` (the checkpoint's `time`).
    /// Doubles as the epoch-start time when `base_height` is the boundary an
    /// incoming retarget block references.
    base_time: u32,
    /// Validated headers, in ascending height. Index `i` is the header at
    /// height `base_height + 1 + i`.
    headers: Vec<Header>,
    /// Cached hashes (internal byte order) parallel to `headers`. Avoids
    /// recomputing on every linkage check.
    hashes: Vec<BlockHash>,
    /// Absolute cap on retained headers (see `MAX_STORED_HEADERS`). A field so
    /// tests can shrink it; production always uses the const.
    max_stored_headers: usize,
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
            max_stored_headers: MAX_STORED_HEADERS,
        }
    }

    /// Test hook: shrink the retention cap so the fail-closed ceiling can be
    /// exercised without building `MAX_STORED_HEADERS` headers.
    #[cfg(test)]
    fn set_max_stored_headers_for_test(&mut self, cap: usize) {
        self.max_stored_headers = cap;
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

    /// Block timestamp of the most recent validated header, or the
    /// checkpoint's `time` when none are stored. Used by the SPV staleness
    /// check to detect a listener feeding real-but-old headers.
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

    /// Look up a stored header by height. Heights at or below the checkpoint
    /// return `None`: only the checkpoint's metadata is kept, not its header.
    /// Every height above it is retained, so old RGB anchors resolve.
    pub fn header_at(&self, height: BlockHeight) -> Option<&Header> {
        if height <= self.base_height {
            return None;
        }
        let idx = (height - self.base_height - 1) as usize;
        self.headers.get(idx)
    }

    /// Look up a stored hash by height. Returns the checkpoint (base) hash for
    /// its own height - useful for chain-linkage checks across the base
    /// boundary. Heights below the checkpoint return `None`.
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

        // Per-call cap. The `framing` 4 MB cap is per-message only, so
        // without this an attacker could pack ~52k headers into one call.
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

        // Total-retention ceiling: on a non-PoW network
        // headers are minted for free, so without this the chain could grow
        // until the enclave OOMs. Fail-closed - reject rather than prune.
        // Headers retained below the batch are `start_height - 1 - base_height`
        // (0 for a reorg back to the base); the batch replaces the rest.
        let retained_below_batch = (start_height - 1 - self.base_height) as usize;
        let projected_len = retained_below_batch + raw_headers.len();
        if projected_len > self.max_stored_headers {
            return Err(SpvError::ChainTooLong {
                len: projected_len,
                max: self.max_stored_headers,
            });
        }

        // Predecessor at `start_height - 1`: the base (checkpoint) or a stored
        // header. A start at or below the checkpoint was already rejected, and
        // everything above it is retained.
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

        // Reorg: require strictly greater cumulative work over the rewritten
        // range. Ties go to the chain we already have.
        if reorg_depth > 0 {
            let truncate_idx = (pred_height - self.base_height) as usize;
            let existing_work = sum_work(self.headers[truncate_idx..].iter())
                .expect("reorg implies non-empty existing range");
            let new_work = sum_work(staged.iter().map(|(h, _)| h))
                .expect("staged batch is non-empty when reorg_depth > 0");
            if new_work <= existing_work {
                return Err(SpvError::WeakerChain);
            }
            // Truncate the displaced tail before appending, so the chain never
            // briefly violates the linkage invariant.
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
    /// at the base (the checkpoint).
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
            // Genesis epoch boundary on regtest etc. - ignore.
            return Ok(0);
        }
        let target_height = height - RETARGET_INTERVAL;

        // Staged batch? (May overlap committed chain on a reorg, in which
        // case the staged value is the right one - it's our pending future.)
        if target_height >= batch_start_height {
            let staged_idx = (target_height - batch_start_height) as usize;
            if let Some((h, _)) = staged.get(staged_idx) {
                return Ok(h.time);
            }
        }

        // Committed chain (strictly above the base / checkpoint)?
        if let Some(h) = self.header_at(target_height) {
            return Ok(h.time);
        }

        // The checkpoint itself: its timestamp is kept as base metadata even
        // though its header is not stored. Full retention means any
        // higher boundary's epoch start is a stored header, resolved above.
        if target_height == self.base_height {
            return Ok(self.base_time);
        }

        Err(SpvError::HeaderNotFound(target_height))
    }
}

/// Sum the proof-of-work of an iterator of headers. `None` when empty, so
/// "no work" is never treated as a comparable value.
fn sum_work<'a, I: IntoIterator<Item = &'a Header>>(headers: I) -> Option<Work> {
    let mut iter = headers.into_iter();
    let first = iter.next()?.work();
    Some(iter.fold(first, |acc, h| acc + h.work()))
}

#[cfg(test)]
mod tests;
