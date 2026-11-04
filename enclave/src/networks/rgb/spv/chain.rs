//! In-memory Bitcoin header chain with bounded reorg support.
//!
//! The chain starts at a compile-time `Checkpoint` (height, hash, bits, time).
//! It grows as the parent sends batches of contiguous 80-byte headers to
//! `submit_headers`. Each header must pass the linkage check against its
//! predecessor and be at most 2 hours ahead of the enclave clock. It must also
//! be newer than the median time past of the eleven blocks below it, as in
//! Bitcoin Core. That rule starts at the eleventh block above the checkpoint.
//! Mainnet and the testnets also check PoW and nBits.
//!
//! On the testnets a block more than 20 minutes after its parent may use the
//! minimum difficulty. Such blocks count toward confirmations and freshness
//! like any other: testnets carry no production value. The clock bound keeps
//! a host from dating them ahead to retarget its fork down.
//!
//! ## Three submission cases
//!
//! 1. **Extension** (`start_height == tip + 1`): append to the tip.
//! 2. **Bounded reorg** (`checkpoint < start_height <= tip`): an alternative
//!    chain that branches at `start_height - 1`. Accepted only if:
//!      - the depth (`tip - start_height + 1`) is <= `MAX_REORG_DEPTH`;
//!      - every header in the batch validates (linkage, time, PoW, nBits);
//!      - its cumulative work over the rewritten range is **strictly
//!        greater** than the existing work. Ties go to the existing chain
//!        (Bitcoin best-chain rule).
//! 3. **Rejection**: a gap above the tip (`start_height > tip + 1`) or a
//!    start at or below the checkpoint.
//!
//! Reorgs are atomic. State changes only after the full batch validates and
//! the work check passes.
//!
//! The BIP-325 signet signature is not checked. The proto does not carry the
//! coinbase witness (see validation.rs).

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::pow::Work;

use crate::networks::rgb::spv::checkpoint::Checkpoint;
use crate::networks::rgb::spv::types::{BlockHash, BlockHeight, Network, Result, SpvError};
use crate::networks::rgb::spv::validation::{
    expected_bits, is_retarget_height, median_time_past, validate_header_full, BitsInput,
    Predecessor, MEDIAN_TIME_SPAN, RETARGET_INTERVAL,
};

/// Maximum reorg depth. Real reorgs are almost always <= 2 blocks. 100 bounds
/// the worst-case reorg work. A deeper split needs the operator.
pub const MAX_REORG_DEPTH: BlockHeight = 100;

// Retention: the chain keeps every validated header above the checkpoint.
// A consignment must prove inclusion of all its witness anchors, and these
// can be tens of thousands of blocks below the tip.
//
// Memory is `tip - checkpoint` headers at approx 112 B each (80 B header and
// 32 B cached hash). The checkpoint must be below the oldest anchor of any
// bridgeable asset.
//
// On signet and regtest the enclave does not check PoW, so headers cost
// nothing to make. `MAX_STORED_HEADERS` caps retention on every network.

/// Absolute cap on retained headers. A batch that goes over it fails closed.
/// The chain does not prune, so no anchor is lost. The operator must move the
/// compile-time checkpoint forward.
///
/// Worst case is approx 112 MB (x 112 B per header). The real chain reaches it
/// in approx 11 months on 30s-block signet and 19 years on mainnet. Tune it to
/// the enclave memory reservation.
pub const MAX_STORED_HEADERS: usize = 1_000_000;

/// Maximum headers in one `submit_headers` call. It bounds per-call work. The
/// 24 MiB `framing` cap alone allows approx 314k headers per message.
pub const MAX_HEADERS_PER_SUBMIT: usize = 10_000;

/// Outcome of pushing a batch of headers.
#[derive(Debug, Clone, Copy)]
pub struct SubmitOutcome {
    pub last_block_height: BlockHeight,
    pub last_block_hash: BlockHash,
    /// Accepted headers. Equals the batch length on success (all-or-nothing).
    pub headers_accepted: u32,
    /// Existing headers displaced by a reorg. `0` for a plain extension.
    pub reorg_depth: BlockHeight,
}

/// In-memory store of validated block headers above a checkpoint.
///
/// The base is the checkpoint and never moves. `headers[i]` is the header at
/// height `base_height + 1 + i`. The base fields hold the checkpoint
/// hash/bits/time. The first stored header chains to them.
pub struct HeaderChain {
    network: Network,
    checkpoint: Checkpoint,
    /// Height of the block before `headers[0]`. Always `checkpoint.height`.
    base_height: BlockHeight,
    /// Checkpoint hash (internal byte order).
    base_hash: BlockHash,
    /// Checkpoint `nBits`: the predecessor difficulty for `headers[0]`.
    base_bits: u32,
    /// Checkpoint `time`. It is also the epoch-start time when a retarget
    /// block refers back to `base_height`, and `base_bits` its bits.
    base_time: u32,
    /// Validated headers, in ascending height. Index `i` is the header at
    /// height `base_height + 1 + i`.
    headers: Vec<Header>,
    /// Cached hashes (internal byte order), parallel to `headers`.
    hashes: Vec<BlockHash>,
    /// Retention cap (see `MAX_STORED_HEADERS`). A field so tests can make it
    /// smaller.
    max_stored_headers: usize,
}

impl HeaderChain {
    /// Makes an empty chain anchored at `checkpoint`.
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

    /// Test hook: a smaller retention cap, to test the cap without
    /// `MAX_STORED_HEADERS` headers.
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

    /// Height of the last validated header, or the checkpoint height.
    pub fn tip_height(&self) -> BlockHeight {
        self.base_height + self.headers.len() as BlockHeight
    }

    /// Hash of the last validated header, or the checkpoint hash.
    pub fn tip_hash(&self) -> BlockHash {
        if let Some(last) = self.hashes.last() {
            *last
        } else {
            self.checkpoint.hash
        }
    }

    /// Timestamp of the last validated header, or the checkpoint `time`.
    pub fn tip_time(&self) -> u32 {
        if let Some(last) = self.headers.last() {
            last.time
        } else {
            self.checkpoint.time
        }
    }

    /// Headers from `height` to the tip, counted up to `cap`. `0` when no
    /// header is at `height`.
    pub fn confirmations(&self, height: BlockHeight, cap: u32) -> u32 {
        if self.header_at(height).is_none() {
            return 0;
        }
        let depth = self.tip_height() - height + 1;
        depth.min(cap)
    }

    /// Number of stored headers, without the checkpoint.
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Stored header at `height`. Returns `None` at or below the checkpoint,
    /// because the chain keeps only the checkpoint metadata.
    pub fn header_at(&self, height: BlockHeight) -> Option<&Header> {
        if height <= self.base_height {
            return None;
        }
        let idx = (height - self.base_height - 1) as usize;
        self.headers.get(idx)
    }

    /// Stored hash at `height`. Returns the checkpoint hash at the checkpoint
    /// height, for linkage checks across the base. Returns `None` below it.
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

    /// Submits contiguous 80-byte headers from `start_height` (see module docs).
    /// `now_unix` is the enclave clock.
    ///
    /// All-or-nothing: one failure (parse, linkage, time, PoW, weaker chain)
    /// stops the batch and leaves the chain unchanged.
    pub fn submit_headers(
        &mut self,
        start_height: BlockHeight,
        raw_headers: &[Vec<u8>],
        now_unix: u64,
    ) -> Result<SubmitOutcome> {
        let tip = self.tip_height();

        // Per-call cap. The 24 MiB `framing` cap alone allows approx 314k headers.
        if raw_headers.len() > MAX_HEADERS_PER_SUBMIT {
            return Err(SpvError::BatchTooLarge {
                len: raw_headers.len(),
                max: MAX_HEADERS_PER_SUBMIT,
            });
        }

        // Empty batch: no-op. The reorg path needs a non-empty staged batch.
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

        // 0 = extension. > 0 = reorg of `reorg_depth` existing headers.
        let reorg_depth = (tip + 1).saturating_sub(start_height);
        if reorg_depth > MAX_REORG_DEPTH {
            return Err(SpvError::ReorgTooDeep {
                depth: reorg_depth,
                max: MAX_REORG_DEPTH,
            });
        }

        // Retention cap. Without PoW, headers cost nothing, so the chain could
        // grow until OOM. Fail closed: reject, do not prune.
        // Headers kept below the batch: `start_height - 1 - base_height`.
        let retained_below_batch = (start_height - 1 - self.base_height) as usize;
        let projected_len = retained_below_batch + raw_headers.len();
        if projected_len > self.max_stored_headers {
            return Err(SpvError::ChainTooLong {
                len: projected_len,
                max: self.max_stored_headers,
            });
        }

        // Predecessor at `start_height - 1`: the checkpoint or a stored header.
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

        // Commit only if the whole batch validates and, for a reorg, has more
        // work than the existing chain.
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

            let expected_bits_value = if self.network.enforces_pow() {
                let input = self.bits_input(
                    height,
                    header.time,
                    (prev_bits, prev_time),
                    start_height,
                    &staged,
                )?;
                expected_bits(&input, self.network)
            } else {
                None
            };

            let median_time_past = self.median_time_past_below(height, start_height, &staged)?;

            validate_header_full(
                &header,
                height,
                Predecessor {
                    hash: prev_hash,
                    time: prev_time,
                },
                median_time_past,
                expected_bits_value,
                self.network,
                now_unix,
            )?;

            let hash: [u8; 32] = *bitcoin::hashes::Hash::as_byte_array(&header.block_hash());
            staged.push((header, hash));
        }

        // Reorg: require strictly greater work over the rewritten range. Ties
        // go to the existing chain.
        if reorg_depth > 0 {
            let truncate_idx = (pred_height - self.base_height) as usize;
            let existing_work = sum_work(self.headers[truncate_idx..].iter())
                .expect("reorg implies non-empty existing range");
            let new_work = sum_work(staged.iter().map(|(h, _)| h))
                .expect("staged batch is non-empty when reorg_depth > 0");
            if new_work <= existing_work {
                return Err(SpvError::WeakerChain);
            }
            // Remove the displaced tail before the append, to keep linkage valid.
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

    /// The chain data the `nBits` rule of the header at `height` reads. Only
    /// the blocks the rule needs are looked up.
    fn bits_input(
        &self,
        height: BlockHeight,
        header_time: u32,
        (prev_bits, prev_time): (u32, u32),
        batch_start_height: BlockHeight,
        staged: &[(Header, BlockHash)],
    ) -> Result<BitsInput> {
        let mut input = BitsInput {
            height,
            header_time,
            prev_bits,
            prev_time,
            ..BitsInput::default()
        };
        if is_retarget_height(height) {
            let first = height
                .checked_sub(RETARGET_INTERVAL)
                .ok_or(SpvError::HeaderNotFound(0))?;
            (input.epoch_first_time, input.epoch_first_bits) =
                self.block_at(first, batch_start_height, staged)?;
        } else if self.network.allows_min_difficulty() {
            let period_start = height - height % RETARGET_INTERVAL;
            input.period_bits = self.block_at(period_start, batch_start_height, staged)?.1;
        }
        Ok(input)
    }

    /// Bitcoin Core's median time past below `height`: the median of the
    /// times of the [`MEDIAN_TIME_SPAN`] blocks before it, read as
    /// [`Self::block_at`] does. So a reorg batch is judged on the chain as it
    /// will be. The checkpoint is one of the eleven when the window reaches
    /// it. A chain from genesis takes the median of the blocks it has, as
    /// Core does. Above any other checkpoint the chain has no times below the
    /// checkpoint, and a median of fewer blocks could be stricter than
    /// Core's. So there the rule starts at the eleventh block above the
    /// checkpoint, and `None` skips it below that.
    fn median_time_past_below(
        &self,
        height: BlockHeight,
        batch_start_height: BlockHeight,
        staged: &[(Header, BlockHash)],
    ) -> Result<Option<u32>> {
        let first = height.saturating_sub(MEDIAN_TIME_SPAN as BlockHeight);
        let first = if first >= self.base_height {
            first
        } else if self.base_height == 0 {
            0
        } else {
            return Ok(None);
        };
        let mut times = Vec::with_capacity(MEDIAN_TIME_SPAN);
        for h in first..height {
            times.push(self.block_at(h, batch_start_height, staged)?.0);
        }
        Ok(Some(median_time_past(&mut times)))
    }

    /// `(time, bits)` of the block at `height`. Looks in the staged batch
    /// (first entry at `batch_start_height`), then the committed chain, then
    /// the checkpoint. The staged batch comes first: on a reorg it replaces
    /// the committed range.
    fn block_at(
        &self,
        height: BlockHeight,
        batch_start_height: BlockHeight,
        staged: &[(Header, BlockHash)],
    ) -> Result<(u32, u32)> {
        let staged_header = height
            .checked_sub(batch_start_height)
            .and_then(|i| staged.get(i as usize))
            .map(|(h, _)| h);
        if let Some(h) = staged_header.or_else(|| self.header_at(height)) {
            return Ok((h.time, h.bits.to_consensus()));
        }
        if height == self.base_height {
            return Ok((self.base_time, self.base_bits));
        }
        Err(SpvError::HeaderNotFound(height))
    }
}

/// Sum of the header work. `None` when empty, so "no work" is never compared.
fn sum_work<'a, I: IntoIterator<Item = &'a Header>>(headers: I) -> Option<Work> {
    let mut iter = headers.into_iter();
    let first = iter.next()?.work();
    Some(iter.fold(first, |acc, h| acc + h.work()))
}

#[cfg(test)]
mod tests;
