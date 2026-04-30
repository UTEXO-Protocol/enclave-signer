//! In-memory Bitcoin header chain.
//!
//! The chain starts at a compile-time `Checkpoint` (height + hash + bits +
//! time) and grows forward as the Listener pushes batches of contiguous
//! 80-byte headers via `submit_headers`. Each header is validated against
//! its predecessor (chain linkage + PoW + nBits) before being appended.
//!
//! ## What this module does NOT do (yet)
//!
//! - **Reorgs.** `submit_headers` is strictly append-only. A header that
//!   doesn't extend the current tip is rejected. Bounded reorg support
//!   (replace last N headers when a deeper alternative is presented) is a
//!   follow-up. Confirmation depth ≥ 6 means small reorgs at the tip are
//!   tolerable for signing decisions.
//! - **BIP-325 signet signature.** Out of scope for PR 2, see validation.rs.
//! - **Header staleness.** Refusing to use a stale tip for confirmation
//!   counts is PR 4.

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;

use crate::spv::checkpoint::Checkpoint;
use crate::spv::types::{BlockHash, BlockHeight, Network, Result, SpvError};
use crate::spv::validation::{
    expected_bits, is_retarget_height, validate_header_full, RETARGET_INTERVAL,
};

/// Outcome of pushing a batch of headers.
#[derive(Debug, Clone, Copy)]
pub struct SubmitOutcome {
    pub last_block_height: BlockHeight,
    pub last_block_hash: BlockHash,
    /// Number of headers from the batch that were accepted before either the
    /// batch ran out or one was rejected. The current implementation aborts
    /// on the first rejection, so this is "headers up to but not including
    /// the bad one". A future PR may surface partial acceptance differently.
    pub headers_accepted: u32,
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

    /// Append a batch of contiguous 80-byte headers starting at
    /// `start_height`. Each header is parsed, linked to its predecessor,
    /// and (on networks with PoW) its bits/PoW are checked.
    ///
    /// Validation is strict: the first failure aborts the batch and the
    /// chain is left exactly as it was before this call.
    pub fn submit_headers(
        &mut self,
        start_height: BlockHeight,
        raw_headers: &[Vec<u8>],
    ) -> Result<SubmitOutcome> {
        let expected_start = self.tip_height() + 1;
        if start_height != expected_start {
            return Err(SpvError::NonContiguous {
                got: start_height,
                expected: expected_start,
            });
        }

        // Stage parsed headers + hashes; only commit if the whole batch validates.
        let mut staged: Vec<(Header, BlockHash)> = Vec::with_capacity(raw_headers.len());

        for (i, raw) in raw_headers.iter().enumerate() {
            let header: Header = deserialize(raw).map_err(|e| SpvError::HeaderParse {
                index: i,
                message: e.to_string(),
            })?;

            let height = start_height + i as BlockHeight;

            // Predecessor lookup: previous staged item, or the chain tip
            // (which may be the checkpoint itself if we're staging the
            // first-ever header).
            let (prev_hash, prev_bits, prev_time) = if let Some((prev_h, prev_hash)) = staged.last()
            {
                (*prev_hash, prev_h.bits.to_consensus(), prev_h.time)
            } else if let Some(last) = self.headers.last() {
                let prev_hash = *self.hashes.last().expect("hashes parallel to headers");
                (prev_hash, last.bits.to_consensus(), last.time)
            } else {
                (
                    self.checkpoint.hash,
                    self.checkpoint.bits,
                    self.checkpoint.time,
                )
            };

            let epoch_start_time = self.epoch_start_time(height, &staged)?;

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

        // All-or-nothing: only after every header validates do we mutate state.
        let accepted = staged.len() as u32;
        for (header, hash) in staged {
            self.headers.push(header);
            self.hashes.push(hash);
        }

        Ok(SubmitOutcome {
            last_block_height: self.tip_height(),
            last_block_hash: self.tip_hash(),
            headers_accepted: accepted,
        })
    }

    /// Find the timestamp of the block at the start of the retarget epoch
    /// containing `height`. Looks first in the staged batch, then in the
    /// committed chain, then at the checkpoint (legitimate when the
    /// checkpoint sits exactly on a retarget boundary).
    ///
    /// Only meaningful at retarget boundaries; on non-boundary heights the
    /// caller ignores the value.
    fn epoch_start_time(&self, height: BlockHeight, staged: &[(Header, BlockHash)]) -> Result<u32> {
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

        // Staged batch?
        if target_height > self.tip_height() {
            let staged_idx = (target_height - self.tip_height() - 1) as usize;
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
        assert_eq!(chain.tip_height(), 105);
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn rejects_non_contiguous_batch() {
        let (mut chain, raws) = synthetic_regtest_setup();
        let err = chain.submit_headers(102, &raws).unwrap_err();
        assert!(matches!(
            err,
            SpvError::NonContiguous {
                got: 102,
                expected: 101
            }
        ));
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
    }
}
