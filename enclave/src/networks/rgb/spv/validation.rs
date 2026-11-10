//! Per-header validation functions. They hold no chain state.
//!
//! `HeaderChain` gives the prior-header context. These functions check the
//! linkage to the predecessor, PoW and the `nBits` for the height. They also
//! check the time against the enclave clock and against the median time past
//! of the blocks below. On testnet4 they also check the BIP94 timewarp rule.
//!
//! Per network:
//!
//! - Mainnet: PoW and retarget checks. `expected_bits` computes the required
//!   `nBits`.
//! - Testnet3 and testnet4: the same, plus the 20-minute rule. A block more
//!   than 20 minutes after its parent may use the minimum difficulty. Other
//!   blocks carry the bits of the period's first block. Testnet4 adds BIP94:
//!   the retarget starts from the first block of the period, and that block
//!   may not be more than 600 s older than its parent.
//! - Signet: this implementation skips PoW and `nBits` checks. It also cannot
//!   check the BIP-325 challenge because the request has no coinbase witness.
//!   Per-header validation checks only chain linkage, the clock bound and the
//!   median-time-past rule.
//! - Regtest: chain linkage, the clock bound and the median-time-past rule
//!   only.

use bitcoin::block::Header;
use bitcoin::pow::CompactTarget;

use crate::networks::rgb::spv::types::{BlockHeight, Network, Result, SpvError};

/// Bitcoin's difficulty-retarget interval: every 2016 blocks.
pub const RETARGET_INTERVAL: BlockHeight = 2016;

/// BIP94: how far a period's first block may be older than its parent.
pub const MAX_TIMEWARP_SECS: u32 = 600;

/// How far a header may be ahead of the enclave clock, as Bitcoin Core's
/// `MAX_FUTURE_BLOCK_TIME`.
pub const MAX_FUTURE_BLOCK_TIME_SECS: u64 = 2 * 60 * 60;

/// Blocks in Bitcoin Core's median-time-past window (`nMedianTimeSpan`).
pub const MEDIAN_TIME_SPAN: usize = 11;

/// Returns true when `height` is the start of a new retarget epoch.
pub fn is_retarget_height(height: BlockHeight) -> bool {
    height.is_multiple_of(RETARGET_INTERVAL)
}

/// Verifies that `header.prev_blockhash` equals `expected_prev_hash`
/// (internal byte order).
pub fn check_linkage(
    header: &Header,
    expected_prev_hash: &[u8; 32],
    height: BlockHeight,
) -> Result<()> {
    let prev_bytes: [u8; 32] = *header.prev_blockhash.as_ref();
    if &prev_bytes != expected_prev_hash {
        return Err(SpvError::ChainLinkage { height });
    }
    Ok(())
}

/// PoW check: `block_hash <= target_from_nBits(header.bits)`. Skipped on
/// signet and regtest (see module docs).
pub fn check_pow(header: &Header, height: BlockHeight, network: Network) -> Result<()> {
    if !network.enforces_pow() {
        return Ok(());
    }
    let target = header.target();
    header
        .validate_pow(target)
        .map_err(|_| SpvError::PowFailed { height })?;
    Ok(())
}

/// What the `nBits` rule of a header reads from the chain below it.
#[derive(Debug, Clone, Copy, Default)]
pub struct BitsInput {
    pub height: BlockHeight,
    pub header_time: u32,
    /// `nBits` and `time` of the block at `height - 1`.
    pub prev_bits: u32,
    pub prev_time: u32,
    /// `nBits` of the period's first block (`height - height % 2016`). Read
    /// off a boundary on min-difficulty networks only.
    pub period_bits: u32,
    /// `nBits` and `time` of the block at `height - 2016`. Read at a boundary
    /// only.
    pub epoch_first_bits: u32,
    pub epoch_first_time: u32,
}

/// Computes the required `nBits` for a header, as Bitcoin Core
/// `GetNextWorkRequired` does.
///
/// Off a boundary, a min-difficulty network takes the minimum when the header
/// is more than 20 minutes after its parent. Otherwise Core walks back to the
/// last block not mined under that rule. In a valid period that block carries
/// the bits of the period's first block, which never takes the exception.
///
/// Returns `None` on signet and regtest. The caller then skips the `nBits`
/// check.
pub fn expected_bits(input: &BitsInput, network: Network) -> Option<u32> {
    if !network.enforces_pow() {
        return None;
    }
    let params = network.as_bitcoin_params();
    if !is_retarget_height(input.height) {
        if !network.allows_min_difficulty() {
            return Some(input.prev_bits);
        }
        let min_difficulty_after = u64::from(input.prev_time) + 2 * params.pow_target_spacing;
        if u64::from(input.header_time) > min_difficulty_after {
            return Some(network.pow_limit_bits());
        }
        return Some(input.period_bits);
    }

    // Boundary: BIP94 retargets from the period's first block, which cannot
    // be a min-difficulty block. Networks without BIP94 use the last block.
    let base = if network.bip94() {
        input.epoch_first_bits
    } else {
        input.prev_bits
    };
    let actual_timespan = u64::from(input.prev_time.saturating_sub(input.epoch_first_time));
    let next = CompactTarget::from_next_work_required(
        CompactTarget::from_consensus(base),
        actual_timespan,
        params,
    );
    Some(next.to_consensus())
}

/// BIP94 timewarp rule: a period's first block may not be more than
/// [`MAX_TIMEWARP_SECS`] older than its parent.
pub fn check_timewarp(
    height: BlockHeight,
    time: u32,
    prev_time: u32,
    network: Network,
) -> Result<()> {
    if !network.bip94() || !is_retarget_height(height) {
        return Ok(());
    }
    if u64::from(time) + u64::from(MAX_TIMEWARP_SECS) < u64::from(prev_time) {
        return Err(SpvError::Timewarp {
            height,
            time,
            prev_time,
        });
    }
    Ok(())
}

/// Core's `time-too-new` rule against the enclave clock (`now_unix`). On the
/// testnets it also bounds how fast a host fork can retarget down: free
/// blocks cannot be dated ahead, so a 4x drop needs 8 weeks of real time.
pub fn check_future_time(height: BlockHeight, time: u32, now_unix: u64) -> Result<()> {
    if u64::from(time) > now_unix.saturating_add(MAX_FUTURE_BLOCK_TIME_SECS) {
        return Err(SpvError::TimeTooNew {
            height,
            time,
            now: now_unix,
        });
    }
    Ok(())
}

/// The median time past of one window of block times, as Bitcoin Core
/// computes it: the middle value of the sorted times. `times` holds at most
/// [`MEDIAN_TIME_SPAN`] values and at least one.
pub fn median_time_past(times: &mut [u32]) -> u32 {
    times.sort_unstable();
    times[times.len() / 2]
}

/// Core's `time-too-old` rule: a block's time is newer than the median time
/// past of the [`MEDIAN_TIME_SPAN`] blocks below it. Near genesis a block has
/// fewer blocks below it, and Core takes the median of those. The rule applies
/// on every network, as in Core. `None` skips the rule. Above a checkpoint
/// that is not genesis, the chain has no times below the checkpoint. A median
/// of fewer blocks could then be stricter than Core's. So there the rule
/// starts where the chain holds all eleven times.
pub fn check_time_too_old(
    height: BlockHeight,
    time: u32,
    median_time_past: Option<u32>,
) -> Result<()> {
    if let Some(median_time_past) = median_time_past {
        if time <= median_time_past {
            return Err(SpvError::TimeTooOld {
                height,
                time,
                median_time_past,
            });
        }
    }
    Ok(())
}

/// The block below a header: its hash (internal byte order) and time.
#[derive(Debug, Clone, Copy)]
pub struct Predecessor {
    pub hash: [u8; 32],
    pub time: u32,
}

/// Checks linkage, the timewarp rule, the clock bound, the median-time-past
/// bound (if given), then `nBits` (if given), then PoW (if the network
/// enforces it). `HeaderChain::submit_headers` calls it.
pub fn validate_header_full(
    header: &Header,
    height: BlockHeight,
    prev: Predecessor,
    median_time_past: Option<u32>,
    expected_bits_value: Option<u32>,
    network: Network,
    now_unix: u64,
) -> Result<()> {
    check_linkage(header, &prev.hash, height)?;
    check_timewarp(height, header.time, prev.time, network)?;
    check_future_time(height, header.time, now_unix)?;
    check_time_too_old(height, header.time, median_time_past)?;

    if let Some(expected) = expected_bits_value {
        let got = header.bits.to_consensus();
        if got != expected {
            return Err(SpvError::BitsMismatch {
                height,
                got,
                expected,
            });
        }
    }

    check_pow(header, height, network)?;
    Ok(())
}

#[cfg(test)]
mod tests;
