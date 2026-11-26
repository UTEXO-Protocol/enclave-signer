//! SPV cross-check: the witness Bitcoin transactions of the consignment must
//! be in the in-enclave header chain with enough confirmations.
//!
//! The consignment carries an SPV proof for each witness tx. rgb-lib checks
//! each proof against a header this module serves from the enclave chain, so
//! nothing here verifies a Merkle path. Before it signs an EVM unlock, this
//! gate requires:
//!
//! 1. **Depth at the source**: [`buried_header`] serves a header only when it
//!    is `SPV_MIN_CONFIRMATIONS` deep (`BridgeConfig::spv_min_confirmations`),
//!    for every witness tx, not only the burn. Spec P8 requires this depth of
//!    each anchoring transaction. On the testnets, min-difficulty blocks
//!    count too: testnets carry no production value.
//! 2. **One chain**: validation reads headers under short locks. Afterwards
//!    [`validate_source_chain`] confirms, under one lock, that every header a
//!    proof was checked against is still in the chain and deep enough.
//!    [`ChainPins`] holds the hash and the depth of every block a check used.
//!    The signer checks both again under the chain lock before it uses the key.

#[cfg(rgb_to_evm)]
use std::num::NonZeroU32;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(rgb_to_evm)]
use bitcoin::block::Header;
#[cfg(rgb_to_evm)]
use bitcoin::hashes::Hash;

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::spv::HeaderChain;

#[cfg(rgb_to_evm)]
use super::validation::{ValidatedConsignment, WitnessBlock};

/// Maximum age of the chain tip `time`, in seconds. With an older tip the
/// enclave does not sign. This stops a host that sends real but old headers
/// and never reaches the real chain head.
///
/// The margin is wide: the parent syncs headers at its
/// `HEADER_SYNC_INTERVAL_SECS` interval, and mainnet blocks come about every
/// 10 minutes.
pub const SPV_MAX_TIP_AGE_SECS: u64 = 2 * 60 * 60;

/// Bitcoin consensus allows a block `time` up to approx 2 hours ahead of
/// network-adjusted time. The check accepts that. A larger skew fails, because
/// `time = far_future` would defeat the staleness check.
pub const SPV_MAX_TIP_FUTURE_SECS: u64 = 2 * 60 * 60;

/// Validates the Bitcoin anchoring of the RGB source before signing.
///
/// Takes the validated consignment. Checks chain freshness, and that every block validation placed a witness in is still in the chain
/// at the required depth.
#[cfg(rgb_to_evm)]
pub fn validate_source_chain(
    chain: &HeaderChain,
    validated_consignment: Option<&ValidatedConsignment>,
    now: SystemTime,
    pins: &ChainPins,
    min_confirmations: u32,
) -> Result<()> {
    let validated = validated_consignment.ok_or_else(|| {
        EnclaveError::Spv(
            "spv: RGB source requires a non-empty validated consignment, \
             but the request had no consignment bytes (or the validator \
             is not configured)"
                .into(),
        )
    })?;

    assert_chain_fresh(chain, now)?;

    // Pin every block under this lock guard. The guard ends at return, so
    // `ChainPins::assert_unchanged` checks the blocks again at signing time.
    for block in &validated.witness_blocks {
        confirm_witness_block(chain, block, min_confirmations)?;
        pins.pin(chain, block.height, min_confirmations)?;
    }

    tracing::info!(
        witnesses = validated.witness_blocks.len(),
        pinned_blocks = pins.pinned_count(),
        "SPV verification passed"
    );

    Ok(())
}

/// The header at `height`, if it is `min_confirmations` deep. rgb-lib checks
/// the SPV proofs of the consignment against the headers this serves.
#[cfg(rgb_to_evm)]
pub fn buried_header(chain: &HeaderChain, height: u32, min_confirmations: u32) -> Result<Header> {
    let tip = chain.tip_height();
    // The tip that buries `height` when every block above it proves work.
    let buried_at = height.saturating_add(min_confirmations.saturating_sub(1));

    // `header_at` returns None at or below the checkpoint and above the tip.
    // Both cases fail. Only above the tip do more headers help.
    let header = chain.header_at(height).ok_or_else(|| {
        let detail = format!("witness proof: no header at height {height} (chain tip = {tip})");
        if height > tip {
            EnclaveError::HeadersPending {
                required_tip: buried_at,
                tip,
                detail,
            }
        } else {
            EnclaveError::Spv(detail)
        }
    })?;

    // Blocks that prove work, from the proof block to the tip.
    let confs = chain.confirmations(height, min_confirmations);
    if confs < min_confirmations {
        return Err(EnclaveError::HeadersPending {
            // A block that proves no work adds no depth, so at least one more block.
            required_tip: buried_at.max(tip.saturating_add(1)),
            tip,
            detail: format!(
                "witness proof: insufficient confirmations for block_height {height} \
                 ({confs} < {min_confirmations})"
            ),
        });
    }

    Ok(*header)
}

/// The header at `height`, if it is buried now and was when the validation
/// began: at or below `safe`, the safe height read then. rgb-lib refuses a
/// witness above that height, so no header above it is served either.
#[cfg(rgb_to_evm)]
pub fn buried_header_within(
    chain: &HeaderChain,
    height: u32,
    safe: Option<NonZeroU32>,
    min_confirmations: u32,
) -> Result<Header> {
    let header = buried_header(chain, height, min_confirmations)?;
    if safe.is_none_or(|safe| height > safe.get()) {
        return Err(EnclaveError::Spv(format!(
            "witness proof: block_height {height} was not {min_confirmations} blocks deep when \
             this validation began - retry"
        )));
    }
    Ok(header)
}

/// The highest block that is `min_confirmations` deep, if the chain has one.
#[cfg(rgb_to_evm)]
pub fn safe_height(chain: &HeaderChain, min_confirmations: u32) -> Option<NonZeroU32> {
    let height = (chain.tip_height() + 1).checked_sub(min_confirmations)?;
    chain.header_at(height)?;
    NonZeroU32::new(height)
}

/// Confirms, in this view of the chain, the block validation placed a witness
/// in: the header its SPV proof was checked against, at the required depth.
#[cfg(rgb_to_evm)]
pub fn confirm_witness_block(
    chain: &HeaderChain,
    block: &WitnessBlock,
    min_confirmations: u32,
) -> Result<()> {
    let header = buried_header(chain, block.height, min_confirmations)?;
    let hash = header.block_hash().to_byte_array();
    if hash != block.hash {
        return Err(EnclaveError::Spv(format!(
            "witness proof: witness tx {} was proven in block {} at height {}, but the enclave \
             chain now holds {} there - the header chain changed during validation, refusing \
             to sign",
            hex::encode(block.txid),
            hex::encode(block.hash),
            block.height,
            hex::encode(hash)
        )));
    }
    Ok(())
}

/// Chain-freshness part of the signing precondition, with this module's
/// bounds. Signing calls it before the proof checks. The readiness probe calls
/// it too, so the two cannot drift apart.
pub fn assert_chain_fresh(chain: &HeaderChain, now: SystemTime) -> Result<()> {
    assert_chain_not_stale(
        chain,
        now,
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )
}

/// Full signing precondition on the chain only: fresh, and at least
/// `min_confirmations` blocks past the checkpoint.
///
/// `buried_header` serves no shallower header. A chain one block past the
/// checkpoint is fresh but cannot confirm anything. A freshness-only probe
/// would then report ready while every signing request fails.
pub fn assert_chain_ready(
    chain: &HeaderChain,
    now: SystemTime,
    min_confirmations: u32,
) -> Result<()> {
    assert_chain_fresh(chain, now)?;

    let depth = chain.confirmations(chain.checkpoint().height + 1, min_confirmations);
    if depth < min_confirmations {
        return Err(EnclaveError::Spv(format!(
            "spv: chain is only {depth} block(s) past the checkpoint, need \
             {min_confirmations} before a proof can reach the required \
             confirmation depth"
        )));
    }

    Ok(())
}

/// Fails if the chain tip is too old, or too far in the future, against the
/// wall clock. `now` is a parameter for tests. Production passes
/// `SystemTime::now()`.
///
/// Threat model: a host that sends real but old headers makes a valid chain
/// with an old tip. An old block then looks well confirmed.
pub fn assert_chain_not_stale(
    chain: &HeaderChain,
    now: SystemTime,
    max_age: Duration,
    max_future: Duration,
) -> Result<()> {
    let now_unix = now
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::Internal(format!("system clock is before UNIX_EPOCH: {e}")))?
        .as_secs();
    let tip_time = u64::from(chain.tip_time());

    // Future bound: Bitcoin consensus allows approx 2h of future skew per
    // block. Reject more than `max_future`.
    if let Some(future_skew) = tip_time.checked_sub(now_unix) {
        if future_skew > max_future.as_secs() {
            return Err(EnclaveError::Spv(format!(
                "spv: chain tip is {future_skew}s in the future (now = {now_unix}, \
                 tip_time = {tip_time}, max future skew = {}s)",
                max_future.as_secs()
            )));
        }
        return Ok(());
    }

    // Past bound: the normal case.
    let age = now_unix.saturating_sub(tip_time);
    if age > max_age.as_secs() {
        return Err(EnclaveError::Spv(format!(
            "spv: chain tip is too stale (now = {now_unix}, tip_time = {tip_time}, \
             age = {age}s, max age = {}s) - listener may be frozen or hostile",
            max_age.as_secs()
        )));
    }

    Ok(())
}

/// One pinned block: its hash and the depth the check required at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pin {
    hash: [u8; 32],
    /// Confirmations the check required. `1` pins presence only.
    depth: u32,
}

/// The blocks the SPV checks used, checked again before the key is used.
///
/// Each check releases the header-chain lock when it returns. Another worker
/// can then accept a reorg before signing.
///
/// A check records every block it used here, with the depth it required.
/// `assert_unchanged` reads those heights again. It fails if a hash changed or
/// a block is shallower than required. An extension touches no pinned hash
/// and only deepens the blocks, so signing continues. A replacement chain of
/// fewer, heavier blocks above a pin keeps the hash and lowers the depth. If
/// that leaves the block shallower than its check required, the depth check
/// refuses the signature. The request fails, and the caller must send it
/// again when the block is deep enough.
#[derive(Debug, Default)]
pub struct ChainPins {
    pinned: std::sync::Mutex<std::collections::BTreeMap<u32, Pin>>,
}

impl ChainPins {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the chain hash at `height` and the `depth` the check required
    /// there. Call it under the check's own lock guard, so the pin and the
    /// check see one chain.
    ///
    /// A second pin of the same height keeps the larger depth. A different
    /// hash means two checks read two chains. That is the race this guards,
    /// so it fails closed.
    #[cfg(rgb_to_evm)]
    pub fn pin(&self, chain: &HeaderChain, height: u32, depth: u32) -> Result<()> {
        let hash = chain.hash_at(height).ok_or_else(|| {
            EnclaveError::Spv(format!(
                "chain pin: enclave holds no header at height {height} (chain tip = {}) \
                 - cannot pin a block the checks relied on",
                chain.tip_height()
            ))
        })?;

        let mut pinned = self.lock()?;
        let pin = pinned.entry(height).or_insert(Pin { hash, depth });
        if pin.hash != hash {
            return Err(EnclaveError::Spv(format!(
                "chain pin: height {height} was pinned as {} but now reads {} \
                 - the header chain changed between two validation checks, refusing to sign",
                hex::encode(pin.hash),
                hex::encode(hash)
            )));
        }
        pin.depth = pin.depth.max(depth);
        Ok(())
    }

    /// Check every pinned block against `chain`: the same hash, and at least
    /// the required depth. Call it under a fresh lock, just before the signing
    /// key is used.
    pub fn assert_unchanged(&self, chain: &HeaderChain) -> Result<()> {
        let pinned = self.lock()?;

        for (&height, pin) in pinned.iter() {
            match chain.hash_at(height) {
                Some(current) if current == pin.hash => {}
                Some(current) => {
                    return Err(EnclaveError::Spv(format!(
                        "chain reorg after validation: height {height} was {} when checked but is \
                         now {} (chain tip = {}) - refusing to sign against a replaced block",
                        hex::encode(pin.hash),
                        hex::encode(current),
                        chain.tip_height()
                    )));
                }
                None => {
                    return Err(EnclaveError::Spv(format!(
                        "chain reorg after validation: height {height} was {} when checked but the \
                         enclave now holds no header there (chain tip = {}) - refusing to sign",
                        hex::encode(pin.hash),
                        chain.tip_height()
                    )));
                }
            }
            let depth = chain.tip_height() - height + 1;
            if depth < pin.depth {
                return Err(EnclaveError::Spv(format!(
                    "chain reorg after validation: height {height} was at least {} blocks deep \
                     when checked but is {depth} deep now (chain tip = {}) - refusing to sign with \
                     fewer confirmations than the check required",
                    pin.depth,
                    chain.tip_height()
                )));
            }
        }

        tracing::debug!(
            pinned_blocks = pinned.len(),
            tip_height = chain.tip_height(),
            "chain pins re-checked at key use"
        );
        Ok(())
    }

    /// Count of pinned blocks. For logs and tests.
    pub fn pinned_count(&self) -> usize {
        self.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Fails on a poisoned lock, so a caller cannot read it as "no pins".
    pub fn none_pinned(&self) -> Result<bool> {
        Ok(self.lock()?.is_empty())
    }

    /// Fail on a poisoned lock. A panic left the pin set in an unknown state.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, std::collections::BTreeMap<u32, Pin>>> {
        self.pinned
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("chain pin set lock poisoned: {e}")))
    }
}

// SPV proof and chain-pin checks run on the RGB -> EVM path only.
#[cfg(all(test, rgb_to_evm))]
mod tests;

/// The pin set checked before key use.
#[cfg(all(test, rgb_to_evm))]
mod chain_pin_tests;
