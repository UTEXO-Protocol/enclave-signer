//! Replay guards for attestation nonces and bridge operations.
//!
//! Bounded by time as well as count, so a flooding parent cannot permanently
//! wedge cloning. Both guards are in-memory and per-instance: defense in
//! depth, never the durable record.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{EnclaveError, Result};

/// Default time-to-live for a recorded nonce. The cloning handshake completes
/// in seconds, so an hour is generous. Entries self-evict after the TTL.
pub(super) const DEFAULT_NONCE_TTL: Duration = Duration::from_secs(60 * 60);

/// Default hard memory ceiling on recorded nonces.
pub(super) const DEFAULT_NONCE_MAX: usize = 10_000;

/// Default TTL for the PSBT bridge-operation dedup guard. Much longer than the
/// nonce TTL: an EVM->RGB deposit can be retried while unsettled, so the window
/// must outlast normal listener retry/confirmation latency. See
/// [`EnclaveState::op_replay_guard`].
pub(super) const DEFAULT_OP_DEDUP_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Hard memory ceiling on recorded bridge operations, ~8 MB at ~80 bytes per
/// entry. On overflow inside one TTL window the oldest entry is evicted rather
/// than wedging signing. See [`EnclaveState::op_replay_guard`].
pub(super) const DEFAULT_OP_DEDUP_MAX: usize = 100_000;

/// Replay guard for attestation nonces, bounded by **time** (not just
/// count) so a flooding parent cannot permanently wedge cloning.
///
/// Every incoming peer attestation contributes its nonce, and duplicates are
/// rejected. Each entry carries the instant it was seen, and `check_and_record`
/// first evicts entries older than `ttl`. `max` is a hard memory ceiling: when
/// the set is still full after eviction, the oldest entry is dropped to admit
/// the new one.
///
/// Rejecting when full instead would let a parent flood `max` distinct nonces
/// and block every legitimate handshake. The trade-off is a
/// bounded replay window: replaying an evicted nonce only re-seals the seed to
/// the encryption pubkey already bound inside that attestation.
pub struct NonceReplayGuard {
    inner: Mutex<GuardState>,
    max: usize,
    ttl: Duration,
}

/// Membership set plus an insertion-ordered (oldest at front) queue that
/// mirrors it. The queue drives both TTL eviction and oldest-first
/// overflow eviction; the set gives O(1) duplicate detection.
struct GuardState {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<(Instant, [u8; 32])>,
}

impl Default for NonceReplayGuard {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_NONCE_MAX, DEFAULT_NONCE_TTL)
    }
}

impl NonceReplayGuard {
    pub fn with_capacity(max: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(GuardState {
                seen: HashSet::new(),
                order: VecDeque::new(),
            }),
            max,
            ttl,
        }
    }

    pub fn check_and_record(&self, nonce: [u8; 32]) -> Result<()> {
        self.check_and_record_at(nonce, Instant::now())
    }

    /// Time-injected core of [`check_and_record`]. `now` is the wall point
    /// against which TTL eviction is measured; the public method passes
    /// `Instant::now()`. Split out so the eviction logic is testable
    /// without sleeping.
    pub(super) fn check_and_record_at(&self, nonce: [u8; 32], now: Instant) -> Result<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("replay guard poisoned: {}", e)))?;

        // 1. Evict everything older than the TTL. `order` is oldest-first,
        //    so stop at the first entry still within the window.
        while let Some(&(seen_at, old)) = g.order.front() {
            if now.saturating_duration_since(seen_at) >= self.ttl {
                g.order.pop_front();
                g.seen.remove(&old);
            } else {
                break;
            }
        }

        // 2. Replay check against what survives.
        if g.seen.contains(&nonce) {
            return Err(EnclaveError::NonceReplay);
        }

        // 3. Hard memory ceiling. If a burst filled the set inside one TTL
        //    window, drop the oldest entries to admit the new nonce rather
        // than wedging cloning.
        while g.seen.len() >= self.max {
            match g.order.pop_front() {
                Some((_, old)) => {
                    g.seen.remove(&old);
                }
                None => break,
            }
        }

        // 4. Record.
        g.seen.insert(nonce);
        g.order.push_back((now, nonce));
        Ok(())
    }

    /// Reserve `nonce`: [`check_and_record`](Self::check_and_record) it and
    /// return an RAII [`ReplayReservation`] that ROLLS BACK the record on drop
    /// unless [`ReplayReservation::commit`] is called first.
    ///
    /// Reserve before the fallible work, commit after it succeeds. Any failure
    /// in between drops the reservation and releases the key, so a transient
    /// error does not self-block a legitimate retry. Reserving
    /// still rejects a concurrent duplicate up front.
    pub fn reserve(&self, nonce: [u8; 32]) -> Result<ReplayReservation<'_>> {
        self.check_and_record(nonce)?;
        Ok(ReplayReservation {
            guard: self,
            nonce,
            committed: false,
        })
    }

    /// Drop a previously recorded nonce. No-op if it is absent (already
    /// TTL-evicted). Only used by [`ReplayReservation`] rollback, so it must not
    /// fail: a poisoned lock is recovered rather than propagated.
    fn remove(&self, nonce: &[u8; 32]) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.seen.remove(nonce) {
            if let Some(pos) = g.order.iter().position(|(_, n)| n == nonce) {
                g.order.remove(pos);
            }
        }
    }

    #[cfg(test)]
    pub fn seen_count(&self) -> usize {
        self.inner.lock().map(|g| g.seen.len()).unwrap_or(0)
    }
}

/// RAII reservation returned by [`NonceReplayGuard::reserve`]. On drop it
/// removes the reserved nonce UNLESS [`Self::commit`] was called, so a guarded
/// operation that fails before committing leaves the key un-consumed.
#[must_use = "an un-committed reservation rolls back on drop"]
pub struct ReplayReservation<'a> {
    guard: &'a NonceReplayGuard,
    nonce: [u8; 32],
    committed: bool,
}

impl ReplayReservation<'_> {
    /// Keep the record: the guarded operation committed.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for ReplayReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.guard.remove(&self.nonce);
        }
    }
}
