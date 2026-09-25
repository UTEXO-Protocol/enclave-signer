//! Replay guards for attestation nonces and bridge operations.
//!
//! Bounded by time as well as count, so a flooding parent cannot permanently
//! wedge cloning. Both guards are in-memory and per-instance: defense in
//! depth, never the durable record.

use std::collections::{HashMap, VecDeque};
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

/// Track nonces in memory for one enclave. (F03-AF-09)
/// Restart clears the set.
/// Each enclave has a separate set.
/// Reject duplicate nonces in the set.
/// Remove entries after their time limit.
/// Evict the oldest entry when the set is full.
/// A replay still needs valid attestation, PCRs, key binding, and HMAC.
/// The HMAC binds the request to the same recipient key and donor.
/// Persistent or shared replay protection requires a separate policy decision.
pub struct NonceReplayGuard {
    inner: Mutex<GuardState>,
    max: usize,
    ttl: Duration,
}

/// Membership map plus an insertion-ordered queue for TTL and capacity eviction.
/// Generations identify the owner of each entry so stale rollback cannot remove
/// a replacement reservation.
struct GuardState {
    seen: HashMap<[u8; 32], u64>,
    next_generation: u64,
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
                seen: HashMap::new(),
                next_generation: 0,
                order: VecDeque::new(),
            }),
            max,
            ttl,
        }
    }

    /// Reject a live replay without recording or evicting anything. A caller
    /// must still reserve before signing to close the concurrent-check race.
    pub fn check(&self, nonce: &[u8; 32]) -> Result<()> {
        let g = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("replay guard poisoned: {e}")))?;
        if g.seen.contains_key(nonce)
            && g.order
                .iter()
                .any(|(seen_at, key)| key == nonce && seen_at.elapsed() < self.ttl)
        {
            return Err(EnclaveError::NonceReplay);
        }
        Ok(())
    }

    pub fn check_and_record(&self, nonce: [u8; 32]) -> Result<()> {
        self.check_and_record_at(nonce, Instant::now()).map(|_| ())
    }

    /// Time-injected core of [`check_and_record`]. `now` is the wall point
    /// against which TTL eviction is measured; the public method passes
    /// `Instant::now()`. Split out so the eviction logic is testable
    /// without sleeping.
    pub(super) fn check_and_record_at(&self, nonce: [u8; 32], now: Instant) -> Result<u64> {
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
        if g.seen.contains_key(&nonce) {
            return Err(EnclaveError::NonceReplay);
        }

        let generation = g.next_generation;
        g.next_generation = generation.checked_add(1).ok_or_else(|| {
            EnclaveError::Internal("replay reservation generation exhausted".into())
        })?;

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
        g.seen.insert(nonce, generation);
        g.order.push_back((now, nonce));
        Ok(generation)
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
        self.reserve_at(nonce, Instant::now())
    }

    pub(super) fn reserve_at(
        &self,
        nonce: [u8; 32],
        now: Instant,
    ) -> Result<ReplayReservation<'_>> {
        let generation = self.check_and_record_at(nonce, now)?;
        Ok(ReplayReservation {
            guard: self,
            nonce,
            generation,
            committed: false,
        })
    }

    /// Remove only the entry owned by this reservation. A missing or replaced
    /// entry is left alone. Rollback must not fail, so a poisoned lock is recovered.
    fn remove(&self, nonce: &[u8; 32], generation: u64) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.seen.get(nonce) == Some(&generation) {
            g.seen.remove(nonce);
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
    generation: u64,
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
            self.guard.remove(&self.nonce, self.generation);
        }
    }
}
