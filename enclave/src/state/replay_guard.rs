//! Replay guards for attestation nonces and bridge operations.
//!
//! Both guards have a time limit and a count limit, so a flooding parent
//! cannot block cloning permanently. Both are in-memory and per instance.
//! They are defense in depth, not the durable record.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{EnclaveError, Result};

/// Default TTL for a recorded nonce. The cloning handshake takes seconds,
/// so one hour gives a large margin.
pub(super) const DEFAULT_NONCE_TTL: Duration = Duration::from_secs(60 * 60);

/// Default maximum count of recorded nonces.
pub(super) const DEFAULT_NONCE_MAX: usize = 10_000;

/// Default TTL for the PSBT bridge-operation dedup guard.
/// The listener can retry an unsettled EVM->RGB deposit. Thus the window must
/// be longer than normal retry and confirmation latency.
/// See [`super::EnclaveState::op_replay_guard`].
pub(super) const DEFAULT_OP_DEDUP_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum count of recorded bridge operations (approx 8 MB at 80 bytes each).
/// On overflow, the guard evicts the oldest entry and does not block signing.
/// See [`super::EnclaveState::op_replay_guard`].
pub(super) const DEFAULT_OP_DEDUP_MAX: usize = 100_000;

/// In-memory nonce set for one enclave. (F03-AF-09)
/// It refuses duplicate nonces. A restart clears the set.
/// Entries expire after the TTL. When the set is full, the oldest entry goes.
/// A replay still needs valid attestation, PCRs, key binding, and HMAC.
/// The HMAC binds the request to the same recipient key and donor.
/// Persistent or shared replay protection needs a separate policy decision.
pub struct NonceReplayGuard {
    inner: Mutex<GuardState>,
    max: usize,
    ttl: Duration,
}

/// Membership map plus an insertion-ordered queue for TTL and capacity eviction.
/// A generation identifies the owner of each entry. Thus a stale rollback
/// cannot remove a replacement reservation.
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

    /// Refuse a live replay. Does not record or evict.
    /// The caller must still reserve before signing to close the concurrent race.
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

    /// Core of [`Self::check_and_record`] with an explicit `now` for TTL eviction.
    /// Tests use it to check eviction without a sleep.
    pub(super) fn check_and_record_at(&self, nonce: [u8; 32], now: Instant) -> Result<u64> {
        let mut g = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("replay guard poisoned: {}", e)))?;

        // Evict expired entries. `order` is oldest-first, so stop at the
        // first live entry.
        while let Some(&(seen_at, old)) = g.order.front() {
            if now.saturating_duration_since(seen_at) >= self.ttl {
                g.order.pop_front();
                g.seen.remove(&old);
            } else {
                break;
            }
        }

        if g.seen.contains_key(&nonce) {
            return Err(EnclaveError::NonceReplay);
        }

        let generation = g.next_generation;
        g.next_generation = generation.checked_add(1).ok_or_else(|| {
            EnclaveError::Internal("replay reservation generation exhausted".into())
        })?;

        // Capacity limit: evict the oldest entries so a burst cannot block cloning.
        while g.seen.len() >= self.max {
            match g.order.pop_front() {
                Some((_, old)) => {
                    g.seen.remove(&old);
                }
                None => break,
            }
        }

        g.seen.insert(nonce, generation);
        g.order.push_back((now, nonce));
        Ok(generation)
    }

    /// Record `nonce` with [`check_and_record`](Self::check_and_record) and
    /// return a [`ReplayReservation`]. The reservation removes the record on
    /// drop, unless [`ReplayReservation::commit`] is called first.
    ///
    /// Reserve before the fallible work. Commit after it succeeds.
    /// A failure between them releases the key, so a legitimate retry can run.
    /// A concurrent duplicate is still refused at reserve time.
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

    /// Remove only the entry that this reservation owns.
    /// Rollback must not fail, so it recovers a poisoned lock.
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

/// Reservation from [`NonceReplayGuard::reserve`]. On drop it removes the
/// nonce, unless [`Self::commit`] was called. A failed operation does not
/// consume the key.
#[must_use = "an un-committed reservation rolls back on drop"]
pub struct ReplayReservation<'a> {
    guard: &'a NonceReplayGuard,
    nonce: [u8; 32],
    generation: u64,
    committed: bool,
}

impl ReplayReservation<'_> {
    /// Keep the record after the guarded operation succeeds.
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
