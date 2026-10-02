//! Tests for the phase machine and both replay guards.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bitcoin::Network;

use crate::cloning::CloneSession;
use crate::error::EnclaveError;

use super::cloning_session::CLONING_SESSION_TTL;
use super::enclave::*;
use super::replay_guard::*;

use super::*;

#[test]
fn seed_export_counter_increments_monotonically() {
    // Each successful export increases the counter. (F03-AF-10)
    let state = EnclaveState::new(Network::Bitcoin);
    assert_eq!(state.seed_export_count(), 0);
    assert_eq!(state.record_seed_export(&[1u8; 32]), 1);
    assert_eq!(state.record_seed_export(&[2u8; 32]), 2);
    assert_eq!(state.record_seed_export(&[3u8; 32]), 3);
    assert_eq!(state.seed_export_count(), 3);
}

// Set the cap directly to avoid environment changes in parallel tests. (F03-AF-10)
#[test]
fn export_hard_cap_blocks_after_quota() {
    let mut state = EnclaveState::new(Network::Bitcoin);
    state.seed_export_hard_cap = 2;
    let pk = [7u8; 32];
    assert_eq!(state.reserve_export_quota().unwrap().commit(&pk), 1);
    assert_eq!(state.reserve_export_quota().unwrap().commit(&pk), 2);
    // The export after the cap is refused before sealing.
    let err = state.reserve_export_quota().err().unwrap();
    assert!(matches!(err, EnclaveError::Clone(_)));
}

// The default cap 0 never blocks exports.
#[test]
fn export_hard_cap_disabled_by_default() {
    let state = EnclaveState::new(Network::Bitcoin);
    assert_eq!(state.seed_export_hard_cap, 0);
    let pk = [9u8; 32];
    for _ in 0..1000 {
        state.reserve_export_quota().unwrap().commit(&pk);
    }
    assert!(state.reserve_export_quota().is_ok());
    assert_eq!(state.seed_export_count.load(Ordering::Relaxed), 1000);
    assert_eq!(state.seed_export_slots.load(Ordering::Relaxed), 0);
}

#[test]
fn export_hard_cap_releases_failed_reservations() {
    let mut state = EnclaveState::new(Network::Bitcoin);
    state.seed_export_hard_cap = 2;
    let first = state.reserve_export_quota().unwrap();
    let second = state.reserve_export_quota().unwrap();
    assert!(state.reserve_export_quota().is_err());
    assert_eq!(state.seed_export_count.load(Ordering::Relaxed), 0);
    drop(first); // e.g. a replay error before sealing
    state.reserve_export_quota().unwrap().commit(&[1; 32]);
    assert!(state.reserve_export_quota().is_err());
    drop(second); // e.g. a failed donor attestation after sealing
    state.reserve_export_quota().unwrap().commit(&[2; 32]);
    assert!(state.reserve_export_quota().is_err());
    assert_eq!(state.seed_export_count.load(Ordering::Relaxed), 2);
}

#[test]
fn export_hard_cap_bounds_concurrent_in_flight_exports() {
    use std::sync::Barrier;
    let mut state = EnclaveState::new(Network::Bitcoin);
    state.seed_export_hard_cap = 2;
    let start = Barrier::new(16);
    let reserved = Barrier::new(16);
    let accepted = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    let slot = state.reserve_export_quota();
                    // All workers try admission before any export is recorded.
                    // This exercises the concurrent reservation race.
                    reserved.wait();
                    if let Ok(slot) = slot {
                        slot.commit(&[3; 32]);
                        true
                    } else {
                        false
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(accepted, 2);
    assert_eq!(state.seed_export_count.load(Ordering::Relaxed), 2);
    assert!(state.reserve_export_quota().is_err());
}

// Replace an expired session without a restart. (F03-AF-01)
#[test]
fn enter_cloning_replaces_expired_but_protects_live_session() {
    let state = EnclaveState::new(Network::Bitcoin);
    let t0 = Instant::now();

    state
        .enter_cloning_at(
            CloningSession::new_at(CloneSession::new(), [1u8; 20], t0),
            t0,
        )
        .unwrap();
    assert_eq!(state.phase_name(), "cloning");

    // A second request is refused while the session is valid.
    let err = state
        .enter_cloning_at(
            CloningSession::new_at(CloneSession::new(), [2u8; 20], t0),
            t0 + Duration::from_secs(10),
        )
        .unwrap_err();
    assert!(matches!(err, EnclaveError::AlreadyInitialized));
    state
        .with_cloning_session(|s| {
            assert_eq!(s.cluster_public_key, [1u8; 20], "live session untouched");
            Ok(())
        })
        .unwrap();

    // The session can be replaced after its time limit.
    let later = t0 + CLONING_SESSION_TTL + Duration::from_secs(1);
    state
        .enter_cloning_at(
            CloningSession::new_at(CloneSession::new(), [3u8; 20], later),
            later,
        )
        .unwrap();
    state
        .with_cloning_session(|s| {
            assert_eq!(s.cluster_public_key, [3u8; 20], "expired session replaced");
            Ok(())
        })
        .unwrap();
}

#[test]
fn enter_cloning_rejected_once_active() {
    let state = EnclaveState::new(Network::Bitcoin);
    state.initialize_from_seed([42u8; 64]).unwrap();
    let err = state
        .enter_cloning(CloningSession::new(CloneSession::new(), [1u8; 20]))
        .unwrap_err();
    assert!(matches!(err, EnclaveError::AlreadyInitialized));
}

#[test]
fn new_state_is_initial() {
    let state = EnclaveState::new(Network::Bitcoin);
    assert_eq!(state.phase_name(), "initial");
    assert!(!state.is_initialized());
}

#[test]
fn initial_to_active_via_entropy() {
    let state = EnclaveState::new(Network::Bitcoin);
    let mut entropy = [1u8; 32];
    state.initialize_from_entropy(&mut entropy).unwrap();
    assert_eq!(state.phase_name(), "active");
    assert!(state.is_initialized());
}

#[test]
fn active_to_active_via_entropy_rejected() {
    let state = EnclaveState::new(Network::Bitcoin);
    let mut entropy = [1u8; 32];
    state.initialize_from_entropy(&mut entropy).unwrap();

    let mut entropy2 = [2u8; 32];
    let err = state.initialize_from_entropy(&mut entropy2).unwrap_err();
    assert!(matches!(err, EnclaveError::AlreadyInitialized));
}

#[test]
fn initial_to_active_via_seed() {
    let state = EnclaveState::new(Network::Bitcoin);
    state.initialize_from_seed([42u8; 64]).unwrap();
    assert_eq!(state.phase_name(), "active");
}

#[test]
fn initial_to_active_via_mnemonic() {
    let state = EnclaveState::new(Network::Bitcoin);
    state
        .initialize_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
    assert_eq!(state.phase_name(), "active");
}

#[test]
fn get_keys_on_initial_errors() {
    let state = EnclaveState::new(Network::Bitcoin);
    assert!(matches!(
        state.get_keys(),
        Err(EnclaveError::KeyNotInitialized)
    ));
}

#[test]
fn sign_evm_on_initial_errors() {
    let state = EnclaveState::new(Network::Bitcoin);
    let err = state.sign_evm(&[0u8; 32]).unwrap_err();
    assert!(matches!(err, EnclaveError::KeyNotInitialized));
}

#[test]
fn sign_psbt_on_initial_errors() {
    let state = EnclaveState::new(Network::Bitcoin);
    let err = state.sign_psbt(&[0u8; 8]).unwrap_err();
    assert!(matches!(err, EnclaveError::KeyNotInitialized));
}

#[test]
fn cloning_phase_is_not_initialized() {
    let state = EnclaveState::new(Network::Bitcoin);
    *state.inner.lock().unwrap() =
        Phase::Cloning(CloningSession::new(CloneSession::new(), [0u8; 20]));
    assert_eq!(state.phase_name(), "cloning");
    assert!(!state.is_initialized());
    assert!(matches!(
        state.get_keys(),
        Err(EnclaveError::KeyNotInitialized)
    ));
}

#[test]
fn initialize_from_cloning_phase_rejected() {
    let state = EnclaveState::new(Network::Bitcoin);
    *state.inner.lock().unwrap() =
        Phase::Cloning(CloningSession::new(CloneSession::new(), [0u8; 20]));
    let err = state.initialize_from_seed([42u8; 64]).unwrap_err();
    assert!(matches!(err, EnclaveError::AlreadyInitialized));
}

// NonceReplayGuard. Tests use `check_and_record_at` to check eviction
// without a sleep.

/// Unique 32-byte nonce from a small integer.
fn nonce(i: u32) -> [u8; 32] {
    let mut n = [0u8; 32];
    n[..4].copy_from_slice(&i.to_be_bytes());
    n
}

#[test]
fn replay_precheck_allows_expired_keys_without_recording() {
    let ttl = Duration::from_secs(60);
    let guard = NonceReplayGuard::with_capacity(1, ttl);
    guard
        .check_and_record_at(nonce(1), Instant::now() - ttl)
        .unwrap();
    assert!(guard.check(&nonce(1)).is_ok());
    assert!(guard.check(&nonce(2)).is_ok());
    assert_eq!(guard.seen_count(), 1);
    guard.reserve(nonce(1)).unwrap().commit();
    assert!(matches!(
        guard.check(&nonce(1)),
        Err(EnclaveError::NonceReplay)
    ));
}

#[test]
fn replay_guard_rejects_duplicate_within_ttl() {
    let g = NonceReplayGuard::with_capacity(100, Duration::from_secs(3600));
    let t0 = Instant::now();
    assert!(g.check_and_record_at(nonce(1), t0).is_ok());
    // The same nonce inside the TTL window is a replay.
    let err = g
        .check_and_record_at(nonce(1), t0 + Duration::from_secs(30))
        .unwrap_err();
    assert!(matches!(err, EnclaveError::NonceReplay));
}

// ReplayReservation: reserve, commit and rollback.

#[test]
fn reservation_rolls_back_when_dropped_uncommitted() {
    let g = NonceReplayGuard::with_capacity(100, Duration::from_secs(3600));
    let key = nonce(1);
    {
        let _r = g.reserve(key).expect("first reserve succeeds");
        assert_eq!(g.seen_count(), 1, "reserved key is recorded while held");
        // `_r` drops here without commit, so it rolls back.
    }
    assert_eq!(
        g.seen_count(),
        0,
        "un-committed reservation rolls back on drop"
    );
    // A legitimate retry can reserve the same key again.
    g.reserve(key)
        .expect("retry after rollback succeeds")
        .commit();
    assert_eq!(g.seen_count(), 1);
}

#[test]
fn stale_rollback_preserves_replacement_after_eviction() {
    for committed in [false, true] {
        let g = NonceReplayGuard::with_capacity(1, Duration::from_secs(3600));
        let key = nonce(1);
        let old = g.reserve(key).unwrap();
        g.reserve(nonce(2)).unwrap().commit();
        let replacement = g.reserve(key).unwrap();
        let replacement = if committed {
            replacement.commit();
            None
        } else {
            Some(replacement)
        };

        drop(old);
        assert!(matches!(g.reserve(key), Err(EnclaveError::NonceReplay)));
        drop(replacement);
        if !committed {
            assert!(
                g.reserve(key).is_ok(),
                "the current owner can still roll back"
            );
        }
    }
}

#[test]
fn stale_rollback_preserves_replacement_after_expiry() {
    for committed in [false, true] {
        let ttl = Duration::from_secs(60);
        let g = NonceReplayGuard::with_capacity(10, ttl);
        let t0 = Instant::now();
        let key = nonce(1);
        let old = g.reserve_at(key, t0).unwrap();
        let replacement = g.reserve_at(key, t0 + ttl).unwrap();
        let replacement = if committed {
            replacement.commit();
            None
        } else {
            Some(replacement)
        };

        drop(old);
        assert!(matches!(
            g.reserve_at(key, t0 + ttl),
            Err(EnclaveError::NonceReplay)
        ));
        drop(replacement);
        if !committed {
            assert!(g.reserve_at(key, t0 + ttl).is_ok());
        }
    }
}

#[test]
fn reservation_sticks_after_commit() {
    let g = NonceReplayGuard::with_capacity(100, Duration::from_secs(3600));
    let key = nonce(2);
    g.reserve(key).expect("reserve succeeds").commit();
    // After commit, a second reserve of the same key is a replay.
    assert!(matches!(g.reserve(key), Err(EnclaveError::NonceReplay)));
}

#[test]
fn reservation_rejects_concurrent_duplicate_before_commit() {
    // An uncommitted reservation also blocks a second reserve of the same key.
    // Thus reserve-before-sign blocks a concurrent duplicate.
    let g = NonceReplayGuard::with_capacity(100, Duration::from_secs(3600));
    let key = nonce(3);
    let held = g.reserve(key).expect("first reserve succeeds");
    assert!(matches!(g.reserve(key), Err(EnclaveError::NonceReplay)));
    held.commit();
}

/// A flood of unique nonces above `max` must not block the guard.
/// Regression test for the reject-when-full DoS.
#[test]
fn replay_guard_never_wedges_under_flood() {
    let max = 8;
    let g = NonceReplayGuard::with_capacity(max, Duration::from_secs(3600));
    let t0 = Instant::now();

    // Flood with 10x the cap in unique nonces.
    for i in 0..(max as u32 * 10) {
        assert!(
            g.check_and_record_at(nonce(i), t0).is_ok(),
            "record {i} should succeed (no reject-when-full)"
        );
    }
    assert_eq!(g.seen_count(), max);

    // A new legitimate handshake is still admitted.
    assert!(g.check_and_record_at(nonce(9_999), t0).is_ok());
}

#[test]
fn replay_guard_evicts_oldest_first_on_overflow() {
    let g = NonceReplayGuard::with_capacity(3, Duration::from_secs(3600));
    let t0 = Instant::now();
    for i in 1..=3 {
        assert!(g.check_and_record_at(nonce(i), t0).is_ok());
    }
    // The 4th unique nonce overflows the cap, so the guard evicts nonce 1.
    assert!(g.check_and_record_at(nonce(4), t0).is_ok());
    assert_eq!(g.seen_count(), 3);

    // nonce(2..=4) stay and are refused as replays. A replay returns before
    // any insert, so these checks do not change the set.
    for i in 2..=4 {
        assert!(
            matches!(
                g.check_and_record_at(nonce(i), t0).unwrap_err(),
                EnclaveError::NonceReplay
            ),
            "nonce({i}) should still be recorded"
        );
    }
    // The evicted nonce(1) is admitted again.
    // This check is last because this insert evicts the new oldest entry.
    assert!(g.check_and_record_at(nonce(1), t0).is_ok());
}

#[test]
fn replay_guard_evicts_stale_entries_by_ttl() {
    let ttl = Duration::from_secs(60);
    let g = NonceReplayGuard::with_capacity(100, ttl);
    let t0 = Instant::now();
    assert!(g.check_and_record_at(nonce(1), t0).is_ok());

    // A later record past the TTL evicts the stale nonce(1) first.
    assert!(g.check_and_record_at(nonce(2), t0 + ttl).is_ok());
    assert_eq!(g.seen_count(), 1, "stale nonce(1) should have been evicted");

    // nonce(1) expired, so the guard accepts it again.
    assert!(g
        .check_and_record_at(nonce(1), t0 + ttl + Duration::from_secs(1))
        .is_ok());
}
