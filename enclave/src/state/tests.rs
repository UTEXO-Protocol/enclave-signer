//! Tests for the phase machine and both replay guards.

use std::time::{Duration, Instant};

use bitcoin::Network;

use crate::cloning::CloneSession;
use crate::error::EnclaveError;

use super::enclave::*;
use super::replay_guard::*;

use super::*;

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

// NonceReplayGuard - time-bounded replay guard (coverage
// map). Helpers use `check_and_record_at` so eviction is exercised
// without sleeping.

/// Distinct 32-byte nonce keyed by a small integer, for readable tests.
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
    // Same nonce, still inside the TTL window -> replay.
    let err = g
        .check_and_record_at(nonce(1), t0 + Duration::from_secs(30))
        .unwrap_err();
    assert!(matches!(err, EnclaveError::NonceReplay));
}

// ReplayReservation - reserve/commit/rollback.

#[test]
fn reservation_rolls_back_when_dropped_uncommitted() {
    let g = NonceReplayGuard::with_capacity(100, Duration::from_secs(3600));
    let key = nonce(1);
    {
        let _r = g.reserve(key).expect("first reserve succeeds");
        assert_eq!(g.seen_count(), 1, "reserved key is recorded while held");
        // `_r` drops here without commit -> rollback.
    }
    assert_eq!(
        g.seen_count(),
        0,
        "un-committed reservation rolls back on drop"
    );
    // The same key can now be reserved again (a legitimate retry).
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
    // Committed -> a second reserve of the same key is a replay.
    assert!(matches!(g.reserve(key), Err(EnclaveError::NonceReplay)));
}

#[test]
fn reservation_rejects_concurrent_duplicate_before_commit() {
    // While a reservation is held (not yet committed), a second reserve of
    // the same key is still rejected up front - reserve-before-sign blocks a
    // concurrent duplicate, not only a committed one.
    let g = NonceReplayGuard::with_capacity(100, Duration::from_secs(3600));
    let key = nonce(3);
    let held = g.reserve(key).expect("first reserve succeeds");
    assert!(matches!(g.reserve(key), Err(EnclaveError::NonceReplay)));
    held.commit();
}

/// A flood of distinct nonces beyond `max` must
/// not wedge the guard. Regression for the reject-when-full DoS.
#[test]
fn replay_guard_never_wedges_under_flood() {
    let max = 8;
    let g = NonceReplayGuard::with_capacity(max, Duration::from_secs(3600));
    let t0 = Instant::now();

    // Flood with 10x the cap in distinct nonces.
    for i in 0..(max as u32 * 10) {
        assert!(
            g.check_and_record_at(nonce(i), t0).is_ok(),
            "record {i} should succeed (no reject-when-full)"
        );
    }
    // Memory stayed bounded.
    assert_eq!(g.seen_count(), max);

    // A brand-new legitimate handshake is still admitted, not blocked.
    assert!(g.check_and_record_at(nonce(9_999), t0).is_ok());
}

#[test]
fn replay_guard_evicts_oldest_first_on_overflow() {
    let g = NonceReplayGuard::with_capacity(3, Duration::from_secs(3600));
    let t0 = Instant::now();
    for i in 1..=3 {
        assert!(g.check_and_record_at(nonce(i), t0).is_ok());
    }
    // 4th distinct nonce overflows the cap -> oldest (nonce 1) evicted.
    assert!(g.check_and_record_at(nonce(4), t0).is_ok());
    assert_eq!(g.seen_count(), 3);

    // nonce(2..=4) survive and are still replay-rejected. A replay returns
    // before any insert, so these checks do not mutate the set.
    for i in 2..=4 {
        assert!(
            matches!(
                g.check_and_record_at(nonce(i), t0).unwrap_err(),
                EnclaveError::NonceReplay
            ),
            "nonce({i}) should still be recorded"
        );
    }
    // nonce(1) was the oldest and got evicted, so it is admitted again.
    // (Done last: this insert evicts the new oldest.)
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

    // Because nonce(1) aged out, the same nonce is accepted again.
    assert!(g
        .check_and_record_at(nonce(1), t0 + ttl + Duration::from_secs(1))
        .is_ok());
}
