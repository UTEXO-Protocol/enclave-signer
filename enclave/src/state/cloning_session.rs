//! Per-handshake state the requester holds between `InitiateCloning` and
//! `SetClone`.

use std::time::{Duration, Instant};

use crate::cloning::CloneSession;

/// Time limit for a Cloning session. (F03-AF-01)
/// An expired session can be replaced without a restart.
/// The requester has no seed in this state.
/// Reject replacement while the session is still valid.
pub(super) const CLONING_SESSION_TTL: Duration = Duration::from_secs(5 * 60);

/// All of the per-handshake state the requester must hold between
/// receiving `InitiateCloning` and receiving `SetClone`.
///
/// The X25519 secret inside `session` is zeroized on drop.
pub struct CloningSession {
    /// Ephemeral X25519 keypair we advertised in `InitiateCloningResponse`.
    pub session: CloneSession,
    /// 20-byte EVM address of the donor we intend to clone from.
    pub cluster_public_key: [u8; 20],
    /// Monotonic start time for session expiry. (F03-AF-01)
    /// Wall-clock changes do not affect it.
    created_at: Instant,
}

impl CloningSession {
    pub fn new(session: CloneSession, cluster_public_key: [u8; 20]) -> Self {
        Self::new_at(session, cluster_public_key, Instant::now())
    }

    /// Create a session with a fixed start time for expiry tests.
    pub(super) fn new_at(
        session: CloneSession,
        cluster_public_key: [u8; 20],
        created_at: Instant,
    ) -> Self {
        Self {
            session,
            cluster_public_key,
            created_at,
        }
    }

    /// Return true when the session reaches [`CLONING_SESSION_TTL`].
    pub(super) fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= CLONING_SESSION_TTL
    }
}

impl std::fmt::Debug for CloningSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloningSession")
            .field("session", &self.session)
            .field("cluster_public_key", &hex::encode(self.cluster_public_key))
            .finish()
    }
}
