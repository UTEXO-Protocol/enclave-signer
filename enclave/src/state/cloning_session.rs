//! Per-handshake state the requester holds between `InitiateCloning` and
//! `SetClone`.

use std::time::{Duration, Instant};

use crate::cloning::CloneSession;

/// Time limit for a Cloning session. (F03-AF-01)
/// A new initiation can replace an expired session without a restart.
/// The state refuses replacement of a valid session.
/// The requester has no seed in this state.
pub(super) const CLONING_SESSION_TTL: Duration = Duration::from_secs(5 * 60);

/// Requester state between `InitiateCloning` and `SetClone`.
///
/// The X25519 secret in `session` is zeroized on drop.
pub struct CloningSession {
    /// Ephemeral X25519 keypair sent in `InitiateCloningResponse`.
    pub session: CloneSession,
    /// 20-byte EVM address of the donor to clone from.
    pub cluster_public_key: [u8; 20],
    /// Monotonic start time for session expiry. (F03-AF-01)
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

    /// True when the session age is >= [`CLONING_SESSION_TTL`].
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
