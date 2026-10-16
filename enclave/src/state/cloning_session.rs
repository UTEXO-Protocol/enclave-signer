//! Per-handshake state the requester holds between `InitiateCloning` and
//! `SetClone`.

use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretBox};

use crate::cloning::{validate_cloning_secret, CloneSession};
use crate::error::Result;

/// Time limit for a Cloning session. (F03-AF-01)
/// A new initiation can replace an expired session without a restart.
/// The state refuses replacement of a valid session.
/// The requester has no seed in this state.
pub(super) const CLONING_SESSION_TTL: Duration = Duration::from_secs(5 * 60);

/// Requester state between `InitiateCloning` and `SetClone`.
///
/// Both the X25519 secret and the pending donor secret are zeroized on drop.
/// Expiry permits replacement; it does not automatically drop the session.
pub struct CloningSession {
    /// Ephemeral X25519 keypair sent in `InitiateCloningResponse`.
    pub session: CloneSession,
    /// 20-byte EVM address of the donor to clone from.
    pub cluster_public_key: [u8; 20],
    /// Validated requester credential. It becomes the donor credential only
    /// when this exact session's verified clone response activates its keys.
    donor_cloning_secret: SecretBox<String>,
    /// Monotonic start time for session expiry. (F03-AF-01)
    created_at: Instant,
}

impl CloningSession {
    /// Create a pending session after validating its future donor credential.
    pub fn new(
        session: CloneSession,
        cluster_public_key: [u8; 20],
        donor_cloning_secret: SecretBox<String>,
    ) -> Result<Self> {
        Self::new_at(
            session,
            cluster_public_key,
            donor_cloning_secret,
            Instant::now(),
        )
    }

    /// Create a session with a fixed start time for expiry tests.
    pub(super) fn new_at(
        session: CloneSession,
        cluster_public_key: [u8; 20],
        donor_cloning_secret: SecretBox<String>,
        created_at: Instant,
    ) -> Result<Self> {
        validate_cloning_secret(donor_cloning_secret.expose_secret())?;
        Ok(Self {
            session,
            cluster_public_key,
            donor_cloning_secret,
            created_at,
        })
    }

    /// True when the session age is >= [`CLONING_SESSION_TTL`].
    pub(super) fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= CLONING_SESSION_TTL
    }

    /// Move the credential only after verified completion, without a plaintext copy.
    pub(super) fn into_donor_cloning_secret(self) -> SecretBox<String> {
        self.donor_cloning_secret
    }
}

impl std::fmt::Debug for CloningSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloningSession")
            .field("session", &self.session)
            .field("cluster_public_key", &hex::encode(self.cluster_public_key))
            .field("donor_cloning_secret", &"<redacted>")
            .finish()
    }
}
