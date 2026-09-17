//! Per-handshake state the requester holds between `InitiateCloning` and
//! `SetClone`.

use crate::cloning::CloneSession;

/// All of the per-handshake state the requester must hold between
/// receiving `InitiateCloning` and receiving `SetClone`.
///
/// The X25519 secret inside `session` is zeroized on drop.
pub struct CloningSession {
    /// Ephemeral X25519 keypair we advertised in `InitiateCloningResponse`.
    pub session: CloneSession,
    /// 20-byte EVM address of the donor we intend to clone from.
    pub cluster_public_key: [u8; 20],
}

impl CloningSession {
    pub fn new(session: CloneSession, cluster_public_key: [u8; 20]) -> Self {
        Self {
            session,
            cluster_public_key,
        }
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
