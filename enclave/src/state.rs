use std::collections::HashSet;
use std::sync::Mutex;

use bip39::Mnemonic;
use bitcoin::Network;
use secrecy::{ExposeSecret, SecretBox};

use crate::cloning::CloneSession;
use crate::error::{EnclaveError, Result};
use crate::keys::{KeyInfo, KeyManager};

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

/// Bounded replay guard for attestation nonces.
///
/// Every incoming peer attestation contributes its nonce to this set;
/// duplicate nonces are rejected. Enclaves are short-lived so unbounded
/// growth is rare, but we cap the set at 10k to prevent a pathological
/// attacker from exhausting memory. On overflow we reject new entries
/// rather than silently rolling the window — a safer default.
pub struct NonceReplayGuard {
    inner: Mutex<HashSet<[u8; 32]>>,
    max: usize,
}

impl Default for NonceReplayGuard {
    fn default() -> Self {
        Self::with_capacity(10_000)
    }
}

impl NonceReplayGuard {
    pub fn with_capacity(max: usize) -> Self {
        Self {
            inner: Mutex::new(HashSet::new()),
            max,
        }
    }

    pub fn check_and_record(&self, nonce: [u8; 32]) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("replay guard poisoned: {}", e)))?;
        if guard.contains(&nonce) {
            return Err(EnclaveError::NonceReplay);
        }
        if guard.len() >= self.max {
            return Err(EnclaveError::Clone(
                "replay guard full; refusing new attestations".into(),
            ));
        }
        guard.insert(nonce);
        Ok(())
    }

    #[cfg(test)]
    pub fn seen_count(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// Enclave lifecycle phase.
///
/// Valid transitions (see `EnclaveState`):
///   Initial  -> Active   (InitializeKey / InitializeFromEntropy)
///   Initial  -> Cloning  (InitiateCloning, wired in PR 4)
///   Cloning  -> Active   (SetClone,      wired in PR 4)
///   Active   -> Active   (GetClone handled by donor without state change)
/// Any other transition is rejected.
///
/// `KeyManager` is boxed so the enum stays small (~24 bytes) rather than
/// bloating every `Phase` value to the size of the biggest variant
/// (~584 bytes). The heap indirection is irrelevant in the hot path —
/// the mutex lock dominates.
pub enum Phase {
    /// No keys, waiting for an initialize request.
    Initial,
    /// Cloning handshake in progress, waiting for SetClone.
    Cloning(CloningSession),
    /// Keys loaded, ready to sign.
    Active(Box<KeyManager>),
}

impl Phase {
    pub fn name(&self) -> &'static str {
        match self {
            Phase::Initial => "initial",
            Phase::Cloning(_) => "cloning",
            Phase::Active(_) => "active",
        }
    }
}

/// Thread-safe enclave state backed by a phase state machine.
pub struct EnclaveState {
    inner: Mutex<Phase>,
    network: Network,
    /// Operator-configured cloning secret for the *donor* role. Required
    /// when serving `GetClone`; not used in the requester role (the
    /// requester receives the secret via `InitiateCloningRequest`).
    donor_cloning_secret: Mutex<Option<SecretBox<String>>>,
    /// Replay guard for nonces in peer attestations.
    pub replay_guard: NonceReplayGuard,
}

impl Default for EnclaveState {
    fn default() -> Self {
        Self::new(Network::Bitcoin)
    }
}

impl EnclaveState {
    pub fn new(network: Network) -> Self {
        Self {
            inner: Mutex::new(Phase::Initial),
            network,
            donor_cloning_secret: Mutex::new(None),
            replay_guard: NonceReplayGuard::default(),
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Configure the donor-side cloning secret. Called at startup from an
    /// operator-provided env var (e.g. `UTEXO_CLONING_SECRET`). Idempotent
    /// and overwrites any previous value. The secret is wrapped in
    /// `SecretBox` for zeroize-on-drop.
    pub fn set_donor_cloning_secret(&self, secret: String) -> Result<()> {
        let mut guard = self
            .donor_cloning_secret
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("lock poisoned: {}", e)))?;
        *guard = Some(SecretBox::new(Box::new(secret)));
        Ok(())
    }

    /// Read the configured donor cloning secret, if any, and apply `f` to
    /// it while holding the lock so the plaintext never escapes the
    /// closure frame.
    pub fn with_donor_cloning_secret<T>(&self, f: impl FnOnce(&str) -> Result<T>) -> Result<T> {
        let guard = self
            .donor_cloning_secret
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("lock poisoned: {}", e)))?;
        match guard.as_ref() {
            Some(secret) => f(secret.expose_secret()),
            None => Err(EnclaveError::NotReady {
                state: "donor cloning secret not configured".into(),
            }),
        }
    }

    /// Returns the name of the current phase ("initial", "cloning", "active").
    pub fn phase_name(&self) -> &'static str {
        self.inner.lock().map(|g| g.name()).unwrap_or("poisoned")
    }

    /// True only when the state holds an active `KeyManager`.
    pub fn is_initialized(&self) -> bool {
        matches!(self.inner.lock().as_deref(), Ok(Phase::Active(_)))
    }

    /// Initialize from OS entropy. Returns the mnemonic for one-time logging.
    /// Only valid from `Phase::Initial`; any other phase returns `AlreadyInitialized`.
    pub fn initialize_from_entropy(&self, entropy: &mut [u8; 32]) -> Result<Mnemonic> {
        let mut guard = self.lock_phase()?;
        ensure_initial(&guard)?;
        let (manager, mnemonic) = KeyManager::generate(entropy, self.network)?;
        *guard = Phase::Active(Box::new(manager));
        Ok(mnemonic)
    }

    /// Initialize from a BIP-39 mnemonic phrase (testing only, requires `allow-seed-import` feature).
    pub fn initialize_from_mnemonic(&self, mnemonic_str: &str) -> Result<()> {
        let mut guard = self.lock_phase()?;
        ensure_initial(&guard)?;
        let manager = KeyManager::from_mnemonic(mnemonic_str, self.network)?;
        *guard = Phase::Active(Box::new(manager));
        Ok(())
    }

    /// Initialize from a raw 64-byte seed (testing only, requires `allow-seed-import` feature).
    pub fn initialize_from_seed(&self, seed: [u8; 64]) -> Result<()> {
        let mut guard = self.lock_phase()?;
        ensure_initial(&guard)?;
        let manager = KeyManager::from_seed(seed, self.network)?;
        *guard = Phase::Active(Box::new(manager));
        Ok(())
    }

    /// Transition `Initial -> Cloning`, consuming the supplied session.
    /// Rejected from any other phase.
    pub fn enter_cloning(&self, session: CloningSession) -> Result<()> {
        let mut guard = self.lock_phase()?;
        ensure_initial(&guard)?;
        *guard = Phase::Cloning(session);
        Ok(())
    }

    /// Run `f` against the live `CloningSession` while holding the state
    /// lock. Errors with `NotReady` if the state is not `Cloning`. The
    /// closure cannot keep a reference to the session past its return.
    pub fn with_cloning_session<T>(
        &self,
        f: impl FnOnce(&CloningSession) -> Result<T>,
    ) -> Result<T> {
        let guard = self.lock_phase()?;
        match &*guard {
            Phase::Cloning(s) => f(s),
            other => Err(EnclaveError::NotReady {
                state: other.name().into(),
            }),
        }
    }

    /// Active-phase accessor for the donor side of `GetClone` — the donor
    /// is in `Phase::Active` and needs to read the seed to seal it.
    pub fn with_seed<T>(&self, f: impl FnOnce(&[u8; 64]) -> Result<T>) -> Result<T> {
        self.with_active(|km| f(km.expose_seed()))
    }

    /// Donor-side accessor for the EVM address used in the `GetClone`
    /// identity check (`cluster_public_key`).
    pub fn evm_address(&self) -> Result<[u8; 20]> {
        self.with_active(|km| Ok(*km.evm_address()))
    }

    /// Initialize from a seed obtained via the cloning handshake.
    ///
    /// This is the production path for cloned enclaves and is NOT gated on
    /// `allow-seed-import`. The `Phase::Cloning` guard replaces the feature
    /// flag: PR 4's `SetClone` handler is the only caller, and it only
    /// runs after verifying the donor's attestation and unsealing the
    /// seed.
    pub fn initialize_from_cloned_seed(&self, seed: [u8; 64]) -> Result<()> {
        let mut guard = self.lock_phase()?;
        match &*guard {
            Phase::Cloning(_) => {}
            other => {
                return Err(EnclaveError::NotReady {
                    state: other.name().into(),
                });
            }
        }
        let manager = KeyManager::from_seed(seed, self.network)?;
        *guard = Phase::Active(Box::new(manager));
        Ok(())
    }

    /// Complete the cloning handshake atomically.
    ///
    /// The closure is given a reference to the current `CloningSession`
    /// and must return a fully-constructed `KeyManager` built from the
    /// unsealed seed. The closure is responsible for any identity check
    /// (e.g. derived-address vs `cluster_public_key`). On `Ok(km)`, the
    /// phase transitions atomically to `Active(km)`. On error, the state
    /// stays in `Cloning` so the operator can retry if desired.
    ///
    /// Locking the phase for the entire decrypt-derive-check-commit
    /// sequence keeps the seed in memory for the shortest possible window
    /// and makes the transition observably atomic from other threads.
    pub fn complete_cloning(
        &self,
        f: impl FnOnce(&CloningSession) -> Result<KeyManager>,
    ) -> Result<()> {
        let mut guard = self.lock_phase()?;
        let session = match &*guard {
            Phase::Cloning(s) => s,
            other => {
                return Err(EnclaveError::NotReady {
                    state: other.name().into(),
                });
            }
        };
        let manager = f(session)?;
        *guard = Phase::Active(Box::new(manager));
        Ok(())
    }

    /// Get public key info. Returns `KeyNotInitialized` if not in the `Active` phase.
    pub fn get_keys(&self) -> Result<KeyInfo> {
        self.with_active(|km| {
            Ok(KeyInfo {
                evm_address: *km.evm_address(),
                evm_uncompressed_pub: *km.evm_uncompressed_pub(),
                btc_compressed_pubkey: *km.btc_compressed_pubkey(),
                btc_xpub: km.btc_xpub().to_string(),
                master_fingerprint: km.master_fingerprint().to_bytes(),
                account_xpub_vanilla: km.account_xpub_vanilla().to_string(),
                account_xpub_colored: km.account_xpub_colored().to_string(),
            })
        })
    }

    /// Sign a 32-byte EVM message hash. Returns 65-byte signature.
    pub fn sign_evm(&self, message_hash: &[u8; 32]) -> Result<[u8; 65]> {
        self.with_active(|km| km.sign_evm(message_hash))
    }

    /// Sign PSBT inputs matching our BTC key. Returns (signed_psbt_bytes, inputs_signed).
    pub fn sign_psbt(&self, psbt_bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
        self.with_active(|km| km.sign_psbt(psbt_bytes))
    }

    fn lock_phase(&self) -> Result<std::sync::MutexGuard<'_, Phase>> {
        self.inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("lock poisoned: {}", e)))
    }

    fn with_active<T>(&self, f: impl FnOnce(&KeyManager) -> Result<T>) -> Result<T> {
        let guard = self.lock_phase()?;
        match &*guard {
            Phase::Active(km) => f(km),
            Phase::Initial | Phase::Cloning(_) => Err(EnclaveError::KeyNotInitialized),
        }
    }
}

fn ensure_initial(phase: &Phase) -> Result<()> {
    match phase {
        Phase::Initial => Ok(()),
        _ => Err(EnclaveError::AlreadyInitialized),
    }
}

#[cfg(test)]
mod tests {
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
}
