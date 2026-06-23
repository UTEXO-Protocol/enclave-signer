use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

/// Default time-to-live for a recorded nonce. A nonce only needs to be
/// remembered long enough that replaying its attestation within a
/// plausible window is still caught; the cloning handshake itself
/// completes in seconds, so an hour is generous. After the TTL the entry
/// self-evicts, keeping the set small in steady state.
const DEFAULT_NONCE_TTL: Duration = Duration::from_secs(60 * 60);

/// Default hard memory ceiling on recorded nonces.
const DEFAULT_NONCE_MAX: usize = 10_000;

/// Default TTL for the PSBT bridge-operation dedup guard. Far longer than
/// the cloning nonce TTL: an EVM→RGB deposit can legitimately be retried
/// for as long as it remains unsettled, and the window must comfortably
/// outlast normal listener retry/confirmation latency so a same-op
/// resubmission is still caught. 24h is generous while keeping the set
/// self-cleaning in steady state. See [`EnclaveState::op_replay_guard`].
const DEFAULT_OP_DEDUP_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Hard memory ceiling on recorded bridge operations. At ~80 bytes/entry
/// this caps the guard near ~8 MB. On overflow inside one TTL window the
/// oldest entry is evicted (never wedge signing) — see the soft-guard
/// caveats on [`EnclaveState::op_replay_guard`].
const DEFAULT_OP_DEDUP_MAX: usize = 100_000;

/// Replay guard for attestation nonces, bounded by **time** (not just
/// count) so a flooding parent cannot permanently wedge cloning.
///
/// Every incoming peer attestation contributes its nonce; duplicates are
/// rejected. Each entry carries the instant it was seen, and every
/// `check_and_record` first evicts entries older than `ttl`, so the set
/// self-cleans in steady state. `max` remains a hard memory ceiling: if
/// the set is still full after TTL eviction (a burst of distinct
/// handshakes inside one TTL window), the **oldest** entry is evicted to
/// admit the new one rather than rejecting it.
///
/// This replaces the previous reject-when-full behaviour, which let a
/// parent flood `max` distinct nonces and then block every legitimate
/// handshake — a cloning-availability DoS (audit TEE-CL-04). Cloning is
/// parent-initiated, so the parent is the threat actor. The trade-off is a
/// bounded, time-limited replay window: replaying an evicted nonce only
/// ever re-seals the seed to the encryption pubkey already bound inside
/// that attestation, so no funds or secret leak to a new party — only
/// availability was ever at stake.
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
    fn check_and_record_at(&self, nonce: [u8; 32], now: Instant) -> Result<()> {
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
        //    than wedging cloning (TEE-CL-04).
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

    #[cfg(test)]
    pub fn seen_count(&self) -> usize {
        self.inner.lock().map(|g| g.seen.len()).unwrap_or(0)
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
    /// **Soft** dedup guard for EVM→RGB bridge PSBT operations, keyed on a
    /// hash of `(chain_id, bridge_contract, evm_tx_hash, operation_idx,
    /// rgb_asset_id)` (see `validation::psbt_crosscheck::psbt_operation_key`).
    /// Rejects a same-operation resubmission inside the TTL window before
    /// signing (audit W-02 / #84).
    ///
    /// This is **defense-in-depth, not a sufficient double-spend control**.
    /// Nitro has no persistent storage, so the set is:
    ///   - **volatile** — wiped on restart;
    ///   - **per-instance** — a sibling enclave in the cluster never saw it,
    ///     so the host can route a duplicate to a fresh peer;
    ///   - **TTL-bounded** — a replay after eviction is admitted again.
    ///
    /// A compromised host that varies any keyed field also bypasses it. It
    /// stops honest listener retries and naive same-tuple replay; the durable
    /// cross-instance/cross-restart guard remains an on-chain ticket (#84/#93).
    pub op_replay_guard: NonceReplayGuard,
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
            op_replay_guard: NonceReplayGuard::with_capacity(
                DEFAULT_OP_DEDUP_MAX,
                DEFAULT_OP_DEDUP_TTL,
            ),
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
                evm_gas_tx_address: *km.evm_gas_tx_address(),
                evm_gas_tx_uncompressed_pub: *km.evm_gas_tx_uncompressed_pub(),
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

    /// Sign a 32-byte digest with the EVM gas TX key. Returns 65-byte signature.
    pub fn sign_evm_gas_tx(&self, message_hash: &[u8; 32]) -> Result<[u8; 65]> {
        self.with_active(|km| km.sign_evm_gas_tx(message_hash))
    }

    /// Sign PSBT inputs matching our BTC key. Returns (signed_psbt_bytes, inputs_signed).
    pub fn sign_psbt(&self, psbt_bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
        self.with_active(|km| km.sign_psbt(psbt_bytes))
    }

    /// Sign a PSBT restricted to a single BIP-86 account (see
    /// [`crate::keys::KeyManager::sign_psbt_scoped`]). The plain-BTC path uses
    /// this with `Some(AccountType::Vanilla)` so it can never co-sign a Colored
    /// (RGB-allocated) input.
    pub fn sign_psbt_scoped(
        &self,
        psbt_bytes: &[u8],
        allowed_account: Option<crate::keys::AccountType>,
    ) -> Result<(Vec<u8>, usize)> {
        self.with_active(|km| km.sign_psbt_scoped(psbt_bytes, allowed_account))
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

    // =========================================================================
    // NonceReplayGuard — time-bounded replay guard (audit TEE-CL-04, coverage
    // map TC-3). Helpers use `check_and_record_at` so eviction is exercised
    // without sleeping.
    // =========================================================================

    /// Distinct 32-byte nonce keyed by a small integer, for readable tests.
    fn nonce(i: u32) -> [u8; 32] {
        let mut n = [0u8; 32];
        n[..4].copy_from_slice(&i.to_be_bytes());
        n
    }

    #[test]
    fn replay_guard_rejects_duplicate_within_ttl() {
        let g = NonceReplayGuard::with_capacity(100, Duration::from_secs(3600));
        let t0 = Instant::now();
        assert!(g.check_and_record_at(nonce(1), t0).is_ok());
        // Same nonce, still inside the TTL window → replay.
        let err = g
            .check_and_record_at(nonce(1), t0 + Duration::from_secs(30))
            .unwrap_err();
        assert!(matches!(err, EnclaveError::NonceReplay));
    }

    /// TC-3 (audit coverage map): a flood of distinct nonces beyond `max`
    /// must NOT wedge the guard. Every record succeeds, the set stays
    /// bounded at `max`, and a fresh legitimate handshake is still admitted
    /// — the regression for the reject-when-full DoS.
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
        // 4th distinct nonce overflows the cap → oldest (nonce 1) evicted.
        assert!(g.check_and_record_at(nonce(4), t0).is_ok());
        assert_eq!(g.seen_count(), 3);

        // nonce(2..=4) survive → still replay-rejected. A replay returns
        // before any insert, so these checks don't mutate the set (the cap
        // is full, so an admit would otherwise evict the next-oldest).
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
}
