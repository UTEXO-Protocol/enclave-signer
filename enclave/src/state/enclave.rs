//! The enclave's phase state machine and the keys it guards.
//!
//! Every signing entry point goes through [`EnclaveState`], which holds the
//! phase behind a `Mutex` and refuses anything the current phase does not
//! allow. [`Phase`] is the machine; `EnclaveState` is the door.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use bip39::Mnemonic;
use bitcoin::Network;
use secrecy::{ExposeSecret, SecretBox};

use crate::cloning::validate_cloning_secret;
use crate::error::{EnclaveError, Result};
use crate::keys::{KeyInfo, KeyManager};

use super::cloning_session::CloningSession;
use super::replay_guard::{NonceReplayGuard, DEFAULT_OP_DEDUP_MAX, DEFAULT_OP_DEDUP_TTL};

/// Environment variable for the export warning threshold. (F03-AF-10)
/// An unset, zero, or invalid value disables the threshold.
/// This threshold does not block exports.
const CLONE_EXPORT_SOFT_CAP_ENV: &str = "CLONE_EXPORT_SOFT_CAP";

/// Environment variable for the export limit per enclave process. (F03-AF-10)
/// An unset, zero, or invalid value disables the limit.
/// A positive value limits successful exports.
/// Check the limit after authentication and before encryption.
/// Restart resets the count.
/// Each enclave has a separate count.
const CLONE_EXPORT_HARD_CAP_ENV: &str = "CLONE_EXPORT_HARD_CAP";

/// Enclave lifecycle phase.
///
/// Valid transitions (see `EnclaveState`):
///   Initial  -> Active   (InitializeKey / InitializeFromEntropy)
///   Initial  -> Cloning  (InitiateCloning, wired in PR 4)
///   Cloning  -> Active   (SetClone,      wired in PR 4)
///   Active   -> Active   (GetClone handled by donor without state change)
/// Any other transition is rejected.
///
/// `KeyManager` is boxed so the enum stays ~24 bytes rather than ~584. The
/// heap indirection is irrelevant next to the mutex lock.
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
    pub(super) inner: Mutex<Phase>,
    network: Network,
    /// Operator-configured cloning secret for the *donor* role. Required
    /// when serving `GetClone`; not used in the requester role (the
    /// requester receives the secret via `InitiateCloningRequest`).
    donor_cloning_secret: Mutex<Option<SecretBox<String>>>,
    /// Replay guard for nonces in peer attestations.
    pub replay_guard: NonceReplayGuard,
    /// **Soft** dedup guard for EVM->RGB bridge PSBT operations, keyed on a
    /// hash of `(chain_id, bridge_contract, evm_tx_hash, operation_idx,
    /// rgb_asset_id)` (see `networks::rgb::psbt_validation::psbt_operation_key`).
    /// Rejects a same-operation resubmission inside the TTL window before
    /// signing.
    ///
    /// Defense in depth, not a sufficient double-spend control. Nitro has no
    /// persistent storage, so the set is volatile (wiped on restart),
    /// per-instance (the host can route a duplicate to a sibling enclave), and
    /// TTL-bounded (a replay after eviction is admitted again). A host that
    /// varies any keyed field also bypasses it.
    ///
    /// It stops honest listener retries and naive same-tuple replay; the
    /// durable guard is an on-chain ticket.
    pub op_replay_guard: NonceReplayGuard,

    /// Successful exports from this enclave process. (F03-AF-10)
    /// Restart resets the count.
    /// The separate slot counter enforces the hard quota.
    pub(super) seed_export_count: AtomicU64,

    /// Successful exports plus exports in flight. Reserving a slot atomically
    /// prevents concurrent GetClone calls from exceeding the per-instance cap.
    pub(super) seed_export_slots: AtomicU64,

    /// Warning threshold for [`Self::seed_export_count`].
    /// Read [`CLONE_EXPORT_SOFT_CAP_ENV`] at startup.
    /// Zero disables the threshold.
    /// This threshold does not block exports.
    seed_export_soft_cap: u64,

    /// Maximum successful exports for this enclave process.
    /// Read [`CLONE_EXPORT_HARD_CAP_ENV`] at startup.
    /// Zero disables the limit.
    /// See [`Self::reserve_export_quota`].
    pub(super) seed_export_hard_cap: u64,
}

/// Holds one export slot until sealing and donor attestation both succeed.
/// Any error before commit releases the slot, including nonce replay rejection.
#[must_use = "hold the reservation until the export succeeds, then commit it"]
pub struct ExportQuotaReservation<'a> {
    state: &'a EnclaveState,
    reserved: bool,
}

impl ExportQuotaReservation<'_> {
    pub fn commit(mut self, requester_pk: &[u8; 32]) -> u64 {
        // A successful export permanently consumes its slot for this process.
        self.reserved = false;
        self.state.record_seed_export(requester_pk)
    }
}

impl Drop for ExportQuotaReservation<'_> {
    fn drop(&mut self) {
        if self.reserved {
            self.state.seed_export_slots.fetch_sub(1, Ordering::Relaxed);
        }
    }
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
            seed_export_count: AtomicU64::new(0),
            seed_export_slots: AtomicU64::new(0),
            seed_export_soft_cap: std::env::var(CLONE_EXPORT_SOFT_CAP_ENV)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0),
            seed_export_hard_cap: std::env::var(CLONE_EXPORT_HARD_CAP_ENV)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0),
        }
    }

    /// Reserve a slot before encrypting the seed. (F03-AF-10)
    /// Count successful exports and exports in progress against the limit.
    /// Return an error when no slot is available.
    /// An error before commit releases the slot.
    /// Zero disables the limit.
    /// Restart resets all slots.
    pub fn reserve_export_quota(&self) -> Result<ExportQuotaReservation<'_>> {
        let cap = self.seed_export_hard_cap;
        if cap > 0 {
            if let Err(used) =
                self.seed_export_slots
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                        if used < cap {
                            Some(used + 1)
                        } else {
                            None
                        }
                    })
            {
                tracing::warn!(
                    seed_export_count = self.seed_export_count.load(Ordering::Relaxed),
                    reserved_or_completed = used,
                    hard_cap = cap,
                    "GetClone: seed-export HARD cap reached - export refused \
                     (F03-AF-10, fail-closed). Rotate/re-provision to lift."
                );
                return Err(EnclaveError::Clone(format!(
                    "seed-export hard cap reached ({used}/{cap}); export refused"
                )));
            }
        }
        Ok(ExportQuotaReservation {
            state: self,
            reserved: cap > 0,
        })
    }

    /// Record a successful export and return the count. (F03-AF-10)
    /// Log each export.
    /// Emit a warning above the configured soft cap.
    /// This method does not enforce the hard quota.
    pub fn record_seed_export(&self, requester_pk: &[u8; 32]) -> u64 {
        let count = self.seed_export_count.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(
            seed_export_count = count,
            requester_pk = %hex::encode(requester_pk),
            "GetClone: donor exported its seed (F03-AF-10 telemetry)"
        );
        if self.seed_export_soft_cap > 0 && count > self.seed_export_soft_cap {
            tracing::warn!(
                seed_export_count = count,
                soft_cap = self.seed_export_soft_cap,
                "GetClone: seed-export soft cap exceeded - review donor custody \
                 (alert only, export not blocked)"
            );
        }
        count
    }

    /// Current lifetime seed-export count for this instance (F03-AF-10).
    pub fn seed_export_count(&self) -> u64 {
        self.seed_export_count.load(Ordering::Relaxed)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Set the donor cloning secret after checking its strength. (F03-AF-26)
    /// Replace any previous secret.
    /// SecretBox clears the bytes when it is dropped.
    pub fn set_donor_cloning_secret(&self, secret: String) -> Result<()> {
        validate_cloning_secret(&secret)?;
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

    /// Enter Cloning from Initial or an expired Cloning session. (F03-AF-01)
    /// Return AlreadyInitialized for a valid Cloning session or Active state.
    pub fn enter_cloning(&self, session: CloningSession) -> Result<()> {
        self.enter_cloning_at(session, Instant::now())
    }

    /// Use an explicit time to test session expiry.
    pub(super) fn enter_cloning_at(&self, session: CloningSession, now: Instant) -> Result<()> {
        let mut guard = self.lock_phase()?;
        match &*guard {
            Phase::Initial => {}
            // Abandoned (expired) handshake: a fresh initiation may replace it.
            Phase::Cloning(existing) if existing.is_expired(now) => {}
            // Live Cloning session or already Active: refuse.
            _ => return Err(EnclaveError::AlreadyInitialized),
        }
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

    /// Active-phase accessor for the donor side of `GetClone` - the donor
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
    /// The production path for cloned enclaves, not gated on
    /// `allow-seed-import`: the `Phase::Cloning` guard replaces that flag. The
    /// `SetClone` handler is the only caller, and runs only after verifying the
    /// donor's attestation and unsealing the seed.
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
    /// The closure gets the current `CloningSession` and must return a
    /// `KeyManager` built from the unsealed seed, including any identity check
    /// (derived address vs `cluster_public_key`). On `Ok`, the phase moves
    /// atomically to `Active`; on error it stays `Cloning` so the operator can
    /// retry.
    ///
    /// The phase stays locked across decrypt-derive-check-commit, so the seed
    /// is in memory for the shortest window and the transition is atomic.
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
        self.with_active(|km| Ok(Self::key_info(km)))
    }

    /// Derive the public bundle without publishing candidate keys as Active.
    pub(crate) fn key_info(km: &KeyManager) -> KeyInfo {
        KeyInfo {
            evm_address: *km.evm_address(),
            evm_uncompressed_pub: *km.evm_uncompressed_pub(),
            evm_gas_tx_address: *km.evm_gas_tx_address(),
            evm_gas_tx_uncompressed_pub: *km.evm_gas_tx_uncompressed_pub(),
            btc_compressed_pubkey: *km.btc_compressed_pubkey(),
            btc_xpub: km.btc_xpub().to_string(),
            master_fingerprint: km.master_fingerprint().to_bytes(),
            account_xpub_vanilla: km.account_xpub_vanilla().to_string(),
            account_xpub_colored: km.account_xpub_colored().to_string(),
            ccd_ed25519_pub: *km.ccd_ed25519_pub(),
        }
    }

    /// Sign a 32-byte EVM message hash. Returns 65-byte signature.
    pub fn sign_evm(&self, message_hash: &[u8; 32]) -> Result<[u8; 65]> {
        self.with_active(|km| km.sign_evm(message_hash))
    }

    /// Sign a 32-byte Concordium account-transaction hash with the governance
    /// Ed25519 key. Returns the 64-byte signature.
    pub fn sign_ccd(&self, hash: &[u8; 32]) -> Result<([u8; 64], [u8; 32])> {
        self.with_active(|km| km.sign_ccd(hash))
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

    /// Run `f` against the active `KeyManager`, or fail with
    /// `KeyNotInitialized`. Exposed for validators that need the derivation and
    /// not just a signature, such as the plain-BTC output ownership proof
    /// ([`crate::networks::rgb::btc_ownership`]).
    pub fn with_keys<T>(&self, f: impl FnOnce(&KeyManager) -> Result<T>) -> Result<T> {
        self.with_active(f)
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
