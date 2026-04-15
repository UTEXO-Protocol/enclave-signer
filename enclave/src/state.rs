use std::sync::Mutex;

use bip39::Mnemonic;
use bitcoin::Network;

use crate::error::{EnclaveError, Result};
use crate::keys::{KeyInfo, KeyManager};

/// Placeholder for cloning session state.
///
/// PR 3 (cloning crypto primitives) will replace this with the real type
/// from `crate::cloning` carrying the X25519 ephemeral keypair, stored
/// cloning secret, target cluster public key, and attestation nonce.
#[derive(Debug, Default)]
pub struct CloningSession {}

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
        }
    }

    pub fn network(&self) -> Network {
        self.network
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

    /// Get public key info. Returns `KeyNotInitialized` if not in the `Active` phase.
    pub fn get_keys(&self) -> Result<KeyInfo> {
        self.with_active(|km| {
            Ok(KeyInfo {
                evm_address: *km.evm_address(),
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
        *state.inner.lock().unwrap() = Phase::Cloning(CloningSession::default());
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
        *state.inner.lock().unwrap() = Phase::Cloning(CloningSession::default());
        let err = state.initialize_from_seed([42u8; 64]).unwrap_err();
        assert!(matches!(err, EnclaveError::AlreadyInitialized));
    }
}
