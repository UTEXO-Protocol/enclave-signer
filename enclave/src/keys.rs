use std::str::FromStr;
use std::sync::Mutex;

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use secrecy::{ExposeSecret, SecretBox};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use crate::error::{EnclaveError, Result};

/// Public key info extracted from KeyManager for responses.
pub struct KeyInfo {
    pub evm_address: [u8; 20],
    pub btc_compressed_pubkey: [u8; 33],
    pub btc_xpub: String,
}

/// Holds HD wallet keys in memory. Secrets are wrapped in SecretBox for
/// zeroize-on-drop. Public keys are stored in plain form.
#[allow(dead_code)] // evm_secret, btc_secret used in T3 (signing)
pub struct KeyManager {
    seed: SecretBox<[u8; 64]>,
    evm_secret: SecretBox<[u8; 32]>,
    btc_secret: SecretBox<[u8; 32]>,
    evm_address: [u8; 20],
    btc_compressed_pubkey: [u8; 33],
    btc_xpub: Xpub,
}

impl KeyManager {
    /// Generate a new KeyManager from 256-bit entropy.
    /// Returns both the manager and the BIP-39 mnemonic (caller logs once, then discards).
    pub fn generate(entropy: &mut [u8; 32]) -> Result<(Self, Mnemonic)> {
        let mnemonic = Mnemonic::from_entropy(entropy)
            .map_err(|e| EnclaveError::InvalidKey(format!("mnemonic generation failed: {}", e)))?;
        entropy.zeroize();

        let seed = mnemonic.to_seed("");
        let manager = Self::from_seed(seed)?;
        Ok((manager, mnemonic))
    }

    /// Create a KeyManager from a raw 64-byte BIP-39 seed.
    ///
    /// CRITICAL: The seed is moved into SecretBox FIRST, before any derivation.
    /// Do NOT zeroize the local seed before boxing — the stored seed would be
    /// all zeros and cloning would break later.
    pub fn from_seed(mut seed: [u8; 64]) -> Result<Self> {
        // Box the seed FIRST
        let seed_box = SecretBox::new(Box::new(seed));
        seed.zeroize();

        let secp = Secp256k1::new();

        // Derive master key from seed
        let master =
            Xpriv::new_master(Network::Bitcoin, seed_box.expose_secret()).map_err(|e| {
                EnclaveError::InvalidKey(format!("master key derivation failed: {}", e))
            })?;

        // === EVM: m/44'/60'/0'/0/0 ===
        let evm_path = DerivationPath::from_str("m/44'/60'/0'/0/0")
            .map_err(|e| EnclaveError::InvalidKey(format!("invalid EVM path: {}", e)))?;
        let evm_xpriv = master
            .derive_priv(&secp, &evm_path)
            .map_err(|e| EnclaveError::InvalidKey(format!("EVM derivation failed: {}", e)))?;
        let evm_secret_key = evm_xpriv.private_key;
        let mut evm_secret_bytes = evm_secret_key.secret_bytes();
        let evm_secret = SecretBox::new(Box::new(evm_secret_bytes));
        evm_secret_bytes.zeroize();

        // EVM address: keccak256(uncompressed_pubkey[1..])[12..]
        let evm_pubkey = PublicKey::from_secret_key(&secp, &evm_secret_key);
        let evm_uncompressed = evm_pubkey.serialize_uncompressed();
        let hash = Keccak256::digest(&evm_uncompressed[1..]);
        let mut evm_address = [0u8; 20];
        evm_address.copy_from_slice(&hash[12..32]);

        // === BTC: m/84'/0'/0'/0/0 ===
        let btc_path = DerivationPath::from_str("m/84'/0'/0'/0/0")
            .map_err(|e| EnclaveError::InvalidKey(format!("invalid BTC path: {}", e)))?;
        let btc_xpriv = master
            .derive_priv(&secp, &btc_path)
            .map_err(|e| EnclaveError::InvalidKey(format!("BTC derivation failed: {}", e)))?;
        let btc_secret_key = btc_xpriv.private_key;
        let mut btc_secret_bytes = btc_secret_key.secret_bytes();
        let btc_secret = SecretBox::new(Box::new(btc_secret_bytes));
        btc_secret_bytes.zeroize();

        let btc_pubkey = PublicKey::from_secret_key(&secp, &btc_secret_key);
        let mut btc_compressed_pubkey = [0u8; 33];
        btc_compressed_pubkey.copy_from_slice(&btc_pubkey.serialize());

        let btc_xpub = Xpub::from_priv(&secp, &btc_xpriv);

        Ok(Self {
            seed: seed_box,
            evm_secret,
            btc_secret,
            evm_address,
            btc_compressed_pubkey,
            btc_xpub,
        })
    }

    pub fn evm_address(&self) -> &[u8; 20] {
        &self.evm_address
    }

    pub fn btc_compressed_pubkey(&self) -> &[u8; 33] {
        &self.btc_compressed_pubkey
    }

    pub fn btc_xpub(&self) -> &Xpub {
        &self.btc_xpub
    }

    pub fn expose_seed(&self) -> &[u8; 64] {
        self.seed.expose_secret()
    }
}

/// Thread-safe enclave state holding an optional KeyManager behind a Mutex.
pub struct EnclaveState {
    inner: Mutex<Option<KeyManager>>,
}

impl EnclaveState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// Initialize from OS entropy. Returns the mnemonic for one-time logging.
    pub fn initialize_from_entropy(&self, entropy: &mut [u8; 32]) -> Result<Mnemonic> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("lock poisoned: {}", e)))?;
        if guard.is_some() {
            return Err(EnclaveError::AlreadyInitialized);
        }
        let (manager, mnemonic) = KeyManager::generate(entropy)?;
        *guard = Some(manager);
        Ok(mnemonic)
    }

    /// Initialize from a raw 64-byte seed (testing only, requires allow-seed-import feature).
    pub fn initialize_from_seed(&self, seed: [u8; 64]) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("lock poisoned: {}", e)))?;
        if guard.is_some() {
            return Err(EnclaveError::AlreadyInitialized);
        }
        let manager = KeyManager::from_seed(seed)?;
        *guard = Some(manager);
        Ok(())
    }

    /// Get public key info. Returns error if not initialized.
    pub fn get_keys(&self) -> Result<KeyInfo> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("lock poisoned: {}", e)))?;
        match guard.as_ref() {
            Some(km) => Ok(KeyInfo {
                evm_address: *km.evm_address(),
                btc_compressed_pubkey: *km.btc_compressed_pubkey(),
                btc_xpub: km.btc_xpub().to_string(),
            }),
            None => Err(EnclaveError::KeyNotInitialized),
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.inner.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let seed = [42u8; 64];
        let km1 = KeyManager::from_seed(seed).unwrap();
        let km2 = KeyManager::from_seed(seed).unwrap();

        assert_eq!(km1.evm_address(), km2.evm_address());
        assert_eq!(km1.btc_compressed_pubkey(), km2.btc_compressed_pubkey());
        assert_eq!(km1.btc_xpub().to_string(), km2.btc_xpub().to_string());
    }

    #[test]
    fn generate_different_keys() {
        let mut entropy1 = [1u8; 32];
        let mut entropy2 = [2u8; 32];
        let (km1, _) = KeyManager::generate(&mut entropy1).unwrap();
        let (km2, _) = KeyManager::generate(&mut entropy2).unwrap();

        assert_ne!(km1.evm_address(), km2.evm_address());
    }

    #[test]
    fn key_formats() {
        let seed = [42u8; 64];
        let km = KeyManager::from_seed(seed).unwrap();

        assert_eq!(km.evm_address().len(), 20);
        assert_eq!(km.btc_compressed_pubkey().len(), 33);
        assert!(
            km.btc_compressed_pubkey()[0] == 0x02 || km.btc_compressed_pubkey()[0] == 0x03,
            "compressed pubkey must start with 0x02 or 0x03"
        );
        assert!(
            km.btc_xpub().to_string().starts_with("xpub"),
            "xpub must start with 'xpub'"
        );
    }

    #[test]
    fn seed_preserved_for_cloning() {
        let original_seed = [99u8; 64];
        let km = KeyManager::from_seed(original_seed).unwrap();
        assert_eq!(km.expose_seed(), &original_seed);
    }

    #[test]
    fn double_initialization_error() {
        let state = EnclaveState::new();
        let mut entropy1 = [1u8; 32];
        let mut entropy2 = [2u8; 32];

        state.initialize_from_entropy(&mut entropy1).unwrap();
        let result = state.initialize_from_entropy(&mut entropy2);
        assert!(result.is_err());
    }

    #[test]
    fn get_keys_before_init_error() {
        let state = EnclaveState::new();
        let result = state.get_keys();
        assert!(result.is_err());
    }
}
