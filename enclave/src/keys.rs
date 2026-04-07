use std::str::FromStr;
use std::sync::Mutex;

use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::Network;
use k256::ecdsa::SigningKey as K256SigningKey;
use secrecy::{ExposeSecret, SecretBox};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use crate::error::{EnclaveError, Result};

/// RGB coin type for colored (RGB asset) operations.
const RGB_COIN_TYPE: u32 = 827167;

/// Public key info extracted from KeyManager for responses.
pub struct KeyInfo {
    pub evm_address: [u8; 20],
    pub btc_compressed_pubkey: [u8; 33],
    pub btc_xpub: String,
    pub master_fingerprint: [u8; 4],
    pub account_xpub_vanilla: String,
    pub account_xpub_colored: String,
}

/// Which BIP-86 account to derive from.
#[derive(Debug, Clone, Copy)]
pub enum AccountType {
    Vanilla,
    Colored,
}

/// Holds HD wallet keys in memory. Secrets are wrapped in SecretBox for
/// zeroize-on-drop. Public keys are stored in plain form.
pub struct KeyManager {
    seed: SecretBox<[u8; 64]>,
    evm_secret: SecretBox<[u8; 32]>,
    btc_secret: SecretBox<[u8; 32]>,
    evm_address: [u8; 20],
    btc_compressed_pubkey: [u8; 33],
    btc_xpub: Xpub,
    // BIP-86 taproot account keys
    master_fingerprint: Fingerprint,
    account_xpriv_vanilla: Xpriv,
    account_xpub_vanilla: Xpub,
    account_xpriv_colored: Xpriv,
    account_xpub_colored: Xpub,
    // Coin type used for vanilla derivation (0 = mainnet, 1 = testnet)
    vanilla_coin_type: u32,
}

impl KeyManager {
    /// Generate a new KeyManager from 256-bit entropy.
    /// Returns both the manager and the BIP-39 mnemonic (caller logs once, then discards).
    pub fn generate(entropy: &mut [u8; 32], network: Network) -> Result<(Self, Mnemonic)> {
        let mnemonic = Mnemonic::from_entropy(entropy)
            .map_err(|e| EnclaveError::InvalidKey(format!("mnemonic generation failed: {}", e)))?;
        entropy.zeroize();

        let seed = mnemonic.to_seed("");
        let manager = Self::from_seed(seed, network)?;
        Ok((manager, mnemonic))
    }

    /// Create a KeyManager from a BIP-39 mnemonic phrase string.
    pub fn from_mnemonic(mnemonic_str: &str, network: Network) -> Result<Self> {
        let mnemonic = Mnemonic::from_str(mnemonic_str)
            .map_err(|e| EnclaveError::InvalidKey(format!("invalid mnemonic: {}", e)))?;
        let seed = mnemonic.to_seed("");
        Self::from_seed(seed, network)
    }

    /// Create a KeyManager from a raw 64-byte BIP-39 seed.
    ///
    /// CRITICAL: The seed is moved into SecretBox FIRST, before any derivation.
    /// Do NOT zeroize the local seed before boxing — the stored seed would be
    /// all zeros and cloning would break later.
    pub fn from_seed(mut seed: [u8; 64], network: Network) -> Result<Self> {
        // Box the seed FIRST
        let seed_box = SecretBox::new(Box::new(seed));
        seed.zeroize();

        let secp = Secp256k1::new();

        // Derive master key from seed.
        // Use the actual network so xpub serialization produces the correct prefix
        // (xpub for mainnet, tpub for testnet/signet/regtest).
        let master = Xpriv::new_master(network, seed_box.expose_secret()).map_err(|e| {
            EnclaveError::InvalidKey(format!("master key derivation failed: {}", e))
        })?;

        let master_fingerprint = master.fingerprint(&secp);

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

        // === BTC Legacy: m/84'/0'/0'/0/0 (kept for backward compatibility) ===
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

        // === BIP-86 Taproot accounts ===
        // Vanilla coin type: 0 for mainnet, 1 for testnet/signet/regtest
        let vanilla_coin_type = match network {
            Network::Bitcoin => 0,
            _ => 1,
        };

        // Vanilla: m/86'/<coin_type>'/0'
        let vanilla_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(vanilla_coin_type).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        let account_xpriv_vanilla = master.derive_priv(&secp, &vanilla_path).map_err(|e| {
            EnclaveError::InvalidKey(format!("BIP-86 vanilla derivation failed: {}", e))
        })?;
        let account_xpub_vanilla = Xpub::from_priv(&secp, &account_xpriv_vanilla);

        // Colored: m/86'/827167'/0'
        let colored_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(RGB_COIN_TYPE).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        let account_xpriv_colored = master.derive_priv(&secp, &colored_path).map_err(|e| {
            EnclaveError::InvalidKey(format!("BIP-86 colored derivation failed: {}", e))
        })?;
        let account_xpub_colored = Xpub::from_priv(&secp, &account_xpriv_colored);

        Ok(Self {
            seed: seed_box,
            evm_secret,
            btc_secret,
            evm_address,
            btc_compressed_pubkey,
            btc_xpub,
            master_fingerprint,
            account_xpriv_vanilla,
            account_xpub_vanilla,
            account_xpriv_colored,
            account_xpub_colored,
            vanilla_coin_type,
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

    pub fn master_fingerprint(&self) -> &Fingerprint {
        &self.master_fingerprint
    }

    pub fn account_xpub_vanilla(&self) -> &Xpub {
        &self.account_xpub_vanilla
    }

    pub fn account_xpub_colored(&self) -> &Xpub {
        &self.account_xpub_colored
    }

    pub fn expose_seed(&self) -> &[u8; 64] {
        self.seed.expose_secret()
    }

    /// Derive a child secret key from one of the BIP-86 account xprivs.
    /// `child_path` is the relative path beyond the account level (e.g., [0, 7] for /0/7).
    pub fn derive_btc_child(
        &self,
        account: AccountType,
        child_path: &[ChildNumber],
    ) -> Result<SecretKey> {
        let secp = Secp256k1::new();
        let account_xpriv = match account {
            AccountType::Vanilla => &self.account_xpriv_vanilla,
            AccountType::Colored => &self.account_xpriv_colored,
        };
        let path = DerivationPath::from(child_path.to_vec());
        let child_xpriv = account_xpriv
            .derive_priv(&secp, &path)
            .map_err(|e| EnclaveError::InvalidKey(format!("child derivation failed: {}", e)))?;
        Ok(child_xpriv.private_key)
    }

    /// Determine which account type a full derivation path belongs to,
    /// and return the relative child path beyond the account level.
    /// E.g., m/86'/1'/0'/0/7 → (Vanilla, [0, 7]) on testnet.
    pub fn resolve_account_and_child_path(
        &self,
        full_path: &DerivationPath,
    ) -> Option<(AccountType, Vec<ChildNumber>)> {
        let steps: Vec<ChildNumber> = full_path.into_iter().cloned().collect();
        // Expect at least: 86' / coin_type' / 0' / ...
        if steps.len() < 3 {
            return None;
        }
        if steps[0] != ChildNumber::from_hardened_idx(86).unwrap() {
            return None;
        }
        if steps[2] != ChildNumber::from_hardened_idx(0).unwrap() {
            return None;
        }
        let coin_type = steps[1];
        let account_type =
            if coin_type == ChildNumber::from_hardened_idx(self.vanilla_coin_type).unwrap() {
                AccountType::Vanilla
            } else if coin_type == ChildNumber::from_hardened_idx(RGB_COIN_TYPE).unwrap() {
                AccountType::Colored
            } else {
                return None;
            };
        let child_path = steps[3..].to_vec();
        Some((account_type, child_path))
    }

    /// Sign a 32-byte message hash with the EVM secp256k1 key.
    /// Returns 65 bytes: r(32) + s(32) + v(1) — Ethereum `ecrecover` convention.
    pub fn sign_evm(&self, message_hash: &[u8; 32]) -> Result<[u8; 65]> {
        let signing_key = K256SigningKey::from_slice(self.evm_secret.expose_secret())
            .map_err(|e| EnclaveError::Signing(format!("evm key: {e}")))?;

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message_hash)
            .map_err(|e| EnclaveError::Signing(format!("ecdsa sign: {e}")))?;

        let mut result = [0u8; 65];
        result[..64].copy_from_slice(&signature.to_bytes());
        result[64] = recovery_id.to_byte();
        Ok(result)
    }

    /// Sign PSBT inputs matching our BTC key (SegWit v0 P2WSH multisig).
    /// Returns the modified PSBT bytes and count of inputs signed.
    pub fn sign_psbt(&self, psbt_bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(self.btc_secret.expose_secret())
            .map_err(|e| EnclaveError::Signing(format!("btc key: {e}")))?;
        let our_pubkey = secret_key.public_key(&secp);

        let mut psbt = Psbt::deserialize(psbt_bytes)
            .map_err(|e| EnclaveError::Signing(format!("psbt deserialize: {e}")))?;

        let unsigned_tx = psbt.unsigned_tx.clone();
        let mut sighash_cache = SighashCache::new(&unsigned_tx);
        let mut signed_count = 0usize;

        for i in 0..psbt.inputs.len() {
            if !crate::signing::psbt::should_sign_segwit_input(&psbt, i, &our_pubkey) {
                continue;
            }

            // SegWit v0 P2WSH: need witness_utxo (for value) and witness_script
            let witness_utxo = psbt.inputs[i].witness_utxo.as_ref().ok_or_else(|| {
                EnclaveError::Signing(format!("missing witness_utxo for input {i}"))
            })?;
            let witness_script = psbt.inputs[i].witness_script.as_ref().ok_or_else(|| {
                EnclaveError::Signing(format!("missing witness_script for input {i}"))
            })?;

            // BIP-143 sighash for SegWit v0
            let sighash = sighash_cache
                .p2wsh_signature_hash(i, witness_script, witness_utxo.value, EcdsaSighashType::All)
                .map_err(|e| EnclaveError::Signing(format!("sighash: {e}")))?;

            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_ecdsa(&msg, &secret_key);

            // Insert partial signature into PSBT
            let bitcoin_sig = bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            };
            psbt.inputs[i]
                .partial_sigs
                .insert(bitcoin::PublicKey::new(our_pubkey), bitcoin_sig);
            signed_count += 1;
        }

        let signed_bytes = psbt.serialize();
        Ok((signed_bytes, signed_count))
    }
}

/// Thread-safe enclave state holding an optional KeyManager behind a Mutex.
pub struct EnclaveState {
    inner: Mutex<Option<KeyManager>>,
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
            inner: Mutex::new(None),
            network,
        }
    }

    pub fn network(&self) -> Network {
        self.network
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
        let (manager, mnemonic) = KeyManager::generate(entropy, self.network)?;
        *guard = Some(manager);
        Ok(mnemonic)
    }

    /// Initialize from a BIP-39 mnemonic phrase (testing only, requires allow-seed-import feature).
    pub fn initialize_from_mnemonic(&self, mnemonic_str: &str) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("lock poisoned: {}", e)))?;
        if guard.is_some() {
            return Err(EnclaveError::AlreadyInitialized);
        }
        let manager = KeyManager::from_mnemonic(mnemonic_str, self.network)?;
        *guard = Some(manager);
        Ok(())
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
        let manager = KeyManager::from_seed(seed, self.network)?;
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
                master_fingerprint: km.master_fingerprint().to_bytes(),
                account_xpub_vanilla: km.account_xpub_vanilla().to_string(),
                account_xpub_colored: km.account_xpub_colored().to_string(),
            }),
            None => Err(EnclaveError::KeyNotInitialized),
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.inner.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Sign a 32-byte EVM message hash. Returns 65-byte signature.
    pub fn sign_evm(&self, message_hash: &[u8; 32]) -> Result<[u8; 65]> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("lock poisoned: {}", e)))?;
        match guard.as_ref() {
            Some(km) => km.sign_evm(message_hash),
            None => Err(EnclaveError::KeyNotInitialized),
        }
    }

    /// Sign PSBT inputs matching our BTC key. Returns (signed_psbt_bytes, inputs_signed).
    pub fn sign_psbt(&self, psbt_bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("lock poisoned: {}", e)))?;
        match guard.as_ref() {
            Some(km) => km.sign_psbt(psbt_bytes),
            None => Err(EnclaveError::KeyNotInitialized),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let seed = [42u8; 64];
        let km1 = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
        let km2 = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();

        assert_eq!(km1.evm_address(), km2.evm_address());
        assert_eq!(km1.btc_compressed_pubkey(), km2.btc_compressed_pubkey());
        assert_eq!(km1.btc_xpub().to_string(), km2.btc_xpub().to_string());
    }

    #[test]
    fn from_mnemonic_deterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let km1 = KeyManager::from_mnemonic(mnemonic, Network::Bitcoin).unwrap();
        let km2 = KeyManager::from_mnemonic(mnemonic, Network::Bitcoin).unwrap();

        assert_eq!(km1.evm_address(), km2.evm_address());
        assert_eq!(km1.btc_compressed_pubkey(), km2.btc_compressed_pubkey());
        assert_eq!(km1.btc_xpub().to_string(), km2.btc_xpub().to_string());
    }

    #[test]
    fn from_mnemonic_matches_seed_derivation() {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
        let seed = mnemonic.to_seed("");

        let km_mnemonic = KeyManager::from_mnemonic(mnemonic_str, Network::Bitcoin).unwrap();
        let km_seed = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();

        assert_eq!(km_mnemonic.evm_address(), km_seed.evm_address());
        assert_eq!(
            km_mnemonic.btc_compressed_pubkey(),
            km_seed.btc_compressed_pubkey()
        );
    }

    #[test]
    fn from_mnemonic_invalid() {
        let result = KeyManager::from_mnemonic("not a valid mnemonic", Network::Bitcoin);
        assert!(result.is_err());
    }

    #[test]
    fn initialize_from_mnemonic_then_double_init_fails() {
        let state = EnclaveState::new(Network::Bitcoin);
        state
            .initialize_from_mnemonic(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            )
            .unwrap();
        let result =
            state.initialize_from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
        assert!(result.is_err());
    }

    #[test]
    fn bip86_testnet_derivation_matches_known_mnemonic() {
        // Known test vector from colleague's multisig setup
        let km = KeyManager::from_mnemonic(
            "rail item marble one share venture artist brisk useful upset bus amused",
            Network::Testnet,
        )
        .unwrap();

        assert_eq!(hex::encode(km.master_fingerprint().to_bytes()), "82fb42e4");
        assert_eq!(
            km.account_xpub_vanilla().to_string(),
            "tpubDDCUjHgx7hFxgc9Zn4tGWyiBsxeGNXfA1oGBMykU7W5LNESKAxtVafP55gqfapRPM5f1wgUG7c9hqvzh548C8g5JTZSxCTCS2nxoBHPWGaH"
        );
        assert_eq!(
            km.account_xpub_colored().to_string(),
            "tpubDDgKC4Kea1GDCQBdR7i2SBycbDhydEHqqDguZZze7A6rLGqRD5YAYD29JAHydzGAmkcoHHdkjazd54zBEr4KPWQftyN3LiyGxGKw7CM38HR"
        );
    }

    #[test]
    fn bip86_second_known_mnemonic() {
        // Second cosigner from the same multisig setup
        let km = KeyManager::from_mnemonic(
            "season pave name banana aspect inject book roast clown young hill unhappy",
            Network::Testnet,
        )
        .unwrap();

        assert_eq!(hex::encode(km.master_fingerprint().to_bytes()), "9f249100");
        assert_eq!(
            km.account_xpub_colored().to_string(),
            "tpubDCSLyZybm4TSDo3aeCK5Ke2iPQQFJ6vrKAuyEa4v5F1Xnoi5UtbEeMBCQ1RtwvEH43NKnzSp63aNQUrkB6sQL6FSW2wqZVWupAy1hV3fcFw"
        );
    }

    #[test]
    fn bip86_vanilla_and_colored_xpubs_differ() {
        let km = KeyManager::from_seed([42u8; 64], Network::Testnet).unwrap();
        assert_ne!(
            km.account_xpub_vanilla().to_string(),
            km.account_xpub_colored().to_string()
        );
    }

    #[test]
    fn bip86_mainnet_vs_testnet_vanilla_differ() {
        let seed = [42u8; 64];
        let km_main = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
        let km_test = KeyManager::from_seed(seed, Network::Testnet).unwrap();

        // Same master fingerprint (derived from same seed)
        assert_eq!(km_main.master_fingerprint(), km_test.master_fingerprint());
        // Different vanilla xpubs (different coin type + different network prefix)
        assert_ne!(
            km_main.account_xpub_vanilla().to_string(),
            km_test.account_xpub_vanilla().to_string()
        );
        // Mainnet xpubs start with "xpub", testnet with "tpub"
        assert!(km_main
            .account_xpub_vanilla()
            .to_string()
            .starts_with("xpub"));
        assert!(km_test
            .account_xpub_vanilla()
            .to_string()
            .starts_with("tpub"));
    }

    #[test]
    fn resolve_account_and_child_path_works() {
        let km = KeyManager::from_seed([42u8; 64], Network::Testnet).unwrap();

        // m/86'/1'/0'/0/7 → Vanilla, [0, 7]
        let path = DerivationPath::from_str("m/86'/1'/0'/0/7").unwrap();
        let (account, child) = km.resolve_account_and_child_path(&path).unwrap();
        assert!(matches!(account, AccountType::Vanilla));
        assert_eq!(child.len(), 2);

        // m/86'/827167'/0'/0/3 → Colored, [0, 3]
        let path = DerivationPath::from_str("m/86'/827167'/0'/0/3").unwrap();
        let (account, child) = km.resolve_account_and_child_path(&path).unwrap();
        assert!(matches!(account, AccountType::Colored));
        assert_eq!(child.len(), 2);

        // m/84'/0'/0'/0/0 → None (wrong purpose)
        let path = DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
        assert!(km.resolve_account_and_child_path(&path).is_none());
    }

    #[test]
    fn derive_btc_child_deterministic() {
        let km = KeyManager::from_seed([42u8; 64], Network::Testnet).unwrap();
        let child1 = km
            .derive_btc_child(
                AccountType::Vanilla,
                &[
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .unwrap();
        let child2 = km
            .derive_btc_child(
                AccountType::Vanilla,
                &[
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .unwrap();
        assert_eq!(child1.secret_bytes(), child2.secret_bytes());
    }

    #[test]
    fn generate_different_keys() {
        let mut entropy1 = [1u8; 32];
        let mut entropy2 = [2u8; 32];
        let (km1, _) = KeyManager::generate(&mut entropy1, Network::Bitcoin).unwrap();
        let (km2, _) = KeyManager::generate(&mut entropy2, Network::Bitcoin).unwrap();

        assert_ne!(km1.evm_address(), km2.evm_address());
    }

    #[test]
    fn key_formats() {
        let seed = [42u8; 64];
        let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();

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
        let km = KeyManager::from_seed(original_seed, Network::Bitcoin).unwrap();
        assert_eq!(km.expose_seed(), &original_seed);
    }

    #[test]
    fn double_initialization_error() {
        let state = EnclaveState::new(Network::Bitcoin);
        let mut entropy1 = [1u8; 32];
        let mut entropy2 = [2u8; 32];

        state.initialize_from_entropy(&mut entropy1).unwrap();
        let result = state.initialize_from_entropy(&mut entropy2);
        assert!(result.is_err());
    }

    #[test]
    fn get_keys_before_init_error() {
        let state = EnclaveState::new(Network::Bitcoin);
        let result = state.get_keys();
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_evm_produces_65_bytes() {
        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
        let hash = [0xABu8; 32];
        let sig = km.sign_evm(&hash).unwrap();
        assert_eq!(sig.len(), 65);
        // recovery_id should be 0 or 1
        assert!(sig[64] <= 1);
    }

    #[test]
    fn test_sign_evm_deterministic() {
        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
        let hash = [0xABu8; 32];
        let sig1 = km.sign_evm(&hash).unwrap();
        let sig2 = km.sign_evm(&hash).unwrap();
        assert_eq!(sig1, sig2); // k256 uses RFC 6979 deterministic nonces
    }

    #[test]
    fn test_sign_evm_recoverable() {
        use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
        let hash = [0xABu8; 32];
        let sig_bytes = km.sign_evm(&hash).unwrap();

        let signature = K256Signature::from_slice(&sig_bytes[..64]).unwrap();
        let recovery_id = RecoveryId::from_byte(sig_bytes[64]).unwrap();
        let recovered_key =
            VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id).unwrap();

        // Derive address from recovered key and compare
        let pubkey_bytes = recovered_key.to_encoded_point(false);
        let pubkey_hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
        let recovered_address: [u8; 20] = pubkey_hash[12..].try_into().unwrap();

        assert_eq!(&recovered_address, km.evm_address());
    }

    /// Build a minimal 2-of-3 multisig PSBT for testing.
    fn build_test_multisig_psbt(our_pubkey: &bitcoin::PublicKey) -> Vec<u8> {
        use bitcoin::blockdata::opcodes::all::*;
        use bitcoin::blockdata::script::Builder as ScriptBuilder;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};

        let secp = Secp256k1::new();

        let sk2 = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let pk2 = bitcoin::PublicKey::new(sk2.public_key(&secp));
        let sk3 = SecretKey::from_slice(&[0x03; 32]).unwrap();
        let pk3 = bitcoin::PublicKey::new(sk3.public_key(&secp));

        let mut pubkeys = [*our_pubkey, pk2, pk3];
        pubkeys.sort_by_key(|k| k.to_bytes());

        let witness_script = ScriptBuilder::new()
            .push_int(2)
            .push_key(&pubkeys[0])
            .push_key(&pubkeys[1])
            .push_key(&pubkeys[2])
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xAA; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [0xBB; 20],
                )),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let witness_script_hash = bitcoin::WScriptHash::hash(witness_script.as_bytes());
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wsh(&witness_script_hash),
        });
        psbt.inputs[0].witness_script = Some(witness_script);

        psbt.serialize()
    }

    #[test]
    fn test_sign_psbt_one_input() {
        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();

        let our_pubkey = bitcoin::PublicKey::from_slice(km.btc_compressed_pubkey()).unwrap();
        let psbt_bytes = build_test_multisig_psbt(&our_pubkey);

        let (signed_bytes, count) = km.sign_psbt(&psbt_bytes).unwrap();
        assert_eq!(count, 1);

        let signed_psbt = Psbt::deserialize(&signed_bytes).unwrap();
        assert!(signed_psbt.inputs[0].partial_sigs.contains_key(&our_pubkey));
    }

    #[test]
    fn test_sign_psbt_skip_already_signed() {
        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();

        let our_pubkey = bitcoin::PublicKey::from_slice(km.btc_compressed_pubkey()).unwrap();
        let psbt_bytes = build_test_multisig_psbt(&our_pubkey);

        let (signed_bytes, count1) = km.sign_psbt(&psbt_bytes).unwrap();
        assert_eq!(count1, 1);

        // Sign the already-signed PSBT again — should skip
        let (_, count2) = km.sign_psbt(&signed_bytes).unwrap();
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_sign_psbt_invalid_bytes() {
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).unwrap();
        let (km, _mnemonic) = KeyManager::generate(&mut entropy, Network::Bitcoin).unwrap();

        let result = km.sign_psbt(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_psbt_no_matching_inputs() {
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).unwrap();
        let (km, _mnemonic) = KeyManager::generate(&mut entropy, Network::Bitcoin).unwrap();

        let secp = Secp256k1::new();
        let other_sk = SecretKey::from_slice(&[0x99; 32]).unwrap();
        let other_pk = bitcoin::PublicKey::new(other_sk.public_key(&secp));
        let psbt_bytes = build_test_multisig_psbt(&other_pk);

        let (_, count) = km.sign_psbt(&psbt_bytes).unwrap();
        assert_eq!(count, 0);
    }
}
