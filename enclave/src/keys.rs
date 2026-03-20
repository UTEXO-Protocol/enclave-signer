use std::str::FromStr;
use std::sync::Mutex;

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
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

/// Public key info extracted from KeyManager for responses.
pub struct KeyInfo {
    pub evm_address: [u8; 20],
    pub btc_compressed_pubkey: [u8; 33],
    pub btc_xpub: String,
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
}

impl Default for EnclaveState {
    fn default() -> Self {
        Self::new()
    }
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

    #[test]
    fn test_sign_evm_produces_65_bytes() {
        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed).unwrap();
        let hash = [0xABu8; 32];
        let sig = km.sign_evm(&hash).unwrap();
        assert_eq!(sig.len(), 65);
        // recovery_id should be 0 or 1
        assert!(sig[64] <= 1);
    }

    #[test]
    fn test_sign_evm_deterministic() {
        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed).unwrap();
        let hash = [0xABu8; 32];
        let sig1 = km.sign_evm(&hash).unwrap();
        let sig2 = km.sign_evm(&hash).unwrap();
        assert_eq!(sig1, sig2); // k256 uses RFC 6979 deterministic nonces
    }

    #[test]
    fn test_sign_evm_recoverable() {
        use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed).unwrap();
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
                script_pubkey: ScriptBuf::new_p2wpkh(
                    &bitcoin::WPubkeyHash::from_byte_array([0xBB; 20]),
                ),
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
        let km = KeyManager::from_seed(seed).unwrap();

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
        let km = KeyManager::from_seed(seed).unwrap();

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
        let (km, _mnemonic) = KeyManager::generate(&mut entropy).unwrap();

        let result = km.sign_psbt(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_psbt_no_matching_inputs() {
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).unwrap();
        let (km, _mnemonic) = KeyManager::generate(&mut entropy).unwrap();

        let secp = Secp256k1::new();
        let other_sk = SecretKey::from_slice(&[0x99; 32]).unwrap();
        let other_pk = bitcoin::PublicKey::new(other_sk.public_key(&secp));
        let psbt_bytes = build_test_multisig_psbt(&other_pk);

        let (_, count) = km.sign_psbt(&psbt_bytes).unwrap();
        assert_eq!(count, 0);
    }
}
