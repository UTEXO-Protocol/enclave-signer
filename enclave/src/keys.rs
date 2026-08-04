use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::Network;
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use hmac::{Hmac, Mac};
use k256::ecdsa::SigningKey as K256SigningKey;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use crate::error::{EnclaveError, Result};

/// RGB coin type for colored (RGB asset) operations.
const RGB_COIN_TYPE: u32 = 827167;

/// SLIP-44 coin type for Concordium.
const CONCORDIUM_COIN_TYPE: u32 = 919;

type HmacSha512 = Hmac<Sha512>;

/// SLIP-0010 Ed25519 hardened key derivation. Returns the 32-byte private key at
/// the given path. Every index is treated as hardened — SLIP-0010 Ed25519 only
/// supports hardened derivation.
fn derive_ed25519_slip10(seed: &[u8; 64], path: &[u32]) -> [u8; 32] {
    // Master key: I = HMAC-SHA512(key="ed25519 seed", data=seed).
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").expect("HMAC accepts any key length");
    mac.update(seed);
    let mut i = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&i[0..32]);
    chain.copy_from_slice(&i[32..64]);

    // Child: I = HMAC-SHA512(key=chain, data=0x00 || key || ser32(index | hardened)).
    for &index in path {
        let hardened = index | 0x8000_0000;
        let mut mac = HmacSha512::new_from_slice(&chain).expect("HMAC accepts any key length");
        mac.update(&[0u8]);
        mac.update(&key);
        mac.update(&hardened.to_be_bytes());
        i = mac.finalize().into_bytes();
        key.copy_from_slice(&i[0..32]);
        chain.copy_from_slice(&i[32..64]);
    }

    i.fill(0);
    chain.zeroize();
    key
}

/// Public key info extracted from KeyManager for responses.
pub struct KeyInfo {
    pub evm_address: [u8; 20],
    pub evm_uncompressed_pub: [u8; 64],
    pub evm_gas_tx_address: [u8; 20],
    pub evm_gas_tx_uncompressed_pub: [u8; 64],
    pub btc_compressed_pubkey: [u8; 33],
    pub btc_xpub: String,
    pub master_fingerprint: [u8; 4],
    pub account_xpub_vanilla: String,
    pub account_xpub_colored: String,
    pub ccd_ed25519_pub: [u8; 32],
}

/// Which BIP-86 account to derive from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountType {
    Vanilla,
    Colored,
}

/// Holds HD wallet keys in memory. Secrets are wrapped in SecretBox for
/// zeroize-on-drop. Public keys are stored in plain form.
pub struct KeyManager {
    seed: SecretBox<[u8; 64]>,
    evm_secret: SecretBox<[u8; 32]>,
    evm_gas_tx_secret: SecretBox<[u8; 32]>,
    btc_secret: SecretBox<[u8; 32]>,
    evm_address: [u8; 20],
    evm_uncompressed_pub: [u8; 64],
    evm_gas_tx_address: [u8; 20],
    evm_gas_tx_uncompressed_pub: [u8; 64],
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
    // Concordium Ed25519 governance key (SLIP-0010, m/44'/919'/0'/0'/0').
    concordium_secret: SecretBox<[u8; 32]>,
    concordium_pub: [u8; 32],
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
        let mut evm_uncompressed_pub = [0u8; 64];
        evm_uncompressed_pub.copy_from_slice(&evm_uncompressed[1..]);
        let hash = Keccak256::digest(evm_uncompressed_pub);
        let mut evm_address = [0u8; 20];
        evm_address.copy_from_slice(&hash[12..32]);

        // === EVM Gas TX: m/44'/60'/0'/0/1 (separate key for gas transaction signing) ===
        let evm_gas_tx_path = DerivationPath::from_str("m/44'/60'/0'/0/1")
            .map_err(|e| EnclaveError::InvalidKey(format!("invalid EVM gas TX path: {}", e)))?;
        let evm_gas_tx_xpriv = master.derive_priv(&secp, &evm_gas_tx_path).map_err(|e| {
            EnclaveError::InvalidKey(format!("EVM gas TX derivation failed: {}", e))
        })?;
        let evm_gas_tx_secret_key = evm_gas_tx_xpriv.private_key;
        let mut evm_gas_tx_secret_bytes = evm_gas_tx_secret_key.secret_bytes();
        let evm_gas_tx_secret = SecretBox::new(Box::new(evm_gas_tx_secret_bytes));
        evm_gas_tx_secret_bytes.zeroize();

        let evm_gas_tx_pubkey = PublicKey::from_secret_key(&secp, &evm_gas_tx_secret_key);
        let evm_gas_tx_uncompressed = evm_gas_tx_pubkey.serialize_uncompressed();
        let mut evm_gas_tx_uncompressed_pub = [0u8; 64];
        evm_gas_tx_uncompressed_pub.copy_from_slice(&evm_gas_tx_uncompressed[1..]);
        let gas_tx_hash = Keccak256::digest(evm_gas_tx_uncompressed_pub);
        let mut evm_gas_tx_address = [0u8; 20];
        evm_gas_tx_address.copy_from_slice(&gas_tx_hash[12..32]);

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

        // === Concordium: Ed25519 via SLIP-0010, m/44'/919'/0'/0'/0' (all hardened) ===
        let mut concordium_secret_bytes = derive_ed25519_slip10(
            seed_box.expose_secret(),
            &[44, CONCORDIUM_COIN_TYPE, 0, 0, 0],
        );
        let concordium_signing = Ed25519SigningKey::from_bytes(&concordium_secret_bytes);
        let concordium_pub = concordium_signing.verifying_key().to_bytes();
        let concordium_secret = SecretBox::new(Box::new(concordium_secret_bytes));
        concordium_secret_bytes.zeroize();
        drop(concordium_signing);

        Ok(Self {
            seed: seed_box,
            evm_secret,
            evm_gas_tx_secret,
            btc_secret,
            evm_address,
            evm_uncompressed_pub,
            evm_gas_tx_address,
            evm_gas_tx_uncompressed_pub,
            btc_compressed_pubkey,
            btc_xpub,
            master_fingerprint,
            account_xpriv_vanilla,
            account_xpub_vanilla,
            account_xpriv_colored,
            account_xpub_colored,
            vanilla_coin_type,
            concordium_secret,
            concordium_pub,
        })
    }

    pub fn evm_address(&self) -> &[u8; 20] {
        &self.evm_address
    }

    pub fn evm_uncompressed_pub(&self) -> &[u8; 64] {
        &self.evm_uncompressed_pub
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

    pub fn evm_gas_tx_address(&self) -> &[u8; 20] {
        &self.evm_gas_tx_address
    }

    pub fn evm_gas_tx_uncompressed_pub(&self) -> &[u8; 64] {
        &self.evm_gas_tx_uncompressed_pub
    }

    pub fn ccd_ed25519_pub(&self) -> &[u8; 32] {
        &self.concordium_pub
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

    /// Sign a 32-byte digest with the EVM gas TX key (m/44'/60'/0'/0/1).
    /// Used exclusively for Ethereum gas transaction signing.
    pub fn sign_evm_gas_tx(&self, message_hash: &[u8; 32]) -> Result<[u8; 65]> {
        let signing_key = K256SigningKey::from_slice(self.evm_gas_tx_secret.expose_secret())
            .map_err(|e| EnclaveError::Signing(format!("evm gas tx key: {e}")))?;

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message_hash)
            .map_err(|e| EnclaveError::Signing(format!("ecdsa sign gas tx: {e}")))?;

        let mut result = [0u8; 65];
        result[..64].copy_from_slice(&signature.to_bytes());
        result[64] = recovery_id.to_byte();
        Ok(result)
    }

    /// Sign a 32-byte Concordium account-transaction hash with the governance
    /// Ed25519 key. Concordium signs the transaction hash directly with plain
    /// Ed25519 (no additional hashing). Returns the 64-byte signature.
    pub fn sign_ccd(&self, hash: &[u8; 32]) -> Result<[u8; 64]> {
        let signing_key = Ed25519SigningKey::from_bytes(self.concordium_secret.expose_secret());
        Ok(signing_key.sign(hash).to_bytes())
    }

    /// Sign PSBT inputs matching our keys.
    /// Auto-detects taproot (Schnorr, BIP-340) vs SegWit v0 P2WSH (ECDSA) per input.
    /// Returns the modified PSBT bytes and count of inputs signed.
    pub fn sign_psbt(&self, psbt_bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
        self.sign_psbt_scoped(psbt_bytes, None)
    }

    /// Sign PSBT inputs matching our keys, optionally restricted to a single
    /// BIP-86 account.
    ///
    /// `allowed_account`:
    ///   * `None` — sign every input we can (taproot any account + legacy
    ///     P2WSH). Used by the consignment-bound bridge path (`SignPsbt`),
    ///     where the consignment, not the account, is the authorization.
    ///   * `Some(account)` — sign ONLY taproot inputs resolving to `account`,
    ///     and skip the legacy P2WSH path entirely. The plain-BTC path
    ///     (`SignBtc`) passes `Some(Vanilla)` so it can never co-sign a
    ///     Colored (RGB-allocated) input — those move only via the
    ///     consignment-bound path. This is the structural guard that keeps the
    ///     M-01 fix from being reopened on the plain-BTC sibling path.
    pub fn sign_psbt_scoped(
        &self,
        psbt_bytes: &[u8],
        allowed_account: Option<AccountType>,
    ) -> Result<(Vec<u8>, usize)> {
        let secp = Secp256k1::new();

        let mut psbt = Psbt::deserialize(psbt_bytes)
            .map_err(|e| EnclaveError::Signing(format!("psbt deserialize: {e}")))?;

        let mut signed_count = 0usize;

        // === Taproot signing (BIP-86 / BIP-340 Schnorr) ===
        let mut taproot_jobs = crate::networks::rgb::signing::taproot::find_taproot_sign_jobs(
            &psbt,
            &self.master_fingerprint,
            self,
        );
        if let Some(account) = allowed_account {
            // Plain-BTC path: refuse any input that resolves to a different
            // account (e.g. Colored/RGB). Dropping the job means the input is
            // left unsigned.
            taproot_jobs.retain(|job| job.account_type == account);
        }
        if !taproot_jobs.is_empty() {
            signed_count += crate::networks::rgb::signing::taproot::sign_taproot_inputs(
                &mut psbt,
                self,
                &taproot_jobs,
            )?;
        }

        // === Legacy SegWit v0 P2WSH signing (ECDSA) ===
        // Skipped entirely on an account-scoped call: the legacy single key is
        // not BIP-86-account-derived, so it has no place on the plain-BTC path.
        if allowed_account.is_some() {
            return Ok((psbt.serialize(), signed_count));
        }
        let secret_key = SecretKey::from_slice(self.btc_secret.expose_secret())
            .map_err(|e| EnclaveError::Signing(format!("btc key: {e}")))?;
        let our_pubkey = secret_key.public_key(&secp);

        let unsigned_tx = psbt.unsigned_tx.clone();
        let mut sighash_cache = SighashCache::new(&unsigned_tx);

        for i in 0..psbt.inputs.len() {
            let crate::networks::rgb::signing::psbt::SegwitSignDecision::SignP2wsh {
                witness_script,
            } = crate::networks::rgb::signing::psbt::should_sign_segwit_input(
                &psbt,
                i,
                &our_pubkey,
            )
            else {
                continue;
            };

            // SAFETY: SignP2wsh is only returned when witness_utxo is present
            // and committed to witness_script.
            let witness_utxo_value = psbt.inputs[i]
                .witness_utxo
                .as_ref()
                .expect("SignP2wsh implies witness_utxo present")
                .value;

            let sighash = sighash_cache
                .p2wsh_signature_hash(
                    i,
                    &witness_script,
                    witness_utxo_value,
                    EcdsaSighashType::All,
                )
                .map_err(|e| EnclaveError::Signing(format!("sighash: {e}")))?;

            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_ecdsa(&msg, &secret_key);

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

impl Drop for KeyManager {
    /// Wipe the BIP-86 account extended private keys on teardown (I-07).
    ///
    /// Unlike `seed`/`evm_secret`/`btc_secret`, these are stored as plain `Xpriv`
    /// fields and are not covered by `SecretBox`'s zeroize-on-drop. Each `Xpriv`
    /// carries a signing `private_key` and a sensitive `chain_code`; overwrite both.
    fn drop(&mut self) {
        self.account_xpriv_vanilla.private_key.non_secure_erase();
        self.account_xpriv_colored.private_key.non_secure_erase();
        self.account_xpriv_vanilla.chain_code = ChainCode::from([0u8; 32]);
        self.account_xpriv_colored.chain_code = ChainCode::from([0u8; 32]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::EnclaveState;

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

    #[test]
    fn test_concordium_pubkey_deterministic() {
        let seed = [0x42u8; 64];
        let km1 = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
        let km2 = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
        assert_eq!(km1.ccd_ed25519_pub(), km2.ccd_ed25519_pub());
        assert_eq!(km1.ccd_ed25519_pub().len(), 32);
    }

    #[test]
    fn test_concordium_different_seeds_differ() {
        let a = KeyManager::from_seed([0x42u8; 64], Network::Bitcoin).unwrap();
        let b = KeyManager::from_seed([0x99u8; 64], Network::Bitcoin).unwrap();
        assert_ne!(a.ccd_ed25519_pub(), b.ccd_ed25519_pub());
    }

    #[test]
    fn test_sign_ccd_produces_valid_signature() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let km = KeyManager::from_seed([0x42u8; 64], Network::Bitcoin).unwrap();
        let hash = [0xABu8; 32];
        let sig_bytes = km.sign_ccd(&hash).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        let vk = VerifyingKey::from_bytes(km.ccd_ed25519_pub()).unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(&hash, &sig).is_ok());
    }

    #[test]
    fn test_sign_ccd_deterministic() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Bitcoin).unwrap();
        let hash = [0xABu8; 32];
        // Ed25519 (RFC 8032) is deterministic.
        assert_eq!(km.sign_ccd(&hash).unwrap(), km.sign_ccd(&hash).unwrap());
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

    /// Adversarial: 2-of-3 P2WSH where the TEE is NOT a cosigner, but the PSBT
    /// places our pubkey in `bip32_derivation`. The pre-fix code signed; the
    /// post-fix code must refuse.
    #[test]
    fn adversarial_psbt_forged_bip32_derivation_is_not_signed() {
        use bitcoin::blockdata::opcodes::all::*;
        use bitcoin::blockdata::script::Builder as ScriptBuilder;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};

        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
        let our_pk = PublicKey::from_slice(km.btc_compressed_pubkey()).unwrap();
        let our_btc_pk = bitcoin::PublicKey::new(our_pk);

        let secp = Secp256k1::new();
        let pk_other = |b: u8| {
            bitcoin::PublicKey::new(SecretKey::from_slice(&[b; 32]).unwrap().public_key(&secp))
        };
        let mut others = [pk_other(0xA1), pk_other(0xA2), pk_other(0xA3)];
        others.sort_by_key(|k| k.to_bytes());

        let witness_script = ScriptBuilder::new()
            .push_int(2)
            .push_key(&others[0])
            .push_key(&others[1])
            .push_key(&others[2])
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
        let ws_hash = bitcoin::WScriptHash::hash(witness_script.as_bytes());
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wsh(&ws_hash),
        });
        psbt.inputs[0].witness_script = Some(witness_script);

        // Plant our pubkey in bip32_derivation — the lie.
        psbt.inputs[0].bip32_derivation.insert(
            our_pk,
            (
                *km.master_fingerprint(),
                bitcoin::bip32::DerivationPath::from(vec![]),
            ),
        );

        let (signed_bytes, count) = km.sign_psbt(&psbt.serialize()).unwrap();
        assert_eq!(
            count, 0,
            "TEE must not sign when it is not in witness_script"
        );
        let signed = Psbt::deserialize(&signed_bytes).unwrap();
        assert!(!signed.inputs[0].partial_sigs.contains_key(&our_btc_pk));
    }

    /// Adversarial: `script_pubkey` commits to script A (not containing us) but
    /// the PSBT ships script B (containing our pubkey) as `witness_script`.
    /// Pre-fix sliding-window/bip32 paths could accept; post-fix must refuse
    /// because sha256(B) != script_pubkey's witness program.
    #[test]
    fn adversarial_psbt_witness_script_mismatch_is_not_signed() {
        use bitcoin::blockdata::opcodes::all::*;
        use bitcoin::blockdata::script::Builder as ScriptBuilder;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};

        let seed = [0x42u8; 64];
        let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
        let our_pk = PublicKey::from_slice(km.btc_compressed_pubkey()).unwrap();
        let our_btc_pk = bitcoin::PublicKey::new(our_pk);

        let secp = Secp256k1::new();
        let pk_other = |b: u8| {
            bitcoin::PublicKey::new(SecretKey::from_slice(&[b; 32]).unwrap().public_key(&secp))
        };

        // Script A — what the on-chain UTXO actually commits to (no us).
        let mut keys_a = [pk_other(0xA1), pk_other(0xA2), pk_other(0xA3)];
        keys_a.sort_by_key(|k| k.to_bytes());
        let script_a = ScriptBuilder::new()
            .push_int(2)
            .push_key(&keys_a[0])
            .push_key(&keys_a[1])
            .push_key(&keys_a[2])
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let real_spk = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::hash(script_a.as_bytes()));

        // Script B — what the attacker ships in PSBT (contains us).
        let mut keys_b = [our_btc_pk, pk_other(0xA2), pk_other(0xA3)];
        keys_b.sort_by_key(|k| k.to_bytes());
        let script_b = ScriptBuilder::new()
            .push_int(2)
            .push_key(&keys_b[0])
            .push_key(&keys_b[1])
            .push_key(&keys_b[2])
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
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: real_spk,
        });
        psbt.inputs[0].witness_script = Some(script_b);

        let (signed_bytes, count) = km.sign_psbt(&psbt.serialize()).unwrap();
        assert_eq!(
            count, 0,
            "TEE must not sign when witness_script does not hash to script_pubkey"
        );
        let signed = Psbt::deserialize(&signed_bytes).unwrap();
        assert!(!signed.inputs[0].partial_sigs.contains_key(&our_btc_pk));
    }

    /// Build a taproot multi_a(2, pk1, pk2, pk3) PSBT for testing.
    /// The signer's key is derived at m/86'/1'/0'/0/0 (vanilla testnet).
    fn build_test_taproot_psbt(km: &KeyManager) -> Vec<u8> {
        use bitcoin::bip32::ChildNumber;
        use bitcoin::blockdata::opcodes::all::*;
        use bitcoin::blockdata::script::Builder as ScriptBuilder;
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
        };

        let secp = Secp256k1::new();

        // Our key: derive child at m/86'/1'/0'/0/0
        let our_secret = km
            .derive_btc_child(
                AccountType::Vanilla,
                &[
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .unwrap();
        let our_keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &our_secret);
        let (our_xonly, _parity) = XOnlyPublicKey::from_keypair(&our_keypair);

        // Two other cosigner keys
        let sk2 = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let kp2 = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk2);
        let (xonly2, _) = XOnlyPublicKey::from_keypair(&kp2);

        let sk3 = SecretKey::from_slice(&[0x03; 32]).unwrap();
        let kp3 = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk3);
        let (xonly3, _) = XOnlyPublicKey::from_keypair(&kp3);

        // Build multi_a(2, pk1, pk2, pk3) tapscript:
        // pk1 OP_CHECKSIG pk2 OP_CHECKSIGADD pk3 OP_CHECKSIGADD 2 OP_NUMEQUAL
        let mut keys = [our_xonly, xonly2, xonly3];
        keys.sort();

        let tap_script = ScriptBuilder::new()
            .push_x_only_key(&keys[0])
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&keys[1])
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&keys[2])
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script();

        let leaf_hash = TapLeafHash::from_script(&tap_script, LeafVersion::TapScript);

        // Use an unspendable internal key (NUMS point)
        let internal_key = XOnlyPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .unwrap();

        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, tap_script.clone())
            .unwrap();
        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        let script_pubkey =
            ScriptBuf::new_p2tr(&secp, internal_key, taproot_spend_info.merkle_root());

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
                script_pubkey: ScriptBuf::new_p2tr_tweaked(taproot_spend_info.output_key()),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        // Set witness_utxo
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        });

        // Set tap_internal_key
        psbt.inputs[0].tap_internal_key = Some(internal_key);

        // Set tap_scripts (control block → script)
        let control_block = taproot_spend_info
            .control_block(&(tap_script.clone(), LeafVersion::TapScript))
            .unwrap();
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (tap_script, LeafVersion::TapScript));

        // Set tap_key_origins for our key
        let our_fingerprint = *km.master_fingerprint();
        let our_derivation = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(), // testnet
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ]);
        psbt.inputs[0].tap_key_origins.insert(
            our_xonly,
            (vec![leaf_hash], (our_fingerprint, our_derivation)),
        );

        psbt.serialize()
    }

    #[test]
    fn test_sign_taproot_psbt_one_input() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let psbt_bytes = build_test_taproot_psbt(&km);

        let (signed_bytes, count) = km.sign_psbt(&psbt_bytes).unwrap();
        assert_eq!(count, 1);

        let signed_psbt = Psbt::deserialize(&signed_bytes).unwrap();
        assert_eq!(signed_psbt.inputs[0].tap_script_sigs.len(), 1);
    }

    #[test]
    fn test_sign_taproot_psbt_skip_already_signed() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let psbt_bytes = build_test_taproot_psbt(&km);

        let (signed_bytes, count1) = km.sign_psbt(&psbt_bytes).unwrap();
        assert_eq!(count1, 1);

        // Sign the already-signed PSBT again — should skip
        let (_, count2) = km.sign_psbt(&signed_bytes).unwrap();
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_sign_taproot_psbt_no_matching_fingerprint() {
        // Key with a different seed → different fingerprint → should not sign
        let km_signer = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let km_other = KeyManager::from_seed([0x99u8; 64], Network::Testnet).unwrap();

        let psbt_bytes = build_test_taproot_psbt(&km_signer);

        // km_other's fingerprint won't match the tap_key_origins
        let (_, count) = km_other.sign_psbt(&psbt_bytes).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_sign_taproot_psbt_schnorr_signature_valid() {
        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let psbt_bytes = build_test_taproot_psbt(&km);

        let (signed_bytes, _) = km.sign_psbt(&psbt_bytes).unwrap();
        let signed_psbt = Psbt::deserialize(&signed_bytes).unwrap();

        // Extract the signature
        let ((xonly_pk, _leaf_hash), tap_sig) =
            signed_psbt.inputs[0].tap_script_sigs.iter().next().unwrap();

        // Verify the Schnorr signature
        let secp = Secp256k1::verification_only();
        let schnorr_sig = &tap_sig.signature;

        // Recompute the sighash
        let prevouts = vec![signed_psbt.inputs[0].witness_utxo.clone().unwrap()];
        let unsigned_tx = signed_psbt.unsigned_tx.clone();
        let mut cache = bitcoin::sighash::SighashCache::new(&unsigned_tx);
        let sighash = cache
            .taproot_script_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                *_leaf_hash,
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap();

        let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());
        assert!(secp.verify_schnorr(schnorr_sig, &msg, xonly_pk).is_ok());
    }

    /// Adversarial taproot: the committed leaf does NOT push our xonly key,
    /// but `tap_key_origins` lies and claims our key participates. Pre-fix
    /// code (which iterated origins) would sign; post-fix must refuse.
    #[test]
    fn adversarial_taproot_psbt_forged_origins_is_not_signed() {
        use bitcoin::bip32::ChildNumber;
        use bitcoin::blockdata::opcodes::all::*;
        use bitcoin::blockdata::script::Builder as ScriptBuilder;
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
        };

        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let secp = Secp256k1::new();

        // Our xonly (BIP-86 vanilla testnet 0/0).
        let our_secret = km
            .derive_btc_child(
                AccountType::Vanilla,
                &[
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .unwrap();
        let our_kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &our_secret);
        let (our_xonly, _) = XOnlyPublicKey::from_keypair(&our_kp);

        // Build a leaf containing three FOREIGN xonly keys.
        let foreign = |b: u8| {
            let kp = bitcoin::secp256k1::Keypair::from_secret_key(
                &secp,
                &SecretKey::from_slice(&[b; 32]).unwrap(),
            );
            XOnlyPublicKey::from_keypair(&kp).0
        };
        let mut keys = [foreign(0xB1), foreign(0xB2), foreign(0xB3)];
        keys.sort();
        let leaf = ScriptBuilder::new()
            .push_x_only_key(&keys[0])
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&keys[1])
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&keys[2])
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script();
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);

        let internal_key = XOnlyPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal_key)
            .unwrap();
        let cb = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();

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
                script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
        });
        psbt.inputs[0].tap_internal_key = Some(internal_key);
        psbt.inputs[0]
            .tap_scripts
            .insert(cb, (leaf, LeafVersion::TapScript));

        // The lie: claim our xonly is in this leaf, with our fingerprint and
        // a real BIP-86 derivation that *does* derive to our xonly.
        let our_path = bitcoin::bip32::DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ]);
        psbt.inputs[0].tap_key_origins.insert(
            our_xonly,
            (vec![leaf_hash], (*km.master_fingerprint(), our_path)),
        );

        let (signed_bytes, count) = km.sign_psbt(&psbt.serialize()).unwrap();
        assert_eq!(
            count, 0,
            "TEE must not sign when leaf does not push our key"
        );
        let signed = Psbt::deserialize(&signed_bytes).unwrap();
        assert!(signed.inputs[0].tap_script_sigs.is_empty());
    }

    /// Adversarial taproot: `script_pubkey` commits to leaf A, but the PSBT
    /// ships a different leaf B (which DOES push our xonly) under a control
    /// block from an unrelated tree. `verify_taproot_commitment` must reject.
    #[test]
    fn adversarial_taproot_psbt_unverified_control_block_is_not_signed() {
        use bitcoin::bip32::ChildNumber;
        use bitcoin::blockdata::opcodes::all::*;
        use bitcoin::blockdata::script::Builder as ScriptBuilder;
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
        };

        let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
        let secp = Secp256k1::new();

        let our_secret = km
            .derive_btc_child(
                AccountType::Vanilla,
                &[
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .unwrap();
        let our_kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &our_secret);
        let (our_xonly, _) = XOnlyPublicKey::from_keypair(&our_kp);

        let foreign = |b: u8| {
            let kp = bitcoin::secp256k1::Keypair::from_secret_key(
                &secp,
                &SecretKey::from_slice(&[b; 32]).unwrap(),
            );
            XOnlyPublicKey::from_keypair(&kp).0
        };

        // Tree REAL: committed leaf A (no us). This produces the on-chain output key.
        let mut keys_a = [foreign(0xA1), foreign(0xA2), foreign(0xA3)];
        keys_a.sort();
        let leaf_a = ScriptBuilder::new()
            .push_x_only_key(&keys_a[0])
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&keys_a[1])
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&keys_a[2])
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script();
        let internal_key_a = XOnlyPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .unwrap();
        let info_a = TaprootBuilder::new()
            .add_leaf(0, leaf_a.clone())
            .unwrap()
            .finalize(&secp, internal_key_a)
            .unwrap();

        // Tree FAKE: separate tree containing leaf B (with us). Its control
        // block is valid for FAKE's output key but NOT for REAL's.
        let mut keys_b = [our_xonly, foreign(0xB2), foreign(0xB3)];
        keys_b.sort();
        let leaf_b = ScriptBuilder::new()
            .push_x_only_key(&keys_b[0])
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&keys_b[1])
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&keys_b[2])
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script();
        let leaf_b_hash = TapLeafHash::from_script(&leaf_b, LeafVersion::TapScript);
        let internal_key_b = foreign(0xC0);
        let info_b = TaprootBuilder::new()
            .add_leaf(0, leaf_b.clone())
            .unwrap()
            .finalize(&secp, internal_key_b)
            .unwrap();
        let bad_cb = info_b
            .control_block(&(leaf_b.clone(), LeafVersion::TapScript))
            .unwrap();

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
                script_pubkey: ScriptBuf::new_p2tr_tweaked(info_a.output_key()),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        // script_pubkey is REAL's output key (commits to leaf A).
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info_a.output_key()),
        });
        psbt.inputs[0].tap_internal_key = Some(internal_key_a);
        // Attacker ships leaf B + bad_cb (which is for FAKE).
        psbt.inputs[0]
            .tap_scripts
            .insert(bad_cb, (leaf_b, LeafVersion::TapScript));

        let our_path = bitcoin::bip32::DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ]);
        psbt.inputs[0].tap_key_origins.insert(
            our_xonly,
            (vec![leaf_b_hash], (*km.master_fingerprint(), our_path)),
        );

        let (signed_bytes, count) = km.sign_psbt(&psbt.serialize()).unwrap();
        assert_eq!(
            count, 0,
            "TEE must not sign when control block fails to verify"
        );
        let signed = Psbt::deserialize(&signed_bytes).unwrap();
        assert!(signed.inputs[0].tap_script_sigs.is_empty());
    }
}
