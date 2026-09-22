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

/// RGB coin types for colored (RGB asset) operations. Mainnet/other split,
/// matching `rgb-lib::utils::get_coin_type` - the host wallet derives the
/// colored addresses this enclave must resolve.
const RGB_COIN_TYPE_MAINNET: u32 = 827166;
const RGB_COIN_TYPE_TESTNET: u32 = 827167;

/// SLIP-44 coin type for Concordium.
const CONCORDIUM_COIN_TYPE: u32 = 919;

type HmacSha512 = Hmac<Sha512>;

/// SLIP-0010 Ed25519 hardened key derivation. Returns the 32-byte private key at
/// the given path. Every index is treated as hardened - SLIP-0010 Ed25519 only
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
    // Coin type used for colored/RGB derivation (827166 mainnet, 827167 testnet)
    colored_coin_type: u32,
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
    /// The seed is moved into `SecretBox` before any derivation. Do not zeroize
    /// the local seed before boxing, or the stored seed ends up all zeros and
    /// cloning breaks.
    pub fn from_seed(mut seed: [u8; 64], network: Network) -> Result<Self> {
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
        // Colored (RGB) coin type: same mainnet / not-mainnet split.
        let colored_coin_type = match network {
            Network::Bitcoin => RGB_COIN_TYPE_MAINNET,
            _ => RGB_COIN_TYPE_TESTNET,
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

        // Colored: m/86'/<rgb_coin_type>'/0'
        let colored_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(colored_coin_type).unwrap(),
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
            colored_coin_type,
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
    /// E.g., m/86'/1'/0'/0/7 -> (Vanilla, [0, 7]) on testnet.
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
            } else if coin_type == ChildNumber::from_hardened_idx(self.colored_coin_type).unwrap() {
                AccountType::Colored
            } else {
                return None;
            };
        let child_path = steps[3..].to_vec();
        Some((account_type, child_path))
    }

    /// Sign a 32-byte message hash with the EVM secp256k1 key.
    /// Returns 65 bytes: r(32) + s(32) + v(1) - Ethereum `ecrecover` convention.
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
    pub fn sign_ccd(&self, hash: &[u8; 32]) -> Result<([u8; 64], [u8; 32])> {
        let signing_key = Ed25519SigningKey::from_bytes(self.concordium_secret.expose_secret());
        Ok((signing_key.sign(hash).to_bytes(), self.concordium_pub))
    }

    /// Sign PSBT inputs matching our keys.
    /// Auto-detects taproot (Schnorr, BIP-340; script path or BIP-86 key path)
    /// vs SegWit v0 P2WSH (ECDSA) per input.
    /// Returns the modified PSBT bytes and count of inputs signed.
    pub fn sign_psbt(&self, psbt_bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
        self.sign_psbt_scoped(psbt_bytes, None)
    }

    /// Sign PSBT inputs matching our keys, optionally restricted to a single
    /// BIP-86 account.
    ///
    /// `allowed_account`:
    ///   * `None`: sign every input we can (taproot on any account, plus legacy
    ///     P2WSH). Used by the consignment-bound bridge path (`SignPsbt`),
    ///     where the consignment is the authorization.
    ///   * `Some(account)`: sign only taproot inputs resolving to `account` and
    ///     skip the legacy P2WSH path. `SignBtc` passes `Some(Vanilla)`, so the
    ///     plain-BTC path can never co-sign a Colored (RGB-allocated) input
    ///     (the structural half of the input-scoping fix).
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
        // Skipped on an account-scoped call: the legacy key is not
        // BIP-86-account-derived.
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
    /// Wipe the BIP-86 account extended private keys on teardown.
    ///
    /// Unlike `seed` / `evm_secret` / `btc_secret`, these are plain `Xpriv`
    /// fields with no `SecretBox` zeroize-on-drop. Each carries a signing
    /// `private_key` and a sensitive `chain_code`; both are overwritten.
    fn drop(&mut self) {
        self.account_xpriv_vanilla.private_key.non_secure_erase();
        self.account_xpriv_colored.private_key.non_secure_erase();
        self.account_xpriv_vanilla.chain_code = ChainCode::from([0u8; 32]);
        self.account_xpriv_colored.chain_code = ChainCode::from([0u8; 32]);
    }
}

#[cfg(test)]
mod tests;
