//! Crypto for the enclave-to-enclave cloning handshake.
//!
//! Three messages (see the `enclave-proto` crate):
//!
//! 1. Parent -> requester: `InitiateCloning { cloning_secret, cluster_public_key }`.
//!    The requester makes an X25519 keypair and attests its pubkey. It replies
//!    with the attestation, the pubkey and an HMAC digest (secret, pubkey, donor).
//! 2. Parent -> donor: `GetClone`. The donor verifies the attestation, PCRs and
//!    digest. It seals its seed with X25519 + HKDF + ChaCha20Poly1305 and
//!    returns the ciphertext, its ephemeral pubkey and its attestation.
//! 3. Parent -> requester: `SetClone`. The requester verifies the donor
//!    attestation and unseals the seed. The derived EVM address must equal
//!    `cluster_public_key`. The requester then becomes Active.
//!
//! The `server` module connects this crypto to the handlers and state machine.

#![allow(dead_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{EnclaveError, Result};

type HmacSha256 = Hmac<Sha256>;

/// HKDF salt for the cloning key. Versioned, so a new version rejects old
/// ciphertexts.
const HKDF_SALT: &[u8] = b"utexo-cloning-v1";
const HKDF_INFO: &[u8] = b"seed-encryption";

/// The requester's ephemeral X25519 keypair for one cloning handshake.
///
/// `StaticSecret`, not `EphemeralSecret`: the secret must live from
/// InitiateCloning to SetClone, and DH consumes an `EphemeralSecret`.
/// `StaticSecret` zeroizes on drop (`zeroize` feature).
pub struct CloneSession {
    secret: StaticSecret,
    public: PublicKey,
}

impl CloneSession {
    /// Generate a fresh ephemeral X25519 keypair from the OS RNG.
    pub fn new() -> Self {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Unseal the donor's ciphertext with this session's secret and the donor
    /// X25519 pubkey. The seed is `Zeroizing`, so it is wiped on drop.
    pub fn decrypt_seed_from_peer(
        &self,
        peer_pubkey: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; 64]>> {
        let peer = PublicKey::from(*peer_pubkey);
        let shared = self.secret.diffie_hellman(&peer);
        reject_non_contributory(&shared)?;
        let key = derive_symmetric_key(shared.as_bytes(), peer_pubkey, &self.public.to_bytes());
        decrypt_with_key(&key, ciphertext)
    }
}

impl Default for CloneSession {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CloneSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloneSession")
            .field("public", &hex::encode(self.public.to_bytes()))
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// HMAC-SHA256(secret, encryption_pubkey || target_cluster_pk).
/// Binds the request to its recipient key and its donor.
pub fn make_cloning_digest(
    secret: &str,
    encryption_pubkey: &[u8; 32],
    target_cluster_pk: &[u8; 20],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(encryption_pubkey);
    mac.update(target_cluster_pk);
    mac.finalize().into_bytes().into()
}

/// Check the cloning digest in constant time, including the donor identity.
pub fn verify_cloning_digest(
    secret: &str,
    encryption_pubkey: &[u8; 32],
    target_cluster_pk: &[u8; 20],
    digest: &[u8; 32],
) -> bool {
    let expected = make_cloning_digest(secret, encryption_pubkey, target_cluster_pk);
    expected.ct_eq(digest).into()
}

/// Minimum cloning-secret length in bytes.
pub const MIN_CLONING_SECRET_BYTES: usize = 32;

/// Minimum number of distinct secret bytes. This rejects repeated values. It
/// does not measure entropy.
pub const MIN_CLONING_SECRET_DISTINCT_BYTES: usize = 8;

/// Reject weak secrets before donor init or InitiateCloning.
/// The operator generates a random secret and rotates it.
pub fn validate_cloning_secret(secret: &str) -> Result<()> {
    let bytes = secret.as_bytes();
    if bytes.is_empty() {
        return Err(EnclaveError::InvalidRequest(
            "cloning_secret is required".into(),
        ));
    }
    if bytes.len() < MIN_CLONING_SECRET_BYTES {
        return Err(EnclaveError::InvalidRequest(format!(
            "cloning_secret too short: {} bytes < {MIN_CLONING_SECRET_BYTES} minimum",
            bytes.len()
        )));
    }
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &b in bytes {
        if !core::mem::replace(&mut seen[b as usize], true) {
            distinct += 1;
        }
    }
    if distinct < MIN_CLONING_SECRET_DISTINCT_BYTES {
        return Err(EnclaveError::InvalidRequest(format!(
            "cloning_secret too low-entropy: {distinct} distinct bytes < {MIN_CLONING_SECRET_DISTINCT_BYTES} minimum"
        )));
    }
    Ok(())
}

/// Donor side: seal `seed` to the requester's X25519 pubkey with a fresh
/// ephemeral keypair. Returns `(ciphertext, our_pubkey)`.
///
/// Rejects small-order peer keys. Such a key forces a known shared secret, and
/// anyone can then derive the key.
pub fn encrypt_seed_for_peer(
    peer_pubkey: &[u8; 32],
    seed: &[u8; 64],
) -> Result<(Vec<u8>, [u8; 32])> {
    let our_secret = EphemeralSecret::random();
    let our_pub = PublicKey::from(&our_secret).to_bytes();
    let peer = PublicKey::from(*peer_pubkey);
    let shared = our_secret.diffie_hellman(&peer);
    reject_non_contributory(&shared)?;

    let key = derive_symmetric_key(shared.as_bytes(), &our_pub, peer_pubkey);
    let ciphertext = encrypt_with_key(&key, seed)?;
    Ok((ciphertext, our_pub))
}

/// Reject non-contributory DH outputs (RFC 7748, section 6.1).
fn reject_non_contributory(shared: &SharedSecret) -> Result<()> {
    if !shared.was_contributory() {
        return Err(EnclaveError::InvalidRequest(
            "peer X25519 public key was small-order (non-contributory DH)".into(),
        ));
    }
    Ok(())
}

/// HKDF-SHA256. `info` binds the key to both pubkeys, in the order
/// donor || requester on both sides.
fn derive_symmetric_key(
    shared_secret: &[u8],
    donor_pubkey: &[u8; 32],
    requester_pubkey: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(HKDF_INFO.len() + 64);
    info.extend_from_slice(HKDF_INFO);
    info.extend_from_slice(donor_pubkey);
    info.extend_from_slice(requester_pubkey);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut())
        .expect("32 bytes is within HKDF output limit");
    okm
}

// All-zero nonce is safe: each seal uses a fresh donor ephemeral key, so each
// derived key encrypts only once.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

fn cipher(key: &Zeroizing<[u8; 32]>) -> ChaCha20Poly1305 {
    let key_array: &[u8; 32] = key;
    ChaCha20Poly1305::new(key_array.into())
}

fn encrypt_with_key(key: &Zeroizing<[u8; 32]>, plaintext: &[u8]) -> Result<Vec<u8>> {
    cipher(key)
        .encrypt((&ZERO_NONCE).into(), plaintext)
        .map_err(|e| EnclaveError::Clone(format!("seed seal failed: {e}")))
}

fn decrypt_with_key(key: &Zeroizing<[u8; 32]>, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let mut plaintext = cipher(key)
        .decrypt((&ZERO_NONCE).into(), ciphertext)
        .map_err(|e| EnclaveError::Clone(format!("seed unseal failed: {e}")))?;
    if plaintext.len() != 64 {
        plaintext.zeroize();
        return Err(EnclaveError::Clone(format!(
            "decrypted seed has wrong length: {}",
            plaintext.len()
        )));
    }
    let mut seed = Zeroizing::new([0u8; 64]);
    seed.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(seed)
}

#[cfg(test)]
mod tests;
