//! Cryptographic primitives for the enclave-to-enclave cloning handshake.
//!
//! The handshake has three messages on the wire (see `proto/enclave.proto`
//! in PR 4):
//!
//! 1. Parent -> requester: `InitiateCloning { secret, target_pubkey }`.
//!    Requester generates an X25519 ephemeral keypair, embeds the pubkey in
//!    an NSM attestation doc, computes a HMAC digest over (secret, pubkey),
//!    and replies with (attestation, pubkey, digest).
//! 2. Parent -> donor (relayed): `GetClone { target_pubkey, pubkey, digest, attestation }`.
//!    Donor verifies the attestation, matches PCRs, verifies the digest,
//!    X25519-DH + HKDF-derives a symmetric key, ChaCha20Poly1305 seals its
//!    seed, returns (ciphertext, our pubkey, our attestation).
//! 3. Parent -> requester (relayed): `SetClone { ciphertext, donor_pubkey, donor_attestation }`.
//!    Requester verifies donor attestation, DH + HKDF + unseal, derives
//!    KeyManager from the seed, verifies the derived EVM address matches
//!    the claimed target_pubkey, transitions to Active.
//!
//! This module provides the crypto layer only. PR 4 wires it into the
//! request handlers and state machine.

#![allow(dead_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{EnclaveError, Result};

type HmacSha256 = Hmac<Sha256>;

/// HKDF salt for cloning-handshake key derivation. Versioned so we can
/// roll it forward without silently accepting old ciphertexts.
const HKDF_SALT: &[u8] = b"utexo-cloning-v1";
const HKDF_INFO: &[u8] = b"seed-encryption";

/// An ephemeral X25519 keypair held by the requester for the duration of
/// the cloning handshake. The secret is dropped (and zeroized) when the
/// session is consumed or dropped.
///
/// `StaticSecret` is used instead of `EphemeralSecret` only because we need
/// to hold it across two message boundaries (InitiateCloning -> SetClone)
/// and `EphemeralSecret` is consume-on-DH. `StaticSecret` implements
/// `ZeroizeOnDrop` when the `zeroize` feature is enabled.
pub struct CloneSession {
    secret: StaticSecret,
    public: PublicKey,
}

impl CloneSession {
    /// Generate a fresh ephemeral X25519 keypair from the OS RNG.
    pub fn new() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Unseal a ciphertext sealed by a donor using our ephemeral secret
    /// and the donor's advertised X25519 public key. Returns the decrypted
    /// seed in a `Zeroizing` wrapper so it is wiped on drop if the caller
    /// does not store it.
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

/// Compute HMAC-SHA256(secret, encryption_pubkey).
///
/// This proves the holder of the cloning secret authorized the request
/// without transmitting the secret over the wire. The message is the
/// raw 32 bytes of the X25519 pubkey — deterministic, no canonicalization
/// ambiguity, unlike the Python enclave-msig implementation that uses JCS(JSON).
pub fn make_cloning_digest(secret: &str, encryption_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(encryption_pubkey);
    mac.finalize().into_bytes().into()
}

/// Constant-time verification of a cloning digest.
pub fn verify_cloning_digest(
    secret: &str,
    encryption_pubkey: &[u8; 32],
    digest: &[u8; 32],
) -> bool {
    let expected = make_cloning_digest(secret, encryption_pubkey);
    expected.ct_eq(digest).into()
}

/// Donor side: seal `seed` to the requester's X25519 pubkey using a fresh
/// ephemeral keypair. Returns `(ciphertext, our_pubkey)`.
///
/// Rejects small-order / non-contributory peer public keys — otherwise an
/// attacker sending a small-order point could force a zero shared secret,
/// making the derived key recoverable from public information and breaking
/// seed confidentiality.
pub fn encrypt_seed_for_peer(
    peer_pubkey: &[u8; 32],
    seed: &[u8; 64],
) -> Result<(Vec<u8>, [u8; 32])> {
    let our_secret = EphemeralSecret::random_from_rng(OsRng);
    let our_pub = PublicKey::from(&our_secret).to_bytes();
    let peer = PublicKey::from(*peer_pubkey);
    let shared = our_secret.diffie_hellman(&peer);
    reject_non_contributory(&shared)?;

    let key = derive_symmetric_key(shared.as_bytes(), &our_pub, peer_pubkey);
    let ciphertext = encrypt_with_key(&key, seed)?;
    Ok((ciphertext, our_pub))
}

// ---- internal HKDF + AEAD helpers ----

/// Reject small-order / non-contributory DH outputs. See
/// <https://tools.ietf.org/html/rfc7748#section-6.1>.
fn reject_non_contributory(shared: &SharedSecret) -> Result<()> {
    if !shared.was_contributory() {
        return Err(EnclaveError::Clone(
            "peer X25519 public key was small-order (non-contributory DH)".into(),
        ));
    }
    Ok(())
}

/// HKDF-SHA256 derivation. The `info` field binds the derived key to both
/// participants' public keys so even a degenerate shared secret cannot be
/// reused across handshakes. Pubkey order is donor-pubkey || requester-pubkey
/// so both sides agree on it regardless of who's calling.
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

// Fixed all-zero nonce: safe because each cloning handshake uses a fresh
// ephemeral keypair, so the derived key is single-use and no nonce/key
// pair is ever reused.
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
mod tests {
    use super::*;

    #[test]
    fn digest_roundtrip_ok() {
        let secret = "correct horse battery staple";
        let pubkey = [7u8; 32];
        let digest = make_cloning_digest(secret, &pubkey);
        assert!(verify_cloning_digest(secret, &pubkey, &digest));
    }

    #[test]
    fn digest_rejects_wrong_secret() {
        let pubkey = [7u8; 32];
        let digest = make_cloning_digest("right", &pubkey);
        assert!(!verify_cloning_digest("wrong", &pubkey, &digest));
    }

    #[test]
    fn digest_rejects_wrong_pubkey() {
        let secret = "s";
        let digest = make_cloning_digest(secret, &[1u8; 32]);
        assert!(!verify_cloning_digest(secret, &[2u8; 32], &digest));
    }

    #[test]
    fn digest_detects_single_bit_flip() {
        let secret = "s";
        let pubkey = [9u8; 32];
        let mut digest = make_cloning_digest(secret, &pubkey);
        digest[0] ^= 0x01;
        assert!(!verify_cloning_digest(secret, &pubkey, &digest));
    }

    #[test]
    fn seed_encrypt_decrypt_roundtrip() {
        let seed: [u8; 64] = core::array::from_fn(|i| (i * 3 + 11) as u8);
        let requester = CloneSession::new();
        let requester_pub = requester.public_key();

        let (ciphertext, donor_pub) = encrypt_seed_for_peer(&requester_pub, &seed).unwrap();
        let decrypted = requester
            .decrypt_seed_from_peer(&donor_pub, &ciphertext)
            .unwrap();

        assert_eq!(*decrypted, seed);
    }

    #[test]
    fn seed_decrypt_with_wrong_peer_key_fails() {
        let seed = [42u8; 64];
        let requester = CloneSession::new();
        let (ciphertext, _donor_pub) =
            encrypt_seed_for_peer(&requester.public_key(), &seed).unwrap();

        // Use a legit random donor pubkey (not zero — that's small-order
        // and would trip the contributory check, masking the real assertion).
        let wrong_donor = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        let result = requester.decrypt_seed_from_peer(&wrong_donor, &ciphertext);
        assert!(matches!(result, Err(EnclaveError::Clone(_))));
    }

    #[test]
    fn encrypt_rejects_small_order_peer_pubkey() {
        // The all-zero point is one of the known small-order points on
        // Curve25519. Sending it as the peer pubkey should be rejected at
        // the encryptor so the attacker cannot force a zero shared secret.
        let result = encrypt_seed_for_peer(&[0u8; 32], &[42u8; 64]);
        assert!(matches!(result, Err(EnclaveError::Clone(_))));
    }

    #[test]
    fn decrypt_rejects_small_order_peer_pubkey() {
        let requester = CloneSession::new();
        // Build a ciphertext via a legit encrypt call, then attempt to
        // decrypt with the all-zero peer key — must fail the contributory
        // check, not silently produce a computable shared secret.
        let (ciphertext, _legit_donor) =
            encrypt_seed_for_peer(&requester.public_key(), &[42u8; 64]).unwrap();
        let result = requester.decrypt_seed_from_peer(&[0u8; 32], &ciphertext);
        assert!(matches!(result, Err(EnclaveError::Clone(_))));
    }

    #[test]
    fn seed_decrypt_tampered_ciphertext_fails() {
        let seed = [42u8; 64];
        let requester = CloneSession::new();
        let (mut ciphertext, donor_pub) =
            encrypt_seed_for_peer(&requester.public_key(), &seed).unwrap();

        // Flip one byte of the ciphertext body.
        ciphertext[0] ^= 0xff;
        let result = requester.decrypt_seed_from_peer(&donor_pub, &ciphertext);
        assert!(matches!(result, Err(EnclaveError::Clone(_))));
    }

    #[test]
    fn seed_decrypt_tampered_auth_tag_fails() {
        let seed = [42u8; 64];
        let requester = CloneSession::new();
        let (mut ciphertext, donor_pub) =
            encrypt_seed_for_peer(&requester.public_key(), &seed).unwrap();

        // Flip the last byte (auth tag).
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;
        let result = requester.decrypt_seed_from_peer(&donor_pub, &ciphertext);
        assert!(matches!(result, Err(EnclaveError::Clone(_))));
    }

    #[test]
    fn decrypt_with_wrong_requester_key_fails() {
        let seed = [42u8; 64];
        let requester_a = CloneSession::new();
        let (ciphertext, donor_pub) =
            encrypt_seed_for_peer(&requester_a.public_key(), &seed).unwrap();

        // Different session — shared secret will differ -> auth tag fails.
        let requester_b = CloneSession::new();
        let result = requester_b.decrypt_seed_from_peer(&donor_pub, &ciphertext);
        assert!(matches!(result, Err(EnclaveError::Clone(_))));
    }

    #[test]
    fn clone_session_public_key_is_stable() {
        let session = CloneSession::new();
        let pk1 = session.public_key();
        let pk2 = session.public_key();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn two_sessions_generate_distinct_keys() {
        let a = CloneSession::new();
        let b = CloneSession::new();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn ciphertext_includes_authentication_overhead() {
        // Seed is 64 bytes; ChaCha20Poly1305 adds a 16-byte Poly1305 tag.
        let session = CloneSession::new();
        let (ct, _) = encrypt_seed_for_peer(&session.public_key(), &[0u8; 64]).unwrap();
        assert_eq!(ct.len(), 64 + 16);
    }
}
