//! Cryptographic primitives for the enclave-to-enclave cloning handshake.
//!
//! Three messages on the wire (see `proto/enclave.proto`):
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
//! This module is the crypto layer only; `server.rs` wires it into the request
//! handlers and state machine.

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
/// `StaticSecret` rather than `EphemeralSecret`, which is consume-on-DH: the
/// secret must survive from InitiateCloning to SetClone. It implements
/// `ZeroizeOnDrop` under the `zeroize` feature.
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
/// Proves the holder of the cloning secret authorized the request without
/// sending the secret. The message is the raw 32 bytes of the X25519 pubkey, so
/// there is no canonicalization ambiguity.
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
/// Rejects small-order / non-contributory peer public keys - otherwise an
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
        // Read the length before zeroizing: `Vec::zeroize` also truncates.
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(EnclaveError::Clone(format!(
            "decrypted seed has wrong length: {len}"
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

        // A random donor pubkey, not zero: zero is small-order and would trip
        // the contributory check, masking the real assertion.
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
        // decrypt with the all-zero peer key - must fail the contributory
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

        // Different session - shared secret will differ -> auth tag fails.
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

#[cfg(test)]
mod coverage_tests {
    use super::*;

    /// Curve25519 low-order points besides the all-zero one: the identity
    /// (1) and an order-8 point. All must be rejected as non-contributory.
    const LOW_ORDER_POINTS: [[u8; 32]; 2] = [
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
    ];

    #[test]
    fn encrypt_and_decrypt_reject_every_known_low_order_point() {
        let requester = CloneSession::new();
        let (ciphertext, _) = encrypt_seed_for_peer(&requester.public_key(), &[1u8; 64]).unwrap();
        for point in LOW_ORDER_POINTS {
            assert!(
                matches!(
                    encrypt_seed_for_peer(&point, &[1u8; 64]),
                    Err(EnclaveError::Clone(_))
                ),
                "encrypt must reject {point:?}"
            );
            assert!(
                matches!(
                    requester.decrypt_seed_from_peer(&point, &ciphertext),
                    Err(EnclaveError::Clone(_))
                ),
                "decrypt must reject {point:?}"
            );
        }
    }

    #[test]
    fn decrypt_rejects_empty_and_tag_only_ciphertext() {
        let requester = CloneSession::new();
        let (_, donor_pub) = encrypt_seed_for_peer(&requester.public_key(), &[1u8; 64]).unwrap();
        for ct in [Vec::new(), vec![0u8; 15], vec![0u8; 16]] {
            let err = requester
                .decrypt_seed_from_peer(&donor_pub, &ct)
                .unwrap_err();
            assert!(matches!(err, EnclaveError::Clone(_)), "{}: {err}", ct.len());
            assert!(err.to_string().contains("seed unseal failed"), "{err}");
        }
    }

    #[test]
    fn decrypt_rejects_truncated_and_extended_ciphertext() {
        let requester = CloneSession::new();
        let (ct, donor_pub) = encrypt_seed_for_peer(&requester.public_key(), &[1u8; 64]).unwrap();
        let truncated = &ct[..ct.len() - 1];
        assert!(matches!(
            requester.decrypt_seed_from_peer(&donor_pub, truncated),
            Err(EnclaveError::Clone(_))
        ));
        let mut extended = ct.clone();
        extended.push(0);
        assert!(matches!(
            requester.decrypt_seed_from_peer(&donor_pub, &extended),
            Err(EnclaveError::Clone(_))
        ));
    }

    #[test]
    fn decrypt_rejects_a_correctly_sealed_plaintext_of_the_wrong_length() {
        // The AEAD accepts the box, but the payload is not a 64-byte seed.
        // Reached via the internal helpers because the public sealer only
        // ever seals 64 bytes.
        let key = Zeroizing::new([0x42u8; 32]);
        for len in [0usize, 32, 63, 65, 128] {
            let ct = encrypt_with_key(&key, &vec![7u8; len]).unwrap();
            let err = decrypt_with_key(&key, &ct).unwrap_err();
            match err {
                EnclaveError::Clone(msg) => assert!(
                    msg.contains("wrong length") && msg.contains(&len.to_string()),
                    "{len}: {msg}"
                ),
                other => panic!("expected Clone, got {other:?}"),
            }
        }
        let ct = encrypt_with_key(&key, &[7u8; 64]).unwrap();
        assert_eq!(*decrypt_with_key(&key, &ct).unwrap(), [7u8; 64]);
    }

    #[test]
    fn symmetric_key_binds_both_pubkeys_and_their_order() {
        let shared = [0x33u8; 32];
        let a = [1u8; 32];
        let b = [2u8; 32];
        let k_ab = derive_symmetric_key(&shared, &a, &b);
        let k_ba = derive_symmetric_key(&shared, &b, &a);
        let k_ab2 = derive_symmetric_key(&shared, &a, &b);
        assert_eq!(*k_ab, *k_ab2, "deterministic");
        assert_ne!(*k_ab, *k_ba, "donor/requester order is part of the info");
        let k_other = derive_symmetric_key(&[0x34u8; 32], &a, &b);
        assert_ne!(*k_ab, *k_other, "shared secret is bound");
        let k_c = derive_symmetric_key(&shared, &a, &[3u8; 32]);
        assert_ne!(*k_ab, *k_c, "each pubkey is bound");
    }

    #[test]
    fn a_ciphertext_cannot_be_opened_under_a_key_derived_with_swapped_pubkeys() {
        // Both sides compute donor||requester; a side that got the order wrong
        // derives a different key and fails the tag.
        let shared = [0x33u8; 32];
        let a = [1u8; 32];
        let b = [2u8; 32];
        let ct = encrypt_with_key(&derive_symmetric_key(&shared, &a, &b), &[9u8; 64]).unwrap();
        assert!(decrypt_with_key(&derive_symmetric_key(&shared, &b, &a), &ct).is_err());
        assert!(decrypt_with_key(&derive_symmetric_key(&shared, &a, &b), &ct).is_ok());
    }

    #[test]
    fn digest_accepts_empty_secret_and_binds_it() {
        // HMAC accepts an empty key; the digest still binds the pubkey and
        // differs from any non-empty secret.
        let pk = [4u8; 32];
        let d = make_cloning_digest("", &pk);
        assert!(verify_cloning_digest("", &pk, &d));
        assert!(!verify_cloning_digest(" ", &pk, &d));
        assert_ne!(d, make_cloning_digest("x", &pk));
    }

    #[test]
    fn digest_is_deterministic_and_secret_length_independent_of_output() {
        let pk = [4u8; 32];
        let long = "s".repeat(1_000);
        let d1 = make_cloning_digest(&long, &pk);
        let d2 = make_cloning_digest(&long, &pk);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
        assert_ne!(d1, make_cloning_digest(&"s".repeat(999), &pk));
    }

    #[test]
    fn digest_rejects_all_zero_and_flipped_high_byte() {
        let pk = [4u8; 32];
        let secret = "s";
        let d = make_cloning_digest(secret, &pk);
        assert!(!verify_cloning_digest(secret, &pk, &[0u8; 32]));
        let mut flipped = d;
        flipped[31] ^= 0x80;
        assert!(!verify_cloning_digest(secret, &pk, &flipped));
    }

    #[test]
    fn same_seed_seals_differently_each_time() {
        // Fresh donor ephemeral keypair per call: two seals of the same seed
        // to the same requester must not share a ciphertext or a donor key.
        let requester = CloneSession::new();
        let (c1, d1) = encrypt_seed_for_peer(&requester.public_key(), &[1u8; 64]).unwrap();
        let (c2, d2) = encrypt_seed_for_peer(&requester.public_key(), &[1u8; 64]).unwrap();
        assert_ne!(c1, c2);
        assert_ne!(d1, d2);
        assert_eq!(
            *requester.decrypt_seed_from_peer(&d1, &c1).unwrap(),
            [1u8; 64]
        );
        assert_eq!(
            *requester.decrypt_seed_from_peer(&d2, &c2).unwrap(),
            [1u8; 64]
        );
        // Cross-pairing the donor keys fails.
        assert!(requester.decrypt_seed_from_peer(&d1, &c2).is_err());
    }

    #[test]
    fn default_session_is_a_fresh_keypair() {
        let a = CloneSession::default();
        let b = CloneSession::default();
        assert_ne!(a.public_key(), b.public_key());
        let dbg = format!("{a:?}");
        assert!(dbg.contains(&hex::encode(a.public_key())));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn roundtrip_preserves_every_seed_byte_pattern() {
        for seed in [[0u8; 64], [0xffu8; 64], core::array::from_fn(|i| i as u8)] {
            let requester = CloneSession::new();
            let (ct, donor) = encrypt_seed_for_peer(&requester.public_key(), &seed).unwrap();
            assert_eq!(
                *requester.decrypt_seed_from_peer(&donor, &ct).unwrap(),
                seed
            );
        }
    }
}
