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

/// Compute HMAC-SHA256(secret, encryption_pubkey ‖ target_cluster_pk).
///
/// Proves the holder of the cloning secret authorized the request without
/// sending the secret, AND binds the request to the *intended donor cluster
/// identity* (F03-AF-07). Both message parts are fixed-width (32 + 20 bytes),
/// so the concatenation is unambiguous without a length prefix.
///
/// Why bind the target: without it the digest is target-agnostic, so a
/// malicious/relaying parent can take a requester armed for cluster identity X
/// and replay it to a donor of a *different* cluster identity Y (setting the
/// plaintext `cluster_public_key` wire field to Y to satisfy the donor's own
/// self-check). The donor Y would then export its sealed seed before the
/// requester's downstream identity check can reject the mismatched result. With
/// the target folded in, the requester's digest is computed over X while donor
/// Y recomputes over its own identity Y → the HMAC mismatches and Y refuses to
/// export at all.
pub fn make_cloning_digest(
    secret: &str,
    encryption_pubkey: &[u8; 32],
    target_cluster_pk: &[u8; 20],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(encryption_pubkey);
    mac.update(target_cluster_pk);
    mac.finalize().into_bytes().into()
}

/// Constant-time verification of a cloning digest, including the target
/// cluster-identity binding (F03-AF-07).
pub fn verify_cloning_digest(
    secret: &str,
    encryption_pubkey: &[u8; 32],
    target_cluster_pk: &[u8; 20],
    digest: &[u8; 32],
) -> bool {
    let expected = make_cloning_digest(secret, encryption_pubkey, target_cluster_pk);
    expected.ct_eq(digest).into()
}

/// Fail-closed strength floor for an operator-supplied cloning secret
/// (F03-AF-26). The secret is used *directly* as the HMAC-SHA256 key in
/// [`make_cloning_digest`], so a captured `(encryption_pubkey, digest)` pair
/// lets an attacker offline-brute-force a weak secret and forge requester
/// authorization. 32 bytes is the minimum accepted length.
pub const MIN_CLONING_SECRET_BYTES: usize = 32;

/// Minimum distinct byte values - a cheap floor against degenerate low-entropy
/// secrets (`"aaaa..."`, `"0101..."`). A uniformly random 32-byte secret has
/// ~32 distinct bytes; even hex-encoded (16 symbols) it clears this. This is a
/// floor, NOT an entropy oracle (true entropy of an arbitrary string is
/// unknowable in-enclave), so the operator still owns generation/rotation.
pub const MIN_CLONING_SECRET_DISTINCT_BYTES: usize = 8;

/// Reject an empty / too-short / degenerate-entropy cloning secret before it is
/// ever used as an HMAC key (F03-AF-26). Called on both entry points: the donor
/// `init` ([`crate::state::EnclaveState::set_donor_cloning_secret`]) and the
/// requester `InitiateCloning` handler. Wire-compatible: the secret is still
/// carried the same way, only trivially weak values are now refused fail-closed.
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
        let target = [3u8; 20];
        let digest = make_cloning_digest(secret, &pubkey, &target);
        assert!(verify_cloning_digest(secret, &pubkey, &target, &digest));
    }

    #[test]
    fn validate_secret_rejects_empty() {
        assert!(matches!(
            validate_cloning_secret(""),
            Err(EnclaveError::InvalidRequest(_))
        ));
    }

    #[test]
    fn validate_secret_rejects_too_short() {
        // 31 bytes (< 32), high distinct so it fails ONLY on length.
        let s = "0123456789abcdef0123456789abcde";
        assert_eq!(s.len(), 31);
        assert!(matches!(
            validate_cloning_secret(s),
            Err(EnclaveError::InvalidRequest(_))
        ));
    }

    #[test]
    fn validate_secret_rejects_low_entropy() {
        // 64 bytes but a single distinct value -> trivially brute-forceable.
        let s = "a".repeat(64);
        assert!(matches!(
            validate_cloning_secret(&s),
            Err(EnclaveError::InvalidRequest(_))
        ));
    }

    #[test]
    fn validate_secret_accepts_64_hex() {
        // Shape of the real stage secret: 32 random bytes hex-encoded ->
        // 64 chars, 16 distinct symbols.
        let s = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(s.len(), 64);
        assert!(validate_cloning_secret(s).is_ok());
    }

    #[test]
    fn validate_secret_accepts_min_length_boundary() {
        // Exactly the 32-byte floor, well-distributed.
        let s = "0123456789abcdef0123456789abcdef";
        assert_eq!(s.len(), MIN_CLONING_SECRET_BYTES);
        assert!(validate_cloning_secret(s).is_ok());
    }

    #[test]
    fn digest_rejects_wrong_secret() {
        let pubkey = [7u8; 32];
        let target = [3u8; 20];
        let digest = make_cloning_digest("right", &pubkey, &target);
        assert!(!verify_cloning_digest("wrong", &pubkey, &target, &digest));
    }

    #[test]
    fn digest_rejects_wrong_pubkey() {
        let secret = "s";
        let target = [3u8; 20];
        let digest = make_cloning_digest(secret, &[1u8; 32], &target);
        assert!(!verify_cloning_digest(secret, &[2u8; 32], &target, &digest));
    }

    #[test]
    fn digest_rejects_wrong_target_cluster_pk() {
        // F03-AF-07: a digest armed for target X must not verify against a
        // different donor cluster identity Y, even with the same secret and
        // encryption pubkey. This is the core relay-to-wrong-donor guard.
        let secret = "correct horse battery staple";
        let pubkey = [7u8; 32];
        let digest = make_cloning_digest(secret, &pubkey, &[0xAAu8; 20]);
        assert!(!verify_cloning_digest(
            secret,
            &pubkey,
            &[0xBBu8; 20],
            &digest
        ));
    }

    #[test]
    fn digest_detects_single_bit_flip() {
        let secret = "s";
        let pubkey = [9u8; 32];
        let target = [3u8; 20];
        let mut digest = make_cloning_digest(secret, &pubkey, &target);
        digest[0] ^= 0x01;
        assert!(!verify_cloning_digest(secret, &pubkey, &target, &digest));
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

    // ---- F03-AF-25: independent byte-level reference vectors ----
    //
    // A round trip through the same implementation only proves the encrypt and
    // decrypt halves agree with *each other*; it cannot catch an unintended
    // shared convention (a wrong domain string, pubkey order, encoding or nonce)
    // that both sides happen to honour. These vectors pin every intermediate
    // byte of the cloning transcript against values produced by a SEPARATE,
    // OpenSSL-backed implementation (Python `cryptography` / `hmac`), so a silent
    // change to the wire crypto is caught in CI and an independently built peer
    // stays compatible. Vectors were produced by an OpenSSL-backed generator
    // (Python `cryptography`/`hmac`) over fixed inputs, then pinned here.

    /// Decode a fixed-width hex constant into a byte array.
    fn hexn<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s)
            .expect("valid hex literal")
            .try_into()
            .expect("hex literal has the expected byte length")
    }

    #[test]
    fn af25_cloning_digest_reference_vector() {
        // Reference: HMAC-SHA256(secret_utf8, encryption_pubkey ‖ target)
        // computed by Python `hmac`/`hashlib` (independent of RustCrypto).
        let secret = "utexo-af25-fixed-reference-secret-0123456789";
        let pubkey = hexn::<32>("030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc");
        let target = hexn::<20>("05101b26313c47525d68737e89949faab5c0cbd6");
        let want = hexn::<32>("ac9ab8ce85a4eabf160922d0077690807c434c4d338d1140fb3f8581605de25b");
        assert_eq!(make_cloning_digest(secret, &pubkey, &target), want);
        assert!(verify_cloning_digest(secret, &pubkey, &target, &want));

        // AF-07 target binding at the byte level: the SAME secret+pubkey with a
        // one-byte-different target maps to an independently-computed, distinct
        // digest — never back to `want`.
        let target_b = hexn::<20>("06111c27323d48535e69747f8a95a0abb6c1ccd7");
        let want_b = hexn::<32>("642b1bb86f3e1b0526fb3932fa85ea1695b4e8feaa07607826158cccf805518e");
        assert_eq!(make_cloning_digest(secret, &pubkey, &target_b), want_b);
        assert_ne!(want, want_b);
    }

    #[test]
    fn af25_seed_seal_reference_vector() {
        // Reference for the full donor->requester seal chain
        // X25519 -> HKDF-SHA256 -> ChaCha20Poly1305(IETF, zero nonce), every
        // stage cross-checked against the OpenSSL-backed implementation.
        let req_sk = hexn::<32>("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let donor_sk =
            hexn::<32>("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        let seed = hexn::<64>(
            "070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e6164\
             676a6d707376797c7f8285888b8e9194979a9da0a3a6a9acafb2b5b8bbbec1c4",
        );

        let req_secret = StaticSecret::from(req_sk);
        let donor_secret = StaticSecret::from(donor_sk);
        let req_pub = PublicKey::from(&req_secret).to_bytes();
        let donor_pub = PublicKey::from(&donor_secret).to_bytes();

        // (a) X25519 public keys (clamped scalar * basepoint) match reference.
        assert_eq!(
            req_pub,
            hexn::<32>("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"),
        );
        assert_eq!(
            donor_pub,
            hexn::<32>("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"),
        );

        // (b) DH shared secret matches, and both peers derive it identically.
        let shared = donor_secret.diffie_hellman(&PublicKey::from(req_pub));
        assert_eq!(
            shared.as_bytes(),
            &hexn::<32>("ae4440cc8d7faddb2894172b78e3d745cafa0098bcc10d7ee0fda08fa85a9a2e"),
        );
        assert_eq!(
            req_secret
                .diffie_hellman(&PublicKey::from(donor_pub))
                .as_bytes(),
            shared.as_bytes(),
        );

        // (c) HKDF-SHA256(salt, shared, "seed-encryption" ‖ donor_pub ‖ req_pub).
        let key = derive_symmetric_key(shared.as_bytes(), &donor_pub, &req_pub);
        assert_eq!(
            *key,
            hexn::<32>("392ccd781d51995d3d1d73c4848432646bc6c2c220ef25826cd15c04bf61500f"),
        );

        // (d) ChaCha20Poly1305 (IETF, all-zero nonce) ciphertext = 64B seed + 16B tag.
        let ct = encrypt_with_key(&key, &seed).expect("seal");
        assert_eq!(
            ct,
            hex::decode(
                "fd74236255f673bcda5c5f2b7b717466d48ad8327d365ddb8d82d0902df8bf74\
                 7fd0a01de3ebddf96d38e026007a62a4cc9151b61ebd5c77c60101ffd7f732d8\
                 581045088a7392fbdfeb22775e65216b",
            )
            .unwrap(),
        );

        // (e) the production decrypt path recovers the exact seed from the vector.
        let session_pub = PublicKey::from(&req_secret);
        let session = CloneSession {
            secret: req_secret,
            public: session_pub,
        };
        let recovered = session
            .decrypt_seed_from_peer(&donor_pub, &ct)
            .expect("unseal");
        assert_eq!(*recovered, seed);
    }
}
