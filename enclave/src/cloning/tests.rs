use super::*;

#[test]
fn validate_secret_rejects_empty() {
    assert!(matches!(
        validate_cloning_secret(""),
        Err(EnclaveError::InvalidRequest(_))
    ));
}

#[test]
fn validate_secret_rejects_too_short() {
    // 31 bytes, many distinct values: only the length check fails.
    let s = "0123456789abcdef0123456789abcde";
    assert_eq!(s.len(), 31);
    assert!(matches!(
        validate_cloning_secret(s),
        Err(EnclaveError::InvalidRequest(_))
    ));
}

#[test]
fn validate_secret_rejects_low_entropy() {
    // 64 bytes, one distinct value.
    let s = "a".repeat(64);
    assert!(matches!(
        validate_cloning_secret(&s),
        Err(EnclaveError::InvalidRequest(_))
    ));
}

#[test]
fn validate_secret_accepts_64_hex() {
    let s = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert_eq!(s.len(), 64);
    assert!(validate_cloning_secret(s).is_ok());
}

#[test]
fn validate_secret_accepts_min_length_boundary() {
    // Exactly 32 bytes.
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
    // Same secret and requester key, different donor.
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
    let (ciphertext, _donor_pub) = encrypt_seed_for_peer(&requester.public_key(), &seed).unwrap();

    // Random, not zero: zero is small-order and fails a different check.
    let wrong_donor = PublicKey::from(&StaticSecret::random()).to_bytes();
    let result = requester.decrypt_seed_from_peer(&wrong_donor, &ciphertext);
    assert!(matches!(result, Err(EnclaveError::Clone(_))));
}

#[test]
fn encrypt_rejects_small_order_peer_pubkey() {
    // The all-zero point is a small-order point on Curve25519.
    let result = encrypt_seed_for_peer(&[0u8; 32], &[42u8; 64]);
    assert!(matches!(result, Err(EnclaveError::InvalidRequest(_))));
}

#[test]
fn decrypt_rejects_small_order_peer_pubkey() {
    let requester = CloneSession::new();
    // A valid ciphertext, opened with the small-order all-zero peer key.
    let (ciphertext, _legit_donor) =
        encrypt_seed_for_peer(&requester.public_key(), &[42u8; 64]).unwrap();
    let result = requester.decrypt_seed_from_peer(&[0u8; 32], &ciphertext);
    assert!(matches!(result, Err(EnclaveError::InvalidRequest(_))));
}

#[test]
fn seed_decrypt_tampered_ciphertext_fails() {
    let seed = [42u8; 64];
    let requester = CloneSession::new();
    let (mut ciphertext, donor_pub) =
        encrypt_seed_for_peer(&requester.public_key(), &seed).unwrap();

    ciphertext[0] ^= 0xff;
    let result = requester.decrypt_seed_from_peer(&donor_pub, &ciphertext);
    assert!(matches!(result, Err(EnclaveError::Clone(_))));
}

#[test]
fn decrypt_with_wrong_requester_key_fails() {
    let seed = [42u8; 64];
    let requester_a = CloneSession::new();
    let (ciphertext, donor_pub) = encrypt_seed_for_peer(&requester_a.public_key(), &seed).unwrap();

    // A different session gives a different shared secret.
    let requester_b = CloneSession::new();
    let result = requester_b.decrypt_seed_from_peer(&donor_pub, &ciphertext);
    assert!(matches!(result, Err(EnclaveError::Clone(_))));
}

#[test]
fn two_sessions_generate_distinct_keys() {
    let a = CloneSession::new();
    let b = CloneSession::new();
    assert_ne!(a.public_key(), b.public_key());
}

// Fixed vectors from Python `cryptography` (OpenSSL) and `hmac`.
// Each step is checked, so a wire-format change fails a test.

/// Decode a fixed-width hex constant into a byte array.
fn hexn<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s)
        .expect("valid hex literal")
        .try_into()
        .expect("hex literal has the expected byte length")
}

#[test]
fn cloning_digest_reference_vector() {
    // HMAC-SHA256(secret_utf8, encryption_pubkey || target) from Python `hmac`.
    let secret = "utexo-fixed-reference-secret-0123456789";
    let pubkey = hexn::<32>("030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc");
    let target = hexn::<20>("05101b26313c47525d68737e89949faab5c0cbd6");
    let want = hexn::<32>("5205503b952299cda46eb7982f5e0e29752f723a23e8d2ae55869504f0a195f4");
    assert_eq!(make_cloning_digest(secret, &pubkey, &target), want);
    assert!(verify_cloning_digest(secret, &pubkey, &target, &want));

    // A target that differs in each byte gives a different digest.
    let target_b = hexn::<20>("06111c27323d48535e69747f8a95a0abb6c1ccd7");
    let want_b = hexn::<32>("8abb75a1b5ddeebb9bb096597060a9b3501293bc422ec4ff859ad4eeac3fe57f");
    assert_eq!(make_cloning_digest(secret, &pubkey, &target_b), want_b);
    assert_ne!(want, want_b);
}

#[test]
fn seed_seal_reference_vector() {
    // Check X25519, HKDF-SHA256, and ChaCha20Poly1305 against independent vectors.
    let req_sk = hexn::<32>("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    let donor_sk = hexn::<32>("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    let seed = hexn::<64>(
        "070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e6164\
         676a6d707376797c7f8285888b8e9194979a9da0a3a6a9acafb2b5b8bbbec1c4",
    );

    let req_secret = StaticSecret::from(req_sk);
    let donor_secret = StaticSecret::from(donor_sk);
    let req_pub = PublicKey::from(&req_secret).to_bytes();
    let donor_pub = PublicKey::from(&donor_secret).to_bytes();

    // (a) X25519 public keys.
    assert_eq!(
        req_pub,
        hexn::<32>("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"),
    );
    assert_eq!(
        donor_pub,
        hexn::<32>("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"),
    );

    // (b) DH shared secret, the same on both sides.
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

    // (c) HKDF-SHA256(salt, shared, "seed-encryption" || donor_pub || req_pub).
    let key = derive_symmetric_key(shared.as_bytes(), &donor_pub, &req_pub);
    assert_eq!(
        *key,
        hexn::<32>("392ccd781d51995d3d1d73c4848432646bc6c2c220ef25826cd15c04bf61500f"),
    );

    // (d) ChaCha20Poly1305 (IETF, zero nonce): 64-byte seed + 16-byte tag.
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

    // (e) The production decrypt path recovers the seed.
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
