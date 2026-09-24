use super::*;

#[test]
fn signet_challenge_matches_oleksandrs_hex() {
    // The byte array must hex-encode to exactly the published value, so a
    // typo is caught before it ships to attestation.
    let hex = hex::encode(UTEXO_SIGNET_CHALLENGE);
    assert_eq!(
        hex,
        "6a4c09011e000000000000004c6953210224a528aa141b7d2ed093575b5d2c2cee4065abc6f7f6b19a970a8975d327f935210249c6bf8338ecda2749c3ffad4b8ec22f71581947c10d1766d9ce83d1bcafb99421024f3a831fcb4db446b07fe8897d193b86f913984f6eb3ab6e9745eeb61017a3b553ae"
    );
}

#[test]
fn signet_challenge_decodes_as_3_of_3_multisig() {
    // Light structural check: the trailing bytes are OP_3 OP_CHECKMULTISIG.
    let len = UTEXO_SIGNET_CHALLENGE.len();
    assert_eq!(UTEXO_SIGNET_CHALLENGE[len - 2], 0x53); // OP_3 (n)
    assert_eq!(UTEXO_SIGNET_CHALLENGE[len - 1], 0xae); // OP_CHECKMULTISIG
}

#[test]
fn signet_magic_is_four_bytes() {
    // Defensive: future refactors that reshape the magic must not silently
    // change its length.
    assert_eq!(UTEXO_SIGNET_MAGIC.len(), 4);
    assert_eq!(UTEXO_SIGNET_MAGIC, [0x6f, 0x21, 0x61, 0x5a]);
}

#[test]
fn checkpoint_for_dispatches_on_network() {
    assert!(checkpoint_for(Network::Mainnet).is_real);
    assert!(checkpoint_for(Network::Signet).is_real);
    assert!(!checkpoint_for(Network::Testnet3).is_real);
    assert!(checkpoint_for(Network::Regtest).is_real);
}

#[test]
fn mainnet_checkpoint_is_retarget_boundary_aligned() {
    // The mainnet checkpoint MUST sit on a retarget boundary, else
    // the chain wedges at the first boundary above it.
    assert_eq!(MAINNET_CHECKPOINT.height % RETARGET_INTERVAL, 0);
    assert_eq!(MAINNET_CHECKPOINT.height, 472 * RETARGET_INTERVAL);
    MAINNET_CHECKPOINT
        .assert_retarget_aligned(Network::Mainnet)
        .expect("mainnet checkpoint must be boundary-aligned");
}

// === SPV_CHECKPOINT override (dev-only boot anchor) ===

/// Round-trip: the spec for the real signet checkpoint must parse back to
/// the compiled-in constant, display-order hash included. Catches a
/// regression in the byte flip.
#[test]
fn parse_spec_round_trips_the_signet_constant() {
    let spec = "334000:000000ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66:0x1e0377ae:1780464472";
    let cp = parse_checkpoint_spec(spec, Network::Signet, &SIGNET_CHECKPOINT).unwrap();
    assert_eq!(cp.height, SIGNET_CHECKPOINT.height);
    assert_eq!(cp.hash, SIGNET_CHECKPOINT.hash);
    assert_eq!(cp.bits, SIGNET_CHECKPOINT.bits);
    assert_eq!(cp.time, SIGNET_CHECKPOINT.time);
    assert!(cp.is_real);
}

#[test]
fn parse_spec_two_field_form_inherits_bits_and_time() {
    let spec = "0x334000".to_string(); // not a full spec - see below
    assert!(parse_checkpoint_spec(&spec, Network::Signet, &SIGNET_CHECKPOINT).is_err());

    let spec = "400000:000000ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66";
    let cp = parse_checkpoint_spec(spec, Network::Signet, &SIGNET_CHECKPOINT).unwrap();
    assert_eq!(cp.height, 400_000);
    assert_eq!(cp.bits, SIGNET_CHECKPOINT.bits, "bits inherited");
    assert_eq!(cp.time, SIGNET_CHECKPOINT.time, "time inherited");
}

#[test]
fn parse_spec_accepts_0x_prefixed_hash() {
    let bare = "400000:000000ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66";
    let prefixed = "400000:0x000000ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66";
    let a = parse_checkpoint_spec(bare, Network::Signet, &SIGNET_CHECKPOINT).unwrap();
    let b = parse_checkpoint_spec(prefixed, Network::Signet, &SIGNET_CHECKPOINT).unwrap();
    assert_eq!(a.hash, b.hash);
}

/// A PoW network must not inherit bits/time: the nBits check and the
/// retarget epoch-start lookup consume them, so a stale pair would reject
/// every real header.
#[test]
fn parse_spec_requires_bits_and_time_on_pow_networks() {
    let spec = "953568:00000000000000000001b472f1922f86148c8286609fb14be39e12b8bd14bb64";
    let err = parse_checkpoint_spec(spec, Network::Mainnet, &MAINNET_CHECKPOINT).unwrap_err();
    assert!(err.contains("enforces PoW"), "got: {err}");
    // Same height with the full four fields is fine.
    let full = format!("{spec}:0x1702068f:1780050586");
    assert!(parse_checkpoint_spec(&full, Network::Mainnet, &MAINNET_CHECKPOINT).is_ok());
}

/// Esplora reports `bits` in decimal; without the `0x` requirement
/// `503538094` would silently parse as hex (a completely different target).
#[test]
fn parse_spec_rejects_decimal_bits() {
    let spec = "334000:000000ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66:503538094:1780464472";
    let err = parse_checkpoint_spec(spec, Network::Signet, &SIGNET_CHECKPOINT).unwrap_err();
    assert!(err.contains("0x"), "got: {err}");
}

#[test]
fn parse_spec_rejects_malformed_specs() {
    let cases = [
        // wrong field count
        "334000",
        "334000:aa:0x1e0377ae",
        // height not a number
        "tip:000000ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66",
        // hash not hex / wrong length
        "334000:zzzz00ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66",
        "334000:00ac5fcc",
        // placeholder hash
        "334000:0000000000000000000000000000000000000000000000000000000000000000",
        // bad time
        "334000:000000ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66:0x1e0377ae:soon",
    ];
    for spec in cases {
        assert!(
            parse_checkpoint_spec(spec, Network::Signet, &SIGNET_CHECKPOINT).is_err(),
            "spec {spec:?} should have been rejected"
        );
    }
}

/// Unit tests run under `cfg(test)`, one of the sanctioned dev shapes, so
/// the override is allowed here. The production-shaped combination
/// (release, no `allow-seed-import`) is what the boot gate refuses.
#[test]
fn override_is_allowed_in_test_builds() {
    assert!(checkpoint_override_allowed());
}

/// With no env var set, boot resolution is the compiled-in constant.
#[test]
fn resolve_without_env_returns_the_compiled_checkpoint() {
    if std::env::var(CHECKPOINT_ENV).is_ok() {
        return; // someone's shell has it set; the pure parser tests cover the rest
    }
    let (cp, source) = resolve_checkpoint(Network::Signet).unwrap();
    assert_eq!(cp.hash, SIGNET_CHECKPOINT.hash);
    assert_eq!(source, CheckpointSource::Compiled);
}

#[test]
fn assert_retarget_aligned_rejects_misaligned_pow_checkpoint() {
    // The previous checkpoint height (950 000) is NOT boundary-aligned
    // (950 000 % 2016 == 464) - exactly the misalignment bug. A PoW network
    // must reject it.
    let misaligned = Checkpoint {
        height: 950_000,
        hash: [0u8; 32],
        bits: 0x1702_0f79,
        time: 1_779_141_269,
        is_real: true,
    };
    assert!(misaligned
        .assert_retarget_aligned(Network::Mainnet)
        .is_err());
    // Non-PoW networks are exempt - they never consult the retarget lookup.
    assert!(misaligned.assert_retarget_aligned(Network::Signet).is_ok());
    assert!(misaligned.assert_retarget_aligned(Network::Regtest).is_ok());
}
