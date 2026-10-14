#![cfg(not(feature = "kms-persistence"))]

//! Integration tests for the cloning handshake.
//!
//! Run with `--no-default-features --features ccd,mock-attestation,allow-seed-import`.
//! KMS persistence disables cloning. Mock attestation skips NSM, COSE, and
//! cert-chain validation. It still checks the pubkey, digest, nonce, and PCR
//! bindings. `allow-seed-import` only gives the donor a known seed. The cloning
//! path does not need it, because `Phase::Cloning` guards
//! `initialize_from_cloned_seed`.

#![cfg(all(feature = "mock-attestation", feature = "allow-seed-import"))]

mod common;

use common::{send_request, start_test_server_with};
use utexo_bridge_enclave::proto::enclave_request::Request as Req;
use utexo_bridge_enclave::proto::enclave_response::Response as Resp;
use utexo_bridge_enclave::proto::*;

// Known BIP-39 test vector. It gives a stable seed that is not secret.
const DONOR_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// Use at least 32 bytes and eight distinct values. (F03-AF-26)
const CLONING_SECRET: &str = "test-operator-cloning-secret-0123456789abcdef";

fn initialize_key_from_mnemonic(port: u16, mnemonic: &str) -> PublicKeysResponse {
    let resp = send_request(
        port,
        &EnclaveRequest {
            request: Some(Req::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: mnemonic.into(),
                cloning_secret: String::new(),
            })),
        },
    );
    match resp.response {
        Some(Resp::InitializeKey(r)) => PublicKeysResponse {
            evm_address: r.evm_address,
            btc_compressed_pub: r.btc_compressed_pub,
            btc_xpub: r.btc_xpub,
            master_fingerprint: r.master_fingerprint,
            account_xpub_vanilla: r.account_xpub_vanilla,
            account_xpub_colored: r.account_xpub_colored,
            evm_uncompressed_pub: r.evm_uncompressed_pub,
            chain_id: r.chain_id,
            bridge_contract: r.bridge_contract,
            rgb_asset_id: r.rgb_asset_id,
            evm_gas_tx_uncompressed_pub: r.evm_gas_tx_uncompressed_pub,
            evm_gas_tx_address: r.evm_gas_tx_address,
            ccd_ed25519_pub: r.ccd_ed25519_pub,
        },
        other => panic!("expected InitializeKey response, got {:?}", other),
    }
}

fn get_public_keys(port: u16) -> PublicKeysResponse {
    let resp = send_request(
        port,
        &EnclaveRequest {
            request: Some(Req::GetPublicKey(GetPublicKeyRequest {})),
        },
    );
    match resp.response {
        Some(Resp::PublicKeys(r)) => r,
        other => panic!("expected PublicKeys response, got {:?}", other),
    }
}

fn start_donor() -> (u16, PublicKeysResponse) {
    let port = start_test_server_with(|state| {
        state
            .set_donor_cloning_secret(CLONING_SECRET.into())
            .expect("set_donor_cloning_secret");
    });
    let keys = initialize_key_from_mnemonic(port, DONOR_MNEMONIC);
    (port, keys)
}

fn start_requester() -> u16 {
    // The requester gets the secret in InitiateCloningRequest. The test also
    // sets a donor secret, as in a deployment that can take both roles.
    start_test_server_with(|state| {
        state
            .set_donor_cloning_secret(CLONING_SECRET.into())
            .expect("set_donor_cloning_secret");
    })
}

fn initiate_cloning(
    requester_port: u16,
    secret: &str,
    cluster_public_key: &[u8],
) -> InitiateCloningResponse {
    let resp = send_request(
        requester_port,
        &EnclaveRequest {
            request: Some(Req::InitiateCloning(InitiateCloningRequest {
                cloning_secret: secret.into(),
                cluster_public_key: cluster_public_key.to_vec(),
            })),
        },
    );
    match resp.response {
        Some(Resp::InitiateCloning(r)) => r,
        other => panic!("expected InitiateCloning response, got {:?}", other),
    }
}

fn request_get_clone(
    donor_port: u16,
    donor_evm: &[u8],
    init: &InitiateCloningResponse,
) -> Result<GetCloneResponse, ErrorResponse> {
    let resp = send_request(
        donor_port,
        &EnclaveRequest {
            request: Some(Req::GetClone(GetCloneRequest {
                cluster_public_key: donor_evm.to_vec(),
                cloning_digest: init.cloning_digest.clone(),
                encryption_pubkey: init.encryption_pubkey.clone(),
                requester_attestation: init.requester_attestation.clone(),
            })),
        },
    );
    match resp.response {
        Some(Resp::GetClone(r)) => Ok(r),
        Some(Resp::Error(e)) => Err(e),
        other => panic!("expected GetClone or Error response, got {:?}", other),
    }
}

fn request_set_clone(requester_port: u16, clone: &GetCloneResponse) -> Result<(), ErrorResponse> {
    let resp = send_request(
        requester_port,
        &EnclaveRequest {
            request: Some(Req::SetClone(SetCloneRequest {
                encrypted_seed: clone.encrypted_seed.clone(),
                donor_pubkey: clone.donor_pubkey.clone(),
                donor_attestation: clone.donor_attestation.clone(),
            })),
        },
    );
    match resp.response {
        Some(Resp::SetClone(_)) => Ok(()),
        Some(Resp::Error(e)) => Err(e),
        other => panic!("expected SetClone or Error response, got {:?}", other),
    }
}

#[test]
fn clone_happy_path_copies_donor_identity_to_requester() {
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);
    assert_eq!(init.encryption_pubkey.len(), 32);
    assert_eq!(init.cloning_digest.len(), 32);
    assert!(!init.requester_attestation.is_empty());

    let clone = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect("GetClone should succeed");
    assert_eq!(clone.donor_pubkey.len(), 32);
    assert_eq!(clone.encrypted_seed.len(), 64 + 16); // seed + Poly1305 tag
    assert!(!clone.donor_attestation.is_empty());

    request_set_clone(requester_port, &clone).expect("SetClone should succeed");

    // The requester is now Active and must report the donor identity.
    let requester_keys = get_public_keys(requester_port);
    assert_eq!(requester_keys.evm_address, donor_keys.evm_address);
    assert_eq!(
        requester_keys.btc_compressed_pub,
        donor_keys.btc_compressed_pub
    );
    assert_eq!(requester_keys.btc_xpub, donor_keys.btc_xpub);
    assert_eq!(
        requester_keys.master_fingerprint,
        donor_keys.master_fingerprint
    );
    assert_eq!(
        requester_keys.account_xpub_vanilla,
        donor_keys.account_xpub_vanilla
    );
    assert_eq!(
        requester_keys.account_xpub_colored,
        donor_keys.account_xpub_colored
    );
}

#[test]
fn clone_rejects_wrong_cloning_secret() {
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    // Use a strong secret so this case tests HMAC rejection. (F03-AF-26)
    let init = initiate_cloning(
        requester_port,
        "wrong-operator-cloning-secret-0123456789abcdef",
        &donor_keys.evm_address,
    );
    let err = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect_err("GetClone should reject a mismatched digest");
    assert_eq!(err.code, 5);
    assert!(
        err.message.contains("digest") || err.message.contains("cloning"),
        "unexpected error: {}",
        err.message
    );
}

#[test]
fn clone_rejects_wrong_cluster_public_key() {
    let (donor_port, _donor_keys) = start_donor();
    let requester_port = start_requester();

    // The requester targets an EVM address that is not the donor address.
    let wrong_target = [0xDEu8; 20];
    let init = initiate_cloning(requester_port, CLONING_SECRET, &wrong_target);
    let err = request_get_clone(donor_port, &wrong_target, &init)
        .expect_err("GetClone should reject mismatched cluster address");
    assert_eq!(err.code, 4);
    assert!(
        err.message.contains("cluster_public_key") || err.message.contains("does not match"),
        "unexpected error: {}",
        err.message
    );
}

#[test]
fn clone_donor_rejects_request_armed_for_a_different_target() {
    // Change the target address without changing its HMAC. (F03-AF-07)
    // The donor must reject the request before encrypting its seed.
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    // Create the digest for a different donor.
    let foreign_target = [0xDEu8; 20];
    let init = initiate_cloning(requester_port, CLONING_SECRET, &foreign_target);

    // Use this donor address to pass the initial address check.
    let err = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect_err("donor must reject a request armed for a different target identity");
    assert_eq!(err.code, 5);
    assert!(
        err.message.contains("digest") || err.message.contains("cloning"),
        "expected a digest-binding rejection (F03-AF-07), got: {}",
        err.message
    );
}

#[test]
fn clone_rejects_tampered_ciphertext() {
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);
    let mut clone = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect("GetClone should succeed");
    // Flip a byte in the Poly1305 tag (the last 16 bytes of the ciphertext).
    let len = clone.encrypted_seed.len();
    clone.encrypted_seed[len - 1] ^= 0x01;

    let err = request_set_clone(requester_port, &clone)
        .expect_err("SetClone should reject a tampered ciphertext");
    assert!(
        err.message.contains("unseal") || err.message.contains("clone"),
        "unexpected error: {}",
        err.message
    );
}

#[test]
fn clone_set_failed_completion_leaves_state_and_nonce_unconsumed() {
    // The requester records the donor nonce only after `complete_cloning`
    // commits. A SetClone that fails inside completion leaves the enclave in
    // `Cloning` with the nonce unused, so a retry can use the same attestation.
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);
    let clone = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect("GetClone should succeed");

    // 1. The first SetClone fails at seed decrypt, inside `complete_cloning`.
    //    The enclave has read the nonce but has not recorded it.
    let mut tampered = clone.clone();
    let len = tampered.encrypted_seed.len();
    tampered.encrypted_seed[len - 1] ^= 0x01;
    let err = request_set_clone(requester_port, &tampered)
        .expect_err("tampered ciphertext must fail at seed-decrypt");
    assert!(
        !err.message.contains("replay") && !err.message.contains("nonce"),
        "must fail on the unseal, not the replay guard: {}",
        err.message
    );

    // 2. The requester is still in `Cloning`, so GetPublicKey fails.
    let resp = send_request(
        requester_port,
        &EnclaveRequest {
            request: Some(Req::GetPublicKey(GetPublicKeyRequest {})),
        },
    );
    assert!(
        matches!(resp.response, Some(Resp::Error(_))),
        "requester must still be in Cloning after a failed SetClone, got {:?}",
        resp.response
    );

    // 3. A retry with the original clone and the same nonce succeeds.
    request_set_clone(requester_port, &clone)
        .expect("retry with the same donor attestation must succeed after a failed completion");

    let requester_keys = get_public_keys(requester_port);
    assert_eq!(requester_keys.evm_address, donor_keys.evm_address);
    assert_eq!(requester_keys.btc_xpub, donor_keys.btc_xpub);
}

#[test]
fn clone_rejects_duplicate_requester_attestation_nonce_on_donor() {
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);

    let _ok = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect("first GetClone should succeed");

    // A replay of the same GetClone (same nonce) must hit the replay guard.
    let err = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect_err("second GetClone should hit replay guard");
    assert_eq!(err.code, 6);
    assert!(
        err.message.contains("replay") || err.message.contains("nonce"),
        "unexpected error: {}",
        err.message
    );
}

#[test]
fn clone_rejected_handshake_does_not_consume_replay_nonce() {
    // The donor records a nonce only after the pubkey, digest, and secret
    // checks pass. An unauthenticated handshake cannot use replay-guard capacity.
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);

    // Tamper the cloning digest so the digest binding rejects the handshake.
    let mut tampered = init.clone();
    tampered.cloning_digest[0] ^= 0xff;
    let err = request_get_clone(donor_port, &donor_keys.evm_address, &tampered)
        .expect_err("tampered cloning_digest must be rejected");
    assert!(
        !err.message.contains("replay"),
        "should fail on the digest binding, not the replay guard: {}",
        err.message
    );

    // The rejected attempt must not record its nonce. A valid handshake with
    // the same attestation still succeeds.
    request_get_clone(donor_port, &donor_keys.evm_address, &init).expect(
        "valid handshake reusing the same nonce must still succeed after a rejected attempt",
    );
}

#[test]
fn cannot_initialize_after_entering_cloning() {
    let requester_port = start_requester();
    // Start a clone session with a throwaway donor address.
    let _init = initiate_cloning(requester_port, CLONING_SECRET, &[0x11u8; 20]);

    // InitializeKey must fail, because the enclave is in Phase::Cloning.
    let resp = send_request(
        requester_port,
        &EnclaveRequest {
            request: Some(Req::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: DONOR_MNEMONIC.into(),
                cloning_secret: String::new(),
            })),
        },
    );
    match resp.response {
        Some(Resp::Error(e)) => {
            assert!(
                e.message.contains("already") || e.message.contains("initialized"),
                "unexpected error: {}",
                e.message
            );
        }
        other => panic!("expected Error, got {:?}", other),
    }
}

#[test]
fn clone_donor_rejects_wire_pubkey_not_matching_attestation() {
    // The X25519 pubkey in the signed requester attestation is authoritative.
    // The plaintext `encryption_pubkey` that the parent relays is not. A parent
    // can swap the wire pubkey to get the sealed seed, so the donor binds the two.
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);

    // Change the wire key but keep the original attestation.
    // Use a valid HMAC to reach the attested-key check. (F03-AF-20)
    let mut tampered = init.clone();
    tampered.encryption_pubkey = vec![0x77u8; 32];
    let tampered_pk: [u8; 32] = tampered
        .encryption_pubkey
        .clone()
        .try_into()
        .expect("32-byte pubkey");
    // Include the donor address so the HMAC passes the target check. (F03-AF-07)
    let donor_target: [u8; 20] = donor_keys
        .evm_address
        .clone()
        .try_into()
        .expect("20-byte donor evm address");
    tampered.cloning_digest = utexo_bridge_enclave::cloning::make_cloning_digest(
        CLONING_SECRET,
        &tampered_pk,
        &donor_target,
    )
    .to_vec();
    assert_ne!(
        tampered.encryption_pubkey, init.encryption_pubkey,
        "the tampered wire pubkey must differ from the attested one"
    );

    let err = request_get_clone(donor_port, &donor_keys.evm_address, &tampered)
        .expect_err("donor must abort when wire pubkey != attested pubkey");
    assert_eq!(err.code, 5);
    assert!(
        err.message.contains("pubkey mismatch") || err.message.contains("does not match"),
        "expected a pubkey-binding rejection, got: {}",
        err.message
    );

    // A correct peer (wire == attested) still succeeds. This proves that the
    // rejection occurred at the pubkey binding, before the replay guard.
    let clone = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect("legitimate handshake (wire == attested) must succeed");
    assert_eq!(clone.donor_pubkey.len(), 32);
    assert_eq!(clone.encrypted_seed.len(), 64 + 16); // seed + Poly1305 tag
    assert!(!clone.donor_attestation.is_empty());
}

#[test]
fn clone_donor_refuses_pcr_mismatched_peer_but_accepts_matching_peer() {
    // The donor must not seal its seed to a peer with a different PCR0/PCR1,
    // even if the rest of the handshake is valid. A PCR-equal peer passes in the
    // same run, so the rejection is specific to the PCRs.
    let (donor_port, donor_keys) = start_donor();

    // 1. PCR-mismatched peer: the donor must refuse to seal.
    let bad_requester_port = start_requester();
    let bad_init = initiate_cloning(bad_requester_port, CLONING_SECRET, &donor_keys.evm_address);

    // In mock mode the donor PCRs are all zero, so non-zero PCR0/PCR1 is a
    // mismatch. The pubkey and digest bindings stay valid, so only the PCR
    // check can fail.
    let mismatched_pcrs =
        attestation_verify::ExpectedPcrs::new([0x11u8; 48], [0x22u8; 48], [0u8; 48]);
    let mismatched_attestation = attestation_verify::build_mock_document_with_pcrs(
        &[0x99u8; 32], // arbitrary fresh nonce; donor verifies with expected_nonce = None
        Some(&bad_init.encryption_pubkey),
        Some(&bad_init.cloning_digest),
        &mismatched_pcrs,
    )
    .expect("build mismatched-PCR mock doc");

    let mut tampered = bad_init.clone();
    tampered.requester_attestation = mismatched_attestation;

    let err = request_get_clone(donor_port, &donor_keys.evm_address, &tampered)
        .expect_err("donor must refuse to seal to a PCR-mismatched peer");
    assert_eq!(err.code, 5);
    assert!(
        err.message.contains("PCR"),
        "expected a PCR-mismatch rejection, got: {}",
        err.message
    );

    // 2. PCR-equal peer: the donor seals in the same run.
    let good_requester_port = start_requester();
    let good_init = initiate_cloning(good_requester_port, CLONING_SECRET, &donor_keys.evm_address);
    let clone = request_get_clone(donor_port, &donor_keys.evm_address, &good_init)
        .expect("donor must seal to a PCR-matching peer");
    assert_eq!(clone.encrypted_seed.len(), 64 + 16); // seed + Poly1305 tag
    assert_eq!(clone.donor_pubkey.len(), 32);

    // The matching peer can unseal the seed, so the clone is real.
    request_set_clone(good_requester_port, &clone).expect("SetClone should succeed");
    let good_keys = get_public_keys(good_requester_port);
    assert_eq!(good_keys.evm_address, donor_keys.evm_address);
}

#[test]
fn clone_rejections_carry_their_codes() {
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();
    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);
    let donor_target: [u8; 20] = donor_keys.evm_address.clone().try_into().unwrap();

    // A donor with a cloning secret but no key.
    let keyless_port = start_test_server_with(|state| {
        state
            .set_donor_cloning_secret(CLONING_SECRET.into())
            .expect("set_donor_cloning_secret");
    });
    // A keyed donor without a cloning secret.
    let secretless_port = start_test_server_with(|_| {});
    initialize_key_from_mnemonic(secretless_port, DONOR_MNEMONIC);

    let mut short_target = init.clone();
    short_target.cloning_digest.clear();
    let mut short_pubkey = init.clone();
    short_pubkey.encryption_pubkey.pop();
    let mut garbage_doc = init.clone();
    garbage_doc.requester_attestation = vec![0xAB; 16];
    let mut no_user_data = init.clone();
    no_user_data.requester_attestation =
        attestation_verify::build_mock_document(&[0x55u8; 32], Some(&init.encryption_pubkey), None)
            .unwrap();
    // The small-order key passes the HMAC and the attestation, then fails at sealing.
    let mut small_order = init.clone();
    small_order.encryption_pubkey = vec![0u8; 32];
    small_order.cloning_digest = utexo_bridge_enclave::cloning::make_cloning_digest(
        CLONING_SECRET,
        &[0u8; 32],
        &donor_target,
    )
    .to_vec();
    small_order.requester_attestation = attestation_verify::build_mock_document(
        &[0x66u8; 32],
        Some(&small_order.encryption_pubkey),
        Some(&small_order.cloning_digest),
    )
    .unwrap();

    let cases: [(&str, u16, &[u8], &InitiateCloningResponse, u32); 8] = [
        (
            "short cluster_public_key",
            donor_port,
            &donor_keys.evm_address[..19],
            &init,
            4,
        ),
        (
            "short cloning_digest",
            donor_port,
            &donor_keys.evm_address,
            &short_target,
            4,
        ),
        (
            "short encryption_pubkey",
            donor_port,
            &donor_keys.evm_address,
            &short_pubkey,
            4,
        ),
        (
            "donor without key",
            keyless_port,
            &donor_keys.evm_address,
            &init,
            3,
        ),
        (
            "donor without cloning secret",
            secretless_port,
            &donor_keys.evm_address,
            &init,
            2,
        ),
        (
            "garbage attestation",
            donor_port,
            &donor_keys.evm_address,
            &garbage_doc,
            5,
        ),
        (
            "attestation without user_data",
            donor_port,
            &donor_keys.evm_address,
            &no_user_data,
            5,
        ),
        (
            "small-order encryption_pubkey",
            donor_port,
            &donor_keys.evm_address,
            &small_order,
            4,
        ),
    ];
    for (name, port, target, req, code) in cases {
        let err = request_get_clone(port, target, req).expect_err(name);
        assert_eq!(err.code, code, "{name}: {}", err.message);
    }
}
