//! Integration tests for the cloning handshake (T5 PR 4).
//!
//! These tests run with `--features mock-attestation,allow-seed-import`.
//! Mock attestation skips NSM / COSE / cert-chain validation but still
//! enforces pubkey, digest, nonce, and PCR binding. `allow-seed-import`
//! is only used to give the *donor* a known fixed seed.
//!
//! The cloning path itself does NOT require `allow-seed-import` — PR 3's
//! `initialize_from_cloned_seed` is production-available and guarded by
//! the `Phase::Cloning` state, not a feature flag.

#![cfg(all(feature = "mock-attestation", feature = "allow-seed-import"))]

mod common;

use common::{send_request, start_test_server_with};
use utexo_bridge_enclave::proto::enclave_request::Request as Req;
use utexo_bridge_enclave::proto::enclave_response::Response as Resp;
use utexo_bridge_enclave::proto::*;

// Known BIP-39 test vector from the key-manager unit tests. Produces a
// stable, non-secret seed we can embed in integration tests.
const DONOR_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CLONING_SECRET: &str = "test-operator-cloning-secret";

fn initialize_key_from_mnemonic(port: u16, mnemonic: &str) -> PublicKeysResponse {
    let resp = send_request(
        port,
        &EnclaveRequest {
            request: Some(Req::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: mnemonic.into(),
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
    // Requester does not need a donor secret configured — it receives
    // the secret via InitiateCloningRequest. But set it anyway to match
    // a realistic deployment where both roles are possible.
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

// ---- happy path ----

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

    // Requester is now Active and should report the donor's identity.
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

// ---- error cases ----

#[test]
fn clone_rejects_wrong_cloning_secret() {
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    // Requester uses a DIFFERENT secret than the donor was configured with.
    let init = initiate_cloning(requester_port, "wrong-secret", &donor_keys.evm_address);
    let err = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect_err("GetClone should reject a mismatched digest");
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

    // Requester targets an EVM address that is not the donor's.
    let wrong_target = [0xDEu8; 20];
    let init = initiate_cloning(requester_port, CLONING_SECRET, &wrong_target);
    let err = request_get_clone(donor_port, &wrong_target, &init)
        .expect_err("GetClone should reject mismatched cluster address");
    assert!(
        err.message.contains("cluster_public_key") || err.message.contains("does not match"),
        "unexpected error: {}",
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
    // Flip a byte in the Poly1305 tag (last 16 bytes of the ciphertext).
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
    // Requester side: the requester records the donor's attestation nonce only
    // AFTER `complete_cloning` commits. A SetClone that
    // fails inside completion (seed decrypt / KeyManager derivation / identity)
    // must therefore leave the enclave in `Cloning` with the nonce un-consumed,
    // so a legitimate party whose handshake fails once can retry with the SAME
    // donor attestation instead of being wedged out by a self-inflicted replay.
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);
    let clone = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect("GetClone should succeed");

    // 1. First SetClone fails at seed-decrypt (flip a byte in the Poly1305 tag),
    //    i.e. inside `complete_cloning`, after the point where the nonce is read
    //    but before it is recorded.
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

    // 2. State unchanged: the requester never reached `Active`, so it exposes no
    //    keys yet (GetPublicKey fails while still in `Cloning`).
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

    // 3. Nonce un-consumed: retrying with the ORIGINAL (untampered) clone — the
    //    same `donor_attestation`, hence the same nonce — still succeeds.
    //    Pre-fix the doomed attempt consumed the nonce first and this retry
    //    failed on the replay guard.
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

    // First GetClone succeeds.
    let _ok = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect("first GetClone should succeed");

    // Replaying the same GetClone (same nonce inside the attestation)
    // must fail on the donor's replay guard.
    let err = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect_err("second GetClone should hit replay guard");
    assert!(
        err.message.contains("replay") || err.message.contains("nonce"),
        "unexpected error: {}",
        err.message
    );
}

#[test]
fn clone_rejected_handshake_does_not_consume_replay_nonce() {
    // audit W-13: the donor must record a handshake nonce only AFTER the
    // pubkey/digest/donor-secret checks pass. A rejected (unauthenticated)
    // handshake must not consume replay-guard capacity — otherwise anyone able
    // to mint attestations over arbitrary nonces (the get_attested_public_key
    // oracle) could exhaust the guard without ever knowing the cloning secret.
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);

    // Tamper the cloning digest so the handshake is rejected at the digest
    // binding — which runs *after* the point where the nonce used to be
    // recorded.
    let mut tampered = init.clone();
    tampered.cloning_digest[0] ^= 0xff;
    let err = request_get_clone(donor_port, &donor_keys.evm_address, &tampered)
        .expect_err("tampered cloning_digest must be rejected");
    assert!(
        !err.message.contains("replay"),
        "should fail on the digest binding, not the replay guard: {}",
        err.message
    );

    // The rejected attempt must NOT have recorded its nonce: a subsequent
    // valid handshake reusing the same attestation (same nonce) still
    // succeeds. Pre-fix this failed on the replay guard because the doomed
    // attempt consumed the nonce first.
    request_get_clone(donor_port, &donor_keys.evm_address, &init).expect(
        "valid handshake reusing the same nonce must still succeed after a rejected attempt",
    );
}

#[test]
fn cannot_initialize_after_entering_cloning() {
    let requester_port = start_requester();
    // Start a clone session using a throwaway donor address.
    let _init = initiate_cloning(requester_port, CLONING_SECRET, &[0x11u8; 20]);

    // Attempting a fresh InitializeKey must now fail — the enclave is in
    // Phase::Cloning, not Phase::Initial.
    let resp = send_request(
        requester_port,
        &EnclaveRequest {
            request: Some(Req::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: DONOR_MNEMONIC.into(),
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

// ---- audit test coverage: attestation binding on the donor ----

#[test]
fn clone_donor_rejects_wire_pubkey_not_matching_attestation() {
    // TC-2 (#107): the parent relays (encryption_pubkey, cloning_digest,
    // requester_attestation) to the donor. The X25519 pubkey inside the
    // NSM-signed requester attestation is authoritative; the plaintext
    // `encryption_pubkey` on the wire is not. A malicious parent could swap the
    // wire pubkey for one it controls to intercept the sealed seed. The donor
    // must bind the two (handle_get_clone step 3) and abort on any mismatch.
    let (donor_port, donor_keys) = start_donor();
    let requester_port = start_requester();

    let init = initiate_cloning(requester_port, CLONING_SECRET, &donor_keys.evm_address);

    // Tamper only the wire pubkey; leave the attestation (which binds the real
    // ephemeral pubkey) untouched. Any well-formed 32-byte key that is not the
    // attested one exercises the binding check.
    let mut tampered = init.clone();
    tampered.encryption_pubkey = vec![0x77u8; 32];
    assert_ne!(
        tampered.encryption_pubkey, init.encryption_pubkey,
        "the tampered wire pubkey must differ from the attested one"
    );

    let err = request_get_clone(donor_port, &donor_keys.evm_address, &tampered)
        .expect_err("donor must abort when wire pubkey != attested pubkey");
    assert!(
        err.message.contains("pubkey mismatch") || err.message.contains("does not match"),
        "expected a pubkey-binding rejection, got: {}",
        err.message
    );

    // Legitimate peer (wire == attested) still succeeds. This also proves the
    // rejected attempt aborted at the pubkey binding (which runs before the
    // replay guard records the nonce), so reusing the same attestation is fine.
    let clone = request_get_clone(donor_port, &donor_keys.evm_address, &init)
        .expect("legitimate handshake (wire == attested) must succeed");
    assert_eq!(clone.donor_pubkey.len(), 32);
    assert_eq!(clone.encrypted_seed.len(), 64 + 16); // seed + Poly1305 tag
    assert!(!clone.donor_attestation.is_empty());
}

#[test]
fn clone_donor_refuses_pcr_mismatched_peer_but_accepts_matching_peer() {
    // TC-1 (#106): the cloning donor must refuse to seal its seed to a peer
    // whose PCR0/PCR1 do not match the donor's own measurement -- even when the
    // handshake otherwise carries a valid attestation, the correct encryption
    // pubkey, and a correctly-authenticated cloning digest. A PCR-equal peer is
    // accepted in the SAME run to prove the rejection is PCR-specific, not a
    // blanket failure.
    let (donor_port, donor_keys) = start_donor();

    // ---- 1. PCR-mismatched peer: donor must refuse to seal ----
    let bad_requester_port = start_requester();
    let bad_init = initiate_cloning(bad_requester_port, CLONING_SECRET, &donor_keys.evm_address);

    // In mock mode the donor's own PCRs (get_own_pcrs) are all-zero, so a
    // non-zero PCR0/PCR1 is a genuine measurement mismatch. Keep the real
    // encryption-pubkey + cloning-digest bindings so the request can only fail
    // on the PCR check (handle_get_clone step 2, which runs first), not on the
    // pubkey/digest binding.
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
    assert!(
        err.message.contains("PCR"),
        "expected a PCR-mismatch rejection, got: {}",
        err.message
    );
    // request_get_clone returned Err -> no GetCloneResponse, so no encrypted
    // seed was ever produced or transmitted to the mismatched peer.

    // ---- 2. PCR-equal peer: donor accepts and seals in the SAME run ----
    let good_requester_port = start_requester();
    let good_init = initiate_cloning(good_requester_port, CLONING_SECRET, &donor_keys.evm_address);
    let clone = request_get_clone(donor_port, &donor_keys.evm_address, &good_init)
        .expect("donor must seal to a PCR-matching peer");
    assert_eq!(clone.encrypted_seed.len(), 64 + 16); // seed + Poly1305 tag
    assert_eq!(clone.donor_pubkey.len(), 32);

    // The matching peer can actually unseal it -> proves a real clone, not just
    // a well-formed-looking response.
    request_set_clone(good_requester_port, &clone).expect("SetClone should succeed");
    let good_keys = get_public_keys(good_requester_port);
    assert_eq!(good_keys.evm_address, donor_keys.evm_address);
}
