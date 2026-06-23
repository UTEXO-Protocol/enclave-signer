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
