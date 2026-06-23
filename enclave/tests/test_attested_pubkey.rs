//! Integration tests for `GetAttestedPublicKey`.
//!
//! Runs with `--features mock-attestation,allow-seed-import`. Mock mode
//! skips COSE / cert-chain validation but still enforces nonce, PCRs, and
//! the embedded `public_key` / `user_data` bindings — which is exactly
//! what we want to exercise here, since those are the bits the new RPC
//! produces.

#![cfg(all(feature = "mock-attestation", feature = "allow-seed-import"))]

mod common;

use common::{send_request, start_test_server};
use sha2::{Digest, Sha256};
use utexo_bridge_enclave::proto::enclave_request::Request as Req;
use utexo_bridge_enclave::proto::enclave_response::Response as Resp;
use utexo_bridge_enclave::proto::*;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn initialize(port: u16) {
    let resp = send_request(
        port,
        &EnclaveRequest {
            request: Some(Req::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: TEST_MNEMONIC.into(),
                cloning_secret: String::new(),
            })),
        },
    );
    assert!(matches!(resp.response, Some(Resp::InitializeKey(_))));
}

fn canonical_bundle(keys: &PublicKeysResponse) -> Vec<u8> {
    let chain_id_bytes = keys.chain_id.to_be_bytes();
    let parts: [&[u8]; 12] = [
        &keys.evm_address,
        &keys.btc_compressed_pub,
        keys.btc_xpub.as_bytes(),
        &keys.master_fingerprint,
        keys.account_xpub_vanilla.as_bytes(),
        keys.account_xpub_colored.as_bytes(),
        &keys.evm_uncompressed_pub,
        &chain_id_bytes,
        &keys.bridge_contract,
        keys.rgb_asset_id.as_bytes(),
        &keys.evm_gas_tx_uncompressed_pub,
        &keys.evm_gas_tx_address,
    ];
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

fn request_attested(port: u16, nonce: &[u8]) -> GetAttestedPublicKeyResponse {
    let resp = send_request(
        port,
        &EnclaveRequest {
            request: Some(Req::GetAttestedPublicKey(GetAttestedPublicKeyRequest {
                nonce: nonce.to_vec(),
            })),
        },
    );
    match resp.response {
        Some(Resp::GetAttestedPublicKey(r)) => r,
        other => panic!("expected GetAttestedPublicKey, got {:?}", other),
    }
}

#[test]
fn attested_pubkey_happy_path_binds_evm_pubkey_and_commitment() {
    let port = start_test_server();
    initialize(port);

    let nonce = [0xa5u8; 32];
    let resp = request_attested(port, &nonce);

    let public_keys = resp.public_keys.expect("public_keys present");

    // Verifier path: parse the attestation doc, confirm the bindings.
    let verified = attestation_verify::verify_mock_attestation(
        &resp.attestation_doc,
        &attestation_verify::ExpectedPcrs::zero(),
        Some(&nonce),
    )
    .expect("attestation verifies");

    // The NSM `public_key` field MUST be the bridge's EVM uncompressed pubkey.
    assert_eq!(verified.enclave_pubkey, public_keys.evm_uncompressed_pub);

    // The NSM `user_data` field MUST be sha256 of the canonical bundle.
    let expected_commitment: [u8; 32] = Sha256::digest(canonical_bundle(&public_keys)).into();
    assert_eq!(
        verified.user_data.as_deref(),
        Some(expected_commitment.as_slice()),
        "user_data must be sha256(canonical_bundle)"
    );

    // Nonce echoed.
    assert_eq!(verified.nonce, nonce.to_vec());
}

#[test]
fn attested_pubkey_rejects_wrong_nonce_size() {
    let port = start_test_server();
    initialize(port);

    let resp = send_request(
        port,
        &EnclaveRequest {
            request: Some(Req::GetAttestedPublicKey(GetAttestedPublicKeyRequest {
                nonce: vec![0u8; 16], // wrong length
            })),
        },
    );

    match resp.response {
        Some(Resp::Error(e)) => {
            assert!(
                e.message.contains("32 bytes"),
                "expected nonce-size error, got {:?}",
                e
            );
        }
        other => panic!("expected Error, got {:?}", other),
    }
}

#[test]
fn attested_pubkey_rejects_before_init() {
    let port = start_test_server();

    let resp = send_request(
        port,
        &EnclaveRequest {
            request: Some(Req::GetAttestedPublicKey(GetAttestedPublicKeyRequest {
                nonce: vec![0u8; 32],
            })),
        },
    );

    assert!(matches!(resp.response, Some(Resp::Error(_))));
}

#[test]
fn attested_pubkey_different_nonces_yield_different_docs() {
    let port = start_test_server();
    initialize(port);

    let resp_a = request_attested(port, &[1u8; 32]);
    let resp_b = request_attested(port, &[2u8; 32]);

    assert_ne!(resp_a.attestation_doc, resp_b.attestation_doc);

    // But the public-key bundle is identical (same enclave, same keys).
    assert_eq!(resp_a.public_keys, resp_b.public_keys);
}

#[test]
fn attested_pubkey_wrong_expected_nonce_fails_verify() {
    let port = start_test_server();
    initialize(port);

    let nonce = [0x11u8; 32];
    let other_nonce = [0x22u8; 32];
    let resp = request_attested(port, &nonce);

    let err = attestation_verify::verify_mock_attestation(
        &resp.attestation_doc,
        &attestation_verify::ExpectedPcrs::zero(),
        Some(&other_nonce),
    )
    .unwrap_err();

    assert!(matches!(
        err,
        attestation_verify::VerifyError::Attestation(_)
    ));
}
