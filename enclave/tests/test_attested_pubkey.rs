//! Integration tests for `GetAttestedPublicKey`.
//!
//! Runs with `--features mock-attestation,allow-seed-import`. Mock mode skips
//! COSE and cert-chain validation. It still checks the nonce, the PCRs, and
//! the `public_key` and `user_data` bindings that this RPC produces.

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
    let parts: [&[u8]; 10] = [
        &keys.evm_address,
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

/// The enclave commitment: sha256(pubkey_bundle || policy_commitment).
/// A debug build with `mock-attestation` resolves to the `Development`
/// policy, so this helper uses the same policy.
fn expected_user_data(keys: &PublicKeysResponse) -> [u8; 32] {
    let mut preimage = canonical_bundle(keys);
    preimage.extend_from_slice(&attestation_verify::AttestedPolicy::Development.to_bytes());
    Sha256::digest(preimage).into()
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

    let verified = attestation_verify::verify_mock_attestation(
        &resp.attestation_doc,
        &attestation_verify::ExpectedPcrs::zero(),
        Some(&nonce),
    )
    .expect("attestation verifies");

    // The NSM `public_key` field must be the bridge EVM uncompressed pubkey.
    assert_eq!(verified.enclave_pubkey, public_keys.evm_uncompressed_pub);

    let expected_commitment = expected_user_data(&public_keys);
    assert_eq!(
        verified.user_data.as_deref(),
        Some(expected_commitment.as_slice()),
        "user_data must be sha256(canonical_bundle || policy_commitment)"
    );

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
fn attested_pubkey_before_init_attests_the_policy_only() {
    let port = start_test_server();
    let nonce = [3u8; 32];

    let r = request_attested(port, &nonce);

    assert!(r.public_keys.is_none());
    let verified = attestation_verify::verify_mock_policy_attestation(
        &r.attestation_doc,
        &attestation_verify::ExpectedPcrs::zero(),
        &nonce,
    )
    .expect("policy-only document verifies");
    assert_eq!(
        verified.user_data.as_deref(),
        Some(attestation_verify::policy_commitment(&r.attested_policy).as_slice())
    );
    assert_eq!(
        r.attested_policy,
        attestation_verify::AttestedPolicy::Development.to_bytes()
    );
}
