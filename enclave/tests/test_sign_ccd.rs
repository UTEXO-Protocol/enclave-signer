mod common;

use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::*;

/// Init the enclave with a fixed seed and return the Concordium Ed25519 pubkey.
#[cfg(all(feature = "allow-seed-import", not(feature = "rgb-validation")))]
fn init_and_get_ccd_pubkey(port: u16) -> Vec<u8> {
    let init = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: [0x42u8; 64].to_vec(),
            mnemonic: String::new(),
        })),
    };
    match common::send_request(port, &init).response {
        Some(Response::InitializeKey(r)) => r.ccd_ed25519_pub,
        other => panic!("expected InitializeKeyResponse, got {:?}", other),
    }
}

#[cfg(all(feature = "allow-seed-import", not(feature = "rgb-validation")))]
#[test]
fn test_sign_ccd_roundtrip() {
    let port = common::start_test_server();

    let ccd_pub = init_and_get_ccd_pubkey(port);
    assert_eq!(ccd_pub.len(), 32, "ed25519 pubkey must be 32 bytes");
    assert!(ccd_pub.iter().any(|&b| b != 0), "pubkey must be non-zero");

    let req = EnclaveRequest {
        request: Some(Request::SignCcd(SignCcdRequest {
            hash: vec![0xABu8; 32],
        })),
    };

    let sig = match common::send_request(port, &req).response {
        Some(Response::CcdSignature(r)) => r.signature,
        other => panic!("expected CcdSignatureResponse, got {:?}", other),
    };
    assert_eq!(sig.len(), 64, "ed25519 signature must be 64 bytes");

    // Ed25519 (RFC 8032) is deterministic: the same hash yields the same signature.
    let sig2 = match common::send_request(port, &req).response {
        Some(Response::CcdSignature(r)) => r.signature,
        other => panic!("expected CcdSignatureResponse, got {:?}", other),
    };
    assert_eq!(sig, sig2);
}

#[cfg(all(feature = "allow-seed-import", not(feature = "rgb-validation")))]
#[test]
fn test_sign_ccd_rejects_wrong_hash_length() {
    let port = common::start_test_server();
    let _ = init_and_get_ccd_pubkey(port);

    let req = EnclaveRequest {
        request: Some(Request::SignCcd(SignCcdRequest {
            hash: vec![0xABu8; 31], // not 32 bytes
        })),
    };
    assert!(
        matches!(
            common::send_request(port, &req).response,
            Some(Response::Error(_))
        ),
        "a non-32-byte hash must be rejected",
    );
}
