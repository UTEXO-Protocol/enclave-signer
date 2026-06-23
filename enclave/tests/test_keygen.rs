mod common;

use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::*;

#[test]
fn initialize_and_get_keys() {
    let port = common::start_test_server();

    // Initialize with new entropy
    let req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };
    let resp = common::send_request(port, &req);

    let init_resp = match &resp.response {
        Some(Response::InitializeKey(r)) => r,
        other => panic!("expected InitializeKeyResponse, got {:?}", other),
    };

    eprintln!("--- initialize_and_get_keys (random entropy) ---");
    eprintln!(
        "  EVM address:    0x{}",
        hex::encode(&init_resp.evm_address)
    );
    eprintln!(
        "  BTC compressed: {}",
        hex::encode(&init_resp.btc_compressed_pub)
    );
    eprintln!("  BTC xpub:       {}", init_resp.btc_xpub);

    assert_eq!(init_resp.evm_address.len(), 20);
    assert_eq!(init_resp.btc_compressed_pub.len(), 33);
    assert!(init_resp.btc_compressed_pub[0] == 0x02 || init_resp.btc_compressed_pub[0] == 0x03);
    assert!(!init_resp.btc_xpub.is_empty());
    assert!(init_resp.btc_xpub.starts_with("xpub"));

    // Get keys — should return same values
    let req2 = EnclaveRequest {
        request: Some(Request::GetPublicKey(GetPublicKeyRequest {})),
    };
    let resp2 = common::send_request(port, &req2);

    let keys_resp = match &resp2.response {
        Some(Response::PublicKeys(r)) => r,
        other => panic!("expected PublicKeysResponse, got {:?}", other),
    };

    assert_eq!(init_resp.evm_address, keys_resp.evm_address);
    assert_eq!(init_resp.btc_compressed_pub, keys_resp.btc_compressed_pub);
    assert_eq!(init_resp.btc_xpub, keys_resp.btc_xpub);
}

#[test]
fn double_initialize_returns_error() {
    let port = common::start_test_server();

    let req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };

    let resp1 = common::send_request(port, &req);
    assert!(
        matches!(&resp1.response, Some(Response::InitializeKey(_))),
        "first init should succeed"
    );

    let resp2 = common::send_request(port, &req);
    if let Some(Response::Error(e)) = &resp2.response {
        eprintln!("--- double_initialize_returns_error ---");
        eprintln!(
            "  second init error: code={} message=\"{}\"",
            e.code, e.message
        );
    }
    assert!(
        matches!(&resp2.response, Some(Response::Error(_))),
        "second init should return error"
    );
}

#[test]
fn get_keys_before_init_returns_error() {
    let port = common::start_test_server();

    let req = EnclaveRequest {
        request: Some(Request::GetPublicKey(GetPublicKeyRequest {})),
    };
    let resp = common::send_request(port, &req);

    if let Some(Response::Error(e)) = &resp.response {
        eprintln!("--- get_keys_before_init_returns_error ---");
        eprintln!("  error: code={} message=\"{}\"", e.code, e.message);
    }
    assert!(
        matches!(&resp.response, Some(Response::Error(_))),
        "get_keys before init should return error"
    );
}

#[test]
#[cfg(feature = "allow-seed-import")]
fn deterministic_seed_import() {
    let seed = [42u8; 64];

    let port1 = common::start_test_server();
    let req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: seed.to_vec(),
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };
    let resp1 = common::send_request(port1, &req);

    let init1 = match &resp1.response {
        Some(Response::InitializeKey(r)) => r,
        other => panic!("expected InitializeKeyResponse, got {:?}", other),
    };

    // Same seed on a fresh server should produce identical keys
    let port2 = common::start_test_server();
    let resp2 = common::send_request(port2, &req);

    let init2 = match &resp2.response {
        Some(Response::InitializeKey(r)) => r,
        other => panic!("expected InitializeKeyResponse, got {:?}", other),
    };

    eprintln!("--- deterministic_seed_import (seed = [42u8; 64]) ---");
    eprintln!("  server 1:");
    eprintln!("    EVM address:    0x{}", hex::encode(&init1.evm_address));
    eprintln!(
        "    BTC compressed: {}",
        hex::encode(&init1.btc_compressed_pub)
    );
    eprintln!("    BTC xpub:       {}", init1.btc_xpub);
    eprintln!("  server 2:");
    eprintln!("    EVM address:    0x{}", hex::encode(&init2.evm_address));
    eprintln!(
        "    BTC compressed: {}",
        hex::encode(&init2.btc_compressed_pub)
    );
    eprintln!("    BTC xpub:       {}", init2.btc_xpub);

    assert_eq!(init1.evm_address, init2.evm_address);
    assert_eq!(init1.btc_compressed_pub, init2.btc_compressed_pub);
    assert_eq!(init1.btc_xpub, init2.btc_xpub);
}
