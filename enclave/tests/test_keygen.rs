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

// A canonical BIP-39 test vector — a stable, non-secret mnemonic used to
// exercise the caller-supplied-mnemonic import path.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// TI-1 (#112) — Production build (default `cargo test`, `allow-seed-import`
/// OFF): an `InitializeKey` carrying a caller-supplied seed OR mnemonic must be
/// REJECTED. The gate is the compile-time `#[cfg(not(feature =
/// "allow-seed-import"))]` arm in `handle_initialize` (server.rs), which returns
/// `EnclaveError::InvalidRequest` -> `Response::Error`. Because the rejection
/// happens before any state mutation, a subsequent OS-entropy init (empty seed
/// + empty mnemonic) on the same server must still succeed.
///
/// The dev-mode acceptance counterpart is
/// `dev_build_accepts_caller_supplied_seed_and_mnemonic` below; CI must run both
/// feature profiles (the gate is compile-time, so the two directions cannot be
/// exercised in one build).
#[test]
#[cfg(not(feature = "allow-seed-import"))]
fn production_build_rejects_caller_supplied_seed_and_mnemonic() {
    let port = common::start_test_server();

    // Caller-supplied raw seed -> rejected.
    let seed_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![7u8; 64],
            mnemonic: String::new(),
        })),
    };
    let seed_resp = common::send_request(port, &seed_req);
    match &seed_resp.response {
        Some(Response::Error(e)) => {
            eprintln!("--- production rejects seed import ---");
            eprintln!("  error: code={} message=\"{}\"", e.code, e.message);
            assert!(
                e.message.contains("not allowed"),
                "expected a 'not allowed' rejection, got: {}",
                e.message
            );
        }
        other => panic!("production build must reject seed import, got {:?}", other),
    }

    // Caller-supplied mnemonic -> rejected.
    let mnemonic_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: TEST_MNEMONIC.into(),
        })),
    };
    let mnemonic_resp = common::send_request(port, &mnemonic_req);
    match &mnemonic_resp.response {
        Some(Response::Error(e)) => assert!(
            e.message.contains("not allowed"),
            "expected a 'not allowed' rejection, got: {}",
            e.message
        ),
        other => panic!(
            "production build must reject mnemonic import, got {:?}",
            other
        ),
    }

    // The rejected imports must not have consumed initialization: a plain
    // OS-entropy init on the same server still succeeds.
    let entropy_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    let entropy_resp = common::send_request(port, &entropy_req);
    assert!(
        matches!(&entropy_resp.response, Some(Response::InitializeKey(_))),
        "OS-entropy init after a rejected import must still succeed, got {:?}",
        entropy_resp.response
    );
}

/// TI-1 (#112) — Dev build (`cargo test ... --features allow-seed-import`, debug
/// profile): the SAME `InitializeKey` call that production rejects is ACCEPTED.
/// The `#[cfg(feature = "allow-seed-import")]` arm of `handle_initialize`
/// installs the caller's seed / mnemonic and returns `Response::InitializeKey`.
/// Each import uses a fresh server (init is one-shot).
#[test]
#[cfg(feature = "allow-seed-import")]
fn dev_build_accepts_caller_supplied_seed_and_mnemonic() {
    // Caller-supplied raw seed -> accepted.
    let port_seed = common::start_test_server();
    let seed_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![7u8; 64],
            mnemonic: String::new(),
        })),
    };
    let seed_resp = common::send_request(port_seed, &seed_req);
    let seed_init = match &seed_resp.response {
        Some(Response::InitializeKey(r)) => r,
        other => panic!("dev build must accept seed import, got {:?}", other),
    };
    assert_eq!(seed_init.evm_address.len(), 20);
    assert_eq!(seed_init.btc_compressed_pub.len(), 33);
    assert!(seed_init.btc_xpub.starts_with("xpub"));

    // Caller-supplied mnemonic -> accepted (fresh server; init is one-shot).
    let port_mnemonic = common::start_test_server();
    let mnemonic_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: TEST_MNEMONIC.into(),
        })),
    };
    let mnemonic_resp = common::send_request(port_mnemonic, &mnemonic_req);
    assert!(
        matches!(&mnemonic_resp.response, Some(Response::InitializeKey(_))),
        "dev build must accept mnemonic import, got {:?}",
        mnemonic_resp.response
    );
}
