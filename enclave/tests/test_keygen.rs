mod common;

use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::*;

#[test]
fn initialize_and_get_keys() {
    let port = common::start_test_server();

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

    assert_eq!(init_resp.evm_address.len(), 20);
    assert!(!init_resp.account_xpub_vanilla.is_empty());
    assert!(init_resp.account_xpub_vanilla.starts_with("xpub"));

    // GetPublicKey must return the same keys.
    let req2 = EnclaveRequest {
        request: Some(Request::GetPublicKey(GetPublicKeyRequest {})),
    };
    let resp2 = common::send_request(port, &req2);

    let keys_resp = match &resp2.response {
        Some(Response::PublicKeys(r)) => r,
        other => panic!("expected PublicKeysResponse, got {:?}", other),
    };

    assert_eq!(init_resp.evm_address, keys_resp.evm_address);
    assert_eq!(
        init_resp.account_xpub_vanilla,
        keys_resp.account_xpub_vanilla
    );
}

#[test]
#[cfg(not(feature = "kms-persistence"))]
fn refused_cloning_secret_keeps_phase_initial() {
    let port = common::start_test_server();
    let init = |secret: &str| {
        common::send_request(
            port,
            &EnclaveRequest {
                request: Some(Request::InitializeKey(InitializeKeyRequest {
                    seed: vec![],
                    mnemonic: String::new(),
                    cloning_secret: secret.into(),
                })),
            },
        )
    };
    let phase = || {
        let req = EnclaveRequest {
            request: Some(Request::Health(HealthRequest::default())),
        };
        match common::send_request(port, &req).response {
            Some(Response::Health(h)) => h.phase,
            other => panic!("expected Health, got {other:?}"),
        }
    };

    match init("weak-secret").response {
        Some(Response::Error(e)) => assert!(e.message.contains("cloning_secret"), "{}", e.message),
        other => panic!("expected Error, got {other:?}"),
    }
    assert_eq!(phase(), "initial");

    let evm_address = match init("test-operator-cloning-secret-0123456789abcdef").response {
        Some(Response::InitializeKey(r)) => r.evm_address,
        other => panic!("expected InitializeKeyResponse, got {other:?}"),
    };
    assert_eq!(phase(), "active");

    // The donor secret is stored: the digest check runs and fails.
    let req = EnclaveRequest {
        request: Some(Request::GetClone(GetCloneRequest {
            cluster_public_key: evm_address,
            encryption_pubkey: vec![0; 32],
            cloning_digest: vec![0; 32],
            requester_attestation: vec![],
        })),
    };
    match common::send_request(port, &req).response {
        Some(Response::Error(e)) => {
            assert!(
                e.message.contains("cloning digest mismatch"),
                "{}",
                e.message
            )
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// The enclave refuses a mnemonic over the size limit before the parse,
/// which normalizes the whole string first. The refusal changes no state.
#[test]
#[cfg(feature = "allow-seed-import")]
fn a_mnemonic_over_the_size_limit_is_refused() {
    let port = common::start_test_server();
    let init = |mnemonic: String| EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic,
            cloning_secret: String::new(),
        })),
    };
    let resp = common::send_request(port, &init("abandon ".repeat(200)));
    match &resp.response {
        Some(Response::Error(e)) => assert!(e.message.contains("the limit is"), "{}", e.message),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let resp = common::send_request(port, &init(TEST_MNEMONIC.into()));
    assert!(
        matches!(resp.response, Some(Response::InitializeKey(_))),
        "{:?}",
        resp.response
    );
}

// Canonical BIP-39 test vector. It is stable and not secret.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Production build (`allow-seed-import` off): `handle_initialize` rejects a
/// caller-supplied seed or mnemonic. The rejection occurs before any state
/// change, so a later OS-entropy init on the same server succeeds.
///
/// The counterpart is `dev_build_accepts_caller_supplied_seed_and_mnemonic`.
/// The gate is compile-time, so CI runs this test in a build without
/// `allow-seed-import` (the `light` job), and the counterpart in the signer
/// test builds.
#[test]
#[cfg(not(feature = "allow-seed-import"))]
fn production_build_rejects_caller_supplied_seed_and_mnemonic() {
    let port = common::start_test_server();

    // Caller-supplied raw seed -> rejected.
    let seed_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![7u8; 64],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };
    let seed_resp = common::send_request(port, &seed_req);
    match &seed_resp.response {
        Some(Response::Error(e)) => {
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
            cloning_secret: String::new(),
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

    // The rejected imports must not consume initialization.
    let entropy_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };
    let entropy_resp = common::send_request(port, &entropy_req);
    assert!(
        matches!(&entropy_resp.response, Some(Response::InitializeKey(_))),
        "OS-entropy init after a rejected import must still succeed, got {:?}",
        entropy_resp.response
    );
}

/// Dev build (`--features allow-seed-import`): the enclave accepts the caller's
/// seed or mnemonic. Each import uses a fresh server, because init is one-shot.
#[test]
#[cfg(feature = "allow-seed-import")]
fn dev_build_accepts_caller_supplied_seed_and_mnemonic() {
    // Caller-supplied raw seed -> accepted.
    let port_seed = common::start_test_server();
    let seed_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![7u8; 64],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };
    let seed_resp = common::send_request(port_seed, &seed_req);
    let seed_init = match &seed_resp.response {
        Some(Response::InitializeKey(r)) => r,
        other => panic!("dev build must accept seed import, got {:?}", other),
    };
    assert_eq!(seed_init.evm_address.len(), 20);
    assert!(seed_init.account_xpub_vanilla.starts_with("xpub"));

    // Caller-supplied mnemonic -> accepted (fresh server; init is one-shot).
    let port_mnemonic = common::start_test_server();
    let mnemonic_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: TEST_MNEMONIC.into(),
            cloning_secret: String::new(),
        })),
    };
    let mnemonic_resp = common::send_request(port_mnemonic, &mnemonic_req);
    assert!(
        matches!(&mnemonic_resp.response, Some(Response::InitializeKey(_))),
        "dev build must accept mnemonic import, got {:?}",
        mnemonic_resp.response
    );
}
