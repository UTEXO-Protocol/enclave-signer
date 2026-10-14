//! A verified clone can replace its donor using the same operator secret.
//!
//! The local harness uses TCP and mock attestation; it does not test real Nitro
//! attestation or production boot. Key and clone requests use the shipped wire
//! handlers. No seed import or direct state secret setter is used; A initializes
//! from entropy and receives its secret through InitializeKey, as in the burn flow.
#![cfg(all(feature = "mock-attestation", not(feature = "kms-persistence")))]

mod common;

use common::{send_request, start_test_server_with_config};
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::proto::enclave_request::Request as Req;
use utexo_bridge_enclave::proto::enclave_response::Response as Resp;
use utexo_bridge_enclave::proto::*;

const CLONING_SECRET: &str = "public-donor-recovery-test-secret-0123456789abcdef";
const WRONG_SECRET: &str = "public-wrong-recovery-test-secret-0123456789abcdef";

fn call(port: u16, request: Req) -> Resp {
    send_request(
        port,
        &EnclaveRequest {
            request: Some(request),
        },
    )
    .response
    .expect("response variant")
}

fn initialize_request(secret: &str) -> Req {
    Req::InitializeKey(InitializeKeyRequest {
        seed: vec![],
        mnemonic: String::new(),
        cloning_secret: secret.into(),
    })
}

fn public_keys(port: u16) -> PublicKeysResponse {
    match call(port, Req::GetPublicKey(GetPublicKeyRequest {})) {
        Resp::PublicKeys(keys) => keys,
        other => panic!("expected active public keys, got {other:?}"),
    }
}

fn initiate_requester(port: u16, target: &[u8], secret: &str) -> Req {
    let Resp::InitiateCloning(init) = call(
        port,
        Req::InitiateCloning(InitiateCloningRequest {
            cloning_secret: secret.into(),
            cluster_public_key: target.to_vec(),
        }),
    ) else {
        panic!("requester failed to initiate cloning");
    };
    Req::GetClone(GetCloneRequest {
        cluster_public_key: target.to_vec(),
        cloning_digest: init.cloning_digest,
        encryption_pubkey: init.encryption_pubkey,
        requester_attestation: init.requester_attestation,
    })
}

fn activate_requester(port: u16, response: Resp) {
    let Resp::GetClone(clone) = response else {
        panic!("expected successful export, got {response:?}");
    };
    let response = call(port, set_clone_request(clone));
    assert!(matches!(response, Resp::SetClone(_)), "{response:?}");
}

fn set_clone_request(clone: GetCloneResponse) -> Req {
    Req::SetClone(SetCloneRequest {
        encrypted_seed: clone.encrypted_seed,
        donor_pubkey: clone.donor_pubkey,
        donor_attestation: clone.donor_attestation,
    })
}

fn assert_error(response: Resp, code: u32, message: &str) {
    let Resp::Error(error) = response else {
        panic!("expected error {code}: {message}, got {response:?}");
    };
    assert_eq!(error.code, code, "{error:?}");
    assert!(error.message.contains(message), "{error:?}");
}

#[test]
fn cloned_replica_replaces_original_donor_without_reinitialization() {
    // Explicit config avoids process environment affecting the policy. In
    // particular, B and C have no secret preinstalled through a state helper.
    let config = BridgeConfig::default();
    let donor_a = start_test_server_with_config(|_| {}, config.clone());
    let replica_b = start_test_server_with_config(|_| {}, config.clone());
    let requester_c = start_test_server_with_config(|_| {}, config.clone());
    let wrong_requester = start_test_server_with_config(|_| {}, config);

    let initialized = call(donor_a, initialize_request(CLONING_SECRET));
    assert!(
        matches!(initialized, Resp::InitializeKey(_)),
        "{initialized:?}"
    );
    let identity = public_keys(donor_a);

    // A -> B succeeds through the ordinary three-message clone handshake.
    let request_for_b = initiate_requester(replica_b, &identity.evm_address, CLONING_SECRET);
    activate_requester(replica_b, call(donor_a, request_for_b));
    assert_eq!(public_keys(replica_b), identity);

    // A is not used again. B must retain the original authentication checks.
    let wrong_request = initiate_requester(wrong_requester, &identity.evm_address, WRONG_SECRET);
    assert_error(call(replica_b, wrong_request), 5, "digest");

    // Active initialization must remain forbidden, including attempts to
    // replace the donor credential with a different valid-length secret.
    assert_error(
        call(replica_b, initialize_request(WRONG_SECRET)),
        1,
        "already initialized",
    );
    assert_eq!(public_keys(replica_b), identity);

    // B -> C succeeds using the original secret supplied through ordinary
    // requests. No boot secret or second InitializeKey is needed on B.
    let request_for_c = initiate_requester(requester_c, &identity.evm_address, CLONING_SECRET);
    activate_requester(requester_c, call(replica_b, request_for_c.clone()));
    assert_eq!(public_keys(requester_c), identity);

    // The cloned donor must retain GetClone nonce replay enforcement too.
    assert_error(call(replica_b, request_for_c), 6, "nonce replay detected");
}

#[test]
fn rejected_clone_can_retry_and_then_donate_without_preinstalled_secret() {
    let config = BridgeConfig::default();
    let donor_a = start_test_server_with_config(|_| {}, config.clone());
    let replica_b = start_test_server_with_config(|_| {}, config.clone());
    let requester_c = start_test_server_with_config(|_| {}, config);
    assert!(matches!(
        call(donor_a, initialize_request(CLONING_SECRET)),
        Resp::InitializeKey(_)
    ));
    let identity = public_keys(donor_a);
    let request_for_b = initiate_requester(replica_b, &identity.evm_address, CLONING_SECRET);
    let Resp::GetClone(clone) = call(donor_a, request_for_b) else {
        panic!("original donor must export successfully");
    };

    // A failed unseal must leave B inactive, retain its pending credential,
    // and release the donor nonce so this exact response can be retried.
    let mut tampered = clone.clone();
    tampered.encrypted_seed[0] ^= 1;
    assert!(matches!(
        call(replica_b, set_clone_request(tampered)),
        Resp::Error(_)
    ));
    assert_error(
        call(replica_b, Req::GetPublicKey(GetPublicKeyRequest {})),
        1,
        "key not initialized",
    );

    activate_requester(replica_b, Resp::GetClone(clone.clone()));
    assert_eq!(public_keys(replica_b), identity);
    assert_error(call(replica_b, set_clone_request(clone)), 1, "replay");

    let request_for_c = initiate_requester(requester_c, &identity.evm_address, CLONING_SECRET);
    activate_requester(requester_c, call(replica_b, request_for_c));
    assert_eq!(public_keys(requester_c), identity);
}
