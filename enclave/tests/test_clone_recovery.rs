//! Characterize the current donor-recovery defect through the wire handlers.
//!
//! This passing test reproduces a defect, not the desired recovery behavior:
//! a replica cloned without a boot-installed donor secret cannot become a donor,
//! even when the operator knows and resubmits the original cloning secret.
//! Change the failure assertions when donor recovery is implemented.
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

fn initialize_request() -> Req {
    Req::InitializeKey(InitializeKeyRequest {
        seed: vec![],
        mnemonic: String::new(),
        cloning_secret: CLONING_SECRET.into(),
    })
}

fn public_keys(port: u16) -> PublicKeysResponse {
    match call(port, Req::GetPublicKey(GetPublicKeyRequest {})) {
        Resp::PublicKeys(keys) => keys,
        other => panic!("expected active public keys, got {other:?}"),
    }
}

fn initiate_requester(port: u16, target: &[u8]) -> Req {
    let Resp::InitiateCloning(init) = call(
        port,
        Req::InitiateCloning(InitiateCloningRequest {
            cloning_secret: CLONING_SECRET.into(),
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
    let response = call(
        port,
        Req::SetClone(SetCloneRequest {
            encrypted_seed: clone.encrypted_seed,
            donor_pubkey: clone.donor_pubkey,
            donor_attestation: clone.donor_attestation,
        }),
    );
    assert!(matches!(response, Resp::SetClone(_)), "{response:?}");
}

fn assert_error(response: Resp, code: u32, message: &str) {
    let Resp::Error(error) = response else {
        panic!("expected error {code}: {message}, got {response:?}");
    };
    assert_eq!(error.code, code, "{error:?}");
    assert!(error.message.contains(message), "{error:?}");
}

#[test]
fn cloned_replica_cannot_donate_even_when_operator_resubmits_secret() {
    // Explicit config avoids process environment affecting the policy. In
    // particular, B and C have no secret preinstalled through a state helper.
    let config = BridgeConfig::default();
    let donor_a = start_test_server_with_config(|_| {}, config.clone());
    let replica_b = start_test_server_with_config(|_| {}, config.clone());
    let requester_c = start_test_server_with_config(|_| {}, config);

    let initialized = call(donor_a, initialize_request());
    assert!(
        matches!(initialized, Resp::InitializeKey(_)),
        "{initialized:?}"
    );
    let identity = public_keys(donor_a);

    // A -> B succeeds through the ordinary three-message clone handshake.
    let request_for_b = initiate_requester(replica_b, &identity.evm_address);
    activate_requester(replica_b, call(donor_a, request_for_b));
    assert_eq!(public_keys(replica_b), identity);

    // The operator still knows the secret and supplies it to fresh requester
    // C. B holds the correct seed but lacks the separate donor-side secret.
    let request_for_c = initiate_requester(requester_c, &identity.evm_address);
    assert_error(
        call(replica_b, request_for_c.clone()),
        2,
        "donor cloning secret not configured",
    );

    // Supplying the same secret to B through InitializeKey cannot repair it:
    // the Active phase rejects initialization before the secret setter runs.
    assert_error(
        call(replica_b, initialize_request()),
        1,
        "already initialized",
    );
    assert_eq!(public_keys(replica_b), identity);
    assert_error(
        call(replica_b, request_for_c.clone()),
        2,
        "donor cloning secret not configured",
    );

    // Positive control: the exact request B refused is valid. A accepts it,
    // and C recovers the complete identity. The failure is B's donor state,
    // not the operator's secret, C's attestation, or the clone transcript.
    activate_requester(requester_c, call(donor_a, request_for_c));
    assert_eq!(public_keys(requester_c), identity);
}
