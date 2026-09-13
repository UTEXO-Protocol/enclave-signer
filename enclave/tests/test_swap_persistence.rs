#![cfg(feature = "rgb-swap")]

mod common;

use bitcoin::Network;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use utexo_bridge_enclave::proto::{enclave_request::Request, enclave_response::Response, *};
use utexo_bridge_enclave::swap_persistence::SwapSeedSource;
use utexo_bridge_enclave::{
    error::{EnclaveError, Result},
    keys::KeyManager,
    state::EnclaveState,
};

struct RetrySource(Arc<AtomicUsize>);
impl SwapSeedSource for RetrySource {
    fn load_keys(&self, network: Network) -> Result<KeyManager> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(EnclaveError::Internal("persistence unavailable".into()));
        }
        KeyManager::from_seed([42; 64], network)
    }
}

#[test]
fn missing_configuration_never_falls_back_to_ephemeral_generation() {
    let state = EnclaveState::new(Network::Bitcoin);
    assert!(state.initialize_from_swap_kms().is_err());
    assert_eq!(state.phase_name(), "initial");
    assert!(matches!(
        state.sign_evm(&[1; 32]),
        Err(EnclaveError::KeyNotInitialized)
    ));
}

#[test]
fn failed_recovery_stays_initial_and_retry_activates_only_once() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let state = EnclaveState::new(Network::Bitcoin)
        .with_swap_seed_source(Box::new(RetrySource(attempts.clone())));
    assert!(state.initialize_from_swap_kms().is_err());
    assert_eq!(state.phase_name(), "initial");
    assert!(state.get_keys().is_err());
    state.initialize_from_swap_kms().unwrap();
    assert_eq!(state.phase_name(), "active");
    let expected = KeyManager::from_seed([42; 64], Network::Bitcoin).unwrap();
    assert_eq!(
        state.sign_evm(&[1; 32]).unwrap(),
        expected.sign_evm(&[1; 32]).unwrap()
    );
    assert!(matches!(
        state.initialize_from_swap_kms(),
        Err(EnclaveError::AlreadyInitialized)
    ));
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[test]
fn swap_wire_rejects_every_peer_cloning_entrypoint() {
    let port = common::start_test_server();
    for request in [
        Request::InitiateCloning(InitiateCloningRequest::default()),
        Request::GetClone(GetCloneRequest::default()),
        Request::SetClone(SetCloneRequest::default()),
    ] {
        let response = common::send_request(
            port,
            &EnclaveRequest {
                request: Some(request),
            },
        );
        match response.response {
            Some(Response::Error(e)) => assert!(e.message.contains("cloning is disabled")),
            other => panic!("cloning must be disabled: {other:?}"),
        }
    }
    let response = common::send_request(
        port,
        &EnclaveRequest {
            request: Some(Request::GetPublicKey(GetPublicKeyRequest {})),
        },
    );
    assert!(matches!(response.response, Some(Response::Error(_))));
}

#[test]
fn swap_initialize_rejects_cloning_secret_before_activating() {
    let port = common::start_test_server();
    let response = common::send_request(
        port,
        &EnclaveRequest {
            request: Some(Request::InitializeKey(InitializeKeyRequest {
                cloning_secret: "obsolete-secret".into(),
                ..Default::default()
            })),
        },
    );
    match response.response {
        Some(Response::Error(e)) => assert!(e.message.contains("cloning_secret is not supported")),
        other => panic!("cloning secret must be rejected: {other:?}"),
    }
    let response = common::send_request(
        port,
        &EnclaveRequest {
            request: Some(Request::GetPublicKey(GetPublicKeyRequest {})),
        },
    );
    assert!(matches!(response.response, Some(Response::Error(_))));
}
