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
    fn load_keys(&self, network: Network, _deadline: std::time::Instant) -> Result<KeyManager> {
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

#[test]
fn recovery_reservation_does_not_block_other_workers_or_allow_overwrite() {
    use std::sync::{mpsc, Mutex};
    use std::time::Duration;
    struct BlockingSource {
        started: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl SwapSeedSource for BlockingSource {
        fn load_keys(&self, network: Network, _: std::time::Instant) -> Result<KeyManager> {
            self.started.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            KeyManager::from_seed([42; 64], network)
        }
    }
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let state = Arc::new(
        EnclaveState::new(Network::Bitcoin).with_swap_seed_source(Box::new(BlockingSource {
            started: started_tx,
            release: Mutex::new(release_rx),
        })),
    );
    let initializing = state.clone();
    let worker = std::thread::spawn(move || initializing.initialize_from_swap_kms());
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let (probe_tx, probe_rx) = mpsc::channel();
    let probing = state.clone();
    let probe = std::thread::spawn(move || {
        let phase = probing.phase_name();
        let keys = probing.get_keys();
        let init = probing.initialize_from_swap_kms();
        let overwrite = probing.initialize_from_seed([17; 64]);
        probe_tx.send((phase, keys, init, overwrite)).unwrap();
    });
    let result = probe_rx.recv_timeout(Duration::from_millis(500));
    release_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();
    probe.join().unwrap();
    let (phase, keys, init, overwrite) =
        result.expect("state mutex must not be held during custody I/O");
    assert_eq!(phase, "initializing");
    assert!(matches!(keys, Err(EnclaveError::KeyNotInitialized)));
    assert!(matches!(init, Err(EnclaveError::NotReady { .. })));
    assert!(matches!(overwrite, Err(EnclaveError::NotReady { .. })));
    assert_eq!(
        state.evm_address().unwrap(),
        *KeyManager::from_seed([42; 64], Network::Bitcoin)
            .unwrap()
            .evm_address()
    );
}

#[test]
fn successful_recovery_after_deadline_never_activates() {
    use std::time::{Duration, Instant};
    struct LateSource;
    impl SwapSeedSource for LateSource {
        fn load_keys(&self, network: Network, deadline: Instant) -> Result<KeyManager> {
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
            );
            KeyManager::from_seed([42; 64], network)
        }
    }
    let state = EnclaveState::new(Network::Bitcoin).with_swap_seed_source(Box::new(LateSource));
    assert!(state
        .initialize_from_swap_kms_until(Instant::now() + Duration::from_millis(30))
        .is_err());
    assert_eq!(state.phase_name(), "initial");
    assert!(state.get_keys().is_err());
}

#[test]
fn expired_request_never_starts_custody_io() {
    let calls = Arc::new(AtomicUsize::new(0));
    let state = EnclaveState::new(Network::Bitcoin)
        .with_swap_seed_source(Box::new(RetrySource(calls.clone())));
    assert!(state
        .initialize_from_swap_kms_until(std::time::Instant::now())
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.phase_name(), "initial");
}

#[test]
fn panicking_recovery_releases_reservation_for_retry() {
    struct PanicOnce(AtomicUsize);
    impl SwapSeedSource for PanicOnce {
        fn load_keys(&self, network: Network, _: std::time::Instant) -> Result<KeyManager> {
            assert_ne!(
                self.0.fetch_add(1, Ordering::SeqCst),
                0,
                "injected recovery panic"
            );
            KeyManager::from_seed([42; 64], network)
        }
    }
    let state = EnclaveState::new(Network::Bitcoin)
        .with_swap_seed_source(Box::new(PanicOnce(AtomicUsize::new(0))));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || state.initialize_from_swap_kms()
    ))
    .is_err());
    assert_eq!(state.phase_name(), "initial");
    state.initialize_from_swap_kms().unwrap();
    assert_eq!(state.phase_name(), "active");
}

#[test]
fn ingress_time_is_subtracted_before_custody_dispatch() {
    use std::io::{Cursor, Read, Write};
    use std::time::{Duration, Instant};
    use utexo_bridge_enclave::networks::rgb::spv::{
        checkpoint_for, HeaderChain, Network as SpvNetwork,
    };
    use utexo_bridge_enclave::{config::BridgeConfig, framing, server};
    struct SlowRequest {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        delay_once: bool,
    }
    impl Read for SlowRequest {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.delay_once {
                std::thread::sleep(Duration::from_millis(40));
                self.delay_once = false;
            }
            self.input.read(buf)
        }
    }
    impl Write for SlowRequest {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let state = EnclaveState::new(Network::Bitcoin)
        .with_swap_seed_source(Box::new(RetrySource(calls.clone())));
    let ctx = server::ServerContext::new(
        state,
        BridgeConfig::default(),
        std::sync::Mutex::new(HeaderChain::new(
            SpvNetwork::Regtest,
            checkpoint_for(SpvNetwork::Regtest),
        )),
    );
    let mut request = Vec::new();
    framing::write_message(
        &mut request,
        &EnclaveRequest {
            request: Some(Request::InitializeKey(InitializeKeyRequest::default())),
        },
    )
    .unwrap();
    let mut stream = SlowRequest {
        input: Cursor::new(request),
        output: Vec::new(),
        delay_once: true,
    };
    // The request has ten milliseconds of dispatch time plus the two seconds
    // reserved for its response. Reading the frame consumes the dispatch time.
    server::handle_connection_until(
        &mut stream,
        &ctx,
        Instant::now() + Duration::from_millis(2010),
    );
    let response: EnclaveResponse = framing::read_message(&mut Cursor::new(stream.output)).unwrap();
    assert!(matches!(response.response, Some(Response::Error(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(ctx.state.phase_name(), "initial");
}
