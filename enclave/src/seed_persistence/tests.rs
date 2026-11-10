use super::*;
use std::cell::{Cell, RefCell};

#[derive(Default)]
struct Store {
    saved: RefCell<Option<Vec<u8>>>,
    creates: Cell<u32>,
    fail_read: Cell<bool>,
    fail_write: Cell<bool>,
    race_winner: Option<Vec<u8>>,
}
impl SeedStore for Store {
    fn load(&self, _deadline: Instant) -> Result<Option<Vec<u8>>> {
        if self.fail_read.get() {
            return Err(failure("read failed"));
        }
        Ok(self.saved.borrow().clone())
    }
    fn create(&self, blob: &[u8], _deadline: Instant) -> Result<Vec<u8>> {
        self.creates.set(self.creates.get() + 1);
        if self.fail_write.get() {
            return Err(failure("write failed"));
        }
        let mut saved = self.saved.borrow_mut();
        let winner =
            saved.get_or_insert_with(|| self.race_winner.clone().unwrap_or_else(|| blob.to_vec()));
        Ok(winner.clone())
    }
}
#[derive(Default)]
struct Kms {
    generates: Cell<u32>,
    decrypts: Cell<u32>,
    fail_decrypt: bool,
}
impl SeedKms for Kms {
    fn generate(&self, _deadline: Instant) -> Result<Vec<u8>> {
        self.generates.set(self.generates.get() + 1);
        Ok(vec![42; 64]) // Stand-in ciphertext.
    }
    fn decrypt(&self, blob: &[u8], _deadline: Instant) -> Result<Zeroizing<[u8; 64]>> {
        self.decrypts.set(self.decrypts.get() + 1);
        if self.fail_decrypt {
            return Err(failure("KMS denied"));
        }
        Ok(Zeroizing::new(
            blob.try_into().map_err(|_| failure("bad ciphertext"))?,
        ))
    }
}

#[test]
fn valid_ciphertext_for_a_different_identity_is_rejected() {
    let expected = *KeyManager::from_seed([42; 64], Network::Bitcoin)
        .unwrap()
        .evm_address();
    assert!(restore_keys(Zeroizing::new([42; 64]), Network::Bitcoin, Some(expected)).is_ok());
    assert!(matches!(
        restore_keys(Zeroizing::new([17; 64]), Network::Bitcoin, Some(expected)),
        Err(EnclaveError::IdentityMismatch)
    ));
}

#[test]
fn bootstrap_then_restart_and_replica_preserve_keys_and_signatures() {
    let store = Store::default();
    let kms = Kms::default();
    let first = recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).unwrap();
    let a = KeyManager::from_seed(*first, Network::Bitcoin).unwrap();
    // An unpinned restart is refused before KMS. Only the pin recovers a
    // saved identity.
    assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
    assert_eq!(kms.decrypts.get(), 1);
    let restored = recover_seed(
        &store,
        &kms,
        Some(*a.evm_address()),
        Instant::now() + RECOVERY_TIMEOUT,
    )
    .unwrap();
    let replica = recover_seed(
        &store,
        &kms,
        Some(*a.evm_address()),
        Instant::now() + RECOVERY_TIMEOUT,
    )
    .unwrap();
    assert_eq!(*first, *restored);
    assert_eq!(*first, *replica);
    assert_eq!(kms.generates.get(), 1);
    assert_eq!(store.creates.get(), 1);
    let b = KeyManager::from_seed(*restored, Network::Bitcoin).unwrap();
    assert_eq!(a.evm_address(), b.evm_address());
    assert_eq!(a.account_xpub_colored(), b.account_xpub_colored());
    assert_eq!(a.sign_evm(&[7; 32]).unwrap(), b.sign_evm(&[7; 32]).unwrap());
}

#[test]
fn pinned_missing_seed_and_unreadable_store_never_generate_or_write() {
    let store = Store::default();
    let kms = Kms::default();
    assert!(recover_seed(
        &store,
        &kms,
        Some([1; 20]),
        Instant::now() + RECOVERY_TIMEOUT
    )
    .is_err());
    store.fail_read.set(true);
    assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
    assert_eq!(kms.generates.get(), 0);
    assert_eq!(kms.decrypts.get(), 0);
    assert_eq!(store.creates.get(), 0);
    assert!(store.saved.borrow().is_none());
}

#[test]
fn existing_ciphertext_is_recovered_only_with_a_pin() {
    let original = vec![42; 64];
    let store = Store {
        saved: RefCell::new(Some(original.clone())),
        ..Store::default()
    };
    let kms = Kms::default();
    let expected = *KeyManager::from_seed([42; 64], Network::Bitcoin)
        .unwrap()
        .evm_address();
    // No pin: the saved object is refused before any KMS call.
    assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
    assert_eq!(kms.decrypts.get(), 0);
    for pin in [Some(expected), Some([1; 20])] {
        let seed = recover_seed(&store, &kms, pin, Instant::now() + RECOVERY_TIMEOUT).unwrap();
        let keys = restore_keys(seed, Network::Bitcoin, pin);
        if pin == Some([1; 20]) {
            assert!(matches!(keys, Err(EnclaveError::IdentityMismatch)));
        } else {
            assert_eq!(*keys.unwrap().evm_address(), expected);
        }
    }
    assert_eq!(kms.generates.get(), 0);
    assert_eq!(kms.decrypts.get(), 2);
    assert_eq!(store.creates.get(), 0);
    assert_eq!(*store.saved.borrow(), Some(original));
}

#[test]
fn failed_persistence_never_recovers_or_activates_generated_key() {
    let store = Store {
        fail_write: Cell::new(true),
        ..Store::default()
    };
    let kms = Kms::default();
    assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
    assert_eq!(kms.decrypts.get(), 0);
    assert!(store.saved.borrow().is_none());
}

#[test]
fn concurrent_bootstrap_loser_never_activates_the_winner() {
    // The store commits a different blob (a concurrent initializer or a
    // planted one). The call fails without a decrypt, and the committed
    // object stays for a pinned relaunch.
    let store = Store {
        race_winner: Some(vec![17; 64]),
        ..Store::default()
    };
    let kms = Kms::default();
    assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
    assert_eq!(kms.generates.get(), 1);
    assert_eq!(kms.decrypts.get(), 0);
    assert_eq!(*store.saved.borrow(), Some(vec![17; 64]));
    let winner = *KeyManager::from_seed([17; 64], Network::Bitcoin)
        .unwrap()
        .evm_address();
    let seed = recover_seed(
        &store,
        &kms,
        Some(winner),
        Instant::now() + RECOVERY_TIMEOUT,
    )
    .unwrap();
    assert_eq!(*seed, [17; 64]);
    assert_eq!(kms.generates.get(), 1);
}

#[test]
fn kms_denial_and_corruption_do_not_replace_saved_seed() {
    let store = Store {
        saved: RefCell::new(Some(vec![99; 64])),
        ..Store::default()
    };
    let kms = Kms {
        fail_decrypt: true,
        ..Kms::default()
    };
    let pin = Some([1; 20]);
    assert!(recover_seed(&store, &kms, pin, Instant::now() + RECOVERY_TIMEOUT).is_err());
    assert_eq!(kms.generates.get(), 0);
    *store.saved.borrow_mut() = Some(vec![]);
    assert!(recover_seed(&store, &kms, pin, Instant::now() + RECOVERY_TIMEOUT).is_err());
    assert_eq!(kms.decrypts.get(), 1);
}

#[test]
fn broker_errors_and_bad_blobs_are_not_missing_objects() {
    for value in [json!({}), json!({"error":"s3_error"})] {
        assert!(serde_json::from_value::<BlobResponse>(value).is_err());
    }
    for value in [json!(""), json!("!bad-base64!"), json!(23)] {
        assert!(decode_blob(BlobResponse { ciphertext: value }).is_err());
    }
    assert!(decode_blob(BlobResponse {
        ciphertext: json!(null)
    })
    .unwrap()
    .is_none());
}
fn mock_broker(
    reply: impl FnOnce(TcpStream) + Send + 'static,
) -> (SeedBroker, std::thread::JoinHandle<serde_json::Value>) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let broker = SeedBroker {
        address: listener.local_addr().unwrap(),
        seed_id: "pool-1".into(),
    };
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).unwrap();
        let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut body).unwrap();
        let request = serde_json::from_slice(&body).unwrap();
        reply(stream);
        request
    });
    (broker, server)
}

fn frame(value: serde_json::Value) -> Vec<u8> {
    let body = serde_json::to_vec(&value).unwrap();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

#[test]
fn broker_socket_protocol_supports_fragmented_frames_for_all_operations() {
    let reply = frame(json!({"ciphertext": STANDARD.encode([17;64])}));
    let (broker, server) = mock_broker(move |mut stream| {
        for chunk in reply.chunks(3) {
            stream.write_all(chunk).unwrap();
        }
    });
    assert_eq!(
        broker
            .load(Instant::now() + Duration::from_secs(2))
            .unwrap()
            .unwrap(),
        vec![17; 64]
    );
    assert_eq!(
        server.join().unwrap(),
        json!({"op":"load", "seed_id":"pool-1"})
    );
    let (broker, server) = mock_broker(|mut stream| {
        stream
            .write_all(&frame(json!({"ciphertext": STANDARD.encode([99;64])})))
            .unwrap();
    });
    assert_eq!(
        broker
            .create(&[17; 64], Instant::now() + Duration::from_secs(2))
            .unwrap(),
        vec![99; 64]
    );
    assert_eq!(
        server.join().unwrap(),
        json!({"op":"create", "seed_id":"pool-1", "ciphertext":STANDARD.encode([17;64])})
    );
    let (broker, server) = mock_broker(|mut stream| {
        stream.write_all(&frame(json!({"access_key_id":"AKID", "secret_access_key":"secret", "session_token":"token"}))).unwrap();
    });
    assert!(broker
        .credentials(Instant::now() + Duration::from_secs(2))
        .is_ok());
    assert_eq!(server.join().unwrap(), json!({"op":"credentials"}));
}

#[test]
fn broker_socket_rejects_oversized_empty_truncated_or_error_frames() {
    for reply in [
        0u32.to_be_bytes().to_vec(),
        ((MAX_MESSAGE_BYTES + 1) as u32).to_be_bytes().to_vec(),
        vec![0, 0],
        vec![0, 0, 0, 10, b'{', b'}'],
        frame(json!({"error":"s3_error"})),
        frame(json!({"ciphertext":null,"unexpected":true})),
    ] {
        let (broker, server) = mock_broker(move |mut stream| {
            stream.write_all(&reply).unwrap();
        });
        assert!(broker
            .load(Instant::now() + Duration::from_secs(2))
            .is_err());
        server.join().unwrap();
    }
}

#[test]
fn broker_error_categories_are_preserved_without_host_text_or_creation() {
    for (code, expected) in [
        ("configuration_error", CustodyFailure::Configuration),
        ("seed_id_not_allowed", CustodyFailure::Configuration),
        ("access_denied", CustodyFailure::AccessDenied),
        ("aws_unavailable", CustodyFailure::Unavailable),
        ("broker_busy", CustodyFailure::Unavailable),
        ("operation_timeout", CustodyFailure::Unavailable),
        ("request_timeout", CustodyFailure::Unavailable),
        ("invalid_ciphertext", CustodyFailure::InvalidCiphertext),
        ("internal_error", CustodyFailure::Internal),
        ("sensitive-host-text", CustodyFailure::InvalidResponse),
    ] {
        let (broker, server) = mock_broker(move |mut stream| {
            stream.write_all(&frame(json!({"error":code}))).unwrap();
        });
        let kms = Kms::default();
        let error =
            recover_seed(&broker, &kms, None, Instant::now() + Duration::from_secs(2)).unwrap_err();
        assert!(matches!(error, EnclaveError::Custody { failure, .. } if failure == expected));
        assert!(!error.to_string().contains("sensitive-host-text"));
        assert_eq!(kms.generates.get(), 0);
        assert_eq!(kms.decrypts.get(), 0);
        server.join().unwrap();
    }
}

#[test]
fn broker_deadline_bounds_prefix_and_body_trickle() {
    for trickle_prefix in [true, false] {
        let (broker, server) = mock_broker(move |mut stream| {
            let response = frame(json!({"ciphertext": STANDARD.encode([17;64])}));
            let bytes = if trickle_prefix {
                &response[..]
            } else {
                stream.write_all(&response[..4]).unwrap();
                &response[4..]
            };
            for byte in bytes {
                std::thread::sleep(Duration::from_millis(25));
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
            }
        });
        let started = Instant::now();
        assert!(broker.load(started + Duration::from_millis(70)).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }
}

#[test]
fn repeated_broker_operations_share_one_deadline() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let broker = SeedBroker {
        address: listener.local_addr().unwrap(),
        seed_id: "pool-1".into(),
    };
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).unwrap();
            std::thread::sleep(Duration::from_millis(80));
            let _ = stream.write_all(&frame(json!({"ciphertext":null})));
        }
    });
    let deadline = Instant::now() + Duration::from_millis(130);
    assert!(broker.load(deadline).unwrap().is_none());
    assert!(broker.load(deadline).is_err());
    server.join().unwrap();
}

#[test]
#[cfg(all(feature = "vsock", target_os = "linux"))]
fn vsock_connect_rejects_expired_deadline_before_opening_a_socket() {
    // This also runs on Linux hosts without the Nitro VSOCK device.
    let error = connect_vsock(BROKER_VSOCK_PORT, Instant::now()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn exhausted_recovery_budget_never_generates_or_decrypts() {
    let store = Store::default();
    let kms = Kms::default();
    assert!(recover_seed(&store, &kms, None, Instant::now()).is_err());
    assert_eq!(kms.generates.get(), 0);
    assert_eq!(kms.decrypts.get(), 0);
    assert!(store.saved.borrow().is_none());
}
