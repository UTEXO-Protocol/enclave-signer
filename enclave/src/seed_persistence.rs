//! Persistent seed lifecycle. The parent holds only an opaque KMS ciphertext;
//! KMS responses are authenticated and decrypted inside the enclave.

use std::io::{self, Read, Write};
#[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::Network;
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::conn::{remaining_until, DeadlineStream};
use crate::error::{CustodyFailure, EnclaveError, Result};
use crate::keys::KeyManager;
use crate::kms::{
    deserialize_secret, AwsCredentials, CustodyFlow, KmsClient, KmsConfig, MAX_CIPHERTEXT_BYTES,
    MAX_MESSAGE_BYTES,
};

// TCP is only used by non-VSOCK development builds and unit fixtures.
#[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
type BrokerStream = TcpStream;
#[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
type BrokerStream = vsock::VsockStream;

pub const BROKER_LOCAL_PORT: u16 = 3446;
pub const BROKER_VSOCK_PORT: u32 = 8004;
// Leave room inside the 30-second parent/request timeout for ingress and reply.
pub const RECOVERY_TIMEOUT: Duration = Duration::from_secs(25);
pub(crate) const RESPONSE_RESERVE: Duration = Duration::from_secs(2);
// The broker's own seven-second operation deadline expires before this cap.
const BROKER_TIMEOUT: Duration = Duration::from_secs(8);

fn failure(message: &str) -> EnclaveError {
    EnclaveError::InvalidRequest(format!("seed persistence: {message}"))
}

/// Production installs a persistent source at boot. Tests can inject a source
/// without teaching the production wire protocol to accept plaintext seeds.
pub trait SeedSource: Send + Sync {
    /// Bound every external operation by this same absolute deadline. The state
    /// machine also checks it immediately before activating the returned keys.
    fn load_keys(&self, network: Network, deadline: Instant) -> Result<KeyManager>;
}

trait SeedStore {
    fn load(&self, deadline: Instant) -> Result<Option<Vec<u8>>>;
    /// Atomically create if absent, then return the persisted winning blob.
    fn create(&self, ciphertext: &[u8], deadline: Instant) -> Result<Vec<u8>>;
}

trait SeedKms {
    fn generate(&self, deadline: Instant) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], deadline: Instant) -> Result<Zeroizing<[u8; 64]>>;
}

impl SeedKms for KmsClient {
    fn generate(&self, deadline: Instant) -> Result<Vec<u8>> {
        self.generate_ciphertext(deadline)
    }

    fn decrypt(&self, ciphertext: &[u8], deadline: Instant) -> Result<Zeroizing<[u8; 64]>> {
        self.decrypt_seed(ciphertext, deadline)
    }
}

fn recover_seed(
    store: &impl SeedStore,
    kms: &impl SeedKms,
    expected_evm_address: Option<[u8; 20]>,
    deadline: Instant,
) -> Result<Zeroizing<[u8; 64]>> {
    remaining_until(deadline)?;
    // Only an explicit missing-object response permits first-use creation.
    // An expected identity makes missing ciphertext a recovery failure, so
    // neither KMS generation nor persistence can replace a lost pinned seed.
    let ciphertext = match store.load(deadline)? {
        Some(blob) => {
            tracing::info!("seed custody: loading saved identity");
            blob
        }
        None if expected_evm_address.is_none() => {
            tracing::info!("seed custody: no saved object; attempting conditional creation");
            remaining_until(deadline)?;
            let blob = kms.generate(deadline)?;
            validate_ciphertext(&blob)?;
            remaining_until(deadline)?;
            store.create(&blob, deadline)?
        }
        None => {
            return Err(failure(
                "saved seed is missing; a pinned identity cannot be replaced",
            ))
        }
    };
    validate_ciphertext(&ciphertext)?;
    // This is the only step that returns plaintext to Rust: recover the blob
    // returned by persistence, including the winner of concurrent bootstrap.
    remaining_until(deadline)?;
    let seed = kms.decrypt(&ciphertext, deadline)?;
    remaining_until(deadline)?;
    Ok(seed)
}

fn validate_ciphertext(blob: &[u8]) -> Result<()> {
    if blob.is_empty() || blob.len() > MAX_CIPHERTEXT_BYTES {
        return Err(failure("invalid ciphertext length"));
    }
    Ok(())
}

pub struct PersistentSeed {
    config: KmsConfig,
    broker: SeedBroker,
    expected_evm_address: Option<[u8; 20]>,
}

impl PersistentSeed {
    /// These nonsecret values belong in the measured EIF configuration.
    pub fn from_env(flow: CustodyFlow) -> Result<Self> {
        let config = KmsConfig::from_env(flow)?;
        let expected_evm_address = match std::env::var("KMS_EXPECTED_EVM_ADDRESS") {
            Err(std::env::VarError::NotPresent) => None,
            Ok(value) if value.is_empty() => None,
            Ok(value) => Some(
                hex::decode(value.strip_prefix("0x").unwrap_or(&value))
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| failure("KMS_EXPECTED_EVM_ADDRESS must be 20-byte hex"))?,
            ),
            Err(_) => return Err(failure("invalid expected address configuration")),
        };
        let broker = SeedBroker {
            #[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, BROKER_LOCAL_PORT)),
            seed_id: config.seed_id.clone(),
        };
        Ok(Self {
            config,
            broker,
            expected_evm_address,
        })
    }
}

impl SeedSource for PersistentSeed {
    fn load_keys(&self, network: Network, deadline: Instant) -> Result<KeyManager> {
        // Refresh short-lived instance-role credentials on every attempt.
        let credentials = self.broker.credentials(deadline)?;
        let kms = KmsClient::new(self.config.clone(), credentials, network)?;
        let seed = recover_seed(&self.broker, &kms, self.expected_evm_address, deadline)?;
        restore_keys(seed, network, self.expected_evm_address)
    }
}

fn restore_keys(
    seed: Zeroizing<[u8; 64]>,
    network: Network,
    expected: Option<[u8; 20]>,
) -> Result<KeyManager> {
    let manager = KeyManager::from_seed(*seed, network)?;
    if expected.is_some_and(|address| *manager.evm_address() != address) {
        return Err(EnclaveError::IdentityMismatch);
    }
    Ok(manager)
}

struct SeedBroker {
    #[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
    address: SocketAddr,
    seed_id: String,
}

impl SeedBroker {
    fn connect(&self, deadline: Instant) -> io::Result<BrokerStream> {
        #[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
        {
            connect_vsock(BROKER_VSOCK_PORT, deadline)
        }
        #[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
        {
            TcpStream::connect_timeout(&self.address, remaining_until(deadline)?)
        }
    }

    fn request<T: serde::de::DeserializeOwned>(
        &self,
        request: serde_json::Value,
        deadline: Instant,
    ) -> Result<T> {
        let deadline = deadline.min(Instant::now() + BROKER_TIMEOUT);
        remaining_until(deadline).map_err(|_| broker_error("operation_timeout"))?;
        let stream = self
            .connect(deadline)
            .map_err(|_| broker_error("aws_unavailable"))?;
        let mut stream = DeadlineStream::with_deadline(stream, deadline, BROKER_TIMEOUT);
        let bytes = serde_json::to_vec(&request).map_err(|_| failure("encode broker request"))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(failure("broker request too large"));
        }
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .map_err(|_| broker_error("aws_unavailable"))?;
        stream
            .write_all(&bytes)
            .map_err(|_| broker_error("aws_unavailable"))?;
        let mut length = [0u8; 4];
        stream
            .read_exact(&mut length)
            .map_err(|_| broker_error("aws_unavailable"))?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_MESSAGE_BYTES {
            return Err(broker_error("invalid_response"));
        }
        // Responses may contain AWS credentials. Avoid Debug/logging and
        // erase the original JSON buffer as soon as typed parsing finishes.
        let mut response = Zeroizing::new(vec![0u8; length]);
        stream
            .read_exact(&mut response)
            .map_err(|_| broker_error("aws_unavailable"))?;
        // Parse only a bounded, exact error envelope before the typed success
        // response. Borrow the code directly; do not copy credential fields into
        // an intermediate JSON value or relay an untrusted host message.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BrokerFailure<'a> {
            error: &'a str,
        }
        if let Ok(error) = serde_json::from_slice::<BrokerFailure<'_>>(&response) {
            return Err(broker_error(error.error));
        }
        serde_json::from_slice(&response).map_err(|_| broker_error("invalid_response"))
    }

    fn credentials(&self, deadline: Instant) -> Result<AwsCredentials> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Credentials {
            #[serde(deserialize_with = "deserialize_secret")]
            access_key_id: Zeroizing<String>,
            #[serde(deserialize_with = "deserialize_secret")]
            secret_access_key: Zeroizing<String>,
            #[serde(deserialize_with = "deserialize_secret")]
            session_token: Zeroizing<String>,
        }
        let c: Credentials = self.request(json!({"op": "credentials"}), deadline)?;
        AwsCredentials::from_protected(c.access_key_id, c.secret_access_key, c.session_token)
    }
}

fn broker_error(code: &str) -> EnclaveError {
    let failure = match code {
        "configuration_error" | "seed_id_not_allowed" => CustodyFailure::Configuration,
        "access_denied" => CustodyFailure::AccessDenied,
        "aws_unavailable" | "broker_busy" | "operation_timeout" | "request_timeout" => {
            CustodyFailure::Unavailable
        }
        "invalid_ciphertext" => CustodyFailure::InvalidCiphertext,
        "internal_error" => CustodyFailure::Internal,
        _ => CustodyFailure::InvalidResponse,
    };
    EnclaveError::Custody {
        service: "seed broker",
        failure,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobResponse {
    // Value deliberately requires the field to exist: a missing property or
    // a broker error is not proof that S3 has no object.
    ciphertext: serde_json::Value,
}

fn decode_blob(response: BlobResponse) -> Result<Option<Vec<u8>>> {
    if response.ciphertext.is_null() {
        return Ok(None);
    }
    let encoded = response
        .ciphertext
        .as_str()
        .ok_or_else(|| failure("invalid ciphertext encoding"))?;
    let blob = STANDARD
        .decode(encoded)
        .map_err(|_| failure("invalid ciphertext encoding"))?;
    validate_ciphertext(&blob)?;
    Ok(Some(blob))
}

impl SeedStore for SeedBroker {
    fn load(&self, deadline: Instant) -> Result<Option<Vec<u8>>> {
        decode_blob(self.request(json!({"op": "load", "seed_id": self.seed_id}), deadline)?)
    }

    fn create(&self, ciphertext: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        validate_ciphertext(ciphertext)?;
        decode_blob(self.request(
            json!({
                "op": "create", "seed_id": self.seed_id, "ciphertext": STANDARD.encode(ciphertext),
            }),
            deadline,
        )?)?
        .ok_or_else(|| failure("broker did not return a committed seed"))
    }
}

// The only broker connection is owned by the initialization attempt: there is
// no background relay or detached I/O. Parent CID 3 is fixed by Nitro, and the
// nonblocking connect consumes the same deadline as framing and recovery.
#[cfg(all(feature = "vsock", target_os = "linux"))]
fn connect_vsock(port: u32, deadline: Instant) -> io::Result<vsock::VsockStream> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
    use std::os::fd::{AsFd, AsRawFd};
    remaining_until(deadline)?;
    let socket = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    remaining_until(deadline)?;
    match connect(socket.as_raw_fd(), &VsockAddr::new(3, port)) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINPROGRESS) => loop {
            let millis = remaining_until(deadline)?
                .as_millis()
                .clamp(1, i32::MAX as u128);
            let timeout = PollTimeout::try_from(millis).map_err(io::Error::other)?;
            let mut fds = [PollFd::new(socket.as_fd(), PollFlags::POLLOUT)];
            let ready = match poll(&mut fds, timeout) {
                Ok(ready) => ready,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(error.into()),
            };
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "vsock connect timed out",
                ));
            }
            let error =
                nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::SocketError)?;
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            if !fds[0]
                .revents()
                .is_some_and(|events| events.contains(PollFlags::POLLOUT))
            {
                return Err(io::Error::other("vsock connect did not complete"));
            }
            break;
        },
        Err(error) => return Err(error.into()),
    }
    remaining_until(deadline)?;
    let stream = vsock::VsockStream::from(socket);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
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
            let winner = saved
                .get_or_insert_with(|| self.race_winner.clone().unwrap_or_else(|| blob.to_vec()));
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
            Ok(vec![42; 64]) // Opaque ciphertext stand-in; never a production backend.
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
        let restored = recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).unwrap();
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
    fn existing_ciphertext_is_reused_with_or_without_a_pin() {
        let original = vec![42; 64];
        let store = Store {
            saved: RefCell::new(Some(original.clone())),
            ..Store::default()
        };
        let kms = Kms::default();
        let expected = *KeyManager::from_seed([42; 64], Network::Bitcoin)
            .unwrap()
            .evm_address();
        for pin in [None, Some(expected), Some([1; 20])] {
            let seed = recover_seed(&store, &kms, pin, Instant::now() + RECOVERY_TIMEOUT).unwrap();
            let keys = restore_keys(seed, Network::Bitcoin, pin);
            if pin == Some([1; 20]) {
                assert!(matches!(keys, Err(EnclaveError::IdentityMismatch)));
            } else {
                assert_eq!(*keys.unwrap().evm_address(), expected);
            }
        }
        assert_eq!(kms.generates.get(), 0);
        assert_eq!(kms.decrypts.get(), 3);
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
    fn concurrent_bootstrap_recovers_the_committed_winner() {
        let store = Store {
            race_winner: Some(vec![17; 64]),
            ..Store::default()
        };
        let seed = recover_seed(
            &store,
            &Kms::default(),
            None,
            Instant::now() + RECOVERY_TIMEOUT,
        )
        .unwrap();
        assert_eq!(*seed, [17; 64]);
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
        assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
        assert_eq!(kms.generates.get(), 0);
        *store.saved.borrow_mut() = Some(vec![]);
        assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
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
            let error = recover_seed(&broker, &kms, None, Instant::now() + Duration::from_secs(2))
                .unwrap_err();
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
}
