//! Persistent seed lifecycle. The parent holds only an opaque KMS ciphertext.
//! The enclave authenticates and decrypts the KMS responses.

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
use crate::kms::{deserialize_secret, AwsCredentials, KmsClient, KmsConfig, MAX_CIPHERTEXT_BYTES};
use crate::policy::KmsPin;

/// Max size of one framed broker message, in each direction.
pub(crate) const MAX_MESSAGE_BYTES: usize = 64 * 1024;

// TCP is only for non-vsock dev builds and unit tests.
#[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
type BrokerStream = TcpStream;
#[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
type BrokerStream = vsock::VsockStream;

pub const BROKER_LOCAL_PORT: u16 = 3446;
pub const BROKER_VSOCK_PORT: u32 = 8004;
// Less than the lowest request deadline in use, to leave time for ingress and
// reply. A shorter request deadline still wins.
pub const RECOVERY_TIMEOUT: Duration = Duration::from_secs(25);
pub(crate) const RESPONSE_RESERVE: Duration = Duration::from_secs(2);
// The broker's own operation deadline (`OPERATION_TIMEOUT` in the parent's
// `seed_persistence.rs`) is shorter, so it expires first.
const BROKER_TIMEOUT: Duration = Duration::from_secs(8);

fn failure(message: &str) -> EnclaveError {
    EnclaveError::InvalidRequest(format!("seed persistence: {message}"))
}

/// The seed source. Production installs a persistent source at launch. Tests
/// inject their own. This interface does not import a plaintext seed from
/// the parent. Separate dev-only handlers permit seed import.
pub trait SeedSource: Send + Sync {
    /// `deadline` bounds every external operation. The state machine checks it
    /// again before it activates the keys.
    fn load_keys(&self, network: Network, deadline: Instant) -> Result<KeyManager>;
}

trait SeedStore {
    fn load(&self, deadline: Instant) -> Result<Option<Vec<u8>>>;
    /// Create atomically if absent. Returns the blob that is persisted.
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
    // The pin decides the direction.
    // Without a pin, the launch only bootstraps: a missing object allows
    // creation, and an existing object is refused. So a parent cannot give an
    // unpinned image a planted blob.
    // With a pin, only the saved object is accepted. Nothing can replace a lost
    // pinned seed.
    let ciphertext = match (store.load(deadline)?, expected_evm_address) {
        (Some(blob), Some(_)) => {
            tracing::info!("seed custody: loading saved identity");
            blob
        }
        (Some(_), None) => {
            return Err(failure(
                "saved seed exists; an unpinned launch only bootstraps, set KMS_EXPECTED_EVM_ADDRESS to recover it",
            ))
        }
        (None, None) => {
            tracing::info!("seed custody: no saved object; attempting conditional creation");
            remaining_until(deadline)?;
            let blob = kms.generate(deadline)?;
            validate_ciphertext(&blob)?;
            remaining_until(deadline)?;
            let committed = store.create(&blob, deadline)?;
            // Activate only the blob that this call generated. A different blob
            // (a concurrent initializer or a planted one) is not decrypted.
            // Relaunch with its pin.
            if committed != blob {
                return Err(failure(
                    "another initializer committed a different seed; pin its identity and restart",
                ));
            }
            committed
        }
        (None, Some(_)) => {
            return Err(failure(
                "saved seed is missing; a pinned identity cannot be replaced",
            ))
        }
    };
    validate_ciphertext(&ciphertext)?;
    // Decrypt the persisted blob. The seed is returned only from here.
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
    /// Build the source from the KMS pin set at launch.
    pub fn new(pin: &KmsPin) -> Result<Self> {
        let config = KmsConfig {
            key_arn: pin.key_arn.clone(),
            region: pin.region.clone(),
            seed_id: pin.seed_id.clone(),
        };
        config.validate()?;
        let broker = SeedBroker {
            #[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, BROKER_LOCAL_PORT)),
            seed_id: config.seed_id.clone(),
        };
        Ok(Self {
            config,
            broker,
            expected_evm_address: pin.expected_evm_address,
        })
    }
}

impl SeedSource for PersistentSeed {
    fn load_keys(&self, network: Network, deadline: Instant) -> Result<KeyManager> {
        // Get new short-lived instance-role credentials on every attempt.
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
        // Responses can contain AWS credentials. Do not log them. The buffer
        // is zeroized after parsing.
        let mut response = Zeroizing::new(vec![0u8; length]);
        stream
            .read_exact(&mut response)
            .map_err(|_| broker_error("aws_unavailable"))?;
        // Parse the exact error shape first. Borrow the code: do not copy
        // credentials into a JSON value or relay an untrusted host message.
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
    // The field must exist: a missing field or a broker error does not prove
    // that S3 has no object.
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

// The initialization attempt owns the only broker connection. There is no
// background I/O. Nitro fixes parent CID 3. The nonblocking connect uses the
// same deadline as framing and recovery.
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
mod tests;
