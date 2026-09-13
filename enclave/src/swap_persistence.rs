//! RGB swap seed lifecycle. The parent holds only an opaque KMS ciphertext;
//! KMS responses are authenticated and decrypted inside the enclave.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::Network;
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::error::{EnclaveError, Result};
use crate::keys::KeyManager;
use crate::swap_kms::{AwsCredentials, SwapKmsClient, SwapKmsConfig};

pub const BROKER_LOCAL_PORT: u16 = 3446;
pub const BROKER_VSOCK_PORT: u32 = 8004;
const MAX_FRAME: usize = 64 * 1024;
const MAX_CIPHERTEXT: usize = 6144;
const TIMEOUT: Duration = Duration::from_secs(15);

fn failure(message: &str) -> EnclaveError {
    EnclaveError::InvalidRequest(format!("swap persistence: {message}"))
}

/// Production installs a persistent source at boot. Tests can inject a source
/// without teaching the production wire protocol to accept plaintext seeds.
pub trait SwapSeedSource: Send + Sync {
    fn load_keys(&self, network: Network) -> Result<KeyManager>;
}

trait SeedStore {
    fn load(&self) -> Result<Option<Vec<u8>>>;
    /// Atomically create if absent, then return the persisted winning blob.
    fn create(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

trait SeedKms {
    fn generate(&self) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 64]>>;
}

impl SeedKms for SwapKmsClient {
    fn generate(&self) -> Result<Vec<u8>> {
        let generated = self.generate_seed()?;
        // Even on creation, recover the committed blob through KMS. This
        // verifies recovery and handles two replicas racing to bootstrap.
        drop(generated.seed);
        Ok(generated.ciphertext_blob)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
        self.decrypt_seed(ciphertext)
    }
}

fn recover_seed(
    store: &impl SeedStore,
    kms: &impl SeedKms,
    allow_create: bool,
) -> Result<Zeroizing<[u8; 64]>> {
    let ciphertext = match store.load()? {
        Some(blob) => blob,
        None if allow_create => {
            let blob = kms.generate()?;
            validate_ciphertext(&blob)?;
            store.create(&blob)?
        }
        None => {
            return Err(failure(
                "saved seed is missing; restore never creates a new identity",
            ))
        }
    };
    validate_ciphertext(&ciphertext)?;
    kms.decrypt(&ciphertext)
}

fn validate_ciphertext(blob: &[u8]) -> Result<()> {
    if blob.is_empty() || blob.len() > MAX_CIPHERTEXT {
        return Err(failure("invalid ciphertext length"));
    }
    Ok(())
}

pub struct PersistentSwapSeed {
    config: SwapKmsConfig,
    broker: SeedBroker,
    allow_create: bool,
    expected_evm_address: Option<[u8; 20]>,
}

impl PersistentSwapSeed {
    /// These nonsecret values belong in the measured EIF configuration.
    pub fn from_env() -> Result<Self> {
        let config = SwapKmsConfig::from_env()?;
        let allow_create = match std::env::var("SWAP_KMS_ALLOW_CREATE") {
            Err(std::env::VarError::NotPresent) => false,
            Ok(value) if value == "0" => false,
            Ok(value) if value == "1" => true,
            _ => return Err(failure("SWAP_KMS_ALLOW_CREATE must be 0 or 1")),
        };
        let expected_evm_address = match std::env::var("SWAP_KMS_EXPECTED_EVM_ADDRESS") {
            Err(std::env::VarError::NotPresent) => None,
            Ok(value) if value.is_empty() => None,
            Ok(value) => Some(
                hex::decode(value.strip_prefix("0x").unwrap_or(&value))
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| failure("SWAP_KMS_EXPECTED_EVM_ADDRESS must be 20-byte hex"))?,
            ),
            Err(_) => return Err(failure("invalid expected address configuration")),
        };
        validate_mode(allow_create, expected_evm_address)?;
        let broker = SeedBroker {
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, BROKER_LOCAL_PORT)),
            seed_id: config.seed_id.clone(),
        };
        Ok(Self {
            config,
            broker,
            allow_create,
            expected_evm_address,
        })
    }
}

impl SwapSeedSource for PersistentSwapSeed {
    fn load_keys(&self, network: Network) -> Result<KeyManager> {
        // Refresh short-lived instance-role credentials on every attempt.
        let credentials = self.broker.credentials()?;
        let kms = SwapKmsClient::new(self.config.clone(), credentials, network)?;
        let seed = recover_seed(&self.broker, &kms, self.allow_create)?;
        restore_keys(seed, network, self.expected_evm_address)
    }
}

fn validate_mode(allow_create: bool, expected: Option<[u8; 20]>) -> Result<()> {
    // Never regenerate an identity whose ciphertext was lost, and never let an
    // untrusted storage relay substitute a different valid same-context blob.
    match (allow_create, expected) {
        (true, Some(_)) => Err(failure(
            "bootstrap cannot be combined with an expected existing address",
        )),
        (false, None) => Err(failure(
            "restore requires SWAP_KMS_EXPECTED_EVM_ADDRESS to pin the saved identity",
        )),
        _ => Ok(()),
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
    address: SocketAddr,
    seed_id: String,
}

impl SeedBroker {
    fn request<T: serde::de::DeserializeOwned>(&self, request: serde_json::Value) -> Result<T> {
        let mut stream = TcpStream::connect_timeout(&self.address, TIMEOUT)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let bytes = serde_json::to_vec(&request).map_err(|_| failure("encode broker request"))?;
        if bytes.len() > MAX_FRAME {
            return Err(failure("broker request too large"));
        }
        stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
        stream.write_all(&bytes)?;
        let mut length = [0u8; 4];
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(failure("invalid broker response length"));
        }
        // Responses may contain AWS credentials. Avoid Debug/logging and
        // erase the original JSON buffer as soon as typed parsing finishes.
        let mut response = Zeroizing::new(vec![0u8; length]);
        stream.read_exact(&mut response)?;
        serde_json::from_slice(&response)
            .map_err(|_| failure("broker request failed or response invalid"))
    }

    fn credentials(&self) -> Result<AwsCredentials> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Credentials {
            access_key_id: String,
            secret_access_key: String,
            session_token: String,
        }
        let c: Credentials = self.request(json!({"op": "credentials"}))?;
        AwsCredentials::new(c.access_key_id, c.secret_access_key, c.session_token)
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
    fn load(&self) -> Result<Option<Vec<u8>>> {
        decode_blob(self.request(json!({"op": "load", "seed_id": self.seed_id}))?)
    }

    fn create(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        validate_ciphertext(ciphertext)?;
        decode_blob(self.request(json!({
            "op": "create", "seed_id": self.seed_id, "ciphertext": STANDARD.encode(ciphertext),
        }))?)?
        .ok_or_else(|| failure("broker did not return a committed seed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[derive(Default)]
    struct Store {
        saved: RefCell<Option<Vec<u8>>>,
        fail_read: Cell<bool>,
        fail_write: Cell<bool>,
        race_winner: Option<Vec<u8>>,
    }
    impl SeedStore for Store {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            if self.fail_read.get() {
                return Err(failure("read failed"));
            }
            Ok(self.saved.borrow().clone())
        }
        fn create(&self, blob: &[u8]) -> Result<Vec<u8>> {
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
        fn generate(&self) -> Result<Vec<u8>> {
            self.generates.set(self.generates.get() + 1);
            Ok(vec![42; 64]) // Opaque ciphertext stand-in; never a production backend.
        }
        fn decrypt(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
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
    fn restore_requires_an_identity_pin_and_bootstrap_forbids_one() {
        assert!(validate_mode(false, None).is_err());
        assert!(validate_mode(true, Some([1; 20])).is_err());
        assert!(validate_mode(true, None).is_ok());
        assert!(validate_mode(false, Some([1; 20])).is_ok());
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
        let first = recover_seed(&store, &kms, true).unwrap();
        let restored = recover_seed(&store, &kms, false).unwrap();
        let replica = recover_seed(&store, &kms, false).unwrap();
        assert_eq!(*first, *restored);
        assert_eq!(*first, *replica);
        assert_eq!(kms.generates.get(), 1);
        let a = KeyManager::from_seed(*first, Network::Bitcoin).unwrap();
        let b = KeyManager::from_seed(*restored, Network::Bitcoin).unwrap();
        assert_eq!(a.evm_address(), b.evm_address());
        assert_eq!(a.account_xpub_colored(), b.account_xpub_colored());
        assert_eq!(a.sign_evm(&[7; 32]).unwrap(), b.sign_evm(&[7; 32]).unwrap());
    }

    #[test]
    fn restore_never_regenerates_missing_or_unreadable_seed() {
        let store = Store::default();
        let kms = Kms::default();
        assert!(recover_seed(&store, &kms, false).is_err());
        store.fail_read.set(true);
        assert!(recover_seed(&store, &kms, true).is_err());
        assert_eq!(kms.generates.get(), 0);
        assert_eq!(kms.decrypts.get(), 0);
    }

    #[test]
    fn failed_persistence_never_recovers_or_activates_generated_key() {
        let store = Store {
            fail_write: Cell::new(true),
            ..Store::default()
        };
        let kms = Kms::default();
        assert!(recover_seed(&store, &kms, true).is_err());
        assert_eq!(kms.decrypts.get(), 0);
        assert!(store.saved.borrow().is_none());
    }

    #[test]
    fn concurrent_bootstrap_recovers_the_committed_winner() {
        let store = Store {
            race_winner: Some(vec![17; 64]),
            ..Store::default()
        };
        let seed = recover_seed(&store, &Kms::default(), true).unwrap();
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
        assert!(recover_seed(&store, &kms, true).is_err());
        assert_eq!(kms.generates.get(), 0);
        *store.saved.borrow_mut() = Some(vec![]);
        assert!(recover_seed(&store, &kms, true).is_err());
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
}
