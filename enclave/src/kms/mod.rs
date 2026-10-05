//! Seed custody through AWS KMS with Nitro recipient attestation.
//!
//! `aws-sdk-kms` sends `GenerateDataKey` / `Decrypt` with an NSM attestation
//! document that carries a one-shot RSA key. `recipient.rs` opens the
//! `CiphertextForRecipient` envelope.
//!
//! The plaintext seed exists only in the enclave. The parent, the proxy and S3
//! see only ciphertext. TLS to `kms.<region>.amazonaws.com` ends in the enclave,
//! against the Amazon Trust Services roots, over vsock port
//! [`DEFAULT_KMS_VSOCK_PORT`]. Errors are fixed [`CustodyFailure`] categories,
//! never service text. See `docs/kms-persistence.md` for deployment, key
//! policy and recovery.

use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, Instant};

use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region, SharedHttpClient};
use aws_sdk_kms::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{EncryptionAlgorithmSpec, KeyEncryptionMechanism, RecipientInfo};
use aws_smithy_async::rt::sleep::default_async_sleep;
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode, TlsContext, TrustStore};
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_types::retry::RetryConfig;
use aws_smithy_types::timeout::TimeoutConfig;
use bitcoin::Network;
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::attestation;
use crate::error::{CustodyFailure, EnclaveError, Result};

mod ber;
mod recipient;
#[cfg(test)]
mod tests;

/// Upper bound on the `CiphertextBlob` KMS returns for a 64-byte data key.
pub const MAX_CIPHERTEXT_BYTES: usize = 6144;
const SEED_BYTES: usize = 64;
/// Max time of one KMS round trip. A shorter caller deadline wins.
const CALL_TIMEOUT: Duration = Duration::from_secs(12);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// KMS accepts a 2048-bit RSA public key in the attestation document.
const RECIPIENT_RSA_BITS: usize = 2048;
/// KMS HTTPS port. A vsock build forwards it to the parent.
pub const KMS_PORT: u16 = 443;
/// Loopback address of the KMS forwarder. It is not `127.0.0.1`, so it does
/// not collide with an EVM RPC forwarder on `127.0.0.1:443`.
pub const KMS_LOOPBACK: std::net::Ipv4Addr = std::net::Ipv4Addr::new(127, 0, 0, 2);
/// Parent `vsock-proxy` port for KMS (`KMS_VSOCK_PORT` overrides it).
pub const DEFAULT_KMS_VSOCK_PORT: u32 = 8003;
const AMAZON_TRUST_ROOTS: &[u8] = include_bytes!("amazon_trust_roots.pem");

/// The `flow` entry of the encryption context. It is compiled into the
/// measured image. Host requests and env cannot change it.
pub const CUSTODY_FLOW: &str = "rgb-mint";

/// Public KMS config. The operator sets it once at launch (`SetEndpoints`).
/// The attested policy commits it.
#[derive(Debug, Clone)]
pub struct KmsConfig {
    pub key_arn: String,
    pub region: String,
    pub seed_id: String,
}

impl KmsConfig {
    pub fn validate(&self) -> Result<()> {
        // Commercial AWS regions only. Other partitions need their own host
        // and ARN rules.
        if !(3..=32).contains(&self.region.len())
            || !self
                .region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || self.region.starts_with('-')
            || self.region.ends_with('-')
            || self.region.starts_with("cn-")
            || self.region.starts_with("us-gov-")
            || self.region.starts_with("us-iso")
        {
            return Err(fail("KMS_REGION must be a commercial AWS region"));
        }
        let parts: Vec<_> = self.key_arn.split(':').collect();
        if parts.len() != 6
            || parts[0] != "arn"
            || parts[1] != "aws"
            || parts[2] != "kms"
            || parts[3] != self.region
            || parts[4].len() != 12
            || !parts[4].bytes().all(|b| b.is_ascii_digit())
            || !parts[5].starts_with("key/")
        {
            return Err(fail(
                "KMS_KEY_ARN must be a full key ARN in KMS_REGION (aliases are not accepted)",
            ));
        }
        let key_id = &parts[5][4..];
        let uuid = key_id.len() == 36
            && key_id.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            });
        let multi_region = key_id
            .strip_prefix("mrk-")
            .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()));
        if !uuid && !multi_region {
            return Err(fail("KMS_KEY_ARN has an invalid key identifier"));
        }
        if self.seed_id.is_empty()
            || self.seed_id.len() > 128
            || !self
                .seed_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(fail(
                "KMS_SEED_ID must be 1-128 ASCII letters, digits, dots, underscores or hyphens",
            ));
        }
        Ok(())
    }

    /// The KMS host name the SDK resolves for this region. A vsock build pins
    /// it to loopback and forwards [`KMS_PORT`] to the parent.
    pub fn endpoint_host(&self) -> String {
        endpoint_host(&self.region)
    }
}

/// `kms.<region>.amazonaws.com`, the SDK default endpoint in the commercial
/// partition.
pub fn endpoint_host(region: &str) -> String {
    format!("kms.{region}.amazonaws.com")
}

/// Temporary EC2 role credentials from the parent. They authorize the HTTPS
/// request. Only the attested enclave can open the KMS response.
/// No `Debug`, so logs never show credentials.
#[derive(Clone)]
pub struct AwsCredentials {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Zeroizing<String>,
}

impl AwsCredentials {
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
    ) -> Result<Self> {
        Self::from_protected(
            Zeroizing::new(access_key_id),
            Zeroizing::new(secret_access_key),
            Zeroizing::new(session_token),
        )
    }

    pub(crate) fn from_protected(
        access_key_id: Zeroizing<String>,
        secret_access_key: Zeroizing<String>,
        session_token: Zeroizing<String>,
    ) -> Result<Self> {
        let credentials = Self {
            access_key_id,
            secret_access_key,
            session_token,
        };
        if credentials.access_key_id.is_empty()
            || credentials.access_key_id.len() > 128
            || !credentials
                .access_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric())
            || credentials.secret_access_key.is_empty()
            || credentials.secret_access_key.len() > 256
            || !credentials
                .secret_access_key
                .bytes()
                .all(|b| b.is_ascii_graphic())
            || credentials.session_token.len() > 16 * 1024
            || !credentials
                .session_token
                .bytes()
                .all(|b| b.is_ascii_graphic())
        {
            return Err(fail("invalid AWS credentials"));
        }
        Ok(credentials)
    }

    /// The SDK credential type. It holds plain `String`s, so make it per call.
    fn to_sdk(&self) -> Credentials {
        let token = (!self.session_token.is_empty()).then(|| self.session_token.to_string());
        Credentials::new(
            self.access_key_id.as_str(),
            self.secret_access_key.as_str(),
            token,
            None,
            "enclave-parent-broker",
        )
    }
}

pub(crate) fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

pub struct KmsClient {
    config: KmsConfig,
    credentials: AwsCredentials,
    network: Network,
    /// Test HTTPS client with canned exchanges, and the fixed recipient key that
    /// opens the canned envelope.
    #[cfg(test)]
    test_transport: Option<(SharedHttpClient, RsaPrivateKey)>,
}

impl KmsClient {
    pub fn new(config: KmsConfig, credentials: AwsCredentials, network: Network) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            credentials,
            network,
            #[cfg(test)]
            test_transport: None,
        })
    }

    /// `GenerateDataKey(NumberOfBytes=64)` with recipient attestation.
    ///
    /// The seed in `CiphertextForRecipient` is opened only to check the envelope,
    /// then dropped. Returns the `CiphertextBlob`. Recover the committed seed
    /// before activation.
    ///
    /// Under `mock-attestation` the call is made without a `Recipient`: AWS KMS
    /// rejects mock CBOR docs (no COSE signature) with `ValidationException`.
    /// KMS returns the plaintext seed directly instead; we verify its length and
    /// drop it. Security is reduced (plaintext briefly on the broker) but that is
    /// acceptable in dev — there is no real NSM anyway.
    pub fn generate_ciphertext(&self, deadline: Instant) -> Result<Vec<u8>> {
        #[cfg(not(feature = "mock-attestation"))]
        // RSA key generation and NSM attestation are slow, so compute the
        // network budget after them.
        let recipient = self.recipient()?;

        let budget = call_budget(deadline)?;
        let client = self.sdk_client(budget)?;
        let key_arn = self.config.key_arn.clone();
        let context = self.encryption_context();

        #[cfg(not(feature = "mock-attestation"))]
        let output = {
            let info = recipient.info.clone();
            block_on(budget, async move {
                client
                    .generate_data_key()
                    .key_id(key_arn)
                    .number_of_bytes(SEED_BYTES as i32)
                    .set_encryption_context(Some(context))
                    .recipient(info)
                    .send()
                    .await
            })?
            .map_err(classify)?
        };

        #[cfg(feature = "mock-attestation")]
        let output = block_on(budget, async move {
            client
                .generate_data_key()
                .key_id(key_arn)
                .number_of_bytes(SEED_BYTES as i32)
                .set_encryption_context(Some(context))
                .send()
                .await
        })?
        .map_err(classify)?;

        self.check_key_id(output.key_id.as_deref())?;

        #[cfg(not(feature = "mock-attestation"))]
        {
            reject_plaintext(output.plaintext.as_ref())?;
            let seed = recipient.open(output.ciphertext_for_recipient.as_ref())?;
            drop(seed);
        }

        #[cfg(feature = "mock-attestation")]
        match output.plaintext.as_ref() {
            Some(blob) if blob.as_ref().len() == SEED_BYTES => {}
            _ => return Err(invalid("KMS plaintext absent or wrong length (mock mode)")),
        }

        let ciphertext = output
            .ciphertext_blob
            .ok_or_else(|| invalid("KMS omitted CiphertextBlob"))?
            .into_inner();
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(invalid("KMS CiphertextBlob has an invalid length"));
        }
        Ok(ciphertext)
    }

    /// `Decrypt(CiphertextBlob)` with recipient attestation; returns the seed.
    ///
    /// Under `mock-attestation` the call is made without a `Recipient` for the
    /// same reason as `generate_ciphertext`: KMS returns the plaintext directly.
    pub fn decrypt_seed(
        &self,
        ciphertext_blob: &[u8],
        deadline: Instant,
    ) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
        if ciphertext_blob.is_empty() || ciphertext_blob.len() > MAX_CIPHERTEXT_BYTES {
            return Err(fail("invalid persisted KMS ciphertext length"));
        }

        #[cfg(not(feature = "mock-attestation"))]
        // Compute the network budget after the slow recipient setup.
        let recipient = self.recipient()?;

        let budget = call_budget(deadline)?;
        let client = self.sdk_client(budget)?;
        let key_arn = self.config.key_arn.clone();
        let context = self.encryption_context();
        let blob = Blob::new(ciphertext_blob);

        #[cfg(not(feature = "mock-attestation"))]
        let output = {
            let info = recipient.info.clone();
            block_on(budget, async move {
                client
                    .decrypt()
                    .key_id(key_arn)
                    .ciphertext_blob(blob)
                    .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
                    .set_encryption_context(Some(context))
                    .recipient(info)
                    .send()
                    .await
            })?
            .map_err(classify)?
        };

        #[cfg(feature = "mock-attestation")]
        let output = block_on(budget, async move {
            client
                .decrypt()
                .key_id(key_arn)
                .ciphertext_blob(blob)
                .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
                .set_encryption_context(Some(context))
                .send()
                .await
        })?
        .map_err(classify)?;

        self.check_key_id(output.key_id.as_deref())?;

        if output.encryption_algorithm != Some(EncryptionAlgorithmSpec::SymmetricDefault) {
            return Err(invalid("KMS reported an unexpected encryption algorithm"));
        }

        #[cfg(not(feature = "mock-attestation"))]
        {
            reject_plaintext(output.plaintext.as_ref())?;
            return recipient.open(output.ciphertext_for_recipient.as_ref());
        }

        #[cfg(feature = "mock-attestation")]
        {
            let plaintext = output
                .plaintext
                .ok_or_else(|| invalid("KMS omitted plaintext (mock mode)"))?;
            let bytes = plaintext.as_ref();
            if bytes.len() != SEED_BYTES {
                return Err(invalid("KMS plaintext has unexpected length (mock mode)"));
            }
            let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
            seed.copy_from_slice(bytes);
            Ok(seed)
        }
    }

    /// The four public context entries. The key policy must require each one
    /// exactly (see docs/kms-persistence.md).
    fn encryption_context(&self) -> HashMap<String, String> {
        HashMap::from([
            (
                "application".to_string(),
                "utexo-enclave-signer".to_string(),
            ),
            ("flow".to_string(), CUSTODY_FLOW.to_string()),
            ("seed_id".to_string(), self.config.seed_id.clone()),
            ("bitcoin_network".to_string(), self.network.to_string()),
        ])
    }

    fn check_key_id(&self, key_id: Option<&str>) -> Result<()> {
        // Bind the response to the pinned key before an envelope is opened.
        if key_id != Some(self.config.key_arn.as_str()) {
            return Err(invalid("KMS answered for an unexpected key"));
        }
        Ok(())
    }

    fn recipient(&self) -> Result<Recipient> {
        #[cfg(test)]
        if let Some((_, key)) = &self.test_transport {
            return Recipient::new(key.clone());
        }
        let key = RsaPrivateKey::new(&mut rand_core::OsRng, RECIPIENT_RSA_BITS)
            .map_err(|_| custody(CustodyFailure::Internal))?;
        Recipient::new(key)
    }

    /// One SDK client per call. No retries: the persistence layer decides.
    /// `budget` bounds every timeout.
    fn sdk_client(&self, budget: Duration) -> Result<aws_sdk_kms::Client> {
        let http_client = self.http_client()?;
        let sleep = default_async_sleep().ok_or_else(|| custody(CustodyFailure::Internal))?;
        let timeouts = TimeoutConfig::builder()
            .connect_timeout(CONNECT_TIMEOUT.min(budget))
            .read_timeout(budget)
            .operation_attempt_timeout(budget)
            .operation_timeout(budget)
            .build();
        let config = aws_sdk_kms::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(self.config.region.clone()))
            .credentials_provider(self.credentials.to_sdk())
            .http_client(http_client)
            .sleep_impl(sleep)
            .retry_config(RetryConfig::disabled())
            .timeout_config(timeouts)
            .build();
        Ok(aws_sdk_kms::Client::from_conf(config))
    }

    fn http_client(&self) -> Result<SharedHttpClient> {
        #[cfg(test)]
        if let Some((client, _)) = &self.test_transport {
            return Ok(client.clone());
        }
        https_client()
    }
}

/// rustls (aws-lc) with only the Amazon Trust Services roots. The enclave
/// must not trust a system certificate store.
fn https_client() -> Result<SharedHttpClient> {
    let trust = TrustStore::empty()
        .with_native_roots(false)
        .with_pem_certificate(AMAZON_TRUST_ROOTS);
    let context = TlsContext::builder()
        .with_trust_store(trust)
        .build()
        .map_err(|_| custody(CustodyFailure::Internal))?;
    Ok(aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(CryptoMode::AwsLc))
        .tls_context(context)
        .build_https())
}

/// The one-shot recipient: an RSA private key and the attestation document
/// with its public key. Dropped with the call.
struct Recipient {
    key: RsaPrivateKey,
    info: RecipientInfo,
}

impl Recipient {
    fn new(key: RsaPrivateKey) -> Result<Self> {
        let public_key = key
            .to_public_key()
            .to_public_key_der()
            .map_err(|_| custody(CustodyFailure::Internal))?;
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| custody(CustodyFailure::Internal))?;
        let document = attestation::get_attestation(&nonce, Some(public_key.as_bytes()), None)?;
        let info = RecipientInfo::builder()
            .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
            .attestation_document(Blob::new(document))
            .build();
        Ok(Self { key, info })
    }

    /// Open `CiphertextForRecipient` and require exactly one seed.
    fn open(&self, envelope: Option<&Blob>) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
        let envelope = envelope.ok_or_else(|| invalid("KMS omitted CiphertextForRecipient"))?;
        let plaintext = recipient::open_envelope(&self.key, envelope.as_ref())?;
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        if plaintext.len() != SEED_BYTES {
            return Err(invalid(
                "KMS recipient envelope did not hold a 64-byte seed",
            ));
        }
        seed.copy_from_slice(&plaintext);
        Ok(seed)
    }
}

fn call_budget(deadline: Instant) -> Result<Duration> {
    Ok(crate::conn::remaining_until(deadline)?.min(CALL_TIMEOUT))
}

/// Run one SDK call on a private single-threaded runtime. The runtime, its
/// connection and the SDK client end with the call.
fn block_on<F, T>(budget: Duration, future: F) -> Result<T>
where
    F: Future<Output = T>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| custody(CustodyFailure::Internal))?;
    // The async block creates the timer inside the runtime.
    runtime
        .block_on(async { tokio::time::timeout(budget, future).await })
        .map_err(|_| custody(CustodyFailure::Unavailable))
}

fn reject_plaintext(plaintext: Option<&Blob>) -> Result<()> {
    // With a Recipient, KMS returns no plaintext (empty is documented).
    // Anything else means the request was not attested.
    match plaintext {
        None => Ok(()),
        Some(blob) if blob.as_ref().is_empty() => Ok(()),
        Some(_) => Err(invalid("KMS returned plaintext to an attested request")),
    }
}

/// Map an SDK failure to a fixed category. Service text is dropped. Only a
/// known error code is logged.
fn classify<E>(error: SdkError<E, HttpResponse>) -> EnclaveError
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
{
    let (failure, code) = match &error {
        SdkError::ConstructionFailure(_) => (CustodyFailure::Internal, None),
        SdkError::TimeoutError(_) => (CustodyFailure::Unavailable, None),
        SdkError::DispatchFailure(dispatch) => {
            let failure = match dispatch.as_connector_error() {
                // Only transport failures can be retried. A TLS auth failure
                // is a bad peer.
                Some(c) if c.is_timeout() || c.is_io() => CustodyFailure::Unavailable,
                Some(c) if c.is_user() => CustodyFailure::Configuration,
                _ => CustodyFailure::InvalidResponse,
            };
            (failure, None)
        }
        SdkError::ResponseError(_) => (CustodyFailure::InvalidResponse, None),
        SdkError::ServiceError(service) => {
            let code = service.err().code().map(kms_error_name);
            (
                classify_service(service.raw().status().as_u16(), code),
                code,
            )
        }
        _ => (CustodyFailure::Internal, None),
    };
    tracing::warn!(?failure, code = code.unwrap_or("-"), "KMS request failed");
    custody(failure)
}

/// The bare error name. The SDK gives `AccessDeniedException` or the wire form
/// `com.amazonaws.kms#AccessDeniedException`.
fn kms_error_name(code: &str) -> &str {
    code.rsplit('#').next().unwrap_or(code)
}

/// Classify by known status and code, never by the service message.
/// Unknown errors are invalid responses, not retryable.
fn classify_service(status: u16, code: Option<&str>) -> CustodyFailure {
    match status {
        401 | 403 => return CustodyFailure::AccessDenied,
        429 | 500..=599 => return CustodyFailure::Unavailable,
        400 => {}
        _ => return CustodyFailure::InvalidResponse,
    }
    match code {
        Some(
            "AccessDeniedException"
            | "UnrecognizedClientException"
            | "ExpiredTokenException"
            | "InvalidSignatureException",
        ) => CustodyFailure::AccessDenied,
        Some(
            "ThrottlingException"
            | "DependencyTimeoutException"
            | "KMSInternalException"
            | "KeyUnavailableException",
        ) => CustodyFailure::Unavailable,
        Some(
            "NotFoundException"
            | "DisabledException"
            | "IncorrectKeyException"
            | "InvalidCiphertextException"
            | "InvalidKeyUsageException"
            | "KMSInvalidStateException",
        ) => CustodyFailure::KeyOrCiphertext,
        Some("ValidationException" | "InvalidArnException" | "UnsupportedOperationException") => {
            CustodyFailure::Configuration
        }
        _ => CustodyFailure::InvalidResponse,
    }
}

fn custody(failure: CustodyFailure) -> EnclaveError {
    EnclaveError::Custody {
        service: "KMS",
        failure,
    }
}

fn invalid(reason: &'static str) -> EnclaveError {
    tracing::warn!(reason, "KMS response rejected");
    custody(CustodyFailure::InvalidResponse)
}

fn fail(message: impl Into<String>) -> EnclaveError {
    EnclaveError::Internal(format!("KMS custody: {}", message.into()))
}
