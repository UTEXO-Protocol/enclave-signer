//! AWS KMS seed custody for the RGB swap image.
//!
//! KMS generates a 64-byte HD seed and keeps its encrypted copy recoverable.
//! Existing key derivation and signing still run inside the enclave. A fresh
//! RSA key is bound to an NSM attestation on every KMS call; AWS returns the
//! seed in a CMS Recipient envelope, never as host-readable plaintext.
//!
//! Recipient encryption does NOT authenticate AWS: anyone who sees the public
//! key can encrypt chosen bytes to it. Therefore only this client's verified
//! HTTPS responses may reach the private CMS decoder. TLS terminates inside
//! the enclave; the parent vsock proxy only transports encrypted bytes.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bitcoin::Network;
use hmac::{Hmac, Mac};
use openssl::cms::CmsContentInfo;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::{EnclaveError, Result};

pub const LOCAL_PORT: u16 = 3445;
pub const VSOCK_PORT: u32 = 8003;
pub const MAX_CIPHERTEXT_BYTES: usize = 6144;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const SEED_BYTES: usize = 64;

/// Public configuration measured into the RGB-swap image. Never accept an
/// arbitrary KMS endpoint, key ARN or seed identifier from a host request.
#[derive(Debug, Clone)]
pub struct SwapKmsConfig {
    pub key_arn: String,
    pub region: String,
    pub seed_id: String,
}

impl SwapKmsConfig {
    pub fn from_env() -> Result<Self> {
        let read =
            |name: &str| std::env::var(name).map_err(|_| fail(format!("{name} is required")));
        let config = Self {
            key_arn: read("SWAP_KMS_KEY_ARN")?,
            region: read("SWAP_KMS_REGION")?,
            seed_id: read("SWAP_KMS_SEED_ID")?,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // Deliberately restrict endpoints to commercial AWS regions. Separate
        // partitions need their own pinned hostname/ARN validation rules.
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
            return Err(fail("SWAP_KMS_REGION must be a commercial AWS region"));
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
            return Err(fail("SWAP_KMS_KEY_ARN must be a full key ARN in SWAP_KMS_REGION (aliases are not accepted)"));
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
            return Err(fail("SWAP_KMS_KEY_ARN has an invalid key identifier"));
        }
        if self.seed_id.is_empty()
            || self.seed_id.len() > 128
            || !self
                .seed_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(fail("SWAP_KMS_SEED_ID must be 1-128 ASCII letters, digits, dots, underscores or hyphens"));
        }
        Ok(())
    }

    pub fn kms_host(&self) -> String {
        format!("kms.{}.amazonaws.com", self.region)
    }

    fn encryption_context(&self, network: Network) -> Value {
        json!({
            "application": "utexo-enclave-signer",
            "flow": "rgb-swap",
            "seed_id": self.seed_id,
            "bitcoin_network": network.to_string(),
        })
    }
}

/// Temporary EC2 role credentials can be relayed by the parent. They authorize
/// the HTTPS request; only the attested enclave can unwrap the KMS response.
/// No Debug implementation: request logging must never expose credentials.
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
        let credentials = Self {
            access_key_id: Zeroizing::new(access_key_id),
            secret_access_key: Zeroizing::new(secret_access_key),
            session_token: Zeroizing::new(session_token),
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
}

pub struct GeneratedSeed {
    pub seed: Zeroizing<[u8; SEED_BYTES]>,
    pub ciphertext_blob: Vec<u8>,
}

pub struct SwapKmsClient {
    config: SwapKmsConfig,
    credentials: AwsCredentials,
    network: Network,
    http: Client,
}

impl SwapKmsClient {
    pub fn new(
        config: SwapKmsConfig,
        credentials: AwsCredentials,
        network: Network,
    ) -> Result<Self> {
        config.validate()?;
        #[cfg(feature = "local-kms-e2e")]
        let local_port = local_e2e_port("SWAP_KMS_E2E_PORT", LOCAL_PORT)?;
        #[cfg(not(feature = "local-kms-e2e"))]
        let local_port = LOCAL_PORT;
        let http = https_client(&config.kms_host(), local_port)?;
        Ok(Self {
            config,
            credentials,
            network,
            http,
        })
    }

    /// Callers must durably persist ciphertext_blob before installing seed in
    /// active signing state. An unsuccessful/ambiguous write must not activate.
    pub fn generate_seed(&self) -> Result<GeneratedSeed> {
        let recipient = Recipient::new()?;
        let response = self.call(
            "GenerateDataKey",
            &json!({
                "KeyId": self.config.key_arn,
                "NumberOfBytes": SEED_BYTES,
                "EncryptionContext": self.config.encryption_context(self.network),
                "Recipient": recipient.request,
            }),
        )?;
        let ciphertext_blob = decode_blob(response.ciphertext_blob.as_deref(), "CiphertextBlob")?;
        let seed = self.unwrap_response(response, &recipient)?;
        Ok(GeneratedSeed {
            seed,
            ciphertext_blob,
        })
    }

    pub fn decrypt_seed(&self, ciphertext_blob: &[u8]) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
        if ciphertext_blob.is_empty() || ciphertext_blob.len() > MAX_CIPHERTEXT_BYTES {
            return Err(fail("invalid persisted KMS ciphertext length"));
        }
        let recipient = Recipient::new()?;
        let response = self.call(
            "Decrypt",
            &json!({
                "KeyId": self.config.key_arn,
                "CiphertextBlob": BASE64.encode(ciphertext_blob),
                "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "EncryptionContext": self.config.encryption_context(self.network),
                "Recipient": recipient.request,
            }),
        )?;
        if response.encryption_algorithm.as_deref() != Some("SYMMETRIC_DEFAULT") {
            return Err(fail("KMS returned an unexpected encryption algorithm"));
        }
        self.unwrap_response(response, &recipient)
    }

    fn call(&self, operation: &str, body: &Value) -> Result<KmsResponse> {
        let host = self.config.kms_host();
        let body = serde_json::to_vec(body).map_err(|_| fail("failed to serialize KMS request"))?;
        let target = format!("TrentService.{operation}");
        let headers = sigv4_headers(
            &self.credentials,
            "POST",
            "/",
            &host,
            &self.config.region,
            "kms",
            &[
                ("content-type", "application/x-amz-json-1.1"),
                ("x-amz-target", &target),
            ],
            &body,
        )?;
        let response = self
            .http
            .post(format!("https://{host}/"))
            .headers(headers)
            .body(body)
            .send()
            .map_err(|_| {
                fail("KMS HTTPS request failed (check credentials, clock and vsock proxy)")
            })?;
        let status = response.status();
        if !status.is_success() {
            // Never return response bodies, credentials or signing material in
            // error text, including for unexpected AWS/service errors.
            return Err(fail(format!(
                "KMS {operation} failed with HTTP {}",
                status.as_u16()
            )));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| fail("failed to read KMS HTTPS response"))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(fail("KMS HTTPS response exceeded size limit"));
        }
        serde_json::from_slice(&bytes).map_err(|_| fail("invalid KMS HTTPS response"))
    }

    fn unwrap_response(
        &self,
        response: KmsResponse,
        recipient: &Recipient,
    ) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
        validate_response(&response, &self.config.key_arn)?;
        let encrypted = decode_blob(
            response.ciphertext_for_recipient.as_deref(),
            "CiphertextForRecipient",
        )?;
        recipient.decrypt(&encrypted)
    }
}

fn https_client(host: &str, local_port: u16) -> Result<Client> {
    let builder = Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        // Keep the real hostname in the URL, Host header and TLS SNI.
        // There is deliberately no port in the URL: an explicit URL port
        // would override this TCP destination in reqwest.
        .resolve(host, SocketAddr::from((Ipv4Addr::LOCALHOST, local_port)));
    // The test harness issues a certificate for the pinned AWS hostname.
    // Keep certificate and hostname validation enabled, including in tests.
    #[cfg(feature = "local-kms-e2e")]
    let builder = match std::env::var_os("SWAP_KMS_E2E_CA_PEM") {
        Some(path) => {
            let pem = std::fs::read(path).map_err(|_| fail("failed to read local E2E CA"))?;
            let ca =
                reqwest::Certificate::from_pem(&pem).map_err(|_| fail("invalid local E2E CA"))?;
            builder.add_root_certificate(ca)
        }
        None => builder,
    };
    builder
        .build()
        .map_err(|_| fail("failed to construct KMS HTTPS client"))
}

#[cfg(feature = "local-kms-e2e")]
pub(crate) fn local_e2e_port(name: &str, default: u16) -> Result<u16> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(default),
        Ok(value) => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| fail(format!("{name} must be a nonzero TCP port"))),
        Err(_) => Err(fail(format!("invalid {name}"))),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KmsResponse {
    key_id: String,
    ciphertext_blob: Option<String>,
    ciphertext_for_recipient: Option<String>,
    encryption_algorithm: Option<String>,
    // Fail closed if AWS ever returns Plaintext. Keep even that unexpected
    // value zeroized after validation, instead of leaving it in a JSON Value.
    #[serde(default, deserialize_with = "deserialize_plaintext")]
    plaintext: Option<Zeroizing<String>>,
}

fn deserialize_plaintext<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

fn validate_response(response: &KmsResponse, key_arn: &str) -> Result<()> {
    if response.key_id != key_arn {
        return Err(fail("KMS returned a different key ARN"));
    }
    if response
        .plaintext
        .as_deref()
        .is_some_and(|text| !text.is_empty())
    {
        return Err(fail(
            "KMS unexpectedly returned plaintext instead of an attested Recipient envelope",
        ));
    }
    Ok(())
}

fn decode_blob(encoded: Option<&str>, name: &str) -> Result<Vec<u8>> {
    let encoded = encoded.ok_or_else(|| fail(format!("KMS response is missing {name}")))?;
    if encoded.is_empty() || encoded.len() > MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4 {
        return Err(fail(format!("invalid KMS {name} length")));
    }
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| fail(format!("invalid base64 KMS {name}")))?;
    if bytes.is_empty() || bytes.len() > MAX_CIPHERTEXT_BYTES {
        return Err(fail(format!("invalid KMS {name} length")));
    }
    Ok(bytes)
}

struct Recipient {
    private_key: PKey<Private>,
    request: Value,
}

impl Recipient {
    fn new() -> Result<Self> {
        let rsa =
            Rsa::generate(2048).map_err(|_| fail("failed to generate KMS Recipient RSA key"))?;
        let private_key =
            PKey::from_rsa(rsa).map_err(|_| fail("failed to construct KMS Recipient key"))?;
        // PKey::public_key_to_der is SubjectPublicKeyInfo (RFC 5280), as AWS
        // requires. Rsa::public_key_to_der_pkcs1 would be the wrong encoding.
        let public_key = private_key
            .public_key_to_der()
            .map_err(|_| fail("failed to encode KMS Recipient public key"))?;
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce)
            .map_err(|_| fail("failed to generate KMS attestation nonce"))?;
        #[cfg(not(feature = "local-kms-e2e"))]
        let attestation = crate::attestation::get_attestation(&nonce, Some(&public_key), None)?;
        #[cfg(feature = "local-kms-e2e")]
        let attestation = {
            // Only KMS Recipient documents use these simulated measurements;
            // ordinary public-key/peer attestation behavior remains unchanged.
            let pcr0 = std::env::var("SWAP_KMS_E2E_PCR0")
                .map_err(|_| fail("SWAP_KMS_E2E_PCR0 is required for local KMS tests"))?;
            let pcrs = attestation_verify::ExpectedPcrs::from_hex(
                &pcr0,
                &"00".repeat(48),
                &"00".repeat(48),
            )?;
            attestation_verify::build_mock_document_with_pcrs(
                &nonce,
                Some(&public_key),
                None,
                &pcrs,
            )?
        };
        Ok(Self {
            private_key,
            request: json!({
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "AttestationDocument": BASE64.encode(attestation),
            }),
        })
    }

    /// Private on purpose: no public handler accepts a host-created CMS blob.
    /// CMS is encryption, not an AWS signature; origin is proven by HTTPS.
    fn decrypt(&self, encrypted: &[u8]) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
        let cms = CmsContentInfo::from_der(encrypted)
            .map_err(|_| fail("invalid KMS Recipient CMS envelope"))?;
        // There is no X509 recipient certificate, only the NSM-bound RSA key.
        // This skips recipient-certificate matching in CMS, never server TLS
        // certificate validation. OpenSSL handles RSA OAEP and AES-256-CBC.
        let plaintext = Zeroizing::new(
            cms.decrypt_without_cert_check(&self.private_key)
                .map_err(|_| fail("failed to decrypt KMS Recipient CMS envelope"))?,
        );
        if plaintext.len() != SEED_BYTES {
            return Err(fail("KMS Recipient plaintext is not a 64-byte HD seed"));
        }
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        seed.copy_from_slice(&plaintext);
        Ok(seed)
    }
}

/// Sign the fixed, query-free AWS requests used by seed custody. Callers must
/// supply an already URI-encoded canonical path and validated AWS hostname;
/// there is no query-string, presigning, redirect or arbitrary-endpoint mode.
#[allow(clippy::too_many_arguments)]
fn sigv4_headers(
    credentials: &AwsCredentials,
    method: &str,
    canonical_path: &str,
    host: &str,
    region: &str,
    service: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Result<HeaderMap> {
    let now = OffsetDateTime::now_utc();
    let timestamp = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    sigv4_headers_at(
        credentials,
        method,
        canonical_path,
        host,
        region,
        service,
        extra_headers,
        body,
        &timestamp,
    )
}

#[allow(clippy::too_many_arguments)]
fn sigv4_headers_at(
    credentials: &AwsCredentials,
    method: &str,
    canonical_path: &str,
    host: &str,
    region: &str,
    service: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    timestamp: &str,
) -> Result<HeaderMap> {
    if !canonical_path.starts_with('/')
        || canonical_path.contains(['?', '#', '\r', '\n'])
        || timestamp.len() != 16
        || !timestamp.is_ascii()
    {
        return Err(fail("invalid fixed AWS request signing input"));
    }
    let mut canonical = BTreeMap::<String, String>::new();
    canonical.insert("host".into(), host.into());
    canonical.insert("x-amz-date".into(), timestamp.into());
    canonical.insert(
        "x-amz-content-sha256".into(),
        hex::encode(Sha256::digest(body)),
    );
    if !credentials.session_token.is_empty() {
        canonical.insert(
            "x-amz-security-token".into(),
            credentials.session_token.to_string(),
        );
    }
    for &(name, value) in extra_headers {
        let name = name.to_ascii_lowercase();
        if canonical.contains_key(&name) || name == "authorization" {
            return Err(fail("duplicate AWS signing header"));
        }
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        canonical.insert(name, value);
    }
    let signed_headers = canonical.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers = canonical
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();
    let canonical_request = Zeroizing::new(format!(
        "{method}\n{canonical_path}\n\n{canonical_headers}\n{signed_headers}\n{}",
        hex::encode(Sha256::digest(body))
    ));
    let authorization = authorization(
        credentials,
        region,
        service,
        timestamp,
        &signed_headers,
        &canonical_request,
    );
    let mut headers = HeaderMap::new();
    for (name, value) in canonical {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| fail("invalid AWS header name"))?;
        let mut header =
            HeaderValue::from_str(&value).map_err(|_| fail("invalid AWS header value"))?;
        if name == "x-amz-security-token" {
            header.set_sensitive(true);
        }
        headers.insert(name, header);
    }
    let mut auth = HeaderValue::from_str(&authorization)
        .map_err(|_| fail("invalid AWS authorization header"))?;
    auth.set_sensitive(true);
    headers.insert("authorization", auth);
    Ok(headers)
}

fn authorization(
    credentials: &AwsCredentials,
    region: &str,
    service: &str,
    timestamp: &str,
    signed_headers: &str,
    canonical_request: &str,
) -> String {
    let date = &timestamp[..8];
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let secret = Zeroizing::new(format!("AWS4{}", credentials.secret_access_key.as_str()));
    let date_key = hmac(secret.as_bytes(), date.as_bytes());
    let region_key = hmac(date_key.as_ref(), region.as_bytes());
    let service_key = hmac(region_key.as_ref(), service.as_bytes());
    let signing_key = hmac(service_key.as_ref(), b"aws4_request");
    let signature = hmac(signing_key.as_ref(), string_to_sign.as_bytes());
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={}",
        credentials.access_key_id.as_str(),
        hex::encode(&signature[..])
    )
}

fn hmac(key: &[u8], bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(bytes);
    Zeroizing::new(hmac.finalize().into_bytes().into())
}

fn fail(message: impl Into<String>) -> EnclaveError {
    EnclaveError::Internal(format!("RGB swap KMS: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::encrypt::Encrypter;
    use openssl::hash::MessageDigest;
    use openssl::rsa::Padding;
    use openssl::symm::{encrypt, Cipher};

    fn config() -> SwapKmsConfig {
        SwapKmsConfig {
            key_arn: "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                .into(),
            region: "eu-west-1".into(),
            seed_id: "pool-1".into(),
        }
    }

    fn credentials(token: &str) -> AwsCredentials {
        AwsCredentials::new(
            "AKIDEXAMPLE".into(),
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            token.into(),
        )
        .unwrap()
    }

    #[test]
    fn signature_matches_official_aws_test_vector() {
        // AWS botocore's aws4_testsuite/get-vanilla, not an expectation
        // calculated by this implementation.
        // https://github.com/boto/botocore/tree/develop/tests/unit/auth/aws4_testsuite/get-vanilla
        let canonical = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(authorization(&credentials(""), "us-east-1", "service", "20150830T123600Z", "host;x-amz-date", canonical),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    }

    #[test]
    fn signs_body_target_and_session_token() {
        let make = |body: &[u8], token: &str| {
            sigv4_headers_at(
                &credentials(token),
                "POST",
                "/",
                "kms.eu-west-1.amazonaws.com",
                "eu-west-1",
                "kms",
                &[
                    ("content-type", "application/x-amz-json-1.1"),
                    ("x-amz-target", "TrentService.GenerateDataKey"),
                ],
                body,
                "20150830T123600Z",
            )
            .unwrap()
        };
        let headers = make(b"{}", "token");
        assert!(headers["authorization"].to_str().unwrap().contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-target"));
        assert_eq!(headers["x-amz-security-token"], "token");
        assert!(headers["x-amz-security-token"].is_sensitive());
        assert!(headers["authorization"].is_sensitive());
        assert_ne!(
            headers["authorization"],
            make(b"{\"NumberOfBytes\":64}", "token")["authorization"]
        );
        assert_ne!(
            headers["authorization"],
            make(b"{}", "other")["authorization"]
        );
    }

    #[test]
    fn configuration_rejects_endpoint_injection_alias_and_wrong_region() {
        assert!(config().validate().is_ok());
        for region in [
            "eu-west-1.attacker.example/",
            "eu-west-1:443",
            "cn-north-1",
            "us-gov-west-1",
        ] {
            let mut value = config();
            value.region = region.into();
            assert!(value.validate().is_err());
        }
        let mut value = config();
        value.key_arn = value.key_arn.replace("key/", "alias/");
        assert!(value.validate().is_err());
        let mut value = config();
        value.key_arn = value.key_arn.replace("eu-west-1", "eu-west-2");
        assert!(value.validate().is_err());
        let mut value = config();
        value.seed_id = "../other-pool".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_plaintext_or_wrong_kms_key() {
        let mut response: KmsResponse =
            serde_json::from_value(json!({"KeyId":config().key_arn,"Plaintext":null})).unwrap();
        assert!(validate_response(&response, &config().key_arn).is_ok());
        response.plaintext = Some(Zeroizing::new("c2VjcmV0".into()));
        assert!(validate_response(&response, &config().key_arn).is_err());
        response.plaintext = None;
        response.key_id = "different-key".into();
        assert!(validate_response(&response, &config().key_arn).is_err());
    }

    #[test]
    fn ciphertext_limits_and_context_are_enforced() {
        assert!(decode_blob(None, "test").is_err());
        assert!(decode_blob(Some(""), "test").is_err());
        assert!(decode_blob(Some("%%%"), "test").is_err());
        assert!(decode_blob(
            Some(&BASE64.encode(vec![0; MAX_CIPHERTEXT_BYTES + 1])),
            "test"
        )
        .is_err());
        assert_ne!(
            config().encryption_context(Network::Bitcoin),
            config().encryption_context(Network::Testnet)
        );
        let mut other = config();
        other.seed_id = "pool-2".into();
        assert_ne!(
            config().encryption_context(Network::Bitcoin),
            other.encryption_context(Network::Bitcoin)
        );
    }

    #[test]
    fn credentials_reject_header_injection() {
        assert!(AwsCredentials::new(
            "AKID".into(),
            "secret".into(),
            "token\r\nx-amz-target: forged".into()
        )
        .is_err());
    }

    // A tiny test-only ASN.1 encoder builds the AWS Recipient envelope's
    // actual algorithms and subjectKeyIdentifier shape. Production uses the
    // maintained OpenSSL CMS decoder, never this helper.
    fn asn1(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        if contents.len() < 128 {
            result.push(contents.len() as u8);
        } else {
            let bytes = contents.len().to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap();
            result.push(0x80 | (bytes.len() - first) as u8);
            result.extend_from_slice(&bytes[first..]);
        }
        result.extend_from_slice(contents);
        result
    }

    fn recipient_envelope(key: &PKey<Private>, seed: &[u8], ber: bool) -> Vec<u8> {
        let aes_key = [7u8; 32];
        let iv = [9u8; 16];
        let mut encrypter = Encrypter::new(key).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        encrypter.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
        encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        let mut wrapped = vec![0; encrypter.encrypt_len(&aes_key).unwrap()];
        let length = encrypter.encrypt(&aes_key, &mut wrapped).unwrap();
        wrapped.truncate(length);

        let sha256 = asn1(
            0x30,
            &[
                asn1(
                    0x06,
                    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                ),
                vec![0x05, 0x00],
            ]
            .concat(),
        );
        let mgf1 = asn1(
            0x30,
            &[
                asn1(
                    0x06,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08],
                ),
                sha256.clone(),
            ]
            .concat(),
        );
        let oaep_parameters = asn1(0x30, &[asn1(0xa0, &sha256), asn1(0xa1, &mgf1)].concat());
        let oaep_algorithm = asn1(
            0x30,
            &[
                asn1(
                    0x06,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07],
                ),
                oaep_parameters,
            ]
            .concat(),
        );
        let recipient = asn1(
            0x30,
            &[
                vec![0x02, 0x01, 0x02],
                asn1(0x80, &[1; 20]),
                oaep_algorithm,
                asn1(0x04, &wrapped),
            ]
            .concat(),
        );
        let aes_algorithm = asn1(
            0x30,
            &[
                asn1(
                    0x06,
                    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a],
                ),
                asn1(0x04, &iv),
            ]
            .concat(),
        );
        let ciphertext = encrypt(Cipher::aes_256_cbc(), &aes_key, Some(&iv), seed).unwrap();
        let ciphertext = if ber {
            // AWS's C SDK accepts BER with indefinite constructed octets.
            [
                vec![0xa0, 0x80],
                asn1(0x04, &ciphertext[..16]),
                asn1(0x04, &ciphertext[16..]),
                vec![0, 0],
            ]
            .concat()
        } else {
            asn1(0x80, &ciphertext)
        };
        let encrypted_content = asn1(
            0x30,
            &[
                asn1(
                    0x06,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01],
                ),
                aes_algorithm,
                ciphertext,
            ]
            .concat(),
        );
        let envelope = asn1(
            0x30,
            &[
                vec![0x02, 0x01, 0x02],
                asn1(0x31, &recipient),
                encrypted_content,
            ]
            .concat(),
        );
        asn1(
            0x30,
            &[
                asn1(
                    0x06,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03],
                ),
                asn1(0xa0, &envelope),
            ]
            .concat(),
        )
    }

    #[test]
    fn decrypts_aws_recipient_algorithms_in_der_and_ber() {
        let recipient = Recipient {
            private_key: PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            request: json!({}),
        };
        for ber in [false, true] {
            let envelope = recipient_envelope(&recipient.private_key, &[42; 64], ber);
            assert_eq!(*recipient.decrypt(&envelope).unwrap(), [42; 64]);
        }
        let short = recipient_envelope(&recipient.private_key, &[42; 63], false);
        assert!(recipient.decrypt(&short).is_err());
        let wrong_key = Recipient {
            private_key: PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            request: json!({}),
        };
        let envelope = recipient_envelope(&recipient.private_key, &[42; 64], false);
        assert!(wrong_key.decrypt(&envelope).is_err());
        assert!(recipient.decrypt(b"malformed CMS").is_err());
    }

    #[test]
    fn tls_rejects_a_parent_proxy_impersonating_kms() {
        use openssl::asn1::Asn1Time;
        use openssl::ssl::{SslAcceptor, SslMethod};
        use openssl::x509::{X509NameBuilder, X509};
        use std::net::TcpListener;

        let host = config().kms_host();
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", &host).unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = cert.build();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        let acceptor = acceptor.build();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            assert!(
                acceptor.accept(stream).is_err(),
                "untrusted proxy must not finish TLS"
            );
        });
        let client = https_client(&host, port).unwrap();
        let error = client.get(format!("https://{host}/")).send().unwrap_err();
        assert!(error.is_connect(), "must reject the TLS connection");
        server.join().unwrap();
        assert!(client
            .get("http://kms.eu-west-1.amazonaws.com/")
            .send()
            .is_err());
    }
}
