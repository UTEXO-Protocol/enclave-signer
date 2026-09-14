//! RGB-swap seed custody through the official AWS Nitro Enclaves SDK for C.
//!
//! The measured enclave-local helper uses the same AWS libraries as
//! kmstool_enclave_cli for HTTPS, SigV4, NSM attestation and Recipient CMS.
//! This module only validates configuration and exchanges bounded messages over
//! private subprocess pipes. Credentials and seed material never enter argv,
//! a temporary file, or logs. Signing and seed persistence remain in Rust.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{EnclaveError, Result};

const HELPER_PATH: &str = "/usr/local/bin/swap-kms-tool";
const HELPER_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_CIPHERTEXT_BYTES: usize = 6144;
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
}

#[derive(Serialize)]
struct HelperRequest<'a> {
    operation: &'a str,
    region: &'a str,
    key_arn: &'a str,
    seed_id: &'a str,
    bitcoin_network: &'a str,
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperResponse {
    key_arn: String,
    #[serde(deserialize_with = "deserialize_seed")]
    seed: Zeroizing<String>,
    ciphertext: Option<String>,
}

fn deserialize_seed<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

impl SwapKmsClient {
    pub fn new(
        config: SwapKmsConfig,
        credentials: AwsCredentials,
        network: Network,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            credentials,
            network,
        })
    }

    /// Persist the ciphertext and decrypt the committed winner before activation.
    pub fn generate_seed(&self) -> Result<GeneratedSeed> {
        let response = self.call("generate", None)?;
        let ciphertext_blob = decode_ciphertext(response.ciphertext.as_deref())?;
        let seed = decode_seed(&response.seed)?;
        Ok(GeneratedSeed {
            seed,
            ciphertext_blob,
        })
    }

    pub fn decrypt_seed(&self, ciphertext_blob: &[u8]) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
        if ciphertext_blob.is_empty() || ciphertext_blob.len() > MAX_CIPHERTEXT_BYTES {
            return Err(fail("invalid persisted KMS ciphertext length"));
        }
        let ciphertext = BASE64.encode(ciphertext_blob);
        let response = self.call("decrypt", Some(&ciphertext))?;
        if response.ciphertext.is_some() {
            return Err(fail("unexpected ciphertext in helper recovery response"));
        }
        decode_seed(&response.seed)
    }

    fn call(&self, operation: &str, ciphertext: Option<&str>) -> Result<HelperResponse> {
        let network = self.network.to_string();
        // Borrow secret strings during serialization instead of making an
        // intermediate JSON Value containing additional unprotected copies.
        let request = HelperRequest {
            operation,
            region: &self.config.region,
            key_arn: &self.config.key_arn,
            seed_id: &self.config.seed_id,
            bitcoin_network: &network,
            access_key_id: &self.credentials.access_key_id,
            secret_access_key: &self.credentials.secret_access_key,
            session_token: &self.credentials.session_token,
            ciphertext,
        };
        let request = Zeroizing::new(
            serde_json::to_vec(&request)
                .map_err(|_| fail("failed to encode SDK helper request"))?,
        );
        let bytes = run_helper(helper_command(), &request, HELPER_TIMEOUT)?;
        parse_response(&bytes, &self.config.key_arn)
    }
}

fn helper_command() -> Command {
    // Fixed path in the measured image; neither the parent nor an inherited
    // environment variable can substitute a different executable.
    let mut command = Command::new(HELPER_PATH);
    command.env_clear();
    command
}

fn run_helper(
    mut command: Command,
    request: &[u8],
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    if request.len() > MAX_MESSAGE_BYTES {
        return Err(fail("SDK helper request exceeded size limit"));
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // The SDK writes connection diagnostics to stderr. Do not relay any
        // subprocess output into application logs or wire error messages.
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| fail("cannot start the AWS Nitro SDK helper"))?;
    let mut input = child.stdin.take().expect("piped helper stdin");
    let output = child.stdout.take().expect("piped helper stdout");
    let deadline = Instant::now() + timeout;
    std::thread::scope(|scope| {
        // Separate pipes avoid deadlock even if a helper exits early or fills
        // stdout while request input is still being written.
        let writer = scope.spawn(move || input.write_all(request));
        let reader = scope.spawn(move || {
            let mut bytes = Zeroizing::new(Vec::new());
            output
                .take((MAX_MESSAGE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            Ok::<_, std::io::Error>(bytes)
        });
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => break Err(fail("AWS Nitro SDK helper timed out")),
                Err(_) => break Err(fail("failed to wait for AWS Nitro SDK helper")),
            }
        };
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let written = writer
            .join()
            .map_err(|_| fail("SDK helper input thread failed"))?;
        let received = reader
            .join()
            .map_err(|_| fail("SDK helper output thread failed"))?;
        if !status?.success() {
            return Err(fail("AWS Nitro SDK helper rejected the KMS operation"));
        }
        written.map_err(|_| fail("failed to write SDK helper request"))?;
        let bytes = received.map_err(|_| fail("failed to read SDK helper response"))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(fail("SDK helper response exceeded size limit"));
        }
        Ok(bytes)
    })
}

fn parse_response(bytes: &[u8], key_arn: &str) -> Result<HelperResponse> {
    let response: HelperResponse =
        serde_json::from_slice(bytes).map_err(|_| fail("invalid SDK helper response"))?;
    if response.key_arn != key_arn {
        return Err(fail("SDK helper returned an unexpected KMS key"));
    }
    Ok(response)
}

fn decode_seed(encoded: &str) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
    let bytes = Zeroizing::new(
        BASE64
            .decode(encoded)
            .map_err(|_| fail("invalid SDK helper seed encoding"))?,
    );
    let canonical = Zeroizing::new(BASE64.encode(bytes.as_slice()));
    if bytes.len() != SEED_BYTES || canonical.as_str() != encoded {
        return Err(fail("SDK helper returned an invalid seed"));
    }
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn decode_ciphertext(encoded: Option<&str>) -> Result<Vec<u8>> {
    let encoded = encoded.ok_or_else(|| fail("SDK helper omitted ciphertext"))?;
    if encoded.len() > MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4 {
        return Err(fail("SDK helper ciphertext exceeded size limit"));
    }
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| fail("invalid SDK helper ciphertext encoding"))?;
    if bytes.is_empty() || bytes.len() > MAX_CIPHERTEXT_BYTES || BASE64.encode(&bytes) != encoded {
        return Err(fail("invalid SDK helper ciphertext length or encoding"));
    }
    Ok(bytes)
}

fn fail(message: impl Into<String>) -> EnclaveError {
    EnclaveError::Internal(format!("RGB swap KMS: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> SwapKmsConfig {
        SwapKmsConfig {
            key_arn: "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                .into(),
            region: "eu-west-1".into(),
            seed_id: "pool-1".into(),
        }
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
        value.region = "eu-west-2".into();
        assert!(value.validate().is_err());
        value.key_arn = value.key_arn.replace("eu-west-1", "eu-west-2");
        assert!(value.validate().is_ok());
        let mut value = config();
        value.seed_id = "../other-pool".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn validates_helper_key_identity_and_seed_material() {
        let data =
            serde_json::to_vec(&json!({"key_arn":config().key_arn,"seed":BASE64.encode([42;64])}))
                .unwrap();
        let response = parse_response(&data, &config().key_arn).unwrap();
        assert_eq!(*decode_seed(&response.seed).unwrap(), [42; 64]);
        assert!(parse_response(&data, "different-key").is_err());
        assert!(decode_seed(&BASE64.encode([0; 63])).is_err());
        assert!(decode_seed("invalid-base64").is_err());
        let data = serde_json::to_vec(
            &json!({"key_arn":config().key_arn,"seed":BASE64.encode([42;64]),"debug":"secret"}),
        )
        .unwrap();
        assert!(parse_response(&data, &config().key_arn).is_err());
    }

    #[test]
    fn ciphertext_limits_are_enforced() {
        for invalid in [None, Some(""), Some("%%%")] {
            assert!(decode_ciphertext(invalid).is_err());
        }
        assert!(
            decode_ciphertext(Some(&BASE64.encode(vec![0; MAX_CIPHERTEXT_BYTES + 1]))).is_err()
        );
        assert!(decode_ciphertext(Some(&BASE64.encode(vec![0; MAX_CIPHERTEXT_BYTES]))).is_ok());
    }

    #[test]
    fn credentials_reject_control_characters() {
        assert!(
            AwsCredentials::new("AKID".into(), "secret".into(), "token\r\nforged".into()).is_err()
        );
    }

    #[cfg(unix)]
    fn fake_helper(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.env_clear().args(["-c", script]);
        command
    }

    #[test]
    #[cfg(unix)]
    fn helper_deadline_kills_and_reaps_a_stuck_process() {
        let started = Instant::now();
        let error = run_helper(
            fake_helper("exec sleep 10"),
            b"{}",
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[cfg(unix)]
    fn helper_output_and_exit_status_fail_closed() {
        assert!(run_helper(fake_helper("exit 1"), b"{}", Duration::from_secs(2)).is_err());
        let output = run_helper(
            fake_helper("cat"),
            b"{\"test\":true}",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(output.as_slice(), b"{\"test\":true}");
        assert!(run_helper(fake_helper("exec yes x"), b"{}", Duration::from_secs(2)).is_err());
        assert!(run_helper(
            fake_helper("cat"),
            &vec![0; MAX_MESSAGE_BYTES + 1],
            Duration::from_secs(2)
        )
        .is_err());
    }
}
