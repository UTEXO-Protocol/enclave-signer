//! Seed custody through the official AWS Nitro Enclaves SDK for C.
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

use crate::error::{CustodyFailure, EnclaveError, Result};

const HELPER_PATH: &str = "/usr/local/bin/kms-tool";
const HELPER_TIMEOUT: Duration = Duration::from_secs(12);
pub(crate) const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_CIPHERTEXT_BYTES: usize = 6144;
const SEED_BYTES: usize = 64;

/// Application-selected custody domain, compiled into the measured image.
/// Add a distinct domain when another signing flow adopts KMS persistence;
/// existing ciphertext must keep its original context value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyFlow {
    RgbSwap,
}

impl CustodyFlow {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RgbSwap => "rgb-swap",
        }
    }
}

/// Public configuration measured into the enclave image. Never accept an
/// arbitrary KMS endpoint, key ARN or seed identifier from a host request.
#[derive(Debug, Clone)]
pub struct KmsConfig {
    pub flow: CustodyFlow,
    pub key_arn: String,
    pub region: String,
    pub seed_id: String,
}

impl KmsConfig {
    pub fn from_env(flow: CustodyFlow) -> Result<Self> {
        let read =
            |name: &str| std::env::var(name).map_err(|_| fail(format!("{name} is required")));
        let config = Self {
            flow,
            key_arn: read("KMS_KEY_ARN")?,
            region: read("KMS_REGION")?,
            seed_id: read("KMS_SEED_ID")?,
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
}

pub struct KmsClient {
    config: KmsConfig,
    credentials: AwsCredentials,
    network: Network,
}

#[derive(Serialize)]
struct HelperRequest<'a> {
    operation: &'a str,
    flow: &'a str,
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
struct GenerateResponse {
    key_arn: String,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecryptResponse {
    key_arn: String,
    #[serde(deserialize_with = "deserialize_secret")]
    seed: Zeroizing<String>,
}

pub(crate) fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

impl KmsClient {
    pub fn new(config: KmsConfig, credentials: AwsCredentials, network: Network) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            credentials,
            network,
        })
    }

    /// The helper validates and erases the generated seed, returning only the
    /// ciphertext. Recover the committed winner separately before activation.
    pub fn generate_ciphertext(&self, deadline: Instant) -> Result<Vec<u8>> {
        let bytes = self.call("generate", None, deadline)?;
        parse_generate_response(&bytes, &self.config.key_arn)
    }

    pub fn decrypt_seed(
        &self,
        ciphertext_blob: &[u8],
        deadline: Instant,
    ) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
        if ciphertext_blob.is_empty() || ciphertext_blob.len() > MAX_CIPHERTEXT_BYTES {
            return Err(fail("invalid persisted KMS ciphertext length"));
        }
        let ciphertext = BASE64.encode(ciphertext_blob);
        let bytes = self.call("decrypt", Some(&ciphertext), deadline)?;
        parse_decrypt_response(&bytes, &self.config.key_arn)
    }

    fn call(
        &self,
        operation: &str,
        ciphertext: Option<&str>,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let network = self.network.to_string();
        // Borrow secret strings during serialization instead of making an
        // intermediate JSON Value containing additional unprotected copies.
        let request = HelperRequest {
            operation,
            flow: self.config.flow.as_str(),
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
        run_helper(
            helper_command(),
            &request,
            deadline.min(Instant::now() + HELPER_TIMEOUT),
        )
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
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>> {
    crate::conn::remaining_until(deadline)?;
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
        .map_err(|_| helper_failure(CustodyFailure::Configuration))?;
    let mut input = child.stdin.take().expect("piped helper stdin");
    let output = child.stdout.take().expect("piped helper stdout");
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
            if Instant::now() >= deadline {
                break Err(helper_failure(CustodyFailure::Unavailable));
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {
                    std::thread::sleep(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_millis(10)),
                    );
                }
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
        let status = status?;
        if !status.success() {
            return Err(helper_status_failure(status));
        }
        written.map_err(|_| fail("failed to write SDK helper request"))?;
        let bytes = received.map_err(|_| fail("failed to read SDK helper response"))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(fail("SDK helper response exceeded size limit"));
        }
        Ok(bytes)
    })
}

fn helper_failure(failure: CustodyFailure) -> EnclaveError {
    EnclaveError::Custody {
        service: "KMS helper",
        failure,
    }
}

fn helper_status_failure(status: std::process::ExitStatus) -> EnclaveError {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        // The helper's independent alarm is also a timeout, even if it wins
        // the race against the enclosing Rust deadline.
        // SIGALRM is 14 on the Linux helper target and macOS test host.
        if status.signal() == Some(14) {
            return helper_failure(CustodyFailure::Unavailable);
        }
    }
    helper_exit_failure(status.code())
}

fn helper_exit_failure(code: Option<i32>) -> EnclaveError {
    // The measured helper emits only these fixed categories, never AWS text.
    // Unknown exit codes and signal termination are not assumed retryable.
    let failure = match code {
        Some(64) => CustodyFailure::Configuration,
        Some(78) => CustodyFailure::KeyOrCiphertext,
        Some(65) => CustodyFailure::InvalidResponse,
        Some(69 | 75) => CustodyFailure::Unavailable,
        Some(77) => CustodyFailure::AccessDenied,
        _ => CustodyFailure::Internal,
    };
    helper_failure(failure)
}

fn parse_generate_response(bytes: &[u8], key_arn: &str) -> Result<Vec<u8>> {
    let response: GenerateResponse =
        serde_json::from_slice(bytes).map_err(|_| fail("invalid SDK helper response"))?;
    if response.key_arn != key_arn {
        return Err(fail("SDK helper returned an unexpected KMS key"));
    }
    decode_ciphertext(&response.ciphertext)
}

fn parse_decrypt_response(bytes: &[u8], key_arn: &str) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
    let response: DecryptResponse =
        serde_json::from_slice(bytes).map_err(|_| fail("invalid SDK helper response"))?;
    if response.key_arn != key_arn {
        return Err(fail("SDK helper returned an unexpected KMS key"));
    }
    decode_seed(&response.seed)
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

fn decode_ciphertext(encoded: &str) -> Result<Vec<u8>> {
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
    EnclaveError::Internal(format!("KMS custody: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> KmsConfig {
        KmsConfig {
            flow: CustodyFlow::RgbSwap,
            key_arn: "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                .into(),
            region: "eu-west-1".into(),
            seed_id: "pool-1".into(),
        }
    }

    #[test]
    fn bitcoin_network_names_fit_the_official_helper_contract() {
        for network in [
            Network::Bitcoin,
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            let name = network.to_string();
            assert!((1..=8).contains(&name.len()));
            assert!(name.bytes().all(|b| b.is_ascii_graphic()));
        }
    }

    #[test]
    #[cfg(unix)]
    fn expired_helper_deadline_never_spawns_a_process() {
        // If a process were started, spawning this nonexistent executable
        // would return a different error instead of the deadline error.
        let error = run_helper(
            Command::new("/nonexistent/expired-helper"),
            b"{}",
            Instant::now(),
        )
        .unwrap_err();
        assert!(
            matches!(error, EnclaveError::Io(ref e) if e.kind() == std::io::ErrorKind::TimedOut)
        );
    }

    #[test]
    #[cfg(unix)]
    fn helper_exit_diagnostics_are_fixed_and_do_not_expose_output() {
        for (code, expected) in [
            (64, CustodyFailure::Configuration),
            (65, CustodyFailure::InvalidResponse),
            (69, CustodyFailure::Unavailable),
            (70, CustodyFailure::Internal),
            (75, CustodyFailure::Unavailable),
            (77, CustodyFailure::AccessDenied),
            (78, CustodyFailure::KeyOrCiphertext),
            (1, CustodyFailure::Internal),
        ] {
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                &format!("printf sensitive-output; printf sensitive-error >&2; exit {code}"),
            ]);
            let error =
                run_helper(command, b"{}", Instant::now() + Duration::from_secs(2)).unwrap_err();
            assert!(matches!(error, EnclaveError::Custody { failure, .. } if failure == expected));
            assert!(!error.to_string().contains("sensitive"));
            assert_eq!(
                error.error_code(),
                if expected == CustodyFailure::Unavailable {
                    2
                } else {
                    1
                }
            );
        }
        assert!(matches!(
            helper_exit_failure(None),
            EnclaveError::Custody {
                failure: CustodyFailure::Internal,
                ..
            }
        ));
    }

    #[test]
    #[cfg(unix)]
    fn helper_alarm_is_reported_as_retryable_timeout() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "kill -ALRM $$"]);
        let error =
            run_helper(command, b"{}", Instant::now() + Duration::from_secs(2)).unwrap_err();
        assert!(matches!(
            error,
            EnclaveError::Custody {
                failure: CustodyFailure::Unavailable,
                ..
            }
        ));
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
    fn generation_accepts_only_ciphertext_for_the_expected_key() {
        let data = serde_json::to_vec(
            &json!({"key_arn":config().key_arn,"ciphertext":BASE64.encode([17;64])}),
        )
        .unwrap();
        assert_eq!(
            parse_generate_response(&data, &config().key_arn).unwrap(),
            [17; 64]
        );
        assert!(parse_generate_response(&data, "different-key").is_err());
        for value in [
            json!({"key_arn":config().key_arn}),
            json!({"key_arn":config().key_arn,"ciphertext":null}),
            json!({"key_arn":config().key_arn,"ciphertext":BASE64.encode([17;64]),"seed":BASE64.encode([42;64])}),
            json!({"key_arn":config().key_arn,"ciphertext":BASE64.encode([17;64]),"seed":null}),
        ] {
            assert!(parse_generate_response(
                &serde_json::to_vec(&value).unwrap(),
                &config().key_arn
            )
            .is_err());
        }
    }

    #[test]
    fn decryption_accepts_only_seed_material_for_the_expected_key() {
        let data =
            serde_json::to_vec(&json!({"key_arn":config().key_arn,"seed":BASE64.encode([42;64])}))
                .unwrap();
        assert_eq!(
            *parse_decrypt_response(&data, &config().key_arn).unwrap(),
            [42; 64]
        );
        assert!(parse_decrypt_response(&data, "different-key").is_err());
        assert!(decode_seed(&BASE64.encode([0; 63])).is_err());
        assert!(decode_seed("invalid-base64").is_err());
        for value in [
            json!({"key_arn":config().key_arn,"seed":BASE64.encode([42;64]),"debug":"secret"}),
            json!({"key_arn":config().key_arn,"seed":BASE64.encode([42;64]),"ciphertext":BASE64.encode([17;64])}),
            json!({"key_arn":config().key_arn,"seed":BASE64.encode([42;64]),"ciphertext":null}),
            json!({"key_arn":config().key_arn,"ciphertext":BASE64.encode([17;64])}),
        ] {
            assert!(parse_decrypt_response(
                &serde_json::to_vec(&value).unwrap(),
                &config().key_arn
            )
            .is_err());
        }
    }

    #[test]
    fn ciphertext_limits_are_enforced() {
        for invalid in ["", "%%%"] {
            assert!(decode_ciphertext(invalid).is_err());
        }
        assert!(decode_ciphertext(&BASE64.encode(vec![0; MAX_CIPHERTEXT_BYTES + 1])).is_err());
        assert!(decode_ciphertext(&BASE64.encode(vec![0; MAX_CIPHERTEXT_BYTES])).is_ok());
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
            Instant::now() + Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            EnclaveError::Custody {
                failure: CustodyFailure::Unavailable,
                ..
            }
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[cfg(unix)]
    fn helper_output_and_exit_status_fail_closed() {
        assert!(run_helper(
            fake_helper("exit 1"),
            b"{}",
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
        let output = run_helper(
            fake_helper("cat"),
            b"{\"test\":true}",
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(output.as_slice(), b"{\"test\":true}");
        assert!(run_helper(
            fake_helper("exec yes x"),
            b"{}",
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
        assert!(run_helper(
            fake_helper("cat"),
            &vec![0; MAX_MESSAGE_BYTES + 1],
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
    }
}
