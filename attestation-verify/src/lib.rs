//! AWS Nitro Enclave attestation document verification.
//!
//! Pure-Rust verifier. The enclave clone peer check and the parent
//! `attest-verify` CLI both use it.
//!
//! Real path: parse COSE_Sign1, verify the AWS Nitro certificate chain from
//! the hardcoded root CA, and compare PCR0/1/2. A nonce must be present. If
//! the caller gives a nonce, it must be equal.
//!
//! Policy-only path. An enclave without keys attests only its policy.
//! The document has no public key. Its `user_data` is [`policy_commitment`].
//!
//! Mock path (`mock` feature): make and verify raw CBOR documents without COSE
//! or certificate checks. It compares PCRs and the expected nonce, if supplied.
//! It requires a public-key field. The caller must check that key and user_data.
//! For integration tests and dev builds without an NSM device.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use thiserror::Error;

pub mod policy;
pub use policy::{
    policy_commitment, AttestationMode, AttestedPolicy, BtcDataSource, EvmDataSource, EvmRpcTlsPin,
    KmsPin, PolicyDecodeError, SignerRole, POLICY_COMMITMENT_V9,
};

// Public types

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("attestation error: {0}")]
    Attestation(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("PCR mismatch: PCR{pcr} expected={expected}, actual={actual}")]
    PcrMismatch {
        pcr: u32,
        expected: String,
        actual: String,
    },
}

pub type Result<T> = std::result::Result<T, VerifyError>;

/// Expected PCR values of a trusted enclave. They come out-of-band (release
/// artifact, on-chain config or operator flag). The verifier compares them
/// byte for byte with the document PCRs.
#[derive(Clone, Debug)]
pub struct ExpectedPcrs {
    pub pcr0: [u8; 48],
    pub pcr1: [u8; 48],
    pub pcr2: [u8; 48],
}

impl ExpectedPcrs {
    pub fn new(pcr0: [u8; 48], pcr1: [u8; 48], pcr2: [u8; 48]) -> Self {
        Self { pcr0, pcr1, pcr2 }
    }

    pub fn zero() -> Self {
        Self {
            pcr0: [0u8; 48],
            pcr1: [0u8; 48],
            pcr2: [0u8; 48],
        }
    }

    pub fn from_hex(pcr0: &str, pcr1: &str, pcr2: &str) -> Result<Self> {
        let parse = |s: &str| -> Result<[u8; 48]> {
            let bytes = hex::decode(s).map_err(|e| VerifyError::Attestation(e.to_string()))?;
            bytes
                .try_into()
                .map_err(|_| VerifyError::Attestation("PCR must be 48 bytes".into()))
        };
        Ok(Self {
            pcr0: parse(pcr0)?,
            pcr1: parse(pcr1)?,
            pcr2: parse(pcr2)?,
        })
    }
}

/// The verified contents of an attestation document, minus CBOR/COSE wrapping.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    /// Empty for a policy-only document.
    pub enclave_pubkey: Vec<u8>,
    pub pcrs: HashMap<u32, Vec<u8>>,
    pub timestamp: u64,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Vec<u8>,
}

/// Wire format of the NSM attestation payload.
///
/// Real mode: the CBOR payload inside COSE_Sign1. Mock mode: the full document.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct AttestationDocument {
    #[serde(rename = "module_id", default)]
    pub module_id: String,
    pub timestamp: u64,
    #[serde(default)]
    pub digest: String,
    pub pcrs: HashMap<u32, Vec<u8>>,
    #[serde(default)]
    pub certificate: Vec<u8>,
    #[serde(default)]
    pub cabundle: Vec<Vec<u8>>,
    #[serde(default)]
    pub public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub user_data: Option<Vec<u8>>,
    #[serde(default)]
    pub nonce: Option<Vec<u8>>,
}

// Public API - real path (always available)

/// Verify a real (production) Nitro Enclave attestation document.
///
/// Checks, in order:
///   1. Parse COSE_Sign1, require alg ES384, and parse the CBOR document.
///   2. Validate the X.509 chain to the hardcoded AWS Nitro root CA,
///      including each validity window.
///   3. Verify the COSE_Sign1 signature with the leaf certificate.
///   4. Require a nonce. If `expected_nonce` is `Some`, it must be equal.
///      If `None`, the caller must enforce freshness with its own replay guard.
///   5. Reject all-zero PCRs (unless `allow-debug-pcrs`).
///   6. Compare PCR0/1/2 with `expected_pcrs`.
///   7. Require a `public_key` field.
///
/// The caller must check the returned public key and user_data. This function
/// returns the document timestamp but does not enforce a maximum document age.
pub fn verify_attestation(
    doc: &[u8],
    expected_pcrs: &ExpectedPcrs,
    expected_nonce: Option<&[u8; 32]>,
) -> Result<VerifiedAttestation> {
    let (attestation, nonce) = real::verify_real_document(
        doc,
        expected_pcrs,
        expected_nonce,
        real::root_cert_der(),
        CheckTime::Now,
    )?;
    into_verified(attestation, nonce, true)
}

/// Verify a real keyed document, as [`verify_attestation`] does, but check
/// the certificates at the document timestamp. NSM certificates live for
/// hours, so a stored document needs this check. The nonce is required.
pub fn verify_attestation_at_document_time(
    doc: &[u8],
    expected_pcrs: &ExpectedPcrs,
    expected_nonce: &[u8; 32],
) -> Result<VerifiedAttestation> {
    let (attestation, nonce) = real::verify_real_document(
        doc,
        expected_pcrs,
        Some(expected_nonce),
        real::root_cert_der(),
        CheckTime::Document,
    )?;
    into_verified(attestation, nonce, true)
}

/// Verify a real policy-only document, as [`verify_attestation`] does.
/// The nonce is required and there must be no `public_key`.
/// The caller must check `user_data` against [`policy_commitment`].
pub fn verify_policy_attestation(
    doc: &[u8],
    expected_pcrs: &ExpectedPcrs,
    expected_nonce: &[u8; 32],
) -> Result<VerifiedAttestation> {
    let (attestation, nonce) = real::verify_real_document(
        doc,
        expected_pcrs,
        Some(expected_nonce),
        real::root_cert_der(),
        CheckTime::Now,
    )?;
    into_verified(attestation, nonce, false)
}

// Public API - mock path (feature-gated)

/// Verify a mock attestation document (raw CBOR, no COSE, no cert chain).
///
/// Compare PCRs and the expected nonce, if supplied. Require a public-key field.
/// The caller must check the public key and user_data. Tests only.
#[cfg(feature = "mock")]
pub fn verify_mock_attestation(
    doc: &[u8],
    expected_pcrs: &ExpectedPcrs,
    expected_nonce: Option<&[u8; 32]>,
) -> Result<VerifiedAttestation> {
    let (attestation, nonce) = mock::verify_mock_document(doc, expected_pcrs, expected_nonce)?;
    into_verified(attestation, nonce, true)
}

/// Mock form of [`verify_policy_attestation`]. Tests only.
#[cfg(feature = "mock")]
pub fn verify_mock_policy_attestation(
    doc: &[u8],
    expected_pcrs: &ExpectedPcrs,
    expected_nonce: &[u8; 32],
) -> Result<VerifiedAttestation> {
    let (attestation, nonce) =
        mock::verify_mock_document(doc, expected_pcrs, Some(expected_nonce))?;
    into_verified(attestation, nonce, false)
}

/// PCR3 of every mock document, of a mock enclave and of a
/// `test_util::signed_document`. PCR3 measures the IAM role of the parent
/// instance; a mock enclave has none, so it gets this fixed, non-zero value.
/// Then the clone-peer PCR3 rule runs in mock tests too.
#[cfg(any(test, feature = "mock", feature = "test-util"))]
pub const MOCK_PCR3: [u8; 48] = [0x33; 48];

/// Build a mock attestation document for tests: zero PCR0/1/2,
/// [`MOCK_PCR3`], no COSE, no certificate. Use with
/// [`verify_mock_attestation`].
#[cfg(feature = "mock")]
pub fn build_mock_document(
    nonce: &[u8; 32],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    mock::build_mock_document(nonce, public_key, user_data)
}

/// Like [`build_mock_document`], but with caller PCRs, to test PCR mismatch.
/// Tests only.
#[cfg(feature = "mock")]
pub fn build_mock_document_with_pcrs(
    nonce: &[u8; 32],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    pcrs: &ExpectedPcrs,
) -> Result<Vec<u8>> {
    mock::build_mock_document_with_pcrs(nonce, public_key, user_data, pcrs, Some(&MOCK_PCR3))
}

/// Like [`build_mock_document`], but with a caller PCR3 (`None`: no PCR3), to
/// test the clone-peer PCR3 rule. Tests only.
#[cfg(feature = "mock")]
pub fn build_mock_document_with_pcr3(
    nonce: &[u8; 32],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    pcr3: Option<&[u8; 48]>,
) -> Result<Vec<u8>> {
    mock::build_mock_document_with_pcrs(nonce, public_key, user_data, &ExpectedPcrs::zero(), pcr3)
}

/// The time at which the certificate validity is checked.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CheckTime {
    Now,
    /// The document timestamp. NSM gives it in milliseconds.
    Document,
}

// Shared helpers

/// Reject all-zero PCR0/1/2. (F03-AF-12 / F02-AF-08)
/// Debug enclaves share these values, so they cannot identify a trusted image.
/// The allow-debug-pcrs feature disables this check for debug tests.
#[cfg(not(feature = "allow-debug-pcrs"))]
fn reject_debug_pcrs(pcrs: &HashMap<u32, Vec<u8>>) -> Result<()> {
    let all_zero = [0u32, 1, 2].iter().all(|idx| {
        pcrs.get(idx)
            .map(|p| !p.is_empty() && p.iter().all(|&b| b == 0))
            .unwrap_or(false)
    });
    if all_zero {
        return Err(VerifyError::Attestation(
            "all-zero PCR0/1/2: attestation is from a debug-mode enclave (no measurement) \
             and is rejected by the production verifier; build with the unsafe \
             `allow-debug-pcrs` feature only for debug/stage drills"
                .into(),
        ));
    }
    Ok(())
}

fn verify_pcrs(pcrs: &HashMap<u32, Vec<u8>>, expected: &ExpectedPcrs) -> Result<()> {
    let check = |idx: u32, expected_bytes: &[u8; 48]| -> Result<()> {
        let actual = pcrs
            .get(&idx)
            .ok_or_else(|| VerifyError::Attestation(format!("Missing PCR{idx}")))?;
        if actual.as_slice() != expected_bytes {
            return Err(VerifyError::PcrMismatch {
                pcr: idx,
                expected: hex::encode(expected_bytes),
                actual: hex::encode(actual),
            });
        }
        Ok(())
    };

    check(0, &expected.pcr0)?;
    check(1, &expected.pcr1)?;
    check(2, &expected.pcr2)?;
    Ok(())
}

/// A keyed document must have a `public_key`. A policy-only document must not.
fn into_verified(
    attestation: AttestationDocument,
    nonce: Vec<u8>,
    keyed: bool,
) -> Result<VerifiedAttestation> {
    let enclave_pubkey = match (attestation.public_key, keyed) {
        (Some(key), true) => key,
        (None, false) => Vec::new(),
        (None, true) => return Err(VerifyError::Attestation("missing public key".into())),
        (Some(_), false) => {
            return Err(VerifyError::Attestation(
                "policy-only attestation has a public key".into(),
            ))
        }
    };
    Ok(VerifiedAttestation {
        enclave_pubkey,
        pcrs: attestation.pcrs,
        timestamp: attestation.timestamp,
        user_data: attestation.user_data,
        nonce,
    })
}

fn check_nonce(doc_nonce: &Option<Vec<u8>>, expected: Option<&[u8; 32]>) -> Result<Vec<u8>> {
    let nonce = doc_nonce
        .as_ref()
        .ok_or_else(|| VerifyError::Attestation("missing nonce in attestation".into()))?;
    if let Some(exp) = expected {
        if nonce.as_slice() != exp {
            return Err(VerifyError::Attestation("nonce mismatch".into()));
        }
    }
    Ok(nonce.clone())
}

// Real path (COSE + cert chain)

mod real {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_cert::der::{Decode, Encode};
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    use x509_cert::Certificate;

    /// COSE algorithm ID for ECDSA with SHA-384 (ES384) (RFC 8152 / RFC 9053).
    /// AWS Nitro signs attestation documents with ES384 and the P-384 leaf key.
    const COSE_ALG_ES384: i128 = -35;

    // AWS Nitro Enclave root CA. Source:
    // https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    // Self-signed, P-384, ECDSA-SHA384, valid 2019-10-28 .. 2049-10-28.
    const AWS_NITRO_ROOT_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"#;

    /// DER bytes of the embedded root cert. Decoded once. Each verify compares
    /// them byte for byte with `cabundle[0]`.
    pub(super) fn root_cert_der() -> &'static [u8] {
        static ROOT: OnceLock<Vec<u8>> = OnceLock::new();
        ROOT.get_or_init(|| {
            let lines: Vec<&str> = AWS_NITRO_ROOT_CERT_PEM
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect();
            BASE64
                .decode(lines.join(""))
                .expect("invalid base64 in embedded root cert")
        })
    }

    /// `root_der` is the trust anchor. Tests pass their own root.
    pub(super) fn verify_real_document(
        doc: &[u8],
        expected_pcrs: &ExpectedPcrs,
        expected_nonce: Option<&[u8; 32]>,
        root_der: &[u8],
        at: CheckTime,
    ) -> Result<(AttestationDocument, Vec<u8>)> {
        let cose = CoseSign1::from_bytes(doc)?;
        verify_cose_alg_es384(&cose.protected)?;
        let payload = cose
            .payload
            .as_ref()
            .ok_or_else(|| VerifyError::Attestation("missing COSE payload".into()))?;

        let attestation: AttestationDocument = ciborium::from_reader(payload.as_slice())
            .map_err(|e| VerifyError::Attestation(format!("failed to parse attestation: {e}")))?;

        let at = match at {
            CheckTime::Now => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| VerifyError::Certificate("system clock error".into()))?
                .as_secs(),
            CheckTime::Document => attestation.timestamp / 1000,
        };
        verify_certificate_chain(
            &attestation.certificate,
            &attestation.cabundle,
            &cose,
            root_der,
            at,
        )?;

        let nonce = check_nonce(&attestation.nonce, expected_nonce)?;

        // Reject all-zero PCRs before comparing them with expected values. (F03-AF-12)
        #[cfg(not(feature = "allow-debug-pcrs"))]
        reject_debug_pcrs(&attestation.pcrs)?;

        verify_pcrs(&attestation.pcrs, expected_pcrs)?;

        Ok((attestation, nonce))
    }

    /// Parse and verify the attestation certificate chain.
    ///
    /// AWS Nitro cabundle ordering:
    ///   cabundle[0]      = AWS Nitro root CA (must match embedded root)
    ///   cabundle[1..N-1] = intermediate CAs
    ///   cabundle[N-1]    = direct issuer of `signing_cert`
    ///   signing_cert     = end-entity cert that signed the COSE envelope
    fn verify_certificate_chain(
        signing_cert_der: &[u8],
        cabundle: &[Vec<u8>],
        cose: &CoseSign1,
        root_der: &[u8],
        at: u64,
    ) -> Result<()> {
        if cabundle.is_empty() {
            return Err(VerifyError::Certificate("empty certificate bundle".into()));
        }

        if cabundle[0].as_slice() != root_der {
            return Err(VerifyError::Certificate(
                "cabundle[0] is not the AWS Nitro root CA".into(),
            ));
        }

        let mut chain = Vec::with_capacity(cabundle.len() + 1);
        for (i, cert_der) in cabundle.iter().enumerate() {
            let cert = Certificate::from_der(cert_der).map_err(|e| {
                VerifyError::Certificate(format!("failed to parse cabundle[{i}]: {e}"))
            })?;
            verify_cert_validity(&cert, at)?;
            chain.push(cert);
        }
        let signing_cert = Certificate::from_der(signing_cert_der)
            .map_err(|e| VerifyError::Certificate(format!("failed to parse signing cert: {e}")))?;
        verify_cert_validity(&signing_cert, at)?;
        chain.push(signing_cert);

        // chain[0] is the root, anchored by byte equality above. Each issuer
        // must sign the next subject and be a CA that can issue subordinate
        // certificates (RFC 5280 6.1.4).
        let mut max_path_len = chain.len();
        for i in 0..chain.len() - 1 {
            verify_issuer_signed_subject(&chain[i], &chain[i + 1])?;
            max_path_len = check_ca_constraints(&chain[i], i == 0, max_path_len)?;
        }

        let leaf = chain.last().expect("non-empty");
        // If the leaf has KeyUsage, it must permit digitalSignature, which it
        // uses to sign the COSE envelope.
        if let Some((_critical, key_usage)) = leaf
            .tbs_certificate()
            .get_extension::<KeyUsage>()
            .map_err(|e| VerifyError::Certificate(format!("invalid signing-cert KeyUsage: {e}")))?
        {
            if !key_usage.digital_signature() {
                return Err(VerifyError::Certificate(
                    "signing certificate KeyUsage forbids digitalSignature".into(),
                ));
            }
        }

        let signing_pubkey = extract_p384_pubkey(leaf)?;
        let cose_sig = parse_cose_ecdsa_signature(&cose.signature)?;
        let to_verify = cose.sig_structure()?;
        signing_pubkey
            .verify(&to_verify, &cose_sig)
            .map_err(|_| VerifyError::Attestation("COSE signature verification failed".into()))?;

        Ok(())
    }

    fn verify_issuer_signed_subject(issuer: &Certificate, subject: &Certificate) -> Result<()> {
        let issuer_pubkey = extract_p384_pubkey(issuer)?;
        let tbs_bytes = subject
            .tbs_certificate()
            .to_der()
            .map_err(|e| VerifyError::Certificate(format!("TBS DER encode failed: {e}")))?;
        let sig_bytes = subject
            .signature()
            .as_bytes()
            .ok_or_else(|| VerifyError::Certificate("missing signature bytes".into()))?;
        // X.509 cert signatures are DER-encoded ECDSA (unlike COSE).
        let signature = Signature::from_der(sig_bytes)
            .map_err(|e| VerifyError::Certificate(format!("invalid cert signature: {e}")))?;
        issuer_pubkey
            .verify(&tbs_bytes, &signature)
            .map_err(|_| VerifyError::Certificate("certificate signature invalid".into()))
    }

    /// Apply RFC 5280 6.1.4 CA constraints to `issuer` (the root or an
    /// intermediate, never the leaf). Without this, a non-CA leaf could sign
    /// more certificates.
    ///
    /// Checks:
    ///   * `BasicConstraints` is present with `cA = TRUE`.
    ///   * If `KeyUsage` is present, it permits `keyCertSign`.
    ///   * The `pathLenConstraint` budget is not used up.
    ///
    /// `max_path_len` is the number of non-self-issued CA certificates still
    /// permitted below `issuer`. Returns the budget for the next issuer.
    /// `is_trust_anchor` is true only for the root (`cabundle[0]`). RFC 5280
    /// does not count the trust anchor against the budget.
    pub(super) fn check_ca_constraints(
        issuer: &Certificate,
        is_trust_anchor: bool,
        max_path_len: usize,
    ) -> Result<usize> {
        let basic_constraints = issuer
            .tbs_certificate()
            .get_extension::<BasicConstraints>()
            .map_err(|e| VerifyError::Certificate(format!("invalid BasicConstraints: {e}")))?
            .map(|(_critical, bc)| bc)
            .ok_or_else(|| {
                VerifyError::Certificate("issuer certificate missing BasicConstraints".into())
            })?;
        if !basic_constraints.ca {
            return Err(VerifyError::Certificate(
                "issuer certificate is not a CA (BasicConstraints cA=FALSE)".into(),
            ));
        }

        // If KeyUsage is present, it must permit signing subordinate certs.
        if let Some((_critical, key_usage)) =
            issuer
                .tbs_certificate()
                .get_extension::<KeyUsage>()
                .map_err(|e| VerifyError::Certificate(format!("invalid KeyUsage: {e}")))?
        {
            if !key_usage.key_cert_sign() {
                return Err(VerifyError::Certificate(
                    "issuer certificate KeyUsage forbids keyCertSign".into(),
                ));
            }
        }

        // Path length (RFC 5280 section 6.1.4 steps (l)/(m)). The trust anchor
        // is not counted. Each other CA uses one unit of budget, and its
        // pathLenConstraint can only make the budget smaller.
        let mut budget = max_path_len;
        if !is_trust_anchor {
            if budget == 0 {
                return Err(VerifyError::Certificate(
                    "certificate path length constraint exceeded".into(),
                ));
            }
            budget -= 1;
        }
        if let Some(path_len_constraint) = basic_constraints.path_len_constraint {
            budget = budget.min(path_len_constraint as usize);
        }
        Ok(budget)
    }

    /// RFC 8152 8.1: the COSE ECDSA signature is raw fixed-width `r || s`,
    /// 96 bytes for P-384 / ES384. Reject DER here. X.509 signatures use DER
    /// (see `verify_issuer_signed_subject`).
    pub(super) fn parse_cose_ecdsa_signature(sig_bytes: &[u8]) -> Result<Signature> {
        if sig_bytes.len() != 96 {
            return Err(VerifyError::Attestation(format!(
                "COSE signature must be 96-byte raw P-384 r||s, got {} bytes",
                sig_bytes.len()
            )));
        }
        Signature::try_from(sig_bytes)
            .map_err(|e| VerifyError::Attestation(format!("invalid COSE raw signature: {e}")))
    }

    /// Require ES384 (COSE alg `-35`) in the COSE_Sign1 protected header.
    /// AWS Nitro uses ES384. Any other value could downgrade to an algorithm
    /// that the leaf key is not for.
    ///
    /// `protected` is the raw CBOR protected header map (bstr content).
    pub(super) fn verify_cose_alg_es384(protected: &[u8]) -> Result<()> {
        let header: ciborium::Value = ciborium::from_reader(protected)
            .map_err(|e| VerifyError::Attestation(format!("invalid COSE protected header: {e}")))?;
        let map = header.as_map().ok_or_else(|| {
            VerifyError::Attestation("COSE protected header must be a map".into())
        })?;
        // COSE header label 1 = alg (RFC 8152 section 3.1).
        let alg = map
            .iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(1))
            .map(|(_, v)| v)
            .ok_or_else(|| {
                VerifyError::Attestation("COSE protected header missing alg (label 1)".into())
            })?;
        let alg = alg
            .as_integer()
            .map(i128::from)
            .ok_or_else(|| VerifyError::Attestation("COSE alg must be an integer".into()))?;
        if alg != COSE_ALG_ES384 {
            return Err(VerifyError::Attestation(format!(
                "unexpected COSE alg {alg}, expected ES384 ({COSE_ALG_ES384})"
            )));
        }
        Ok(())
    }

    fn extract_p384_pubkey(cert: &Certificate) -> Result<VerifyingKey> {
        let spki = cert.tbs_certificate().subject_public_key_info();
        let key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| VerifyError::Certificate("missing public key bytes".into()))?;

        VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|e| VerifyError::Certificate(format!("invalid P-384 key: {e}")))
    }

    /// Clock-skew tolerance in seconds, on both sides of the certificate
    /// validity window.
    ///
    /// Nitro enclaves get their time from the hypervisor at boot and have no
    /// NTP, so clocks can drift. `enclave::clocksync` corrects CLOCK_REALTIME
    /// from the hypervisor PTP clock. This tolerance covers short skew, for
    /// example before the first PTP sync. Keep it small. Nonces, not the wall
    /// clock, prevent replay.
    const CERT_CLOCK_SKEW_TOLERANCE_SECS: u64 = 60;

    /// `at` is the check time in Unix seconds.
    fn verify_cert_validity(cert: &Certificate, at: u64) -> Result<()> {
        let validity = cert.tbs_certificate().validity();
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();

        check_cert_validity_window(at, not_before, not_after)
    }

    /// Validity-window check with clock-skew tolerance. Separate, so tests do
    /// not need a signed certificate.
    fn check_cert_validity_window(now: u64, not_before: u64, not_after: u64) -> Result<()> {
        if now.saturating_add(CERT_CLOCK_SKEW_TOLERANCE_SECS) < not_before {
            return Err(VerifyError::Certificate("certificate not yet valid".into()));
        }
        if now > not_after.saturating_add(CERT_CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(VerifyError::Certificate("certificate has expired".into()));
        }
        Ok(())
    }

    pub(super) struct CoseSign1 {
        protected: Vec<u8>,
        _unprotected: ciborium::Value,
        pub payload: Option<Vec<u8>>,
        pub signature: Vec<u8>,
    }

    impl CoseSign1 {
        pub fn from_bytes(data: &[u8]) -> Result<Self> {
            let value: ciborium::Value = ciborium::from_reader(data)
                .map_err(|e| VerifyError::Attestation(format!("invalid CBOR: {e}")))?;

            // Accept a bare COSE_Sign1 array or CBOR tag 18. (RFC 8152, F03-AF-14)
            // Reject other tags.
            // The signature checks below still apply.
            let value = match value {
                ciborium::Value::Tag(18, inner) => *inner,
                ciborium::Value::Tag(tag, _) => {
                    return Err(VerifyError::Attestation(format!(
                        "unexpected CBOR tag {tag} on COSE_Sign1 (expected 18)"
                    )));
                }
                other => other,
            };

            let arr = value
                .as_array()
                .ok_or_else(|| VerifyError::Attestation("COSE_Sign1 must be array".into()))?;
            if arr.len() != 4 {
                return Err(VerifyError::Attestation(
                    "COSE_Sign1 must have 4 elements".into(),
                ));
            }

            let protected = arr[0]
                .as_bytes()
                .ok_or_else(|| VerifyError::Attestation("invalid protected header".into()))?
                .clone();
            let unprotected = arr[1].clone();
            let payload = if arr[2].is_null() {
                None
            } else {
                Some(
                    arr[2]
                        .as_bytes()
                        .ok_or_else(|| VerifyError::Attestation("invalid payload".into()))?
                        .clone(),
                )
            };
            let signature = arr[3]
                .as_bytes()
                .ok_or_else(|| VerifyError::Attestation("invalid signature".into()))?
                .clone();

            Ok(Self {
                protected,
                _unprotected: unprotected,
                payload,
                signature,
            })
        }

        pub fn sig_structure(&self) -> Result<Vec<u8>> {
            let structure = ciborium::Value::Array(vec![
                ciborium::Value::Text("Signature1".into()),
                ciborium::Value::Bytes(self.protected.clone()),
                ciborium::Value::Bytes(vec![]),
                ciborium::Value::Bytes(self.payload.clone().unwrap_or_default()),
            ]);

            let mut buf = Vec::new();
            ciborium::into_writer(&structure, &mut buf).map_err(|e| {
                VerifyError::Attestation(format!("failed to encode sig structure: {e}"))
            })?;
            Ok(buf)
        }
    }

    #[cfg(test)]
    mod hardening_tests {
        use super::*;
        use x509_cert::der::asn1::OctetString;
        use x509_cert::der::oid::AssociatedOid;
        use x509_cert::ext::pkix::KeyUsages;
        use x509_cert::ext::Extension;

        // --- COSE_Sign1 envelope (F03-AF-14) -------------------------------

        fn sample_cose_array() -> ciborium::Value {
            ciborium::Value::Array(vec![
                ciborium::Value::Bytes(vec![0xa1, 0x01, 0x38, 0x22]), // protected {1:-35}
                ciborium::Value::Map(vec![]),
                ciborium::Value::Bytes(vec![1, 2, 3]),
                ciborium::Value::Bytes(vec![4, 5, 6, 7]),
            ])
        }

        fn encode(v: &ciborium::Value) -> Vec<u8> {
            let mut buf = Vec::new();
            ciborium::into_writer(v, &mut buf).expect("encode cbor");
            buf
        }

        #[test]
        fn cose_from_bytes_accepts_tag18_wrapper() {
            let arr = sample_cose_array();
            let bare = CoseSign1::from_bytes(&encode(&arr)).expect("bare parses");

            let tagged = ciborium::Value::Tag(18, Box::new(arr));
            let tagged = CoseSign1::from_bytes(&encode(&tagged)).expect("tag-18 parses");

            // Same fields with or without the tag.
            assert_eq!(bare.protected, tagged.protected);
            assert_eq!(bare.payload, tagged.payload);
            assert_eq!(bare.signature, tagged.signature);
        }

        #[test]
        fn cose_from_bytes_rejects_non_18_tag() {
            let tagged = ciborium::Value::Tag(17, Box::new(sample_cose_array()));
            assert!(matches!(
                CoseSign1::from_bytes(&encode(&tagged)),
                Err(VerifyError::Attestation(_))
            ));
        }

        // --- helpers -------------------------------------------------------

        fn ext<T: Encode + AssociatedOid>(value: &T, critical: bool) -> Extension {
            Extension {
                extn_id: T::OID,
                critical,
                extn_value: OctetString::new(value.to_der().expect("encode extension"))
                    .expect("octet string"),
            }
        }

        /// The embedded root with its extensions replaced. The constraint
        /// checks do not read the signature, so no signed chain is needed.
        /// x509-cert has no mutable access, so this edits the DER: the `[3]`
        /// element of the TBS sequence holds the extensions.
        fn cert_with_exts(exts: Vec<Extension>) -> Certificate {
            use x509_cert::der::asn1::{Any, ContextSpecific};
            use x509_cert::der::{Tag, TagMode, TagNumber, Tagged};
            let seq = |any: &Any| Vec::<Any>::from_der(&any.to_der().unwrap()).unwrap();
            let mut cert = Vec::<Any>::from_der(root_cert_der()).expect("cert is a SEQUENCE");
            let mut tbs = seq(&cert[0]);
            tbs.retain(|a| {
                !matches!(
                    a.tag(),
                    Tag::ContextSpecific {
                        number: TagNumber(3),
                        ..
                    }
                )
            });
            let exts = ContextSpecific {
                tag_number: TagNumber(3),
                tag_mode: TagMode::Explicit,
                value: exts,
            };
            tbs.push(Any::from_der(&exts.to_der().unwrap()).unwrap());
            cert[0] = Any::from_der(&tbs.to_der().unwrap()).unwrap();
            Certificate::from_der(&cert.to_der().unwrap()).expect("edited cert parses")
        }

        fn basic(ca: bool, path_len: Option<u8>) -> BasicConstraints {
            BasicConstraints {
                ca,
                path_len_constraint: path_len,
            }
        }

        /// CBOR encoding of a COSE protected-header map `{1: alg}`.
        fn protected_with_alg(alg: i128) -> Vec<u8> {
            use ciborium::value::Integer;
            let map = ciborium::Value::Map(vec![(
                ciborium::Value::Integer(Integer::try_from(1_i128).unwrap()),
                ciborium::Value::Integer(Integer::try_from(alg).unwrap()),
            )]);
            let mut buf = Vec::new();
            ciborium::into_writer(&map, &mut buf).unwrap();
            buf
        }

        fn signed_document(pcrs: &ExpectedPcrs, nonce: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
            // 2020-01-01T12:00:00Z, inside the default leaf validity.
            crate::test_util::signed_document(
                pcrs,
                nonce,
                None,
                &[0x55; 32],
                1_577_880_000_000,
                None,
            )
        }

        #[test]
        fn a_flipped_signature_byte_fails_the_cose_signature_check() {
            let pcrs = ExpectedPcrs::new([1; 48], [2; 48], [3; 48]);
            let nonce = [9; 32];
            let (doc, root) = signed_document(&pcrs, &nonce);
            for at in [CheckTime::Now, CheckTime::Document] {
                verify_real_document(&doc, &pcrs, Some(&nonce), &root, at).expect("valid control");

                // The signature is the last element, so the last byte is in it.
                let mut bad = doc.clone();
                *bad.last_mut().unwrap() ^= 1;
                let err = verify_real_document(&bad, &pcrs, Some(&nonce), &root, at).unwrap_err();
                assert!(
                    matches!(&err, VerifyError::Attestation(m) if m == "COSE signature verification failed"),
                    "{at:?}: {err}"
                );
            }
        }

        #[test]
        fn a_document_past_its_certificates_verifies_at_its_own_time() {
            let pcrs = ExpectedPcrs::new([1; 48], [2; 48], [3; 48]);
            let nonce = [9; 32];
            // 2020-01-01T12:00:00Z. The leaf is valid on 2020-01-01 only.
            let noon_ms = 1_577_880_000_000;
            let document = |timestamp_ms| {
                crate::test_util::signed_document(
                    &pcrs,
                    &nonce,
                    None,
                    &[0x55; 32],
                    timestamp_ms,
                    Some((2020, 1, 1)),
                )
            };
            let verify = |(doc, root): &(Vec<u8>, Vec<u8>), at| {
                verify_real_document(doc, &pcrs, Some(&nonce), root, at).map(|_| ())
            };

            let noon = document(noon_ms);
            let err = verify(&noon, CheckTime::Now).unwrap_err();
            assert!(err.to_string().contains("certificate has expired"), "{err}");
            verify(&noon, CheckTime::Document).expect("valid at the document time");

            // A year later the leaf has expired.
            let later = document(noon_ms + 366 * 86_400_000);
            let err = verify(&later, CheckTime::Document).unwrap_err();
            assert!(err.to_string().contains("certificate has expired"), "{err}");

            // The timestamp is in milliseconds. Seconds read as 1970.
            let seconds = document(noon_ms / 1000);
            let err = verify(&seconds, CheckTime::Document).unwrap_err();
            assert!(err.to_string().contains("not yet valid"), "{err}");
        }

        #[test]
        fn a_signed_document_with_other_pcrs_fails() {
            let pcrs = ExpectedPcrs::new([1; 48], [2; 48], [3; 48]);
            let nonce = [9; 32];
            let (doc, root) = signed_document(&pcrs, &nonce);
            let other = ExpectedPcrs::new([1; 48], [2; 48], [4; 48]);
            let err = verify_real_document(&doc, &other, Some(&nonce), &root, CheckTime::Now)
                .unwrap_err();
            assert!(
                matches!(err, VerifyError::PcrMismatch { pcr: 2, .. }),
                "{err}"
            );
        }

        // --- certificate validity window w/ clock-skew tolerance -----------

        #[test]
        fn cert_validity_accepts_now_inside_window() {
            assert!(check_cert_validity_window(1_000, 900, 1_100).is_ok());
        }

        #[test]
        fn cert_validity_accepts_fresh_peer_within_skew_tolerance() {
            // The verifier clock is behind not_before by less than the tolerance.
            let not_before = 1_000;
            let now = not_before - (CERT_CLOCK_SKEW_TOLERANCE_SECS - 1);
            assert!(check_cert_validity_window(now, not_before, not_before + 10_000).is_ok());
        }

        #[test]
        fn cert_validity_rejects_beyond_skew_tolerance_before() {
            let not_before = 100_000;
            let now = not_before - (CERT_CLOCK_SKEW_TOLERANCE_SECS + 1);
            let err = check_cert_validity_window(now, not_before, not_before + 10_000).unwrap_err();
            assert!(matches!(err, VerifyError::Certificate(_)));
        }

        #[test]
        fn cert_validity_accepts_just_expired_within_skew_tolerance() {
            let not_after = 1_000;
            let now = not_after + (CERT_CLOCK_SKEW_TOLERANCE_SECS - 1);
            assert!(check_cert_validity_window(now, 0, not_after).is_ok());
        }

        #[test]
        fn cert_validity_rejects_beyond_skew_tolerance_after() {
            let not_after = 1_000;
            let now = not_after + (CERT_CLOCK_SKEW_TOLERANCE_SECS + 1);
            let err = check_cert_validity_window(now, 0, not_after).unwrap_err();
            assert!(matches!(err, VerifyError::Certificate(_)));
        }

        #[test]
        fn cert_validity_saturates_near_epoch_zero() {
            // `now` near 0 must not underflow.
            assert!(check_cert_validity_window(0, 10, 10_000).is_ok());
        }

        // --- COSE signature form (I-05) ------------------------------------

        #[test]
        fn cose_sig_accepts_96_byte_raw() {
            // r = s = 0x0101..01 (48 bytes each) is a valid, in-range P-384 sig.
            assert!(parse_cose_ecdsa_signature(&[0x01u8; 96]).is_ok());
        }

        #[test]
        fn cose_sig_rejects_non_96_lengths() {
            for len in [0usize, 48, 64, 95, 97, 128] {
                let err = parse_cose_ecdsa_signature(&vec![0x01u8; len]).unwrap_err();
                assert!(
                    matches!(err, VerifyError::Attestation(_)),
                    "length {len} should be rejected"
                );
            }
        }

        #[test]
        fn cose_sig_rejects_der_encoding() {
            // A full-size P-384 DER ECDSA-Sig-Value: SEQUENCE { INTEGER(48),
            // INTEGER(48) } is 102 bytes. RFC 8152 requires raw r||s.
            let integer = |bytes: &[u8]| {
                let mut v = vec![0x02u8, bytes.len() as u8];
                v.extend_from_slice(bytes);
                v
            };
            let mut body = integer(&[0x01u8; 48]);
            body.extend_from_slice(&integer(&[0x01u8; 48]));
            let mut der = vec![0x30u8, body.len() as u8];
            der.extend_from_slice(&body);
            assert_eq!(der.len(), 102, "sanity: full-size P-384 DER signature");
            assert!(matches!(
                parse_cose_ecdsa_signature(&der).unwrap_err(),
                VerifyError::Attestation(_)
            ));
        }

        // --- COSE protected-header algorithm ------------------------

        #[test]
        fn cose_alg_es384_accepted() {
            assert!(verify_cose_alg_es384(&protected_with_alg(COSE_ALG_ES384)).is_ok());
        }

        #[test]
        fn cose_alg_es256_rejected() {
            // -7 == ES256; only ES384 (-35) is permitted.
            let err = verify_cose_alg_es384(&protected_with_alg(-7)).unwrap_err();
            assert!(matches!(err, VerifyError::Attestation(_)));
        }

        #[test]
        fn cose_alg_missing_rejected() {
            let mut buf = Vec::new();
            ciborium::into_writer(&ciborium::Value::Map(vec![]), &mut buf).unwrap();
            assert!(matches!(
                verify_cose_alg_es384(&buf).unwrap_err(),
                VerifyError::Attestation(_)
            ));
        }

        // --- X.509 CA constraints -----------------------------

        #[test]
        fn ca_valid_issuer_passes_and_decrements_budget() {
            let ca = cert_with_exts(vec![
                ext(&basic(true, None), true),
                ext(
                    &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::DigitalSignature),
                    true,
                ),
            ]);
            // A non-anchor CA consumes one unit of the path-length budget.
            assert_eq!(check_ca_constraints(&ca, false, 3).unwrap(), 2);
            // The trust anchor is not counted against the budget.
            assert_eq!(check_ca_constraints(&ca, true, 3).unwrap(), 3);
        }

        #[test]
        fn ca_missing_basic_constraints_rejected() {
            let cert = cert_with_exts(vec![ext(&KeyUsage(KeyUsages::KeyCertSign.into()), true)]);
            assert!(matches!(
                check_ca_constraints(&cert, false, 3).unwrap_err(),
                VerifyError::Certificate(_)
            ));
        }

        #[test]
        fn ca_non_ca_issuer_rejected() {
            // BasicConstraints with cA = FALSE: a non-CA cert is not an issuer.
            let cert = cert_with_exts(vec![ext(&basic(false, None), false)]);
            assert!(matches!(
                check_ca_constraints(&cert, false, 3).unwrap_err(),
                VerifyError::Certificate(_)
            ));
            assert!(check_ca_constraints(&cert, true, 3).is_err());
        }

        #[test]
        fn ca_keyusage_without_keycertsign_rejected() {
            let cert = cert_with_exts(vec![
                ext(&basic(true, None), true),
                ext(&KeyUsage(KeyUsages::DigitalSignature.into()), true),
            ]);
            assert!(matches!(
                check_ca_constraints(&cert, false, 3).unwrap_err(),
                VerifyError::Certificate(_)
            ));
        }

        #[test]
        fn ca_without_keyusage_is_allowed() {
            // KeyUsage is optional. Without it, the check must pass.
            let cert = cert_with_exts(vec![ext(&basic(true, None), true)]);
            assert!(check_ca_constraints(&cert, false, 3).is_ok());
        }

        #[test]
        fn ca_path_len_budget_exhausted_rejected() {
            let ca = cert_with_exts(vec![ext(&basic(true, None), true)]);
            // Budget 0 for a non-anchor issuer means too many CAs precede it.
            assert!(matches!(
                check_ca_constraints(&ca, false, 0).unwrap_err(),
                VerifyError::Certificate(_)
            ));
            // The anchor is exempt from the budget check.
            assert!(check_ca_constraints(&ca, true, 0).is_ok());
        }

        #[test]
        fn ca_path_len_constraint_tightens_budget() {
            // pathLenConstraint clamps the budget carried to downstream issuers.
            let ca0 = cert_with_exts(vec![ext(&basic(true, Some(0)), true)]);
            assert_eq!(check_ca_constraints(&ca0, false, 5).unwrap(), 0);
            let ca2 = cert_with_exts(vec![ext(&basic(true, Some(2)), true)]);
            assert_eq!(check_ca_constraints(&ca2, false, 5).unwrap(), 2);

            // Chained effect: a pathLen=0 CA followed by another CA is rejected.
            let budget_after = check_ca_constraints(&ca0, false, 5).unwrap();
            let next = cert_with_exts(vec![ext(&basic(true, None), true)]);
            assert!(check_ca_constraints(&next, false, budget_after).is_err());
        }
    }
}

/// Real-format documents signed under a test root. Tests only.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    use super::*;
    use p384::ecdsa::{signature::Signer, Signature, SigningKey};
    use p384::pkcs8::DecodePrivateKey;
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};

    /// A COSE_Sign1 document signed by a leaf under a fresh test root, and
    /// the root DER. PCR3 is [`MOCK_PCR3`], as in a mock document.
    /// `leaf_valid_on` limits the leaf to one UTC day (year, month, day).
    /// `None` keeps the rcgen default validity.
    pub fn signed_document(
        pcrs: &ExpectedPcrs,
        nonce: &[u8; 32],
        public_key: Option<&[u8]>,
        user_data: &[u8],
        timestamp_ms: u64,
        leaf_valid_on: Option<(i32, u8, u8)>,
    ) -> (Vec<u8>, Vec<u8>) {
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = root_params.self_signed(&root_key).unwrap();
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        if let Some((year, month, day)) = leaf_valid_on {
            leaf_params.not_before = rcgen::date_time_ymd(year, month, day);
            leaf_params.not_after = leaf_params.not_before + std::time::Duration::from_secs(86_400);
        }
        let leaf = leaf_params
            .signed_by(&leaf_key, &Issuer::from_params(&root_params, &root_key))
            .unwrap();

        let document = AttestationDocument {
            module_id: "test".into(),
            timestamp: timestamp_ms,
            digest: "SHA384".into(),
            pcrs: HashMap::from([
                (0, pcrs.pcr0.to_vec()),
                (1, pcrs.pcr1.to_vec()),
                (2, pcrs.pcr2.to_vec()),
                (3, MOCK_PCR3.to_vec()),
            ]),
            certificate: leaf.der().to_vec(),
            cabundle: vec![root.der().to_vec()],
            public_key: public_key.map(<[u8]>::to_vec),
            user_data: Some(user_data.to_vec()),
            nonce: Some(nonce.to_vec()),
        };
        let encode = |v: &ciborium::Value| {
            let mut buf = Vec::new();
            ciborium::into_writer(v, &mut buf).unwrap();
            buf
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&document, &mut payload).unwrap();
        // Protected header {1: -35}: alg ES384.
        let protected = vec![0xa1, 0x01, 0x38, 0x22];
        let sig_structure = encode(&ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".into()),
            ciborium::Value::Bytes(protected.clone()),
            ciborium::Value::Bytes(vec![]),
            ciborium::Value::Bytes(payload.clone()),
        ]));
        let key = SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
        let signature: Signature = key.sign(&sig_structure);
        let cose = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(signature.to_bytes().to_vec()),
        ]);
        (encode(&cose), root.der().to_vec())
    }

    /// [`verify_attestation_at_document_time`] with `root_der` as the trust
    /// anchor.
    pub fn verify_at_document_time_with_root(
        doc: &[u8],
        expected_pcrs: &ExpectedPcrs,
        expected_nonce: &[u8; 32],
        root_der: &[u8],
    ) -> Result<VerifiedAttestation> {
        let (attestation, nonce) = real::verify_real_document(
            doc,
            expected_pcrs,
            Some(expected_nonce),
            root_der,
            CheckTime::Document,
        )?;
        into_verified(attestation, nonce, true)
    }
}

// Mock path (raw CBOR, no COSE / cert chain)

#[cfg(feature = "mock")]
mod mock {
    use super::*;

    pub(super) fn build_mock_document(
        nonce: &[u8; 32],
        public_key: Option<&[u8]>,
        user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        build_mock_document_with_pcrs(
            nonce,
            public_key,
            user_data,
            &ExpectedPcrs::zero(),
            Some(&super::MOCK_PCR3),
        )
    }

    pub(super) fn build_mock_document_with_pcrs(
        nonce: &[u8; 32],
        public_key: Option<&[u8]>,
        user_data: Option<&[u8]>,
        expected: &ExpectedPcrs,
        pcr3: Option<&[u8; 48]>,
    ) -> Result<Vec<u8>> {
        let mut pcrs = HashMap::new();
        pcrs.insert(0, expected.pcr0.to_vec());
        pcrs.insert(1, expected.pcr1.to_vec());
        pcrs.insert(2, expected.pcr2.to_vec());
        if let Some(pcr3) = pcr3 {
            pcrs.insert(3, pcr3.to_vec());
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let doc = AttestationDocument {
            module_id: "mock".into(),
            timestamp,
            digest: "SHA384".into(),
            pcrs,
            certificate: Vec::new(),
            cabundle: Vec::new(),
            public_key: public_key.map(|p| p.to_vec()),
            user_data: user_data.map(|d| d.to_vec()),
            nonce: Some(nonce.to_vec()),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&doc, &mut buf)
            .map_err(|e| VerifyError::Attestation(format!("failed to encode mock doc: {e}")))?;
        Ok(buf)
    }

    pub(super) fn verify_mock_document(
        doc: &[u8],
        expected_pcrs: &ExpectedPcrs,
        expected_nonce: Option<&[u8; 32]>,
    ) -> Result<(AttestationDocument, Vec<u8>)> {
        let attestation: AttestationDocument = ciborium::from_reader(doc)
            .map_err(|e| VerifyError::Attestation(format!("failed to parse mock doc: {e}")))?;

        let nonce = check_nonce(&attestation.nonce, expected_nonce)?;
        verify_pcrs(&attestation.pcrs, expected_pcrs)?;

        Ok((attestation, nonce))
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // Test the zero-PCR check when allow-debug-pcrs is disabled. (F03-AF-12)
    #[cfg(not(feature = "allow-debug-pcrs"))]
    #[test]
    fn reject_debug_pcrs_flags_all_zero_but_allows_measured() {
        let zeros = || vec![0u8; 48];
        let mut all_zero = HashMap::new();
        all_zero.insert(0u32, zeros());
        all_zero.insert(1u32, zeros());
        all_zero.insert(2u32, zeros());
        assert!(
            reject_debug_pcrs(&all_zero).is_err(),
            "all-zero PCR0/1/2 must be rejected by the production verifier"
        );

        // One nonzero PCR passes this check.
        // The verifier must still compare all expected PCR values.
        let mut measured = all_zero.clone();
        measured.insert(0u32, vec![1u8; 48]);
        assert!(reject_debug_pcrs(&measured).is_ok());

        // A fully measured set passes the guard.
        let mut full = HashMap::new();
        full.insert(0u32, vec![0xa1u8; 48]);
        full.insert(1u32, vec![0xb2u8; 48]);
        full.insert(2u32, vec![0xc3u8; 48]);
        assert!(reject_debug_pcrs(&full).is_ok());
    }

    #[test]
    fn expected_pcrs_from_hex_roundtrip() {
        let pcr0 = "00".repeat(48);
        let pcr1 = "11".repeat(48);
        let pcr2 = "22".repeat(48);
        let pcrs = ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2).unwrap();
        assert_eq!(pcrs.pcr0[0], 0x00);
        assert_eq!(pcrs.pcr1[0], 0x11);
        assert_eq!(pcrs.pcr2[47], 0x22);
    }

    #[test]
    fn expected_pcrs_from_hex_bad_length() {
        assert!(ExpectedPcrs::from_hex("ab", "cd", "ef").is_err());
    }

    #[test]
    fn expected_pcrs_from_hex_invalid_chars() {
        let bad = "zz".repeat(48);
        assert!(ExpectedPcrs::from_hex(&bad, &bad, &bad).is_err());
    }

    #[cfg(feature = "mock")]
    mod mock_flow {
        use super::*;

        #[test]
        fn mock_roundtrip_happy_path() {
            let nonce = [7u8; 32];
            let pubkey = [1u8; 32];
            let doc = build_mock_document(&nonce, Some(&pubkey), Some(b"user")).unwrap();

            let verified =
                verify_mock_attestation(&doc, &ExpectedPcrs::zero(), Some(&nonce)).unwrap();

            assert_eq!(verified.enclave_pubkey, pubkey.to_vec());
            assert_eq!(verified.user_data.as_deref(), Some(b"user".as_ref()));
            assert_eq!(verified.nonce, nonce.to_vec());
            assert_eq!(verified.pcrs.get(&0).unwrap().len(), 48);
        }

        #[test]
        fn mock_extracts_nonce_when_expected_is_none() {
            let nonce = [0x5au8; 32];
            let doc = build_mock_document(&nonce, Some(&[0u8; 32]), None).unwrap();
            let verified = verify_mock_attestation(&doc, &ExpectedPcrs::zero(), None).unwrap();
            assert_eq!(verified.nonce, nonce.to_vec());
        }

        #[test]
        fn mock_reject_nonce_mismatch() {
            let nonce = [1u8; 32];
            let other = [2u8; 32];
            let doc = build_mock_document(&nonce, Some(&[0u8; 32]), None).unwrap();
            let err =
                verify_mock_attestation(&doc, &ExpectedPcrs::zero(), Some(&other)).unwrap_err();
            assert!(matches!(err, VerifyError::Attestation(_)));
        }

        #[test]
        fn mock_reject_pcr_mismatch() {
            let nonce = [3u8; 32];
            let doc = build_mock_document(&nonce, Some(&[0u8; 32]), None).unwrap();
            let expected = ExpectedPcrs::new([1u8; 48], [0u8; 48], [0u8; 48]);
            let err = verify_mock_attestation(&doc, &expected, Some(&nonce)).unwrap_err();
            assert!(matches!(err, VerifyError::PcrMismatch { pcr: 0, .. }));
        }

        #[test]
        fn mock_reject_missing_pubkey() {
            let nonce = [4u8; 32];
            let doc = build_mock_document(&nonce, None, None).unwrap();
            let err =
                verify_mock_attestation(&doc, &ExpectedPcrs::zero(), Some(&nonce)).unwrap_err();
            assert!(matches!(err, VerifyError::Attestation(_)));
        }

        #[test]
        fn mock_policy_only_rejects_a_public_key() {
            let nonce = [6u8; 32];
            let keyed = build_mock_document(&nonce, Some(&[1u8; 65]), Some(b"p")).unwrap();
            let err =
                verify_mock_policy_attestation(&keyed, &ExpectedPcrs::zero(), &nonce).unwrap_err();
            assert!(err.to_string().contains("has a public key"), "{err}");

            let policy_only = build_mock_document(&nonce, None, Some(b"p")).unwrap();
            let verified =
                verify_mock_policy_attestation(&policy_only, &ExpectedPcrs::zero(), &nonce)
                    .unwrap();
            assert!(verified.enclave_pubkey.is_empty());
            assert_eq!(verified.user_data.as_deref(), Some(b"p".as_ref()));
        }

        #[test]
        fn mock_policy_only_requires_the_nonce() {
            let nonce = [6u8; 32];
            let doc = build_mock_document(&nonce, None, None).unwrap();
            let err = verify_mock_policy_attestation(&doc, &ExpectedPcrs::zero(), &[7u8; 32])
                .unwrap_err();
            assert!(err.to_string().contains("nonce mismatch"), "{err}");

            let mut no_nonce: AttestationDocument = ciborium::from_reader(doc.as_slice()).unwrap();
            no_nonce.nonce = None;
            let mut doc = Vec::new();
            ciborium::into_writer(&no_nonce, &mut doc).unwrap();
            let err =
                verify_mock_policy_attestation(&doc, &ExpectedPcrs::zero(), &nonce).unwrap_err();
            assert!(err.to_string().contains("missing nonce"), "{err}");
        }

        #[test]
        fn mock_reject_corrupted_doc() {
            let err =
                verify_mock_attestation(&[0xffu8; 16], &ExpectedPcrs::zero(), Some(&[0u8; 32]))
                    .unwrap_err();
            assert!(matches!(err, VerifyError::Attestation(_)));
        }
    }
}
