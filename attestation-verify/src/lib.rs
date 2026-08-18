//! AWS Nitro Enclave attestation document verification.
//!
//! Pure-Rust verifier shared by the enclave's cloning peer-verify path and the
//! parent's `attest-verify` CLI, so both run the same code.
//!
//! Real path: parses COSE_Sign1, verifies the AWS Nitro certificate chain
//! down from the hardcoded root CA, checks PCR0/1/2 against expected, and
//! enforces nonce presence (and equality if a specific value is expected).
//!
//! Mock path (`mock` feature): produces and verifies raw CBOR documents
//! without COSE wrapping or certificate validation. PCR/nonce/pubkey
//! binding is still enforced. Used by integration tests and dev builds
//! that cannot reach a real NSM device.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use thiserror::Error;

pub mod policy;
pub use policy::{
    AttestationMode, AttestedPolicy, BtcDataSource, EvmDataSource, POLICY_COMMITMENT_V2,
};

// ----------------------------------------------------------------------------
// Public types
// ----------------------------------------------------------------------------

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

/// Expected PCR values for an enclave we trust. Sourced out-of-band (a release
/// artifact, on-chain config, or an operator flag) and compared bytewise
/// against the PCRs in an attestation document.
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
    pub enclave_pubkey: Vec<u8>,
    pub pcrs: HashMap<u32, Vec<u8>>,
    pub timestamp: u64,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Vec<u8>,
}

/// Wire-format representation of the NSM attestation payload.
///
/// In real mode this is the CBOR payload *inside* a COSE_Sign1 wrapper.
/// In mock mode it is the entire document (no COSE wrapping).
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

// ----------------------------------------------------------------------------
// Public API - real path (always available)
// ----------------------------------------------------------------------------

/// Verify a real (production) Nitro Enclave attestation document.
///
/// Checks (in order):
///   1. Parse COSE_Sign1 envelope and inner CBOR AttestationDocument.
///   2. Validate the X.509 certificate chain back to the hardcoded
///      AWS Nitro root CA, checking each certificate's validity window.
///   3. Verify the COSE_Sign1 signature using the leaf signing certificate.
///   4. Compare PCR0/1/2 against `expected_pcrs`.
///   5. Require a nonce. If `expected_nonce` is `Some`, require byte-equality
///      with it; if `None`, the caller is expected to enforce freshness via
///      its own replay guard.
///   6. Require a `public_key` field.
pub fn verify_attestation(
    doc: &[u8],
    expected_pcrs: &ExpectedPcrs,
    expected_nonce: Option<&[u8; 32]>,
) -> Result<VerifiedAttestation> {
    real::verify_real_document(doc, expected_pcrs, expected_nonce)
}

// ----------------------------------------------------------------------------
// Public API - mock path (feature-gated)
// ----------------------------------------------------------------------------

/// Verify a mock attestation document (raw CBOR, no COSE wrapping, no cert chain).
///
/// PCR / nonce / pubkey binding are still enforced. Test-only.
#[cfg(feature = "mock")]
pub fn verify_mock_attestation(
    doc: &[u8],
    expected_pcrs: &ExpectedPcrs,
    expected_nonce: Option<&[u8; 32]>,
) -> Result<VerifiedAttestation> {
    mock::verify_mock_document(doc, expected_pcrs, expected_nonce)
}

/// Build a mock attestation document for tests.
///
/// PCRs are zeroed, no COSE wrapping, no certificate. Pairs with
/// [`verify_mock_attestation`].
#[cfg(feature = "mock")]
pub fn build_mock_document(
    nonce: &[u8; 32],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    mock::build_mock_document(nonce, public_key, user_data)
}

/// Build a mock attestation document with caller-specified PCRs. Like
/// [`build_mock_document`], but a test can set PCR0/1/2 to exercise the
/// PCR-binding rejection path. Test-only.
#[cfg(feature = "mock")]
pub fn build_mock_document_with_pcrs(
    nonce: &[u8; 32],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    pcrs: &ExpectedPcrs,
) -> Result<Vec<u8>> {
    mock::build_mock_document_with_pcrs(nonce, public_key, user_data, pcrs)
}

// ----------------------------------------------------------------------------
// Shared helpers
// ----------------------------------------------------------------------------

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

// ----------------------------------------------------------------------------
// Real path (COSE + cert chain)
// ----------------------------------------------------------------------------

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

    /// COSE algorithm identifier for ECDSA with SHA-384 (ES384), from the COSE
    /// Algorithms registry (RFC 8152 / RFC 9053). AWS Nitro attestation
    /// documents are signed with ES384 over the P-384 leaf key.
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

    /// DER bytes of the embedded root cert. Parsed once and compared to
    /// `cabundle[0]` bytewise on every verify.
    fn root_cert_der() -> &'static [u8] {
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

    pub(super) fn verify_real_document(
        doc: &[u8],
        expected_pcrs: &ExpectedPcrs,
        expected_nonce: Option<&[u8; 32]>,
    ) -> Result<VerifiedAttestation> {
        let cose = CoseSign1::from_bytes(doc)?;
        verify_cose_alg_es384(&cose.protected)?;
        let payload = cose
            .payload
            .as_ref()
            .ok_or_else(|| VerifyError::Attestation("missing COSE payload".into()))?;

        let attestation: AttestationDocument = ciborium::from_reader(payload.as_slice())
            .map_err(|e| VerifyError::Attestation(format!("failed to parse attestation: {e}")))?;

        verify_certificate_chain(&attestation.certificate, &attestation.cabundle, &cose)?;

        let nonce = check_nonce(&attestation.nonce, expected_nonce)?;
        verify_pcrs(&attestation.pcrs, expected_pcrs)?;

        let enclave_pubkey = attestation
            .public_key
            .ok_or_else(|| VerifyError::Attestation("missing public key".into()))?;

        Ok(VerifiedAttestation {
            enclave_pubkey,
            pcrs: attestation.pcrs,
            timestamp: attestation.timestamp,
            user_data: attestation.user_data,
            nonce,
        })
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
    ) -> Result<()> {
        if cabundle.is_empty() {
            return Err(VerifyError::Certificate("empty certificate bundle".into()));
        }

        if cabundle[0].as_slice() != root_cert_der() {
            return Err(VerifyError::Certificate(
                "cabundle[0] is not the AWS Nitro root CA".into(),
            ));
        }

        let mut chain = Vec::with_capacity(cabundle.len() + 1);
        for (i, cert_der) in cabundle.iter().enumerate() {
            let cert = Certificate::from_der(cert_der).map_err(|e| {
                VerifyError::Certificate(format!("failed to parse cabundle[{i}]: {e}"))
            })?;
            verify_cert_validity(&cert)?;
            chain.push(cert);
        }
        let signing_cert = Certificate::from_der(signing_cert_der)
            .map_err(|e| VerifyError::Certificate(format!("failed to parse signing cert: {e}")))?;
        verify_cert_validity(&signing_cert)?;
        chain.push(signing_cert);

        // chain[0] is the root, anchored above by byte-equality. Walk forward,
        // checking each issuer both signed the next subject and is a CA
        // permitted to issue subordinate certificates (RFC 5280 6.1.4).
        let mut max_path_len = chain.len();
        for i in 0..chain.len() - 1 {
            verify_issuer_signed_subject(&chain[i], &chain[i + 1])?;
            max_path_len = check_ca_constraints(&chain[i], i == 0, max_path_len)?;
        }

        let leaf = chain.last().expect("non-empty");
        // Defensive: if the end-entity asserts a KeyUsage it must permit the
        // digitalSignature it uses to sign the COSE envelope.
        if let Some((_critical, key_usage)) = leaf
            .tbs_certificate
            .get::<KeyUsage>()
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
            .tbs_certificate
            .to_der()
            .map_err(|e| VerifyError::Certificate(format!("TBS DER encode failed: {e}")))?;
        let sig_bytes = subject
            .signature
            .as_bytes()
            .ok_or_else(|| VerifyError::Certificate("missing signature bytes".into()))?;
        // X.509 cert signatures are DER-encoded ECDSA (unlike COSE).
        let signature = Signature::from_der(sig_bytes)
            .map_err(|e| VerifyError::Certificate(format!("invalid cert signature: {e}")))?;
        issuer_pubkey
            .verify(&tbs_bytes, &signature)
            .map_err(|_| VerifyError::Certificate("certificate signature invalid".into()))
    }

    /// Enforce RFC 5280 6.1.4-style CA constraints on `issuer`, a certificate
    /// that signs a subordinate one (the root and every intermediate, never the
    /// end-entity). Without this a non-CA leaf could sign further certificates.
    ///
    /// Checks:
    ///   * `BasicConstraints` is present and asserts `cA = TRUE`.
    ///   * if `KeyUsage` is present it permits `keyCertSign`.
    ///   * the `pathLenConstraint` budget is not exhausted.
    ///
    /// `max_path_len` is the number of additional non-self-issued CA
    /// certificates still permitted below `issuer`, per constraints set by
    /// certificates already processed higher in the chain. The (possibly
    /// tightened) budget for the next issuer down the chain is returned.
    /// `is_trust_anchor` is true only for the root (`cabundle[0]`); per RFC 5280
    /// the trust anchor is not counted against the path-length budget.
    pub(super) fn check_ca_constraints(
        issuer: &Certificate,
        is_trust_anchor: bool,
        max_path_len: usize,
    ) -> Result<usize> {
        let basic_constraints = issuer
            .tbs_certificate
            .get::<BasicConstraints>()
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

        // If KeyUsage is asserted it must permit signing subordinate certs.
        if let Some((_critical, key_usage)) = issuer
            .tbs_certificate
            .get::<KeyUsage>()
            .map_err(|e| VerifyError::Certificate(format!("invalid KeyUsage: {e}")))?
        {
            if !key_usage.key_cert_sign() {
                return Err(VerifyError::Certificate(
                    "issuer certificate KeyUsage forbids keyCertSign".into(),
                ));
            }
        }

        // Path length (RFC 5280 section 6.1.4 steps (l)/(m)). The trust anchor is not
        // counted; every other (non-self-issued) CA consumes one unit of budget
        // and may only tighten it via its own pathLenConstraint.
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

    /// RFC 8152 8.1 mandates the COSE ECDSA signature be the fixed-width raw
    /// `r || s` concatenation, 96 bytes for P-384 / ES384. DER is rejected here,
    /// unlike X.509 certificate signatures (see `verify_issuer_signed_subject`).
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

    /// Assert the COSE_Sign1 protected header pins the signature algorithm to
    /// ES384 (COSE alg `-35`), the algorithm AWS Nitro uses. Rejecting any
    /// other value prevents a document from downgrading to a weaker or foreign
    /// algorithm that the leaf key was not meant to be used with.
    ///
    /// `protected` is the raw CBOR-encoded protected header map (bstr content).
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
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| VerifyError::Certificate("missing public key bytes".into()))?;

        VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|e| VerifyError::Certificate(format!("invalid P-384 key: {e}")))
    }

    fn verify_cert_validity(cert: &Certificate) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VerifyError::Certificate("system clock error".into()))?
            .as_secs();

        let validity = &cert.tbs_certificate.validity;
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();

        if now < not_before {
            return Err(VerifyError::Certificate("certificate not yet valid".into()));
        }
        if now > not_after {
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

        // --- helpers -------------------------------------------------------

        /// A base certificate to mutate. Neither `check_ca_constraints` nor the
        /// end-entity KeyUsage gate inspects the signature, so swapping the
        /// embedded root's extensions exercises the constraint logic without
        /// minting a full signed chain.
        fn base_cert() -> Certificate {
            Certificate::from_der(root_cert_der()).expect("embedded root parses")
        }

        fn ext<T: Encode + AssociatedOid>(value: &T, critical: bool) -> Extension {
            Extension {
                extn_id: T::OID,
                critical,
                extn_value: OctetString::new(value.to_der().expect("encode extension"))
                    .expect("octet string"),
            }
        }

        fn cert_with_exts(exts: Vec<Extension>) -> Certificate {
            let mut cert = base_cert();
            cert.tbs_certificate.extensions = Some(exts);
            cert
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
            // A full-size DER ECDSA-Sig-Value for P-384: SEQUENCE { INTEGER(48),
            // INTEGER(48) } == 102 bytes. RFC 8152 requires raw r||s, so it must
            // be rejected.
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

        // --- COSE protected-header algorithm (I-05) ------------------------

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

        // --- X.509 CA constraints (W-10 / #70) -----------------------------

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
            // BasicConstraints present but cA = FALSE (the W-10 case): a non-CA
            // cert must not be accepted as an issuer.
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
            // KeyUsage is optional; its absence must not fail the usage gate.
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

// ----------------------------------------------------------------------------
// Mock path (raw CBOR, no COSE / cert chain)
// ----------------------------------------------------------------------------

#[cfg(feature = "mock")]
mod mock {
    use super::*;

    pub(super) fn build_mock_document(
        nonce: &[u8; 32],
        public_key: Option<&[u8]>,
        user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        build_mock_document_with_pcrs(nonce, public_key, user_data, &ExpectedPcrs::zero())
    }

    pub(super) fn build_mock_document_with_pcrs(
        nonce: &[u8; 32],
        public_key: Option<&[u8]>,
        user_data: Option<&[u8]>,
        expected: &ExpectedPcrs,
    ) -> Result<Vec<u8>> {
        let mut pcrs = HashMap::new();
        pcrs.insert(0, expected.pcr0.to_vec());
        pcrs.insert(1, expected.pcr1.to_vec());
        pcrs.insert(2, expected.pcr2.to_vec());

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
    ) -> Result<VerifiedAttestation> {
        let attestation: AttestationDocument = ciborium::from_reader(doc)
            .map_err(|e| VerifyError::Attestation(format!("failed to parse mock doc: {e}")))?;

        let nonce = check_nonce(&attestation.nonce, expected_nonce)?;
        verify_pcrs(&attestation.pcrs, expected_pcrs)?;

        let enclave_pubkey = attestation
            .public_key
            .ok_or_else(|| VerifyError::Attestation("missing public key".into()))?;

        Ok(VerifiedAttestation {
            enclave_pubkey,
            pcrs: attestation.pcrs,
            timestamp: attestation.timestamp,
            user_data: attestation.user_data,
            nonce,
        })
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        fn mock_reject_corrupted_doc() {
            let err =
                verify_mock_attestation(&[0xffu8; 16], &ExpectedPcrs::zero(), Some(&[0u8; 32]))
                    .unwrap_err();
            assert!(matches!(err, VerifyError::Attestation(_)));
        }
    }
}
