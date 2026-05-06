//! AWS Nitro Enclave attestation document verification.
//!
//! Pure-Rust verifier extracted from the enclave crate so that:
//!   - the enclave's cloning peer-verify path,
//!   - the parent's external `attest-verify` CLI binary,
//!
//! all run the *same* verification code. Single source of truth for
//! "is this attestation document trustworthy?"
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

/// Expected PCR values for an enclave we trust.
///
/// Sourced out-of-band — typically pinned in a release artifact, on-chain
/// config, or operator-supplied flag — and compared bytewise against the
/// PCRs reported in an attestation document.
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
// Public API — real path (always available)
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
// Public API — mock path (feature-gated)
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
    use x509_cert::Certificate;

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

        // chain[0] is the root, anchored above by byte-equality. Walk forward.
        for i in 0..chain.len() - 1 {
            verify_issuer_signed_subject(&chain[i], &chain[i + 1])?;
        }

        let signing_pubkey = extract_p384_pubkey(chain.last().expect("non-empty"))?;
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

    /// RFC 8152 §8.1 mandates raw `r || s` (96 bytes for P-384). Accept DER
    /// defensively in case a doc source deviates.
    fn parse_cose_ecdsa_signature(sig_bytes: &[u8]) -> Result<Signature> {
        if sig_bytes.len() == 96 {
            Signature::try_from(sig_bytes)
                .map_err(|e| VerifyError::Attestation(format!("invalid COSE raw signature: {e}")))
        } else {
            Signature::from_der(sig_bytes).map_err(|e| {
                VerifyError::Attestation(format!(
                    "invalid COSE signature ({} bytes, not raw P-384 r||s or DER): {e}",
                    sig_bytes.len()
                ))
            })
        }
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
        let mut pcrs = HashMap::new();
        pcrs.insert(0, vec![0u8; 48]);
        pcrs.insert(1, vec![0u8; 48]);
        pcrs.insert(2, vec![0u8; 48]);

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
