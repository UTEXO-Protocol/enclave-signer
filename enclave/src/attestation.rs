//! AWS Nitro Enclave attestation.
//!
//! Two paths:
//!   1. Real (default on Linux): requests attestation documents from the
//!      NSM device (`/dev/nsm`) via `aws-nitro-enclaves-nsm-api`, and
//!      verifies peer attestations by parsing COSE_Sign1, validating the
//!      AWS Nitro certificate chain, and comparing PCRs + nonce.
//!   2. Mock (`mock-attestation` feature or non-Linux): the document is
//!      a raw CBOR-encoded `AttestationDocument` with no COSE wrapping
//!      and no certificate chain. Verification skips the crypto checks
//!      but still enforces PCRs, nonce, and pubkey binding. This lets
//!      cloning integration tests run on any dev machine.
//!
//! Module is currently not wired into server.rs. PR 4 will plug it in.

#![allow(dead_code)]

use std::collections::HashMap;

use crate::error::{EnclaveError, Result};

/// Expected PCR values for a peer enclave. Constructed once from
/// a self-attestation at startup (`get_own_pcrs`) and reused for
/// every peer check.
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
            let bytes = hex::decode(s).map_err(|e| EnclaveError::Attestation(e.to_string()))?;
            bytes
                .try_into()
                .map_err(|_| EnclaveError::Attestation("PCR must be 48 bytes".into()))
        };
        Ok(Self {
            pcr0: parse(pcr0)?,
            pcr1: parse(pcr1)?,
            pcr2: parse(pcr2)?,
        })
    }
}

/// The verified contents of a peer attestation, minus the CBOR/COSE wrapping.
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
/// In mock mode it is the outer document (no COSE wrapping).
///
/// Byte fields are encoded as CBOR arrays-of-uint in the mock roundtrip,
/// which ciborium handles transparently. Real NSM documents use proper
/// CBOR byte strings — ciborium's deserializer accepts both.
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
// Public API
// ----------------------------------------------------------------------------

/// Produce an attestation document binding `nonce`, `public_key`, and optional
/// `user_data`. The returned bytes are what we hand to peers over the wire.
///
/// Real path (Linux + no mock): calls the NSM device.
/// Mock path (`mock-attestation` feature): returns a raw CBOR `AttestationDocument`
/// with all-zero PCRs and the supplied fields. Non-Linux builds without
/// `mock-attestation` will fail to compile at the call site.
pub fn get_attestation(
    nonce: &[u8; 32],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    #[cfg(feature = "mock-attestation")]
    {
        mock::build_mock_document(nonce, public_key, user_data)
    }

    #[cfg(all(target_os = "linux", not(feature = "mock-attestation")))]
    {
        real::request_nsm_attestation(nonce, public_key, user_data)
    }

    #[cfg(all(not(target_os = "linux"), not(feature = "mock-attestation")))]
    {
        let _ = (nonce, public_key, user_data);
        Err(EnclaveError::Attestation(
            "attestation not available: build for Linux with NSM or enable mock-attestation"
                .into(),
        ))
    }
}

/// Read PCR0/1/2 from a self-attestation. Used at startup to learn our own
/// measurement so we can reject peers with mismatched PCRs.
pub fn get_own_pcrs() -> Result<ExpectedPcrs> {
    #[cfg(feature = "mock-attestation")]
    {
        Ok(ExpectedPcrs::zero())
    }

    #[cfg(all(target_os = "linux", not(feature = "mock-attestation")))]
    {
        real::read_own_pcrs()
    }

    #[cfg(all(not(target_os = "linux"), not(feature = "mock-attestation")))]
    {
        Err(EnclaveError::Attestation(
            "NSM not available on this platform; enable mock-attestation for dev builds".into(),
        ))
    }
}

/// Verify a peer attestation document and return the extracted fields.
///
/// Checks (in order):
///   1. Parse COSE_Sign1 / AttestationDocument (CBOR).
///   2. Verify the COSE signature using the embedded leaf certificate.
///   3. Verify the certificate chain terminates at the AWS Nitro root CA.
///   4. Check certificate validity windows (not_before / not_after).
///   5. Compare PCR0/1/2 against `expected_pcrs`.
///   6. Compare the document nonce against `expected_nonce`.
///
/// In `mock-attestation` mode, steps 1–4 are replaced with a raw CBOR parse
/// and the cert chain is not validated. PCR/nonce/pubkey binding still hold.
pub fn verify_peer_attestation(
    doc: &[u8],
    expected_pcrs: &ExpectedPcrs,
    expected_nonce: &[u8; 32],
) -> Result<VerifiedAttestation> {
    #[cfg(feature = "mock-attestation")]
    {
        mock::verify_mock_document(doc, expected_pcrs, expected_nonce)
    }

    #[cfg(not(feature = "mock-attestation"))]
    {
        real::verify_real_document(doc, expected_pcrs, expected_nonce)
    }
}

// ----------------------------------------------------------------------------
// Shared helpers
// ----------------------------------------------------------------------------

fn verify_pcrs(
    pcrs: &HashMap<u32, Vec<u8>>,
    expected: &ExpectedPcrs,
) -> Result<()> {
    let check = |idx: u32, expected_bytes: &[u8; 48]| -> Result<()> {
        let actual = pcrs
            .get(&idx)
            .ok_or_else(|| EnclaveError::Attestation(format!("Missing PCR{idx}")))?;
        if actual.as_slice() != expected_bytes {
            return Err(EnclaveError::PcrMismatch {
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

fn check_nonce(doc_nonce: &Option<Vec<u8>>, expected: &[u8; 32]) -> Result<Vec<u8>> {
    match doc_nonce {
        Some(n) if n.as_slice() == expected => Ok(n.clone()),
        Some(_) => Err(EnclaveError::Attestation("nonce mismatch".into())),
        None => Err(EnclaveError::Attestation(
            "missing nonce in attestation".into(),
        )),
    }
}

// ----------------------------------------------------------------------------
// Real path (COSE + cert chain)
// ----------------------------------------------------------------------------

#[cfg(not(feature = "mock-attestation"))]
mod real {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_cert::der::{Decode, Encode};
    use x509_cert::Certificate;

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

    fn parse_pem_cert(pem: &str) -> Certificate {
        let lines: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let b64 = lines.join("");
        let der = BASE64
            .decode(&b64)
            .expect("invalid base64 in embedded root cert");
        Certificate::from_der(&der).expect("invalid DER in embedded root cert")
    }

    pub(super) fn verify_real_document(
        doc: &[u8],
        expected_pcrs: &ExpectedPcrs,
        expected_nonce: &[u8; 32],
    ) -> Result<VerifiedAttestation> {
        let root_cert = parse_pem_cert(AWS_NITRO_ROOT_CERT_PEM);

        let cose = CoseSign1::from_bytes(doc)?;
        let payload = cose
            .payload
            .as_ref()
            .ok_or_else(|| EnclaveError::Attestation("missing COSE payload".into()))?;

        let attestation: AttestationDocument = ciborium::from_reader(payload.as_slice())
            .map_err(|e| EnclaveError::Attestation(format!("failed to parse attestation: {e}")))?;

        verify_certificate_chain(
            &attestation.certificate,
            &attestation.cabundle,
            &cose,
            &root_cert,
        )?;

        let nonce = check_nonce(&attestation.nonce, expected_nonce)?;
        verify_pcrs(&attestation.pcrs, expected_pcrs)?;

        let enclave_pubkey = attestation
            .public_key
            .ok_or_else(|| EnclaveError::Attestation("missing public key".into()))?;

        Ok(VerifiedAttestation {
            enclave_pubkey,
            pcrs: attestation.pcrs,
            timestamp: attestation.timestamp,
            user_data: attestation.user_data,
            nonce,
        })
    }

    fn verify_certificate_chain(
        signing_cert_der: &[u8],
        cabundle: &[Vec<u8>],
        cose: &CoseSign1,
        root_cert: &Certificate,
    ) -> Result<()> {
        let signing_cert = Certificate::from_der(signing_cert_der).map_err(|e| {
            EnclaveError::Certificate(format!("failed to parse signing cert: {e}"))
        })?;
        verify_cert_validity(&signing_cert)?;

        let signing_pubkey = extract_p384_pubkey(&signing_cert)?;
        let sig_bytes = cose.signature.as_slice();
        let signature = Signature::from_der(sig_bytes)
            .map_err(|e| EnclaveError::Attestation(format!("invalid COSE signature: {e}")))?;

        let to_verify = cose.sig_structure()?;
        signing_pubkey
            .verify(&to_verify, &signature)
            .map_err(|_| EnclaveError::Attestation("COSE signature verification failed".into()))?;

        if cabundle.is_empty() {
            return Err(EnclaveError::Attestation("empty certificate bundle".into()));
        }

        let issuer_cert = Certificate::from_der(&cabundle[0])
            .map_err(|e| EnclaveError::Certificate(format!("failed to parse issuer cert: {e}")))?;
        verify_cert_validity(&issuer_cert)?;

        let issuer_pubkey = extract_p384_pubkey(&issuer_cert)?;
        let tbs_bytes = signing_cert
            .tbs_certificate
            .to_der()
            .map_err(|e| EnclaveError::Certificate(format!("DER encode failed: {e}")))?;

        let cert_sig_bytes = signing_cert.signature.as_bytes().ok_or_else(|| {
            EnclaveError::Certificate("missing signature bytes on signing cert".into())
        })?;
        let cert_signature = Signature::from_der(cert_sig_bytes)
            .map_err(|e| EnclaveError::Certificate(format!("invalid signature: {e}")))?;

        issuer_pubkey
            .verify(&tbs_bytes, &cert_signature)
            .map_err(|_| EnclaveError::Certificate("signing certificate not issued by CA".into()))?;

        let mut certs = Vec::with_capacity(cabundle.len());
        for cert_der in cabundle {
            let cert = Certificate::from_der(cert_der)
                .map_err(|e| EnclaveError::Certificate(format!("failed to parse cert: {e}")))?;
            verify_cert_validity(&cert)?;
            certs.push(cert);
        }

        for i in 0..certs.len().saturating_sub(1) {
            let subject = &certs[i];
            let issuer = &certs[i + 1];

            let issuer_pubkey = extract_p384_pubkey(issuer)?;
            let tbs_bytes = subject
                .tbs_certificate
                .to_der()
                .map_err(|e| EnclaveError::Certificate(format!("DER encode failed: {e}")))?;

            let sig_bytes = subject
                .signature
                .as_bytes()
                .ok_or_else(|| EnclaveError::Certificate("missing signature bytes".into()))?;

            let signature = Signature::from_der(sig_bytes)
                .map_err(|e| EnclaveError::Certificate(format!("invalid signature: {e}")))?;

            issuer_pubkey
                .verify(&tbs_bytes, &signature)
                .map_err(|_| EnclaveError::Certificate("certificate signature invalid".into()))?;
        }

        let chain_root = certs
            .last()
            .ok_or_else(|| EnclaveError::Certificate("empty certificate chain".into()))?;

        let chain_root_der = chain_root
            .to_der()
            .map_err(|e| EnclaveError::Certificate(format!("DER encode failed: {e}")))?;
        let expected_root_der = root_cert
            .to_der()
            .map_err(|e| EnclaveError::Certificate(format!("DER encode failed: {e}")))?;

        if chain_root_der != expected_root_der {
            return Err(EnclaveError::Certificate(
                "certificate chain does not terminate at AWS Nitro root CA".into(),
            ));
        }

        Ok(())
    }

    fn extract_p384_pubkey(cert: &Certificate) -> Result<VerifyingKey> {
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| EnclaveError::Certificate("missing public key bytes".into()))?;

        VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|e| EnclaveError::Certificate(format!("invalid P-384 key: {e}")))
    }

    fn verify_cert_validity(cert: &Certificate) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EnclaveError::Certificate("system clock error".into()))?
            .as_secs();

        let validity = &cert.tbs_certificate.validity;
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();

        if now < not_before {
            return Err(EnclaveError::Certificate("certificate not yet valid".into()));
        }
        if now > not_after {
            return Err(EnclaveError::Certificate("certificate has expired".into()));
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
                .map_err(|e| EnclaveError::Attestation(format!("invalid CBOR: {e}")))?;

            let arr = value
                .as_array()
                .ok_or_else(|| EnclaveError::Attestation("COSE_Sign1 must be array".into()))?;
            if arr.len() != 4 {
                return Err(EnclaveError::Attestation(
                    "COSE_Sign1 must have 4 elements".into(),
                ));
            }

            let protected = arr[0]
                .as_bytes()
                .ok_or_else(|| EnclaveError::Attestation("invalid protected header".into()))?
                .clone();
            let unprotected = arr[1].clone();
            let payload = if arr[2].is_null() {
                None
            } else {
                Some(
                    arr[2]
                        .as_bytes()
                        .ok_or_else(|| EnclaveError::Attestation("invalid payload".into()))?
                        .clone(),
                )
            };
            let signature = arr[3]
                .as_bytes()
                .ok_or_else(|| EnclaveError::Attestation("invalid signature".into()))?
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
                EnclaveError::Attestation(format!("failed to encode sig structure: {e}"))
            })?;
            Ok(buf)
        }
    }

    // NSM self-attestation (Linux only).
    #[cfg(target_os = "linux")]
    pub(super) fn request_nsm_attestation(
        nonce: &[u8; 32],
        public_key: Option<&[u8]>,
        user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

        let fd = nsm_init();
        if fd < 0 {
            return Err(EnclaveError::Attestation(
                "failed to initialize NSM".into(),
            ));
        }

        let request = Request::Attestation {
            user_data: user_data.map(|d| d.to_vec().into()),
            nonce: Some(nonce.to_vec().into()),
            public_key: public_key.map(|p| p.to_vec().into()),
        };

        let response = nsm_process_request(fd, request);
        nsm_exit(fd);

        match response {
            Response::Attestation { document } => Ok(document),
            Response::Error(e) => Err(EnclaveError::Attestation(format!(
                "NSM attestation failed: {:?}",
                e
            ))),
            _ => Err(EnclaveError::Attestation(
                "unexpected NSM response".into(),
            )),
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn read_own_pcrs() -> Result<ExpectedPcrs> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

        let fd = nsm_init();
        if fd < 0 {
            return Err(EnclaveError::Attestation(
                "failed to initialize NSM".into(),
            ));
        }

        let mut read = |index: u16| -> Result<[u8; 48]> {
            let response = nsm_process_request(fd, Request::DescribePCR { index });
            match response {
                Response::DescribePCR { lock: _, data } => data
                    .as_slice()
                    .try_into()
                    .map_err(|_| EnclaveError::Attestation(format!("PCR{index} wrong length"))),
                Response::Error(e) => Err(EnclaveError::Attestation(format!(
                    "PCR{index} read failed: {:?}",
                    e
                ))),
                _ => Err(EnclaveError::Attestation(format!(
                    "PCR{index} unexpected NSM response",
                ))),
            }
        };

        let pcr0 = read(0)?;
        let pcr1 = read(1)?;
        let pcr2 = read(2)?;
        nsm_exit(fd);
        Ok(ExpectedPcrs::new(pcr0, pcr1, pcr2))
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn request_nsm_attestation(
        _nonce: &[u8; 32],
        _public_key: Option<&[u8]>,
        _user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Err(EnclaveError::Attestation(
            "NSM not available on this platform".into(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn read_own_pcrs() -> Result<ExpectedPcrs> {
        Err(EnclaveError::Attestation(
            "NSM not available on this platform".into(),
        ))
    }
}

// ----------------------------------------------------------------------------
// Mock path (raw CBOR, no COSE / cert chain)
// ----------------------------------------------------------------------------

#[cfg(feature = "mock-attestation")]
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
        ciborium::into_writer(&doc, &mut buf).map_err(|e| {
            EnclaveError::Attestation(format!("failed to encode mock doc: {e}"))
        })?;
        Ok(buf)
    }

    pub(super) fn verify_mock_document(
        doc: &[u8],
        expected_pcrs: &ExpectedPcrs,
        expected_nonce: &[u8; 32],
    ) -> Result<VerifiedAttestation> {
        let attestation: AttestationDocument = ciborium::from_reader(doc)
            .map_err(|e| EnclaveError::Attestation(format!("failed to parse mock doc: {e}")))?;

        let nonce = check_nonce(&attestation.nonce, expected_nonce)?;
        verify_pcrs(&attestation.pcrs, expected_pcrs)?;

        let enclave_pubkey = attestation
            .public_key
            .ok_or_else(|| EnclaveError::Attestation("missing public key".into()))?;

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

    #[cfg(feature = "mock-attestation")]
    mod mock_flow {
        use super::*;

        #[test]
        fn mock_roundtrip_happy_path() {
            let nonce = [7u8; 32];
            let pubkey = [1u8; 32];
            let doc = get_attestation(&nonce, Some(&pubkey), Some(b"user")).unwrap();

            let verified = verify_peer_attestation(&doc, &ExpectedPcrs::zero(), &nonce).unwrap();

            assert_eq!(verified.enclave_pubkey, pubkey.to_vec());
            assert_eq!(verified.user_data.as_deref(), Some(b"user".as_ref()));
            assert_eq!(verified.nonce, nonce.to_vec());
            assert_eq!(verified.pcrs.get(&0).unwrap().len(), 48);
        }

        #[test]
        fn mock_reject_nonce_mismatch() {
            let nonce = [1u8; 32];
            let other = [2u8; 32];
            let doc = get_attestation(&nonce, Some(&[0u8; 32]), None).unwrap();
            let err = verify_peer_attestation(&doc, &ExpectedPcrs::zero(), &other).unwrap_err();
            assert!(matches!(err, EnclaveError::Attestation(_)));
        }

        #[test]
        fn mock_reject_pcr_mismatch() {
            let nonce = [3u8; 32];
            let doc = get_attestation(&nonce, Some(&[0u8; 32]), None).unwrap();
            let expected = ExpectedPcrs::new([1u8; 48], [0u8; 48], [0u8; 48]);
            let err = verify_peer_attestation(&doc, &expected, &nonce).unwrap_err();
            assert!(matches!(
                err,
                EnclaveError::PcrMismatch { pcr: 0, .. }
            ));
        }

        #[test]
        fn mock_reject_missing_pubkey() {
            let nonce = [4u8; 32];
            let doc = get_attestation(&nonce, None, None).unwrap();
            let err = verify_peer_attestation(&doc, &ExpectedPcrs::zero(), &nonce).unwrap_err();
            assert!(matches!(err, EnclaveError::Attestation(_)));
        }

        #[test]
        fn mock_reject_corrupted_doc() {
            let err =
                verify_peer_attestation(&[0xffu8; 16], &ExpectedPcrs::zero(), &[0u8; 32])
                    .unwrap_err();
            assert!(matches!(err, EnclaveError::Attestation(_)));
        }

        #[test]
        fn get_own_pcrs_mock_returns_zero() {
            let pcrs = get_own_pcrs().unwrap();
            assert_eq!(pcrs.pcr0, [0u8; 48]);
            assert_eq!(pcrs.pcr1, [0u8; 48]);
            assert_eq!(pcrs.pcr2, [0u8; 48]);
        }
    }
}
