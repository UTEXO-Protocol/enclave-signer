//! AWS Nitro Enclave attestation - enclave-side facade.
//!
//! Production: requests attestation documents from the NSM device
//! (`/dev/nsm`) via `aws-nitro-enclaves-nsm-api` and reads the enclave's
//! own PCRs at startup.
//!
//! Verification (peer attestation, both real and mock): delegated to the
//! workspace `attestation-verify` crate so the same code path is exercised
//! by the cloning flow, by tests, and by the external `attest-verify` CLI.
//!
//! Mock mode (`mock-attestation` feature): documents are raw CBOR with
//! all-zero PCRs and no COSE wrapping. Testing only.

#![allow(dead_code)]

use crate::error::{EnclaveError, Result};

pub use attestation_verify::{ExpectedPcrs, VerifiedAttestation};

impl From<attestation_verify::VerifyError> for EnclaveError {
    fn from(e: attestation_verify::VerifyError) -> Self {
        match e {
            attestation_verify::VerifyError::Attestation(s) => EnclaveError::Attestation(s),
            attestation_verify::VerifyError::Certificate(s) => EnclaveError::Certificate(s),
            attestation_verify::VerifyError::PcrMismatch {
                pcr,
                expected,
                actual,
            } => EnclaveError::PcrMismatch {
                pcr,
                expected,
                actual,
            },
        }
    }
}

/// Produce an attestation document binding `nonce`, `public_key`, and optional
/// `user_data`. The returned bytes are what we hand to peers (or external
/// verifiers) over the wire.
///
/// Real path (Linux + no mock): calls the NSM device.
/// Mock path (`mock-attestation` feature): returns a raw CBOR document with
/// all-zero PCRs. Non-Linux builds without `mock-attestation` will fail.
pub fn get_attestation(
    nonce: &[u8; 32],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    #[cfg(feature = "mock-attestation")]
    {
        attestation_verify::build_mock_document(nonce, public_key, user_data).map_err(Into::into)
    }

    #[cfg(all(target_os = "linux", not(feature = "mock-attestation")))]
    {
        nsm::request_nsm_attestation(nonce, public_key, user_data)
    }

    #[cfg(all(not(target_os = "linux"), not(feature = "mock-attestation")))]
    {
        let _ = (nonce, public_key, user_data);
        Err(EnclaveError::Attestation(
            "attestation not available: build for Linux with NSM or enable mock-attestation".into(),
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
        nsm::read_own_pcrs()
    }

    #[cfg(all(not(target_os = "linux"), not(feature = "mock-attestation")))]
    {
        Err(EnclaveError::Attestation(
            "NSM not available on this platform; enable mock-attestation for dev builds".into(),
        ))
    }
}

/// Verify a peer attestation document. See [`attestation_verify::verify_attestation`]
/// for the real path; under `mock-attestation` the mock verifier is used.
pub fn verify_peer_attestation(
    doc: &[u8],
    expected_pcrs: &ExpectedPcrs,
    expected_nonce: Option<&[u8; 32]>,
) -> Result<VerifiedAttestation> {
    #[cfg(feature = "mock-attestation")]
    {
        attestation_verify::verify_mock_attestation(doc, expected_pcrs, expected_nonce)
            .map_err(Into::into)
    }

    #[cfg(not(feature = "mock-attestation"))]
    {
        attestation_verify::verify_attestation(doc, expected_pcrs, expected_nonce)
            .map_err(Into::into)
    }
}

// NSM device interaction (Linux only, production path)

#[cfg(all(target_os = "linux", not(feature = "mock-attestation")))]
mod nsm {
    use super::*;
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    pub(super) fn request_nsm_attestation(
        nonce: &[u8; 32],
        public_key: Option<&[u8]>,
        user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(EnclaveError::Attestation("failed to initialize NSM".into()));
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
            _ => Err(EnclaveError::Attestation("unexpected NSM response".into())),
        }
    }

    pub(super) fn read_own_pcrs() -> Result<ExpectedPcrs> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(EnclaveError::Attestation("failed to initialize NSM".into()));
        }

        let read = |index: u16| -> Result<[u8; 48]> {
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
}

// Tests - facade-level only. The verifier itself is tested in attestation-verify.

// Both tests below need the mock-attestation path; gate the whole module
// so the `use super::*` doesn't fire `unused_imports` when building without
// `--features mock-attestation` (CI runs both feature combinations).
#[cfg(all(test, feature = "mock-attestation"))]
mod tests {
    use super::*;

    #[test]
    fn facade_mock_roundtrip() {
        let nonce = [7u8; 32];
        let pubkey = [1u8; 32];
        let doc = get_attestation(&nonce, Some(&pubkey), Some(b"user")).unwrap();

        let verified = verify_peer_attestation(&doc, &ExpectedPcrs::zero(), Some(&nonce)).unwrap();

        assert_eq!(verified.enclave_pubkey, pubkey.to_vec());
        assert_eq!(verified.user_data.as_deref(), Some(b"user".as_ref()));
        assert_eq!(verified.nonce, nonce.to_vec());
    }

    #[test]
    fn facade_get_own_pcrs_returns_zero_in_mock() {
        let pcrs = get_own_pcrs().unwrap();
        assert_eq!(pcrs.pcr0, [0u8; 48]);
    }
}

// The real NSM path outside an enclave: `/dev/nsm` is absent on every CI
// runner and developer machine, so the facade must surface a clean error
// rather than panic or return a document.
#[cfg(all(test, not(feature = "mock-attestation"), target_os = "linux"))]
mod real_path_tests {
    use super::*;

    #[test]
    fn get_attestation_without_an_nsm_device_fails_closed() {
        let err = get_attestation(&[1u8; 32], Some(&[2u8; 32]), None).unwrap_err();
        assert!(matches!(err, EnclaveError::Attestation(_)), "{err}");
        assert!(err.to_string().contains("NSM"), "{err}");
    }

    #[test]
    fn get_own_pcrs_without_an_nsm_device_fails_closed() {
        let err = get_own_pcrs().unwrap_err();
        assert!(matches!(err, EnclaveError::Attestation(_)), "{err}");
    }

    #[test]
    fn verify_peer_attestation_uses_the_real_cose_verifier() {
        // A raw-CBOR mock-style map is not a COSE_Sign1 array, so the real
        // verifier rejects it: a mock document can never pass a real build.
        let mut buf = Vec::new();
        ciborium_map_into(&mut buf);
        let err = verify_peer_attestation(&buf, &ExpectedPcrs::zero(), None).unwrap_err();
        assert!(matches!(err, EnclaveError::Attestation(_)), "{err}");
        assert!(err.to_string().contains("must be array"), "{err}");
        let err = verify_peer_attestation(&[], &ExpectedPcrs::zero(), None).unwrap_err();
        assert!(matches!(err, EnclaveError::Attestation(_)), "{err}");
    }

    /// CBOR `{}` without pulling ciborium into the enclave crate's deps.
    fn ciborium_map_into(buf: &mut Vec<u8>) {
        buf.push(0xa0);
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use super::*;

    #[test]
    fn expected_pcrs_reexport_is_the_verifier_type() {
        let p = ExpectedPcrs::new([1u8; 48], [2u8; 48], [3u8; 48]);
        let q: attestation_verify::ExpectedPcrs = p.clone();
        assert_eq!(q.pcr2, [3u8; 48]);
    }

    #[test]
    fn verify_errors_keep_their_category_and_text() {
        let e: EnclaveError = attestation_verify::VerifyError::Certificate("chain".into()).into();
        assert_eq!(e.to_string(), "certificate error: chain");
        assert_eq!(e.error_code(), 1);
        let e: EnclaveError = attestation_verify::VerifyError::Attestation("nonce".into()).into();
        assert_eq!(e.to_string(), "attestation error: nonce");
    }
}
