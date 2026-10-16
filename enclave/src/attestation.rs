//! AWS Nitro Enclave attestation, enclave side.
//!
//! Production gets attestation documents and the enclave's own PCRs from the
//! NSM device (`/dev/nsm`).
//!
//! Peer verification uses the `attestation-verify` crate. Cloning, tests and
//! the `attest-verify` CLI share that code.
//!
//! Mock mode (`mock-attestation`): raw CBOR documents with all-zero PCRs and no
//! COSE. Testing only.

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

/// Produce an attestation document that binds `nonce`, `public_key` and
/// optional `user_data`.
///
/// Non-Linux builds without `mock-attestation` return an error.
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

/// Read the enclave's own PCR0/1/2. Peers with different PCRs are rejected.
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

/// Verify a peer attestation document with [`attestation_verify::verify_attestation`],
/// or with the mock verifier under `mock-attestation`.
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

        // AF-21: stop on the first read error and release the NSM fd on every path.
        let pcr0 = match read(0) {
            Ok(value) => value,
            Err(error) => {
                nsm_exit(fd);
                return Err(error);
            }
        };
        let pcr1 = match read(1) {
            Ok(value) => value,
            Err(error) => {
                nsm_exit(fd);
                return Err(error);
            }
        };
        let pcr2 = match read(2) {
            Ok(value) => value,
            Err(error) => {
                nsm_exit(fd);
                return Err(error);
            }
        };
        nsm_exit(fd);
        Ok(ExpectedPcrs::new(pcr0, pcr1, pcr2))
    }
}

// Facade tests only. attestation-verify tests the verifier.
// Both tests need the mock path.
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
