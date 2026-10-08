//! AWS Nitro Enclave attestation, enclave side.
//!
//! Production gets attestation documents and the enclave's own PCRs from the
//! NSM device (`/dev/nsm`).
//!
//! Peer verification uses the `attestation-verify` crate. Cloning, tests and
//! the `attest-verify` CLI share that code.
//!
//! Mock mode (`mock-attestation`): raw CBOR documents with all-zero PCR0/1/2,
//! [`attestation_verify::MOCK_PCR3`] and no COSE. Testing only.

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

/// Read the enclave's own PCR3: the measurement of the parent instance IAM
/// role. All zero when the instance has no role. Clone peers must have the
/// same value ([`check_clone_peer_pcr3`]).
pub fn get_own_pcr3() -> Result<[u8; 48]> {
    #[cfg(feature = "mock-attestation")]
    {
        Ok(attestation_verify::MOCK_PCR3)
    }

    #[cfg(all(target_os = "linux", not(feature = "mock-attestation")))]
    {
        nsm::read_own_pcr(3)
    }

    #[cfg(all(not(target_os = "linux"), not(feature = "mock-attestation")))]
    {
        Err(EnclaveError::Attestation(
            "NSM not available on this platform; enable mock-attestation for dev builds".into(),
        ))
    }
}

/// The clone-peer rule. PCR0/1/2 are the same for each instance of the
/// published image, so they alone accept a peer that runs under another AWS
/// account. PCR3 binds the peer to the IAM role of this enclave's parent.
///
/// Refuses if this enclave's own PCR3 is all zero (no IAM role: nothing to
/// bind to), if the peer document has no PCR3, or if the two differ.
pub fn check_clone_peer_pcr3(own_pcr3: &[u8; 48], peer: &VerifiedAttestation) -> Result<()> {
    if own_pcr3.iter().all(|&b| b == 0) {
        return Err(EnclaveError::Attestation(
            "this enclave's PCR3 is all zero: the parent instance has no IAM role, so a clone \
             peer cannot be bound to the operator account - refusing to clone"
                .into(),
        ));
    }
    let actual = peer.pcrs.get(&3).ok_or_else(|| {
        EnclaveError::Attestation("the peer attestation has no PCR3 - refusing to clone".into())
    })?;
    if actual.as_slice() != own_pcr3 {
        return Err(EnclaveError::PcrMismatch {
            pcr: 3,
            expected: hex::encode(own_pcr3),
            actual: hex::encode(actual),
        });
    }
    Ok(())
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

    /// Read one PCR of this enclave.
    pub(super) fn read_own_pcr(index: u16) -> Result<[u8; 48]> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(EnclaveError::Attestation("failed to initialize NSM".into()));
        }
        let response = nsm_process_request(fd, Request::DescribePCR { index });
        nsm_exit(fd);
        match response {
            Response::DescribePCR { lock: _, data } => data
                .as_slice()
                .try_into()
                .map_err(|_| EnclaveError::Attestation(format!("PCR{index} wrong length"))),
            Response::Error(e) => Err(EnclaveError::Attestation(format!(
                "PCR{index} read failed: {e:?}"
            ))),
            _ => Err(EnclaveError::Attestation(format!(
                "PCR{index} unexpected NSM response",
            ))),
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

#[cfg(test)]
mod clone_peer_pcr3 {
    use super::*;
    use std::collections::HashMap;

    fn peer(pcr3: Option<[u8; 48]>) -> VerifiedAttestation {
        let mut pcrs = HashMap::new();
        for idx in 0..3 {
            pcrs.insert(idx, vec![0u8; 48]);
        }
        if let Some(pcr3) = pcr3 {
            pcrs.insert(3, pcr3.to_vec());
        }
        VerifiedAttestation {
            enclave_pubkey: vec![1; 32],
            pcrs,
            timestamp: 0,
            user_data: None,
            nonce: vec![0; 32],
        }
    }

    const ROLE_A: [u8; 48] = [0x33; 48];
    const ROLE_B: [u8; 48] = [0x44; 48];

    #[test]
    fn accepts_a_peer_under_the_same_role() {
        assert!(check_clone_peer_pcr3(&ROLE_A, &peer(Some(ROLE_A))).is_ok());
    }

    #[test]
    fn refuses_a_peer_under_another_role() {
        let err = check_clone_peer_pcr3(&ROLE_A, &peer(Some(ROLE_B))).unwrap_err();
        assert!(
            matches!(err, EnclaveError::PcrMismatch { pcr: 3, .. }),
            "{err}"
        );
    }

    #[test]
    fn refuses_a_peer_without_pcr3() {
        let err = check_clone_peer_pcr3(&ROLE_A, &peer(None)).unwrap_err();
        assert!(err.to_string().contains("no PCR3"), "{err}");
    }

    #[test]
    fn refuses_a_peer_with_an_all_zero_pcr3() {
        assert!(check_clone_peer_pcr3(&ROLE_A, &peer(Some([0; 48]))).is_err());
    }

    /// An enclave on an instance with no IAM role refuses each peer, even
    /// one that also has no role.
    #[test]
    fn refuses_when_this_enclave_has_no_role() {
        let err = check_clone_peer_pcr3(&[0; 48], &peer(Some([0; 48]))).unwrap_err();
        assert!(err.to_string().contains("no IAM role"), "{err}");
    }
}
