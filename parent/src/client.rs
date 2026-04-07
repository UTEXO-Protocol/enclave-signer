use std::net::TcpStream;

use crate::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, EvmSignatureResponse,
    GetPublicKeyRequest, InitializeKeyRequest, InitializeKeyResponse, PublicKeysResponse,
    RawSignatureResponse, SignEvmRequest, SignPsbtRequest, SignRawMessageRequest,
    SignedPsbtResponse,
};
use crate::error::{ParentError, Result};
use crate::framing;

pub struct EnclaveClient {
    addr: String,
}

impl EnclaveClient {
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
        }
    }

    pub fn send_request(&self, req: &EnclaveRequest) -> Result<EnclaveResponse> {
        #[cfg(feature = "vsock")]
        {
            use vsock::VsockStream;
            let mut stream = VsockStream::connect_with_cid_port(16, 5000)
                .map_err(|e| ParentError::Connection(e.to_string()))?;
            framing::write_message(&mut stream, req)?;
            framing::read_message(&mut stream)
        }
        #[cfg(not(feature = "vsock"))]
        {
            let mut stream = TcpStream::connect(&self.addr)
                .map_err(|e| ParentError::Connection(e.to_string()))?;
            framing::write_message(&mut stream, req)?;
            framing::read_message(&mut stream)
        }
    }

    pub fn initialize_keys(&self, seed: Option<Vec<u8>>) -> Result<InitializeKeyResponse> {
        self.initialize_keys_inner(seed, None)
    }

    pub fn initialize_keys_mnemonic(&self, mnemonic: &str) -> Result<InitializeKeyResponse> {
        self.initialize_keys_inner(None, Some(mnemonic.to_string()))
    }

    fn initialize_keys_inner(
        &self,
        seed: Option<Vec<u8>>,
        mnemonic: Option<String>,
    ) -> Result<InitializeKeyResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::InitializeKey(
                InitializeKeyRequest {
                    seed: seed.unwrap_or_default(),
                    mnemonic: mnemonic.unwrap_or_default(),
                },
            )),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::InitializeKey(r)) => Ok(r),
            Some(enclave_response::Response::Error(e)) => Err(ParentError::EnclaveError {
                code: e.code,
                message: e.message,
            }),
            other => Err(ParentError::Connection(format!(
                "unexpected response variant: {:?}",
                other
            ))),
        }
    }

    pub fn get_public_keys(&self) -> Result<PublicKeysResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::GetPublicKey(
                GetPublicKeyRequest {},
            )),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::PublicKeys(r)) => Ok(r),
            Some(enclave_response::Response::Error(e)) => Err(ParentError::EnclaveError {
                code: e.code,
                message: e.message,
            }),
            other => Err(ParentError::Connection(format!(
                "unexpected response variant: {:?}",
                other
            ))),
        }
    }

    pub fn sign_evm(&self, req: SignEvmRequest) -> Result<EvmSignatureResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::SignEvm(req)),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::EvmSignature(r)) => Ok(r),
            Some(enclave_response::Response::Error(e)) => Err(ParentError::EnclaveError {
                code: e.code,
                message: e.message,
            }),
            other => Err(ParentError::Connection(format!(
                "unexpected response variant: {:?}",
                other
            ))),
        }
    }

    pub fn sign_psbt(&self, req: SignPsbtRequest) -> Result<SignedPsbtResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::SignPsbt(req)),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::SignedPsbt(r)) => Ok(r),
            Some(enclave_response::Response::Error(e)) => Err(ParentError::EnclaveError {
                code: e.code,
                message: e.message,
            }),
            other => Err(ParentError::Connection(format!(
                "unexpected response variant: {:?}",
                other
            ))),
        }
    }

    pub fn sign_raw_message(&self, message: Vec<u8>) -> Result<RawSignatureResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::SignRawMessage(
                SignRawMessageRequest { message },
            )),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::RawSignature(r)) => Ok(r),
            Some(enclave_response::Response::Error(e)) => Err(ParentError::EnclaveError {
                code: e.code,
                message: e.message,
            }),
            other => Err(ParentError::Connection(format!(
                "unexpected response variant: {:?}",
                other
            ))),
        }
    }
}
