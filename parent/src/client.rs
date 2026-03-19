use std::net::TcpStream;

use crate::error::{ParentError, Result};
use crate::framing;
use crate::proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, GetPublicKeyRequest,
    InitializeKeyRequest, InitializeKeyResponse, PublicKeysResponse,
};

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
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::InitializeKey(
                InitializeKeyRequest {
                    seed: seed.unwrap_or_default(),
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
}
