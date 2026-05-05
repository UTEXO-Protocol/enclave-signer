use std::time::Duration;

use crate::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, EvmSignatureResponse,
    GetLastSavedBlockRequest, GetLastSavedBlockResponse, GetPublicKeyRequest, InitializeKeyRequest,
    InitializeKeyResponse, PublicKeysResponse, RawSignatureResponse, SignEvmRequest,
    SignPsbtRequest, SignRawMessageRequest, SignedPsbtResponse, SubmitHeadersRequest,
    SubmitHeadersResponse,
};
use crate::error::{ParentError, Result};
use crate::framing;

/// Connect timeout. Localhost connect resolves in microseconds; this is
/// only relevant when reaching across a network (or through a mis-routed
/// vsock proxy).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Read timeout for the response. Without this, an unrelated peer that
/// accepts the TCP connection but never speaks our wire protocol (the
/// classic case being macOS AirPlay Receiver hijacking port 5000) makes
/// the CLI hang forever instead of failing fast. Enclave operations that
/// could legitimately take a while (key generation, RGB consignment
/// validation against Esplora) still need to fit inside this budget.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

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
            use std::net::{TcpStream, ToSocketAddrs};
            let socket_addr = self
                .addr
                .to_socket_addrs()
                .map_err(|e| ParentError::Connection(format!("resolve {}: {}", self.addr, e)))?
                .next()
                .ok_or_else(|| {
                    ParentError::Connection(format!("no addresses for {}", self.addr))
                })?;
            let mut stream = TcpStream::connect_timeout(&socket_addr, CONNECT_TIMEOUT)
                .map_err(|e| ParentError::Connection(e.to_string()))?;
            stream
                .set_read_timeout(Some(READ_TIMEOUT))
                .map_err(|e| ParentError::Connection(format!("set_read_timeout: {e}")))?;
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

    pub fn get_last_saved_block(&self) -> Result<GetLastSavedBlockResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::GetLastSavedBlock(
                GetLastSavedBlockRequest {},
            )),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::GetLastSavedBlock(r)) => Ok(r),
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

    pub fn submit_headers(
        &self,
        start_height: u32,
        headers: Vec<Vec<u8>>,
    ) -> Result<SubmitHeadersResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::SubmitHeaders(
                SubmitHeadersRequest {
                    headers,
                    start_height,
                },
            )),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::SubmitHeaders(r)) => Ok(r),
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
