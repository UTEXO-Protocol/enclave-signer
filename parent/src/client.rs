use std::time::Duration;

use crate::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, EvmSignatureResponse,
    GetLastSavedBlockRequest, GetLastSavedBlockResponse, GetPublicKeyRequest, InitializeKeyRequest,
    InitializeKeyResponse, InitiateCloningRequest, InitiateCloningResponse, PublicKeysResponse,
    RawSignatureResponse, SetCloneRequest, SignEvmRequest, SignPsbtRequest, SignRawMessageRequest,
    SignedPsbtResponse, SubmitHeadersRequest, SubmitHeadersResponse,
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
            let cid = std::env::var("ENCLAVE_VSOCK_CID")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(16);
            let port = std::env::var("ENCLAVE_VSOCK_PORT")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(5000);

            let mut stream = VsockStream::connect_with_cid_port(cid, port)
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
        self.initialize_keys_inner(seed, None, None)
    }

    /// Initialize a donor enclave and configure its cloning secret in one
    /// message, so the secret is delivered at runtime (never baked into the EIF).
    pub fn initialize_keys_with_secret(
        &self,
        seed: Option<Vec<u8>>,
        cloning_secret: Option<String>,
    ) -> Result<InitializeKeyResponse> {
        self.initialize_keys_inner(seed, None, cloning_secret)
    }

    pub fn initialize_keys_mnemonic(&self, mnemonic: &str) -> Result<InitializeKeyResponse> {
        self.initialize_keys_inner(None, Some(mnemonic.to_string()), None)
    }

    fn initialize_keys_inner(
        &self,
        seed: Option<Vec<u8>>,
        mnemonic: Option<String>,
        cloning_secret: Option<String>,
    ) -> Result<InitializeKeyResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::InitializeKey(
                InitializeKeyRequest {
                    seed: seed.unwrap_or_default(),
                    mnemonic: mnemonic.unwrap_or_default(),
                    cloning_secret: cloning_secret.unwrap_or_default(),
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

    /// Requester side, step 1 of cloning. Asks the local enclave to enter the
    /// Cloning phase: it mints an ephemeral X25519 keypair, computes the
    /// cloning digest from the operator secret, and returns an NSM attestation
    /// binding both. The digest is returned so the orchestrator can forward it
    /// to the donor (the secret itself never leaves this enclave).
    pub fn initiate_cloning(
        &self,
        cloning_secret: &str,
        cluster_public_key: Vec<u8>,
    ) -> Result<InitiateCloningResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::InitiateCloning(
                InitiateCloningRequest {
                    cloning_secret: cloning_secret.to_string(),
                    cluster_public_key,
                },
            )),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::InitiateCloning(r)) => Ok(r),
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

    /// Requester side, step 3 of cloning. Hands the donor's sealed seed +
    /// ephemeral pubkey + attestation to the local enclave. The enclave
    /// verifies the donor attestation, unseals the seed, and only commits the
    /// derived keys if the resulting EVM address matches the cluster identity it
    /// was told to clone. On success it transitions Cloning -> Active.
    pub fn set_clone(
        &self,
        encrypted_seed: Vec<u8>,
        donor_pubkey: Vec<u8>,
        donor_attestation: Vec<u8>,
    ) -> Result<()> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::SetClone(SetCloneRequest {
                encrypted_seed,
                donor_pubkey,
                donor_attestation,
            })),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::SetClone(_)) => Ok(()),
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
