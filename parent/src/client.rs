use std::time::Duration;

use crate::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, EvmSignatureResponse,
    GetLastSavedBlockRequest, GetLastSavedBlockResponse, GetPublicKeyRequest, InitializeKeyRequest,
    InitializeKeyResponse, InitiateCloningRequest, InitiateCloningResponse, MerkleProofEntry,
    PublicKeysResponse, RawSignatureResponse, SetCloneRequest, SignRawMessageRequest,
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

#[derive(Debug, Clone)]
pub struct SignEvmRequest {
    pub call_data: Vec<u8>,
    pub nonce: u64,
    pub deadline: u64,
    pub consignment_valid: bool,
    pub rgb_amount: u64,
    pub rgb_asset_id: String,
    pub chain_id: u64,
    pub proxy_contract: Vec<u8>,
    pub calldata_amount: u64,
    pub calldata_commission: u64,
    pub consignment: Vec<u8>,
    pub consignment_hash: Vec<u8>,
    pub merkle_proofs: Vec<MerkleProofEntry>,
    /// LZ-specific fields for `lzFundsOutCall` releases. `None` for direct
    /// `fundsOutCall` releases. When set, the enclave routes to the
    /// `TeeLzFundsOut` EIP-712 digest and crosschecks these fields against
    /// the decoded calldata.
    pub lz_release: Option<crate::enclave_proto::LzReleaseParams>,
}

#[derive(Debug, Clone)]
pub struct SignPsbtRequest {
    pub evm_tx_hash: Vec<u8>,
    /// On-chain BridgeFundsIn.operationId, 32 bytes. Required by the enclave;
    /// distinct from `operation_idx` (the RGB hub index / replay-guard key).
    pub evm_funds_in_operation_id: Vec<u8>,
    pub operation_idx: u64,
    pub evm_event_valid: bool,
    pub evm_event_finalized: bool,
    pub evm_token: Vec<u8>,
    pub evm_amount: u64,
    pub evm_recipient: Vec<u8>,
    pub evm_commission: u64,
    pub psbt_bytes: Vec<u8>,
    pub psbt_output_amount: u64,
    pub rgb_asset_id: String,
    pub consignment: Vec<u8>,
    pub consignment_hash: Vec<u8>,
}

/// Parse a `vsock://` address body (`<cid>` or `<cid>:<port>`) into `(cid, port)`,
/// defaulting the port to 5000. Keeps enclave selection explicit on multi-enclave
/// hosts instead of silently using a default CID.
#[cfg(all(feature = "vsock", target_os = "linux"))]
fn parse_vsock_spec(spec: &str) -> Result<(u32, u32)> {
    let (cid_str, port_str) = match spec.split_once(':') {
        Some((c, p)) => (c, p),
        None => (spec, "5000"),
    };
    let cid = cid_str
        .parse::<u32>()
        .map_err(|_| ParentError::Connection(format!("invalid vsock cid in addr: {cid_str:?}")))?;
    let port = port_str.parse::<u32>().map_err(|_| {
        ParentError::Connection(format!("invalid vsock port in addr: {port_str:?}"))
    })?;
    Ok((cid, port))
}

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
        // A `vsock://<cid>[:<port>]` address explicitly targets one enclave and
        // works regardless of build features (errors if vsock isn't compiled in).
        if let Some(spec) = self.addr.strip_prefix("vsock://") {
            #[cfg(all(feature = "vsock", target_os = "linux"))]
            {
                let (cid, port) = parse_vsock_spec(spec)?;
                return self.send_vsock(req, cid, port);
            }
            #[cfg(not(all(feature = "vsock", target_os = "linux")))]
            {
                return Err(ParentError::Connection(format!(
                    "addr `vsock://{spec}` requests vsock, but this binary was built \
                     without vsock support (needs feature `vsock` on Linux)"
                )));
            }
        }

        #[cfg(all(feature = "vsock", target_os = "linux"))]
        {
            // No `vsock://` address: fall back to env for back-compat, but DO NOT
            // silently default to CID 16 — on a multi-enclave host that routes
            // every call to the wrong enclave (init/sign on the wrong identity).
            let cid = std::env::var("ENCLAVE_VSOCK_CID")
                .ok()
                .and_then(|v| v.parse::<u32>().ok());
            let port = std::env::var("ENCLAVE_VSOCK_PORT")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(5000);
            match cid {
                Some(cid) => self.send_vsock(req, cid, port),
                None => Err(ParentError::Connection(
                    "vsock build: select the enclave explicitly — pass \
                     `--addr vsock://<cid>:<port>` (e.g. vsock://16:5000) or set \
                     ENCLAVE_VSOCK_CID. Refusing to default to CID 16."
                        .to_string(),
                )),
            }
        }
        #[cfg(not(all(feature = "vsock", target_os = "linux")))]
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

    #[cfg(feature = "vsock")]
    fn send_vsock(&self, req: &EnclaveRequest, cid: u32, port: u32) -> Result<EnclaveResponse> {
        use vsock::VsockStream;
        let mut stream = VsockStream::connect_with_cid_port(cid, port).map_err(|e| {
            ParentError::Connection(format!("vsock connect cid={cid} port={port}: {e}"))
        })?;
        framing::write_message(&mut stream, req)?;
        framing::read_message(&mut stream)
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
            request: Some(enclave_request::Request::Sign(
                crate::enclave_proto::SignRequest {
                    amount: req.rgb_amount,
                    source_network: Some(
                        crate::enclave_proto::sign_request::SourceNetwork::RgbSource(
                            crate::enclave_proto::RgbSource {
                                consignment_valid: req.consignment_valid,
                                asset_id: req.rgb_asset_id,
                                consignment: req.consignment,
                                consignment_hash: req.consignment_hash,
                                commission: req.calldata_commission,
                                merkle_proofs: req.merkle_proofs,
                            },
                        ),
                    ),
                    destination_network: Some(
                        crate::enclave_proto::sign_request::DestinationNetwork::EvmDestination(
                            crate::enclave_proto::EvmDestination {
                                call_data: req.call_data,
                                nonce: req.nonce,
                                deadline: req.deadline,
                                chain_id: req.chain_id,
                                proxy_contract: req.proxy_contract,
                                calldata_amount: req.calldata_amount,
                                calldata_commission: req.calldata_commission,
                                lz_release: req.lz_release,
                            },
                        ),
                    ),
                },
            )),
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
            request: Some(enclave_request::Request::Sign(
                crate::enclave_proto::SignRequest {
                    amount: req.evm_amount,
                    source_network: Some(
                        crate::enclave_proto::sign_request::SourceNetwork::EvmSource(
                            crate::enclave_proto::EvmSource {
                                tx_hash: req.evm_tx_hash,
                                event_valid: req.evm_event_valid,
                                event_finalized: req.evm_event_finalized,
                                token: req.evm_token,
                                recipient: req.evm_recipient,
                                commission: req.evm_commission,
                                funds_in_operation_id: req.evm_funds_in_operation_id,
                            },
                        ),
                    ),
                    destination_network: Some(
                        crate::enclave_proto::sign_request::DestinationNetwork::RgbDestination(
                            crate::enclave_proto::RgbDestination {
                                operation_idx: req.operation_idx,
                                psbt_bytes: req.psbt_bytes,
                                psbt_output_amount: req.psbt_output_amount,
                                asset_id: req.rgb_asset_id,
                                consignment: req.consignment,
                                consignment_hash: req.consignment_hash,
                            },
                        ),
                    ),
                },
            )),
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
