use std::time::Duration;

use crate::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, EvmSignatureResponse,
    GetLastSavedBlockRequest, GetLastSavedBlockResponse, GetPublicKeyRequest, HealthRequest,
    HealthResponse, InitializeKeyRequest, InitializeKeyResponse, InitiateCloningRequest,
    InitiateCloningResponse, MerkleProofEntry, PublicKeysResponse, SetCloneRequest,
    SetEndpointsRequest, SignedPsbtResponse,
};
use crate::error::{ParentError, Result};
use crate::framing;

/// TCP connect timeout. It matters only across a network or a bad vsock proxy.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP response read timeout. It stops a silent TCP peer from hanging the CLI.
/// The vsock path has no read timeout.
/// Slow valid operations (key generation, consignment validation) must fit in it.
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
    /// LZ fields for `lzFundsOutCall` releases. `None` for `fundsOutCall`.
    /// When set, the enclave uses the `TeeLzFundsOut` EIP-712 digest and
    /// checks these fields against the decoded calldata.
    pub lz_release: Option<crate::enclave_proto::LzReleaseParams>,
}

#[derive(Debug, Clone)]
pub struct SignPsbtRequest {
    pub evm_tx_hash: Vec<u8>,
    /// On-chain `BridgeFundsIn.operationId` (32 bytes). Required.
    /// Different from `operation_idx`, the RGB hub index. The replay key uses
    /// this full operation ID, not the hub index.
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

/// Parse a `vsock://` address body (`<cid>` or `<cid>:<port>`) into `(cid, port)`.
/// The port defaults to 5000. There is no default CID: on multi-enclave hosts
/// the caller must select the enclave.
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

#[derive(Clone)]
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
        // A `vsock://<cid>[:<port>]` address targets one enclave. Without vsock
        // support in the build, it is an error.
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
            // No `vsock://` address: read the env. Do not default to CID 16.
            // On a multi-enclave host that sends calls to the wrong enclave.
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
                    "vsock build: select the enclave explicitly - pass \
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

    /// Initialize a donor enclave and set its cloning secret in one message.
    /// The secret comes at runtime and is never in the EIF.
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

    /// Requester side, cloning step 1. The local enclave enters the Cloning
    /// phase. It makes an ephemeral X25519 keypair, computes the cloning
    /// digest from the operator secret, and returns an NSM attestation that
    /// binds both. The orchestrator sends the digest to the donor. The secret
    /// stays in this enclave.
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

    /// Requester side, final cloning step (SetClone). Sends the donor sealed
    /// seed, ephemeral public key and attestation to the local enclave. The
    /// enclave verifies the attestation and unseals the seed. It commits the
    /// keys only if the EVM address matches the cluster identity. On success:
    /// Cloning -> Active.
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
                                // The CLI cannot resolve the deposit behind
                                // a mint, so the enclave rejects a BFA burn
                                // signed through it.
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
                                // The CLI cannot resolve the deposits behind
                                // a chained mint, so the enclave rejects one.
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

    /// Readiness probe. Gives the enclave part of the parent `GET /health`
    /// report, for operators on the host shell.
    pub fn health(&self) -> Result<HealthResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::Health(HealthRequest {})),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::Health(r)) => Ok(r),
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

    /// Set the chain endpoints once, at launch. The enclave rejects a second
    /// call.
    pub fn set_endpoints(&self, req: SetEndpointsRequest) -> Result<()> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::SetEndpoints(req)),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::SetEndpoints(_)) => Ok(()),
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
