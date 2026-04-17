use std::time::Duration;

use prost::Message as ProstMessage;
use tonic::{Request, Response, Status};

use crate::enclave_proto::{
    self, enclave_request, enclave_response, EnclaveRequest, EnclaveResponse,
};
use crate::enriched;

const ENCLAVE_TIMEOUT: Duration = Duration::from_secs(30);
use crate::grpc_proto::enclave_service_server::EnclaveService;
use crate::grpc_proto::{
    CloneRequest, CloneResponse, DataType, InitializeRequest, InitializeResponse, PublicKeyRequest,
    PublicKeyResponse, SignRequest, Signature,
};

/// Enclave connection target — either TCP address or vsock CID+port.
#[derive(Clone)]
pub enum EnclaveTarget {
    Tcp(String),
    #[cfg(target_os = "linux")]
    Vsock {
        cid: u32,
        port: u32,
    },
}

/// gRPC server that translates the federated-signer-node's listener-enclave.proto
/// RPCs into enclave.proto wire-protocol requests over TCP/vsock.
#[derive(Clone)]
pub struct ParentAdapterService {
    target: EnclaveTarget,
}

impl ParentAdapterService {
    pub fn new(target: EnclaveTarget) -> Self {
        Self { target }
    }

    /// Send an EnclaveRequest to the enclave and read the EnclaveResponse.
    /// Runs blocking I/O on a spawn_blocking thread.
    async fn send_to_enclave(&self, req: EnclaveRequest) -> Result<EnclaveResponse, Status> {
        let target = self.target.clone();

        let result = tokio::time::timeout(
            ENCLAVE_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                use crate::framing;

                match target {
                    EnclaveTarget::Tcp(addr) => {
                        let mut stream = std::net::TcpStream::connect(&addr).map_err(|e| {
                            Status::unavailable(format!("enclave connection failed: {e}"))
                        })?;
                        stream.set_read_timeout(Some(ENCLAVE_TIMEOUT)).ok();
                        framing::write_message(&mut stream, &req)
                            .map_err(|e| Status::internal(format!("enclave write failed: {e}")))?;
                        let resp: EnclaveResponse = framing::read_message(&mut stream)
                            .map_err(|e| Status::internal(format!("enclave read failed: {e}")))?;
                        Ok(resp)
                    }
                    #[cfg(target_os = "linux")]
                    EnclaveTarget::Vsock { cid, port } => {
                        let mut stream = vsock::VsockStream::connect_with_cid_port(cid, port)
                            .map_err(|e| {
                                Status::unavailable(format!("enclave vsock connection failed: {e}"))
                            })?;
                        framing::write_message(&mut stream, &req)
                            .map_err(|e| Status::internal(format!("enclave write failed: {e}")))?;
                        let resp: EnclaveResponse = framing::read_message(&mut stream)
                            .map_err(|e| Status::internal(format!("enclave read failed: {e}")))?;
                        Ok(resp)
                    }
                }
            }),
        )
        .await;

        match result {
            Ok(join_result) => join_result
                .map_err(|e| Status::internal(format!("spawn_blocking join failed: {e}")))?,
            Err(_) => Err(Status::deadline_exceeded("enclave request timed out (30s)")),
        }
    }

    /// Unwrap an enclave error response into a gRPC Status.
    fn enclave_error_to_status(err: &enclave_proto::ErrorResponse) -> Status {
        match err.code {
            3 => Status::failed_precondition(err.message.clone()),
            _ => Status::internal(format!(
                "enclave error (code {}): {}",
                err.code, err.message
            )),
        }
    }
}

#[tonic::async_trait]
impl EnclaveService for ParentAdapterService {
    /// Sign — dispatches based on data_type:
    ///   TRANSACTION → deserialize EnrichedPsbtPayload → SignPsbtRequest
    ///   SWAP        → deserialize EnrichedEvmPayload  → SignEvmRequest
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<Signature>, Status> {
        let inner = request.into_inner();

        let data_type = DataType::try_from(inner.data_type).unwrap_or(DataType::Transaction);

        let enclave_req = match data_type {
            DataType::Transaction => {
                // Deserialize enriched PSBT payload from data bytes
                let payload = enriched::EnrichedPsbtPayload::decode(inner.data.as_slice())
                    .map_err(|e| {
                        Status::invalid_argument(format!(
                            "failed to decode EnrichedPsbtPayload: {e}"
                        ))
                    })?;

                tracing::info!(
                    psbt_len = payload.psbt_bytes.len(),
                    has_tx_hash = !payload.evm_tx_hash.is_empty(),
                    operation_idx = payload.operation_idx,
                    "gRPC Sign: PSBT (data_type=TRANSACTION)"
                );

                EnclaveRequest {
                    request: Some(enclave_request::Request::SignPsbt(
                        enclave_proto::SignPsbtRequest {
                            psbt_bytes: payload.psbt_bytes,
                            evm_tx_hash: payload.evm_tx_hash,
                            operation_idx: payload.operation_idx,
                            evm_event_valid: payload.evm_event_valid,
                            evm_event_finalized: payload.evm_event_finalized,
                            evm_token: payload.evm_token,
                            evm_amount: payload.evm_amount,
                            evm_recipient: payload.evm_recipient,
                            evm_commission: payload.evm_commission,
                            psbt_output_amount: payload.psbt_output_amount,
                            rgb_asset_id: payload.rgb_asset_id,
                        },
                    )),
                }
            }
            DataType::Swap => {
                // Deserialize enriched EVM payload from data bytes
                let payload =
                    enriched::EnrichedEvmPayload::decode(inner.data.as_slice()).map_err(|e| {
                        Status::invalid_argument(format!(
                            "failed to decode EnrichedEvmPayload: {e}"
                        ))
                    })?;

                tracing::info!(
                    calldata_len = payload.call_data.len(),
                    consignment_valid = payload.consignment_valid,
                    nonce = payload.nonce,
                    deadline = payload.deadline,
                    "gRPC Sign: EVM (data_type=SWAP)"
                );

                EnclaveRequest {
                    request: Some(enclave_request::Request::SignEvm(
                        enclave_proto::SignEvmRequest {
                            call_data: payload.call_data,
                            nonce: payload.nonce,
                            deadline: payload.deadline,
                            consignment_valid: payload.consignment_valid,
                            rgb_amount: payload.rgb_amount,
                            rgb_asset_id: payload.rgb_asset_id,
                            chain_id: payload.chain_id,
                            proxy_contract: payload.proxy_contract,
                            calldata_amount: payload.calldata_amount,
                            calldata_commission: payload.calldata_commission,
                            // Note: the enriched proto uses consignment_sha256 (SHA-256),
                            // while the enclave proto uses consignment_hash (keccak256).
                            // The Go Listener handles this distinction; we pass through as-is.
                            consignment: vec![],
                            consignment_hash: payload.consignment_sha256,
                        },
                    )),
                }
            }
            other => {
                tracing::warn!(?other, "unsupported data_type in Sign request");
                return Err(Status::invalid_argument(format!(
                    "unsupported data_type: {other:?}"
                )));
            }
        };

        let start = std::time::Instant::now();
        let resp = self.send_to_enclave(enclave_req).await?;
        tracing::debug!(
            elapsed_ms = start.elapsed().as_millis() as u64,
            "enclave round-trip"
        );

        match resp.response {
            Some(enclave_response::Response::SignedPsbt(r)) => Ok(Response::new(Signature {
                network_id: inner.network_id,
                signature: r.signed_psbt,
            })),
            Some(enclave_response::Response::EvmSignature(r)) => Ok(Response::new(Signature {
                network_id: inner.network_id,
                signature: r.signature,
            })),
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for Sign: {:?}",
                other
            ))),
        }
    }

    /// PublicKey — returns the enclave's public key bytes.
    /// Dispatches on `data_type`:
    ///   TRANSACTION/SWAP/SIGNATURE/COMMISSION/OWNER_MULTIPLE_SIGNATURE → 64-byte uncompressed X||Y
    ///   UNSPENDABLE and other BTC-specific → 33-byte compressed pubkey
    async fn public_key(
        &self,
        request: Request<PublicKeyRequest>,
    ) -> Result<Response<PublicKeyResponse>, Status> {
        let inner = request.into_inner();
        let data_type = DataType::try_from(inner.data_type).unwrap_or(DataType::Transaction);
        tracing::info!(
            ?data_type,
            network_id = inner.network_id,
            "gRPC PublicKey called"
        );

        let enclave_req = EnclaveRequest {
            request: Some(enclave_request::Request::GetPublicKey(
                enclave_proto::GetPublicKeyRequest {},
            )),
        };

        let resp = self.send_to_enclave(enclave_req).await?;

        match resp.response {
            Some(enclave_response::Response::PublicKeys(r)) => {
                let public_key = match data_type {
                    DataType::Unspendable => r.btc_compressed_pub,
                    _ => r.evm_uncompressed_pub,
                };
                Ok(Response::new(PublicKeyResponse { public_key }))
            }
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for PublicKey: {:?}",
                other
            ))),
        }
    }

    /// Initialize — generates new keys in the enclave from OS entropy.
    async fn initialize(
        &self,
        _request: Request<InitializeRequest>,
    ) -> Result<Response<InitializeResponse>, Status> {
        tracing::info!("gRPC Initialize called");
        let enclave_req = EnclaveRequest {
            request: Some(enclave_request::Request::InitializeKey(
                enclave_proto::InitializeKeyRequest {
                    seed: vec![],
                    mnemonic: String::new(),
                },
            )),
        };

        let resp = self.send_to_enclave(enclave_req).await?;

        match resp.response {
            Some(enclave_response::Response::InitializeKey(r)) => {
                Ok(Response::new(InitializeResponse {
                    attestation: vec![], // Attestation not yet implemented
                    public_key: r.btc_compressed_pub,
                }))
            }
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for Initialize: {:?}",
                other
            ))),
        }
    }

    /// Clone — not yet implemented (cluster cloning).
    async fn clone(
        &self,
        _request: Request<CloneRequest>,
    ) -> Result<Response<CloneResponse>, Status> {
        Err(Status::unimplemented(
            "Clone not yet implemented (cluster cloning)",
        ))
    }
}
