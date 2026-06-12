use std::collections::HashSet;
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
    AttestedPublicKeyRequest, AttestedPublicKeyResponse, CloneRequest, CloneResponse, DataType,
    GetLastSavedBlockRequest, GetLastSavedBlockResponse, InitializeRequest, InitializeResponse,
    PublicKeyRequest, PublicKeyResponse, SignRequest, Signature, SubmitHeadersRequest,
    SubmitHeadersResponse,
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
    evm_network_ids: HashSet<u32>,
}

impl ParentAdapterService {
    pub fn new(target: EnclaveTarget, evm_network_ids: HashSet<u32>) -> Self {
        Self {
            target,
            evm_network_ids,
        }
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
    /// Sign — dispatches based on data_type + network_id:
    ///   TRANSACTION + EVM network_id → deserialize EnrichedEvmPayload → SignEvmRequest
    ///   TRANSACTION + other          → deserialize EnrichedPsbtPayload → SignPsbtRequest
    ///   EVM_GAS_TX                   → unsigned gas-tx preimage → SignRawDigestRequest
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<Signature>, Status> {
        let inner = request.into_inner();

        let data_type = DataType::try_from(inner.data_type).unwrap_or(DataType::Transaction);

        let enclave_req = match data_type {
            DataType::Transaction if self.evm_network_ids.contains(&inner.network_id) => {
                let payload =
                    enriched::EnrichedEvmPayload::decode(inner.data.as_slice()).map_err(|e| {
                        Status::invalid_argument(format!(
                            "failed to decode EnrichedEvmPayload: {e}"
                        ))
                    })?;

                tracing::info!(
                    network_id = inner.network_id,
                    calldata_len = payload.call_data.len(),
                    consignment_valid = payload.consignment_valid,
                    nonce = payload.nonce,
                    deadline = payload.deadline,
                    "gRPC Sign: EVM (data_type=TRANSACTION, evm network)"
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
                            consignment: payload.consignment,
                            consignment_hash: payload.consignment_hash,
                            merkle_proofs: payload
                                .merkle_proofs
                                .into_iter()
                                .map(|p| enclave_proto::MerkleProofEntry {
                                    txid: p.txid,
                                    block_height: p.block_height,
                                    tx_position: p.tx_position,
                                    merkle_path: p.merkle_path,
                                })
                                .collect(),
                        },
                    )),
                }
            }
            DataType::Transaction => {
                let payload = enriched::EnrichedPsbtPayload::decode(inner.data.as_slice())
                    .map_err(|e| {
                        Status::invalid_argument(format!(
                            "failed to decode EnrichedPsbtPayload: {e}"
                        ))
                    })?;

                tracing::info!(
                    network_id = inner.network_id,
                    psbt_len = payload.psbt_bytes.len(),
                    has_tx_hash = !payload.evm_tx_hash.is_empty(),
                    operation_idx = payload.operation_idx,
                    "gRPC Sign: PSBT (data_type=TRANSACTION, non-evm network)"
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
            DataType::EvmGasTx => {
                tracing::info!(
                    data_len = inner.data.len(),
                    "gRPC Sign: gas tx preimage (data_type=EVM_GAS_TX)"
                );

                // Post-#68 (TEE-XC-09): the enclave no longer blind-signs an
                // opaque digest. `data` now carries the full unsigned gas-tx
                // preimage (EIP-1559 `0x02||rlp([...])` or legacy EIP-155
                // `rlp([...])`); the enclave decodes it, enforces the gas-tx
                // shape allowlist, and computes the digest itself. The
                // listener must send the preimage here rather than a digest.
                EnclaveRequest {
                    request: Some(enclave_request::Request::SignRawDigest(
                        enclave_proto::SignRawDigestRequest {
                            digest: Vec::new(),
                            unsigned_tx: inner.data,
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
            Some(enclave_response::Response::RawDigestSig(r)) => Ok(Response::new(Signature {
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
    ///   EVM_GAS_TX  → 64-byte uncompressed X||Y (gas key m/44'/60'/0'/0/1)
    ///   UNSPENDABLE → 33-byte compressed BTC pubkey
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
                    DataType::EvmGasTx => r.evm_gas_tx_uncompressed_pub,
                    DataType::Transaction | DataType::Unspendable => r.btc_compressed_pub,
                    other => {
                        return Err(Status::invalid_argument(format!(
                            "PublicKey not supported for data_type {:?}",
                            other
                        )));
                    }
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

    /// Initialize — generates new keys in the enclave.
    /// If cloning_secret is provided, it is forwarded as a BIP-39 mnemonic;
    /// otherwise the enclave generates keys from OS entropy.
    async fn initialize(
        &self,
        request: Request<InitializeRequest>,
    ) -> Result<Response<InitializeResponse>, Status> {
        let inner = request.into_inner();
        tracing::info!(
            has_mnemonic = !inner.cloning_secret.is_empty(),
            "gRPC Initialize called"
        );
        let enclave_req = EnclaveRequest {
            request: Some(enclave_request::Request::InitializeKey(
                enclave_proto::InitializeKeyRequest {
                    seed: vec![],
                    mnemonic: inner.cloning_secret,
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

    /// GetLastSavedBlock — forwards to enclave. PR 1 wires the surface only;
    /// the enclave currently returns NOT_READY until the SPV header chain
    /// lands in PR 2 (see docs/spv-review.md).
    async fn get_last_saved_block(
        &self,
        _request: Request<GetLastSavedBlockRequest>,
    ) -> Result<Response<GetLastSavedBlockResponse>, Status> {
        tracing::info!("gRPC GetLastSavedBlock called");

        let enclave_req = EnclaveRequest {
            request: Some(enclave_request::Request::GetLastSavedBlock(
                enclave_proto::GetLastSavedBlockRequest {},
            )),
        };

        let resp = self.send_to_enclave(enclave_req).await?;

        match resp.response {
            Some(enclave_response::Response::GetLastSavedBlock(r)) => {
                Ok(Response::new(GetLastSavedBlockResponse {
                    block_height: r.block_height,
                    block_hash: r.block_hash,
                }))
            }
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for GetLastSavedBlock: {:?}",
                other
            ))),
        }
    }

    /// SubmitHeaders — forwards a batch of raw 80-byte Bitcoin headers to the
    /// enclave. PR 1 wires the surface only; the enclave currently returns
    /// NOT_READY until the SPV header chain lands in PR 2.
    async fn submit_headers(
        &self,
        request: Request<SubmitHeadersRequest>,
    ) -> Result<Response<SubmitHeadersResponse>, Status> {
        let inner = request.into_inner();
        tracing::info!(
            headers_len = inner.headers.len(),
            start_height = inner.start_height,
            "gRPC SubmitHeaders called"
        );

        let enclave_req = EnclaveRequest {
            request: Some(enclave_request::Request::SubmitHeaders(
                enclave_proto::SubmitHeadersRequest {
                    headers: inner.headers,
                    start_height: inner.start_height,
                },
            )),
        };

        let resp = self.send_to_enclave(enclave_req).await?;

        match resp.response {
            Some(enclave_response::Response::SubmitHeaders(r)) => {
                Ok(Response::new(SubmitHeadersResponse {
                    last_block_height: r.last_block_height,
                    last_block_hash: r.last_block_hash,
                    headers_accepted: r.headers_accepted,
                }))
            }
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for SubmitHeaders: {:?}",
                other
            ))),
        }
    }

    /// AttestedPublicKey — proves the bridge's signing pubkey was produced
    /// inside this TEE. Forwards a 32-byte caller nonce to the enclave,
    /// returns the public-key bundle plus an NSM attestation document that
    /// binds the EVM pubkey + a sha256 commitment over the full bundle to
    /// the enclave's PCRs. See docs/pubkey-attestation.md for the
    /// verification recipe.
    async fn attested_public_key(
        &self,
        request: Request<AttestedPublicKeyRequest>,
    ) -> Result<Response<AttestedPublicKeyResponse>, Status> {
        let inner = request.into_inner();
        if inner.nonce.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "nonce must be 32 bytes, got {}",
                inner.nonce.len()
            )));
        }
        tracing::info!("gRPC AttestedPublicKey called");

        let enclave_req = EnclaveRequest {
            request: Some(enclave_request::Request::GetAttestedPublicKey(
                enclave_proto::GetAttestedPublicKeyRequest { nonce: inner.nonce },
            )),
        };

        let resp = self.send_to_enclave(enclave_req).await?;

        match resp.response {
            Some(enclave_response::Response::GetAttestedPublicKey(r)) => {
                let pk = r.public_keys.ok_or_else(|| {
                    Status::internal("enclave returned attestation without public_keys")
                })?;
                Ok(Response::new(AttestedPublicKeyResponse {
                    evm_address: pk.evm_address,
                    evm_uncompressed_pub: pk.evm_uncompressed_pub,
                    btc_compressed_pub: pk.btc_compressed_pub,
                    btc_xpub: pk.btc_xpub,
                    master_fingerprint: pk.master_fingerprint,
                    account_xpub_vanilla: pk.account_xpub_vanilla,
                    account_xpub_colored: pk.account_xpub_colored,
                    attestation_doc: r.attestation_doc,
                    chain_id: pk.chain_id,
                    bridge_contract: pk.bridge_contract,
                    rgb_asset_id: pk.rgb_asset_id,
                    evm_gas_tx_uncompressed_pub: pk.evm_gas_tx_uncompressed_pub,
                    evm_gas_tx_address: pk.evm_gas_tx_address,
                }))
            }
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for AttestedPublicKey: {:?}",
                other
            ))),
        }
    }
}
