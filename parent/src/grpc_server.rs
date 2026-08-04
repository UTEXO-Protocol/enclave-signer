use std::collections::HashSet;
use std::time::Duration;

use tonic::{Request, Response, Status};

use crate::enclave_proto::{
    self, enclave_request, enclave_response, EnclaveRequest, EnclaveResponse,
};

const ENCLAVE_TIMEOUT: Duration = Duration::from_secs(30);
use crate::grpc_proto::parent_service_server::ParentService;
use crate::grpc_proto::{
    self, sign_request, source_proof, AttestedPublicKeyRequest, AttestedPublicKeyResponse,
    CloneRequest, CloneResponse, GetLastSavedBlockRequest, GetLastSavedBlockResponse,
    InitializeRequest, InitializeResponse, SourceProof, SubmitHeadersRequest,
    SubmitHeadersResponse,
};
use crate::signer::{
    DataType, PublicKeyRequest, PublicKeyResponse, SignRequest as CommonSignRequest,
    SignatureResponse,
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
    // `tonic::Status` is a large (~176 byte) error type, but it is the fixed
    // gRPC error contract here — it cannot be boxed away. Allow the
    // large-Err-variant lint rather than wrap every call site.
    #[allow(clippy::result_large_err)]
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

    fn common_sign_request(req: &grpc_proto::SignRequest) -> Result<CommonSignRequest, Status> {
        req.clone()
            .common
            .ok_or_else(|| Status::invalid_argument("SignRequest.common is missing"))
    }

    fn source_proof(req: &grpc_proto::SignRequest) -> Result<SourceProof, Status> {
        req.source
            .clone()
            .ok_or_else(|| Status::invalid_argument("SignRequest.source is missing"))
    }

    fn decode_hex_field(field: &str, value: String) -> Result<Vec<u8>, Status> {
        if value.is_empty() {
            return Ok(Vec::new());
        }
        let hex = value.strip_prefix("0x").unwrap_or(&value);
        hex::decode(hex)
            .map_err(|e| Status::invalid_argument(format!("{field} must be hex bytes: {e}")))
    }

    /// Decode a field that is hex for EVM addresses but an opaque string for
    /// other networks — EVM→RGB FundsIn events carry the RGB invoice
    /// (`utxob:…`) in SourceProof.recipient. Non-hex values pass through as
    /// their raw UTF-8 bytes so the enclave sees what the listener saw.
    fn decode_hex_or_raw_field(value: String) -> Vec<u8> {
        let hex = value.strip_prefix("0x").unwrap_or(&value);
        match hex::decode(hex) {
            Ok(bytes) => bytes,
            Err(_) => value.into_bytes(),
        }
    }

    fn enclave_merkle_proof(
        proof: grpc_proto::MerkleProofEntry,
    ) -> enclave_proto::MerkleProofEntry {
        enclave_proto::MerkleProofEntry {
            txid: proof.txid,
            block_height: proof.block_height,
            tx_position: proof.tx_position,
            merkle_path: proof.merkle_path,
        }
    }

    fn enclave_source_network(
        source: SourceProof,
    ) -> Result<enclave_proto::sign_request::SourceNetwork, Status> {
        match source.chain {
            Some(source_proof::Chain::Evm(evm)) => Ok(
                enclave_proto::sign_request::SourceNetwork::EvmSource(enclave_proto::EvmSource {
                    tx_hash: evm.tx_hash,
                    event_valid: true,
                    event_finalized: source.finalized,
                    token: Self::decode_hex_field("SourceProof.token", source.token)?,
                    recipient: Self::decode_hex_or_raw_field(source.recipient),
                    commission: source.commission,
                    // On-chain FundsIn operationId (bridge transfer id); the
                    // enclave #60 check binds to this, not to operation_idx.
                    funds_in_operation_id: evm.funds_in_operation_id,
                }),
            ),
            Some(source_proof::Chain::Rgb(rgb)) => Ok(
                enclave_proto::sign_request::SourceNetwork::RgbSource(enclave_proto::RgbSource {
                    consignment_valid: true,
                    asset_id: rgb.rgb_asset_id,
                    consignment: rgb.consignment,
                    consignment_hash: rgb.consignment_hash,
                    commission: source.commission,
                    merkle_proofs: rgb
                        .merkle_proofs
                        .into_iter()
                        .map(Self::enclave_merkle_proof)
                        .collect(),
                }),
            ),
            // A CCD source (fundsIn burn) feeding an EVM release. The listener
            // validated finality/structure on-chain; the enclave trusts it and
            // cross-checks the release amount against the destination.
            Some(source_proof::Chain::Ccd(ccd)) => Ok(
                enclave_proto::sign_request::SourceNetwork::CcdSource(enclave_proto::CcdSource {
                    tx_hash: ccd.tx_hash,
                    commission: source.commission,
                }),
            ),
            None => Err(Status::invalid_argument(
                "source proof has no chain-specific evidence",
            )),
        }
    }

    fn enclave_destination_network(
        data: sign_request::Data,
    ) -> enclave_proto::sign_request::DestinationNetwork {
        match data {
            sign_request::Data::EvmData(payload) => {
                enclave_proto::sign_request::DestinationNetwork::EvmDestination(
                    enclave_proto::EvmDestination {
                        call_data: payload.call_data,
                        nonce: payload.nonce,
                        deadline: payload.deadline,
                        chain_id: payload.chain_id,
                        proxy_contract: payload.proxy_contract,
                        calldata_amount: payload.calldata_amount,
                        calldata_commission: payload.calldata_commission,
                    },
                )
            }
            sign_request::Data::RgbData(payload) => {
                enclave_proto::sign_request::DestinationNetwork::RgbDestination(
                    enclave_proto::RgbDestination {
                        operation_idx: payload.operation_idx,
                        psbt_bytes: payload.psbt_bytes,
                        psbt_output_amount: payload.psbt_output_amount,
                        asset_id: payload.rgb_asset_id,
                        consignment: payload.consignment,
                        consignment_hash: payload.consignment_hash,
                    },
                )
            }
            // Plain BTC is not a cross-network destination — it is dispatched
            // via `data_type=BTC_UTXO` to the SignBtc path, never here.
            sign_request::Data::BtcData(_) => unreachable!(
                "BtcData is handled by the BTC_UTXO dispatch, not enclave_destination_network"
            ),
            // CCD is handled in `sign` before destination dispatch; never routed here.
            sign_request::Data::CcdData(_) => {
                unreachable!("CCD sign requests are handled before destination dispatch")
            }
        }
    }

    fn validate_cross_network_route(
        source: &enclave_proto::sign_request::SourceNetwork,
        destination: &enclave_proto::sign_request::DestinationNetwork,
    ) -> Result<(), Status> {
        let same_network = matches!(
            (source, destination),
            (
                enclave_proto::sign_request::SourceNetwork::EvmSource(_),
                enclave_proto::sign_request::DestinationNetwork::EvmDestination(_)
            ) | (
                enclave_proto::sign_request::SourceNetwork::RgbSource(_),
                enclave_proto::sign_request::DestinationNetwork::RgbDestination(_)
            )
        );

        if same_network {
            return Err(Status::invalid_argument(
                "source and destination networks must be different",
            ));
        }

        Ok(())
    }
}

#[tonic::async_trait]
impl ParentService for ParentAdapterService {
    /// Sign converts the structured ParentService request into the enclave
    /// wire `SignRequest`.
    ///
    /// Dispatches on `data_type`:
    ///   TRANSACTION → source/destination cross-network Sign (bridge / RGB-send / EVM)
    ///   EVM_GAS_TX  → unsigned gas-tx preimage → SignRawDigest
    ///   BTC_UTXO    → plain-BTC PSBT → SignBtc (vanilla BIP-86 path, audit #69/M-01)
    async fn sign(
        &self,
        request: Request<grpc_proto::SignRequest>,
    ) -> Result<Response<SignatureResponse>, Status> {
        let inner = request.into_inner();

        let common = Self::common_sign_request(&inner)?;
        let data_type = DataType::try_from(common.data_type).unwrap_or(DataType::Transaction);
        let signer_network_id = common.dst_network_id;

        // Concordium: the listener has already validated the operation and
        // re-derived the transaction hash; the enclave signs the hash directly.
        // No source/destination validation or amount cross-check happens here.
        if let Some(sign_request::Data::CcdData(payload)) = inner.data.as_ref() {
            if data_type != DataType::Transaction {
                return Err(Status::invalid_argument(
                    "CCD signing requires TRANSACTION data_type",
                ));
            }
            tracing::info!(
                src_network_id = common.src_network_id,
                dst_network_id = common.dst_network_id,
                hash_len = payload.hash.len(),
                "gRPC Sign: Concordium transaction"
            );

            let enclave_req = EnclaveRequest {
                request: Some(enclave_request::Request::SignCcd(
                    enclave_proto::SignCcdRequest {
                        hash: payload.hash.clone(),
                    },
                )),
            };
            let resp = self.send_to_enclave(enclave_req).await?;
            return match resp.response {
                Some(enclave_response::Response::CcdSignature(r)) => {
                    Ok(Response::new(SignatureResponse {
                        signer_network_id,
                        signature: r.signature,
                        identifier: None,
                        call_data: Vec::new(),
                    }))
                }
                Some(enclave_response::Response::Error(e)) => {
                    Err(Self::enclave_error_to_status(&e))
                }
                other => Err(Status::internal(format!(
                    "unexpected enclave response for CCD Sign: {:?}",
                    other
                ))),
            };
        }

        match data_type {
            DataType::Transaction => {
                let source = Self::source_proof(&inner)?;
                let amount = source.amount;

                let destination_network = match inner.data {
                    Some(sign_request::Data::EvmData(payload)) => {
                        if !self.evm_network_ids.contains(&common.dst_network_id) {
                            return Err(Status::invalid_argument(format!(
                                "EVM payload destination network {} is not configured as EVM",
                                common.dst_network_id
                            )));
                        }
                        tracing::info!(
                            src_network_id = common.src_network_id,
                            dst_network_id = common.dst_network_id,
                            calldata_len = payload.call_data.len(),
                            nonce = payload.nonce,
                            deadline = payload.deadline,
                            "gRPC Sign: EVM transaction"
                        );

                        Self::enclave_destination_network(sign_request::Data::EvmData(payload))
                    }
                    Some(sign_request::Data::RgbData(payload)) => {
                        if self.evm_network_ids.contains(&common.dst_network_id) {
                            return Err(Status::invalid_argument(format!(
                                "RGB payload destination network {} is configured as EVM",
                                common.dst_network_id
                            )));
                        }
                        tracing::info!(
                            src_network_id = common.src_network_id,
                            dst_network_id = common.dst_network_id,
                            psbt_len = payload.psbt_bytes.len(),
                            operation_idx = payload.operation_idx,
                            "gRPC Sign: RGB transaction"
                        );

                        Self::enclave_destination_network(sign_request::Data::RgbData(payload))
                    }
                    Some(sign_request::Data::BtcData(_)) => {
                        return Err(Status::invalid_argument(
                            "TRANSACTION data_type must not carry BtcData; \
                             use data_type=BTC_UTXO for plain-BTC signing",
                        ))
                    }
                    Some(sign_request::Data::CcdData(_)) => {
                        return Err(Status::internal(
                            "CCD sign request should have been handled before destination dispatch",
                        ));
                    }
                    None => return Err(Status::invalid_argument("SignRequest.data is missing")),
                };

                let source_network = Self::enclave_source_network(source)?;
                Self::validate_cross_network_route(&source_network, &destination_network)?;

                let enclave_req = EnclaveRequest {
                    request: Some(enclave_request::Request::Sign(enclave_proto::SignRequest {
                        amount,
                        source_network: Some(source_network),
                        destination_network: Some(destination_network),
                    })),
                };

                let start = std::time::Instant::now();
                let resp = self.send_to_enclave(enclave_req).await?;
                tracing::debug!(
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    "enclave round-trip"
                );

                match resp.response {
                    Some(enclave_response::Response::SignedPsbt(r)) => {
                        Ok(Response::new(SignatureResponse {
                            signer_network_id,
                            signature: r.signed_psbt,
                            identifier: None,
                            call_data: Vec::new(),
                        }))
                    }
                    Some(enclave_response::Response::EvmSignature(r)) => {
                        Ok(Response::new(SignatureResponse {
                            signer_network_id,
                            signature: r.signature,
                            identifier: None,
                            // The enclave may rewrite the OpId-bound calldata
                            // fields (burnId, fundsInIds) from the validated
                            // consignment, so forward the exact calldata the
                            // signature commits to — the caller must submit these
                            // bytes, not the ones it sent (audit M-02 / #93, #63).
                            call_data: r.call_data,
                        }))
                    }
                    Some(enclave_response::Response::Error(e)) => {
                        Err(Self::enclave_error_to_status(&e))
                    }
                    other => Err(Status::internal(format!(
                        "unexpected enclave response for Sign: {:?}",
                        other
                    ))),
                }
            }
            DataType::EvmGasTx => {
                // EVM_GAS_TX is signed with the enclave's dedicated gas-tx key.
                // It has no source proof, so it is routed to SignRawDigest
                // rather than the source/destination Sign path. The Listener
                // sends the unsigned tx preimage in `EnrichedEvmPayload.unsigned_tx`
                // (and MAY still carry a pre-hashed digest in `call_data` for
                // defense-in-depth); the enclave decodes the preimage, enforces
                // the gas-tx shape allowlist, and computes the digest itself
                // (audit TEE-XC-09 / #68 — see `networks::evm::gas_tx`).
                let (digest, unsigned_tx) =
                    match inner.data {
                        Some(sign_request::Data::EvmData(payload)) => {
                            (payload.call_data, payload.unsigned_tx)
                        }
                        _ => return Err(Status::invalid_argument(
                            "EVM_GAS_TX sign requires EvmData with the unsigned tx in unsigned_tx",
                        )),
                    };
                tracing::info!(
                    dst_network_id = signer_network_id,
                    digest_len = digest.len(),
                    unsigned_tx_len = unsigned_tx.len(),
                    "gRPC Sign: EVM gas tx raw digest"
                );
                let enclave_req = EnclaveRequest {
                    request: Some(enclave_request::Request::SignRawDigest(
                        enclave_proto::SignRawDigestRequest {
                            digest,
                            unsigned_tx,
                        },
                    )),
                };
                let resp = self.send_to_enclave(enclave_req).await?;
                match resp.response {
                    Some(enclave_response::Response::RawDigestSig(r)) => {
                        Ok(Response::new(SignatureResponse {
                            signer_network_id,
                            signature: r.signature,
                            identifier: None,
                            call_data: Vec::new(),
                        }))
                    }
                    Some(enclave_response::Response::Error(e)) => {
                        Err(Self::enclave_error_to_status(&e))
                    }
                    other => Err(Status::internal(format!(
                        "unexpected enclave response for SignRawDigest: {:?}",
                        other
                    ))),
                }
            }
            DataType::BtcUtxo => {
                // Plain-BTC signing (audit #69/M-01): a distinct request that
                // never carries a source proof or consignment. The Listener
                // sends the PSBT in `EnrichedBtcPayload.psbt_bytes`; the enclave
                // signs it with the vanilla BIP-86 account under a strict output
                // allowlist + input-value cap.
                let payload = match inner.data {
                    Some(sign_request::Data::BtcData(payload)) => payload,
                    _ => {
                        return Err(Status::invalid_argument(
                            "BTC_UTXO sign requires BtcData with the PSBT in psbt_bytes",
                        ))
                    }
                };

                tracing::info!(
                    dst_network_id = signer_network_id,
                    psbt_len = payload.psbt_bytes.len(),
                    "gRPC Sign: plain BTC (data_type=BTC_UTXO)"
                );

                let enclave_req = EnclaveRequest {
                    request: Some(enclave_request::Request::SignBtc(
                        enclave_proto::SignBtcRequest {
                            psbt_bytes: payload.psbt_bytes,
                        },
                    )),
                };

                let resp = self.send_to_enclave(enclave_req).await?;
                match resp.response {
                    Some(enclave_response::Response::SignedPsbt(r)) => {
                        Ok(Response::new(SignatureResponse {
                            signer_network_id,
                            signature: r.signed_psbt,
                            identifier: None,
                            call_data: Vec::new(),
                        }))
                    }
                    Some(enclave_response::Response::Error(e)) => {
                        Err(Self::enclave_error_to_status(&e))
                    }
                    other => Err(Status::internal(format!(
                        "unexpected enclave response for SignBtc: {:?}",
                        other
                    ))),
                }
            }
            other => {
                tracing::warn!(?other, "unsupported data_type in Sign request");
                Err(Status::invalid_argument(format!(
                    "unsupported data_type: {other:?}"
                )))
            }
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
                Ok(Response::new(PublicKeyResponse {
                    public_key,
                    identifier: None,
                }))
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
                    ccd_ed25519_pub: pk.ccd_ed25519_pub,
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
