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

/// Enclave connection target: a TCP address or a vsock CID and port.
#[derive(Clone)]
pub enum EnclaveTarget {
    Tcp(String),
    #[cfg(target_os = "linux")]
    Vsock {
        cid: u32,
        port: u32,
    },
}

/// gRPC server. It translates `ParentService` RPCs from the federated signer
/// node into enclave wire requests over TCP or vsock.
#[derive(Clone)]
pub struct ParentAdapterService {
    target: EnclaveTarget,
}

impl ParentAdapterService {
    pub fn new(target: EnclaveTarget) -> Self {
        Self { target }
    }

    /// Send an `EnclaveRequest` and read the `EnclaveResponse`.
    /// The blocking I/O runs on a `spawn_blocking` thread.
    // `tonic::Status` is large (~176 bytes), but it is the gRPC error contract.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn send_to_enclave(
        &self,
        req: EnclaveRequest,
    ) -> Result<EnclaveResponse, Status> {
        let target = self.target.clone();

        let result = tokio::time::timeout(
            ENCLAVE_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                use crate::framing;

                // The outer timeout cannot stop a blocking worker. (F03-AF-18)
                // Use socket timeouts to limit each transport operation.
                match target {
                    EnclaveTarget::Tcp(addr) => {
                        use std::net::ToSocketAddrs;
                        let sockaddr = addr
                            .to_socket_addrs()
                            .map_err(|e| {
                                Status::unavailable(format!("enclave addr resolve failed: {e}"))
                            })?
                            .next()
                            .ok_or_else(|| {
                                Status::unavailable(
                                    "enclave addr resolved to no endpoints".to_string(),
                                )
                            })?;
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&sockaddr, ENCLAVE_TIMEOUT)
                                .map_err(|e| {
                                    Status::unavailable(format!("enclave connection failed: {e}"))
                                })?;
                        stream.set_read_timeout(Some(ENCLAVE_TIMEOUT)).ok();
                        stream.set_write_timeout(Some(ENCLAVE_TIMEOUT)).ok();
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
                        // Same as TCP. Without socket timeouts, a stuck socket
                        // holds a blocking-pool thread forever. (F03-AF-18)
                        stream.set_read_timeout(Some(ENCLAVE_TIMEOUT)).ok();
                        stream.set_write_timeout(Some(ENCLAVE_TIMEOUT)).ok();
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
            // Report NotReady as unavailable so the caller can retry. (F03-AF-11)
            2 => Status::unavailable(err.message.clone()),
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

    /// Decode a field that is hex for EVM but an opaque string elsewhere.
    /// EVM->RGB FundsIn events put the RGB invoice (`utxob:`) in
    /// `SourceProof.recipient`. Non-hex values pass through as raw UTF-8, so
    /// the enclave sees what the listener saw.
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
            Some(source_proof::Chain::Evm(evm)) => {
                // For diagnostics only: here the sending node is still known.
                // The enclave check is the authority.
                if evm.funds_in_operation_id.len() != 32 {
                    return Err(Status::invalid_argument(format!(
                        "EvmSource.funds_in_operation_id must be 32 bytes (the BridgeFundsIn \
                         operationId from indexed topic1), got {}",
                        evm.funds_in_operation_id.len()
                    )));
                }
                Ok(enclave_proto::sign_request::SourceNetwork::EvmSource(
                    enclave_proto::EvmSource {
                        tx_hash: evm.tx_hash,
                        event_valid: true,
                        event_finalized: source.finalized,
                        token: Self::decode_hex_field("SourceProof.token", source.token)?,
                        recipient: Self::decode_hex_or_raw_field(source.recipient),
                        commission: source.commission,
                        funds_in_operation_id: evm.funds_in_operation_id,
                    },
                ))
            }
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
            // CCD source (fundsIn burn) for an EVM release. The listener
            // checked finality and structure on-chain. The enclave trusts it and
            // checks the release amount against the destination.
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
                        lz_release: payload.lz_release.map(|lr| enclave_proto::LzReleaseParams {
                            dst_eid: lr.dst_eid,
                            min_amount_ld: lr.min_amount_ld,
                            recipient: lr.recipient,
                        }),
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
            // Plain BTC goes to SignBtc through `data_type=BTC_UTXO`.
            sign_request::Data::BtcData(_) => unreachable!(
                "BtcData is handled by the BTC_UTXO dispatch, not enclave_destination_network"
            ),
            // `sign` handles CCD before destination dispatch.
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
    /// Convert a `ParentService` sign request into an enclave request.
    ///
    /// Dispatch on `data_type`:
    /// - TRANSACTION: cross-network Sign (bridge, RGB send, EVM).
    /// - EVM_GAS_TX: unsigned gas-tx preimage to SignRawDigest.
    /// - BTC_UTXO: plain-BTC PSBT to SignBtc (vanilla BIP-86 path).
    async fn sign(
        &self,
        request: Request<grpc_proto::SignRequest>,
    ) -> Result<Response<SignatureResponse>, Status> {
        let inner = request.into_inner();

        let common = Self::common_sign_request(&inner)?;
        let data_type = DataType::try_from(common.data_type).map_err(|_| {
            Status::invalid_argument(format!("unknown data_type: {}", common.data_type))
        })?;
        let signer_network_id = common.dst_network_id;

        // Concordium: the listener validated the operation and derived the
        // transaction hash. The enclave signs the hash. There is no
        // source/destination check or amount check here.
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
                        // Ed25519: the signer cannot be recovered from the signature,
                        // so the key travels with it.
                        public_key: r.public_key,
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
                let expects_evm = match &destination_network {
                    enclave_proto::sign_request::DestinationNetwork::EvmDestination(_) => true,
                    enclave_proto::sign_request::DestinationNetwork::RgbDestination(_) => false,
                };

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
                        if expects_evm {
                            return Err(Status::internal(
                                "enclave reply type mismatch for Sign: expected EvmSignature, got SignedPsbt",
                            ));
                        }
                        Ok(Response::new(SignatureResponse {
                            signer_network_id,
                            signature: r.signed_psbt,
                            identifier: None,
                            call_data: Vec::new(),
                            // A PSBT carries per-input key material of its own.
                            public_key: Vec::new(),
                        }))
                    }
                    Some(enclave_response::Response::EvmSignature(r)) => {
                        if !expects_evm {
                            return Err(Status::internal(
                                "enclave reply type mismatch for Sign: expected SignedPsbt, got EvmSignature",
                            ));
                        }
                        Ok(Response::new(SignatureResponse {
                            signer_network_id,
                            signature: r.signature,
                            identifier: None,
                            // Return the calldata the signature commits to.
                            // The caller must submit these bytes.
                            call_data: r.call_data,
                            // secp256k1: the signer is recoverable from the signature.
                            public_key: Vec::new(),
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
                // EVM_GAS_TX uses the gas-tx key and has no source proof, so
                // it goes to SignRawDigest. The Listener sends the unsigned tx
                // preimage in `EnrichedEvmPayload.unsigned_tx`. `call_data` can
                // also hold a digest. The enclave decodes the preimage, applies
                // the gas-tx shape allowlist, and computes the digest itself.
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
                            // secp256k1: the signer is recoverable from the signature.
                            public_key: Vec::new(),
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
                // Plain-BTC signing, with no source proof or consignment. The
                // Listener sends the PSBT in `EnrichedBtcPayload.psbt_bytes`.
                // The enclave signs on the vanilla BIP-86 account. It signs only
                // if every output pays to its own script and inputs are under
                // the value cap.
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
                            // A PSBT carries per-input key material of its own.
                            public_key: Vec::new(),
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

    /// Return an enclave public key, selected by `data_type`:
    /// - EVM_GAS_TX: 64-byte uncompressed X||Y (gas key m/44'/60'/0'/0/1).
    /// - TRANSACTION, UNSPENDABLE: 33-byte compressed BTC public key.
    /// - CCD_GOVERNANCE: 32-byte Concordium Ed25519 governance key
    ///   (m/44'/919'/0'/0'/0').
    ///
    /// `CCD_GOVERNANCE` reads the governance key without attestation.
    /// `AttestedPublicKey` needs a Nitro Security Module. For proof that the
    /// key comes from a real enclave, use `AttestedPublicKey`
    /// (see docs/pubkey-attestation.md).
    async fn public_key(
        &self,
        request: Request<PublicKeyRequest>,
    ) -> Result<Response<PublicKeyResponse>, Status> {
        let inner = request.into_inner();
        let data_type = DataType::try_from(inner.data_type).map_err(|_| {
            Status::invalid_argument(format!("unknown data_type: {}", inner.data_type))
        })?;
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
                    DataType::CcdGovernance => r.ccd_ed25519_pub,
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

    /// Generate fresh enclave keys and set the optional donor secret.
    /// Map cloning_secret to the enclave cloning_secret field. (F03-AF-27)
    /// This RPC does not import a mnemonic or seed.
    async fn initialize(
        &self,
        request: Request<InitializeRequest>,
    ) -> Result<Response<InitializeResponse>, Status> {
        let inner = request.into_inner();
        tracing::info!(
            configures_donor = !inner.cloning_secret.is_empty(),
            "gRPC Initialize called"
        );
        let enclave_req = EnclaveRequest {
            request: Some(enclave_request::Request::InitializeKey(
                enclave_proto::InitializeKeyRequest {
                    seed: vec![],
                    mnemonic: String::new(),
                    cloning_secret: inner.cloning_secret,
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

    /// Donor side of cluster cloning. The requester orchestrator sends its
    /// InitiateCloning output here. The parent turns it into a GetCloneRequest
    /// for the local donor enclave.
    ///
    /// Before it seals the seed, the enclave verifies the requester
    /// attestation, PCRs, nonce freshness, public key and digest binding, and
    /// the digest against its cloning secret. The response has the sealed
    /// seed, the donor ephemeral public key and attestation for SetClone.
    async fn clone(
        &self,
        request: Request<CloneRequest>,
    ) -> Result<Response<CloneResponse>, Status> {
        let inner = request.into_inner();
        tracing::info!("gRPC Clone called (donor GetClone)");

        let enclave_req = EnclaveRequest {
            request: Some(enclave_request::Request::GetClone(
                enclave_proto::GetCloneRequest {
                    cluster_public_key: inner.cluster_public_key,
                    cloning_digest: inner.cloning_digest,
                    encryption_pubkey: inner.encryption_pubkey,
                    requester_attestation: inner.attestation,
                },
            )),
        };

        let resp = self.send_to_enclave(enclave_req).await?;

        match resp.response {
            Some(enclave_response::Response::GetClone(r)) => Ok(Response::new(CloneResponse {
                encrypted_seed: r.encrypted_seed,
                donor_pubkey: r.donor_pubkey,
                donor_attestation: r.donor_attestation,
            })),
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for Clone: {:?}",
                other
            ))),
        }
    }

    /// Read the tip of the enclave SPV header chain. A build without that
    /// chain returns NOT_READY.
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

    /// Always refused. The parent header sync is the only header writer.
    async fn submit_headers(
        &self,
        _request: Request<SubmitHeadersRequest>,
    ) -> Result<Response<SubmitHeadersResponse>, Status> {
        Err(Status::permission_denied(
            "SubmitHeaders is closed; the parent syncs headers itself",
        ))
    }

    /// Prove that the bridge signing key comes from this TEE. Sends a 32-byte
    /// caller nonce to the enclave. Returns the public-key bundle and an NSM
    /// attestation document. The document binds the EVM public key and a
    /// sha256 of the full bundle to the enclave PCRs.
    /// See docs/pubkey-attestation.md for verification.
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
                crate::attest_verify::attested_response(r)
                    .map(Response::new)
                    .map_err(|e| Status::internal(e.to_string()))
            }
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for AttestedPublicKey: {:?}",
                other
            ))),
        }
    }
}
