use std::time::Duration;

use tonic::{Request, Response, Status};

use crate::enclave_proto::{
    self, enclave_request, enclave_response, EnclaveRequest, EnclaveResponse,
};

const ENCLAVE_TIMEOUT: Duration = Duration::from_secs(30);
use crate::grpc_proto::enclave_service_server::EnclaveService;
use crate::grpc_proto::{
    enclave_sign_request, EnclaveSignRequest, EnclaveSignResponse, GetPublicKeysRequest,
    GetPublicKeysResponse,
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

/// gRPC server that translates parentadapter.proto RPCs into enclave.proto
/// wire-protocol requests over TCP/vsock.
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
    async fn sign(
        &self,
        request: Request<EnclaveSignRequest>,
    ) -> Result<Response<EnclaveSignResponse>, Status> {
        let inner = request.into_inner();

        let flow = inner
            .flow
            .ok_or_else(|| Status::invalid_argument("missing flow in EnclaveSignRequest"))?;

        let enclave_req = match flow {
            enclave_sign_request::Flow::Psbt(psbt_flow) => {
                // Translate PSBTSigningFlow → SignPsbtRequest.
                // The Go Listener sends a subset of fields; we map what's available
                // and set defaults for enriched fields the Go side doesn't send yet.
                let evm_tx_hash = if psbt_flow.validated_tx_hash.is_empty() {
                    vec![]
                } else {
                    let decoded = hex::decode(&psbt_flow.validated_tx_hash).map_err(|e| {
                        Status::invalid_argument(format!("validated_tx_hash is not valid hex: {e}"))
                    })?;
                    if decoded.len() != 32 {
                        return Err(Status::invalid_argument(format!(
                            "validated_tx_hash must be 32 bytes, got {}",
                            decoded.len()
                        )));
                    }
                    decoded
                };

                EnclaveRequest {
                    request: Some(enclave_request::Request::SignPsbt(
                        enclave_proto::SignPsbtRequest {
                            psbt_bytes: psbt_flow.psbt,
                            evm_tx_hash,
                            operation_idx: psbt_flow.operation_idx,
                            evm_event_finalized: psbt_flow.evm_event_finalized,
                            // Fields the Go Listener doesn't send yet — defaults.
                            // The enclave will skip cross-checks in dev-mode,
                            // or these will need to be populated once the Go proto evolves.
                            evm_event_valid: psbt_flow.evm_event_finalized, // best approximation
                            evm_token: vec![],
                            evm_amount: 0,
                            evm_recipient: vec![],
                            evm_commission: 0,
                            psbt_output_amount: 0,
                            rgb_asset_id: String::new(),
                        },
                    )),
                }
            }
            enclave_sign_request::Flow::Evm(evm_flow) => {
                // Translate EVMSigningFlow → SignEvmRequest.
                // Same story: map available fields, default the rest.
                EnclaveRequest {
                    request: Some(enclave_request::Request::SignEvm(
                        enclave_proto::SignEvmRequest {
                            call_data: evm_flow.sign_payload,
                            nonce: evm_flow.nonce,
                            deadline: evm_flow.deadline,
                            consignment_valid: evm_flow.consignment_valid,
                            // Raw consignment bytes — passed through for enclave-side validation.
                            consignment: evm_flow.consignment,
                            consignment_hash: evm_flow.consignment_hash,
                            // Fields the Go Listener doesn't send yet — defaults.
                            rgb_amount: 0,
                            rgb_asset_id: String::new(),
                            chain_id: 0,
                            proxy_contract: vec![],
                            calldata_amount: 0,
                            calldata_commission: 0,
                        },
                    )),
                }
            }
        };

        let resp = self.send_to_enclave(enclave_req).await?;

        match resp.response {
            Some(enclave_response::Response::SignedPsbt(r)) => {
                Ok(Response::new(EnclaveSignResponse {
                    result: Some(
                        crate::grpc_proto::enclave_sign_response::Result::SignedPsbt(r.signed_psbt),
                    ),
                }))
            }
            Some(enclave_response::Response::EvmSignature(r)) => {
                Ok(Response::new(EnclaveSignResponse {
                    result: Some(
                        crate::grpc_proto::enclave_sign_response::Result::EvmSignature(r.signature),
                    ),
                }))
            }
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for Sign: {:?}",
                other
            ))),
        }
    }

    async fn get_public_keys(
        &self,
        _request: Request<GetPublicKeysRequest>,
    ) -> Result<Response<GetPublicKeysResponse>, Status> {
        let enclave_req = EnclaveRequest {
            request: Some(enclave_request::Request::GetPublicKey(
                enclave_proto::GetPublicKeyRequest {},
            )),
        };

        let resp = self.send_to_enclave(enclave_req).await?;

        match resp.response {
            Some(enclave_response::Response::PublicKeys(r)) => {
                // Flatten our structured response into the Go proto's repeated bytes.
                let mut keys = Vec::with_capacity(2);
                if !r.evm_address.is_empty() {
                    keys.push(r.evm_address);
                }
                if !r.btc_compressed_pub.is_empty() {
                    keys.push(r.btc_compressed_pub);
                }
                Ok(Response::new(GetPublicKeysResponse { public_keys: keys }))
            }
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for GetPublicKeys: {:?}",
                other
            ))),
        }
    }
}
