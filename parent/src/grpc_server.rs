use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use socket2::{Domain, SockAddr, Socket, Type};
use tonic::{Request, Response, Status};

use crate::enclave_proto::{
    self, enclave_request, enclave_response, EnclaveRequest, EnclaveResponse,
};
use crate::error::ParentError;
use crate::framing;

use crate::signed_responses::{Claim, Lead, SignedResponses};

/// How much longer the parent and the CLI wait for a reply than the socket
/// deadline of the enclave. The enclave must give up first: its failed write
/// then rolls its replay key back, while a parent that gives up first leaves a
/// committed key and a response nobody read. The deadline starts at accept,
/// while the wait of the parent starts before the worker is queued.
pub(crate) const ENCLAVE_WAIT_MARGIN_SECS: u64 = 10;

/// The socket deadline of the image. The parent uses it until it has read the
/// deadline in force, and the CLI uses it when the enclave does not say it.
pub(crate) const IMAGE_DEADLINE_SECS: u64 = 90;

/// True when the gRPC handler timeout outlasts the wait for the enclave. A
/// handler that times out first drops a reply after the enclave has committed
/// its replay key.
pub fn handler_timeout_covers_enclave_wait(handler_secs: u64, deadline_secs: u64) -> bool {
    handler_secs > deadline_secs.saturating_add(ENCLAVE_WAIT_MARGIN_SECS)
}

/// The handler timeout that start-up must use with the image deadline.
pub fn image_handler_timeout_is_valid(handler_secs: u64) -> bool {
    handler_timeout_covers_enclave_wait(handler_secs, IMAGE_DEADLINE_SECS)
}

/// How often the parent reads the limits in force. The operator changes them
/// with the CLI, which goes straight to the enclave.
const LIMITS_READ_INTERVAL: Duration = Duration::from_secs(5);
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

/// The error when the request timeout ends a call before the enclave answers.
fn timeout_conflict(request_timeout: Duration, enclave_wait: Duration) -> Option<String> {
    (request_timeout <= enclave_wait).then(|| {
        format!(
            "GRPC_REQUEST_TIMEOUT_SECS is {} s, but the parent waits up to {} s for the \
             enclave (total_request_timeout_secs plus ENCLAVE_WAIT_MARGIN_SECS): a slow \
             request ends before the enclave answers; raise GRPC_REQUEST_TIMEOUT_SECS",
            request_timeout.as_secs(),
            enclave_wait.as_secs()
        )
    })
}

/// The warning when kept replies expire inside the enclave's replay window.
fn reply_ttl_conflict(parent_ttl: Duration, enclave_ttl: Duration) -> Option<String> {
    (parent_ttl < enclave_ttl).then(|| {
        format!(
            "SIGNED_RESPONSE_TTL_SECS is {} s, below the enclave's mint_replay_ttl_secs of \
             {} s: the enclave refuses a mint retry that comes after the parent dropped \
             its reply, until its window ends",
            parent_ttl.as_secs(),
            enclave_ttl.as_secs()
        )
    })
}

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

/// Start the deadline before the worker is queued, then run `exchange`.
#[allow(clippy::result_large_err)]
async fn send_within(
    target: EnclaveTarget,
    req: EnclaveRequest,
    timeout: Duration,
    lead: Option<Lead>,
) -> Result<EnclaveResponse, Status> {
    let deadline = Instant::now() + timeout;
    let worker = tokio::task::spawn_blocking(move || exchange(&target, &req, deadline, lead));
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), worker).await {
        Ok(join_result) => {
            join_result.map_err(|e| Status::internal(format!("spawn_blocking join failed: {e}")))?
        }
        Err(_) => Err(timed_out()),
    }
}

/// Connect, write `req` and read the response before `deadline`. With a
/// `lead`, a signed-PSBT reply is stored for a retry here, on the worker:
/// the gRPC future that waits for this exchange may already be gone, and
/// the reply must not go with it.
#[allow(clippy::result_large_err)]
fn exchange(
    target: &EnclaveTarget,
    req: &EnclaveRequest,
    deadline: Instant,
    lead: Option<Lead>,
) -> Result<EnclaveResponse, Status> {
    let (domain, addr, connect_failed) = match target {
        EnclaveTarget::Tcp(addr) => {
            use std::net::ToSocketAddrs;
            let sockaddr = addr
                .to_socket_addrs()
                .map_err(|e| Status::unavailable(format!("enclave addr resolve failed: {e}")))?
                .next()
                .ok_or_else(|| {
                    Status::unavailable("enclave addr resolved to no endpoints".to_string())
                })?;
            (
                Domain::for_address(sockaddr),
                SockAddr::from(sockaddr),
                "enclave connection failed",
            )
        }
        #[cfg(target_os = "linux")]
        EnclaveTarget::Vsock { cid, port } => (
            Domain::VSOCK,
            SockAddr::vsock(*cid, *port),
            "enclave vsock connection failed",
        ),
    };
    let connect_status = |e: io::Error| {
        if is_timeout(&e) {
            timed_out()
        } else {
            Status::unavailable(format!("{connect_failed}: {e}"))
        }
    };

    // The worker can start late. Each step uses the time left.
    let left = remaining(deadline).map_err(|_| timed_out())?;
    let sock = Socket::new(domain, Type::STREAM, None).map_err(connect_status)?;
    sock.connect_timeout(&addr, left).map_err(connect_status)?;
    let mut stream = DeadlineStream { sock, deadline };
    framing::write_message(&mut stream, req).map_err(|e| io_status(e, "enclave write failed"))?;
    let response: EnclaveResponse =
        framing::read_message(&mut stream).map_err(|e| io_status(e, "enclave read failed"))?;
    if let Some(lead) = lead {
        if let Some(enclave_response::Response::SignedPsbt(signed)) = &response.response {
            lead.complete(signed);
        }
        // Any other reply drops the lead: waiters make their own attempt.
    }
    Ok(response)
}

fn timed_out() -> Status {
    Status::deadline_exceeded("enclave request timed out")
}

pub(crate) fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// A socket timeout gives the same status as the outer timer. Any other
/// socket failure is a transport fault the caller may retry: the enclave
/// commits a replay key only after its write succeeds.
fn io_status(e: ParentError, context: &str) -> Status {
    match e {
        ParentError::Io(e) if is_timeout(&e) => timed_out(),
        ParentError::Io(e) => Status::unavailable(format!("{context}: {e}")),
        e => Status::internal(format!("{context}: {e}")),
    }
}

/// Time left until `deadline`, or `TimedOut`.
fn remaining(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "request deadline exceeded",
        ));
    }
    // socket2 reads a timeout below 1 microsecond as no timeout.
    Ok(left.max(Duration::from_micros(1)))
}

/// A socket that sets its timeout to the time left before each read and write.
struct DeadlineStream {
    sock: Socket,
    deadline: Instant,
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        (&self.sock).read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        (&self.sock).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// gRPC server. It translates `ParentService` RPCs from the federated signer
/// node into enclave wire requests over TCP or vsock.
#[derive(Clone)]
pub struct ParentAdapterService {
    target: EnclaveTarget,
    /// Replies of EVM->RGB bridge signs, kept for a retry of the same request.
    signed: std::sync::Arc<SignedResponses>,
    /// The socket deadline of the enclave, in seconds.
    deadline_secs: std::sync::Arc<AtomicU64>,
    /// The limits in force at the last read; `None` before the first.
    limits: std::sync::Arc<std::sync::RwLock<Option<enclave_proto::Limits>>>,
    /// `GRPC_REQUEST_TIMEOUT_SECS`, when the server has one.
    request_timeout: Option<Duration>,
}

impl ParentAdapterService {
    /// A service with the default reply store (`signed_responses` defaults).
    pub fn new(target: EnclaveTarget) -> Self {
        Self::with_signed_responses(
            target,
            SignedResponses::new(
                crate::signed_responses::DEFAULT_TTL,
                crate::signed_responses::DEFAULT_MAX_ENTRIES,
                crate::signed_responses::DEFAULT_MAX_BYTES,
            ),
        )
    }

    pub fn with_signed_responses(
        target: EnclaveTarget,
        signed: std::sync::Arc<SignedResponses>,
    ) -> Self {
        Self {
            target,
            signed,
            deadline_secs: std::sync::Arc::new(AtomicU64::new(IMAGE_DEADLINE_SECS)),
            limits: Default::default(),
            request_timeout: None,
        }
    }

    /// Sets the request timeout to check against the wait for the enclave.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// The limits in force that the enclave last reported.
    pub(crate) fn limits_in_force(&self) -> Option<enclave_proto::Limits> {
        *self.limits.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Sets the socket deadline that the parent assumes.
    pub fn with_enclave_deadline_secs(self, secs: u64) -> Self {
        self.deadline_secs.store(secs, Ordering::Relaxed);
        self
    }

    /// The wait for a reply of the enclave.
    fn enclave_wait(&self) -> Duration {
        let deadline = self.deadline_secs.load(Ordering::Relaxed);
        Duration::from_secs(deadline.saturating_add(ENCLAVE_WAIT_MARGIN_SECS))
    }

    /// Reads the limits in force. A failed read keeps the last values.
    async fn read_enclave_limits(&self) {
        let request = EnclaveRequest {
            request: Some(enclave_request::Request::GetLimits(
                enclave_proto::GetLimitsRequest {},
            )),
        };
        let response = self.send_to_enclave(request).await.ok();
        let Some(enclave_response::Response::Limits(limits)) = response.and_then(|r| r.response)
        else {
            return;
        };
        let Some(current) = limits.current else {
            return;
        };
        if current.total_request_timeout_secs != 0 {
            self.deadline_secs
                .store(current.total_request_timeout_secs, Ordering::Relaxed);
        }
        let previous = self
            .limits
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .replace(current);
        self.report_conflicts(previous.as_ref(), &current);
    }

    /// Logs parent settings that conflict with changed limits in force.
    fn report_conflicts(
        &self,
        previous: Option<&enclave_proto::Limits>,
        current: &enclave_proto::Limits,
    ) {
        let changed = |f: fn(&enclave_proto::Limits) -> u64| previous.map(f) != Some(f(current));
        if changed(|l| l.total_request_timeout_secs) {
            let wait = self.enclave_wait();
            if let Some(problem) = self
                .request_timeout
                .and_then(|timeout| timeout_conflict(timeout, wait))
            {
                tracing::error!("{problem}");
            }
        }
        if changed(|l| l.mint_replay_ttl_secs) {
            let enclave_ttl = Duration::from_secs(current.mint_replay_ttl_secs);
            if let Some(problem) = reply_ttl_conflict(self.signed.ttl(), enclave_ttl) {
                tracing::warn!("{problem}");
            }
        }
    }

    /// Re-reads the limits in force for the life of the parent; the wait for
    /// the enclave and the header sync follow them.
    pub async fn follow_enclave_limits(self) {
        let mut interval = tokio::time::interval(LIMITS_READ_INTERVAL);
        loop {
            interval.tick().await;
            self.read_enclave_limits().await;
        }
    }

    /// Send an `EnclaveRequest` and read the `EnclaveResponse`.
    /// The blocking I/O runs on a `spawn_blocking` thread.
    // `tonic::Status` is large, but it is the gRPC error contract.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn send_to_enclave(
        &self,
        req: EnclaveRequest,
    ) -> Result<EnclaveResponse, Status> {
        send_within(self.target.clone(), req, self.enclave_wait(), None).await
    }

    /// Like [`Self::send_to_enclave`], and a signed-PSBT reply completes `lead`.
    async fn send_to_enclave_leading(
        &self,
        req: EnclaveRequest,
        lead: Option<Lead>,
    ) -> Result<EnclaveResponse, Status> {
        send_within(self.target.clone(), req, self.enclave_wait(), lead).await
    }

    /// Unwrap an enclave error response into a gRPC Status.
    fn enclave_error_to_status(err: &enclave_proto::ErrorResponse) -> Status {
        match err.code {
            // Report NotReady as unavailable so the caller can retry.
            2 => Status::unavailable(err.message.clone()),
            3 => Status::failed_precondition(err.message.clone()),
            // Codes 4-7 come from GetClone only.
            4 => Status::invalid_argument(err.message.clone()),
            5 => Status::permission_denied(err.message.clone()),
            6 => Status::already_exists(err.message.clone()),
            7 => Status::resource_exhausted(err.message.clone()),
            // Stable wire prefix already understood by the bridge's finality
            // backoff. The enclave's human diagnostic may change independently.
            8 => Status::failed_precondition(format!(
                "evm event pending finality: 1 signer node(s) have not seen the deposit finalized yet ({})",
                err.message
            )),
            _ => Status::internal(format!(
                "enclave error (code {}): {}",
                err.code, err.message
            )),
        }
    }

    /// Copies only `common`. A copy of the whole request would also copy the
    /// source with every Merkle proof.
    fn common_sign_request(req: &grpc_proto::SignRequest) -> Result<CommonSignRequest, Status> {
        req.common
            .ok_or_else(|| Status::invalid_argument("SignRequest.common is missing"))
    }

    /// Moves the source out of the request, so that its Merkle proofs exist
    /// once.
    fn source_proof(req: &mut grpc_proto::SignRequest) -> Result<SourceProof, Status> {
        req.source
            .take()
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
            Some(source_proof::Chain::Ccd(_)) => Err(Status::invalid_argument(
                "Concordium sources are not supported",
            )),
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
                        burn_destination: payload.burn_destination.map(|bd| {
                            enclave_proto::BurnDestination {
                                version: bd.version,
                                destination_chain_id: bd.destination_chain_id,
                                dst_eid: bd.dst_eid,
                                recipient: bd.recipient,
                            }
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
                        fascia: payload.fascia,
                        parent_fascia: payload.parent_fascia,
                    },
                )
            }
            // Plain BTC goes to SignBtc through `data_type=BTC_UTXO`.
            sign_request::Data::BtcData(_) => unreachable!(
                "BtcData is handled by the BTC_UTXO dispatch, not enclave_destination_network"
            ),
            // `sign` refuses Concordium data before destination dispatch.
            sign_request::Data::CcdData(_) => {
                unreachable!("Concordium sign requests are refused before destination dispatch")
            }
        }
    }

    /// A rights refill has no source: the mint enclave authorizes it by shape
    /// alone, so a source here is a routing error.
    fn rights_refill_request(req: grpc_proto::SignRequest) -> Result<EnclaveRequest, Status> {
        if req.source.is_some() {
            return Err(Status::invalid_argument(
                "RGB_RIGHTS_REFILL carries no source proof",
            ));
        }
        let Some(sign_request::Data::RgbData(payload)) = req.data else {
            return Err(Status::invalid_argument(
                "RGB_RIGHTS_REFILL sign requires RgbData with the PSBT, its fascia and its parent \
                 fascia",
            ));
        };
        Ok(EnclaveRequest {
            request: Some(enclave_request::Request::SignRightsRefill(
                enclave_proto::SignRightsRefillRequest {
                    psbt_bytes: payload.psbt_bytes,
                    asset_id: payload.rgb_asset_id,
                    fascia: payload.fascia,
                    parent_fascia: payload.parent_fascia,
                },
            )),
        })
    }

    /// The signed PSBT of a `SignBtc` or `SignRightsRefill` reply.
    fn signed_psbt_reply(
        resp: EnclaveResponse,
        signer_network_id: u32,
        rpc: &str,
    ) -> Result<Response<SignatureResponse>, Status> {
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
            Some(enclave_response::Response::Error(e)) => Err(Self::enclave_error_to_status(&e)),
            other => Err(Status::internal(format!(
                "unexpected enclave response for {rpc}: {:?}",
                other
            ))),
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
    /// - RGB_RIGHTS_REFILL: the mint wallet's rights send to SignRightsRefill
    ///   (no source).
    async fn sign(
        &self,
        request: Request<grpc_proto::SignRequest>,
    ) -> Result<Response<SignatureResponse>, Status> {
        let mut inner = request.into_inner();

        let common = Self::common_sign_request(&inner)?;
        let data_type = DataType::try_from(common.data_type).map_err(|_| {
            Status::invalid_argument(format!("unknown data_type: {}", common.data_type))
        })?;
        let signer_network_id = common.dst_network_id;

        if let Some(sign_request::Data::CcdData(_)) = inner.data.as_ref() {
            return Err(Status::invalid_argument(
                "Concordium signing is not supported",
            ));
        }

        match data_type {
            DataType::Transaction => {
                let source = Self::source_proof(&mut inner)?;
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
                            "Concordium sign request should have been refused before destination dispatch",
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

                // An EVM->RGB bridge sign: the reply is kept for a retry of the
                // same request, and a retry of a request still in flight joins
                // it instead of reaching the enclave (see `signed_responses`).
                let lead = if expects_evm {
                    None
                } else {
                    match self.signed.claim(SignedResponses::key(&enclave_req)).await {
                        Claim::Serve(signed) => {
                            tracing::info!(
                                psbt_len = signed.signed_psbt.len(),
                                "gRPC Sign: retried RGB transaction answered from the kept reply"
                            );
                            return Ok(Response::new(SignatureResponse {
                                signer_network_id,
                                signature: signed.signed_psbt,
                                identifier: None,
                                call_data: Vec::new(),
                                public_key: Vec::new(),
                            }));
                        }
                        Claim::Lead(lead) => Some(lead),
                    }
                };

                let start = std::time::Instant::now();
                let resp = self.send_to_enclave_leading(enclave_req, lead).await?;
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
                // The enclave signs on the vanilla BIP-86 account. Outputs that
                // do not pay back to its own scripts must fit `BTC_MAX_UNOWNED_SATS`,
                // the inputs `BTC_MAX_TOTAL_SATS`, and the fee the fee policy.
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
                Self::signed_psbt_reply(resp, signer_network_id, "SignBtc")
            }
            DataType::RgbRightsRefill => {
                let enclave_req = Self::rights_refill_request(inner)?;
                tracing::info!(
                    dst_network_id = signer_network_id,
                    "gRPC Sign: rights refill (data_type=RGB_RIGHTS_REFILL)"
                );
                let resp = self.send_to_enclave(enclave_req).await?;
                Self::signed_psbt_reply(resp, signer_network_id, "SignRightsRefill")
            }
            other => {
                tracing::warn!(?other, "unsupported data_type in Sign request");
                Err(Status::invalid_argument(format!(
                    "unsupported data_type: {other:?}"
                )))
            }
        }
    }

    /// Return the enclave gas-tx public key for `data_type` EVM_GAS_TX: the
    /// 64-byte uncompressed X||Y of the gas key m/44'/60'/0'/0/1. Other data
    /// types are refused.
    ///
    /// For Nitro evidence binding these public keys to approved measured code,
    /// use `AttestedPublicKey` with a trusted Real verifier. Genuine Nitro
    /// evidence requires a Nitro Security Module. See docs/pubkey-attestation.md
    /// for what verification does and does not prove.
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

    /// Initialize the enclave keys and set the optional donor secret. The
    /// enclave generates a new mnemonic, or a KMS build loads or creates its
    /// seed through KMS. Map cloning_secret to the enclave cloning_secret
    /// field. This RPC does not import a mnemonic or seed.
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
            Some(enclave_response::Response::InitializeKey(_)) => {
                Ok(Response::new(InitializeResponse {
                    attestation: vec![], // Initialize returns no attestation
                    // AttestedPublicKey returns the keys, so Initialize returns none.
                    public_key: Vec::new(),
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

    /// Relay a 32-byte caller nonce to the enclave and return its public-key
    /// bundle, policy and attestation document. The document commits to the EVM
    /// public key and sha256(bundle || policy). This handler does not verify it:
    /// the caller must use a trusted verifier with approved PCRs and expected
    /// policy before relying on the identity. See docs/pubkey-attestation.md
    /// for the checks and their limits.
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

#[cfg(test)]
mod tests;
