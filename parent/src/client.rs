use std::time::Duration;

use crate::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, EvmSignatureResponse,
    GetAttestedPublicKeyRequest, GetAttestedPublicKeyResponse, GetLastSavedBlockRequest,
    GetLastSavedBlockResponse, GetLimitsRequest, GetPublicKeyRequest, HealthRequest,
    HealthResponse, InitializeKeyRequest, InitializeKeyResponse, InitiateCloningRequest,
    InitiateCloningResponse, Limits, LimitsResponse, MerkleProofEntry, PublicKeysResponse,
    SetCloneRequest, SetEndpointsRequest, SetLimitsRequest, SignedPsbtResponse,
};
use crate::error::{ParentError, Result};
use crate::framing;
use crate::grpc_server::{is_timeout, ENCLAVE_WAIT_MARGIN_SECS, IMAGE_DEADLINE_SECS};

/// TCP connect timeout. It matters only across a network or a bad vsock proxy.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Read and write timeout for one socket operation of `GetLimits`. The enclave
/// answers it with no other work, so this timeout stops a silent peer from
/// hanging the CLI.
const LIMITS_IO_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// On-chain `BridgeFundsIn.operationId` (32 bytes). Required; the replay key uses it.
    pub evm_funds_in_operation_id: Vec<u8>,
    pub evm_event_valid: bool,
    pub evm_event_finalized: bool,
    pub evm_token: Vec<u8>,
    pub evm_amount: u64,
    pub evm_recipient: Vec<u8>,
    pub evm_commission: u64,
    pub psbt_bytes: Vec<u8>,
    pub rgb_asset_id: String,
    /// rgb-lib fascia of the PSBT's tx: rgb-lib keeps its RGB data there.
    pub fascia: Vec<u8>,
    /// rgb-lib fascia of the tx that made the right the mint spends.
    pub parent_fascia: Vec<u8>,
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

    /// Send `req` and read the reply. Before any request other than
    /// `GetLimits`, read the socket deadline in force: each socket read and
    /// write of the request may then block for that deadline plus
    /// [`ENCLAVE_WAIT_MARGIN_SECS`], so the enclave gives up first, as it does
    /// for the parent. A consignment validation can take most of the deadline.
    pub fn send_request(&self, req: &EnclaveRequest) -> Result<EnclaveResponse> {
        let wait = match req.request {
            Some(enclave_request::Request::GetLimits(_)) => LIMITS_IO_TIMEOUT,
            _ => self.enclave_wait(LIMITS_IO_TIMEOUT)?,
        };
        self.exchange(req, wait)
    }

    /// The socket deadline in force plus [`ENCLAVE_WAIT_MARGIN_SECS`]. The
    /// deadline comes from `GetLimits`, whose socket reads and writes may each
    /// block for `limits_wait`. A `GetLimits` that times out is the error: the
    /// enclave does not answer. After any other failure, the wait starts from
    /// [`IMAGE_DEADLINE_SECS`].
    fn enclave_wait(&self, limits_wait: Duration) -> Result<Duration> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::GetLimits(GetLimitsRequest {})),
        };
        let deadline = match self.exchange(&req, limits_wait).and_then(limits_reply) {
            Ok(limits) => limits
                .current
                .map(|current| current.total_request_timeout_secs)
                .filter(|&secs| secs != 0)
                .unwrap_or(IMAGE_DEADLINE_SECS),
            Err(ParentError::Io(e)) if is_timeout(&e) => return Err(e.into()),
            Err(_) => IMAGE_DEADLINE_SECS,
        };
        Ok(Duration::from_secs(
            deadline.saturating_add(ENCLAVE_WAIT_MARGIN_SECS),
        ))
    }

    /// Connect, write `req` and read the reply. Each socket read and write may
    /// block for `wait`.
    fn exchange(&self, req: &EnclaveRequest, wait: Duration) -> Result<EnclaveResponse> {
        // A `vsock://<cid>[:<port>]` address targets one enclave. Without vsock
        // support in the build, it is an error.
        if let Some(spec) = self.addr.strip_prefix("vsock://") {
            #[cfg(all(feature = "vsock", target_os = "linux"))]
            {
                let (cid, port) = parse_vsock_spec(spec)?;
                return self.send_vsock(req, cid, port, wait);
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
                Some(cid) => self.send_vsock(req, cid, port, wait),
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
                .set_read_timeout(Some(wait))
                .map_err(|e| ParentError::Connection(format!("set_read_timeout: {e}")))?;
            stream
                .set_write_timeout(Some(wait))
                .map_err(|e| ParentError::Connection(format!("set_write_timeout: {e}")))?;
            framing::write_message(&mut stream, req)?;
            framing::read_message(&mut stream)
        }
    }

    #[cfg(feature = "vsock")]
    fn send_vsock(
        &self,
        req: &EnclaveRequest,
        cid: u32,
        port: u32,
        wait: Duration,
    ) -> Result<EnclaveResponse> {
        use vsock::VsockStream;
        let mut stream = VsockStream::connect_with_cid_port(cid, port).map_err(|e| {
            ParentError::Connection(format!("vsock connect cid={cid} port={port}: {e}"))
        })?;
        stream
            .set_read_timeout(Some(wait))
            .map_err(|e| ParentError::Connection(format!("set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(wait))
            .map_err(|e| ParentError::Connection(format!("set_write_timeout: {e}")))?;
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
                                // The CLI has no record, so it signs V0 burns only.
                                burn_destination: None,
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
                                psbt_bytes: req.psbt_bytes,
                                asset_id: req.rgb_asset_id,
                                fascia: req.fascia,
                                parent_fascia: req.parent_fascia,
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

    /// Attestation for `nonce`, straight from the enclave. Before keys exist,
    /// it attests the policy only.
    pub fn get_attested_public_key(&self, nonce: [u8; 32]) -> Result<GetAttestedPublicKeyResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::GetAttestedPublicKey(
                GetAttestedPublicKeyRequest {
                    nonce: nonce.to_vec(),
                },
            )),
        };
        let resp = self.send_request(&req)?;
        match resp.response {
            Some(enclave_response::Response::GetAttestedPublicKey(r)) => Ok(r),
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

    /// Read the time, memory and size limits of the enclave.
    pub fn get_limits(&self) -> Result<LimitsResponse> {
        self.limits_request(enclave_request::Request::GetLimits(GetLimitsRequest {}))
    }

    /// Change limits. A value of 0 keeps that limit. With `reset`, the limits
    /// go back to the image values first.
    pub fn set_limits(&self, values: Limits, reset: bool) -> Result<LimitsResponse> {
        self.limits_request(enclave_request::Request::SetLimits(SetLimitsRequest {
            values: Some(values),
            reset,
        }))
    }

    fn limits_request(&self, request: enclave_request::Request) -> Result<LimitsResponse> {
        let req = EnclaveRequest {
            request: Some(request),
        };
        limits_reply(self.send_request(&req)?)
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

/// The limits of a `GetLimits` or `SetLimits` reply.
fn limits_reply(resp: EnclaveResponse) -> Result<LimitsResponse> {
    match resp.response {
        Some(enclave_response::Response::Limits(limits)) => Ok(limits),
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

#[cfg(all(test, not(all(feature = "vsock", target_os = "linux"))))]
mod tests {
    use super::*;
    use crate::enclave_proto::ErrorResponse;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    /// A fake enclave on TCP. It sends each request to the receiver, then
    /// writes the reply of `answer`, or closes the connection when there is
    /// none.
    fn fake_enclave(
        answer: impl Fn(&EnclaveRequest) -> Option<EnclaveResponse> + Send + 'static,
    ) -> (EnclaveClient, mpsc::Receiver<EnclaveRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = EnclaveClient::new(&listener.local_addr().unwrap().to_string());
        let (requests, received) = mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let request: EnclaveRequest = framing::read_message(&mut stream).unwrap();
                let reply = answer(&request);
                let _ = requests.send(request);
                if let Some(reply) = reply {
                    // The client may have given up already.
                    let _ = framing::write_message(&mut stream, &reply);
                }
            }
        });
        (client, received)
    }

    fn limits_with_deadline(deadline: u64) -> EnclaveResponse {
        EnclaveResponse {
            response: Some(enclave_response::Response::Limits(LimitsResponse {
                current: Some(Limits {
                    total_request_timeout_secs: deadline,
                    ..Default::default()
                }),
                image: None,
            })),
        }
    }

    fn health() -> EnclaveResponse {
        EnclaveResponse {
            response: Some(enclave_response::Response::Health(HealthResponse::default())),
        }
    }

    fn is_get_limits(request: &EnclaveRequest) -> bool {
        matches!(
            request.request,
            Some(enclave_request::Request::GetLimits(_))
        )
    }

    fn assert_timeout(result: Result<impl std::fmt::Debug>) {
        match result {
            Err(ParentError::Io(e)) if is_timeout(&e) => {}
            other => panic!("expected a socket timeout, got {other:?}"),
        }
    }

    #[test]
    fn the_wait_is_the_deadline_in_force_and_the_margin() {
        let (client, _) = fake_enclave(|_| Some(limits_with_deadline(3_600)));
        assert_eq!(
            client.enclave_wait(LIMITS_IO_TIMEOUT).unwrap(),
            Duration::from_secs(3_600 + ENCLAVE_WAIT_MARGIN_SECS)
        );
    }

    #[test]
    fn each_request_but_get_limits_reads_the_deadline_first() {
        let (client, received) = fake_enclave(|request| {
            Some(if is_get_limits(request) {
                limits_with_deadline(40)
            } else {
                health()
            })
        });
        client.health().unwrap();
        assert!(is_get_limits(&received.recv().unwrap()));
        assert!(matches!(
            received.recv().unwrap().request,
            Some(enclave_request::Request::Health(_))
        ));

        client.get_limits().unwrap();
        assert!(is_get_limits(&received.recv().unwrap()));
        assert!(received.try_recv().is_err(), "a second request was sent");
    }

    #[test]
    fn an_enclave_that_does_not_give_its_deadline_gets_the_image_deadline() {
        let image = Duration::from_secs(IMAGE_DEADLINE_SECS + ENCLAVE_WAIT_MARGIN_SECS);
        let refused = EnclaveResponse {
            response: Some(enclave_response::Response::Error(ErrorResponse {
                code: 1,
                message: "refused".into(),
            })),
        };
        let no_current = EnclaveResponse {
            response: Some(enclave_response::Response::Limits(LimitsResponse::default())),
        };
        for answer in [
            None,
            Some(refused),
            Some(limits_with_deadline(0)),
            Some(no_current),
        ] {
            let (client, _) = fake_enclave(move |_| answer.clone());
            assert_eq!(client.enclave_wait(LIMITS_IO_TIMEOUT).unwrap(), image);
        }
    }

    #[test]
    fn a_silent_enclave_ends_the_request_at_get_limits() {
        // The fake keeps each connection open for a second and writes nothing.
        let (client, received) = fake_enclave(|_| {
            thread::sleep(Duration::from_secs(1));
            None
        });
        assert_timeout(client.enclave_wait(Duration::from_millis(100)));
        assert!(is_get_limits(&received.recv().unwrap()));
    }

    #[test]
    fn the_wait_bounds_each_socket_read() {
        let (client, _) = fake_enclave(|_| {
            thread::sleep(Duration::from_millis(500));
            Some(health())
        });
        let request = EnclaveRequest {
            request: Some(enclave_request::Request::Health(HealthRequest {})),
        };
        assert_timeout(client.exchange(&request, Duration::from_millis(100)));
        client.exchange(&request, Duration::from_secs(30)).unwrap();
    }
}
