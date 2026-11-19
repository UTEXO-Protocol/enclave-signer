//! Real BFA/SPV validation through the generated Parent gRPC entry point.
//! Test keys, regtest headers and the issuer-list transport are controlled.

// The shared generator gates a mint-only helper with an enclave cfg.
#[allow(dead_code, unexpected_cfgs)]
#[path = "../../enclave/tests/support/bfa_burn.rs"]
mod burn_fixture;

use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::U256;
use bitcoin::Network;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tonic::transport::{Endpoint, Server};
use tonic::{Code, Status};

use burn_fixture::{destination, digest, recover, Fixture, Route, CHAIN_ID, PAYEE, SEED};
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::keys::KeyManager;
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::{
    BurnDestination, EnclaveResponse, EvmDestination, SignRequest as EnclaveSignRequest,
};
use utexo_bridge_enclave::server;
use utexo_bridge_parent::enriched;
use utexo_bridge_parent::grpc_proto::parent_service_client::ParentServiceClient;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_proto::{self, sign_request, source_proof};
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::signer::{DataType, SignRequest as CommonSignRequest, SignatureResponse};
use utexo_bridge_parent::transport_security::LimitedIncoming;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const DESTINATION_NETWORK: u32 = 84;

/// Observe bytes consumed and returned by the actual handler, without replacing it.
struct RecordedStream {
    stream: TcpStream,
    received: Vec<u8>,
    sent: Vec<u8>,
}

impl Read for RecordedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.stream.read(buffer)?;
        self.received.extend_from_slice(&buffer[..count]);
        Ok(count)
    }
}

impl Write for RecordedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let count = self.stream.write(buffer)?;
        self.sent.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn grpc_request(request: &EnclaveSignRequest) -> grpc_proto::SignRequest {
    let Some(SourceNetwork::RgbSource(source)) = &request.source_network else {
        panic!("the fixture must supply real RGB evidence");
    };
    let destination = destination(request);

    grpc_proto::SignRequest {
        common: Some(CommonSignRequest {
            src_network_id: 0,
            dst_network_id: DESTINATION_NETWORK,
            data_type: DataType::Transaction as i32,
        }),
        source: Some(grpc_proto::SourceProof {
            source_network_id: 0,
            token: String::new(),
            amount: request.amount,
            commission: source.commission,
            recipient: String::new(),
            finalized: true,
            chain: Some(source_proof::Chain::Rgb(grpc_proto::RgbSource {
                consignment: source.consignment.clone(),
                consignment_hash: source.consignment_hash.clone(),
                // A different legacy hint detects use instead of SourceProof.amount.
                rgb_amount: request
                    .amount
                    .checked_add(1)
                    .expect("distinct legacy amount"),
                rgb_asset_id: source.asset_id.clone(),
            })),
        }),
        data: Some(sign_request::Data::EvmData(enriched::EnrichedEvmPayload {
            call_data: destination.call_data.clone(),
            nonce: destination.nonce,
            deadline: destination.deadline,
            chain_id: destination.chain_id,
            proxy_contract: destination.proxy_contract.clone(),
            calldata_amount: destination.calldata_amount,
            calldata_commission: destination.calldata_commission,
            unsigned_tx: Vec::new(),
            lz_release: destination
                .lz_release
                .as_ref()
                .map(|release| enriched::LzReleaseParams {
                    dst_eid: release.dst_eid,
                    min_amount_ld: release.min_amount_ld,
                    recipient: release.recipient.clone(),
                }),
            burn_destination: destination.burn_destination.as_ref().map(|record| {
                enriched::BurnDestination {
                    version: record.version,
                    destination_chain_id: record.destination_chain_id,
                    dst_eid: record.dst_eid,
                    recipient: record.recipient.clone(),
                }
            }),
        })),
    }
}

async fn sign_through_parent(
    fixture: Arc<Fixture>,
    mut expected_request: EnclaveSignRequest,
) -> (EnclaveResponse, Result<SignatureResponse, Status>) {
    let request = grpc_request(&expected_request);
    let list_reads = fixture.list_reads.clone();
    let reads_before = list_reads.load(Ordering::SeqCst);

    // Parent supplies this advisory flag; consensus still validates the bytes.
    let Some(SourceNetwork::RgbSource(source)) = &mut expected_request.source_network else {
        unreachable!();
    };
    source.consignment_valid = true;

    let enclave_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind enclave listener");
    let enclave_address = enclave_listener.local_addr().unwrap();
    let enclave_task = tokio::spawn(async move {
        let (stream, _) = timeout(TEST_TIMEOUT, enclave_listener.accept())
            .await
            .expect("Parent must connect to the enclave")
            .expect("accept enclave connection");
        let stream = stream.into_std().expect("blocking enclave socket");
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();

        tokio::task::spawn_blocking(move || {
            let mut stream = RecordedStream {
                stream,
                received: Vec::new(),
                sent: Vec::new(),
            };
            server::handle_connection(&mut stream, &fixture.ctx);
            let received = framing::read_request(&mut Cursor::new(stream.received))
                .expect("decode the bytes consumed by the real handler");
            let sent: EnclaveResponse = framing::read_message(&mut Cursor::new(stream.sent))
                .expect("decode the bytes returned by the real handler");
            (received, sent)
        })
        .await
        .expect("enclave worker must finish")
    });

    let incoming = LimitedIncoming::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .expect("bind Parent listener");
    let parent_address = incoming.local_addr().unwrap();
    let service = ParentAdapterService::new(EnclaveTarget::Tcp(enclave_address.to_string()));
    let (shutdown, stopped) = oneshot::channel();
    let parent_task = tokio::spawn(async move {
        Server::builder()
            .add_service(ParentServiceServer::new(service))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .expect("Parent server must finish")
    });

    let channel = timeout(
        TEST_TIMEOUT,
        Endpoint::from_shared(format!("http://{parent_address}"))
            .unwrap()
            .connect_timeout(TEST_TIMEOUT)
            .timeout(TEST_TIMEOUT)
            .connect(),
    )
    .await
    .expect("gRPC connection must finish within the test budget")
    .expect("connect generated gRPC client");
    let mut client = ParentServiceClient::new(channel);
    let result = timeout(TEST_TIMEOUT, client.sign(request)).await;
    drop(client);
    let _ = shutdown.send(());
    timeout(TEST_TIMEOUT, parent_task)
        .await
        .expect("Parent shutdown must finish")
        .expect("Parent task must not panic");
    let (received, sent) = timeout(TEST_TIMEOUT, enclave_task)
        .await
        .expect("enclave request must finish")
        .expect("enclave task must not panic");

    let reply = result
        .expect("Sign must complete within the test budget")
        .map(|response| response.into_inner());
    assert_eq!(received.request, Some(Request::Sign(expected_request)));
    assert!(
        list_reads.load(Ordering::SeqCst) >= reads_before + 2,
        "each real validation must consult the issuer's reject list"
    );
    (sent, reply)
}

async fn assert_signed(fixture: Arc<Fixture>, request: EnclaveSignRequest) {
    let original_destination = destination(&request).clone();
    let expected_address = *KeyManager::from_seed(SEED, Network::Regtest)
        .expect("test key")
        .evm_address();
    let (sent, reply) = sign_through_parent(fixture, request).await;
    let reply = reply.expect("valid RGB burn must sign through Parent");
    let Some(Response::EvmSignature(signed)) = sent.response else {
        panic!("the real handler must return an EVM signature: {sent:?}");
    };
    assert_eq!(reply.signer_network_id, DESTINATION_NETWORK);
    assert_eq!(reply.call_data, original_destination.call_data);
    assert_eq!(reply.call_data, signed.call_data);
    assert_eq!(reply.signature, signed.signature);
    assert_eq!(
        recover(&reply.signature, digest(&original_destination)),
        expected_address
    );
    let mut other_intent = original_destination;
    other_intent.nonce += 1;
    assert_ne!(
        recover(&reply.signature, digest(&other_intent)),
        expected_address,
        "the signature must commit to the original nonce"
    );
}

async fn assert_rejected(
    fixture: Arc<Fixture>,
    request: EnclaveSignRequest,
    expected_message: &str,
) {
    let (sent, reply) = sign_through_parent(fixture, request).await;
    let Some(Response::Error(error)) = sent.response else {
        panic!("the real handler must refuse without a signature: {sent:?}");
    };
    assert_eq!(error.code, 3, "the destination must fail its cross-check");
    assert!(
        error.message.contains(expected_message),
        "expected {expected_message:?}, got {error:?}"
    );
    let status = reply.expect_err("Parent must not return a signed reply");
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), error.message);
}

fn destination_mut(request: &mut EnclaveSignRequest) -> &mut EvmDestination {
    let Some(DestinationNetwork::EvmDestination(destination)) = &mut request.destination_network
    else {
        panic!("the fixture must supply an EVM destination");
    };
    destination
}

fn recipient_with_leading_zero() -> Vec<u8> {
    let mut recipient = vec![0];
    recipient.extend_from_slice(&PAYEE);
    recipient
}

#[tokio::test]
async fn grpc_direct_burn_returns_a_signature_for_the_forwarded_intent() {
    let fixture = Arc::new(Fixture::new(Route::Direct));
    let request = fixture.request(fixture.params.clone());
    assert_eq!(
        destination(&request)
            .burn_destination
            .as_ref()
            .unwrap()
            .version,
        1
    );
    assert_signed(fixture, request).await;
}

#[tokio::test]
async fn grpc_legacy_direct_burn_signs_without_a_destination_record() {
    let fixture = Arc::new(Fixture::v0(Route::Direct));
    let request = fixture.request(fixture.params.clone());
    assert!(destination(&request).burn_destination.is_none());
    assert_signed(fixture, request).await;
}

#[tokio::test]
async fn grpc_layerzero_burn_preserves_the_original_recipient_bytes() {
    let recipient = recipient_with_leading_zero();
    let fixture = Arc::new(Fixture::v1_with_recipient(
        Route::LayerZero,
        recipient.clone(),
    ));
    let request = fixture.request(fixture.params.clone());
    let destination = destination(&request);
    assert_eq!(
        destination.burn_destination.as_ref().unwrap().recipient,
        recipient
    );
    let mut padded = vec![0; 32 - PAYEE.len()];
    padded.extend_from_slice(&PAYEE);
    assert_eq!(destination.lz_release.as_ref().unwrap().recipient, padded);
    assert_signed(fixture, request).await;
}

#[tokio::test]
async fn grpc_legacy_burn_rejects_a_destination_record() {
    let fixture = Arc::new(Fixture::v0(Route::Direct));
    let mut request = fixture.request(fixture.params.clone());
    assert_signed(fixture.clone(), request.clone()).await;
    destination_mut(&mut request).burn_destination = Some(BurnDestination {
        version: 1,
        destination_chain_id: CHAIN_ID,
        dst_eid: 0,
        recipient: PAYEE.to_vec(),
    });
    assert_rejected(fixture, request, "burn_destination sent for a V0 burn").await;
}

#[tokio::test]
async fn grpc_legacy_burn_rejects_the_layerzero_route() {
    let mut fixture = Fixture::v0(Route::LayerZero);
    // Keep the LayerZero payload admissible so the burn's direct-only rule rejects it.
    let layerzero_request = fixture.request(fixture.params.clone());
    fixture.route = Route::Direct;
    let mut direct_params = fixture.params.clone();
    direct_params.destinationChainId = U256::from(CHAIN_ID);
    let direct_request = fixture.request(direct_params);
    let fixture = Arc::new(fixture);
    assert_signed(fixture.clone(), direct_request).await;
    assert_rejected(
        fixture,
        layerzero_request,
        "dstEid mismatch: burn names None, calldata sends to Some(30109)",
    )
    .await;
}

#[tokio::test]
async fn grpc_versioned_burn_requires_a_destination_record() {
    let fixture = Arc::new(Fixture::new(Route::Direct));
    let mut request = fixture.request(fixture.params.clone());
    assert_signed(fixture.clone(), request.clone()).await;
    destination_mut(&mut request).burn_destination = None;
    assert_rejected(
        fixture,
        request,
        "burn commits to a destination hash, but the request has no burn_destination",
    )
    .await;
}

#[tokio::test]
async fn grpc_burn_rejects_an_unknown_destination_record_version() {
    let fixture = Arc::new(Fixture::new(Route::Direct));
    let mut request = fixture.request(fixture.params.clone());
    assert_signed(fixture.clone(), request.clone()).await;
    destination_mut(&mut request)
        .burn_destination
        .as_mut()
        .unwrap()
        .version = 2;
    assert_rejected(fixture, request, "unknown burn_destination version 2").await;
}

#[tokio::test]
async fn grpc_burn_rejects_changed_destination_record_bytes() {
    let fixture = Arc::new(Fixture::v1_with_recipient(
        Route::LayerZero,
        recipient_with_leading_zero(),
    ));
    let mut request = fixture.request(fixture.params.clone());
    assert_signed(fixture.clone(), request.clone()).await;
    let destination = destination_mut(&mut request);
    let record = destination.burn_destination.as_mut().unwrap();
    assert_eq!(record.recipient.remove(0), 0);
    assert_eq!(record.recipient, PAYEE);
    // Both byte strings pad to the same calldata word; only the committed record changes.
    let mut padded = vec![0; 32 - record.recipient.len()];
    padded.extend_from_slice(&record.recipient);
    assert_eq!(destination.lz_release.as_ref().unwrap().recipient, padded);
    assert_rejected(fixture, request, "!= burn burnReason 0x").await;
}
