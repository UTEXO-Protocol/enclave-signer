//! Real BFA/SPV validation through the generated Parent gRPC entry point.
//! Test keys, regtest headers and the issuer-list transport are controlled.

// The shared generator has enclave-only cfgs for unused mint helpers.
#[allow(dead_code, unexpected_cfgs)]
#[path = "../../enclave/tests/support/bfa_burn.rs"]
mod burn_fixture;

use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bitcoin::Network;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tonic::transport::{Endpoint, Server};

use burn_fixture::{destination, digest, recover, Fixture, Route, SEED};
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::keys::KeyManager;
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::SourceNetwork;
use utexo_bridge_enclave::proto::{EnclaveResponse, SignRequest as EnclaveSignRequest};
use utexo_bridge_enclave::server;
use utexo_bridge_parent::enriched;
use utexo_bridge_parent::grpc_proto::parent_service_client::ParentServiceClient;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_proto::{self, sign_request, source_proof};
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::signer::{DataType, SignRequest as CommonSignRequest};
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
    assert!(destination.lz_release.is_none(), "this control is direct");

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
                rgb_amount: request.amount,
                rgb_asset_id: source.asset_id.clone(),
                merkle_proofs: source
                    .merkle_proofs
                    .iter()
                    .map(|proof| grpc_proto::MerkleProofEntry {
                        txid: proof.txid.clone(),
                        block_height: proof.block_height,
                        tx_position: proof.tx_position,
                        merkle_path: proof.merkle_path.clone(),
                    })
                    .collect(),
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
            lz_release: None,
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

#[tokio::test]
async fn grpc_direct_burn_returns_a_signature_for_the_forwarded_intent() {
    let fixture = Fixture::new(Route::Direct);
    let mut expected_request = fixture.request(fixture.params.clone());
    let original_destination = destination(&expected_request).clone();
    let request = grpc_request(&expected_request);
    let expected_address = *KeyManager::from_seed(SEED, Network::Regtest)
        .expect("test key")
        .evm_address();
    let list_reads = fixture.list_reads.clone();

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
        .expect("valid RGB burn must sign through Parent")
        .into_inner();
    assert_eq!(received.request, Some(Request::Sign(expected_request)));
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
    assert!(
        list_reads.load(Ordering::SeqCst) >= 2,
        "real consensus must consult the issuer's reject list"
    );
}
