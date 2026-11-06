//! The parent keeps the reply of an EVM->RGB bridge sign and answers a retry
//! of the same request itself, so a response lost between the enclave and the
//! node is not lost for good and the enclave never sees the request twice.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Server;

use utexo_bridge_parent::enclave_proto::{
    self, enclave_request, enclave_response, EnclaveRequest, EnclaveResponse,
};
use utexo_bridge_parent::enriched;
use utexo_bridge_parent::framing;
use utexo_bridge_parent::grpc_proto::parent_service_client::ParentServiceClient;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_proto::{
    sign_request, source_proof, EvmSource, SignRequest, SourceProof,
};
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::signed_responses::SignedResponses;
use utexo_bridge_parent::signer::{DataType, SignRequest as CommonSignRequest};

/// A mock enclave that signs every RGB-destination `Sign` after `delay` and
/// counts the requests it saw. The signature is the PSBT, reversed.
fn start_counting_enclave(delay: Duration) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let req: EnclaveRequest = match framing::read_message(&mut stream) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let resp = match req.request {
                Some(enclave_request::Request::Sign(sign)) => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(delay);
                    let psbt = match sign.destination_network {
                        Some(enclave_proto::sign_request::DestinationNetwork::RgbDestination(
                            d,
                        )) => d.psbt_bytes,
                        other => panic!("the mock expects an RGB destination, got {other:?}"),
                    };
                    EnclaveResponse {
                        response: Some(enclave_response::Response::SignedPsbt(
                            enclave_proto::SignedPsbtResponse {
                                signed_psbt: psbt.into_iter().rev().collect(),
                                inputs_signed: 1,
                            },
                        )),
                    }
                }
                other => panic!("the mock expects Sign, got {other:?}"),
            };
            let _ = framing::write_message(&mut stream, &resp);
        }
    });

    (port, seen)
}

async fn start_parent(enclave_port: u16, ttl: Duration) -> u16 {
    let grpc_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let grpc_addr = grpc_listener.local_addr().unwrap();
    drop(grpc_listener);

    let service = ParentAdapterService::with_signed_responses(
        EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")),
        SignedResponses::new(ttl, 16, 1 << 20),
    );
    tokio::spawn(async move {
        Server::builder()
            .add_service(ParentServiceServer::new(service))
            .serve(grpc_addr)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    grpc_addr.port()
}

fn rgb_sign_request(psbt_bytes: Vec<u8>) -> SignRequest {
    SignRequest {
        common: Some(CommonSignRequest {
            src_network_id: 84,
            dst_network_id: 0,
            data_type: DataType::Transaction as i32,
        }),
        source: Some(SourceProof {
            source_network_id: 84,
            token: String::new(),
            amount: 1_000,
            commission: 10,
            recipient: String::new(),
            finalized: true,
            chain: Some(source_proof::Chain::Evm(EvmSource {
                tx_hash: vec![0xAA; 32],
                funds_in_operation_id: vec![0x33; 32],
            })),
        }),
        data: Some(sign_request::Data::RgbData(enriched::EnrichedRgbPayload {
            operation_idx: 5,
            psbt_bytes,
            psbt_output_amount: 0,
            rgb_asset_id: String::new(),
            consignment: vec![],
            consignment_hash: vec![],
            fascia: vec![],
            parent_fascia: vec![],
        })),
    }
}

async fn client(grpc_port: u16) -> ParentServiceClient<tonic::transport::Channel> {
    ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap()
}

/// The node lost the first reply and asks again: the parent answers from the
/// reply it kept, with the same bytes, and the enclave saw one request.
#[tokio::test]
async fn a_retry_of_the_same_request_is_answered_without_a_second_exchange() {
    let (enclave_port, seen) = start_counting_enclave(Duration::ZERO);
    let grpc_port = start_parent(enclave_port, Duration::from_secs(60)).await;
    let mut client = client(grpc_port).await;

    let first = client
        .sign(rgb_sign_request(vec![0x11; 32]))
        .await
        .unwrap()
        .into_inner();
    let second = client
        .sign(rgb_sign_request(vec![0x11; 32]))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(first.signature, vec![0x11; 32]);
    assert_eq!(
        first.signature, second.signature,
        "the retry gets the same signed PSBT"
    );
    assert_eq!(seen.load(Ordering::SeqCst), 1, "the enclave signed once");
}

/// The first caller gives up while the enclave signs (its gRPC deadline ends
/// first), so its handler is gone when the reply arrives. The reply is kept
/// anyway: a retry after the enclave answered gets it, and the enclave signed
/// once.
#[tokio::test]
async fn a_reply_outlives_a_caller_that_gave_up() {
    let (enclave_port, seen) = start_counting_enclave(Duration::from_millis(600));
    let grpc_port = start_parent(enclave_port, Duration::from_secs(60)).await;
    let mut client = client(grpc_port).await;

    let mut first = tonic::Request::new(rgb_sign_request(vec![0x55; 32]));
    first.set_timeout(Duration::from_millis(100));
    let err = client.sign(first).await.unwrap_err();
    assert!(
        matches!(
            err.code(),
            tonic::Code::DeadlineExceeded | tonic::Code::Cancelled
        ),
        "the first call gives up: {err:?}"
    );

    // The enclave answers at about 600 ms.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let retry = client
        .sign(rgb_sign_request(vec![0x55; 32]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(retry.signature, vec![0x55; 32], "the signed PSBT");
    assert_eq!(seen.load(Ordering::SeqCst), 1, "the enclave signed once");
}

/// A retry that arrives while the first exchange is still waiting on the
/// enclave joins it: one exchange, both callers get the reply.
#[tokio::test]
async fn a_retry_during_the_exchange_joins_it() {
    let (enclave_port, seen) = start_counting_enclave(Duration::from_millis(400));
    let grpc_port = start_parent(enclave_port, Duration::from_secs(60)).await;
    let mut a = client(grpc_port).await;
    let mut b = client(grpc_port).await;

    let first = tokio::spawn(async move { a.sign(rgb_sign_request(vec![0x22; 32])).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = tokio::spawn(async move { b.sign(rgb_sign_request(vec![0x22; 32])).await });

    let first = first.await.unwrap().unwrap().into_inner();
    let second = second.await.unwrap().unwrap().into_inner();
    assert_eq!(first.signature, second.signature);
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "one exchange for both callers"
    );
}

#[tokio::test]
async fn a_cancelled_grpc_call_keeps_the_reply_for_a_retry() {
    let (enclave_port, seen) = start_counting_enclave(Duration::from_millis(400));
    let grpc_port = start_parent(enclave_port, Duration::from_secs(60)).await;
    let mut first_client = client(grpc_port).await;
    let mut retry_client = client(grpc_port).await;
    let first =
        tokio::spawn(async move { first_client.sign(rgb_sign_request(vec![0x52; 32])).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while seen.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();

    assert!(!first.is_finished());
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());

    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        retry_client.sign(rgb_sign_request(vec![0x52; 32])),
    )
    .await
    .unwrap()
    .unwrap()
    .into_inner();

    assert_eq!(reply.signature, vec![0x52; 32]);
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "the detached exchange must supply the retry"
    );
}

/// Another PSBT is another request: it reaches the enclave, which applies its
/// own replay rule. An expired reply is not served either.
#[tokio::test]
async fn another_request_or_an_expired_reply_reaches_the_enclave() {
    let (enclave_port, seen) = start_counting_enclave(Duration::ZERO);
    let grpc_port = start_parent(enclave_port, Duration::from_millis(200)).await;
    let mut client = client(grpc_port).await;

    client.sign(rgb_sign_request(vec![0x33; 32])).await.unwrap();
    client.sign(rgb_sign_request(vec![0x44; 32])).await.unwrap();
    assert_eq!(
        seen.load(Ordering::SeqCst),
        2,
        "a different PSBT is a new exchange"
    );

    tokio::time::sleep(Duration::from_millis(250)).await;
    client.sign(rgb_sign_request(vec![0x33; 32])).await.unwrap();
    assert_eq!(
        seen.load(Ordering::SeqCst),
        3,
        "an expired reply is not served"
    );
}
