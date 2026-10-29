//! The Sign limit of the shape layer.
//!
//! The signer node checks the parent with a `PublicKey` call. When that call
//! fails, the node reports the parent as unreachable. When it gets
//! `UNAVAILABLE`, the node also opens a new connection, and that cancels each
//! `Sign` request on the old one. So the limit applies to `Sign` only, and a
//! `PublicKey` call gets an answer while the `Sign` requests run.
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tonic::transport::{Channel, Endpoint, Server};
use tonic::Code;
use utexo_bridge_parent::{
    config::Config,
    enclave_proto::{enclave_response, EnclaveResponse, ErrorResponse},
    framing,
    grpc_proto::{
        parent_service_client::ParentServiceClient, parent_service_server::ParentServiceServer,
        sign_request, source_proof, EnrichedEvmPayload, MerkleProofEntry, RgbSource, SignRequest,
        SourceProof,
    },
    grpc_server::{EnclaveTarget, ParentAdapterService},
    request_shape::ShapeLayer,
    signer::{DataType, PublicKeyRequest},
    transport_security::LimitedIncoming,
};

/// An enclave stand-in. It answers a frame of less than 1 KiB at once, and it
/// holds each larger frame until `release` is set. `held` counts the frames
/// that it holds.
fn holding_enclave(held: Arc<AtomicUsize>, release: Arc<AtomicBool>) -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (held, release) = (held.clone(), release.clone());
            std::thread::spawn(move || {
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let len = u32::from_le_bytes(len) as usize;
                let mut frame = vec![0u8; len];
                if stream.read_exact(&mut frame).is_err() {
                    return;
                }
                let message = if len < 1024 {
                    "answered by the test enclave"
                } else {
                    held.fetch_add(1, SeqCst);
                    while !release.load(SeqCst) {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    "released by the test enclave"
                };
                let reply = EnclaveResponse {
                    response: Some(enclave_response::Response::Error(ErrorResponse {
                        code: 3,
                        message: message.into(),
                    })),
                };
                let _ = framing::write_message(&mut stream, &reply);
            });
        }
    });
    addr
}

async fn server(enclave: std::net::SocketAddr) -> std::net::SocketAddr {
    let incoming = LimitedIncoming::bind("127.0.0.1:0".parse().unwrap(), 64)
        .await
        .unwrap();
    let addr = incoming.local_addr().unwrap();
    let cfg = Config::from_env();
    tokio::spawn(async move {
        Server::builder()
            .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
                cfg.grpc_max_concurrent,
            ))
            .layer(ShapeLayer::new(cfg.grpc_max_concurrent_sign))
            .load_shed(true)
            .concurrency_limit_per_connection(32)
            .max_concurrent_streams(Some(32))
            .timeout(Duration::from_secs(120))
            .add_service(ParentServiceServer::new(ParentAdapterService::new(
                EnclaveTarget::Tcp(enclave.to_string()),
            )))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    addr
}

/// A small burn: its enclave frame is more than 1 KiB.
fn burn() -> SignRequest {
    SignRequest {
        common: Some(Default::default()),
        source: Some(SourceProof {
            chain: Some(source_proof::Chain::Rgb(RgbSource {
                consignment: vec![0x33; 4096],
                merkle_proofs: vec![MerkleProofEntry {
                    txid: vec![0x11; 32],
                    block_height: 900_000,
                    tx_position: 7,
                    merkle_path: vec![vec![0x22; 32]; 13],
                }],
                ..Default::default()
            })),
            ..Default::default()
        }),
        data: Some(sign_request::Data::EvmData(EnrichedEvmPayload::default())),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_public_key_call_gets_an_answer_while_the_sign_limit_is_full() {
    let max_sign = Config::from_env().grpc_max_concurrent_sign;
    let held = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let addr = server(holding_enclave(held.clone(), release.clone())).await;
    let channel: Channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .timeout(Duration::from_secs(60))
        .connect()
        .await
        .unwrap();

    // Fill the Sign limit with requests that the enclave holds.
    let mut running = tokio::task::JoinSet::new();
    for _ in 0..max_sign {
        let mut client = ParentServiceClient::new(channel.clone());
        running.spawn(async move { client.sign(burn()).await });
    }
    let start = Instant::now();
    while held.load(SeqCst) < max_sign {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the Sign requests did not arrive"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The probe of the signer node still reaches the enclave.
    let mut client = ParentServiceClient::new(channel.clone());
    let probe = client
        .public_key(PublicKeyRequest {
            network_id: 0,
            data_type: DataType::EvmGasTx as i32,
        })
        .await
        .unwrap_err();
    assert_eq!(probe.message(), "answered by the test enclave", "{probe}");

    // One more Sign request gets UNAVAILABLE at once, so the node can retry it.
    let refused = client.sign(burn()).await.unwrap_err();
    assert_eq!(refused.code(), Code::Unavailable, "{refused}");
    assert!(
        refused
            .message()
            .contains(&format!("at most {max_sign} Sign requests at once")),
        "{refused}"
    );
    assert_eq!(held.load(SeqCst), max_sign);

    // The held requests end when the enclave answers them.
    release.store(true, SeqCst);
    while let Some(done) = running.join_next().await {
        let status = done.unwrap().unwrap_err();
        assert_eq!(status.message(), "released by the test enclave", "{status}");
    }
    // A Sign request gets a permit again.
    let again = client.sign(burn()).await.unwrap_err();
    assert_eq!(again.message(), "released by the test enclave", "{again}");
}
