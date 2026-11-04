//! The heap of the parent while it serves large `Sign` requests.
//!
//! The server has the limits of `main.rs` without TLS and the access layer.
//! These are the default number of requests at once, the shape check and the
//! 24 MiB message limit. The enclave stand-in reads each frame and answers with an
//! error at once. A global meter counts the heap of the whole process, so it
//! also counts the copy of each request that the client encodes.
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Duration;

use prost::Message;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Endpoint, Server};
use tonic::{Code, Status};
use utexo_bridge_parent::{
    config::Config,
    enclave_proto::{enclave_response, EnclaveResponse, ErrorResponse},
    framing,
    grpc_proto::{
        parent_service_server::ParentServiceServer, sign_request, source_proof, EnrichedEvmPayload,
        MerkleProofEntry, RgbSource, SignRequest, SourceProof,
    },
    grpc_server::{EnclaveTarget, ParentAdapterService},
    request_shape::{ShapeLayer, MAX_WIRE_ELEMENTS},
    signer::SignatureResponse,
    transport_security::LimitedIncoming,
};

struct Meter;
static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = NOW.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        System.dealloc(p, layout);
        NOW.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        let q = System.realloc(p, layout, new);
        if !q.is_null() {
            if new >= layout.size() {
                grew(new - layout.size());
            } else {
                NOW.fetch_sub(layout.size() - new, Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static METER: Meter = Meter;

const MIB: usize = 1024 * 1024;

/// Sends a ready-made protobuf body, so the client holds no decoded copy.
#[derive(Clone, Default)]
struct Raw;
struct RawEncoder;
struct ResponseDecoder;

impl Codec for Raw {
    type Encode = Vec<u8>;
    type Decode = SignatureResponse;
    type Encoder = RawEncoder;
    type Decoder = ResponseDecoder;
    fn encoder(&mut self) -> RawEncoder {
        RawEncoder
    }
    fn decoder(&mut self) -> ResponseDecoder {
        ResponseDecoder
    }
}

impl Encoder for RawEncoder {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        use bytes::BufMut;
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for ResponseDecoder {
    type Item = SignatureResponse;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<SignatureResponse>, Status> {
        SignatureResponse::decode(src)
            .map(Some)
            .map_err(|e| Status::internal(e.to_string()))
    }
}

/// `SignRequest` with an RGB source of `entries` empty Merkle proof entries,
/// written directly. Each entry is 2 bytes on the wire and a 56-byte struct
/// after the decode.
fn empty_entries(entries: usize) -> Vec<u8> {
    let rgb_len = 2 * entries;
    let mut source = vec![0x5a]; // SourceProof.rgb, field 11
    prost::encoding::encode_varint(rgb_len as u64, &mut source);
    source.extend(std::iter::repeat_n([0x2a, 0x00], entries).flatten()); // RgbSource field 5
    let mut body = vec![0x0a, 0x00]; // SignRequest.common, empty
    body.push(0x12); // SignRequest.source, field 2
    prost::encoding::encode_varint(source.len() as u64, &mut body);
    body.extend_from_slice(&source);
    body
}

/// The densest request that passes the shape check. It has as many empty
/// proof entries as the element limit allows. A consignment fills the rest of
/// the frame.
fn densest_passing(frame: usize) -> Vec<u8> {
    let entries = MAX_WIRE_ELEMENTS - 8;
    let req = SignRequest {
        common: Some(Default::default()),
        source: Some(SourceProof {
            chain: Some(source_proof::Chain::Rgb(RgbSource {
                consignment: vec![0x33; frame - 2 * entries - 64],
                merkle_proofs: vec![MerkleProofEntry::default(); entries],
                ..Default::default()
            })),
            ..Default::default()
        }),
        data: Some(sign_request::Data::EvmData(EnrichedEvmPayload::default())),
    };
    req.encode_to_vec()
}

/// A burn as large as the enclave takes: a consignment of `consignment`
/// bytes and 16 384 proofs of 13 path elements.
fn real_burn(consignment: usize) -> Vec<u8> {
    let proof = MerkleProofEntry {
        txid: vec![0x11; 32],
        block_height: 900_000,
        tx_position: 7,
        merkle_path: vec![vec![0x22; 32]; 13],
    };
    SignRequest {
        common: Some(Default::default()),
        source: Some(SourceProof {
            chain: Some(source_proof::Chain::Rgb(RgbSource {
                consignment: vec![0x33; consignment],
                merkle_proofs: vec![proof; 16_384],
                ..Default::default()
            })),
            ..Default::default()
        }),
        data: Some(sign_request::Data::EvmData(EnrichedEvmPayload::default())),
    }
    .encode_to_vec()
}

/// Reads each frame and answers with an error, as an enclave that refuses.
fn refusing_enclave() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let mut left = u32::from_le_bytes(len) as usize;
                let mut sink = [0u8; 64 * 1024];
                while left > 0 {
                    let want = left.min(sink.len());
                    match stream.read(&mut sink[..want]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => left -= n,
                    }
                }
                let reply = EnclaveResponse {
                    response: Some(enclave_response::Response::Error(ErrorResponse {
                        code: 3,
                        message: "refused by the test enclave".into(),
                    })),
                };
                let _ = framing::write_message(&mut stream, &reply);
                let _ = stream.flush();
            });
        }
    });
    addr
}

async fn server() -> std::net::SocketAddr {
    let enclave = refusing_enclave();
    let incoming = LimitedIncoming::bind("127.0.0.1:0".parse().unwrap(), 64)
        .await
        .unwrap();
    let addr = incoming.local_addr().unwrap();
    let max_concurrent = Config::from_env().grpc_max_concurrent;
    tokio::spawn(async move {
        Server::builder()
            .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
                max_concurrent,
            ))
            .layer(ShapeLayer)
            .load_shed(true)
            .concurrency_limit_per_connection(32)
            .max_concurrent_streams(Some(32))
            .timeout(Duration::from_secs(120))
            .add_service(
                ParentServiceServer::new(ParentAdapterService::new(EnclaveTarget::Tcp(
                    enclave.to_string(),
                )))
                .max_decoding_message_size(framing::MAX_MESSAGE_SIZE as usize),
            )
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    addr
}

/// Sends each body at once and returns the outcomes and the peak heap above
/// the start.
async fn send(
    addr: std::net::SocketAddr,
    bodies: Vec<Vec<u8>>,
) -> (Vec<Result<(), Status>>, usize) {
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .timeout(Duration::from_secs(120))
        .connect()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let start = NOW.load(Relaxed);
    PEAK.store(start, Relaxed);
    let mut calls = tokio::task::JoinSet::new();
    for body in bodies {
        let mut grpc = tonic::client::Grpc::new(channel.clone());
        calls.spawn(async move {
            grpc.ready().await.unwrap();
            let path =
                tonic::codegen::http::uri::PathAndQuery::from_static("/parent.ParentService/Sign");
            grpc.unary(tonic::Request::new(body), path, Raw)
                .await
                .map(|_| ())
        });
    }
    let mut outcomes = Vec::new();
    while let Some(done) = calls.join_next().await {
        outcomes.push(done.unwrap());
    }
    (outcomes, PEAK.load(Relaxed) - start)
}

/// One test, so that no other test moves the meter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_sign_requests_stay_within_a_small_factor_of_their_size() {
    assert_eq!(Config::from_env().grpc_max_concurrent, 8);
    let addr = server().await;
    let frame = framing::MAX_MESSAGE_SIZE as usize;

    // A frame of empty proof entries is refused before the decode. Before the
    // shape check, it took 65 times its size.
    let worst = empty_entries((frame - 16) / 2);
    let size = worst.len();
    let (outcomes, peak) = send(addr, vec![worst]).await;
    let status = outcomes[0].as_ref().unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument, "{status}");
    assert!(
        status
            .message()
            .contains(&format!("more than {MAX_WIRE_ELEMENTS} elements")),
        "{status}"
    );
    println!("empty proof entries: {size} bytes, peak {} MiB", peak / MIB);
    assert!(
        peak <= 4 * size,
        "peak {peak} for a request of {size} bytes"
    );

    // A burn as large as the enclave takes passes the check and reaches the
    // enclave stand-in.
    let burn = real_burn(10 * MIB);
    let size = burn.len();
    let (outcomes, peak) = send(addr, vec![burn]).await;
    let status = outcomes[0].as_ref().unwrap_err();
    assert_eq!(status.message(), "refused by the test enclave", "{status}");
    println!("largest real burn: {size} bytes, peak {} MiB", peak / MIB);
    assert!(
        peak <= 6 * size,
        "peak {peak} for a request of {size} bytes"
    );

    // The densest request that passes the check holds the most elements and
    // the most bytes.
    let densest = densest_passing(frame);
    let size = densest.len();
    let (outcomes, peak) = send(addr, vec![densest]).await;
    let status = outcomes[0].as_ref().unwrap_err();
    assert_eq!(status.message(), "refused by the test enclave", "{status}");
    println!(
        "densest passing request: {size} bytes, peak {} MiB",
        peak / MIB
    );
    assert!(
        peak <= 8 * size,
        "peak {peak} for a request of {size} bytes"
    );

    // Requests sent at once add up, each within its own bound.
    let bursts = 12;
    let each = real_burn(MIB);
    let size = each.len();
    let (outcomes, peak) = send(addr, vec![each; bursts]).await;
    assert!(outcomes.iter().all(|o| o.is_err()));
    println!(
        "{bursts} burns at once: {size} bytes each, peak {} MiB",
        peak / MIB
    );
    assert!(
        peak <= bursts * 6 * size,
        "peak {peak} for {bursts} requests of {size} bytes"
    );
}
