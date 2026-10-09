//! The parent's header sync against a real enclave or a scripted one, with a
//! fake Electrum server that serves synthetic regtest headers.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::block::{Header, Version};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
use tokio::sync::watch;
use tonic::Request;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, Checkpoint, HeaderChain, Network};
use utexo_bridge_enclave::server::{self as enclave_server, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;
use utexo_bridge_parent::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, ErrorResponse,
    GetLastSavedBlockRequest, GetLastSavedBlockResponse, HealthResponse, SubmitHeadersRequest,
    SubmitHeadersResponse,
};
use utexo_bridge_parent::enriched::EnrichedBtcPayload;
use utexo_bridge_parent::framing;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentService;
use utexo_bridge_parent::grpc_proto::{sign_request, SignRequest};
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::header_source::ElectrumSource;
use utexo_bridge_parent::header_sync::{HeaderSync, SyncState, SyncStatus};
use utexo_bridge_parent::signer::{DataType, PublicKeyRequest, SignRequest as CommonSignRequest};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

type Chain = Vec<[u8; 80]>;

fn block_hash(h: &[u8]) -> Vec<u8> {
    deserialize::<Header>(h)
        .unwrap()
        .block_hash()
        .to_byte_array()
        .to_vec()
}

fn header_bytes(h: &Header) -> [u8; 80] {
    serialize(h).try_into().unwrap()
}

fn genesis() -> Chain {
    vec![header_bytes(
        &bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header,
    )]
}

/// A genesis the regtest enclave does not know.
fn foreign_genesis() -> Chain {
    vec![header_bytes(&Header {
        version: Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 99,
    })]
}

/// `chain` plus `n` headers on its tip. `salt` makes a distinct branch.
fn extend(chain: &[[u8; 80]], n: usize, salt: u32) -> Chain {
    let mut out = chain.to_vec();
    for _ in 0..n {
        let prev: Header = deserialize(out.last().unwrap()).unwrap();
        out.push(header_bytes(&Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: prev.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: prev.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: salt,
        }));
    }
    out
}

// Fake Electrum server

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Good,
    /// Close every connection at once.
    Down,
    /// Accept and never answer.
    Silent,
    /// Good tip, malformed headers.
    Malformed,
}

struct Electrum {
    url: String,
    state: Arc<Mutex<(Chain, Mode)>>,
    connections: Arc<AtomicUsize>,
    max_open: Arc<AtomicUsize>,
}

impl Electrum {
    fn start(chain: Chain) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new((chain, Mode::Good)));
        let connections = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicUsize::new(0));
        let max_open = Arc::new(AtomicUsize::new(0));
        let (st, conns, mx) = (state.clone(), connections.clone(), max_open.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                conns.fetch_add(1, Ordering::SeqCst);
                let now = open.fetch_add(1, Ordering::SeqCst) + 1;
                mx.fetch_max(now, Ordering::SeqCst);
                let (st, open) = (st.clone(), open.clone());
                std::thread::spawn(move || {
                    serve_electrum(stream, &st);
                    open.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Self {
            url,
            state,
            connections,
            max_open,
        }
    }

    fn set_chain(&self, chain: Chain) {
        self.state.lock().unwrap().0 = chain;
    }

    fn set_mode(&self, mode: Mode) {
        self.state.lock().unwrap().1 = mode;
    }
}

fn serve_electrum(mut stream: TcpStream, state: &Mutex<(Chain, Mode)>) {
    match state.lock().unwrap().1 {
        Mode::Down => return,
        Mode::Silent => {
            // Hold the socket until the client closes it.
            let _ = std::io::copy(&mut stream, &mut std::io::sink());
            return;
        }
        _ => {}
    }
    let reader = BufReader::new(stream.try_clone().unwrap());
    for line in reader.lines() {
        let Ok(line) = line else { return };
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let (chain, mode) = state.lock().unwrap().clone();
        let result = match req["method"].as_str().unwrap() {
            "blockchain.headers.subscribe" => {
                let tip = chain.len() - 1;
                serde_json::json!({"height": tip, "hex": hex::encode(chain[tip])})
            }
            "blockchain.block.headers" if mode == Mode::Malformed => {
                serde_json::json!({"count": 1, "hex": "", "max": 2016})
            }
            "blockchain.block.headers" => {
                let start = req["params"][0].as_u64().unwrap() as usize;
                let count = req["params"][1].as_u64().unwrap() as usize;
                let end = (start + count.min(2016)).min(chain.len()).max(start);
                let hex: String = chain[start.min(chain.len())..end]
                    .iter()
                    .map(hex::encode)
                    .collect();
                serde_json::json!({"count": end - start, "hex": hex, "max": 2016})
            }
            other => panic!("unexpected Electrum method {other}"),
        };
        let reply = serde_json::json!({"jsonrpc": "2.0", "id": req["id"], "result": result});
        if writeln!(stream, "{reply}").is_err() {
            return;
        }
    }
}

// Enclaves

type Log = Arc<Mutex<Vec<(Instant, EnclaveRequest)>>>;

fn start_real_enclave() -> u16 {
    start_real_enclave_at(checkpoint_for(Network::Regtest))
}

/// The regtest checkpoint moved to `chain[height]`.
fn checkpoint_at(chain: &[[u8; 80]], height: u32) -> Checkpoint {
    let header: Header = deserialize(&chain[height as usize]).unwrap();
    Checkpoint {
        height,
        hash: header.block_hash().to_byte_array(),
        bits: header.bits.to_consensus(),
        time: header.time,
        ..checkpoint_for(Network::Regtest)
    }
}

fn start_real_enclave_at(checkpoint: Checkpoint) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    state.initialize_from_mnemonic(TEST_MNEMONIC).unwrap();
    let chain = Mutex::new(HeaderChain::new(Network::Regtest, checkpoint));
    let ctx = Arc::new(ServerContext::new(state, BridgeConfig::from_env(), chain));
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            enclave_server::handle_connection(s, &ctx);
        }
    });
    port
}

/// A server that logs every request and answers with `handler`. `None` holds
/// the connection open with no answer.
fn start_enclave_with(
    handler: impl Fn(EnclaveRequest) -> Option<EnclaveResponse> + Send + Sync + 'static,
) -> (u16, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let (handler, l) = (Arc::new(handler), log.clone());
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let (handler, l) = (handler.clone(), l.clone());
            std::thread::spawn(move || {
                let Ok(req) = framing::read_message::<EnclaveRequest>(&mut s) else {
                    return;
                };
                l.lock().unwrap().push((Instant::now(), req.clone()));
                match handler(req) {
                    Some(resp) => {
                        let _ = framing::write_message(&mut s, &resp);
                    }
                    None => {
                        let _ = std::io::copy(&mut s, &mut std::io::sink());
                    }
                }
            });
        }
    });
    (port, log)
}

/// A logging relay in front of `enclave`.
fn start_relay(enclave: u16) -> (u16, Log) {
    start_enclave_with(move |req| {
        let mut s = TcpStream::connect(("127.0.0.1", enclave)).unwrap();
        framing::write_message(&mut s, &req).unwrap();
        Some(framing::read_message(&mut s).unwrap())
    })
}

fn reply(r: enclave_response::Response) -> Option<EnclaveResponse> {
    Some(EnclaveResponse { response: Some(r) })
}

fn health(max_tip_age: u32) -> Option<EnclaveResponse> {
    reply(enclave_response::Response::Health(HealthResponse {
        spv_max_tip_age_secs: max_tip_age,
        ..Default::default()
    }))
}

/// A scripted enclave that follows `chain` and applies every submit that
/// `bad` lets through. `bad` answers the submits it wants to break.
fn start_scripted_enclave(
    chain: Chain,
    bad: impl Fn(&SubmitHeadersRequest) -> Option<Option<EnclaveResponse>> + Send + Sync + 'static,
) -> (u16, Log) {
    let tip = Mutex::new(0u32);
    start_enclave_with(move |req| match req.request.unwrap() {
        enclave_request::Request::Health(_) => health(7200),
        enclave_request::Request::GetLastSavedBlock(_) => {
            let h = *tip.lock().unwrap();
            reply(enclave_response::Response::GetLastSavedBlock(
                GetLastSavedBlockResponse {
                    block_height: h,
                    block_hash: block_hash(&chain[h as usize]),
                },
            ))
        }
        enclave_request::Request::SubmitHeaders(r) => {
            if let Some(answer) = bad(&r) {
                return answer;
            }
            let last = r.start_height + r.headers.len() as u32 - 1;
            *tip.lock().unwrap() = last;
            reply(enclave_response::Response::SubmitHeaders(
                SubmitHeadersResponse {
                    last_block_height: last,
                    last_block_hash: block_hash(r.headers.last().unwrap()),
                    headers_accepted: r.headers.len() as u32,
                },
            ))
        }
        other => panic!("unexpected request {other:?}"),
    })
}

fn submits(log: &Log) -> Vec<(Instant, SubmitHeadersRequest)> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|(t, r)| match &r.request {
            Some(enclave_request::Request::SubmitHeaders(s)) => Some((*t, s.clone())),
            _ => None,
        })
        .collect()
}

/// The real enclave's tip, read around the relay.
fn enclave_tip(port: u16) -> (u32, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = EnclaveRequest {
        request: Some(enclave_request::Request::GetLastSavedBlock(
            GetLastSavedBlockRequest {},
        )),
    };
    framing::write_message(&mut s, &req).unwrap();
    match framing::read_message::<EnclaveResponse>(&mut s)
        .unwrap()
        .response
    {
        Some(enclave_response::Response::GetLastSavedBlock(r)) => (r.block_height, r.block_hash),
        other => panic!("unexpected {other:?}"),
    }
}

// Sync

fn service(port: u16) -> ParentAdapterService {
    ParentAdapterService::new(EnclaveTarget::Tcp(format!("127.0.0.1:{port}")))
}

fn start_sync(
    port: u16,
    url: Option<&str>,
) -> (tokio::task::JoinHandle<()>, watch::Receiver<SyncStatus>) {
    let source = url.map(|u| ElectrumSource::new(u).unwrap());
    let (sync, rx) = HeaderSync::new(service(port), Ok(source), Duration::from_secs(1));
    (tokio::spawn(sync.run()), rx)
}

async fn wait(
    rx: &mut watch::Receiver<SyncStatus>,
    secs: u64,
    f: impl FnMut(&SyncStatus) -> bool,
) -> SyncStatus {
    let waited = tokio::time::timeout(Duration::from_secs(secs), rx.wait_for(f))
        .await
        .map(|s| s.unwrap().clone());
    waited.unwrap_or_else(|_| panic!("timed out; status {:?}", *rx.borrow()))
}

fn synced_at(tip: u32) -> impl FnMut(&SyncStatus) -> bool {
    move |s| s.state == SyncState::Synced && s.enclave_tip == Some(tip)
}

fn stalled(s: &SyncStatus) -> bool {
    s.state == SyncState::Stalled
}

/// Record every state the task reports.
fn watch_states(mut rx: watch::Receiver<SyncStatus>) -> Arc<Mutex<Vec<SyncState>>> {
    let seen: Arc<Mutex<Vec<SyncState>>> = Arc::default();
    let s = seen.clone();
    tokio::spawn(async move {
        while rx.changed().await.is_ok() {
            let state = rx.borrow().state;
            s.lock().unwrap().push(state);
        }
    });
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_enclave_syncs_follows_and_resumes() {
    let chain = extend(&genesis(), 4500, 1);
    let electrum = Electrum::start(chain.clone());
    let enclave = start_real_enclave();
    let (relay, log) = start_relay(enclave);

    // More than two batches, with no node running.
    let (task, mut rx) = start_sync(relay, Some(&electrum.url));
    wait(&mut rx, 60, synced_at(4500)).await;
    assert_eq!(enclave_tip(enclave), (4500, block_hash(&chain[4500])));
    let starts: Vec<u32> = submits(&log).iter().map(|(_, s)| s.start_height).collect();
    assert_eq!(starts, vec![1, 2017, 4033]);

    // A new block arrives within one interval.
    let chain = extend(&chain, 1, 1);
    electrum.set_chain(chain.clone());
    let t = Instant::now();
    wait(&mut rx, 10, synced_at(4501)).await;
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());

    // A restarted parent sends its first batch from the enclave tip plus one.
    task.abort();
    electrum.set_chain(extend(&chain, 10, 1));
    log.lock().unwrap().clear();
    let (task, mut rx) = start_sync(relay, Some(&electrum.url));
    wait(&mut rx, 10, synced_at(4511)).await;
    assert_eq!(submits(&log)[0].1.start_height, 4502);
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fork_1_and_100_replace_101_stalls() {
    let a = extend(&genesis(), 300, 1);
    let electrum = Electrum::start(a.clone());
    let enclave = start_real_enclave();
    let (task, mut rx) = start_sync(enclave, Some(&electrum.url));
    wait(&mut rx, 30, synced_at(300)).await;

    // Forked 1 below the tip: header 300 differs.
    let b = extend(&a[..300], 2, 2);
    electrum.set_chain(b.clone());
    wait(&mut rx, 20, synced_at(301)).await;
    assert_eq!(enclave_tip(enclave), (301, block_hash(&b[301])));

    // Forked 100 below the tip 301: headers 202..=301 differ.
    let c = extend(&b[..=201], 101, 3);
    electrum.set_chain(c.clone());
    wait(&mut rx, 20, synced_at(302)).await;
    assert_eq!(enclave_tip(enclave), (302, block_hash(&c[302])));

    // Forked 101 below the tip 302: headers 202..=302 differ.
    electrum.set_chain(extend(&c[..=201], 110, 4));
    wait(&mut rx, 20, stalled).await;
    assert_eq!(enclave_tip(enclave), (302, block_hash(&c[302])));
    task.abort();
}

/// A fork repair near the checkpoint: the first rewind lands below it and the
/// enclave refuses; the parent learns the checkpoint and repairs above it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fork_near_checkpoint_repairs_above_it() {
    let a = extend(&genesis(), 250, 1);
    let electrum = Electrum::start(a.clone());
    let enclave = start_real_enclave_at(checkpoint_at(&a, 200));
    let (relay, log) = start_relay(enclave);
    let (task, mut rx) = start_sync(relay, Some(&electrum.url));
    wait(&mut rx, 30, synced_at(250)).await;
    assert_eq!(submits(&log)[0].1.start_height, 201);

    // Forked 1 below the tip. A 99-deep rewind would start at 151.
    let b = extend(&a[..250], 2, 2);
    electrum.set_chain(b.clone());
    wait(&mut rx, 20, synced_at(251)).await;
    assert_eq!(enclave_tip(enclave), (251, block_hash(&b[251])));
    let starts: Vec<u32> = submits(&log)[1..]
        .iter()
        .map(|(_, s)| s.start_height)
        .collect();
    assert_eq!(
        starts,
        [151, 201],
        "one refusal, then a repair above the checkpoint"
    );

    // Forked at the checkpoint: every repair starts just above it, and the
    // enclave refuses each one.
    electrum.set_chain(extend(&a[..200], 60, 3));
    wait(&mut rx, 20, stalled).await;
    assert_eq!(enclave_tip(enclave), (251, block_hash(&b[251])));
    let starts: Vec<u32> = submits(&log)[3..]
        .iter()
        .map(|(_, s)| s.start_height)
        .collect();
    assert!(
        !starts.is_empty() && starts.iter().all(|s| *s == 201),
        "{starts:?}"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foreign_chain_fresh_and_synced() {
    let foreign = extend(&foreign_genesis(), 400, 5);

    // A fresh enclave.
    let electrum = Electrum::start(foreign.clone());
    let enclave = start_real_enclave();
    let (task, mut rx) = start_sync(enclave, Some(&electrum.url));
    wait(&mut rx, 20, stalled).await;
    assert_eq!(enclave_tip(enclave), (0, block_hash(&genesis()[0])));
    task.abort();

    // A synced enclave.
    let a = extend(&genesis(), 300, 1);
    let electrum = Electrum::start(a.clone());
    let enclave = start_real_enclave();
    let (task, mut rx) = start_sync(enclave, Some(&electrum.url));
    wait(&mut rx, 30, synced_at(300)).await;
    electrum.set_chain(foreign);
    wait(&mut rx, 20, stalled).await;
    assert_eq!(enclave_tip(enclave), (300, block_hash(&a[300])));
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_catch_up_batches_and_rate() {
    let chain = extend(&genesis(), 50_400, 1);
    let electrum = Electrum::start(chain.clone());
    let (enclave, log) = start_scripted_enclave(chain.clone(), |_| None);
    let (task, mut rx) = start_sync(enclave, Some(&electrum.url));
    wait(&mut rx, 120, synced_at(50_400)).await;
    task.abort();

    let sent = submits(&log);
    assert_eq!(sent.len(), 25);
    let mut next = 1u32;
    for (_, s) in &sent {
        assert_eq!(s.start_height, next);
        assert!(!s.headers.is_empty() && s.headers.len() <= 2016);
        let mut prev = block_hash(&chain[next as usize - 1]);
        for h in &s.headers {
            assert_eq!(h.len(), 80);
            assert_eq!(h[4..36], prev[..]);
            prev = block_hash(h);
        }
        next += s.headers.len() as u32;
    }
    for (t, _) in &sent {
        let window: usize = sent
            .iter()
            .filter(|(u, _)| *u >= *t && *u < *t + Duration::from_secs(60))
            .map(|(_, s)| s.headers.len())
            .sum();
        assert!(window <= 50_000, "{window} headers in 60 s");
    }
    assert!(sent[23].0 - sent[0].0 < Duration::from_secs(10));
    assert!(sent[24].0 - sent[0].0 >= Duration::from_secs(59));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_reply_rereads_tip() {
    fn case(
        answer: impl Fn(&SubmitHeadersRequest) -> Option<EnclaveResponse> + Send + Sync + 'static,
    ) -> impl std::future::Future<Output = ()> {
        let chain = extend(&genesis(), 10, 1);
        let electrum = Electrum::start(chain.clone());
        let first = AtomicBool::new(true);
        let (enclave, log) = start_scripted_enclave(chain, move |r| {
            first.swap(false, Ordering::SeqCst).then(|| answer(r))
        });
        async move {
            let (task, mut rx) = start_sync(enclave, Some(&electrum.url));
            wait(&mut rx, 60, synced_at(10)).await;
            task.abort();
            let log = log.lock().unwrap();
            let kinds: Vec<&str> = log
                .iter()
                .map(|(_, r)| match r.request {
                    Some(enclave_request::Request::Health(_)) => "health",
                    Some(enclave_request::Request::GetLastSavedBlock(_)) => "tip",
                    Some(enclave_request::Request::SubmitHeaders(_)) => "submit",
                    _ => "other",
                })
                .collect();
            let first = kinds.iter().position(|k| *k == "submit").unwrap();
            let second = first
                + 1
                + kinds[first + 1..]
                    .iter()
                    .position(|k| *k == "submit")
                    .unwrap();
            assert!(kinds[first + 1..second].contains(&"tip"), "{kinds:?}");
            let starts: Vec<u32> = log
                .iter()
                .filter_map(|(_, r)| match &r.request {
                    Some(enclave_request::Request::SubmitHeaders(s)) => Some(s.start_height),
                    _ => None,
                })
                .collect();
            assert_eq!(starts[..2], [1, 1]);
        }
    }
    let ok = |r: &SubmitHeadersRequest, accepted: u32, hash: Vec<u8>| {
        reply(enclave_response::Response::SubmitHeaders(
            SubmitHeadersResponse {
                last_block_height: r.start_height + r.headers.len() as u32 - 1,
                last_block_hash: hash,
                headers_accepted: accepted,
            },
        ))
    };
    tokio::join!(
        // A short accept.
        case(move |r| ok(
            r,
            r.headers.len() as u32 - 1,
            block_hash(r.headers.last().unwrap())
        )),
        // A wrong hash.
        case(move |r| ok(r, r.headers.len() as u32, vec![0; 32])),
        // An error.
        case(|_| reply(enclave_response::Response::Error(ErrorResponse {
            code: 1,
            message: "refused".into(),
        }))),
        // A timeout.
        case(|_| None),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn off_without_chain_is_stable() {
    let electrum = Electrum::start(extend(&genesis(), 10, 1));
    let (enclave, log) = start_enclave_with(|_| health(0));
    let (task, rx) = start_sync(enclave, Some(&electrum.url));
    let seen = watch_states(rx.clone());
    tokio::time::sleep(Duration::from_millis(5500)).await;
    task.abort();

    assert_eq!(rx.borrow().state, SyncState::Off);
    assert!(!seen.lock().unwrap().is_empty());
    assert!(seen.lock().unwrap().iter().all(|s| *s == SyncState::Off));
    assert_eq!(electrum.connections.load(Ordering::SeqCst), 0);
    let log = log.lock().unwrap();
    assert!(log.len() >= 5);
    assert!(log
        .iter()
        .all(|(_, r)| matches!(r.request, Some(enclave_request::Request::Health(_)))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unconfigured_is_stable() {
    let (enclave, log) = start_enclave_with(|_| health(7200));
    let (task, rx) = start_sync(enclave, None);
    let seen = watch_states(rx.clone());
    tokio::time::sleep(Duration::from_millis(5500)).await;
    task.abort();

    assert_eq!(rx.borrow().state, SyncState::Unconfigured);
    assert_eq!(rx.borrow().last_error, None);
    assert!(seen
        .lock()
        .unwrap()
        .iter()
        .all(|s| *s == SyncState::Unconfigured));
    let log = log.lock().unwrap();
    assert!(log.len() >= 5);
    assert!(log
        .iter()
        .all(|(_, r)| matches!(r.request, Some(enclave_request::Request::Health(_)))));
}

/// A bad `HEADER_ELECTRUM_URL` is `unconfigured` with the reason, not a crash.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_url_is_unconfigured_with_reason() {
    let (enclave, _log) = start_enclave_with(|_| health(7200));
    let (sync, mut rx) = HeaderSync::new(
        service(enclave),
        Err("HEADER_ELECTRUM_URL: no port".into()),
        Duration::from_secs(1),
    );
    let task = tokio::spawn(sync.run());
    let st = wait(&mut rx, 10, |s| s.state == SyncState::Unconfigured).await;
    assert_eq!(
        st.last_error.as_deref(),
        Some("HEADER_ELECTRUM_URL: no port")
    );
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(rx.borrow().state, SyncState::Unconfigured);
    assert_eq!(
        rx.borrow().last_error.as_deref(),
        Some("HEADER_ELECTRUM_URL: no port")
    );
    task.abort();
}

/// `PublicKey` and `Sign` reach the enclave.
async fn assert_relays(service: &ParentAdapterService, log: &Log) {
    let t = Instant::now();
    service
        .public_key(Request::new(PublicKeyRequest {
            network_id: 0,
            data_type: DataType::EvmGasTx as i32,
        }))
        .await
        .unwrap();
    let before = log.lock().unwrap().len();
    let sign = SignRequest {
        common: Some(CommonSignRequest {
            data_type: DataType::BtcUtxo as i32,
            ..Default::default()
        }),
        source: None,
        data: Some(sign_request::Data::BtcData(EnrichedBtcPayload {
            psbt_bytes: vec![0x70, 0x73, 0x62, 0x74, 0xFF],
        })),
    };
    // The enclave refuses the junk PSBT, which proves the request reached it.
    let _ = service.sign(Request::new(sign)).await;
    assert!(log.lock().unwrap()[before..]
        .iter()
        .any(|(_, r)| matches!(r.request, Some(enclave_request::Request::SignBtc(_)))));
    assert!(t.elapsed() < Duration::from_secs(5));
}

fn http_get(port: u16) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let status = raw.split_whitespace().nth(1).unwrap().parse().unwrap();
    (
        status,
        raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_outage_keeps_signing_and_recovers() {
    let chain = extend(&genesis(), 50, 1);
    let electrum = Electrum::start(chain.clone());
    let enclave = start_real_enclave();
    let (relay, log) = start_relay(enclave);
    let (task, mut rx) = start_sync(relay, Some(&electrum.url));
    wait(&mut rx, 20, synced_at(50)).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health_port = listener.local_addr().unwrap().port();
    let router = utexo_bridge_parent::health::router(service(relay), rx.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    electrum.set_mode(Mode::Down);
    electrum.set_chain(extend(&chain, 5, 1));
    let st = wait(&mut rx, 20, stalled).await;
    assert!(st.last_error.is_some());
    assert_eq!(st.lag_blocks, Some(0));

    assert_relays(&service(relay), &log).await;
    let (code, body) = tokio::task::spawn_blocking(move || http_get(health_port))
        .await
        .unwrap();
    assert_eq!(
        code, 503,
        "the enclave has no endpoints set, so it is not ready"
    );
    assert!(body.contains(r#""state":"stalled""#), "{body}");
    assert!(body.contains(r#""lag_blocks":0"#), "{body}");
    assert!(body.contains(r#""last_error":""#), "{body}");

    electrum.set_mode(Mode::Good);
    wait(&mut rx, 20, synced_at(55)).await;
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_source_times_out_without_pileup() {
    let electrum = Electrum::start(extend(&genesis(), 10, 1));
    electrum.set_mode(Mode::Silent);
    let enclave = start_real_enclave();
    let (relay, log) = start_relay(enclave);
    let (task, mut rx) = start_sync(relay, Some(&electrum.url));

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_relays(&service(relay), &log).await;
    let st = wait(&mut rx, 90, stalled).await;
    assert!(st.last_error.is_some());
    assert_eq!(electrum.max_open.load(Ordering::SeqCst), 1);
    assert!(submits(&log).is_empty());
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_source_then_recovers() {
    let chain = extend(&genesis(), 50, 1);
    let electrum = Electrum::start(chain.clone());
    let enclave = start_real_enclave();
    let (relay, log) = start_relay(enclave);
    let (task, mut rx) = start_sync(relay, Some(&electrum.url));
    wait(&mut rx, 20, synced_at(50)).await;

    electrum.set_mode(Mode::Malformed);
    electrum.set_chain(extend(&chain, 5, 1));
    log.lock().unwrap().clear();
    wait(&mut rx, 20, stalled).await;
    assert!(submits(&log).is_empty());
    assert_eq!(enclave_tip(enclave).0, 50);

    electrum.set_mode(Mode::Good);
    wait(&mut rx, 20, synced_at(55)).await;
    task.abort();
}

#[test]
fn self_signed_tls_source_is_refused() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let signed = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert: CertificateDer<'static> = signed.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signed.signing_key.serialize_der()));
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let got_request = Arc::new(AtomicBool::new(false));
    let got = got_request.clone();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        let mut line = String::new();
        if BufReader::new(&mut tls).read_line(&mut line).unwrap_or(0) > 0 {
            got.store(true, Ordering::SeqCst);
        }
    });

    let err = ElectrumSource::new(&format!("ssl://localhost:{port}"))
        .unwrap()
        .tip()
        .unwrap_err();
    server.join().unwrap();
    let rustls_err = err
        .chain()
        .find_map(|e| e.downcast_ref::<std::io::Error>())
        .and_then(|e| e.get_ref())
        .and_then(|e| e.downcast_ref::<rustls::Error>());
    assert!(
        matches!(rustls_err, Some(rustls::Error::InvalidCertificate(_))),
        "{err:#}"
    );
    assert!(!got_request.load(Ordering::SeqCst));
}
