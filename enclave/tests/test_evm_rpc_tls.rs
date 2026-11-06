//! The EVM RPC channel must be authenticated end to end. The host relays
//! every byte between the enclave and the RPC, so it must not be able to
//! answer a receipt request itself.
// The mint path reads the deposit and the BFA mint lock over this channel.
// The same channel authenticates the selected head and canonical receipt block.
#![cfg(feature = "rgb-validation")]

use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::U256;
use alloy_sol_types::{sol, SolEvent};
use attestation_verify::EvmFinalityTag;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::networks::evm::events::{verify_rgb_funds_in, EvmReceiptProvider};
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
#[cfg(evm_to_rgb)]
use utexo_bridge_enclave::networks::{
    evm::events::verify_funds_in_event,
    rgb::invoice::{assert_recipient_authorized, parse_authorized_recipient},
};
use utexo_bridge_enclave::policy::BuildContext;
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::{EnclaveRequest, EnclaveResponse, SetEndpointsRequest};
use utexo_bridge_enclave::server::{handle_connection, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;

sol! {
    event BridgeFundsIn(
        bytes32 indexed operationId, bytes32 indexed sourceSender, address indexed sender,
        uint256 senderNonce, uint256 amount, uint256 netAmount, uint256 tokenCommission,
        uint256 nativeCommission, uint256 sourceChainId, uint256 destinationChainId,
        string destinationAddress, bytes settlementData
    );
    event FundsIn(address indexed sender, uint256 indexed lockId, uint64 amount);
}

const BRIDGE: [u8; 20] = [0xB1; 20];
const TX: [u8; 32] = [0x11; 32];
const OP_ID: [u8; 32] = [0xAB; 32];
const MINT_LOCK_ID: [u8; 32] = [0xCD; 32];
/// The mint's `beforeBlock`: the lock is at block 100.
const BEFORE_BLOCK: u64 = 110;
/// Hex of the CA's DER.
const CA_A_HEX: &str = include_str!("fixtures/evm_rpc_tls/ca_a.der.hex");
const CA_B_HEX: &str = include_str!("fixtures/evm_rpc_tls/ca_b.der.hex");
/// PEM of CA A, for `pinned_ca_is_the_only_trusted_root` to add to a system
/// trust store the client must not consult.
#[cfg(target_os = "linux")]
const CA_A_CERT_PEM: &str = include_str!("fixtures/evm_rpc_tls/ca_a.pem");
/// Leaves signed by CA A: (certificate, key).
const RPC_TEST: (&str, &str) = (
    include_str!("fixtures/evm_rpc_tls/rpc_test.pem"),
    include_str!("fixtures/evm_rpc_tls/rpc_test.key.pem"),
);
const OTHER_TEST: (&str, &str) = (
    include_str!("fixtures/evm_rpc_tls/other_test.pem"),
    include_str!("fixtures/evm_rpc_tls/other_test.key.pem"),
);
const EXPIRED_RPC_TEST: (&str, &str) = (
    include_str!("fixtures/evm_rpc_tls/expired_rpc_test.pem"),
    include_str!("fixtures/evm_rpc_tls/expired_rpc_test.key.pem"),
);
const INVOICE: &str = "rgb:fuhLYX9G-eC8gDvf-V0XpYFH-ceSafoc-lGutAYq-~SExGU4/\
                       XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                       UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP";
#[cfg(evm_to_rgb)]
const SEAL: &str = "utxob:UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP";

/// One receipt log from `BRIDGE` at block 100.
fn log_json(topics: &[alloy_primitives::B256], data: &[u8], index: u8) -> String {
    let topics: Vec<String> = topics.iter().map(|t| format!("\"{t}\"")).collect();
    format!(
        r#"{{"address":"0x{bridge}","topics":[{topics}],"data":"0x{data}",
        "blockHash":"0x{block}","blockNumber":"0x64","transactionHash":"0x{tx}",
        "transactionIndex":"0x0","logIndex":"0x{index:x}","removed":false}}"#,
        bridge = hex::encode(BRIDGE),
        topics = topics.join(","),
        data = hex::encode(data),
        block = "22".repeat(32),
        tx = hex::encode(TX),
    )
}

/// A successful receipt at block 100 with one `BridgeFundsIn` from `BRIDGE`
/// (gross 1000, commission 50, recipient `INVOICE`) and one `FundsIn` that
/// locks 950 under the mint lockId `MINT_LOCK_ID`.
fn forged_receipt() -> String {
    let event = BridgeFundsIn {
        operationId: OP_ID.into(),
        sourceSender: [0x5c; 32].into(),
        sender: [0xde; 20].into(),
        senderNonce: U256::ZERO,
        amount: U256::from(1000),
        netAmount: U256::from(950),
        tokenCommission: U256::from(50),
        nativeCommission: U256::ZERO,
        sourceChainId: U256::ZERO,
        destinationChainId: U256::from(utexo_bridge_enclave::networks::evm::RGB_CHAIN_ID),
        destinationAddress: INVOICE.into(),
        settlementData: Default::default(),
    };
    let lock = FundsIn {
        sender: [0xde; 20].into(),
        lockId: U256::from_be_bytes(MINT_LOCK_ID),
        amount: 950,
    };
    let bridge_topics: Vec<_> = event.encode_topics().iter().map(|t| t.0).collect();
    let lock_topics: Vec<_> = lock.encode_topics().iter().map(|t| t.0).collect();
    let logs = [
        log_json(&bridge_topics, &event.encode_data(), 0),
        log_json(&lock_topics, &lock.encode_data(), 1),
    ];
    let (tx, bridge) = (hex::encode(TX), hex::encode(BRIDGE));
    format!(
        r#"{{"type":"0x2","status":"0x1","cumulativeGasUsed":"0x5208","gasUsed":"0x5208",
        "effectiveGasPrice":"0x1","logsBloom":"0x{bloom}","transactionHash":"0x{tx}",
        "transactionIndex":"0x0","blockHash":"0x{block}","blockNumber":"0x64",
        "from":"0x{bridge}","to":"0x{bridge}","contractAddress":null,
        "logs":[{logs}]}}"#,
        bloom = "00".repeat(256),
        block = "22".repeat(32),
        logs = logs.join(","),
    )
}

/// Answers JSON-RPC on loopback, over TLS with `leaf` when set. With
/// `truncate` it sends half of each body and closes.
fn serve(leaf: Option<(&str, &str)>, truncate: bool) -> u16 {
    serve_chain(leaf, truncate, ChainView::Eligible, EvmFinalityTag::Safe)
}

#[derive(Clone, Copy)]
enum ChainView {
    Eligible,
    AboveHead,
    MissingHead,
    Reorg,
}

fn block_json(number: u64, hash_byte: u8) -> String {
    let mut block: alloy::rpc::types::Block = Default::default();
    block.header.inner.number = number;
    block.header.hash = alloy_primitives::B256::repeat_byte(hash_byte);
    serde_json::to_string(&block).unwrap()
}

fn serve_chain(
    leaf: Option<(&str, &str)>,
    truncate: bool,
    chain: ChainView,
    finality_tag: EvmFinalityTag,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let tls = leaf.map(|(cert, key)| {
        let cert = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        )
    });
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            // A TLS client that talks to the plain server waits for a reply.
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            match &tls {
                None => answer(stream, truncate, chain, finality_tag),
                Some(cfg) => {
                    let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
                    answer(
                        rustls::StreamOwned::new(conn, stream),
                        truncate,
                        chain,
                        finality_tag,
                    )
                }
            }
        }
    });
    port
}

/// Complete TLS and consume a JSON-RPC request, then withhold its response.
/// The observed request distinguishes RPC timeout coverage from TLS failure.
fn serve_hang() -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(AtomicBool::new(false));
    let observed = received.clone();
    let cert = CertificateDer::from_pem_slice(RPC_TEST.0.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(RPC_TEST.1.as_bytes()).unwrap();
    let cfg = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let conn = rustls::ServerConnection::new(cfg).unwrap();
        let mut reader = BufReader::new(rustls::StreamOwned::new(conn, stream));
        let mut len = 0;
        for line in reader.by_ref().lines().map_while(Result::ok) {
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                len = value.trim().parse().unwrap();
            }
            if line.is_empty() || line == "\r" {
                break;
            }
        }
        let mut body = vec![0; len];
        reader.read_exact(&mut body).unwrap();
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(request["method"].is_string());
        observed.store(true, Ordering::SeqCst);
        // Longer than the production deadline, but finite if that deadline regresses.
        std::thread::sleep(Duration::from_secs(30));
    });
    (port, received)
}

/// Redirect to another reachable port on the same certified host. A client
/// that follows redirects can complete the request, so DNS/TLS errors cannot
/// masquerade as proof that redirects were disabled.
fn serve_redirect(target_port: u16) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (cert, key) = RPC_TEST;
    let cert = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    let cfg = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            {
                let mut reader = BufReader::new(&mut tls);
                let mut len = 0;
                for line in reader.by_ref().lines().map_while(Result::ok) {
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    if line.is_empty() || line == "\r" {
                        break;
                    }
                }
                let mut body = vec![0; len];
                if reader.read_exact(&mut body).is_err() || body.is_empty() {
                    continue;
                }
            }
            observed.fetch_add(1, Ordering::SeqCst);
            let _ = write!(
                tls,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://rpc.test:{target_port}/\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    (port, requests)
}

/// The Host header of every request `answer` read.
static HOSTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Answers one JSON-RPC request for the selected tag, canonical block, receipt,
/// or chain id (42161).
fn answer(
    stream: impl Read + Write,
    truncate: bool,
    chain: ChainView,
    finality_tag: EvmFinalityTag,
) {
    let mut reader = BufReader::new(stream);
    let mut len = 0;
    for line in reader.by_ref().lines().map_while(Result::ok) {
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap();
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("host:") {
            HOSTS.lock().unwrap().push(v.trim().to_string());
        }
        if line.is_empty() || line == "\r" {
            break;
        }
    }
    let mut body = vec![0; len];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return;
    };
    let id = &body["id"];
    let result = match body["method"].as_str().unwrap() {
        "eth_getTransactionReceipt" => forged_receipt(),
        "eth_getBlockByNumber" => {
            assert_eq!(body["params"][1], false, "only block headers are needed");
            match body["params"][0].as_str().unwrap() {
                tag if tag == finality_tag.as_str() => match chain {
                    ChainView::Eligible => block_json(100, 0x22),
                    ChainView::AboveHead => block_json(99, 0x21),
                    ChainView::MissingHead => "null".into(),
                    ChainView::Reorg => block_json(101, 0x33),
                },
                "0x64" => block_json(
                    100,
                    if matches!(chain, ChainView::Reorg) {
                        0x99
                    } else {
                        0x22
                    },
                ),
                tag => panic!("unexpected block tag {tag}; configured tag is {finality_tag}"),
            }
        }
        "eth_chainId" => "\"0xa4b1\"".into(),
        method => panic!("unexpected RPC method {method}"),
    };
    let reply = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#);
    let sent = if truncate {
        &reply[..reply.len() / 2]
    } else {
        &reply
    };
    let _ = write!(
        reader.get_mut(),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{sent}",
        reply.len()
    );
}

/// The client a launch set installs: TLS to `rpc.test` on `port`, under
/// `ca_der_hex`.
fn pinned_client(port: u16, ca_der_hex: &str) -> Box<dyn EvmReceiptProvider + Send + Sync> {
    // With `vsock`, the set binds a forwarder on each port and pins the
    // Electrum host in /etc/hosts. Give it free ports and `localhost`.
    #[cfg(feature = "vsock")]
    let (electrum_url, set_port) = {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        (
            format!("ssl://localhost:{}", a.local_addr().unwrap().port()),
            b.local_addr().unwrap().port(),
        )
    };
    #[cfg(not(feature = "vsock"))]
    let (electrum_url, set_port) = ("ssl://electrum.test:1".to_string(), port);
    let config = BridgeConfig::default();
    // No-SPV launch validation still requires the public-signet profile and
    // bridge pins. Reach the TLS client through the same launch handler.
    #[cfg(not(feature = "spv"))]
    let config = BridgeConfig {
        bitcoin_network: utexo_bridge_enclave::policy::BitcoinNetwork::Signet,
        btc_relay_mode: utexo_bridge_enclave::config::BtcRelayMode::None,
        chain_id: 42161,
        bridge_contract: [1; 20],
        funds_in_contract: BRIDGE,
        token_contract: [3; 20],
        rgb_asset_id: "test-asset".into(),
        ..config
    };
    let (bitcoin_network, network) = if cfg!(feature = "spv") {
        (bitcoin::Network::Regtest, Network::Regtest)
    } else {
        (bitcoin::Network::Signet, Network::Signet)
    };
    let ctx = ServerContext::awaiting_launch(
        EnclaveState::new(bitcoin_network),
        config,
        std::sync::Mutex::new(HeaderChain::new(network, checkpoint_for(network))),
        BuildContext::current(),
    );
    let endpoints = SetEndpointsRequest {
        electrum_url,
        evm_rpc_host: "rpc.test".into(),
        evm_rpc_ca_der: hex::decode(ca_der_hex.trim()).unwrap(),
        evm_rpc_tls_port: set_port.into(),
        ..Default::default()
    };
    // Installing the mint seed source validates these values but does not
    // contact KMS: this test never initializes keys.
    #[cfg(all(feature = "kms-persistence", not(feature = "allow-seed-import")))]
    let endpoints = SetEndpointsRequest {
        kms_key_arn: "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
            .into(),
        kms_region: "eu-west-1".into(),
        kms_seed_id: "rpc-tls-test".into(),
        ..endpoints
    };
    let set = EnclaveRequest {
        request: Some(Request::SetEndpoints(endpoints)),
    };
    // The handler writes the response after the request in the buffer.
    let mut wire = Cursor::new(Vec::new());
    framing::write_message(&mut wire, &set).unwrap();
    let request_len = wire.position();
    wire.set_position(0);
    handle_connection(&mut wire, &ctx);
    wire.set_position(request_len);
    let resp: EnclaveResponse = framing::read_message(&mut wire).unwrap();
    assert!(
        matches!(resp.response, Some(Response::SetEndpoints(_))),
        "{resp:?}"
    );
    let launch = ctx.launch.into_inner().unwrap();
    // The forwarder reaches the RPC only over vsock. Build the same client
    // on the mock server's port.
    #[cfg(feature = "vsock")]
    {
        let mut tls = launch.endpoints.evm_rpc_tls.unwrap();
        tls.tls_port = port;
        Box::new(
            utexo_bridge_enclave::networks::evm::events::AlloyEvmClient::with_pinned_tls(&tls)
                .unwrap(),
        )
    }
    #[cfg(not(feature = "vsock"))]
    launch.evm_rpc_client.unwrap()
}

/// The URL port selects the listener, so the Host header carries it.
#[test]
fn non_default_port_reaches_listener_with_host_header() {
    let port = serve(Some(RPC_TEST), false);
    assert_ne!(port, 443);
    let client = pinned_client(port, CA_A_HEX);
    verify_rgb_funds_in(
        &*client,
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &MINT_LOCK_ID,
        &OP_ID,
        950,
        BEFORE_BLOCK,
    )
    .unwrap();
    let want = format!("rpc.test:{port}");
    assert!(HOSTS.lock().unwrap().contains(&want), "no Host {want}");
}

#[cfg(evm_to_rgb)]
#[test]
fn pinned_ca_and_host_return_the_deposit() {
    let client = pinned_client(serve(Some(RPC_TEST), false), CA_A_HEX);
    verify_funds_in_event(
        &*client,
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &OP_ID,
        1000,
        50,
    )
    .unwrap();
}

#[test]
fn pinned_ca_and_host_return_the_ancestor_mint_lock() {
    let client = pinned_client(serve(Some(RPC_TEST), false), CA_A_HEX);
    verify_rgb_funds_in(
        &*client,
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &MINT_LOCK_ID,
        &OP_ID,
        950,
        BEFORE_BLOCK,
    )
    .unwrap();
}

/// The chain id read parses a real node's answer.
#[test]
fn pinned_client_reads_the_chain_id() {
    let client = pinned_client(serve(Some(RPC_TEST), false), CA_A_HEX);
    assert_eq!(client.get_chain_id().unwrap(), 42161);
}

/// The Alloy client must send the configured tag verbatim on both head reads.
#[test]
fn pinned_rpc_uses_latest_safe_and_finalized_tags() {
    for tag in [
        EvmFinalityTag::Latest,
        EvmFinalityTag::Safe,
        EvmFinalityTag::Finalized,
    ] {
        let client = pinned_client(
            serve_chain(Some(RPC_TEST), false, ChainView::Eligible, tag),
            CA_A_HEX,
        );
        #[cfg(evm_to_rgb)]
        verify_funds_in_event(&*client, &BRIDGE, tag, &TX, &OP_ID, 1000, 50).unwrap();
        verify_rgb_funds_in(
            &*client,
            &BRIDGE,
            tag,
            &TX,
            &MINT_LOCK_ID,
            &OP_ID,
            950,
            BEFORE_BLOCK,
        )
        .unwrap();
    }
}

/// The authenticated selected head and canonical block authorize the receipt.
#[test]
fn pinned_rpc_requires_configured_tag_and_matching_canonical_block() {
    for tag in [
        EvmFinalityTag::Latest,
        EvmFinalityTag::Safe,
        EvmFinalityTag::Finalized,
    ] {
        for chain in [
            ChainView::AboveHead,
            ChainView::MissingHead,
            ChainView::Reorg,
        ] {
            let client = pinned_client(serve_chain(Some(RPC_TEST), false, chain, tag), CA_A_HEX);
            #[cfg(evm_to_rgb)]
            assert!(
                verify_funds_in_event(&*client, &BRIDGE, tag, &TX, &OP_ID, 1000, 50).is_err(),
                "a receipt above the {tag} head or outside the canonical chain must not authorize signing"
            );
            assert!(
                verify_rgb_funds_in(&*client, &BRIDGE, tag, &TX, &MINT_LOCK_ID, &OP_ID, 950, BEFORE_BLOCK).is_err(),
                "a receipt above the {tag} head or outside the canonical chain must not authorize a mint lock"
            );
        }
    }
}

#[test]
fn tls_failure_refuses_to_sign() {
    let cases = [
        ("unknown CA", serve(Some(RPC_TEST), false), CA_B_HEX),
        (
            "leaf for other.test",
            serve(Some(OTHER_TEST), false),
            CA_A_HEX,
        ),
        (
            "expired leaf",
            serve(Some(EXPIRED_RPC_TEST), false),
            CA_A_HEX,
        ),
        ("close mid-response", serve(Some(RPC_TEST), true), CA_A_HEX),
        ("plaintext server", serve(None, false), CA_A_HEX),
    ];
    for (case, port, ca_hex) in cases {
        let client = pinned_client(port, ca_hex);
        #[cfg(evm_to_rgb)]
        assert!(
            verify_funds_in_event(
                &*client,
                &BRIDGE,
                EvmFinalityTag::Safe,
                &TX,
                &OP_ID,
                1000,
                50
            )
            .is_err(),
            "deposit accepted: {case}"
        );
        assert!(
            verify_rgb_funds_in(
                &*client,
                &BRIDGE,
                EvmFinalityTag::Safe,
                &TX,
                &MINT_LOCK_ID,
                &OP_ID,
                950,
                BEFORE_BLOCK
            )
            .is_err(),
            "ancestor mint lock accepted: {case}"
        );
    }
}

/// Run environment-sensitive cases in their own test process. The parent and
/// concurrent tests never mutate process-global proxy or trust-store settings.
fn isolated_test(name: &str, configure: impl FnOnce(&mut std::process::Command)) -> bool {
    if std::env::var("UTEXO_TLS_TEST_CHILD").as_deref() == Ok(name) {
        return false;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture"])
        .env("UTEXO_TLS_TEST_CHILD", name);
    configure(&mut command);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "isolated {name} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

/// An HTTP client using the same pinned endpoint, with optional CA pin and
/// reqwest's ordinary redirect policy, for positive controls.
fn control_rpc(port: u16, ca: Option<&str>, no_proxy: bool) -> Result<String, String> {
    use alloy::transports::http::reqwest;
    let mut builder = reqwest::Client::builder()
        .resolve("rpc.test", ([127, 0, 0, 1], 0).into())
        .timeout(Duration::from_secs(3));
    if let Some(ca) = ca {
        builder = builder
            .tls_certs_only([
                reqwest::Certificate::from_der(&hex::decode(ca.trim()).unwrap()).unwrap(),
            ]);
    }
    if no_proxy {
        builder = builder.no_proxy();
    }
    let client = builder.build().unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        client
            .post(format!("https://rpc.test:{port}/"))
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .text()
            .await
            .map_err(|e| e.to_string())
    })
}

#[test]
fn proxy_env_has_no_effect() {
    if isolated_test("proxy_env_has_no_effect", |command| {
        for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
            command
                .env(name, "http://127.0.0.1:1")
                .env(name.to_ascii_lowercase(), "http://127.0.0.1:1");
        }
        command.env_remove("NO_PROXY").env_remove("no_proxy");
    }) {
        return;
    }
    let port = serve(Some(RPC_TEST), false);
    assert!(
        control_rpc(port, Some(CA_A_HEX), false).is_err(),
        "control: ordinary client must try the configured dead proxy"
    );
    assert_eq!(pinned_client(port, CA_A_HEX).get_chain_id().unwrap(), 42161);
}

/// Linux's native verifier honors SSL_CERT_FILE. Establish that positive
/// control before requiring the pinned client to reject the same CA A leaf.
/// Other platforms use their native stores, so this specific override is Linux-only.
#[cfg(target_os = "linux")]
#[test]
fn pinned_ca_is_the_only_trusted_root() {
    if std::env::var("UTEXO_TLS_TEST_CHILD").as_deref() != Ok("pinned_ca_is_the_only_trusted_root")
    {
        let path =
            std::env::temp_dir().join(format!("evm_rpc_tls_ca_a_{}.pem", std::process::id()));
        std::fs::write(&path, CA_A_CERT_PEM).unwrap();
        isolated_test("pinned_ca_is_the_only_trusted_root", |command| {
            command
                .env("SSL_CERT_FILE", &path)
                .env_remove("SSL_CERT_DIR");
        });
        std::fs::remove_file(path).unwrap();
        return;
    }
    let port = serve(Some(RPC_TEST), false);
    let baseline = control_rpc(port, None, true).expect("native roots must trust fixture CA A");
    assert!(baseline.contains("0xa4b1"), "{baseline}");
    assert!(
        pinned_client(port, CA_B_HEX).get_chain_id().is_err(),
        "CA A must be refused when only CA B is pinned, even if native roots trust A"
    );
}

/// A hung RPC must fail closed within `evm_rpc_timeout_secs`. It must not block
/// the enclave.
#[test]
fn timeout_refuses_to_sign() {
    let (port, received) = serve_hang();
    let client = pinned_client(port, CA_A_HEX);
    let start = std::time::Instant::now();
    let got = verify_rgb_funds_in(
        &*client,
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &MINT_LOCK_ID,
        &OP_ID,
        950,
        BEFORE_BLOCK,
    );
    assert!(
        received.load(Ordering::SeqCst),
        "TLS must succeed and the RPC request must reach the peer"
    );
    assert!(got.is_err(), "a hung RPC must refuse to sign");
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "must fail within the 15s call timeout, took {:?}",
        start.elapsed()
    );
}

/// A redirect target is observable and reachable with the pinned CA. The
/// control follows it successfully; the production client must never contact it.
#[test]
fn pinned_host_redirect_is_not_followed() {
    let target = serve(Some(RPC_TEST), false);
    let (redirect, redirected_requests) = serve_redirect(target);
    let baseline = control_rpc(redirect, Some(CA_A_HEX), true)
        .expect("control must follow redirect to the reachable target");
    assert!(baseline.contains("0xa4b1"), "{baseline}");
    let target_host = format!("rpc.test:{target}");
    let target_requests = || {
        HOSTS
            .lock()
            .unwrap()
            .iter()
            .filter(|h| **h == target_host)
            .count()
    };
    let before = target_requests();
    assert!(before > 0, "control must have reached redirect target");
    let redirects_before = redirected_requests.load(Ordering::SeqCst);
    let client = pinned_client(redirect, CA_A_HEX);
    assert!(
        client.get_chain_id().is_err(),
        "production client must refuse redirect"
    );
    assert!(
        redirected_requests.load(Ordering::SeqCst) > redirects_before,
        "production client must have completed TLS and received the redirect"
    );
    assert_eq!(
        target_requests(),
        before,
        "production client followed the redirect"
    );
}

#[cfg(evm_to_rgb)]
#[test]
fn host_forged_receipt_is_refused() {
    // The host answers in plaintext. The TLS handshake fails.
    let client = pinned_client(serve(None, false), CA_A_HEX);
    // The mint path: the deposit predicate, the recipient bind, then the BFA
    // mint lock, all read through the same client.
    let got = verify_funds_in_event(
        &*client,
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &OP_ID,
        1000,
        50,
    )
    .and_then(|v| parse_authorized_recipient(&v.destination_address))
    .and_then(|r| assert_recipient_authorized(&[SEAL.into()], &r))
    .and_then(|()| {
        verify_rgb_funds_in(
            &*client,
            &BRIDGE,
            EvmFinalityTag::Safe,
            &TX,
            &MINT_LOCK_ID,
            &OP_ID,
            950,
            BEFORE_BLOCK,
        )
    });
    assert!(
        got.is_err(),
        "the enclave accepted a FundsIn receipt that the host forged over plaintext: {got:?}"
    );
}
