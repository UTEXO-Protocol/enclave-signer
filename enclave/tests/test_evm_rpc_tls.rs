//! The EVM RPC channel must be authenticated end to end. The host relays
//! every byte between the enclave and the RPC, so it must not be able to
//! answer a receipt request itself.
// The mint path reads the deposit and the BFA mint lock over this channel.
// The burn path reads the ancestor mint locks.
#![cfg(feature = "bfa-validation")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::U256;
use alloy_sol_types::{sol, SolEvent};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use utexo_bridge_enclave::bootstrap::build_evm_rpc_client;
use utexo_bridge_enclave::config::{BridgeConfig, EvmRpcConfig};
use utexo_bridge_enclave::networks::evm::events::{verify_rgb_funds_in, EvmReceiptProvider};
#[cfg(evm_to_rgb)]
use utexo_bridge_enclave::networks::{
    evm::events::verify_funds_in_event,
    rgb::invoice::{assert_recipient_authorized, parse_authorized_recipient},
};

sol! {
    event BridgeFundsIn(
        bytes32 indexed operationId, bytes32 indexed sourceSender, address indexed sender,
        uint256 senderNonce, uint256 amount, uint256 netAmount, uint256 tokenCommission,
        uint256 nativeCommission, uint256 sourceChainId, uint256 destinationChainId,
        string destinationAddress
    );
    event FundsIn(address indexed sender, uint256 rgbOpId, uint64 amount);
}

const BRIDGE: [u8; 20] = [0xB1; 20];
const TX: [u8; 32] = [0x11; 32];
const OP_ID: [u8; 32] = [0xAB; 32];
const MINT_OPID: [u8; 32] = [0xCD; 32];
const CA_A_PEM: &str = include_str!("fixtures/evm_rpc_tls/ca_a.pem");
const CA_B_PEM: &str = include_str!("fixtures/evm_rpc_tls/ca_b.pem");
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
/// locks 950 for the mint `MINT_OPID`.
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
        destinationChainId: U256::ZERO,
        destinationAddress: INVOICE.into(),
    };
    let lock = FundsIn {
        sender: [0xde; 20].into(),
        rgbOpId: U256::from_be_bytes(MINT_OPID),
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
                None => answer(stream, truncate),
                Some(cfg) => {
                    let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
                    answer(rustls::StreamOwned::new(conn, stream), truncate)
                }
            }
        }
    });
    port
}

/// Answers one JSON-RPC request with the forged receipt or block 112.
fn answer(stream: impl Read + Write, truncate: bool) {
    let mut reader = BufReader::new(stream);
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
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body);
    let Some(id) = body.split("\"id\":").nth(1) else {
        return;
    };
    let id = id.split(['}', ',']).next().unwrap();
    let result = if body.contains("eth_getTransactionReceipt") {
        forged_receipt()
    } else {
        "\"0x70\"".into() // eth_blockNumber: 112
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

/// The image's client: `https://` to the forwarder port, pinned to
/// `rpc.test` and `ca_pem`.
fn pinned_client(port: u16, ca_pem: &str) -> Box<dyn EvmReceiptProvider + Send + Sync> {
    let cfg = EvmRpcConfig::from_vars(|name| match name {
        "EVM_RPC_URL" => Some(format!("https://127.0.0.1:{port}")),
        "EVM_RPC_HOST" => Some("rpc.test".into()),
        "EVM_RPC_TLS_CA_PEM" => Some(ca_pem.into()),
        _ => None,
    });
    build_evm_rpc_client(&BridgeConfig::default(), &cfg).expect("valid pins build a client")
}

#[cfg(evm_to_rgb)]
#[test]
fn pinned_ca_and_host_return_the_deposit() {
    let client = pinned_client(serve(Some(RPC_TEST), false), CA_A_PEM);
    verify_funds_in_event(&*client, &BRIDGE, 12, &TX, &OP_ID, 1000, 50).unwrap();
}

#[test]
fn pinned_ca_and_host_return_the_ancestor_mint_lock() {
    let client = pinned_client(serve(Some(RPC_TEST), false), CA_A_PEM);
    verify_rgb_funds_in(&*client, &BRIDGE, 12, &TX, &MINT_OPID).unwrap();
}

#[test]
fn tls_failure_refuses_to_sign() {
    let cases = [
        ("unknown CA", serve(Some(RPC_TEST), false), CA_B_PEM),
        (
            "leaf for other.test",
            serve(Some(OTHER_TEST), false),
            CA_A_PEM,
        ),
        (
            "expired leaf",
            serve(Some(EXPIRED_RPC_TEST), false),
            CA_A_PEM,
        ),
        ("close mid-response", serve(Some(RPC_TEST), true), CA_A_PEM),
        ("plaintext server", serve(None, false), CA_A_PEM),
    ];
    for (case, port, ca_pem) in cases {
        let client = pinned_client(port, ca_pem);
        #[cfg(evm_to_rgb)]
        assert!(
            verify_funds_in_event(&*client, &BRIDGE, 12, &TX, &OP_ID, 1000, 50).is_err(),
            "deposit accepted: {case}"
        );
        assert!(
            verify_rgb_funds_in(&*client, &BRIDGE, 12, &TX, &MINT_OPID).is_err(),
            "ancestor mint lock accepted: {case}"
        );
    }
}

#[test]
fn proxy_env_has_no_effect() {
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        std::env::set_var(name, "http://127.0.0.1:1");
        std::env::set_var(name.to_ascii_lowercase(), "http://127.0.0.1:1");
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");
    let client = pinned_client(serve(Some(RPC_TEST), false), CA_A_PEM);
    verify_rgb_funds_in(&*client, &BRIDGE, 12, &TX, &MINT_OPID).unwrap();
}

#[cfg(evm_to_rgb)]
#[test]
fn host_forged_receipt_is_refused() {
    let port = serve(None, false);
    std::env::set_var("EVM_RPC_URL", format!("https://127.0.0.1:{port}"));
    std::env::set_var("EVM_RPC_HOST", "rpc.test");
    std::env::set_var("EVM_RPC_TLS_CA_PEM", CA_A_PEM);

    let cfg = EvmRpcConfig::from_env();
    let client = build_evm_rpc_client(&BridgeConfig::default(), &cfg).expect("client");
    // The mint path: the deposit predicate, the recipient bind, then the BFA
    // mint lock, all read through the same client.
    let got = verify_funds_in_event(&*client, &BRIDGE, 12, &TX, &OP_ID, 1000, 50)
        .and_then(|v| parse_authorized_recipient(&v.destination_address))
        .and_then(|r| assert_recipient_authorized(&[SEAL.into()], &r))
        .and_then(|()| verify_rgb_funds_in(&*client, &BRIDGE, 12, &TX, &MINT_OPID));
    assert!(
        got.is_err(),
        "the enclave accepted a FundsIn receipt that the host forged over plaintext: {got:?}"
    );
}
