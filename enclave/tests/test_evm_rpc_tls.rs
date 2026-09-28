//! The EVM RPC channel must be authenticated end to end. The host relays
//! every byte between the enclave and the RPC, so it must not be able to
//! answer a receipt request itself.
// The mint path reads the deposit and the BFA mint lock over this channel.
#![cfg(all(feature = "bfa-validation", evm_to_rgb))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

use alloy_primitives::U256;
use alloy_sol_types::{sol, SolEvent};
use utexo_bridge_enclave::bootstrap::build_evm_rpc_client;
use utexo_bridge_enclave::config::{BridgeConfig, EvmRpcConfig};
use utexo_bridge_enclave::networks::evm::events::{verify_funds_in_event, verify_rgb_funds_in};
use utexo_bridge_enclave::networks::rgb::invoice::{
    assert_recipient_authorized, parse_authorized_recipient,
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
const INVOICE: &str = "rgb:fuhLYX9G-eC8gDvf-V0XpYFH-ceSafoc-lGutAYq-~SExGU4/\
                       XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                       UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP";
const SEAL: &str = "utxob:UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP";

/// One receipt log from `BRIDGE` at block 100.
fn log_json(topics: &[alloy_primitives::B256], data: &[u8], index: u8) -> String {
    let topics: Vec<String> = topics
        .iter()
        .map(|t| format!("\"0x{}\"", hex::encode(t.0)))
        .collect();
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

/// Plays the host: answers JSON-RPC over plain HTTP on loopback.
fn serve_as_host() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut len = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut body = vec![0; len];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let body = String::from_utf8_lossy(&body);
            let Some(id) = body.split("\"id\":").nth(1) else {
                continue;
            };
            let id = id.split(['}', ',']).next().unwrap();
            let result = if body.contains("eth_getTransactionReceipt") {
                forged_receipt()
            } else {
                "\"0x70\"".into() // eth_blockNumber: 112
            };
            let reply = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        }
    });
    port
}

#[test]
fn host_forged_receipt_is_refused() {
    let port = serve_as_host();
    std::env::set_var("EVM_RPC_URL", format!("http://127.0.0.1:{port}"));
    std::env::set_var("EVM_RPC_HOST", "rpc.test");
    std::env::set_var("EVM_RPC_TLS_CA_PEM", CA_A_PEM);

    let cfg = EvmRpcConfig::from_env();
    let Some(client) = build_evm_rpc_client(&BridgeConfig::default(), &cfg) else {
        return;
    };
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
