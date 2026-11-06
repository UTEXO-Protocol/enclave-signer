//! The configured provider path reaches the pinned TLS host without leaking
//! the API key in errors or global debug/trace logs.
#![cfg(feature = "evm-rpc")]
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::util::SubscriberInitExt;
use utexo_bridge_enclave::config::EvmRpcTls;
use utexo_bridge_enclave::networks::evm::events::{AlloyEvmClient, EvmReceiptProvider};

#[derive(Clone)]
struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn rpc_path_reaches_pinned_tls_host_and_errors_hide_credentials() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let logs = LogWriter(Arc::new(Mutex::new(Vec::new())));
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    // This integration binary has one test. A global subscriber also captures
    // logs from the client's Tokio workers and spawned HTTP tasks. Like enclave
    // bootstrap, try_init also forwards dependencies' `log` events to tracing.
    subscriber.try_init().unwrap();
    tracing::info!("RPC log capture is active");
    std::thread::spawn(|| tracing::info!("Background log capture is active"))
        .join()
        .unwrap();
    for (method, success) in [
        "eth_chainId",
        "eth_getTransactionReceipt",
        "eth_getBlockByNumber",
        "eth_call",
    ]
    .into_iter()
    .flat_map(|method| [true, false].map(|success| (method, success)))
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cert =
            CertificateDer::from_pem_slice(include_bytes!("fixtures/evm_rpc_tls/rpc_test.pem"))
                .unwrap();
        let key =
            PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/evm_rpc_tls/rpc_test.key.pem"))
                .unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let conn = rustls::ServerConnection::new(config).unwrap();
            let mut reader = BufReader::new(rustls::StreamOwned::new(conn, stream));
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "POST /v2/fixture-secret HTTP/1.1\r\n");
            let mut length = 0;
            let mut host_matches = false;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
                if lower.trim() == format!("host: rpc.test:{port}") {
                    host_matches = true;
                }
            }
            assert!(host_matches);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(request["method"], method);
            let response = if success {
                let result = match method {
                    "eth_chainId" => serde_json::json!("0xa4b1"),
                    "eth_call" => serde_json::json!("0x"),
                    _ => serde_json::Value::Null,
                };
                serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":result})
            } else {
                serde_json::json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":"provider echoed /v2/fixture-secret"}})
            }.to_string();
            write!(reader.get_mut(), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            reader.get_mut().flush().unwrap();
        });
        let tls = EvmRpcTls {
            host: "rpc.test".into(),
            tls_port: port,
            ca_der: hex::decode(include_str!("fixtures/evm_rpc_tls/ca_a.der.hex").trim()).unwrap(),
            path: "/v2/fixture-secret".into(),
        };
        let client = AlloyEvmClient::with_pinned_tls(&tls).unwrap();
        let result = match method {
            "eth_chainId" => client.get_chain_id().map(|id| assert_eq!(id, 42161)),
            "eth_getTransactionReceipt" => client
                .get_transaction_receipt(&[1; 32])
                .map(|receipt| assert!(receipt.is_none())),
            "eth_getBlockByNumber" => client
                .get_block_by_number(1)
                .map(|block| assert!(block.is_none())),
            "eth_call" => client
                .call(&[2; 20], &[1, 2, 3, 4], 1)
                .map(|bytes| assert!(bytes.is_empty())),
            _ => unreachable!(),
        };
        server.join().unwrap();
        if success {
            result.unwrap();
        } else {
            let error = result.unwrap_err().to_string();
            assert!(!error.contains("fixture-secret"));
            assert!(error.contains(method));
            assert!(error.contains("failed"));
        }
    }
    tracing::info!("RPC log capture remains active");
    let captured = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(captured.contains("RPC log capture is active"));
    assert!(captured.contains("Background log capture is active"));
    assert!(captured.contains("RPC log capture remains active"));
    assert!(
        !captured.contains("fixture-secret"),
        "credential leaked into trace output"
    );
}
