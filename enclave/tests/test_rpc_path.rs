//! The configured provider path reaches the pinned TLS host without leaking
//! the API key in a failed RPC response.
#![cfg(feature = "evm-rpc")]
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use utexo_bridge_enclave::config::EvmRpcTls;
use utexo_bridge_enclave::networks::evm::events::{AlloyEvmClient, EvmReceiptProvider};

#[test]
fn rpc_path_reaches_pinned_tls_host_and_errors_hide_credentials() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    for success in [true, false] {
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
            let response = if success {
                serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":"0xa4b1"})
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
        let result = client.get_chain_id();
        server.join().unwrap();
        if success {
            assert_eq!(result.unwrap(), 42161);
        } else {
            let error = result.unwrap_err().to_string();
            assert!(!error.contains("fixture-secret"));
            assert!(error.contains("eth_chainId failed"));
        }
    }
}
