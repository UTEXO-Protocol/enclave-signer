//! Integration tests for the gRPC bridge (Parent Adapter → Enclave).
//!
//! These tests start a mock enclave TCP server that speaks our wire protocol,
//! then a real tonic gRPC server (Parent Adapter) pointing at it, and finally
//! exercise the full path via a gRPC client.

use std::net::TcpListener;

use tonic::transport::Server;

use utexo_bridge_parent::enclave_proto::{
    self, enclave_request, enclave_response, EnclaveRequest, EnclaveResponse,
};
use utexo_bridge_parent::framing;
use utexo_bridge_parent::grpc_proto::enclave_service_client::EnclaveServiceClient;
use utexo_bridge_parent::grpc_proto::enclave_service_server::EnclaveServiceServer;
use utexo_bridge_parent::grpc_proto::{
    enclave_sign_request, enclave_sign_response, EnclaveSignRequest as GrpcSignRequest,
    EvmSigningFlow, GetPublicKeysRequest as GrpcGetPublicKeysRequest, PsbtSigningFlow,
};
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

/// Start a mock enclave TCP server that responds to specific request types.
/// This mimics the real enclave wire protocol without depending on the enclave crate.
fn start_mock_enclave() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

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
                Some(enclave_request::Request::GetPublicKey(_)) => EnclaveResponse {
                    response: Some(enclave_response::Response::PublicKeys(
                        enclave_proto::PublicKeysResponse {
                            evm_address: vec![0xAA; 20],
                            btc_compressed_pub: vec![0xBB; 33],
                            btc_xpub: "xpub-test".into(),
                            master_fingerprint: vec![0xDD; 4],
                            account_xpub_vanilla: "tpub-vanilla-test".into(),
                            account_xpub_colored: "tpub-colored-test".into(),
                        },
                    )),
                },
                Some(enclave_request::Request::SignEvm(_)) => EnclaveResponse {
                    response: Some(enclave_response::Response::EvmSignature(
                        enclave_proto::EvmSignatureResponse {
                            signature: vec![0xCC; 65],
                        },
                    )),
                },
                Some(enclave_request::Request::SignPsbt(_)) => EnclaveResponse {
                    response: Some(enclave_response::Response::SignedPsbt(
                        enclave_proto::SignedPsbtResponse {
                            signed_psbt: vec![0xDD; 100],
                            inputs_signed: 2,
                        },
                    )),
                },
                _ => EnclaveResponse {
                    response: Some(enclave_response::Response::Error(
                        enclave_proto::ErrorResponse {
                            code: 1,
                            message: "not implemented in mock".into(),
                        },
                    )),
                },
            };

            let _ = framing::write_message(&mut stream, &resp);
        }
    });

    port
}

async fn start_grpc_server(enclave_port: u16) -> u16 {
    let grpc_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let grpc_addr = grpc_listener.local_addr().unwrap();
    let grpc_port = grpc_addr.port();
    drop(grpc_listener);

    let service =
        ParentAdapterService::new(EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")));

    tokio::spawn(async move {
        Server::builder()
            .add_service(EnclaveServiceServer::new(service))
            .serve(grpc_addr)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    grpc_port
}

// =========================================================================
// Happy-path tests
// =========================================================================

#[tokio::test]
async fn grpc_get_public_keys_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let resp = client
        .get_public_keys(GrpcGetPublicKeysRequest {})
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.public_keys.len(), 2);
    assert_eq!(resp.public_keys[0].len(), 20, "EVM address");
    assert_eq!(resp.public_keys[1].len(), 33, "BTC compressed pubkey");
}

#[tokio::test]
async fn grpc_sign_evm_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let req = GrpcSignRequest {
        flow: Some(enclave_sign_request::Flow::Evm(EvmSigningFlow {
            sign_payload: vec![0xAB; 132],
            consignment_hash: vec![],
            consignment: vec![],
            consignment_valid: true,
            nonce: 1,
            deadline: u64::MAX,
        })),
    };

    let resp = client.sign(req).await.unwrap().into_inner();
    match resp.result {
        Some(enclave_sign_response::Result::EvmSignature(sig)) => {
            assert_eq!(sig.len(), 65, "EVM signature must be 65 bytes");
        }
        other => panic!("expected EvmSignature, got {:?}", other),
    }
}

#[tokio::test]
async fn grpc_sign_psbt_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let req = GrpcSignRequest {
        flow: Some(enclave_sign_request::Flow::Psbt(PsbtSigningFlow {
            psbt: vec![0xFF; 32],
            validated_tx_hash: "aa".repeat(32), // 32 bytes as hex
            operation_idx: 5,
            evm_event_finalized: true,
        })),
    };

    let resp = client.sign(req).await.unwrap().into_inner();
    match resp.result {
        Some(enclave_sign_response::Result::SignedPsbt(psbt)) => {
            assert!(!psbt.is_empty(), "signed PSBT should not be empty");
        }
        other => panic!("expected SignedPsbt, got {:?}", other),
    }
}

#[tokio::test]
async fn grpc_evm_passes_consignment_bytes_through() {
    // Verify the Parent Adapter actually passes consignment + hash to the enclave.
    // We use a custom mock that inspects the received request.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let enclave_port = listener.local_addr().unwrap().port();

    let (tx, rx) = std::sync::mpsc::channel::<enclave_proto::SignEvmRequest>();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let req: EnclaveRequest = framing::read_message(&mut stream).unwrap();

            if let Some(enclave_request::Request::SignEvm(evm_req)) = req.request {
                tx.send(evm_req).unwrap();
                let resp = EnclaveResponse {
                    response: Some(enclave_response::Response::EvmSignature(
                        enclave_proto::EvmSignatureResponse {
                            signature: vec![0xCC; 65],
                        },
                    )),
                };
                let _ = framing::write_message(&mut stream, &resp);
            }
        }
    });

    let grpc_port = start_grpc_server(enclave_port).await;
    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let consignment = b"test-consignment-payload".to_vec();
    let hash = b"test-consignment-hash-32bytes!!!".to_vec();

    let req = GrpcSignRequest {
        flow: Some(enclave_sign_request::Flow::Evm(EvmSigningFlow {
            sign_payload: vec![0xAB; 10],
            consignment: consignment.clone(),
            consignment_hash: hash.clone(),
            consignment_valid: true,
            nonce: 42,
            deadline: 9999,
        })),
    };

    client.sign(req).await.unwrap();

    // Inspect what the mock enclave received
    let received = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    assert_eq!(
        received.consignment, consignment,
        "consignment bytes must pass through"
    );
    assert_eq!(
        received.consignment_hash, hash,
        "consignment hash must pass through"
    );
    assert_eq!(
        received.call_data,
        vec![0xAB; 10],
        "call_data mapped from sign_payload"
    );
    assert_eq!(received.nonce, 42);
    assert_eq!(received.deadline, 9999);
    assert!(received.consignment_valid);
}

// =========================================================================
// Error-path tests
// =========================================================================

#[tokio::test]
async fn grpc_missing_flow_returns_invalid_argument() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let err = client
        .sign(GrpcSignRequest { flow: None })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn grpc_invalid_tx_hash_hex_returns_invalid_argument() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let req = GrpcSignRequest {
        flow: Some(enclave_sign_request::Flow::Psbt(PsbtSigningFlow {
            psbt: vec![0xFF; 32],
            validated_tx_hash: "not-hex!!!".to_string(),
            operation_idx: 0,
            evm_event_finalized: false,
        })),
    };

    let err = client.sign(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("not valid hex"));
}

#[tokio::test]
async fn grpc_wrong_tx_hash_length_returns_invalid_argument() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    // 16 bytes hex = valid hex but wrong length
    let req = GrpcSignRequest {
        flow: Some(enclave_sign_request::Flow::Psbt(PsbtSigningFlow {
            psbt: vec![0xFF; 32],
            validated_tx_hash: "aabbccdd00112233aabbccdd00112233".to_string(),
            operation_idx: 0,
            evm_event_finalized: false,
        })),
    };

    let err = client.sign(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("32 bytes"));
}
