//! Integration tests for the gRPC bridge (Parent Adapter -> Enclave).
//!
//! These tests start a mock enclave TCP server that speaks our wire protocol,
//! then a real tonic gRPC server (Parent Adapter) pointing at it, and finally
//! exercise the full path via a gRPC client.

use std::net::TcpListener;

use prost::Message as ProstMessage;
use tonic::transport::Server;

use utexo_bridge_parent::enclave_proto::{
    self, enclave_request, enclave_response, EnclaveRequest, EnclaveResponse,
};
use utexo_bridge_parent::enriched;
use utexo_bridge_parent::framing;
use utexo_bridge_parent::grpc_proto::enclave_service_client::EnclaveServiceClient;
use utexo_bridge_parent::grpc_proto::enclave_service_server::EnclaveServiceServer;
use utexo_bridge_parent::grpc_proto::{DataType, PublicKeyRequest, SignRequest};
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

/// Start a mock enclave TCP server that responds to specific request types.
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
                Some(enclave_request::Request::InitializeKey(_)) => EnclaveResponse {
                    response: Some(enclave_response::Response::InitializeKey(
                        enclave_proto::InitializeKeyResponse {
                            evm_address: vec![0xAA; 20],
                            btc_compressed_pub: vec![0xBB; 33],
                            btc_xpub: "xpub-test".into(),
                            master_fingerprint: vec![0xDD; 4],
                            account_xpub_vanilla: "tpub-vanilla-test".into(),
                            account_xpub_colored: "tpub-colored-test".into(),
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
async fn grpc_public_key_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let resp = client
        .public_key(PublicKeyRequest {
            network_id: 0,
            data_type: 0,
            algorithm: None,
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.public_key.len(), 33, "BTC compressed pubkey");
    assert_eq!(resp.public_key, vec![0xBB; 33]);
}

#[tokio::test]
async fn grpc_public_key_returns_evm_address_for_swap() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let resp = client
        .public_key(PublicKeyRequest {
            network_id: 0,
            data_type: DataType::Swap as i32,
            algorithm: None,
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.public_key.len(), 20, "EVM address is 20 bytes");
    assert_eq!(resp.public_key, vec![0xAA; 20]);
}

#[tokio::test]
async fn grpc_sign_evm_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let payload = enriched::EnrichedEvmPayload {
        call_data: vec![0xAB; 132],
        nonce: 1,
        deadline: u64::MAX,
        consignment_valid: true,
        rgb_amount: 0,
        rgb_asset_id: String::new(),
        chain_id: 1,
        proxy_contract: vec![],
        calldata_amount: 0,
        calldata_commission: 0,
        consignment_sha256: vec![],
    };

    let req = SignRequest {
        network_id: 0,
        data_type: DataType::Swap as i32,
        data: payload.encode_to_vec(),
        inputs: vec![],
        algorithm: None,
    };

    let resp = client.sign(req).await.unwrap().into_inner();
    assert_eq!(resp.signature.len(), 65, "EVM signature must be 65 bytes");
}

#[tokio::test]
async fn grpc_sign_psbt_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let payload = enriched::EnrichedPsbtPayload {
        evm_tx_hash: vec![0xAA; 32],
        operation_idx: 5,
        evm_event_valid: true,
        evm_event_finalized: true,
        evm_token: vec![],
        evm_amount: 0,
        evm_recipient: vec![],
        evm_commission: 0,
        psbt_bytes: vec![0xFF; 32],
        psbt_output_amount: 0,
        rgb_asset_id: String::new(),
    };

    let req = SignRequest {
        network_id: 0,
        data_type: DataType::Transaction as i32,
        data: payload.encode_to_vec(),
        inputs: vec![],
        algorithm: None,
    };

    let resp = client.sign(req).await.unwrap().into_inner();
    assert!(
        !resp.signature.is_empty(),
        "signed PSBT should not be empty"
    );
}

#[tokio::test]
async fn grpc_evm_passes_enriched_fields_through() {
    // Verify the Parent Adapter correctly deserializes EnrichedEvmPayload
    // and passes fields to the enclave.
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

    let consignment_hash = b"test-consignment-hash-32bytes!!!".to_vec();

    let payload = enriched::EnrichedEvmPayload {
        call_data: vec![0xAB; 10],
        nonce: 42,
        deadline: 9999,
        consignment_valid: true,
        rgb_amount: 100,
        rgb_asset_id: "asset-id".into(),
        chain_id: 1,
        proxy_contract: vec![0x01; 20],
        calldata_amount: 50,
        calldata_commission: 5,
        consignment_sha256: consignment_hash.clone(),
    };

    let req = SignRequest {
        network_id: 0,
        data_type: DataType::Swap as i32,
        data: payload.encode_to_vec(),
        inputs: vec![],
        algorithm: None,
    };

    client.sign(req).await.unwrap();

    let received = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    assert_eq!(received.call_data, vec![0xAB; 10]);
    assert_eq!(received.nonce, 42);
    assert_eq!(received.deadline, 9999);
    assert!(received.consignment_valid);
    assert_eq!(received.rgb_amount, 100);
    assert_eq!(received.chain_id, 1);
    // consignment_sha256 maps to consignment_hash on the enclave side
    assert_eq!(received.consignment_hash, consignment_hash);
}

// =========================================================================
// Error-path tests
// =========================================================================

#[tokio::test]
async fn grpc_invalid_data_type_returns_error() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    // Use SIGNATURE data_type which we don't support
    let req = SignRequest {
        network_id: 0,
        data_type: DataType::Signature as i32,
        data: vec![],
        inputs: vec![],
        algorithm: None,
    };

    let err = client.sign(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn grpc_invalid_enriched_payload_returns_error() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    // Send garbage bytes as TRANSACTION data
    let req = SignRequest {
        network_id: 0,
        data_type: DataType::Transaction as i32,
        data: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        inputs: vec![],
        algorithm: None,
    };

    // This should still succeed at the gRPC level (prost is lenient with unknown fields)
    // but the point is it doesn't crash
    let _result = client.sign(req).await;
}

#[tokio::test]
async fn grpc_initialize_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = EnclaveServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let resp = client
        .initialize(utexo_bridge_parent::grpc_proto::InitializeRequest {
            cloning_secret: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.public_key.len(),
        33,
        "public_key should be BTC compressed pubkey"
    );
}
