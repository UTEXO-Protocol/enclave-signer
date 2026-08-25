//! Integration tests for the gRPC bridge (Parent Adapter -> Enclave).
//!
//! These tests start a mock enclave TCP server that speaks our wire protocol,
//! then a real tonic gRPC server (Parent Adapter) pointing at it, and finally
//! exercise the full path via a gRPC client.

use std::collections::HashSet;
use std::net::TcpListener;

use tonic::transport::Server;

use utexo_bridge_parent::enclave_proto::{
    self, enclave_request, enclave_response, EnclaveRequest, EnclaveResponse,
};
use utexo_bridge_parent::enriched;
use utexo_bridge_parent::framing;
use utexo_bridge_parent::grpc_proto::parent_service_client::ParentServiceClient;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_proto::{
    sign_request, source_proof, AttestedPublicKeyRequest, EvmSource, RgbSource, SignRequest,
    SourceProof,
};
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::signer::{DataType, PublicKeyRequest, SignRequest as CommonSignRequest};

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
                            evm_uncompressed_pub: vec![0xEE; 64],
                            chain_id: 0,
                            bridge_contract: vec![0u8; 20],
                            rgb_asset_id: String::new(),
                            evm_gas_tx_uncompressed_pub: vec![0xFF; 64],
                            evm_gas_tx_address: vec![0xFA; 20],
                            ccd_ed25519_pub: vec![0x99; 32],
                        },
                    )),
                },
                Some(enclave_request::Request::Sign(sign_req)) => {
                    match sign_req.destination_network {
                        Some(enclave_proto::sign_request::DestinationNetwork::EvmDestination(
                            _,
                        )) => EnclaveResponse {
                            response: Some(enclave_response::Response::EvmSignature(
                                enclave_proto::EvmSignatureResponse {
                                    signature: vec![0xCC; 65],
                                    // Marker so the roundtrip test can assert the
                                    // parent forwards the enclave-rewritten
                                    // calldata (OpId binding, #93/#63).
                                    call_data: vec![0xE0; 9],
                                },
                            )),
                        },
                        Some(enclave_proto::sign_request::DestinationNetwork::RgbDestination(
                            _,
                        )) => EnclaveResponse {
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
                                    message: "missing destination in mock".into(),
                                },
                            )),
                        },
                    }
                }
                Some(enclave_request::Request::SignBtc(_)) => EnclaveResponse {
                    response: Some(enclave_response::Response::SignedPsbt(
                        enclave_proto::SignedPsbtResponse {
                            signed_psbt: vec![0xBC; 80],
                            inputs_signed: 1,
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
                            evm_uncompressed_pub: vec![0xEE; 64],
                            chain_id: 0,
                            bridge_contract: vec![0u8; 20],
                            rgb_asset_id: String::new(),
                            evm_gas_tx_uncompressed_pub: vec![0xFF; 64],
                            evm_gas_tx_address: vec![0xFA; 20],
                            ccd_ed25519_pub: vec![0x99; 32],
                        },
                    )),
                },
                Some(enclave_request::Request::GetLastSavedBlock(_)) => EnclaveResponse {
                    response: Some(enclave_response::Response::GetLastSavedBlock(
                        enclave_proto::GetLastSavedBlockResponse {
                            block_height: 215_000,
                            block_hash: vec![0x11; 32],
                        },
                    )),
                },
                Some(enclave_request::Request::SubmitHeaders(req)) => EnclaveResponse {
                    response: Some(enclave_response::Response::SubmitHeaders(
                        enclave_proto::SubmitHeadersResponse {
                            last_block_height: req.start_height + req.headers.len() as u32 - 1,
                            last_block_hash: vec![0x22; 32],
                            headers_accepted: req.headers.len() as u32,
                        },
                    )),
                },
                Some(enclave_request::Request::GetAttestedPublicKey(req)) => {
                    // Build a fresh mock attestation doc binding the mock pubkey.
                    use sha2::Digest;
                    let public_keys = enclave_proto::PublicKeysResponse {
                        evm_address: vec![0xAA; 20],
                        btc_compressed_pub: vec![0xBB; 33],
                        btc_xpub: "xpub-test".into(),
                        master_fingerprint: vec![0xDD; 4],
                        account_xpub_vanilla: "tpub-vanilla-test".into(),
                        account_xpub_colored: "tpub-colored-test".into(),
                        evm_uncompressed_pub: vec![0xEE; 64],
                        chain_id: 0,
                        bridge_contract: vec![0u8; 20],
                        rgb_asset_id: String::new(),
                        evm_gas_tx_uncompressed_pub: vec![0xFF; 64],
                        evm_gas_tx_address: vec![0xCC; 20],
                        ccd_ed25519_pub: vec![0x99; 32],
                    };
                    let mut bundle: Vec<u8> = Vec::new();
                    let chain_id_bytes = public_keys.chain_id.to_be_bytes();
                    let parts: [&[u8]; 13] = [
                        &public_keys.evm_address,
                        &public_keys.btc_compressed_pub,
                        public_keys.btc_xpub.as_bytes(),
                        &public_keys.master_fingerprint,
                        public_keys.account_xpub_vanilla.as_bytes(),
                        public_keys.account_xpub_colored.as_bytes(),
                        &public_keys.evm_uncompressed_pub,
                        &chain_id_bytes,
                        &public_keys.bridge_contract,
                        public_keys.rgb_asset_id.as_bytes(),
                        &public_keys.evm_gas_tx_uncompressed_pub,
                        &public_keys.evm_gas_tx_address,
                        &public_keys.ccd_ed25519_pub,
                    ];
                    for p in parts {
                        bundle.extend_from_slice(&(p.len() as u32).to_be_bytes());
                        bundle.extend_from_slice(p);
                    }
                    let commitment: [u8; 32] = sha2::Sha256::digest(&bundle).into();
                    let nonce: [u8; 32] = req
                        .nonce
                        .as_slice()
                        .try_into()
                        .expect("test must send 32-byte nonce");
                    let doc = attestation_verify::build_mock_document(
                        &nonce,
                        Some(&public_keys.evm_uncompressed_pub),
                        Some(&commitment),
                    )
                    .expect("build mock doc");
                    EnclaveResponse {
                        response: Some(enclave_response::Response::GetAttestedPublicKey(
                            enclave_proto::GetAttestedPublicKeyResponse {
                                public_keys: Some(public_keys),
                                attestation_doc: doc,
                            },
                        )),
                    }
                }
                Some(enclave_request::Request::SignRawDigest(req)) => {
                    // Prove the parent forwarded the unsigned gas-tx preimage:
                    // require it, and echo its first byte into the signature so
                    // the test can assert what the enclave received.
                    if req.unsigned_tx.is_empty() {
                        EnclaveResponse {
                            response: Some(enclave_response::Response::Error(
                                enclave_proto::ErrorResponse {
                                    code: 3,
                                    message: "mock: SignRawDigest missing unsigned_tx".into(),
                                },
                            )),
                        }
                    } else {
                        EnclaveResponse {
                            response: Some(enclave_response::Response::RawDigestSig(
                                enclave_proto::RawDigestSignatureResponse {
                                    signature: vec![req.unsigned_tx[0]; 65],
                                },
                            )),
                        }
                    }
                }
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

    let service = ParentAdapterService::new(
        EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")),
        HashSet::from([84]),
    );

    tokio::spawn(async move {
        Server::builder()
            .add_service(ParentServiceServer::new(service))
            .serve(grpc_addr)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    grpc_port
}

fn common(src_network_id: u32, dst_network_id: u32, data_type: DataType) -> CommonSignRequest {
    CommonSignRequest {
        src_network_id,
        dst_network_id,
        data_type: data_type as i32,
    }
}

fn rgb_source(
    amount: u64,
    commission: u64,
    consignment: Vec<u8>,
    consignment_hash: Vec<u8>,
    rgb_asset_id: impl Into<String>,
) -> SourceProof {
    SourceProof {
        source_network_id: 0,
        token: String::new(),
        amount,
        commission,
        recipient: String::new(),
        finalized: true,
        chain: Some(source_proof::Chain::Rgb(RgbSource {
            consignment,
            consignment_hash,
            rgb_amount: amount,
            rgb_asset_id: rgb_asset_id.into(),
            merkle_proofs: vec![],
        })),
    }
}

fn evm_source(amount: u64, commission: u64) -> SourceProof {
    SourceProof {
        source_network_id: 84,
        token: String::new(),
        amount,
        commission,
        recipient: String::new(),
        finalized: true,
        chain: Some(source_proof::Chain::Evm(EvmSource {
            tx_hash: vec![0xAA; 32],
            funds_in_operation_id: vec![0x33; 32],
        })),
    }
}

fn sign_evm_request(source: SourceProof, payload: enriched::EnrichedEvmPayload) -> SignRequest {
    SignRequest {
        common: Some(common(0, 84, DataType::Transaction)),
        source: Some(source),
        data: Some(sign_request::Data::EvmData(payload)),
    }
}

fn sign_rgb_request(source: SourceProof, payload: enriched::EnrichedRgbPayload) -> SignRequest {
    SignRequest {
        common: Some(common(84, 0, DataType::Transaction)),
        source: Some(source),
        data: Some(sign_request::Data::RgbData(payload)),
    }
}

// Happy-path tests

#[tokio::test]
async fn grpc_public_key_evm_gas_tx() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let resp = client
        .public_key(PublicKeyRequest {
            network_id: 0,
            data_type: DataType::EvmGasTx as i32,
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.public_key.len(),
        64,
        "EVM gas TX uncompressed pubkey X||Y"
    );
    assert_eq!(resp.public_key, vec![0xFF; 64]);
}

#[tokio::test]
async fn grpc_public_key_transaction_type() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let resp = client
        .public_key(PublicKeyRequest {
            network_id: 0,
            data_type: DataType::Transaction as i32,
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.public_key.len(),
        33,
        "Transaction type returns BTC compressed pubkey"
    );
    assert_eq!(resp.public_key, vec![0xBB; 33]);
}

#[tokio::test]
async fn grpc_public_key_ccd_governance() {
    // The governance pubkey must be reachable over plain PublicKey, with no
    // attestation involved - AttestedPublicKey needs an NSM device, which the
    // dev deployment (plain container, no /dev/nsm) does not have.
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let resp = client
        .public_key(PublicKeyRequest {
            network_id: 0,
            data_type: DataType::CcdGovernance as i32,
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.public_key.len(),
        32,
        "CCD_GOVERNANCE returns a 32-byte Ed25519 pubkey"
    );
    assert_eq!(resp.public_key, vec![0x99; 32]);
}

#[tokio::test]
async fn grpc_public_key_rejects_unsupported_data_type() {
    // Guard against the CCD_GOVERNANCE arm turning the match into a catch-all:
    // data types with no pubkey of their own must still be rejected.
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let err = client
        .public_key(PublicKeyRequest {
            network_id: 0,
            data_type: DataType::Swap as i32,
        })
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn grpc_sign_evm_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let payload = enriched::EnrichedEvmPayload {
        call_data: vec![0xAB; 132],
        nonce: 1,
        deadline: u64::MAX,
        chain_id: 1,
        proxy_contract: vec![],
        calldata_amount: 0,
        calldata_commission: 0,
        unsigned_tx: Vec::new(),
        lz_release: None,
    };

    let req = sign_evm_request(rgb_source(0, 0, vec![], vec![], String::new()), payload);

    let resp = client.sign(req).await.unwrap().into_inner();
    assert_eq!(resp.signature.len(), 65, "EVM signature must be 65 bytes");
    // The parent must forward the enclave-rewritten (OpId-bound) calldata back
    // to the caller - the signature commits to it (#93/#63).
    assert_eq!(
        resp.call_data,
        vec![0xE0; 9],
        "parent must forward EvmSignatureResponse.call_data to the caller"
    );
}

#[tokio::test]
async fn grpc_sign_evm_gas_tx_forwards_unsigned_tx() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    // EVM_GAS_TX: the unsigned tx preimage travels in EnrichedEvmPayload.unsigned_tx.
    let payload = enriched::EnrichedEvmPayload {
        call_data: Vec::new(),
        nonce: 0,
        deadline: 0,
        chain_id: 1,
        proxy_contract: vec![],
        calldata_amount: 0,
        calldata_commission: 0,
        unsigned_tx: vec![0x02; 10],
        lz_release: None,
    };
    let req = SignRequest {
        common: Some(common(0, 84, DataType::EvmGasTx)),
        source: None,
        data: Some(sign_request::Data::EvmData(payload)),
    };

    // The mock enclave echoes unsigned_tx[0] into every signature byte, so a
    // signature of all-0x02 proves the parent forwarded the preimage to
    // SignRawDigestRequest.unsigned_tx (and would have errored on an empty one).
    let resp = client.sign(req).await.unwrap().into_inner();
    assert_eq!(
        resp.signature,
        vec![0x02; 65],
        "parent must forward EnrichedEvmPayload.unsigned_tx to the enclave"
    );
}

#[tokio::test]
async fn grpc_sign_psbt_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let payload = enriched::EnrichedRgbPayload {
        operation_idx: 5,
        psbt_bytes: vec![0xFF; 32],
        psbt_output_amount: 0,
        rgb_asset_id: String::new(),
        consignment: vec![],
        consignment_hash: vec![],
    };

    let req = sign_rgb_request(evm_source(0, 0), payload);

    let resp = client.sign(req).await.unwrap().into_inner();
    assert!(
        !resp.signature.is_empty(),
        "signed PSBT should not be empty"
    );
}

#[tokio::test]
async fn grpc_sign_btc_roundtrip() {
    // BTC_UTXO routes the EnrichedBtcPayload to a SignBtcRequest and returns a
    // signed PSBT - the plain-BTC path is distinct from TRANSACTION/SignPsbt.
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let payload = enriched::EnrichedBtcPayload {
        psbt_bytes: vec![0x70, 0x73, 0x62, 0x74, 0xFF],
    };

    let req = SignRequest {
        common: Some(common(0, 0, DataType::BtcUtxo)),
        source: None,
        data: Some(sign_request::Data::BtcData(payload)),
    };

    let resp = client.sign(req).await.unwrap().into_inner();
    assert_eq!(
        resp.signature,
        vec![0xBC; 80],
        "BTC_UTXO should route to SignBtc and return its signed PSBT"
    );
}

#[tokio::test]
async fn grpc_btc_utxo_rejects_missing_payload() {
    // BTC_UTXO with no BtcData in the oneof must be rejected at the boundary,
    // not forwarded to the enclave.
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let req = SignRequest {
        common: Some(common(0, 0, DataType::BtcUtxo)),
        source: None,
        data: None,
    };

    let status = client.sign(req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn grpc_evm_passes_enriched_fields_through() {
    // Verify the Parent Adapter correctly deserializes EnrichedEvmPayload
    // and passes fields to the enclave.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let enclave_port = listener.local_addr().unwrap().port();

    let (tx, rx) = std::sync::mpsc::channel::<enclave_proto::SignRequest>();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let req: EnclaveRequest = framing::read_message(&mut stream).unwrap();

            if let Some(enclave_request::Request::Sign(sign_req)) = req.request {
                tx.send(sign_req).unwrap();
                let resp = EnclaveResponse {
                    response: Some(enclave_response::Response::EvmSignature(
                        enclave_proto::EvmSignatureResponse {
                            signature: vec![0xCC; 65],
                            call_data: Vec::new(),
                        },
                    )),
                };
                let _ = framing::write_message(&mut stream, &resp);
            }
        }
    });

    let grpc_port = start_grpc_server(enclave_port).await;
    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let consignment_bytes = vec![0xAB; 100];
    let consignment_hash = b"test-consignment-hash-32bytes!!!".to_vec();

    let payload = enriched::EnrichedEvmPayload {
        call_data: vec![0xAB; 10],
        nonce: 42,
        deadline: 9999,
        chain_id: 1,
        proxy_contract: vec![0x01; 20],
        calldata_amount: 50,
        calldata_commission: 5,
        unsigned_tx: Vec::new(),
        lz_release: None,
    };

    let req = sign_evm_request(
        rgb_source(
            100,
            5,
            consignment_bytes.clone(),
            consignment_hash.clone(),
            "asset-id",
        ),
        payload,
    );

    client.sign(req).await.unwrap();

    let received = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    assert_eq!(received.amount, 100);
    match received.source_network {
        Some(enclave_proto::sign_request::SourceNetwork::RgbSource(source)) => {
            assert!(source.consignment_valid);
            assert_eq!(source.asset_id, "asset-id");
            assert_eq!(source.commission, 5);
            assert_eq!(source.consignment, consignment_bytes);
            assert_eq!(source.consignment_hash, consignment_hash);
        }
        other => panic!("expected RGB source, got {other:?}"),
    }
    match received.destination_network {
        Some(enclave_proto::sign_request::DestinationNetwork::EvmDestination(destination)) => {
            assert_eq!(destination.call_data, vec![0xAB; 10]);
            assert_eq!(destination.nonce, 42);
            assert_eq!(destination.deadline, 9999);
            assert_eq!(destination.chain_id, 1);
            assert_eq!(destination.proxy_contract, vec![0x01; 20]);
            assert_eq!(destination.calldata_amount, 50);
            assert_eq!(destination.calldata_commission, 5);
        }
        other => panic!("expected EVM destination, got {other:?}"),
    }
}

#[tokio::test]
async fn grpc_evm_forwards_raw_consignment_bytes() {
    // Regression: parent adapter previously hardcoded consignment: vec![] and
    // forwarded only the hash. After the listener wire-format change (field 11
    // is now raw bytes; new field 12 carries keccak256), both must round-trip.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let enclave_port = listener.local_addr().unwrap().port();

    let (tx, rx) = std::sync::mpsc::channel::<enclave_proto::SignRequest>();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let req: EnclaveRequest = framing::read_message(&mut stream).unwrap();

            if let Some(enclave_request::Request::Sign(sign_req)) = req.request {
                tx.send(sign_req).unwrap();
                let resp = EnclaveResponse {
                    response: Some(enclave_response::Response::EvmSignature(
                        enclave_proto::EvmSignatureResponse {
                            signature: vec![0xCC; 65],
                            call_data: Vec::new(),
                        },
                    )),
                };
                let _ = framing::write_message(&mut stream, &resp);
            }
        }
    });

    let grpc_port = start_grpc_server(enclave_port).await;
    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let consignment_bytes: Vec<u8> = (0..256u32).map(|i| (i & 0xFF) as u8).collect();
    let consignment_hash = vec![0x5A; 32];

    let payload = enriched::EnrichedEvmPayload {
        call_data: vec![0xAB; 132],
        nonce: 7,
        deadline: 1234,
        chain_id: 1,
        proxy_contract: vec![0x02; 20],
        calldata_amount: 0,
        calldata_commission: 0,
        unsigned_tx: Vec::new(),
        lz_release: None,
    };

    let req = sign_evm_request(
        rgb_source(
            0,
            0,
            consignment_bytes.clone(),
            consignment_hash.clone(),
            String::new(),
        ),
        payload,
    );

    client.sign(req).await.unwrap();

    let received = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    match received.source_network {
        Some(enclave_proto::sign_request::SourceNetwork::RgbSource(source)) => {
            assert_eq!(source.consignment.len(), 256);
            assert_eq!(source.consignment, consignment_bytes);
            assert_eq!(source.consignment_hash.len(), 32);
            assert_eq!(source.consignment_hash, consignment_hash);
        }
        other => panic!("expected RGB source, got {other:?}"),
    }
}

// Error-path tests

#[tokio::test]
async fn grpc_invalid_data_type_returns_error() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    // Use SIGNATURE data_type which we don't support
    let req = SignRequest {
        common: Some(common(0, 84, DataType::Signature)),
        source: Some(rgb_source(0, 0, vec![], vec![], String::new())),
        data: None,
    };

    let err = client.sign(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn grpc_missing_transaction_payload_returns_error() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    // Structured API requires one destination payload for transaction signing.
    let req = SignRequest {
        common: Some(common(0, 84, DataType::Transaction)),
        source: Some(rgb_source(0, 0, vec![], vec![], String::new())),
        data: None,
    };

    let err = client.sign(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn grpc_initialize_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
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

#[tokio::test]
async fn grpc_get_last_saved_block_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let resp = client
        .get_last_saved_block(utexo_bridge_parent::grpc_proto::GetLastSavedBlockRequest {})
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.block_height, 215_000);
    assert_eq!(resp.block_hash, vec![0x11; 32]);
}

#[tokio::test]
async fn grpc_submit_headers_roundtrip() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let headers = vec![vec![0xAB; 80], vec![0xCD; 80], vec![0xEF; 80]];
    let resp = client
        .submit_headers(utexo_bridge_parent::grpc_proto::SubmitHeadersRequest {
            headers: headers.clone(),
            start_height: 215_001,
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.last_block_height, 215_003);
    assert_eq!(resp.last_block_hash, vec![0x22; 32]);
    assert_eq!(resp.headers_accepted, 3);
}

#[tokio::test]
async fn grpc_attested_public_key_roundtrip_and_verify() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let nonce = [0x37u8; 32];
    let resp = client
        .attested_public_key(AttestedPublicKeyRequest {
            nonce: nonce.to_vec(),
        })
        .await
        .unwrap()
        .into_inner();

    // Wire-level public-key bundle is intact.
    assert_eq!(resp.evm_address, vec![0xAA; 20]);
    assert_eq!(resp.evm_uncompressed_pub, vec![0xEE; 64]);
    assert!(!resp.attestation_doc.is_empty());

    // The attestation document verifies, binds the EVM pubkey, and the
    // commitment over the canonical bundle matches.
    let verified = attestation_verify::verify_mock_attestation(
        &resp.attestation_doc,
        &attestation_verify::ExpectedPcrs::zero(),
        Some(&nonce),
    )
    .expect("verify mock doc");
    assert_eq!(verified.enclave_pubkey, resp.evm_uncompressed_pub);

    use sha2::Digest;
    let mut bundle: Vec<u8> = Vec::new();
    let chain_id_bytes = resp.chain_id.to_be_bytes();
    let parts: [&[u8]; 13] = [
        &resp.evm_address,
        &resp.btc_compressed_pub,
        resp.btc_xpub.as_bytes(),
        &resp.master_fingerprint,
        resp.account_xpub_vanilla.as_bytes(),
        resp.account_xpub_colored.as_bytes(),
        &resp.evm_uncompressed_pub,
        &chain_id_bytes,
        &resp.bridge_contract,
        resp.rgb_asset_id.as_bytes(),
        &resp.evm_gas_tx_uncompressed_pub,
        &resp.evm_gas_tx_address,
        &resp.ccd_ed25519_pub,
    ];
    for p in parts {
        bundle.extend_from_slice(&(p.len() as u32).to_be_bytes());
        bundle.extend_from_slice(p);
    }
    let expected: [u8; 32] = sha2::Sha256::digest(&bundle).into();
    assert_eq!(verified.user_data.as_deref(), Some(expected.as_slice()));
    assert_eq!(verified.nonce, nonce.to_vec());
}

#[tokio::test]
async fn grpc_attested_public_key_rejects_wrong_nonce_size() {
    let enclave_port = start_mock_enclave();
    let grpc_port = start_grpc_server(enclave_port).await;

    let mut client = ParentServiceClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();

    let err = client
        .attested_public_key(AttestedPublicKeyRequest {
            nonce: vec![0u8; 16],
        })
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
