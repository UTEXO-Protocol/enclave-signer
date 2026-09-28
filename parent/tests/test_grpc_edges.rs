//! Edge and error paths of the gRPC bridge: every boundary rejection, every
//! enclave error mapping, every "unexpected reply", and the transport
//! failures - against a scriptable mock enclave.

mod common;

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use common::{
    dead_port, error_response, msg, response, start_enclave, start_enclave_replying, Reply,
};
use tonic::transport::{Channel, Server};
use tonic::Code;
use utexo_bridge_parent::enclave_proto::{
    self, enclave_request, enclave_response, CcdSignatureResponse, EnclaveRequest,
    EvmSignatureResponse, GetAttestedPublicKeyResponse, GetCloneResponse, InitializeKeyResponse,
    PublicKeysResponse, RawDigestSignatureResponse, SignedPsbtResponse,
};
use utexo_bridge_parent::enriched;
use utexo_bridge_parent::grpc_proto::parent_service_client::ParentServiceClient;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_proto::{
    sign_request, source_proof, AttestedPublicKeyRequest, CloneRequest, EvmSource,
    GetLastSavedBlockRequest, InitializeRequest, MerkleProofEntry, MintAncestor, RgbSource,
    SignRequest, SourceProof, SubmitHeadersRequest,
};
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::signer::{DataType, PublicKeyRequest, SignRequest as CommonSignRequest};

const EVM_NET: u32 = 84;
const RGB_NET: u32 = 0;

async fn grpc(enclave_port: u16) -> ParentServiceClient<Channel> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let service = ParentAdapterService::new(
        EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")),
        HashSet::from([EVM_NET]),
    );
    tokio::spawn(async move {
        Server::builder()
            .add_service(ParentServiceServer::new(service))
            .serve(addr)
            .await
            .unwrap();
    });
    for _ in 0..50 {
        if let Ok(c) = ParentServiceClient::connect(format!("http://{addr}")).await {
            return c;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("gRPC server did not come up");
}

fn common(dst: u32, data_type: DataType) -> Option<CommonSignRequest> {
    Some(CommonSignRequest {
        src_network_id: if dst == EVM_NET { RGB_NET } else { EVM_NET },
        dst_network_id: dst,
        data_type: data_type as i32,
    })
}

fn rgb_source() -> SourceProof {
    SourceProof {
        source_network_id: RGB_NET,
        token: String::new(),
        amount: 100,
        commission: 5,
        recipient: String::new(),
        finalized: true,
        chain: Some(source_proof::Chain::Rgb(RgbSource {
            consignment: vec![0xC0; 3],
            consignment_hash: vec![0xC1; 32],
            rgb_amount: 100,
            rgb_asset_id: "rgb:asset".into(),
            merkle_proofs: vec![MerkleProofEntry {
                txid: vec![0x1D; 32],
                block_height: 200,
                tx_position: 3,
                merkle_path: vec![vec![0x2A; 32]],
            }],
            mint_ancestors: vec![MintAncestor {
                op_id: vec![0x0A; 32],
                tx_hash: vec![0x0B; 32],
            }],
        })),
    }
}

fn evm_source(opid_len: usize) -> SourceProof {
    SourceProof {
        source_network_id: EVM_NET,
        token: format!("0x{}", "11".repeat(20)),
        amount: 100,
        commission: 5,
        recipient: "utxob:seal".into(),
        finalized: false,
        chain: Some(source_proof::Chain::Evm(EvmSource {
            tx_hash: vec![0xAA; 32],
            funds_in_operation_id: vec![0x33; opid_len],
        })),
    }
}

fn evm_payload() -> enriched::EnrichedEvmPayload {
    let mut p = enriched::EnrichedEvmPayload {
        call_data: vec![0xAB; 4],
        nonce: 1,
        deadline: 2,
        chain_id: 3,
        proxy_contract: vec![0x04; 20],
        calldata_amount: 95,
        calldata_commission: 5,
        unsigned_tx: vec![0x02; 10],
        lz_release: Some(Default::default()),
    };
    if let Some(lr) = p.lz_release.as_mut() {
        lr.dst_eid = 30101;
        lr.min_amount_ld = 90;
        lr.recipient = vec![0x13; 32];
    }
    p
}

fn rgb_payload() -> enriched::EnrichedRgbPayload {
    enriched::EnrichedRgbPayload {
        operation_idx: 9,
        psbt_bytes: vec![0x70; 8],
        psbt_output_amount: 95,
        rgb_asset_id: "rgb:asset".into(),
        consignment: vec![0xC0; 3],
        consignment_hash: vec![0xC1; 32],
        mint_ancestors: vec![MintAncestor {
            op_id: vec![0x0A; 32],
            tx_hash: vec![0x0B; 32],
        }],
    }
}

fn ccd_data(hash: Vec<u8>) -> sign_request::Data {
    let mut d = sign_request::Data::CcdData(Default::default());
    if let sign_request::Data::CcdData(p) = &mut d {
        p.hash = hash;
    }
    d
}

fn rgb_to_evm() -> SignRequest {
    SignRequest {
        common: common(EVM_NET, DataType::Transaction),
        source: Some(rgb_source()),
        data: Some(sign_request::Data::EvmData(evm_payload())),
    }
}

fn evm_to_rgb() -> SignRequest {
    SignRequest {
        common: common(RGB_NET, DataType::Transaction),
        source: Some(evm_source(32)),
        data: Some(sign_request::Data::RgbData(rgb_payload())),
    }
}

fn keys() -> PublicKeysResponse {
    PublicKeysResponse {
        evm_address: vec![0xAA; 20],
        btc_compressed_pub: vec![0xBB; 33],
        btc_xpub: "xpub".into(),
        master_fingerprint: vec![0xDD; 4],
        account_xpub_vanilla: "v".into(),
        account_xpub_colored: "c".into(),
        evm_uncompressed_pub: vec![0xEE; 64],
        chain_id: 7,
        bridge_contract: vec![0x01; 20],
        rgb_asset_id: "rgb:x".into(),
        evm_gas_tx_uncompressed_pub: vec![0xFF; 64],
        evm_gas_tx_address: vec![0xFA; 20],
        ccd_ed25519_pub: vec![0x99; 32],
    }
}

fn assert_no_enclave_contact(rx: &Receiver<EnclaveRequest>) {
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(200))
            .is_err(),
        "the request must be rejected before the enclave is contacted"
    );
}

fn assert_status(status: &tonic::Status, code: Code, needle: &str) {
    assert_eq!(status.code(), code, "{}", status.message());
    assert!(
        status.message().contains(needle),
        "expected {needle:?} in {:?}",
        status.message()
    );
}

// ---- CCD -------------------------------------------------------------------

#[tokio::test]
async fn ccd_sign_routes_to_sign_ccd_and_returns_the_key_with_the_signature() {
    let (port, rx) = start_enclave_replying(response(enclave_response::Response::CcdSignature(
        CcdSignatureResponse {
            signature: vec![0xC5; 64],
            public_key: vec![0x99; 32],
        },
    )));
    let mut client = grpc(port).await;
    let resp = client
        .sign(SignRequest {
            common: common(919, DataType::Transaction),
            source: None,
            data: Some(ccd_data(vec![0x4A; 32])),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.signature, vec![0xC5; 64]);
    assert_eq!(resp.public_key, vec![0x99; 32]);
    assert!(resp.call_data.is_empty());
    assert!(resp.identifier.is_none());
    assert_eq!(resp.signer_network_id, 919);
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::SignCcd(s)) => assert_eq!(s.hash, vec![0x4A; 32]),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn ccd_sign_requires_the_transaction_data_type() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;
    for dt in [DataType::EvmGasTx, DataType::BtcUtxo, DataType::Signature] {
        let status = client
            .sign(SignRequest {
                common: common(919, dt),
                source: None,
                data: Some(ccd_data(vec![0x4A; 32])),
            })
            .await
            .unwrap_err();
        assert_status(
            &status,
            Code::InvalidArgument,
            "CCD signing requires TRANSACTION",
        );
    }
    assert_no_enclave_contact(&rx);
}

#[tokio::test]
async fn ccd_sign_maps_enclave_errors_and_unexpected_replies() {
    let req = || SignRequest {
        common: common(919, DataType::Transaction),
        source: None,
        data: Some(ccd_data(vec![0x4A; 32])),
    };
    let (port, _rx) = start_enclave_replying(error_response(3, "not the governance key"));
    let status = grpc(port).await.sign(req()).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "not the governance key");

    let (port, _rx) = start_enclave_replying(error_response(1, "boom"));
    let status = grpc(port).await.sign(req()).await.unwrap_err();
    assert_status(&status, Code::Internal, "enclave error (code 1): boom");

    let (port, _rx) =
        start_enclave_replying(response(enclave_response::Response::PublicKeys(keys())));
    let status = grpc(port).await.sign(req()).await.unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for CCD Sign",
    );
}

// ---- TRANSACTION boundary checks ---------------------------------------------

#[tokio::test]
async fn transaction_sign_rejects_a_request_without_common_or_source() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;

    let mut req = rgb_to_evm();
    req.common = None;
    let status = client.sign(req).await.unwrap_err();
    assert_status(
        &status,
        Code::InvalidArgument,
        "SignRequest.common is missing",
    );

    let mut req = rgb_to_evm();
    req.source = None;
    let status = client.sign(req).await.unwrap_err();
    assert_status(
        &status,
        Code::InvalidArgument,
        "SignRequest.source is missing",
    );

    assert_no_enclave_contact(&rx);
}

#[tokio::test]
async fn transaction_sign_checks_the_payload_against_the_evm_network_set() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;

    // EVM payload addressed to a network that is not configured as EVM.
    let mut req = rgb_to_evm();
    req.common = common(RGB_NET, DataType::Transaction);
    let status = client.sign(req).await.unwrap_err();
    assert_status(&status, Code::InvalidArgument, "is not configured as EVM");

    // RGB payload addressed to the EVM network.
    let mut req = evm_to_rgb();
    req.common = common(EVM_NET, DataType::Transaction);
    let status = client.sign(req).await.unwrap_err();
    assert_status(&status, Code::InvalidArgument, "is configured as EVM");

    assert_no_enclave_contact(&rx);
}

#[tokio::test]
async fn transaction_sign_rejects_btc_data_and_missing_data() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;

    let mut req = rgb_to_evm();
    req.data = Some(sign_request::Data::BtcData(enriched::EnrichedBtcPayload {
        psbt_bytes: vec![0x70],
    }));
    let status = client.sign(req).await.unwrap_err();
    assert_status(&status, Code::InvalidArgument, "must not carry BtcData");

    let mut req = rgb_to_evm();
    req.data = None;
    let status = client.sign(req).await.unwrap_err();
    assert_status(
        &status,
        Code::InvalidArgument,
        "SignRequest.data is missing",
    );

    assert_no_enclave_contact(&rx);
}

#[tokio::test]
async fn transaction_sign_validates_the_source_proof() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;

    let mut req = rgb_to_evm();
    req.source.as_mut().unwrap().chain = None;
    let status = client.sign(req).await.unwrap_err();
    assert_status(&status, Code::InvalidArgument, "no chain-specific evidence");

    let mut req = evm_to_rgb();
    req.source = Some(evm_source(31));
    let status = client.sign(req).await.unwrap_err();
    assert_status(&status, Code::InvalidArgument, "must be 32 bytes");

    let mut req = evm_to_rgb();
    req.source.as_mut().unwrap().token = "0xnothex".into();
    let status = client.sign(req).await.unwrap_err();
    assert_status(
        &status,
        Code::InvalidArgument,
        "SourceProof.token must be hex bytes",
    );

    assert_no_enclave_contact(&rx);
}

#[tokio::test]
async fn transaction_sign_rejects_same_network_routes() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;

    // EVM source with an EVM payload.
    let mut req = rgb_to_evm();
    req.source = Some(evm_source(32));
    let status = client.sign(req).await.unwrap_err();
    assert_status(&status, Code::InvalidArgument, "must be different");

    // RGB source with an RGB payload.
    let mut req = evm_to_rgb();
    req.source = Some(rgb_source());
    let status = client.sign(req).await.unwrap_err();
    assert_status(&status, Code::InvalidArgument, "must be different");

    assert_no_enclave_contact(&rx);
}

#[tokio::test]
async fn unsupported_data_types_are_rejected_before_the_enclave() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;
    for dt in [
        DataType::Signature,
        DataType::Swap,
        DataType::Unspendable,
        DataType::CcdGovernance,
    ] {
        let mut req = rgb_to_evm();
        req.common = common(EVM_NET, dt);
        let status = client.sign(req).await.unwrap_err();
        assert_status(&status, Code::InvalidArgument, "unsupported data_type");
    }
    assert_no_enclave_contact(&rx);
}

// ---- TRANSACTION forwarding and reply mapping ------------------------------

#[tokio::test]
async fn transaction_sign_forwards_every_field_in_both_directions() {
    let (port, rx) = start_enclave(Arc::new(|req| match req.request {
        Some(enclave_request::Request::Sign(s)) => match s.destination_network {
            Some(enclave_proto::sign_request::DestinationNetwork::EvmDestination(_)) => {
                msg(response(enclave_response::Response::EvmSignature(
                    EvmSignatureResponse {
                        signature: vec![0xCC; 65],
                        call_data: vec![0xE0; 9],
                    },
                )))
            }
            _ => msg(response(enclave_response::Response::SignedPsbt(
                SignedPsbtResponse {
                    signed_psbt: vec![0xDD; 10],
                    inputs_signed: 1,
                },
            ))),
        },
        _ => msg(error_response(1, "unexpected")),
    }));
    let mut client = grpc(port).await;

    // RGB -> EVM.
    let resp = client.sign(rgb_to_evm()).await.unwrap().into_inner();
    assert_eq!(resp.signature, vec![0xCC; 65]);
    assert_eq!(resp.call_data, vec![0xE0; 9]);
    assert!(
        resp.public_key.is_empty(),
        "secp256k1 signer is recoverable"
    );
    assert!(resp.identifier.is_none());
    assert_eq!(resp.signer_network_id, EVM_NET);
    let sent = match rx.recv().unwrap().request {
        Some(enclave_request::Request::Sign(s)) => s,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(sent.amount, 100);
    match sent.source_network.unwrap() {
        enclave_proto::sign_request::SourceNetwork::RgbSource(s) => {
            assert!(s.consignment_valid);
            assert_eq!(s.asset_id, "rgb:asset");
            assert_eq!(s.commission, 5);
            assert_eq!(s.consignment, vec![0xC0; 3]);
            assert_eq!(s.consignment_hash, vec![0xC1; 32]);
            assert_eq!(s.merkle_proofs.len(), 1);
            assert_eq!(s.merkle_proofs[0].txid, vec![0x1D; 32]);
            assert_eq!(s.merkle_proofs[0].merkle_path, vec![vec![0x2A; 32]]);
            assert_eq!(s.mint_ancestors.len(), 1);
            assert_eq!(s.mint_ancestors[0].op_id, vec![0x0A; 32]);
            assert_eq!(s.mint_ancestors[0].tx_hash, vec![0x0B; 32]);
        }
        other => panic!("unexpected {other:?}"),
    }
    match sent.destination_network.unwrap() {
        enclave_proto::sign_request::DestinationNetwork::EvmDestination(d) => {
            assert_eq!(d.call_data, vec![0xAB; 4]);
            assert_eq!((d.nonce, d.deadline, d.chain_id), (1, 2, 3));
            assert_eq!(d.proxy_contract, vec![0x04; 20]);
            assert_eq!((d.calldata_amount, d.calldata_commission), (95, 5));
            let lr = d.lz_release.expect("lz release forwarded");
            assert_eq!((lr.dst_eid, lr.min_amount_ld), (30101, 90));
            assert_eq!(lr.recipient, vec![0x13; 32]);
        }
        other => panic!("unexpected {other:?}"),
    }

    // EVM -> RGB.
    let resp = client.sign(evm_to_rgb()).await.unwrap().into_inner();
    assert_eq!(resp.signature, vec![0xDD; 10]);
    assert!(resp.call_data.is_empty());
    assert!(resp.public_key.is_empty());
    assert_eq!(resp.signer_network_id, RGB_NET);
    let sent = match rx.recv().unwrap().request {
        Some(enclave_request::Request::Sign(s)) => s,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(sent.amount, 100);
    match sent.source_network.unwrap() {
        enclave_proto::sign_request::SourceNetwork::EvmSource(s) => {
            assert_eq!(s.tx_hash, vec![0xAA; 32]);
            assert!(s.event_valid);
            assert!(!s.event_finalized);
            assert_eq!(s.token, vec![0x11; 20]);
            assert_eq!(s.recipient, b"utxob:seal".to_vec());
            assert_eq!(s.commission, 5);
            assert_eq!(s.funds_in_operation_id, vec![0x33; 32]);
        }
        other => panic!("unexpected {other:?}"),
    }
    match sent.destination_network.unwrap() {
        enclave_proto::sign_request::DestinationNetwork::RgbDestination(d) => {
            assert_eq!(d.operation_idx, 9);
            assert_eq!(d.psbt_bytes, vec![0x70; 8]);
            assert_eq!(d.psbt_output_amount, 95);
            assert_eq!(d.asset_id, "rgb:asset");
            assert_eq!(d.consignment, vec![0xC0; 3]);
            assert_eq!(d.consignment_hash, vec![0xC1; 32]);
            assert_eq!(d.mint_ancestors.len(), 1);
            assert_eq!(d.mint_ancestors[0].tx_hash, vec![0x0B; 32]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn transaction_sign_maps_enclave_errors_and_unexpected_replies() {
    let (port, _rx) = start_enclave_replying(error_response(3, "amount mismatch"));
    let status = grpc(port).await.sign(rgb_to_evm()).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "amount mismatch");

    let (port, _rx) = start_enclave_replying(error_response(2, "not ready"));
    let status = grpc(port).await.sign(evm_to_rgb()).await.unwrap_err();
    assert_status(&status, Code::Internal, "enclave error (code 2): not ready");

    let (port, _rx) =
        start_enclave_replying(response(enclave_response::Response::PublicKeys(keys())));
    let status = grpc(port).await.sign(rgb_to_evm()).await.unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for Sign",
    );
}

// ---- EVM_GAS_TX ------------------------------------------------------------

#[tokio::test]
async fn gas_tx_sign_requires_evm_data() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;
    for data in [None, Some(sign_request::Data::RgbData(rgb_payload()))] {
        let status = client
            .sign(SignRequest {
                common: common(EVM_NET, DataType::EvmGasTx),
                source: None,
                data,
            })
            .await
            .unwrap_err();
        assert_status(
            &status,
            Code::InvalidArgument,
            "EVM_GAS_TX sign requires EvmData",
        );
    }
    assert_no_enclave_contact(&rx);
}

#[tokio::test]
async fn gas_tx_sign_forwards_the_digest_and_preimage_and_maps_replies() {
    let req = || SignRequest {
        common: common(EVM_NET, DataType::EvmGasTx),
        source: None,
        data: Some(sign_request::Data::EvmData(evm_payload())),
    };

    let (port, rx) = start_enclave_replying(response(enclave_response::Response::RawDigestSig(
        RawDigestSignatureResponse {
            signature: vec![0x5A; 65],
        },
    )));
    let resp = grpc(port).await.sign(req()).await.unwrap().into_inner();
    assert_eq!(resp.signature, vec![0x5A; 65]);
    assert!(resp.call_data.is_empty() && resp.public_key.is_empty());
    assert_eq!(resp.signer_network_id, EVM_NET);
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::SignRawDigest(s)) => {
            assert_eq!(s.digest, vec![0xAB; 4], "call_data rides as the digest");
            assert_eq!(s.unsigned_tx, vec![0x02; 10]);
        }
        other => panic!("unexpected {other:?}"),
    }

    let (port, _rx) = start_enclave_replying(error_response(3, "gas path unpinned"));
    let status = grpc(port).await.sign(req()).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), "gas path unpinned");

    let (port, _rx) = start_enclave_replying(response(enclave_response::Response::SignedPsbt(
        SignedPsbtResponse {
            signed_psbt: vec![1],
            inputs_signed: 1,
        },
    )));
    let status = grpc(port).await.sign(req()).await.unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for SignRawDigest",
    );
}

// ---- BTC_UTXO --------------------------------------------------------------

#[tokio::test]
async fn btc_utxo_sign_forwards_the_psbt_and_maps_replies() {
    let req = || SignRequest {
        common: common(RGB_NET, DataType::BtcUtxo),
        source: None,
        data: Some(sign_request::Data::BtcData(enriched::EnrichedBtcPayload {
            psbt_bytes: vec![0x70, 0x73, 0x62, 0x74],
        })),
    };

    let (port, rx) = start_enclave_replying(response(enclave_response::Response::SignedPsbt(
        SignedPsbtResponse {
            signed_psbt: vec![0xBC; 80],
            inputs_signed: 1,
        },
    )));
    let resp = grpc(port).await.sign(req()).await.unwrap().into_inner();
    assert_eq!(resp.signature, vec![0xBC; 80]);
    assert!(resp.public_key.is_empty() && resp.call_data.is_empty());
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::SignBtc(s)) => {
            assert_eq!(s.psbt_bytes, vec![0x70, 0x73, 0x62, 0x74])
        }
        other => panic!("unexpected {other:?}"),
    }

    let (port, _rx) = start_enclave_replying(error_response(1, "vanilla path disabled"));
    let status = grpc(port).await.sign(req()).await.unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "enclave error (code 1): vanilla path disabled",
    );

    let (port, _rx) = start_enclave_replying(response(enclave_response::Response::EvmSignature(
        EvmSignatureResponse {
            signature: vec![1],
            call_data: vec![],
        },
    )));
    let status = grpc(port).await.sign(req()).await.unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for SignBtc",
    );
}

#[tokio::test]
async fn btc_utxo_sign_rejects_other_payloads() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;
    for data in [
        Some(sign_request::Data::EvmData(evm_payload())),
        Some(sign_request::Data::RgbData(rgb_payload())),
    ] {
        let status = client
            .sign(SignRequest {
                common: common(RGB_NET, DataType::BtcUtxo),
                source: None,
                data,
            })
            .await
            .unwrap_err();
        assert_status(
            &status,
            Code::InvalidArgument,
            "BTC_UTXO sign requires BtcData",
        );
    }
    assert_no_enclave_contact(&rx);
}

// ---- PublicKey -------------------------------------------------------------

#[tokio::test]
async fn public_key_picks_the_key_by_data_type_and_falls_back_to_transaction() {
    let (port, _rx) =
        start_enclave_replying(response(enclave_response::Response::PublicKeys(keys())));
    let mut client = grpc(port).await;
    for (dt, want) in [
        (DataType::Transaction as i32, vec![0xBB; 33]),
        (DataType::Unspendable as i32, vec![0xBB; 33]),
        (DataType::EvmGasTx as i32, vec![0xFF; 64]),
        (DataType::CcdGovernance as i32, vec![0x99; 32]),
        // Unknown enum values decode as TRANSACTION.
        (i32::MAX, vec![0xBB; 33]),
    ] {
        let resp = client
            .public_key(PublicKeyRequest {
                network_id: 0,
                data_type: dt,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.public_key, want, "data_type {dt}");
        assert!(resp.identifier.is_none());
    }
}

#[tokio::test]
async fn public_key_maps_enclave_errors_and_unexpected_replies() {
    let req = || PublicKeyRequest {
        network_id: 0,
        data_type: DataType::Transaction as i32,
    };
    let (port, _rx) = start_enclave_replying(error_response(2, "keys not initialized"));
    let status = grpc(port).await.public_key(req()).await.unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "enclave error (code 2): keys not initialized",
    );

    let (port, _rx) = start_enclave_replying(response(enclave_response::Response::InitializeKey(
        Default::default(),
    )));
    let status = grpc(port).await.public_key(req()).await.unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for PublicKey",
    );
}

// ---- Initialize / Clone ----------------------------------------------------

#[tokio::test]
async fn initialize_forwards_the_mnemonic_and_maps_replies() {
    let (port, rx) = start_enclave_replying(response(enclave_response::Response::InitializeKey(
        InitializeKeyResponse {
            btc_compressed_pub: vec![0xBB; 33],
            ..Default::default()
        },
    )));
    let mut client = grpc(port).await;
    let resp = client
        .initialize(InitializeRequest {
            cloning_secret: "abandon abandon about".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.public_key, vec![0xBB; 33]);
    assert!(resp.attestation.is_empty());
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::InitializeKey(k)) => {
            assert!(k.seed.is_empty());
            assert_eq!(k.mnemonic, "abandon abandon about");
            assert!(k.cloning_secret.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }

    let (port, _rx) = start_enclave_replying(error_response(1, "already initialized"));
    let status = grpc(port)
        .await
        .initialize(InitializeRequest {
            cloning_secret: String::new(),
        })
        .await
        .unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "enclave error (code 1): already initialized",
    );

    let (port, _rx) =
        start_enclave_replying(response(enclave_response::Response::PublicKeys(keys())));
    let status = grpc(port)
        .await
        .initialize(InitializeRequest {
            cloning_secret: String::new(),
        })
        .await
        .unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for Initialize",
    );
}

#[tokio::test]
async fn clone_forwards_the_requester_material_and_maps_replies() {
    let req = || CloneRequest {
        attestation: vec![0xA7; 5],
        encryption_pubkey: vec![0xE1; 32],
        cluster_public_key: vec![0xC1; 20],
        cloning_digest: vec![0xD1; 32],
    };
    let (port, rx) = start_enclave_replying(response(enclave_response::Response::GetClone(
        GetCloneResponse {
            encrypted_seed: vec![0x5E; 80],
            donor_pubkey: vec![0xD0; 32],
            donor_attestation: vec![0xDA; 5],
        },
    )));
    let mut client = grpc(port).await;
    // Path syntax: `client.clone(req)` would resolve to `Clone::clone`.
    let resp = ParentServiceClient::clone(&mut client, req())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.encrypted_seed, vec![0x5E; 80]);
    assert_eq!(resp.donor_pubkey, vec![0xD0; 32]);
    assert_eq!(resp.donor_attestation, vec![0xDA; 5]);
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::GetClone(g)) => {
            assert_eq!(g.cluster_public_key, vec![0xC1; 20]);
            assert_eq!(g.cloning_digest, vec![0xD1; 32]);
            assert_eq!(g.encryption_pubkey, vec![0xE1; 32]);
            assert_eq!(g.requester_attestation, vec![0xA7; 5]);
        }
        other => panic!("unexpected {other:?}"),
    }

    let (port, _rx) = start_enclave_replying(error_response(1, "digest mismatch"));
    let mut client = grpc(port).await;
    let status = ParentServiceClient::clone(&mut client, req())
        .await
        .unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "enclave error (code 1): digest mismatch",
    );

    let (port, _rx) =
        start_enclave_replying(response(enclave_response::Response::PublicKeys(keys())));
    let mut client = grpc(port).await;
    let status = ParentServiceClient::clone(&mut client, req())
        .await
        .unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for Clone",
    );
}

// ---- Header chain ----------------------------------------------------------

#[tokio::test]
async fn header_chain_rpcs_map_not_ready_and_unexpected_replies() {
    let (port, _rx) = start_enclave_replying(error_response(2, "header chain not compiled in"));
    let mut client = grpc(port).await;
    let status = client
        .get_last_saved_block(GetLastSavedBlockRequest {})
        .await
        .unwrap_err();
    assert_status(&status, Code::Internal, "enclave error (code 2)");
    let status = client
        .submit_headers(SubmitHeadersRequest {
            headers: vec![vec![0; 80]],
            start_height: 1,
        })
        .await
        .unwrap_err();
    assert_status(&status, Code::Internal, "enclave error (code 2)");

    let (port, _rx) =
        start_enclave_replying(response(enclave_response::Response::PublicKeys(keys())));
    let mut client = grpc(port).await;
    let status = client
        .get_last_saved_block(GetLastSavedBlockRequest {})
        .await
        .unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for GetLastSavedBlock",
    );
    let status = client
        .submit_headers(SubmitHeadersRequest {
            headers: vec![],
            start_height: 1,
        })
        .await
        .unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for SubmitHeaders",
    );
}

#[tokio::test]
async fn submit_headers_forwards_the_batch_verbatim() {
    let (port, rx) = start_enclave_replying(response(enclave_response::Response::SubmitHeaders(
        Default::default(),
    )));
    let mut client = grpc(port).await;
    let headers = vec![vec![0xAB; 80], vec![0xCD; 80]];
    client
        .submit_headers(SubmitHeadersRequest {
            headers: headers.clone(),
            start_height: 4242,
        })
        .await
        .unwrap();
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::SubmitHeaders(s)) => {
            assert_eq!(s.headers, headers);
            assert_eq!(s.start_height, 4242);
        }
        other => panic!("unexpected {other:?}"),
    }
}

// ---- AttestedPublicKey -----------------------------------------------------

#[tokio::test]
async fn attested_public_key_maps_the_whole_bundle_and_the_document() {
    let (port, rx) = start_enclave_replying(response(
        enclave_response::Response::GetAttestedPublicKey(GetAttestedPublicKeyResponse {
            public_keys: Some(keys()),
            attestation_doc: vec![0xD0; 7],
        }),
    ));
    let resp = grpc(port)
        .await
        .attested_public_key(AttestedPublicKeyRequest {
            nonce: vec![0x37; 32],
        })
        .await
        .unwrap()
        .into_inner();
    let k = keys();
    assert_eq!(resp.evm_address, k.evm_address);
    assert_eq!(resp.evm_uncompressed_pub, k.evm_uncompressed_pub);
    assert_eq!(resp.btc_compressed_pub, k.btc_compressed_pub);
    assert_eq!(resp.btc_xpub, k.btc_xpub);
    assert_eq!(resp.master_fingerprint, k.master_fingerprint);
    assert_eq!(resp.account_xpub_vanilla, k.account_xpub_vanilla);
    assert_eq!(resp.account_xpub_colored, k.account_xpub_colored);
    assert_eq!(resp.attestation_doc, vec![0xD0; 7]);
    assert_eq!(resp.chain_id, 7);
    assert_eq!(resp.bridge_contract, k.bridge_contract);
    assert_eq!(resp.rgb_asset_id, k.rgb_asset_id);
    assert_eq!(
        resp.evm_gas_tx_uncompressed_pub,
        k.evm_gas_tx_uncompressed_pub
    );
    assert_eq!(resp.evm_gas_tx_address, k.evm_gas_tx_address);
    assert_eq!(resp.ccd_ed25519_pub, k.ccd_ed25519_pub);
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::GetAttestedPublicKey(g)) => {
            assert_eq!(g.nonce, vec![0x37; 32])
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn attested_public_key_rejects_bad_nonces_before_the_enclave() {
    let (port, rx) = start_enclave_replying(error_response(1, "unreachable"));
    let mut client = grpc(port).await;
    for len in [0usize, 16, 31, 33, 64] {
        let status = client
            .attested_public_key(AttestedPublicKeyRequest {
                nonce: vec![0; len],
            })
            .await
            .unwrap_err();
        assert_status(
            &status,
            Code::InvalidArgument,
            &format!("nonce must be 32 bytes, got {len}"),
        );
    }
    assert_no_enclave_contact(&rx);
}

#[tokio::test]
async fn attested_public_key_maps_missing_bundle_errors_and_unexpected_replies() {
    let req = || AttestedPublicKeyRequest {
        nonce: vec![0x37; 32],
    };
    let (port, _rx) = start_enclave_replying(response(
        enclave_response::Response::GetAttestedPublicKey(GetAttestedPublicKeyResponse {
            public_keys: None,
            attestation_doc: vec![0xD0; 7],
        }),
    ));
    let status = grpc(port)
        .await
        .attested_public_key(req())
        .await
        .unwrap_err();
    assert_status(&status, Code::Internal, "attestation without public_keys");

    let (port, _rx) = start_enclave_replying(error_response(1, "nsm unavailable"));
    let status = grpc(port)
        .await
        .attested_public_key(req())
        .await
        .unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "enclave error (code 1): nsm unavailable",
    );

    let (port, _rx) =
        start_enclave_replying(response(enclave_response::Response::PublicKeys(keys())));
    let status = grpc(port)
        .await
        .attested_public_key(req())
        .await
        .unwrap_err();
    assert_status(
        &status,
        Code::Internal,
        "unexpected enclave response for AttestedPublicKey",
    );
}

// ---- Transport -------------------------------------------------------------

#[tokio::test]
async fn unreachable_enclave_is_unavailable() {
    let status = grpc(dead_port())
        .await
        .get_last_saved_block(GetLastSavedBlockRequest {})
        .await
        .unwrap_err();
    assert_status(&status, Code::Unavailable, "enclave connection failed");
}

#[tokio::test]
async fn enclave_hangup_or_garbage_reply_is_internal() {
    let (port, _rx) = start_enclave(Arc::new(|_| Reply::Hangup));
    let status = grpc(port)
        .await
        .get_last_saved_block(GetLastSavedBlockRequest {})
        .await
        .unwrap_err();
    assert_status(&status, Code::Internal, "enclave read failed");

    let (port, _rx) = start_enclave(Arc::new(|_| Reply::Raw(vec![0, 0, 0, 0])));
    let status = grpc(port)
        .await
        .get_last_saved_block(GetLastSavedBlockRequest {})
        .await
        .unwrap_err();
    assert_status(&status, Code::Internal, "enclave read failed");

    let (port, _rx) = start_enclave(Arc::new(|_| Reply::Raw(vec![3, 0, 0, 0, 0xff, 0xff, 0xff])));
    let status = grpc(port)
        .await
        .get_last_saved_block(GetLastSavedBlockRequest {})
        .await
        .unwrap_err();
    assert_status(&status, Code::Internal, "enclave read failed");
}

#[tokio::test]
async fn empty_enclave_reply_is_a_read_failure() {
    // A variant-less `EnclaveResponse` encodes to zero bytes, so it never
    // reaches the response match: the frame itself is refused.
    let (port, _rx) = start_enclave_replying(Default::default());
    let status = grpc(port)
        .await
        .get_last_saved_block(GetLastSavedBlockRequest {})
        .await
        .unwrap_err();
    assert_status(&status, Code::Internal, "enclave read failed");
    assert_status(&status, Code::Internal, "zero-length message");
}
