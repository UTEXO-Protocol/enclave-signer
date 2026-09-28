//! The parent gRPC server in front of the real in-process enclave: what the
//! listener actually sees for each RPC when nothing is mocked.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::Arc;

use tonic::transport::{Channel, Server};
use tonic::Code;
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
use utexo_bridge_enclave::server::{self as enclave_server, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;
use utexo_bridge_parent::grpc_proto::parent_service_client::ParentServiceClient;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_proto::{
    sign_request, source_proof, GetLastSavedBlockRequest, InitializeRequest, RgbSource,
    SignRequest, SourceProof, SubmitHeadersRequest,
};
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::{enriched, signer};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const EVM_NET: u32 = 84;

/// A real enclave server on a random port, keys already initialised.
fn start_real_enclave(initialized: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    if initialized {
        state
            .initialize_from_mnemonic(TEST_MNEMONIC)
            .expect("seed import");
    }
    let header_chain = std::sync::Mutex::new(HeaderChain::new(
        Network::Regtest,
        checkpoint_for(Network::Regtest),
    ));
    let ctx = Arc::new(ServerContext::new(
        state,
        BridgeConfig::from_env(),
        header_chain,
    ));

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => enclave_server::handle_connection(s, &ctx),
                Err(_) => continue,
            }
        }
    });
    port
}

async fn stack(initialized: bool) -> ParentServiceClient<Channel> {
    let enclave_port = start_real_enclave(initialized);
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

fn pubkey_req(dt: signer::DataType) -> signer::PublicKeyRequest {
    signer::PublicKeyRequest {
        network_id: 0,
        data_type: dt as i32,
    }
}

#[tokio::test]
async fn public_key_returns_each_key_family_from_the_real_enclave() {
    let mut client = stack(true).await;
    let btc = client
        .public_key(pubkey_req(signer::DataType::Transaction))
        .await
        .unwrap()
        .into_inner()
        .public_key;
    assert_eq!(btc.len(), 33);
    assert!(btc[0] == 0x02 || btc[0] == 0x03, "compressed secp256k1 key");

    let unspendable = client
        .public_key(pubkey_req(signer::DataType::Unspendable))
        .await
        .unwrap()
        .into_inner()
        .public_key;
    assert_eq!(unspendable, btc, "UNSPENDABLE reads the same BTC key");

    let gas = client
        .public_key(pubkey_req(signer::DataType::EvmGasTx))
        .await
        .unwrap()
        .into_inner()
        .public_key;
    assert_eq!(gas.len(), 64, "uncompressed X||Y without the 0x04 prefix");

    let ccd = client
        .public_key(pubkey_req(signer::DataType::CcdGovernance))
        .await
        .unwrap()
        .into_inner()
        .public_key;
    assert_eq!(ccd.len(), 32, "Ed25519 governance key");

    // Deterministic: the same mnemonic yields the same keys on a second stack.
    let mut other = stack(true).await;
    let btc_again = other
        .public_key(pubkey_req(signer::DataType::Transaction))
        .await
        .unwrap()
        .into_inner()
        .public_key;
    assert_eq!(btc_again, btc);
}

#[tokio::test]
async fn public_key_before_initialization_is_an_enclave_error() {
    let mut client = stack(false).await;
    let status = client
        .public_key(pubkey_req(signer::DataType::Transaction))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Internal, "{}", status.message());
    assert!(
        status.message().starts_with("enclave error (code "),
        "{}",
        status.message()
    );
}

#[tokio::test]
async fn initialize_twice_is_refused_by_the_real_enclave() {
    let mut client = stack(true).await;
    let status = client
        .initialize(InitializeRequest {
            cloning_secret: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Internal, "{}", status.message());
    assert!(
        status.message().starts_with("enclave error (code "),
        "{}",
        status.message()
    );
}

#[tokio::test]
async fn initialize_from_a_mnemonic_then_read_the_same_key_back() {
    let mut client = stack(false).await;
    let init = client
        .initialize(InitializeRequest {
            cloning_secret: TEST_MNEMONIC.into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(init.public_key.len(), 33);
    assert!(init.attestation.is_empty());

    let btc = client
        .public_key(pubkey_req(signer::DataType::Transaction))
        .await
        .unwrap()
        .into_inner()
        .public_key;
    assert_eq!(btc, init.public_key);

    // A second initialisation is refused even through the parent.
    let status = client
        .initialize(InitializeRequest {
            cloning_secret: TEST_MNEMONIC.into(),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Internal, "{}", status.message());
}

#[tokio::test]
async fn initialize_with_garbage_words_is_refused() {
    let mut client = stack(false).await;
    let status = client
        .initialize(InitializeRequest {
            cloning_secret: "this is not a bip39 phrase and must be refused".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Internal, "{}", status.message());
    // Still uninitialised afterwards.
    let status = client
        .public_key(pubkey_req(signer::DataType::Transaction))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Internal, "{}", status.message());
}

#[tokio::test]
async fn get_last_saved_block_reports_the_compiled_in_checkpoint() {
    let mut client = stack(true).await;
    let resp = client
        .get_last_saved_block(GetLastSavedBlockRequest {})
        .await
        .unwrap()
        .into_inner();
    let cp = checkpoint_for(Network::Regtest);
    assert_eq!(resp.block_height, cp.height);
    assert_eq!(resp.block_hash.len(), 32);
}

#[tokio::test]
async fn submit_headers_that_do_not_connect_is_failed_precondition() {
    let mut client = stack(true).await;
    let cp = checkpoint_for(Network::Regtest);
    let status = client
        .submit_headers(SubmitHeadersRequest {
            headers: vec![vec![0u8; 80], vec![0u8; 80]],
            start_height: cp.height + 1,
        })
        .await
        .unwrap_err();
    // SPV rejections carry enclave code 3, which the parent maps verbatim.
    assert_eq!(
        status.code(),
        Code::FailedPrecondition,
        "{}",
        status.message()
    );
    assert!(!status.message().is_empty());

    // The chain is unchanged.
    let resp = client
        .get_last_saved_block(GetLastSavedBlockRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.block_height, cp.height);
}

#[tokio::test]
async fn submit_headers_with_a_wrong_start_height_is_failed_precondition() {
    let mut client = stack(true).await;
    let cp = checkpoint_for(Network::Regtest);
    let status = client
        .submit_headers(SubmitHeadersRequest {
            headers: vec![vec![0u8; 80]],
            start_height: cp.height + 2,
        })
        .await
        .unwrap_err();
    assert_eq!(
        status.code(),
        Code::FailedPrecondition,
        "{}",
        status.message()
    );
}

#[tokio::test]
async fn submit_headers_with_a_malformed_header_is_failed_precondition() {
    let mut client = stack(true).await;
    let cp = checkpoint_for(Network::Regtest);
    let status = client
        .submit_headers(SubmitHeadersRequest {
            headers: vec![vec![0u8; 79]],
            start_height: cp.height + 1,
        })
        .await
        .unwrap_err();
    assert_eq!(
        status.code(),
        Code::FailedPrecondition,
        "{}",
        status.message()
    );
}

#[tokio::test]
async fn btc_utxo_sign_with_a_garbage_psbt_fails_closed() {
    let mut client = stack(true).await;
    let status = client
        .sign(SignRequest {
            common: Some(signer::SignRequest {
                src_network_id: 0,
                dst_network_id: 0,
                data_type: signer::DataType::BtcUtxo as i32,
            }),
            source: None,
            data: Some(sign_request::Data::BtcData(enriched::EnrichedBtcPayload {
                psbt_bytes: vec![0x70, 0x73, 0x62, 0x74, 0xFF],
            })),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(status.code(), Code::Internal | Code::FailedPrecondition),
        "{}",
        status.message()
    );
}

#[tokio::test]
async fn gas_tx_sign_with_a_garbage_preimage_fails_closed() {
    let mut client = stack(true).await;
    let status = client
        .sign(SignRequest {
            common: Some(signer::SignRequest {
                src_network_id: 0,
                dst_network_id: EVM_NET,
                data_type: signer::DataType::EvmGasTx as i32,
            }),
            source: None,
            data: Some(sign_request::Data::EvmData(enriched::EnrichedEvmPayload {
                call_data: vec![0; 32],
                nonce: 0,
                deadline: 0,
                chain_id: 1,
                proxy_contract: vec![],
                calldata_amount: 0,
                calldata_commission: 0,
                unsigned_tx: vec![0x02, 0xFF, 0xFF],
                lz_release: None,
            })),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(status.code(), Code::Internal | Code::FailedPrecondition),
        "{}",
        status.message()
    );
}

#[tokio::test]
async fn rgb_to_evm_sign_with_a_bogus_consignment_fails_closed() {
    let mut client = stack(true).await;
    let status = client
        .sign(SignRequest {
            common: Some(signer::SignRequest {
                src_network_id: 0,
                dst_network_id: EVM_NET,
                data_type: signer::DataType::Transaction as i32,
            }),
            source: Some(SourceProof {
                source_network_id: 0,
                token: String::new(),
                amount: 100,
                commission: 0,
                recipient: String::new(),
                finalized: true,
                chain: Some(source_proof::Chain::Rgb(RgbSource {
                    consignment: vec![0xC0; 64],
                    consignment_hash: vec![0xC1; 32],
                    rgb_amount: 100,
                    rgb_asset_id: "rgb:asset".into(),
                    merkle_proofs: vec![],
                    mint_ancestors: vec![],
                })),
            }),
            data: Some(sign_request::Data::EvmData(enriched::EnrichedEvmPayload {
                call_data: vec![0xAB; 132],
                nonce: 1,
                deadline: u64::MAX,
                chain_id: 1,
                proxy_contract: vec![0x02; 20],
                calldata_amount: 100,
                calldata_commission: 0,
                unsigned_tx: vec![],
                lz_release: None,
            })),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(status.code(), Code::Internal | Code::FailedPrecondition),
        "{}",
        status.message()
    );
}

#[tokio::test]
async fn attested_public_key_from_the_real_enclave_verifies_as_mock() {
    let mut client = stack(true).await;
    let nonce = [0x5Au8; 32];
    let resp = client
        .attested_public_key(utexo_bridge_parent::grpc_proto::AttestedPublicKeyRequest {
            nonce: nonce.to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    let verified = attestation_verify::verify_mock_attestation(
        &resp.attestation_doc,
        &attestation_verify::ExpectedPcrs::zero(),
        Some(&nonce),
    )
    .expect("mock document verifies");
    assert_eq!(verified.enclave_pubkey, resp.evm_uncompressed_pub);
    assert_eq!(verified.nonce, nonce.to_vec());

    // The commitment is over bundle || Development posture, as the verifier
    // library reconstructs it.
    use sha2::Digest;
    let mut preimage = utexo_bridge_parent::attest_verify::canonical_bundle(&resp);
    preimage.extend_from_slice(&attestation_verify::AttestedPolicy::Development.to_bytes());
    let expected: [u8; 32] = sha2::Sha256::digest(&preimage).into();
    assert_eq!(verified.user_data.as_deref(), Some(expected.as_slice()));

    // A replayed nonce check: verifying with a different nonce fails.
    assert!(attestation_verify::verify_mock_attestation(
        &resp.attestation_doc,
        &attestation_verify::ExpectedPcrs::zero(),
        Some(&[0u8; 32]),
    )
    .is_err());
}
