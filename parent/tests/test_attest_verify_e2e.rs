//! End-to-end test for the `attest-verify` flow.
//!
//! Starts the real enclave server and the real parent gRPC server in-process.
//! Then runs the `attest-verify` library function against them. It covers all
//! CLI behavior except argument parsing and output formatting.

use std::net::TcpListener;
use std::sync::Arc;

use tonic::transport::Server;

use attestation_verify::EvmDataSource;
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
use utexo_bridge_enclave::policy::BuildContext;
use utexo_bridge_enclave::server::{self as enclave_server, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;
use utexo_bridge_parent::attest_verify::{verify_attested_pubkey, ExpectedPolicy, VerifyMode};
use utexo_bridge_parent::client::EnclaveClient;
use utexo_bridge_parent::enclave_proto::SetEndpointsRequest;
use utexo_bridge_parent::error::ParentError;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Start a real enclave TCP server on a random port and return the port.
/// Keys come from the BIP-39 test mnemonic, so the EVM address is stable.
fn start_real_enclave() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    state
        .initialize_from_mnemonic(TEST_MNEMONIC)
        .expect("seed import");

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

async fn start_real_parent_grpc(enclave_port: u16) -> u16 {
    let grpc_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let grpc_addr = grpc_listener.local_addr().unwrap();
    let grpc_port = grpc_addr.port();
    drop(grpc_listener);

    let service = ParentAdapterService::new(
        EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")),
        std::collections::HashSet::new(),
    );

    tokio::spawn(async move {
        Server::builder()
            .add_service(ParentServiceServer::new(service))
            .serve(grpc_addr)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    grpc_port
}

#[tokio::test]
async fn e2e_attest_verify_succeeds_against_live_stack() {
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    let result = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Mock,
        // The in-process enclave is a mock build, so its posture is Development.
        ExpectedPolicy::Development,
    )
    .await
    .expect("end-to-end verification succeeds");

    // Check the structure only. The test does not hardcode key bytes.
    assert_eq!(result.response.evm_address.len(), 20);
    assert_eq!(result.response.evm_uncompressed_pub.len(), 64);
    assert_eq!(result.response.btc_compressed_pub.len(), 33);
    assert_eq!(result.response.master_fingerprint.len(), 4);
    assert!(result.response.btc_xpub.starts_with("xpub"));
    assert!(!result.response.account_xpub_vanilla.is_empty());
    assert!(!result.response.account_xpub_colored.is_empty());

    // The verified `public_key` (NSM-bound) MUST equal the wire EVM pubkey.
    assert_eq!(
        result.verified.enclave_pubkey,
        result.response.evm_uncompressed_pub
    );

    // verify_attested_pubkey checked this commitment against `user_data`.
    assert_ne!(result.bundle_commitment, [0u8; 32]);

    // The document returns the fresh 32-byte nonce.
    assert_eq!(result.verified.nonce.len(), 32);
}

#[tokio::test]
async fn e2e_attest_verify_fails_on_pcr_mismatch() {
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    // Mock enclaves report all-zero PCRs. Non-zero expected PCRs simulate
    // wrong or old operator PCRs.
    let wrong_pcrs = attestation_verify::ExpectedPcrs::new([0xAA; 48], [0u8; 48], [0u8; 48]);

    let err = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        wrong_pcrs,
        VerifyMode::Mock,
        ExpectedPolicy::Development,
    )
    .await
    .expect_err("PCR0 mismatch must fail verification");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("PCR0") || msg.contains("PCR mismatch"),
        "expected PCR mismatch error, got: {msg}"
    );
}

#[tokio::test]
async fn e2e_attest_verify_fails_on_real_path_against_mock_enclave() {
    // The mock enclave makes a raw-CBOR doc, not COSE_Sign1. The real path
    // must reject it, so --mock and the real path cannot replace each other.
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    let err = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Real, // Real path against a mock doc.
        ExpectedPolicy::Development,
    )
    .await
    .expect_err("real verifier must reject a mock document");

    let msg = format!("{err:#}");
    // The mock doc is not a 4-element COSE array, so parsing fails first.
    assert!(
        msg.contains("COSE") || msg.contains("CBOR") || msg.contains("attestation verify failed"),
        "expected COSE/CBOR parse failure, got: {msg}"
    );
}

#[tokio::test]
async fn e2e_attest_verify_fails_on_unreachable_endpoint() {
    let err = verify_attested_pubkey(
        "http://127.0.0.1:1", // nothing listening here
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Mock,
        ExpectedPolicy::Development,
    )
    .await
    .expect_err("connection to dead port must fail");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("connecting")
            || msg.contains("connect")
            || msg.contains("Connection")
            || msg.contains("transport"),
        "expected connection error, got: {msg}"
    );
}

#[tokio::test]
async fn e2e_attest_verify_fails_on_policy_mismatch() {
    // The in-process mock enclave attests the `Development` posture. A
    // verifier that expects production must reject the committed policy.
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    let err = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Mock,
        ExpectedPolicy::Production {
            allow_vanilla_psbt: false,
            signer_role: attestation_verify::SignerRole::Mint,
            evm_source: EvmDataSource::RawRpc,
            evm_checkpoint: None,
            electrum_host: "electrum.test".into(),
            evm_rpc_tls: None,
            expected_chain_id: None,
            expected_bridge_contract: None,
            expected_rgb_asset_id: None,
            funds_in_contract: [0x11; 20],
            token_contract: [0x22; 20],
            evm_min_confirmations: 12,
            gas_tx_allowed_to: [0u8; 20],
            gas_tx_max_gas_limit: 0,
            gas_tx_max_fee_per_gas: 0,
            gas_tx_max_value_wei: 0,
            gas_tx_allowed_selectors: Vec::new(),
            kms: None,
        },
    )
    .await
    .expect_err("expecting a production policy against a dev enclave must fail");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("user_data") || msg.contains("security posture") || msg.contains("policy"),
        "expected a policy/user_data mismatch error, got: {msg}"
    );
}

/// The parent sets the endpoints once, after launch. Before that, the
/// enclave attests nothing and opens no chain connection.
#[tokio::test]
async fn e2e_endpoints_are_set_once_at_launch() {
    // Fake Electrum. Nothing must connect to it.
    let electrum = TcpListener::bind("127.0.0.1:0").unwrap();
    electrum.set_nonblocking(true).unwrap();
    let electrum_port = electrum.local_addr().unwrap().port();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let enclave_port = listener.local_addr().unwrap().port();
    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    state
        .initialize_from_mnemonic(TEST_MNEMONIC)
        .expect("seed import");
    let ctx = Arc::new(ServerContext::awaiting_launch(
        state,
        BridgeConfig::from_env(),
        std::sync::Mutex::new(HeaderChain::new(
            Network::Regtest,
            checkpoint_for(Network::Regtest),
        )),
        BuildContext::current(),
    ));
    let served = ctx.clone();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            enclave_server::handle_connection(s, &served);
        }
    });
    let grpc = format!(
        "http://127.0.0.1:{}",
        start_real_parent_grpc(enclave_port).await
    );
    let verify = || {
        verify_attested_pubkey(
            &grpc,
            attestation_verify::ExpectedPcrs::zero(),
            VerifyMode::Mock,
            ExpectedPolicy::Development,
        )
    };
    let client = EnclaveClient::new(&format!("127.0.0.1:{enclave_port}"));
    let set = |host: &str| SetEndpointsRequest {
        electrum_url: format!("tcp://{host}:{electrum_port}"),
        ..Default::default()
    };

    assert!(verify().await.is_err(), "attested before the set");
    assert!(!client.health().unwrap().endpoints_set);

    client.set_endpoints(set("localhost")).unwrap();
    assert!(client.health().unwrap().endpoints_set);
    verify().await.expect("attests after the set");

    let err = client.set_endpoints(set("other.test")).unwrap_err();
    assert!(
        matches!(&err, ParentError::EnclaveError { message, .. } if message.contains("already set")),
        "{err:?}"
    );
    assert_eq!(ctx.launch().unwrap().endpoints.electrum_host, "localhost");
    assert!(electrum.accept().is_err(), "a chain connection opened");
}
