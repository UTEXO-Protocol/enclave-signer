//! True end-to-end test for the `attest-verify` flow.
//!
//! Spins up the **real** enclave server (in-process, via the public API
//! exposed from the enclave crate), the **real** parent gRPC server
//! pointing at it, and drives the **real** `attest-verify` library
//! function against the full stack. No hand-built mock attestations,
//! no inline-duplicated check logic — this exercises everything the
//! deployed CLI binary does, except for argument parsing and stdout
//! formatting.

use std::net::TcpListener;
use std::sync::Arc;

use tonic::transport::Server;

use attestation_verify::EvmDataSource;
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
use utexo_bridge_enclave::server::{self as enclave_server, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;
use utexo_bridge_parent::attest_verify::{verify_attested_pubkey, ExpectedPolicy, VerifyMode};
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Start a real enclave TCP server on a random port. Initializes keys
/// from the canonical BIP-39 test mnemonic so the EVM address is
/// deterministic across test runs. Returns the port.
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
        // The in-process enclave is a debug/mock build => Development posture.
        ExpectedPolicy::Development,
    )
    .await
    .expect("end-to-end verification succeeds");

    // EVM address from BIP-39 test vector "abandon abandon ... about" with
    // the project's BIP-44 derivation. We don't hardcode the bytes —
    // we just assert the structure is correct.
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

    // The bundle commitment is non-zero and matches what verify_attested_pubkey
    // checked against the NSM-bound `user_data`.
    assert_ne!(result.bundle_commitment, [0u8; 32]);

    // Nonce was a fresh 32 bytes and was echoed back in the doc.
    assert_eq!(result.verified.nonce.len(), 32);
}

#[tokio::test]
async fn e2e_attest_verify_fails_on_pcr_mismatch() {
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    // Mock enclaves report all-zero PCRs; pass non-zero expected PCRs to
    // simulate "operator passed wrong/stale PCRs to the verifier".
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
    // Mock enclave produces a raw-CBOR doc, not a COSE_Sign1. The real
    // verify path expects COSE_Sign1, so it must reject the doc — proving
    // that --mock and the real path are not interchangeable, which is the
    // entire safety property of the mode flag.
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    let err = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Real, // <- real path against mock doc
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
    // The in-process enclave is a debug/mock build, so it attests the
    // `Development` posture. A verifier that expects a *production* enclave must
    // reject it: the committed policy differs, so the user_data commitment no
    // longer matches. This is the C-01 property — the security posture is one
    // attested value the verifier checks, not something inferred out of band.
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    let err = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Mock,
        ExpectedPolicy::Production {
            allow_vanilla_psbt: false,
            evm_source: EvmDataSource::RawRpc,
            evm_checkpoint: None,
            gas_tx_allowed_to: [0u8; 20],
            gas_tx_max_gas_limit: 0,
            gas_tx_max_fee_per_gas: 0,
            gas_tx_max_value_wei: 0,
            gas_tx_allowed_selectors: Vec::new(),
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
