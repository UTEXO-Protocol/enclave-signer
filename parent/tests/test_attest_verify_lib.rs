//! The verifier library against a mock enclave whose attestation disagrees
//! with the wire bundle in each of the ways the checks exist for.

mod common;

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::Arc;

use common::{msg, response, start_enclave, Reply};
use tonic::transport::Server;
use utexo_bridge_parent::attest_verify::{
    canonical_bundle, verify_attested_pubkey, ExpectedPolicy, VerifyMode,
};
use utexo_bridge_parent::enclave_proto::{
    enclave_request, enclave_response, GetAttestedPublicKeyResponse, PublicKeysResponse,
};
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_proto::AttestedPublicKeyResponse;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

fn keys() -> PublicKeysResponse {
    PublicKeysResponse {
        evm_address: vec![0xAA; 20],
        btc_compressed_pub: vec![0xBB; 33],
        btc_xpub: "xpub".into(),
        master_fingerprint: vec![0xDD; 4],
        account_xpub_vanilla: "v".into(),
        account_xpub_colored: "c".into(),
        evm_uncompressed_pub: vec![0xEE; 64],
        chain_id: 0,
        bridge_contract: vec![0; 20],
        rgb_asset_id: String::new(),
        evm_gas_tx_uncompressed_pub: vec![0xFF; 64],
        evm_gas_tx_address: vec![0xFA; 20],
        ccd_ed25519_pub: vec![0x99; 32],
    }
}

/// The commitment the verifier expects for the Development posture.
fn development_commitment(k: &PublicKeysResponse) -> [u8; 32] {
    use sha2::Digest;
    let wire = AttestedPublicKeyResponse {
        evm_address: k.evm_address.clone(),
        evm_uncompressed_pub: k.evm_uncompressed_pub.clone(),
        btc_compressed_pub: k.btc_compressed_pub.clone(),
        btc_xpub: k.btc_xpub.clone(),
        master_fingerprint: k.master_fingerprint.clone(),
        account_xpub_vanilla: k.account_xpub_vanilla.clone(),
        account_xpub_colored: k.account_xpub_colored.clone(),
        attestation_doc: Vec::new(),
        chain_id: k.chain_id,
        bridge_contract: k.bridge_contract.clone(),
        rgb_asset_id: k.rgb_asset_id.clone(),
        evm_gas_tx_uncompressed_pub: k.evm_gas_tx_uncompressed_pub.clone(),
        evm_gas_tx_address: k.evm_gas_tx_address.clone(),
        ccd_ed25519_pub: k.ccd_ed25519_pub.clone(),
    };
    let mut preimage = canonical_bundle(&wire);
    preimage.extend_from_slice(&attestation_verify::AttestedPolicy::Development.to_bytes());
    sha2::Sha256::digest(&preimage).into()
}

/// A mock enclave whose attestation document is built by `doc(nonce)`.
async fn stack(doc: impl Fn(&[u8; 32]) -> Vec<u8> + Send + Sync + 'static) -> String {
    let (enclave_port, _rx) = start_enclave(Arc::new(move |req| match req.request {
        Some(enclave_request::Request::GetAttestedPublicKey(g)) => {
            let nonce: [u8; 32] = g.nonce.as_slice().try_into().unwrap();
            msg(response(enclave_response::Response::GetAttestedPublicKey(
                GetAttestedPublicKeyResponse {
                    public_keys: Some(keys()),
                    attestation_doc: doc(&nonce),
                },
            )))
        }
        _ => Reply::Hangup,
    }));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let service = ParentAdapterService::new(
        EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")),
        HashSet::new(),
    );
    tokio::spawn(async move {
        Server::builder()
            .add_service(ParentServiceServer::new(service))
            .serve(addr)
            .await
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    format!("http://{addr}")
}

async fn verify(endpoint: &str) -> anyhow::Result<()> {
    verify_attested_pubkey(
        endpoint,
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Mock,
        ExpectedPolicy::Development,
    )
    .await
    .map(|_| ())
}

#[tokio::test]
async fn a_consistent_mock_document_verifies() {
    let endpoint = stack(|nonce| {
        let k = keys();
        attestation_verify::build_mock_document(
            nonce,
            Some(&k.evm_uncompressed_pub),
            Some(&development_commitment(&k)),
        )
        .unwrap()
    })
    .await;
    verify(&endpoint)
        .await
        .expect("consistent document verifies");
}

#[tokio::test]
async fn a_document_binding_a_different_key_is_rejected() {
    let endpoint = stack(|nonce| {
        let k = keys();
        attestation_verify::build_mock_document(
            nonce,
            Some(&[0x12; 64]),
            Some(&development_commitment(&k)),
        )
        .unwrap()
    })
    .await;
    let msg = format!("{:#}", verify(&endpoint).await.unwrap_err());
    assert!(
        msg.contains("does not match wire evm_uncompressed_pub"),
        "{msg}"
    );
}

#[tokio::test]
async fn a_document_without_user_data_is_rejected() {
    let endpoint = stack(|nonce| {
        let k = keys();
        attestation_verify::build_mock_document(nonce, Some(&k.evm_uncompressed_pub), None).unwrap()
    })
    .await;
    let msg = format!("{:#}", verify(&endpoint).await.unwrap_err());
    assert!(msg.contains("attestation has no user_data field"), "{msg}");
}

#[tokio::test]
async fn a_document_committing_to_other_keys_is_rejected() {
    let endpoint = stack(|nonce| {
        let k = keys();
        attestation_verify::build_mock_document(
            nonce,
            Some(&k.evm_uncompressed_pub),
            Some(&[0x77; 32]),
        )
        .unwrap()
    })
    .await;
    let msg = format!("{:#}", verify(&endpoint).await.unwrap_err());
    assert!(
        msg.contains("does not match sha256(canonical_bundle || policy)"),
        "{msg}"
    );
}

#[tokio::test]
async fn a_document_for_another_nonce_is_rejected() {
    let endpoint = stack(|_| {
        let k = keys();
        attestation_verify::build_mock_document(
            &[0u8; 32],
            Some(&k.evm_uncompressed_pub),
            Some(&development_commitment(&k)),
        )
        .unwrap()
    })
    .await;
    let msg = format!("{:#}", verify(&endpoint).await.unwrap_err());
    assert!(msg.contains("mock attestation verify failed"), "{msg}");
}

#[tokio::test]
async fn an_rpc_failure_is_reported_as_such() {
    let (enclave_port, _rx) = start_enclave(Arc::new(|_| Reply::Hangup));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let service = ParentAdapterService::new(
        EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")),
        HashSet::new(),
    );
    tokio::spawn(async move {
        Server::builder()
            .add_service(ParentServiceServer::new(service))
            .serve(addr)
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let msg = format!("{:#}", verify(&format!("http://{addr}")).await.unwrap_err());
    assert!(msg.contains("AttestedPublicKey RPC failed"), "{msg}");
}
