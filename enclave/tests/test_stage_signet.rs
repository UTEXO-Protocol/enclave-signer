//! Both real-attestation stage roles preserve their production key lifecycle.
#![cfg(feature = "stage-signet")]

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use utexo_bridge_enclave::bootstrap;
use utexo_bridge_enclave::config::{BridgeConfig, BtcRelayMode, Endpoints};
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::networks::rgb::spv::Network;
use utexo_bridge_enclave::policy::{
    AttestedPolicy, BitcoinNetwork, BuildContext, DevReason, EvmDataSource, SecurityPolicy,
};
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::*;
use utexo_bridge_enclave::server::{self, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;

fn config() -> BridgeConfig {
    BridgeConfig {
        bitcoin_network: BitcoinNetwork::Signet,
        btc_relay_mode: BtcRelayMode::None,
        chain_id: 11155111,
        bridge_contract: [1; 20],
        funds_in_contract: [2; 20],
        token_contract: [3; 20],
        rgb_asset_id: "stage-test-asset".into(),
        ..BridgeConfig::default()
    }
}

fn start() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let ctx = Arc::new(ServerContext::awaiting_launch(
        EnclaveState::new(bitcoin::Network::Signet),
        config(),
        bootstrap::build_header_chain(Network::Signet),
        BuildContext::current(),
    ));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            server::handle_connection(stream.unwrap(), &ctx);
        }
    });
    port
}

fn send(port: u16, request: Request) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    framing::write_message(
        &mut stream,
        &EnclaveRequest {
            request: Some(request),
        },
    )
    .unwrap();
    let response: EnclaveResponse = framing::read_message(&mut stream).unwrap();
    response.response.unwrap()
}

fn endpoints() -> SetEndpointsRequest {
    let request = SetEndpointsRequest {
        electrum_url: "ssl://electrum.test:50002".into(),
        evm_rpc_host: "rpc.test".into(),
        evm_rpc_ca_der: hex::decode(include_str!("fixtures/evm_rpc_tls/ca_a.der.hex").trim())
            .unwrap(),
        evm_rpc_tls_port: 443,
        ..Default::default()
    };
    #[cfg(feature = "mint-signer")]
    let request = SetEndpointsRequest {
        kms_key_arn: "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
            .into(),
        kms_region: "eu-west-1".into(),
        kms_seed_id: "stage".into(),
        ..request
    };
    request
}

#[cfg(feature = "burn-signer")]
fn initialize(port: u16) -> InitializeKeyResponse {
    match send(
        port,
        Request::InitializeKey(InitializeKeyRequest::default()),
    ) {
        Response::InitializeKey(r) => r,
        other => panic!("expected internally generated keys, got {other:?}"),
    }
}

fn health(port: u16) -> HealthResponse {
    match send(port, Request::Health(HealthRequest {})) {
        Response::Health(r) => r,
        other => panic!("expected Health, got {other:?}"),
    }
}

#[cfg(feature = "burn-signer")]
#[test]
fn stage_signet_generates_distinct_keys_and_refuses_reinitialization() {
    let first = start();
    let a = initialize(first);
    let b = initialize(start());
    assert_ne!(a.evm_address, b.evm_address);
    assert_ne!(a.btc_compressed_pub, b.btc_compressed_pub);
    assert_eq!(a.evm_address.len(), 20);
    assert!(a.btc_xpub.starts_with("tpub"));
    assert!(matches!(
        send(
            first,
            Request::InitializeKey(InitializeKeyRequest::default())
        ),
        Response::Error(_)
    ));
    match send(first, Request::GetPublicKey(GetPublicKeyRequest {})) {
        Response::PublicKeys(r) => assert_eq!(r.evm_address, a.evm_address),
        other => panic!("expected stable public keys, got {other:?}"),
    }
}

#[test]
fn stage_signet_refuses_imports_without_installing_keys() {
    let port = start();
    for request in [
        Request::InitializeKey(InitializeKeyRequest {
            seed: vec![42; 64],
            ..Default::default()
        }),
        Request::InitializeKey(InitializeKeyRequest {
            mnemonic: "abandon ".repeat(24),
            ..Default::default()
        }),
    ] {
        assert!(matches!(send(port, request), Response::Error(_)));
        assert!(!health(port).key_loaded);
    }
}

#[test]
fn stage_signet_cloning_routing_matches_the_production_role() {
    let response = send(
        start(),
        Request::InitiateCloning(InitiateCloningRequest::default()),
    );
    let Response::Error(error) = response else {
        panic!("expected cloning request validation to fail before attestation");
    };
    #[cfg(feature = "burn-signer")]
    assert!(
        error.message.contains("cloning_secret is required"),
        "{error:?}"
    );
    #[cfg(feature = "mint-signer")]
    assert!(
        error
            .message
            .contains("cloning is disabled with KMS persistence"),
        "{error:?}"
    );
}

#[cfg(feature = "burn-signer")]
#[test]
fn stage_signet_is_ready_without_headers_only_after_keys_and_endpoints() {
    let port = start();
    assert!(!health(port).ready);
    initialize(port);
    assert!(!health(port).ready);
    assert!(matches!(
        send(port, Request::SetEndpoints(endpoints())),
        Response::SetEndpoints(_)
    ));
    let h = health(port);
    assert!(h.ready && h.key_loaded && h.endpoints_set);
    assert_eq!(
        (
            h.spv_tip_height,
            h.spv_tip_time,
            h.spv_tip_age_secs,
            h.spv_max_tip_age_secs
        ),
        (0, 0, 0, 0)
    );
    for request in [
        Request::SubmitHeaders(SubmitHeadersRequest::default()),
        Request::GetLastSavedBlock(GetLastSavedBlockRequest {}),
    ] {
        assert!(matches!(send(port, request), Response::Error(_)));
    }
    assert!(health(port).ready);
}

#[cfg(feature = "burn-signer")]
#[test]
fn stage_signet_burn_refuses_kms_fields() {
    assert!(Endpoints::parse(&endpoints()).unwrap().kms.is_none());
    for field in 0..4 {
        let mut request = endpoints();
        match field {
            0 => request.kms_key_arn = "arn:aws:kms:eu-west-1:123456789012:key/stage".into(),
            1 => request.kms_region = "eu-west-1".into(),
            2 => request.kms_seed_id = "stage".into(),
            _ => request.kms_expected_evm_address = "ab".repeat(20),
        }
        assert!(Endpoints::parse(&request).is_err());
    }
}

#[cfg(feature = "mint-signer")]
#[test]
fn stage_signet_mint_requires_and_accepts_production_kms_pins() {
    let kms = Endpoints::parse(&endpoints()).unwrap().kms.unwrap();
    assert_eq!(kms.region, "eu-west-1");
    assert_eq!(kms.seed_id, "stage");
    for field in 0..3 {
        let mut request = endpoints();
        match field {
            0 => request.kms_key_arn.clear(),
            1 => request.kms_region.clear(),
            _ => request.kms_seed_id.clear(),
        }
        assert!(Endpoints::parse(&request).is_err());
    }
    let mut pinned = endpoints();
    pinned.kms_expected_evm_address = "ab".repeat(20);
    assert_eq!(
        Endpoints::parse(&pinned)
            .unwrap()
            .kms
            .unwrap()
            .expected_evm_address,
        Some([0xab; 20])
    );
}

#[test]
fn stage_signet_release_policy_never_claims_production_spv() {
    let mut build = BuildContext::current();
    build.debug_or_test = false;
    let policy = SecurityPolicy::resolve(&build, &config(), EvmDataSource::Disabled, None, "");
    assert!(matches!(
        policy,
        SecurityPolicy::Development {
            reason: DevReason::StageSignet
        }
    ));
    assert_eq!(policy.attested(), AttestedPolicy::Development);
    policy.assert_valid_at_boot(&build).unwrap();
    policy.assert_valid_for_build(&build).unwrap();
}

#[test]
fn stage_signet_refuses_other_networks_and_missing_pins_even_in_debug() {
    let mut invalid = Vec::new();
    for network in [
        BitcoinNetwork::Mainnet,
        BitcoinNetwork::Testnet3,
        BitcoinNetwork::Testnet4,
        BitcoinNetwork::SignetCustom,
        BitcoinNetwork::Regtest,
    ] {
        let mut cfg = config();
        cfg.bitcoin_network = network;
        invalid.push(cfg);
    }
    for chain in [0, 1, 42161] {
        let mut cfg = config();
        cfg.chain_id = chain;
        invalid.push(cfg);
    }
    let mut cfg = config();
    cfg.btc_relay_mode = BtcRelayMode::Required;
    invalid.push(cfg);
    let mut cfg = config();
    cfg.rgb_asset_id.clear();
    invalid.push(cfg);
    let mut cfg = config();
    cfg.token_contract = [0; 20];
    invalid.push(cfg);
    for cfg in invalid {
        assert!(cfg.validate_stage_signet().is_err());
        let build = BuildContext::current();
        let policy = SecurityPolicy::resolve(&build, &cfg, EvmDataSource::Disabled, None, "");
        assert!(policy.assert_valid_at_boot(&build).is_err());
        assert!(policy.assert_valid_for_build(&build).is_err());
    }
}
