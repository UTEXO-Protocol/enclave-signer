//! Public-signet builds preserve production mint KMS and burn cloning custody.
#![cfg(all(feature = "rgb-validation", not(feature = "spv")))]

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
        chain_id: 42161,
        bridge_contract: [1; 20],
        funds_in_contract: [2; 20],
        token_contract: [3; 20],
        rgb_asset_id: "test-asset".into(),
        endpoints_sha256: Some(utexo_bridge_enclave::config::chain_endpoints_sha256(
            &endpoints(),
        )),
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
        kms_seed_id: "signet-mint".into(),
        ..request
    };
    request
}

#[cfg(feature = "burn-signer")]
fn initialize(port: u16) -> InitializeKeyResponse {
    match send(
        port,
        Request::InitializeKey(InitializeKeyRequest {
            cloning_secret: "burn-donor-cloning-secret-with-entropy".into(),
            ..Default::default()
        }),
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

#[test]
#[cfg(feature = "burn-signer")]
fn indexer_only_generates_distinct_keys_and_refuses_reinitialization() {
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
fn indexer_only_refuses_imports_without_installing_keys() {
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
    #[cfg(feature = "burn-signer")]
    initialize(port);
}

#[test]
#[cfg(feature = "burn-signer")]
fn indexer_only_is_ready_without_headers_only_after_keys_and_endpoints() {
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

#[test]
#[cfg(feature = "burn-signer")]
fn indexer_only_burn_refuses_kms_fields() {
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

#[test]
fn indexer_only_cloning_entrypoints_match_production_custody() {
    let port = start();
    for (request, _burn_error) in [
        (
            Request::InitiateCloning(InitiateCloningRequest::default()),
            "cloning_secret is required",
        ),
        (
            Request::GetClone(GetCloneRequest::default()),
            "cluster_public_key must be 20 bytes",
        ),
        (
            Request::SetClone(SetCloneRequest::default()),
            "donor_pubkey must be 32 bytes",
        ),
    ] {
        let Response::Error(error) = send(port, request) else {
            panic!("an invalid clone request must fail before NSM attestation");
        };
        #[cfg(feature = "burn-signer")]
        assert!(error.message.contains(_burn_error), "{error:?}");
        #[cfg(feature = "mint-signer")]
        assert!(
            error
                .message
                .contains("cloning is disabled with KMS persistence"),
            "{error:?}"
        );
        assert!(!health(port).key_loaded);
    }
}

#[test]
fn indexer_only_chain_endpoint_pin_refuses_substitution_without_installing_launch() {
    let port = start();
    let mutations: [fn(&mut SetEndpointsRequest); 6] = [
        |r| r.electrum_url = "ssl://attacker.test:50002".into(),
        |r| r.electrum_url = "tcp://electrum.test:50002".into(),
        |r| r.electrum_url = "ssl://electrum.test:50003".into(),
        |r| r.evm_rpc_host = "attacker.test".into(),
        |r| {
            r.evm_rpc_ca_der =
                hex::decode(include_str!("fixtures/evm_rpc_tls/ca_b.der.hex").trim()).unwrap()
        },
        |r| r.evm_rpc_tls_port = 8443,
    ];
    for mutate in mutations {
        let mut request = endpoints();
        mutate(&mut request);
        let Response::Error(error) = send(port, Request::SetEndpoints(request)) else {
            panic!("an unapproved chain endpoint must be refused");
        };
        assert!(error.message.contains("ENDPOINTS_SHA256"), "{error:?}");
        assert!(!health(port).endpoints_set);
    }
    assert!(matches!(
        send(port, Request::SetEndpoints(endpoints())),
        Response::SetEndpoints(_)
    ));
    assert!(health(port).endpoints_set);
}

#[test]
#[cfg(feature = "burn-signer")]
fn indexer_only_burn_installs_a_runtime_donor_secret() {
    let port = start();
    let keys = initialize(port);
    let Response::Error(error) = send(
        port,
        Request::GetClone(GetCloneRequest {
            cluster_public_key: keys.evm_address,
            encryption_pubkey: vec![1; 32],
            cloning_digest: vec![0; 32],
            ..Default::default()
        }),
    ) else {
        panic!("wrong clone HMAC must fail before attestation");
    };
    assert_eq!(error.code, 5, "{error:?}");
    assert!(error.message.contains("digest mismatch"), "{error:?}");
    assert!(health(port).key_loaded);
}

#[test]
#[cfg(feature = "mint-signer")]
fn indexer_only_mint_requires_valid_kms_pins_and_accepts_an_address_pin() {
    let kms = Endpoints::parse(&endpoints()).unwrap().kms.unwrap();
    assert_eq!(kms.seed_id, "signet-mint");
    assert!(kms.expected_evm_address.is_none());
    let port = start();
    let malformed: [fn(&mut SetEndpointsRequest); 7] = [
        |r| r.kms_key_arn.clear(),
        |r| r.kms_region.clear(),
        |r| r.kms_seed_id.clear(),
        |r| r.kms_key_arn = "alias/not-a-key-arn".into(),
        |r| r.kms_region = "eu-west-2".into(),
        |r| r.kms_seed_id = "../other".into(),
        |r| r.kms_expected_evm_address = "not-an-address".into(),
    ];
    for mutate in malformed {
        let mut request = endpoints();
        mutate(&mut request);
        assert!(Endpoints::parse(&request).is_err());
        assert!(matches!(
            send(port, Request::SetEndpoints(request)),
            Response::Error(_)
        ));
        assert!(!health(port).endpoints_set);
    }
    let mut pinned = endpoints();
    pinned.kms_expected_evm_address = "ab".repeat(20);
    assert_eq!(
        utexo_bridge_enclave::config::chain_endpoints_sha256(&pinned),
        utexo_bridge_enclave::config::chain_endpoints_sha256(&endpoints()),
    );
    assert_eq!(
        Endpoints::parse(&pinned)
            .unwrap()
            .kms
            .unwrap()
            .expected_evm_address,
        Some([0xab; 20])
    );
    assert!(matches!(
        send(port, Request::SetEndpoints(pinned)),
        Response::SetEndpoints(_)
    ));
    assert!(!health(port).key_loaded);
}

// This real PersistentSeed path uses its local broker transport, with no NSM
// or AWS request: the broker denies credentials before either can be used.
#[test]
#[cfg(all(
    feature = "mint-signer",
    not(all(feature = "vsock", target_os = "linux"))
))]
fn indexer_only_mint_reaches_persistent_seed_and_never_falls_back_to_entropy() {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let listener = TcpListener::bind((
        "127.0.0.1",
        utexo_bridge_enclave::seed_persistence::BROKER_LOCAL_PORT,
    ))
    .unwrap();
    listener.set_nonblocking(true).unwrap();
    let broker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "PersistentSeed never contacted its broker"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("broker accept: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut request = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request).unwrap(),
            serde_json::json!({"op":"credentials"})
        );
        let response = br#"{"error":"access_denied"}"#;
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(response).unwrap();
    });
    let port = start();
    assert!(matches!(
        send(
            port,
            Request::InitializeKey(InitializeKeyRequest::default())
        ),
        Response::Error(_)
    ));
    assert!(!health(port).key_loaded);
    assert!(matches!(
        send(port, Request::SetEndpoints(endpoints())),
        Response::SetEndpoints(_)
    ));
    let Response::Error(error) = send(
        port,
        Request::InitializeKey(InitializeKeyRequest::default()),
    ) else {
        panic!("KMS failure must not fall back to fresh keys");
    };
    broker.join().unwrap();
    assert!(
        error
            .message
            .contains("seed custody seed broker: access_denied"),
        "{error:?}"
    );
    assert!(!health(port).key_loaded);
    let Response::Error(error) = send(
        port,
        Request::InitializeKey(InitializeKeyRequest {
            cloning_secret: "not-supported-by-mint".into(),
            ..Default::default()
        }),
    ) else {
        panic!("mint must reject a cloning secret");
    };
    assert!(
        error.message.contains("cloning_secret is not supported"),
        "{error:?}"
    );
}

#[test]
fn indexer_only_release_policy_never_claims_production_spv() {
    let mut build = BuildContext::current();
    build.debug_or_test = false;
    let policy = SecurityPolicy::resolve(&build, &config(), EvmDataSource::Disabled, None, "");
    assert!(matches!(
        policy,
        SecurityPolicy::Development {
            reason: DevReason::IndexerTrusted
        }
    ));
    assert_eq!(policy.attested(), AttestedPolicy::Development);
    policy.assert_valid_at_boot(&build).unwrap();
    policy.assert_valid_for_build(&build).unwrap();
}

#[test]
fn indexer_only_refuses_other_networks_and_missing_pins_even_in_debug() {
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
    let mut cfg = config();
    cfg.chain_id = 0;
    invalid.push(cfg);
    let mut cfg = config();
    cfg.btc_relay_mode = BtcRelayMode::Required;
    invalid.push(cfg);
    let mut cfg = config();
    cfg.rgb_asset_id.clear();
    invalid.push(cfg);
    let mut cfg = config();
    cfg.token_contract = [0; 20];
    invalid.push(cfg);
    let mut cfg = config();
    cfg.spv_min_confirmations = 0;
    invalid.push(cfg);
    for pin in [None, Some([0; 32])] {
        let mut cfg = config();
        cfg.endpoints_sha256 = pin;
        invalid.push(cfg);
    }
    for cfg in invalid {
        assert!(cfg.validate_indexer_only().is_err());
        let build = BuildContext::current();
        let policy = SecurityPolicy::resolve(&build, &cfg, EvmDataSource::Disabled, None, "");
        assert!(policy.assert_valid_at_boot(&build).is_err());
        assert!(policy.assert_valid_for_build(&build).is_err());
    }
    for chain in [1, 10, 137, 8453, 42161, 31337, 11155111, 421614, 123456] {
        let mut cfg = config();
        cfg.chain_id = chain;
        cfg.validate_indexer_only().unwrap();
    }
}
