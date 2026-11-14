use super::*;
use crate::proto::SetEndpointsRequest;

#[test]
fn endpoints_sha256_env_does_not_affect_bridge_configuration() {
    const CHILD: &str = "UTEXO_TEST_ENDPOINTS_ENV_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let config = BridgeConfig::from_env();
        config.validate_indexer_only().unwrap();
        assert_eq!(config.chain_id, 42161);
        assert_eq!(config.bridge_contract, [1; 20]);
        assert_eq!(config.funds_in_contract, [2; 20]);
        assert_eq!(config.token_contract, [3; 20]);
        assert_eq!(config.rgb_asset_id, "test-asset");
        return;
    }

    // An `ENDPOINTS_SHA256` env value must not pin endpoints or stop
    // startup, even when it is malformed. A child process isolates the env.
    for value in [String::new(), "ab".repeat(32), "not-a-digest".into()] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::tests::endpoints_sha256_env_does_not_affect_bridge_configuration",
                "--nocapture",
            ])
            .env_clear()
            .env(CHILD, "1")
            .env("ENDPOINTS_SHA256", value)
            .env("BITCOIN_NETWORK", "signet")
            .env("BTC_RELAY_MODE", "none")
            .env("EVM_CHAIN_ID", "42161")
            .env("EVM_PROXY_CONTRACT_ADDRESS", "01".repeat(20))
            .env("FUNDS_IN_CONTRACT", "02".repeat(20))
            .env("TOKEN_CONTRACT", "03".repeat(20))
            .env("RGB_ASSET_ID", "test-asset")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
}

/// Every name the SPV chain runs on attests the network a verifier
/// expects for that same name (testnet4 attested as mainnet).
#[test]
fn attested_network_matches_the_spv_network() {
    use crate::networks::rgb::spv::Network;
    for name in [
        "bitcoin",
        "mainnet",
        "signet",
        "signetcustom",
        "testnet",
        "testnet3",
        "testnet4",
        "regtest",
    ] {
        let spv = Network::from_env_str(name).unwrap();
        assert_eq!(
            Some(spv.attested()),
            BitcoinNetwork::from_env_str(name),
            "{name}"
        );
    }
}

#[test]
fn finality_tag_env_defaults_only_when_absent() {
    assert_eq!(
        parse_evm_finality_tag(Err(std::env::VarError::NotPresent)).unwrap(),
        EvmFinalityTag::Finalized
    );
    for (value, tag) in [
        ("latest", EvmFinalityTag::Latest),
        ("safe", EvmFinalityTag::Safe),
        ("finalized", EvmFinalityTag::Finalized),
    ] {
        assert_eq!(parse_evm_finality_tag(Ok(value.into())).unwrap(), tag);
    }
    for value in ["", "finilized", "pending", "Safe", " safe "] {
        assert!(parse_evm_finality_tag(Ok(value.into())).is_err());
    }
    assert!(parse_evm_finality_tag(Err(std::env::VarError::NotUnicode(
        std::ffi::OsString::new()
    )))
    .is_err());
}

#[test]
fn parse_eth_address_with_prefix() {
    let a = parse_eth_address("0x0102030405060708090a0b0c0d0e0f1011121314").unwrap();
    assert_eq!(
        a,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
    );
}

#[test]
fn parse_eth_address_without_prefix() {
    let a = parse_eth_address("0102030405060708090a0b0c0d0e0f1011121314").unwrap();
    assert_eq!(a[0], 1);
    assert_eq!(a[19], 20);
}

#[test]
fn btc_relay_mode_defaults_to_required() {
    assert_eq!(BtcRelayMode::from_env_value(None), BtcRelayMode::Required);
    assert_eq!(
        BtcRelayMode::from_env_value(Some("".into())),
        BtcRelayMode::Required
    );
    assert_eq!(
        BtcRelayMode::from_env_value(Some("required".into())),
        BtcRelayMode::Required
    );
}

#[test]
fn btc_relay_mode_none_must_be_spelled_out() {
    assert_eq!(
        BtcRelayMode::from_env_value(Some("none".into())),
        BtcRelayMode::None
    );
    assert_eq!(
        BtcRelayMode::from_env_value(Some(" None ".into())),
        BtcRelayMode::None
    );
}

/// A typo must fail closed, never relax the relay check.
#[test]
fn btc_relay_mode_unknown_value_stays_required() {
    for v in ["off", "false", "0", "disabled", "nope"] {
        assert_eq!(
            BtcRelayMode::from_env_value(Some(v.into())),
            BtcRelayMode::Required,
            "{v}"
        );
    }
}

#[test]
fn spv_min_confirmations_defaults_to_three_when_unset() {
    assert_eq!(parse_spv_min_confirmations(None), Ok(3));
    assert_eq!(parse_spv_min_confirmations(Some(" ")), Ok(3));
}

#[test]
fn spv_min_confirmations_accepts_a_positive_number() {
    assert_eq!(parse_spv_min_confirmations(Some("1")), Ok(1));
    assert_eq!(parse_spv_min_confirmations(Some(" 12 ")), Ok(12));
}

#[test]
fn spv_min_confirmations_rejects_zero_and_garbage() {
    for v in ["0", "-1", "six", "6.5", "99999999999"] {
        let err = parse_spv_min_confirmations(Some(v)).unwrap_err();
        assert!(err.contains("at least 1"), "{v}: {err}");
    }
}

/// `MAX_CONSIGNMENT_BYTES` may lower the limit, never raise it past the
/// size the memory model is sized for.
#[test]
fn the_consignment_limit_cannot_be_raised_above_the_default() {
    let max = DEFAULT_MAX_CONSIGNMENT_BYTES;
    for unset in [None, Some(""), Some("0"), Some("ten"), Some("-1")] {
        assert_eq!(parse_consignment_limit(unset), Ok(max), "{unset:?}");
    }
    assert_eq!(parse_consignment_limit(Some("1048576")), Ok(1024 * 1024));
    assert_eq!(parse_consignment_limit(Some(&max.to_string())), Ok(max));
    for above in [max + 1, 12 * 1024 * 1024, 1 << 30] {
        let err = parse_consignment_limit(Some(&above.to_string())).unwrap_err();
        assert!(err.contains("memory model"), "{above}: {err}");
    }
}

#[test]
fn mint_witness_sat_defaults_to_1500_when_unset() {
    assert_eq!(parse_mint_witness_sat(None), Ok(1_500));
    assert_eq!(parse_mint_witness_sat(Some(" ")), Ok(1_500));
}

#[test]
fn mint_witness_sat_accepts_values_in_bounds() {
    assert_eq!(parse_mint_witness_sat(Some("546")), Ok(546));
    assert_eq!(parse_mint_witness_sat(Some(" 1500 ")), Ok(1_500));
    assert_eq!(parse_mint_witness_sat(Some("10000")), Ok(10_000));
}

#[test]
fn mint_witness_sat_rejects_dust_values_above_the_cap_and_garbage() {
    for v in [
        "0",
        "545",
        "10001",
        "-1",
        "1.5",
        "abc",
        "99999999999999999999",
    ] {
        let err = parse_mint_witness_sat(Some(v)).unwrap_err();
        assert!(err.contains("from 546 to 10000"), "{v}: {err}");
    }
}

#[test]
fn parse_eth_address_rejects_wrong_length() {
    assert!(parse_eth_address("0xabcd").is_err());
}

#[test]
fn parse_eth_address_rejects_non_hex() {
    assert!(parse_eth_address("0xzz02030405060708090a0b0c0d0e0f1011121314").is_err());
}

#[test]
fn unconfigured_when_all_unset() {
    let c = BridgeConfig {
        chain_id: 0,
        bridge_contract: [0u8; 20],
        rgb_asset_id: String::new(),
        ..Default::default()
    };
    assert!(!c.is_configured());
    assert!(!c.is_partially_configured());
}

#[test]
fn configured_only_when_all_three_set() {
    let c = BridgeConfig {
        chain_id: 1,
        bridge_contract: [1u8; 20],
        rgb_asset_id: "rgb:asset".into(),
        gas_tx_allowed_to: None,
        ..Default::default()
    };
    assert!(c.is_configured());
    assert!(!c.is_partially_configured());
}

#[test]
fn partial_config_is_not_configured() {
    // Contract zero: an OR check accepts a request for the zero address.
    let c = BridgeConfig {
        chain_id: 1,
        bridge_contract: [0u8; 20],
        rgb_asset_id: "rgb:asset".into(),
        ..Default::default()
    };
    assert!(!c.is_configured());
    assert!(c.is_partially_configured());
}

#[test]
fn zero_chain_id_is_not_configured() {
    let c = BridgeConfig {
        chain_id: 0,
        bridge_contract: [1u8; 20],
        rgb_asset_id: "rgb:asset".into(),
        gas_tx_allowed_to: None,
        ..Default::default()
    };
    assert!(!c.is_configured());
    assert!(c.is_partially_configured());
}

const CA_HEX: &str = include_str!("../../tests/fixtures/evm_rpc_tls/ca_a.der.hex");

/// A valid set for this build: only the values it uses.
fn valid() -> SetEndpointsRequest {
    let mut req = SetEndpointsRequest::default();
    if cfg!(feature = "rgb-validation") {
        req.electrum_url = "ssl://Electrum.test:50002".into();
    }
    if cfg!(feature = "rgb-validation") {
        req.evm_rpc_host = "RPC.Test".into();
        req.evm_rpc_ca_der = hex::decode(CA_HEX.trim()).unwrap();
        req.evm_rpc_tls_port = 443;
    }
    if cfg!(feature = "kms-persistence") {
        req.kms_key_arn = KEY_ARN.into();
        req.kms_region = "eu-west-1".into();
        req.kms_seed_id = "seed-1".into();
    }
    req
}

const KEY_ARN: &str = "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef";

fn parse_with(
    edit: impl FnOnce(&mut SetEndpointsRequest),
) -> std::result::Result<Endpoints, String> {
    let mut req = valid();
    edit(&mut req);
    Endpoints::parse(&req, &[], true)
}

#[cfg(feature = "kms-persistence")]
#[test]
fn the_account_list_parses_ids_and_refuses_a_malformed_entry() {
    assert_eq!(parse_kms_allowed_accounts(None), Ok(vec![]));
    assert_eq!(parse_kms_allowed_accounts(Some(" , ")), Ok(vec![]));
    assert_eq!(
        parse_kms_allowed_accounts(Some(" 111111111111 , 123456789012 ")),
        Ok(vec!["111111111111".to_string(), "123456789012".to_string()])
    );
    for bad in ["12345", "12345678901a", "123456789012,abc"] {
        assert!(parse_kms_allowed_accounts(Some(bad)).is_err(), "{bad}");
    }
}

#[test]
fn valid_endpoints_parse_and_hosts_are_lowercased() {
    let e = parse_with(|_| {}).unwrap();
    if cfg!(feature = "rgb-validation") {
        assert_eq!(e.electrum_host, "electrum.test");
        assert_eq!(e.electrum_port, 50002);
    }
    assert_eq!(e.evm_rpc_tls.is_some(), cfg!(feature = "rgb-validation"));
    if let Some(tls) = e.evm_rpc_tls {
        assert_eq!(tls.host, "rpc.test");
        assert_eq!(tls.tls_port, 443);
    }
}

#[cfg(feature = "rgb-validation")]
#[test]
fn electrum_url_must_be_ssl_or_tcp_host_and_port() {
    assert!(parse_with(|r| r.electrum_url = "tcp://electrum.test:50001".into()).is_ok());
    let e = parse_with(|r| r.electrum_url = "ssl://electrum.test:50002/".into()).unwrap();
    assert_eq!(e.electrum_url, "ssl://electrum.test:50002");
    for url in [
        "",
        "ftp://electrum.test:50001",
        "electrum.test:50001",
        "ssl://electrum.test",
        "ssl://electrum.test:50002/x",
        "ssl://electrum.test:0",
        "ssl://electrum.test:65536",
        "ssl://127.0.0.1:50002",
        "ssl://electrum_test:50002",
        "ssl://electrum test:50002",
    ] {
        assert!(
            parse_with(|r| r.electrum_url = url.into()).is_err(),
            "{url:?}"
        );
    }
}

/// A release image refuses a plaintext indexer. The host relays the
/// bytes, so over `tcp://` or `http://` it can forge every answer.
#[cfg(feature = "rgb-validation")]
#[test]
fn a_release_build_refuses_a_plaintext_indexer() {
    for url in [
        "tcp://electrum.test:50001",
        "http://esplora.test:3000",
        "http://esplora.test",
    ] {
        let err = parse_indexer_url(url, false).unwrap_err();
        assert!(err.contains("plaintext"), "{url:?}: {err}");
        assert!(
            parse_indexer_url(url, true).is_ok(),
            "{url:?} in a dev build"
        );
    }
    assert_eq!(
        parse_indexer_url("ssl://electrum.test:50002", false).unwrap(),
        ("electrum.test".to_string(), 50002)
    );
    assert_eq!(
        parse_indexer_url("https://esplora.test", false).unwrap(),
        ("esplora.test".to_string(), 443)
    );
    assert!(parse_indexer_url("ftp://electrum.test:1", false)
        .unwrap_err()
        .contains("is not ssl://"));
}

/// The test build is a dev build, so the launch path takes plaintext.
#[cfg(feature = "rgb-validation")]
#[test]
fn a_test_build_allows_a_plaintext_indexer() {
    assert!(plaintext_indexer_allowed());
}

#[cfg(feature = "rgb-validation")]
#[test]
fn esplora_url_takes_a_default_port() {
    // The EVM RPC forwarder takes another loopback port than Esplora's 443.
    let e = parse_with(|r| {
        r.electrum_url = "https://esplora.test".into();
        r.evm_rpc_tls_port = 8443;
    })
    .unwrap();
    assert_eq!(
        (e.electrum_host.as_str(), e.electrum_port),
        ("esplora.test", 443)
    );
    let e = parse_with(|r| r.electrum_url = "http://esplora.test:3000/".into()).unwrap();
    assert_eq!(
        (e.electrum_host.as_str(), e.electrum_port),
        ("esplora.test", 3000)
    );
    for url in [
        "https://esplora.test/api",
        "https://esplora.test:0",
        "https://",
    ] {
        assert!(
            parse_with(|r| r.electrum_url = url.into()).is_err(),
            "{url:?}"
        );
    }
}

#[cfg(feature = "rgb-validation")]
#[test]
fn evm_rpc_host_must_be_a_host_name() {
    // A DNS name up to 253 bytes total, no label over 63.
    let long = [
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(61),
    ]
    .join(".");
    assert_eq!(long.len(), 253);
    for host in ["rpc.test", "a", "rpc-1.Example.com", &long] {
        assert!(
            parse_with(|r| r.evm_rpc_host = host.into()).is_ok(),
            "{host}"
        );
    }
    let too_long_label = "a".repeat(64);
    for host in [
        "",
        ".rpc.test",
        "rpc.test.",
        "rpc..test",
        "-rpc.test",
        "https://rpc.test",
        "rpc.test/v2",
        "rpc.test:443",
        "rpc test",
        "rpc.test\n",
        "rpc_test",
        "127.0.0.1",
        &too_long_label,
    ] {
        assert!(
            parse_with(|r| r.evm_rpc_host = host.into()).is_err(),
            "{host:?}"
        );
    }
}

#[cfg(feature = "rgb-validation")]
#[test]
fn evm_rpc_ca_must_be_a_valid_certificate() {
    let der = hex::decode(CA_HEX.trim()).unwrap();
    let truncated = der[..der.len() - 10].to_vec();
    for ca in [Vec::new(), b"not der".to_vec(), truncated] {
        assert!(
            parse_with(|r| r.evm_rpc_ca_der = ca.clone()).is_err(),
            "{ca:?}"
        );
    }
    let err =
        parse_with(|r| r.evm_rpc_ca_der = vec![0x30; MAX_EVM_RPC_CA_DER_BYTES + 1]).unwrap_err();
    assert!(err.contains("the limit is"), "{err}");
}

/// Each `SetEndpoints` string over the limit is refused before any parse.
/// A key ARN of colons would split into one part per colon: the
/// measurement shows the refusal stays within the request bound.
#[test]
fn a_set_endpoints_string_over_the_limit_is_refused_before_the_parse() {
    use crate::memory::peak;

    type Set = fn(&mut SetEndpointsRequest, String);
    let fields: [(&str, Set); 6] = [
        ("electrum_url", |r, v| r.electrum_url = v),
        ("evm_rpc_host", |r, v| r.evm_rpc_host = v),
        ("kms_key_arn", |r, v| r.kms_key_arn = v),
        ("kms_region", |r, v| r.kms_region = v),
        ("kms_seed_id", |r, v| r.kms_seed_id = v),
        ("kms_expected_evm_address", |r, v| {
            r.kms_expected_evm_address = v
        }),
    ];
    for (name, set) in fields {
        let err = parse_with(|r| set(r, ":".repeat(MAX_ENDPOINT_STRING_BYTES + 1))).unwrap_err();
        assert!(
            err.starts_with(name) && err.contains("the limit is"),
            "{err}"
        );
    }

    let (arn, result, peak) = peak::measure(
        || ":".repeat(4 * 1024 * 1024),
        |arn| parse_with(|r| r.kms_key_arn = arn.clone()),
    );
    assert!(result.unwrap_err().contains("the limit is"));
    peak::assert_within_request_bound("SetEndpoints with a 4 MiB key ARN", arn.len(), peak);
}

#[cfg(feature = "rgb-validation")]
#[test]
fn evm_rpc_tls_port_must_be_a_free_port() {
    for port in [0, 65536, 50002] {
        assert!(parse_with(|r| r.evm_rpc_tls_port = port).is_err(), "{port}");
    }
}

#[cfg(not(feature = "rgb-validation"))]
#[test]
fn unsupported_rpc_paths_are_refused_without_echoing_them() {
    Endpoints::parse(&valid(), &[], true).unwrap();
    for path in [
        "/",
        "/v2/private-api-key",
        "https://other.test/private-api-key",
    ] {
        let err = parse_with(|r| r.evm_rpc_path = path.into()).unwrap_err();
        assert_eq!(err, "evm_rpc_path is set, but this build does not use it");
    }
}

#[cfg(feature = "rgb-validation")]
#[test]
fn rpc_path_is_parsed_and_debug_redacted() {
    let root = parse_with(|_| {}).unwrap();
    assert_eq!(root.evm_rpc_tls.unwrap().path, "/");
    let e = parse_with(|r| r.evm_rpc_path = "/v3/fixture-secret".into()).unwrap();
    assert_eq!(e.evm_rpc_tls.as_ref().unwrap().path, "/v3/fixture-secret");
    assert!(!format!("{e:?}").contains("fixture-secret"));
    assert!(format!("{e:?}").contains("[REDACTED]"));
}

#[cfg(feature = "rgb-validation")]
#[test]
fn rpc_path_rejects_authority_query_fragment_and_normalization() {
    for bad in [
        "https://other.test/key",
        "//other.test/key",
        "key",
        "/x?key=y",
        "/x#key",
        "/x\\key",
        "/x\r\nheader",
        "/x/../key",
        "/./key",
        "/%2e%2e/key",
        "/clé",
        "/key with space",
    ] {
        let err = parse_with(|r| r.evm_rpc_path = bad.into()).unwrap_err();
        assert!(err.contains("evm_rpc_path"));
        assert!(!err.contains(bad));
    }
    assert!(parse_with(|r| r.evm_rpc_path = format!("/{}", "a".repeat(2048))).is_err());
}

#[test]
fn a_value_the_build_does_not_use_is_refused() {
    if !cfg!(feature = "rgb-validation") {
        assert!(parse_with(|r| r.electrum_url = "ssl://electrum.test:50002".into()).is_err());
    }
    if !cfg!(feature = "rgb-validation") {
        assert!(parse_with(|r| r.evm_rpc_host = "rpc.test".into()).is_err());
        assert!(parse_with(|r| r.evm_rpc_ca_der = vec![1]).is_err());
        assert!(parse_with(|r| r.evm_rpc_tls_port = 443).is_err());
    }
}

#[cfg(feature = "kms-persistence")]
#[test]
fn kms_values_are_checked_at_launch() {
    let edits: [fn(&mut SetEndpointsRequest); 8] = [
        |r| r.kms_key_arn = "arn:aws:kms:eu-west-1:123456789012:alias/seed".into(),
        |r| r.kms_key_arn = KEY_ARN.replace("eu-west-1", "eu-west-2"),
        |r| {
            r.kms_region = "cn-north-1".into();
            r.kms_key_arn = KEY_ARN.replace("eu-west-1", "cn-north-1");
        },
        |r| r.kms_seed_id = "seed 1".into(),
        |r| r.kms_expected_evm_address = "00".repeat(19),
        |r| r.kms_expected_evm_address = "zz".repeat(20),
        |r| {
            r.kms_region.clear();
            r.kms_seed_id.clear();
        },
        |r| r.electrum_url = "ssl://kms.eu-west-1.amazonaws.com:50002".into(),
    ];
    for edit in edits {
        assert!(parse_with(edit).is_err());
    }
    if cfg!(feature = "allow-seed-import") {
        let e = parse_with(|r| {
            r.kms_key_arn.clear();
            r.kms_region.clear();
            r.kms_seed_id.clear();
        })
        .unwrap();
        assert_eq!(e.kms, None);
    }
    let e = parse_with(|r| r.kms_expected_evm_address = format!("0x{}", "ab".repeat(20))).unwrap();
    assert_eq!(
        e.kms,
        Some(crate::policy::KmsPin {
            key_arn: KEY_ARN.into(),
            region: "eu-west-1".into(),
            seed_id: "seed-1".into(),
            expected_evm_address: Some([0xab; 20]),
        })
    );
    assert_eq!(
        parse_with(|_| {})
            .unwrap()
            .kms
            .unwrap()
            .expected_evm_address,
        None
    );
}

#[cfg(not(feature = "kms-persistence"))]
#[test]
fn kms_values_are_refused_without_kms_persistence() {
    let edits: [fn(&mut SetEndpointsRequest); 4] = [
        |r| r.kms_key_arn = KEY_ARN.into(),
        |r| r.kms_region = "eu-west-1".into(),
        |r| r.kms_seed_id = "seed-1".into(),
        |r| r.kms_expected_evm_address = "ab".repeat(20),
    ];
    for edit in edits {
        assert!(parse_with(edit).is_err());
    }
}

#[test]
fn an_unset_funds_in_contract_is_the_bridge_contract() {
    assert_eq!(parse_funds_in_contract(None, [7; 20]), Ok([7; 20]));
}

#[test]
fn a_set_funds_in_contract_is_used() {
    let addr = format!("0x{}", "ab".repeat(20));
    assert_eq!(
        parse_funds_in_contract(Some(&addr), [7; 20]),
        Ok([0xab; 20])
    );
}

#[test]
fn a_malformed_funds_in_contract_is_refused_not_replaced() {
    for bad in ["", "0x1234", "not-an-address"] {
        assert!(
            parse_funds_in_contract(Some(bad), [7; 20]).is_err(),
            "{bad}"
        );
    }
}
