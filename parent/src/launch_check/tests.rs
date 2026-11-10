use super::*;
use attestation_verify::test_util::{signed_document, verify_policy_with_root};

const PCRS: ExpectedPcrs = ExpectedPcrs {
    pcr0: [1; 48],
    pcr1: [2; 48],
    pcr2: [3; 48],
};
const NONCE: [u8; 32] = [7; 32];
const ARN: &str = "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef";

fn image_env() -> String {
    serde_json::json!([
        "PATH=/usr/bin",
        "EVM_CHAIN_ID=42161",
        "EVM_PROXY_CONTRACT_ADDRESS=0xC985c12bbCECe96A13A72A62FD75d8aB9381ef5A",
        "RGB_ASSET_ID=rgb:asset",
        "FUNDS_IN_CONTRACT=0x6711f1a319B37847fa0234181C34D883774c4951",
        "TOKEN_CONTRACT=0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
        "SPV_MIN_CONFIRMATIONS=6",
        "GAS_TX_ALLOWED_TO=0x6711f1a319B37847fa0234181C34D883774c4951",
        "GAS_TX_MAX_GAS_LIMIT=300000",
        "GAS_TX_MAX_FEE_PER_GAS=1000",
        "GAS_TX_MAX_VALUE_WEI=5",
        "GAS_TX_ALLOWED_SELECTORS=0xdeadbeef,0x01020304",
        "BTC_MAX_TOTAL_SATS=1000000",
    ])
    .to_string()
}

fn endpoints() -> SetEndpointsRequest {
    SetEndpointsRequest {
        electrum_url: "ssl://electrum.example:50002".into(),
        evm_rpc_host: "rpc.example".into(),
        evm_rpc_ca_der: vec![0xca; 40],
        evm_rpc_tls_port: 443,
        kms_key_arn: ARN.into(),
        kms_region: "eu-west-1".into(),
        kms_seed_id: "seed-1".into(),
        kms_expected_evm_address: format!("0x{}", "ab".repeat(20)),
        evm_rpc_path: String::new(),
    }
}

fn expected() -> AttestedPolicy {
    expected_policy(SignerRole::Combined, &image_env(), &endpoints()).unwrap()
}

#[test]
fn image_finality_tag_defaults_only_when_absent() {
    assert!(matches!(
        expected(),
        AttestedPolicy::Production {
            evm_finality_tag: EvmFinalityTag::Finalized,
            ..
        }
    ));
    for value in ["safe", "finalized", "", "SAFE", " safe", "safe ", "pending"] {
        let mut env: Vec<String> = serde_json::from_str(&image_env()).unwrap();
        env.push(format!("EVM_FINALITY_TAG={value}"));
        let result = expected_policy(
            SignerRole::Combined,
            &serde_json::to_string(&env).unwrap(),
            &endpoints(),
        );
        match value.parse::<EvmFinalityTag>() {
            Ok(expected_tag) => assert!(matches!(result.unwrap(), AttestedPolicy::Production {
                evm_finality_tag, ..
            } if evm_finality_tag == expected_tag)),
            Err(_) => assert!(result.unwrap_err().to_string().contains("EVM_FINALITY_TAG")),
        }
    }
}

#[test]
fn image_with_the_latest_tag_is_refused() {
    let mut env: Vec<String> = serde_json::from_str(&image_env()).unwrap();
    env.push("EVM_FINALITY_TAG=latest".into());
    let err = expected_policy(
        SignerRole::Combined,
        &serde_json::to_string(&env).unwrap(),
        &endpoints(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("EVM_FINALITY_TAG=latest"), "{err}");
}

#[test]
fn mint_image_depth_is_taken_from_the_image() {
    let env = image_env().replace("SPV_MIN_CONFIRMATIONS=6", "SPV_MIN_CONFIRMATIONS=3");
    let policy = expected_policy(SignerRole::Mint, &env, &endpoints()).unwrap();
    assert!(matches!(
        policy,
        AttestedPolicy::Production {
            spv_min_confirmations: 3,
            ..
        }
    ));
}

/// The policy-only answer of an enclave that attests `policy`, signed
/// under a test root, and the root DER.
fn response(policy: &[u8]) -> (GetAttestedPublicKeyResponse, Vec<u8>) {
    let commitment = policy_commitment(policy);
    let (doc, root) = signed_document(&PCRS, &NONCE, None, &commitment, 1_577_880_000_000, None);
    let answer = GetAttestedPublicKeyResponse {
        public_keys: None,
        attestation_doc: doc,
        attested_policy: policy.to_vec(),
    };
    (answer, root)
}

/// The policy-only answer of a mock enclave that attests `policy`.
fn mock_response(policy: &[u8]) -> GetAttestedPublicKeyResponse {
    let commitment = policy_commitment(policy);
    GetAttestedPublicKeyResponse {
        public_keys: None,
        attestation_doc: attestation_verify::build_mock_document_with_pcrs(
            &NONCE,
            None,
            Some(&commitment),
            &PCRS,
        )
        .unwrap(),
        attested_policy: policy.to_vec(),
    }
}

/// The launch check in Real mode, with `root` as the trust anchor.
fn check_with(
    (response, root): (GetAttestedPublicKeyResponse, Vec<u8>),
    nonce: [u8; 32],
    pcrs: &ExpectedPcrs,
) -> Result<AttestedPolicy> {
    check_launch_with(response, VerifyMode::Real, &expected(), |doc| {
        Ok(verify_policy_with_root(doc, pcrs, &nonce, &root)?)
    })
}

fn check(answer: (GetAttestedPublicKeyResponse, Vec<u8>)) -> Result<AttestedPolicy> {
    check_with(answer, NONCE, &PCRS)
}

/// The enclave attests `expected()` with one edit. The check must fail
/// with `message`.
fn assert_mismatch(edit: impl FnOnce(&mut AttestedPolicy), message: &str) {
    let mut policy = attested();
    edit(&mut policy);
    let err = check(response(&policy.to_bytes())).unwrap_err();
    assert_eq!(err.to_string(), message);
}

macro_rules! set {
    ($field:ident, $value:expr) => {
        |p: &mut AttestedPolicy| match p {
            AttestedPolicy::Production { $field, .. } => *$field = $value,
            AttestedPolicy::Development => unreachable!(),
        }
    };
}

/// What a matching enclave attests: `expected()` with the PCR3 of its
/// mock document as the clone-peer PCR3.
fn attested() -> AttestedPolicy {
    let mut policy = expected();
    set!(clone_peer_pcr3, Some(attestation_verify::MOCK_PCR3))(&mut policy);
    policy
}

fn tls(edit: impl FnOnce(&mut EvmRpcTlsPin)) -> impl FnOnce(&mut AttestedPolicy) {
    |p| match p {
        AttestedPolicy::Production {
            evm_rpc_tls: Some(pin),
            ..
        } => edit(pin),
        _ => unreachable!(),
    }
}

fn kms(edit: impl FnOnce(&mut KmsPin)) -> impl FnOnce(&mut AttestedPolicy) {
    |p| match p {
        AttestedPolicy::Production { kms: Some(pin), .. } => edit(pin),
        _ => unreachable!(),
    }
}

#[test]
fn a_matching_enclave_passes() {
    let policy = check(response(&attested().to_bytes())).unwrap();
    assert_eq!(policy.to_bytes(), attested().to_bytes());
}

#[test]
fn allow_vanilla_psbt_mismatch_aborts() {
    assert_mismatch(
        set!(allow_vanilla_psbt, false),
        "allow_vanilla_psbt mismatch: expected true, attested false",
    );
}

#[test]
fn signer_role_mismatch_aborts() {
    assert_mismatch(
        set!(signer_role, SignerRole::Mint),
        "signer_role mismatch: expected Combined, attested Mint",
    );
}

#[test]
fn attestation_mismatch_aborts() {
    assert_mismatch(
        set!(attestation, AttestationMode::Mock),
        "attestation mismatch: expected Real, attested Mock",
    );
}

#[test]
fn evm_source_mismatch_aborts() {
    assert_mismatch(
        set!(evm_source, EvmDataSource::RawRpc),
        "evm_source mismatch: expected PinnedTlsRpc, attested RawRpc",
    );
}

#[test]
fn evm_finality_tag_mismatch_aborts() {
    for tag in [EvmFinalityTag::Latest, EvmFinalityTag::Safe] {
        assert_mismatch(
            set!(evm_finality_tag, tag),
            &format!("evm_finality_tag mismatch: expected finalized, attested {tag}"),
        );
    }
}

#[test]
fn an_unknown_btc_source_aborts_at_decode() {
    // SpvVerified is the only value. Byte 6 is btc_source.
    let mut bytes = attested().to_bytes();
    assert_eq!(bytes[6], BtcDataSource::SpvVerified as u8);
    bytes[6] = 2;
    let err = check(response(&bytes)).unwrap_err();
    assert!(err.to_string().contains("unknown BTC data source"), "{err}");
}

#[test]
fn chain_id_mismatch_aborts() {
    assert_mismatch(
        set!(chain_id, 1),
        "chain_id mismatch: expected 42161, attested 1",
    );
}

#[test]
fn bitcoin_network_mismatch_aborts() {
    assert_mismatch(
        set!(bitcoin_network, BitcoinNetwork::Signet),
        "bitcoin_network mismatch: expected Mainnet, attested Signet",
    );
}

#[test]
fn the_image_bitcoin_network_is_expected() {
    let env = image_env().replace("\"PATH=/usr/bin\"", "\"BITCOIN_NETWORK=signet\"");
    let policy = expected_policy(SignerRole::Combined, &env, &endpoints()).unwrap();
    assert!(matches!(
        policy,
        AttestedPolicy::Production {
            bitcoin_network: BitcoinNetwork::Signet,
            ..
        }
    ));
    let env = image_env().replace("\"PATH=/usr/bin\"", "\"BITCOIN_NETWORK=testnet4\"");
    let policy = expected_policy(SignerRole::Combined, &env, &endpoints()).unwrap();
    assert!(matches!(
        policy,
        AttestedPolicy::Production {
            bitcoin_network: BitcoinNetwork::Testnet4,
            ..
        }
    ));
    let env = image_env().replace("\"PATH=/usr/bin\"", "\"BITCOIN_NETWORK=testnet9\"");
    let err = expected_policy(SignerRole::Combined, &env, &endpoints()).unwrap_err();
    assert!(err.to_string().contains("not a known network"), "{err}");
}

#[test]
fn bridge_contract_mismatch_aborts() {
    assert_mismatch(
        set!(bridge_contract, [0x11; 20]),
        &format!(
            "bridge_contract mismatch: expected 0xc985c12bbcece96a13a72a62fd75d8ab9381ef5a, \
             attested 0x{}",
            "11".repeat(20)
        ),
    );
}

#[test]
fn rgb_asset_id_mismatch_aborts() {
    assert_mismatch(
        set!(rgb_asset_id, "rgb:other".into()),
        "rgb_asset_id mismatch: expected rgb:asset, attested rgb:other",
    );
}

#[test]
fn funds_in_contract_mismatch_aborts() {
    assert_mismatch(
        set!(funds_in_contract, [0x22; 20]),
        &format!(
            "funds_in_contract mismatch: expected 0x6711f1a319b37847fa0234181c34d883774c4951, \
             attested 0x{}",
            "22".repeat(20)
        ),
    );
}

#[test]
fn spv_min_confirmations_mismatch_aborts() {
    assert_mismatch(
        set!(spv_min_confirmations, 3),
        "spv_min_confirmations mismatch: expected 6, attested 3",
    );
}

#[test]
fn electrum_host_mismatch_aborts() {
    assert_mismatch(
        set!(electrum_host, "evil.example".into()),
        "electrum_host mismatch: expected electrum.example, attested evil.example",
    );
}

#[test]
fn evm_rpc_tls_host_mismatch_aborts() {
    assert_mismatch(
        tls(|pin| pin.host = "evil.example".into()),
        "evm_rpc_tls.host mismatch: expected rpc.example, attested evil.example",
    );
}

#[test]
fn evm_rpc_tls_ca_sha256_mismatch_aborts() {
    assert_mismatch(
        tls(|pin| pin.ca_sha256 = [0x33; 32]),
        &format!(
            "evm_rpc_tls.ca_sha256 mismatch: expected 0x{}, attested 0x{}",
            hex::encode(Sha256::digest([0xca; 40])),
            "33".repeat(32)
        ),
    );
}

#[test]
fn evm_rpc_tls_absent_aborts() {
    assert_mismatch(
        set!(evm_rpc_tls, None),
        "evm_rpc_tls mismatch: expected present, attested absent",
    );
}

#[test]
fn gas_tx_allowed_to_mismatch_aborts() {
    assert_mismatch(
        set!(gas_tx_allowed_to, [0; 20]),
        &format!(
            "gas_tx_allowed_to mismatch: expected 0x6711f1a319b37847fa0234181c34d883774c4951, \
             attested 0x{}",
            "00".repeat(20)
        ),
    );
}

#[test]
fn gas_tx_max_gas_limit_mismatch_aborts() {
    assert_mismatch(
        set!(gas_tx_max_gas_limit, 1),
        "gas_tx_max_gas_limit mismatch: expected 300000, attested 1",
    );
}

#[test]
fn gas_tx_max_fee_per_gas_mismatch_aborts() {
    assert_mismatch(
        set!(gas_tx_max_fee_per_gas, 1),
        "gas_tx_max_fee_per_gas mismatch: expected 1000, attested 1",
    );
}

#[test]
fn gas_tx_max_value_wei_mismatch_aborts() {
    assert_mismatch(
        set!(gas_tx_max_value_wei, 6),
        "gas_tx_max_value_wei mismatch: expected 5, attested 6",
    );
}

#[test]
fn gas_tx_allowed_selectors_mismatch_aborts() {
    assert_mismatch(
        set!(gas_tx_allowed_selectors, vec![[0xde, 0xad, 0xbe, 0xef]]),
        "gas_tx_allowed_selectors mismatch: expected 0x01020304,0xdeadbeef, \
         attested 0xdeadbeef",
    );
}

#[test]
fn token_contract_mismatch_aborts() {
    assert_mismatch(
        set!(token_contract, [0x44; 20]),
        &format!(
            "token_contract mismatch: expected 0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9, \
             attested 0x{}",
            "44".repeat(20)
        ),
    );
}

#[test]
fn kms_key_arn_mismatch_aborts() {
    assert_mismatch(
        kms(|pin| pin.key_arn = "arn:other".into()),
        &format!("kms.key_arn mismatch: expected {ARN}, attested arn:other"),
    );
}

#[test]
fn kms_region_mismatch_aborts() {
    assert_mismatch(
        kms(|pin| pin.region = "us-east-1".into()),
        "kms.region mismatch: expected eu-west-1, attested us-east-1",
    );
}

#[test]
fn kms_seed_id_mismatch_aborts() {
    assert_mismatch(
        kms(|pin| pin.seed_id = "seed-2".into()),
        "kms.seed_id mismatch: expected seed-1, attested seed-2",
    );
}

#[test]
fn kms_expected_evm_address_mismatch_aborts() {
    assert_mismatch(
        kms(|pin| pin.expected_evm_address = None),
        &format!(
            "kms.expected_evm_address mismatch: expected 0x{}, attested none",
            "ab".repeat(20)
        ),
    );
}

#[test]
fn kms_absent_aborts() {
    assert_mismatch(
        set!(kms, None),
        "kms mismatch: expected present, attested absent",
    );
}

/// A cloning role must attest its document PCR3.
#[test]
fn clone_peer_pcr3_absent_aborts() {
    assert_mismatch(
        set!(clone_peer_pcr3, None),
        "clone_peer_pcr3 mismatch: expected present, attested absent",
    );
}

#[test]
fn clone_peer_pcr3_of_another_role_aborts() {
    assert_mismatch(
        set!(clone_peer_pcr3, Some([0x44; 48])),
        &format!(
            "clone_peer_pcr3.value mismatch: expected 0x{}, attested 0x{}",
            "33".repeat(48),
            "44".repeat(48)
        ),
    );
}

/// The mint signer does not clone, so it attests no PCR3.
#[test]
fn the_mint_signer_attests_no_pcr3() {
    let mint = expected_policy(SignerRole::Mint, &image_env(), &endpoints()).unwrap();
    let (r, root) = response(&mint.to_bytes());
    let policy = check_launch_with(r, VerifyMode::Real, &mint, |doc| {
        Ok(verify_policy_with_root(doc, &PCRS, &NONCE, &root)?)
    })
    .unwrap();
    assert!(matches!(
        policy,
        AttestedPolicy::Production {
            clone_peer_pcr3: None,
            ..
        }
    ));
}

#[test]
fn a_development_policy_aborts() {
    let err = check(response(&AttestedPolicy::Development.to_bytes())).unwrap_err();
    assert_eq!(
        err.to_string(),
        "policy mismatch: expected Production, attested Development"
    );
}

#[test]
fn a_wrong_pcr_aborts() {
    let other = ExpectedPcrs::new([1; 48], [2; 48], [9; 48]);
    let err = check_with(response(&attested().to_bytes()), NONCE, &other).unwrap_err();
    assert!(format!("{err:#}").contains("PCR mismatch: PCR2"), "{err:#}");
}

#[test]
fn a_wrong_nonce_aborts() {
    let err = check_with(response(&attested().to_bytes()), [8; 32], &PCRS).unwrap_err();
    assert!(format!("{err:#}").contains("nonce mismatch"), "{err:#}");
}

#[test]
fn a_missing_nonce_aborts() {
    // The mock builder always sets a nonce. Drop it from the CBOR map.
    // A signed document cannot drop it, so this test runs in Mock mode.
    let dev = AttestedPolicy::Development;
    let mut r = mock_response(&dev.to_bytes());
    let mut doc: ciborium::Value = ciborium::from_reader(r.attestation_doc.as_slice()).unwrap();
    doc.as_map_mut()
        .unwrap()
        .retain(|(k, _)| k.as_text() != Some("nonce"));
    r.attestation_doc.clear();
    ciborium::into_writer(&doc, &mut r.attestation_doc).unwrap();
    let err = check_launch(r, NONCE, &PCRS, &dev, VerifyMode::Mock).unwrap_err();
    assert!(format!("{err:#}").contains("missing nonce"), "{err:#}");
}

#[test]
fn changed_policy_bytes_fail_the_commitment() {
    let (mut r, root) = response(&attested().to_bytes());
    let mut other = expected();
    set!(chain_id, 1)(&mut other);
    r.attested_policy = other.to_bytes();
    let err = check((r, root)).unwrap_err();
    assert!(err.to_string().contains("does not commit"), "{err}");
}

#[test]
fn a_keyed_answer_aborts() {
    let (mut r, root) = response(&attested().to_bytes());
    r.public_keys = Some(Default::default());
    let err = check((r, root)).unwrap_err();
    assert!(err.to_string().contains("already has keys"), "{err}");
}

#[test]
fn a_keyed_document_aborts() {
    let (mut r, _) = response(&attested().to_bytes());
    let commitment = policy_commitment(&r.attested_policy);
    let (doc, root) = signed_document(
        &PCRS,
        &NONCE,
        Some(&[4; 65]),
        &commitment,
        1_577_880_000_000,
        None,
    );
    r.attestation_doc = doc;
    let err = check((r, root)).unwrap_err();
    assert!(format!("{err:#}").contains("has a public key"), "{err:#}");
}

#[test]
fn a_malformed_document_aborts_in_real_mode() {
    let err = check_launch(
        mock_response(&attested().to_bytes()),
        NONCE,
        &PCRS,
        &expected(),
        VerifyMode::Real,
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").starts_with("attestation verification failed"),
        "{err:#}"
    );
}

#[test]
fn mock_mode_refuses_a_production_expectation() {
    let refused = "mock mode refuses a Production expectation";
    let err = check_launch(
        Default::default(),
        NONCE,
        &PCRS,
        &expected(),
        VerifyMode::Mock,
    )
    .unwrap_err();
    assert!(err.to_string().contains(refused), "{err}");

    let dev = AttestedPolicy::Development;
    let ok = check_launch(
        mock_response(&dev.to_bytes()),
        NONCE,
        &PCRS,
        &dev,
        VerifyMode::Mock,
    )
    .unwrap();
    assert_eq!(ok, dev);
}

#[test]
fn mixed_case_hosts_match_the_lowercased_attestation() {
    let mut upper = endpoints();
    upper.electrum_url = "ssl://Electrum.Example:50002/".into();
    upper.evm_rpc_host = "RPC.Example".into();
    let policy = expected_policy(SignerRole::Combined, &image_env(), &upper).unwrap();
    assert_eq!(policy, expected());
}

#[test]
fn esplora_urls_give_the_attested_host() {
    for url in [
        "https://esplora.example",
        "https://Esplora.Example:443/",
        "http://esplora.example:3000",
        "tcp://esplora.example:50001",
    ] {
        assert_eq!(indexer_host(url).unwrap(), "esplora.example", "{url}");
    }
    for url in [
        "ssl://esplora.example",
        "esplora.example:443",
        "ftp://e.example:1",
    ] {
        assert!(indexer_host(url).is_err(), "{url}");
    }
}

#[test]
fn a_missing_required_image_env_key_is_an_error() {
    let env = image_env().replace("\"TOKEN_CONTRACT=", "\"OTHER=");
    let err = expected_policy(SignerRole::Combined, &env, &endpoints()).unwrap_err();
    assert_eq!(err.to_string(), "IMAGE-ENV.json has no TOKEN_CONTRACT");
}

#[test]
fn mint_masks_the_gas_fields_and_burn_masks_vanilla() {
    let AttestedPolicy::Production {
        gas_tx_allowed_to,
        gas_tx_max_gas_limit,
        gas_tx_max_fee_per_gas,
        gas_tx_max_value_wei,
        gas_tx_allowed_selectors,
        allow_vanilla_psbt,
        ..
    } = expected_policy(SignerRole::Mint, &image_env(), &endpoints()).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(gas_tx_allowed_to, [0; 20]);
    assert_eq!(
        (
            gas_tx_max_gas_limit,
            gas_tx_max_fee_per_gas,
            gas_tx_max_value_wei
        ),
        (0, 0, 0)
    );
    assert!(gas_tx_allowed_selectors.is_empty());
    assert!(allow_vanilla_psbt);

    let AttestedPolicy::Production {
        allow_vanilla_psbt,
        gas_tx_max_gas_limit,
        ..
    } = expected_policy(SignerRole::Burn, &image_env(), &endpoints()).unwrap()
    else {
        unreachable!()
    };
    assert!(!allow_vanilla_psbt);
    assert_eq!(gas_tx_max_gas_limit, 300_000);
}
