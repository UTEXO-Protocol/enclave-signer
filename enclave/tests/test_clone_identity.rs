//! F03-AF-08: test identity commitments before state changes.
//! These tests use mock attestation without an NSM signature.
//! Real NSM tests run separately.
// Cloning is disabled with KMS persistence (see `test_clone.rs`).
#![cfg(all(
    feature = "mock-attestation",
    feature = "allow-seed-import",
    not(feature = "kms-persistence")
))]
#[path = "common/clone_commitment.rs"]
mod clone_commitment;
mod common;

use common::{send_request, start_test_server_with_policy};
use enclave_request::Request as Req;
use enclave_response::Response as Resp;
use utexo_bridge_enclave::{attestation, config::BridgeConfig, policy::*, proto::*};

const SECRET: &str = "public-af08-fixture-secret-0123456789abcdef";

fn context() -> (BridgeConfig, SecurityPolicy) {
    let cfg = BridgeConfig {
        chain_id: 42161,
        bridge_contract: [0x31; 20],
        rgb_asset_id: "rgb:af08-test-only".into(),
        ..Default::default()
    };
    let policy = SecurityPolicy::resolve(
        &BuildContext {
            debug_or_test: false,
            mock_attestation: false,
            allow_seed_import: false,
            rgb_validation: true,
            signer_role: SignerRole::Combined,
        },
        &cfg,
        EvmDataSource::RawRpc,
        None,
        "electrum.test",
    );
    assert!(matches!(policy, SecurityPolicy::Production(_)));
    (cfg, policy)
}

fn call(port: u16, request: Req) -> Resp {
    send_request(
        port,
        &EnclaveRequest {
            request: Some(request),
        },
    )
    .response
    .unwrap()
}

fn set(port: u16, clone: &GetCloneResponse) -> Resp {
    call(
        port,
        Req::SetClone(SetCloneRequest {
            encrypted_seed: clone.encrypted_seed.clone(),
            donor_pubkey: clone.donor_pubkey.clone(),
            donor_attestation: clone.donor_attestation.clone(),
        }),
    )
}

#[test]
fn clone_identity_rejects_each_bundle_and_policy_field_before_active_and_allows_retry() {
    let (cfg, policy) = context();
    let donor = start_test_server_with_policy(
        |s| {
            s.initialize_from_seed([0x42; 64]).unwrap();
            s.set_donor_cloning_secret(SECRET.into()).unwrap();
        },
        cfg.clone(),
        policy.clone(),
    );
    let Resp::PublicKeys(keys) = call(donor, Req::GetPublicKey(GetPublicKeyRequest {})) else {
        panic!("donor keys unavailable")
    };
    let bundles = clone_commitment::bundle_cases(&keys);
    let policies = clone_commitment::policy_cases(&policy.attested());
    assert_eq!(bundles.len(), 13);
    assert_eq!(policies.len(), 24);
    let mut cases: Vec<_> = bundles
        .into_iter()
        .map(|(name, k)| (format!("bundle.{name}"), k, policy.commitment_bytes()))
        .collect();
    cases.extend(
        policies
            .into_iter()
            .map(|(name, p)| (format!("policy.{name}"), keys.clone(), p)),
    );

    for (name, claimed_keys, claimed_policy) in cases {
        let requester = start_test_server_with_policy(|_| {}, cfg.clone(), policy.clone());
        let Resp::InitiateCloning(init) = call(
            requester,
            Req::InitiateCloning(InitiateCloningRequest {
                cloning_secret: SECRET.into(),
                cluster_public_key: keys.evm_address.clone(),
            }),
        ) else {
            panic!("{name}: initiate failed")
        };
        let Resp::GetClone(original) = call(
            donor,
            Req::GetClone(GetCloneRequest {
                cluster_public_key: keys.evm_address.clone(),
                cloning_digest: init.cloning_digest.clone(),
                encryption_pubkey: init.encryption_pubkey.clone(),
                requester_attestation: init.requester_attestation,
            }),
        ) else {
            panic!("{name}: donor failed")
        };
        let verified = attestation::verify_peer_attestation(
            &original.donor_attestation,
            &attestation::get_own_pcrs().unwrap(),
            None,
        )
        .unwrap();
        let expected = clone_commitment::commitment(
            &keys,
            &policy.commitment_bytes(),
            &init.encryption_pubkey,
            &original.donor_pubkey,
            &original.encrypted_seed,
        );
        assert_eq!(
            verified.user_data.as_deref(),
            Some(expected.as_slice()),
            "{name}: positive encoder control"
        );
        let wrong = clone_commitment::commitment(
            &claimed_keys,
            &claimed_policy,
            &init.encryption_pubkey,
            &original.donor_pubkey,
            &original.encrypted_seed,
        );
        assert_ne!(wrong, expected, "{name}: case must change the commitment");
        let nonce = verified.nonce.as_slice().try_into().unwrap();
        let mut altered = original.clone();
        altered.donor_attestation =
            attestation::get_attestation(nonce, Some(&original.donor_pubkey), Some(&wrong))
                .unwrap();
        // Confirm that attestation checks pass before testing the commitment.
        let v = attestation::verify_peer_attestation(
            &altered.donor_attestation,
            &attestation::get_own_pcrs().unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(v.enclave_pubkey, original.donor_pubkey);
        assert_eq!(v.nonce, verified.nonce);
        assert_eq!(v.user_data.as_deref(), Some(wrong.as_slice()));
        let Resp::Error(err) = set(requester, &altered) else {
            panic!("{name}: accepted mismatch")
        };
        assert!(
            err.message
                .contains("clone response version/identity/policy/transcript mismatch"),
            "{name}: {err:?}"
        );
        let Resp::Error(err) = call(requester, Req::GetPublicKey(GetPublicKeyRequest {})) else {
            panic!("{name}: exposed keys after rejection")
        };
        assert_eq!(err.message, "key not initialized", "{name}");
        assert_eq!(err.code, 1, "{name}");
        assert!(
            matches!(set(requester, &original), Resp::SetClone(_)),
            "{name}: same-nonce retry failed"
        );
        let Resp::PublicKeys(actual) = call(requester, Req::GetPublicKey(GetPublicKeyRequest {}))
        else {
            panic!("{name}: retry did not activate")
        };
        assert_eq!(actual, keys, "{name}: retry must restore all 13 fields");
        let Resp::Error(err) = set(requester, &original) else {
            panic!("{name}: replay accepted")
        };
        assert!(err.message.contains("nonce replay"), "{name}: {err:?}");
        assert_eq!(
            call(requester, Req::GetPublicKey(GetPublicKeyRequest {})),
            Resp::PublicKeys(keys.clone()),
            "{name}: replay changed Active identity"
        );
        eprintln!("PASS {name}: mismatch -> no keys -> same-nonce retry -> full identity -> replay reject");
    }
}

// The no-SPV profile forbids mock attestation. Exercise the shared clone
// handlers in the SPV test binary with an explicit, complete IndexerTrusted
// policy. The launch-gate tests cover the actual no-SPV policy construction.
#[cfg(all(feature = "spv", feature = "burn-signer"))]
fn indexer_context(request: &SetEndpointsRequest) -> (BridgeConfig, SecurityPolicy) {
    use utexo_bridge_enclave::{
        bootstrap,
        config::{BtcRelayMode, Endpoints},
    };
    let cfg = BridgeConfig {
        bitcoin_network: BitcoinNetwork::Signet,
        btc_relay_mode: BtcRelayMode::None,
        chain_id: 42161,
        bridge_contract: [0x31; 20],
        funds_in_contract: [0x32; 20],
        token_contract: [0x33; 20],
        rgb_asset_id: "rgb:indexer-clone-test".into(),
        ..Default::default()
    };
    let endpoints = Endpoints::parse(request).unwrap();
    let (source, pin) = bootstrap::resolve_evm_data_source(endpoints.evm_rpc_tls.as_ref().unwrap());
    let SecurityPolicy::Production(mut policy) = SecurityPolicy::resolve(
        &BuildContext {
            debug_or_test: false,
            mock_attestation: false,
            allow_seed_import: false,
            rgb_validation: true,
            signer_role: SignerRole::Burn,
        },
        &cfg,
        source,
        pin,
        &endpoints.electrum_host,
    ) else {
        panic!("this explicit-policy regression runs in the SPV test binary");
    };
    policy.btc_source = BtcDataSource::IndexerTrusted;
    policy.clone_peer_pcr3 = Some(attestation::get_own_pcr3().unwrap());
    policy.check_invariants().unwrap();
    let policy = SecurityPolicy::IndexerTrusted {
        policy,
        endpoints_sha256: Some(utexo_bridge_enclave::config::chain_endpoints_sha256(
            request,
        )),
    };
    (cfg, policy)
}

#[cfg(all(feature = "spv", feature = "burn-signer"))]
#[test]
fn indexer_clone_rejects_endpoint_policy_mismatch_before_activation_and_allows_path_rotation() {
    let original = SetEndpointsRequest {
        electrum_url: "ssl://electrum.test:50002".into(),
        evm_rpc_host: "rpc.test".into(),
        evm_rpc_ca_der: hex::decode(include_str!("fixtures/evm_rpc_tls/ca_a.der.hex").trim())
            .unwrap(),
        evm_rpc_tls_port: 443,
        evm_rpc_path: "/v2/original-api-key".into(),
        ..Default::default()
    };
    let rotated = SetEndpointsRequest {
        evm_rpc_path: "/v2/rotated-api-key".into(),
        ..original.clone()
    };
    // Only the digest changes in this policy: the separate TLS host/CA pins
    // and the Electrum host stay equal. This proves the digest is committed.
    let changed = SetEndpointsRequest {
        evm_rpc_tls_port: 8443,
        ..original.clone()
    };
    let (cfg, expected) = indexer_context(&original);
    let (_, matching) = indexer_context(&rotated);
    let (_, mismatching) = indexer_context(&changed);
    assert_eq!(expected.commitment_bytes(), matching.commitment_bytes());
    assert_ne!(expected.commitment_bytes(), mismatching.commitment_bytes());

    let start_donor = |policy| {
        start_test_server_with_policy(
            |s| {
                s.initialize_from_seed([0x42; 64]).unwrap();
                s.set_donor_cloning_secret(SECRET.into()).unwrap();
            },
            cfg.clone(),
            policy,
        )
    };
    let wrong_donor = start_donor(mismatching);
    let matching_donor = start_donor(matching);
    let Resp::PublicKeys(keys) = call(matching_donor, Req::GetPublicKey(GetPublicKeyRequest {}))
    else {
        panic!("donor keys unavailable");
    };
    let Resp::GetAttestedPublicKey(attested) = call(
        matching_donor,
        Req::GetAttestedPublicKey(GetAttestedPublicKeyRequest {
            nonce: vec![0x17; 32],
        }),
    ) else {
        panic!("IndexerTrusted public-key attestation unavailable");
    };
    assert_eq!(attested.attested_policy, expected.commitment_bytes());
    assert!(matches!(
        AttestedPolicy::from_bytes(&attested.attested_policy).unwrap(),
        AttestedPolicy::IndexerTrusted { .. }
    ));

    let requester = start_test_server_with_policy(|_| {}, cfg, expected.clone());
    let Resp::InitiateCloning(init) = call(
        requester,
        Req::InitiateCloning(InitiateCloningRequest {
            cloning_secret: SECRET.into(),
            cluster_public_key: keys.evm_address.clone(),
        }),
    ) else {
        panic!("initiate cloning failed");
    };
    let get_clone = |donor| {
        let Resp::GetClone(response) = call(
            donor,
            Req::GetClone(GetCloneRequest {
                cluster_public_key: keys.evm_address.clone(),
                cloning_digest: init.cloning_digest.clone(),
                encryption_pubkey: init.encryption_pubkey.clone(),
                requester_attestation: init.requester_attestation.clone(),
            }),
        ) else {
            panic!("donor failed");
        };
        response
    };
    let wrong = get_clone(wrong_donor);
    let Resp::Error(error) = set(requester, &wrong) else {
        panic!("a different public endpoint policy activated the requester");
    };
    assert!(
        error
            .message
            .contains("clone response version/identity/policy/transcript mismatch"),
        "{error:?}"
    );
    assert!(
        matches!(call(requester, Req::GetPublicKey(GetPublicKeyRequest {})), Resp::Error(e) if e.message == "key not initialized")
    );

    let matching = get_clone(matching_donor);
    let verified = attestation::verify_peer_attestation(
        &matching.donor_attestation,
        &attestation::get_own_pcrs().unwrap(),
        None,
    )
    .unwrap();
    let commitment = clone_commitment::commitment(
        &keys,
        &expected.commitment_bytes(),
        &init.encryption_pubkey,
        &matching.donor_pubkey,
        &matching.encrypted_seed,
    );
    assert_eq!(verified.user_data.as_deref(), Some(commitment.as_slice()));
    assert!(
        matches!(set(requester, &matching), Resp::SetClone(_)),
        "path-only credential rotation must preserve clone identity"
    );
    assert_eq!(
        call(requester, Req::GetPublicKey(GetPublicKeyRequest {})),
        Resp::PublicKeys(keys)
    );
}
