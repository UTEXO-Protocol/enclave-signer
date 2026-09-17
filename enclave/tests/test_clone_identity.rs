//! F03-AF-08: test identity commitments before state changes.
//! These tests use mock attestation without an NSM signature.
//! Real NSM tests run separately.
#![cfg(all(feature = "mock-attestation", feature = "allow-seed-import"))]
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
            dev_mode: false,
            mock_attestation: false,
            allow_seed_import: false,
            rgb_validation: true,
        },
        &cfg,
        EvmDataSource::RawRpc,
        None,
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
    assert_eq!(policies.len(), 14);
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
