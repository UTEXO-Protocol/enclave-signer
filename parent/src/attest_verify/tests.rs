use super::*;
use attestation_verify::test_util::{signed_document, verify_at_document_time_with_root};

const PCRS: ExpectedPcrs = ExpectedPcrs {
    pcr0: [1; 48],
    pcr1: [2; 48],
    pcr2: [3; 48],
};

/// A production expectation with the given chain_id, bridge_contract and
/// rgb_asset_id pins. All other fields are neutral.
fn expect_prod(
    chain_id: Option<u64>,
    bridge_contract: Option<[u8; 20]>,
    rgb_asset_id: Option<String>,
) -> ExpectedPolicy {
    ExpectedPolicy::Production {
        allow_vanilla_psbt: false,
        evm_source: EvmDataSource::RawRpc,
        signer_role: SignerRole::Combined,
        electrum_host: "electrum.test".into(),
        evm_rpc_tls: None,
        funds_in_contract: [0x11; 20],
        evm_finality_tag: EvmFinalityTag::Safe,
        token_contract: [0x22; 20],
        spv_min_confirmations: 6,
        expected_chain_id: chain_id,
        bitcoin_network: BitcoinNetwork::Mainnet,
        expected_bridge_contract: bridge_contract,
        expected_rgb_asset_id: rgb_asset_id,
        gas_tx_allowed_to: [0u8; 20],
        gas_tx_max_gas_limit: 0,
        gas_tx_max_fee_per_gas: 0,
        gas_tx_max_value_wei: 0,
        gas_tx_allowed_selectors: Vec::new(),
        kms: None,
    }
}

fn production(signer_role: SignerRole) -> ExpectedPolicy {
    ExpectedPolicy::Production {
        allow_vanilla_psbt: false,
        signer_role,
        evm_source: EvmDataSource::PinnedTlsRpc,
        electrum_host: "electrum.test".into(),
        evm_rpc_tls: Some(EvmRpcTlsPin {
            host: "rpc.test".into(),
            ca_sha256: [0x33; 32],
        }),
        funds_in_contract: [0x11; 20],
        evm_finality_tag: EvmFinalityTag::Safe,
        token_contract: [0x22; 20],
        spv_min_confirmations: 6,
        expected_chain_id: None,
        bitcoin_network: BitcoinNetwork::Mainnet,
        expected_bridge_contract: None,
        expected_rgb_asset_id: None,
        gas_tx_allowed_to: [0u8; 20],
        gas_tx_max_gas_limit: 0,
        gas_tx_max_fee_per_gas: 0,
        gas_tx_max_value_wei: 0,
        gas_tx_allowed_selectors: Vec::new(),
        kms: None,
    }
}

#[test]
fn finality_tag_must_match_the_verifier_expectation() {
    for tag in [
        EvmFinalityTag::Latest,
        EvmFinalityTag::Safe,
        EvmFinalityTag::Finalized,
    ] {
        let mut expected = production(SignerRole::Burn);
        if let ExpectedPolicy::Production {
            evm_finality_tag, ..
        } = &mut expected
        {
            *evm_finality_tag = tag;
        }
        let (response, root) = signed(&expected, &[0x42; 32]);
        assert!(verify_policy(response.clone(), &root, &expected).is_ok());
        if tag != EvmFinalityTag::Safe {
            let err = verify_policy(response, &root, &production(SignerRole::Burn)).unwrap_err();
            assert!(
                format!("{err:#}").contains("does not match the expected policy"),
                "{err:#}"
            );
        }
    }
}

/// The PCRs of a mock document: zero PCR0/1/2 and the mock PCR3.
fn mock_pcrs() -> std::collections::HashMap<u32, Vec<u8>> {
    let mut pcrs: std::collections::HashMap<u32, Vec<u8>> =
        (0..3).map(|i| (i, vec![0u8; 48])).collect();
    pcrs.insert(3, attestation_verify::MOCK_PCR3.to_vec());
    pcrs
}

/// A wire response pinned to chain 42161, contract 0x11.., asset "rgb:abc".
fn wire() -> AttestedPublicKeyResponse {
    AttestedPublicKeyResponse {
        chain_id: 42161,
        bridge_contract: vec![0x11u8; 20],
        rgb_asset_id: "rgb:abc".to_string(),
        ..Default::default()
    }
}

#[test]
fn unset_pins_trust_the_wire() {
    // Without operator pins, authenticate values without comparing them.
    let got = expected_attested_policy(&expect_prod(None, None, None), &wire(), &mock_pcrs())
        .expect("unset pins must not reject");
    match got {
        AttestedPolicy::Production {
            chain_id,
            rgb_asset_id,
            ..
        } => {
            assert_eq!(chain_id, 42161);
            assert_eq!(rgb_asset_id, "rgb:abc");
        }
        AttestedPolicy::Development => panic!("expected production policy"),
    }
}

#[test]
fn matching_pins_are_accepted() {
    let exp = expect_prod(Some(42161), Some([0x11u8; 20]), Some("rgb:abc".into()));
    assert!(expected_attested_policy(&exp, &wire(), &mock_pcrs()).is_ok());
}

#[test]
fn wrong_chain_id_is_rejected() {
    let exp = expect_prod(Some(1), None, None);
    let err =
        expected_attested_policy(&exp, &wire(), &mock_pcrs()).expect_err("wrong chain must fail");
    assert!(format!("{err:#}").contains("chain_id mismatch"));
}

#[test]
fn wrong_bridge_contract_is_rejected() {
    let exp = expect_prod(None, Some([0x22u8; 20]), None);
    let err = expected_attested_policy(&exp, &wire(), &mock_pcrs())
        .expect_err("wrong contract must fail");
    assert!(format!("{err:#}").contains("bridge_contract mismatch"));
}

#[test]
fn wrong_rgb_asset_is_rejected() {
    let exp = expect_prod(None, None, Some("rgb:other".into()));
    let err =
        expected_attested_policy(&exp, &wire(), &mock_pcrs()).expect_err("wrong asset must fail");
    assert!(format!("{err:#}").contains("rgb_asset_id mismatch"));
}

#[test]
fn empty_asset_pin_matches_empty_wire() {
    // A build with no RGB asset (EVM only) must match a "" pin.
    let mut w = wire();
    w.rgb_asset_id = String::new();
    let exp = expect_prod(None, None, Some(String::new()));
    assert!(expected_attested_policy(&exp, &w, &mock_pcrs()).is_ok());
}

/// A response without a document, and the `user_data` that commits it
/// to `attested`.
fn committed(attested: &ExpectedPolicy) -> (AttestedPublicKeyResponse, [u8; 32]) {
    let mut resp = AttestedPublicKeyResponse {
        evm_address: vec![0x0E; 20],
        evm_uncompressed_pub: vec![0x04; 65],
        chain_id: 1,
        bridge_contract: vec![0xAA; 20],
        rgb_asset_id: "rgb:asset".into(),
        ..Default::default()
    };
    resp.attested_policy = expected_attested_policy(attested, &resp, &mock_pcrs())
        .unwrap()
        .to_bytes();
    let mut preimage = canonical_bundle(&resp);
    preimage.extend_from_slice(&resp.attested_policy);
    (resp, Sha256::digest(&preimage).into())
}

/// A response whose mock document commits to `attested`.
fn attested_by(attested: &ExpectedPolicy, nonce: &[u8; 32]) -> AttestedPublicKeyResponse {
    let (mut resp, user_data) = committed(attested);
    resp.attestation_doc = attestation_verify::build_mock_document(
        nonce,
        Some(&resp.evm_uncompressed_pub),
        Some(&user_data),
    )
    .unwrap();
    resp
}

/// A response whose document, signed under a test root, commits to
/// `attested`, and the root DER.
fn signed(attested: &ExpectedPolicy, nonce: &[u8; 32]) -> (AttestedPublicKeyResponse, Vec<u8>) {
    let (mut resp, user_data) = committed(attested);
    let (doc, root) = signed_document(
        &PCRS,
        nonce,
        Some(&resp.evm_uncompressed_pub),
        &user_data,
        1_577_880_000_000,
        None,
    );
    resp.attestation_doc = doc;
    (resp, root)
}

fn verify(attested: SignerRole, expected: SignerRole) -> Result<AttestedPubkeyResult> {
    let (resp, root) = signed(&production(attested), &[0x42; 32]);
    verify_policy(resp, &root, &production(expected))
}

#[test]
fn matching_signer_role_verifies() {
    verify(SignerRole::Mint, SignerRole::Mint).unwrap();
    verify(SignerRole::Burn, SignerRole::Burn).unwrap();
}

/// Everything but the role matches, so the role alone fails the check.
#[test]
fn wrong_signer_role_alone_fails() {
    for (attested, expected) in [
        (SignerRole::Burn, SignerRole::Mint),
        (SignerRole::Mint, SignerRole::Burn),
        (SignerRole::Combined, SignerRole::Mint),
    ] {
        let err = verify(attested, expected).unwrap_err();
        assert!(
            format!("{err:#}").contains("expected policy"),
            "attested {attested:?}, expected {expected:?}: {err:#}"
        );
    }
}

#[test]
fn wrong_evm_rpc_tls_pin_fails() {
    let (resp, root) = signed(&production(SignerRole::Mint), &[0x42; 32]);
    for (host, ca_sha256) in [("other.test", [0x33; 32]), ("rpc.test", [0x44; 32])] {
        let mut expected = production(SignerRole::Mint);
        if let ExpectedPolicy::Production { evm_rpc_tls, .. } = &mut expected {
            *evm_rpc_tls = Some(EvmRpcTlsPin {
                host: host.into(),
                ca_sha256,
            });
        }
        let err = verify_policy(resp.clone(), &root, &expected).unwrap_err();
        assert!(format!("{err:#}").contains("expected policy"), "{err:#}");
    }
}

fn with_kms(kms: Option<KmsPin>) -> ExpectedPolicy {
    let mut p = production(SignerRole::Mint);
    if let ExpectedPolicy::Production { kms: k, .. } = &mut p {
        *k = kms;
    }
    p
}

fn a_kms_pin() -> KmsPin {
    KmsPin {
        key_arn: "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef"
            .into(),
        region: "eu-west-1".into(),
        seed_id: "seed-1".into(),
        expected_evm_address: Some([0x42; 20]),
    }
}

/// The public checks in Real mode, with `root` as the trust anchor.
fn verify_policy(
    resp: AttestedPublicKeyResponse,
    root: &[u8],
    expected: &ExpectedPolicy,
) -> Result<AttestedPubkeyResult> {
    let nonce = [0x42; 32];
    verify_attested_response_with(resp, nonce, VerifyMode::Real, expected, |doc| {
        Ok(verify_at_document_time_with_root(doc, &PCRS, &nonce, root)?)
    })
}

#[test]
fn tampered_policy_bytes_fail() {
    let expected = with_kms(Some(a_kms_pin()));
    let (good, root) = signed(&expected, &[0x42; 32]);
    let mut flipped = good.clone();
    let last = flipped.attested_policy.len() - 1;
    flipped.attested_policy[last] ^= 1;
    let mut swapped = good.clone();
    swapped.attested_policy = committed(&with_kms(None)).0.attested_policy;
    for resp in [flipped, swapped] {
        let err = verify_policy(resp, &root, &expected).unwrap_err();
        assert!(
            format!("{err:#}").contains("do not match the attestation"),
            "{err:#}"
        );
    }
    verify_policy(good, &root, &expected).unwrap();
}

#[test]
fn wrong_kms_pin_fails() {
    let (resp, root) = signed(&with_kms(Some(a_kms_pin())), &[0x42; 32]);
    let edits: [fn(&mut KmsPin); 4] = [
        |k| k.key_arn = k.key_arn.replace("mrk-0", "mrk-1"),
        |k| k.region = "eu-west-2".into(),
        |k| k.seed_id = "seed-2".into(),
        |k| k.expected_evm_address = None,
    ];
    for edit in edits {
        let mut pin = a_kms_pin();
        edit(&mut pin);
        let err = verify_policy(resp.clone(), &root, &with_kms(Some(pin))).unwrap_err();
        assert!(
            format!("{err:#}").contains("does not match the expected policy"),
            "{err:#}"
        );
    }
    let err = verify_policy(resp.clone(), &root, &with_kms(None)).unwrap_err();
    assert!(
        format!("{err:#}").contains("does not match the expected policy"),
        "{err:#}"
    );
    let ok = verify_policy(resp, &root, &with_kms(Some(a_kms_pin()))).unwrap();
    assert!(
        matches!(ok.policy, AttestedPolicy::Production { kms: Some(k), .. } if k == a_kms_pin())
    );
}

/// A burn expectation with chain and contract pins.
fn burn_pinned(chain_id: Option<u64>, bridge_contract: Option<[u8; 20]>) -> ExpectedPolicy {
    let mut p = production(SignerRole::Burn);
    if let ExpectedPolicy::Production {
        expected_chain_id,
        expected_bridge_contract,
        ..
    } = &mut p
    {
        *expected_chain_id = chain_id;
        *expected_bridge_contract = bridge_contract;
    }
    p
}

#[test]
fn a_tampered_bundle_fails_with_the_field_named() {
    let nonce = [0x42; 32];
    let (resp, root) = signed(&production(SignerRole::Burn), &nonce);
    let good = {
        let result = verify_policy(resp, &root, &production(SignerRole::Burn)).unwrap();
        assert_eq!(result.nonce_sent, nonce);
        serde_json::to_value(AttestationBundle::new(&result)).unwrap()
    };
    let pcr0 = ExpectedPcrs::new([9; 48], [2; 48], [3; 48]);
    let verify = |bundle: &serde_json::Value, pcrs: &ExpectedPcrs, expected: &ExpectedPolicy| {
        verify_bundle_with(
            &bundle.to_string(),
            VerifyMode::Real,
            expected,
            |doc, nonce| Ok(verify_at_document_time_with_root(doc, pcrs, nonce, &root)?),
        )
    };
    let ok = verify(&good, &PCRS, &burn_pinned(Some(1), Some([0xAA; 20]))).unwrap();
    assert_eq!(ok.response.evm_uncompressed_pub, vec![0x04; 65]);

    /// Change the last hex digit.
    fn flip(v: &mut serde_json::Value) {
        let s = v.as_str().unwrap();
        let last = if s.ends_with('0') { '1' } else { '0' };
        *v = format!("{}{last}", &s[..s.len() - 1]).into();
    }
    type Edit = fn(&mut serde_json::Value);
    let rows: [(Edit, &ExpectedPcrs, ExpectedPolicy, &str); 9] = [
        (
            |b| flip(&mut b["public_keys"]["evm_uncompressed_pub"]),
            &PCRS,
            production(SignerRole::Burn),
            "public_key",
        ),
        (
            |b| flip(&mut b["nonce"]),
            &PCRS,
            production(SignerRole::Burn),
            "nonce mismatch",
        ),
        (
            |b| flip(&mut b["attested_policy"]),
            &PCRS,
            production(SignerRole::Burn),
            "user_data",
        ),
        (
            |b| {
                let row = b["policy"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|r| r[0] == "chain_id")
                    .unwrap();
                row[1] = "42161".into();
            },
            &PCRS,
            production(SignerRole::Burn),
            "policy field chain_id mismatch",
        ),
        (|_| {}, &pcr0, production(SignerRole::Burn), "PCR0"),
        (
            |_| {},
            &PCRS,
            burn_pinned(None, Some([0xBB; 20])),
            "bridge_contract mismatch",
        ),
        (
            |_| {},
            &PCRS,
            burn_pinned(Some(42161), None),
            "chain_id mismatch",
        ),
        (
            |b| b["verification_mode"] = "mock".into(),
            &PCRS,
            production(SignerRole::Burn),
            "verification_mode",
        ),
        (
            |b| {
                b["format"] = "utexo-signer-attestation/1".into();
                b.as_object_mut().unwrap().remove("verification_mode");
            },
            &PCRS,
            production(SignerRole::Burn),
            "not supported",
        ),
    ];
    for (edit, pcrs, expected, message) in rows {
        let mut bundle = good.clone();
        edit(&mut bundle);
        let err = verify(&bundle, pcrs, &expected).unwrap_err();
        assert!(format!("{err:#}").contains(message), "{message}: {err:#}");
    }
}

#[test]
fn a_real_format_expired_bundle_verifies_offline() {
    let nonce = [0x42; 32];
    let (mut resp, user_data) = committed(&production(SignerRole::Burn));
    // 2020-01-01T12:00:00Z. The leaf certificate expired on 2020-01-02.
    let (doc, root) = signed_document(
        &PCRS,
        &nonce,
        Some(&resp.evm_uncompressed_pub),
        &user_data,
        1_577_880_000_000,
        Some((2020, 1, 1)),
    );
    resp.attestation_doc = doc;
    let verify_doc = |doc: &[u8], nonce: &[u8; 32]| {
        verify_at_document_time_with_root(doc, &PCRS, nonce, &root)
            .context("attestation verify failed")
    };
    let result =
        verify_keyed(resp, nonce, VerifyMode::Real, |doc| verify_doc(doc, &nonce)).unwrap();
    let mut bundle = AttestationBundle::new(&result);
    let expected = production(SignerRole::Burn);
    verify_bundle_with(
        &serde_json::to_string(&bundle).unwrap(),
        VerifyMode::Real,
        &expected,
        verify_doc,
    )
    .unwrap();

    // The signature is the last element, so the last byte is in it.
    let mut doc = BASE64.decode(&bundle.attestation_doc).unwrap();
    *doc.last_mut().unwrap() ^= 1;
    bundle.attestation_doc = BASE64.encode(doc);
    let err = verify_bundle_with(
        &serde_json::to_string(&bundle).unwrap(),
        VerifyMode::Real,
        &expected,
        verify_doc,
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("COSE signature"), "{err:#}");
}

#[test]
fn the_report_prints_every_verified_field() {
    let expected = with_kms(Some(a_kms_pin()));
    let (resp, root) = signed(&expected, &[0x42; 32]);
    let mut result = verify_policy(resp, &root, &expected).unwrap();
    // The formatter sees these values; verification does not.
    let r = &mut result.response;
    r.master_fingerprint = vec![0xF1; 4];
    r.account_xpub_vanilla = "tpub-vanilla".into();
    r.account_xpub_colored = "tpub-colored".into();
    r.evm_gas_tx_uncompressed_pub = vec![0x05; 65];
    r.evm_gas_tx_address = vec![0x06; 20];
    result.response.rgb_asset_id = "rgb:x\n  public_keys.evm_address: 0xevil".into();

    // A new field of the result does not compile until it is listed here.
    let AttestedPubkeyResult {
        mode,
        response,
        verified,
        bundle_commitment,
        nonce_sent,
        policy,
    } = &result;
    let AttestedPublicKeyResponse {
        evm_address,
        evm_uncompressed_pub,
        master_fingerprint,
        account_xpub_vanilla,
        account_xpub_colored,
        // The verified document itself. The bundle carries it.
        attestation_doc: _,
        chain_id,
        bridge_contract,
        rgb_asset_id,
        evm_gas_tx_uncompressed_pub,
        evm_gas_tx_address,
        // Printed decoded, as the `policy.*` lines.
        attested_policy: _,
    } = response;
    let VerifiedAttestation {
        // Verified equal to `evm_uncompressed_pub`.
        enclave_pubkey: _,
        pcrs: doc_pcrs,
        timestamp,
        // Verified equal to `bundle_commitment`.
        user_data: _,
        nonce: doc_nonce,
    } = verified;
    assert_eq!(doc_nonce, nonce_sent);
    let hex = |b: &[u8]| format!("0x{}", hex::encode(b));
    let mut want: Vec<(String, String)> = [
        ("mode", format!("{mode:?}")),
        ("public_keys.evm_address", hex(evm_address)),
        ("public_keys.master_fingerprint", hex(master_fingerprint)),
        (
            "public_keys.account_xpub_vanilla",
            account_xpub_vanilla.clone(),
        ),
        (
            "public_keys.account_xpub_colored",
            account_xpub_colored.clone(),
        ),
        (
            "public_keys.evm_uncompressed_pub",
            hex(evm_uncompressed_pub),
        ),
        ("public_keys.chain_id", chain_id.to_string()),
        ("public_keys.bridge_contract", hex(bridge_contract)),
        ("public_keys.rgb_asset_id", rgb_asset_id.clone()),
        (
            "public_keys.evm_gas_tx_uncompressed_pub",
            hex(evm_gas_tx_uncompressed_pub),
        ),
        ("public_keys.evm_gas_tx_address", hex(evm_gas_tx_address)),
        ("bundle_commitment", hex(bundle_commitment)),
        ("pcr0", hex(&doc_pcrs[&0])),
        ("pcr1", hex(&doc_pcrs[&1])),
        ("pcr2", hex(&doc_pcrs[&2])),
        ("timestamp_ms", timestamp.to_string()),
        ("nonce", hex(nonce_sent)),
    ]
    .map(|(name, value)| (name.to_string(), value))
    .into();
    want.extend(
        launch_check::fields(policy)
            .into_iter()
            .map(|(name, value)| (format!("policy.{name}"), value)),
    );
    assert!(want.iter().any(|(name, _)| name == "policy.kms.key_arn"));

    let report = verified_report(&result);
    let mut lines = report.lines();
    assert_eq!(lines.next(), Some("OK"));
    let printed: Vec<(String, String)> = lines
        .map(|l| {
            let (name, value) = l.strip_prefix("  ").unwrap().split_once(": ").unwrap();
            (name.into(), value.into())
        })
        .collect();
    let want: Vec<(String, String)> = want
        .into_iter()
        .map(|(name, value)| (name, value.escape_debug().to_string()))
        .collect();
    assert_eq!(printed, want);
    assert!(report
        .contains("\n  public_keys.rgb_asset_id: rgb:x\\n  public_keys.evm_address: 0xevil\n"));
    assert_eq!(report.matches("public_keys.evm_address:").count(), 2);
    assert_eq!(report.matches("\n  public_keys.evm_address:").count(), 1);
}

/// The enclave answer that `resp` maps from.
fn enclave_answer(resp: AttestedPublicKeyResponse) -> GetAttestedPublicKeyResponse {
    GetAttestedPublicKeyResponse {
        public_keys: Some(crate::enclave_proto::PublicKeysResponse {
            evm_address: resp.evm_address,
            evm_uncompressed_pub: resp.evm_uncompressed_pub,
            chain_id: resp.chain_id,
            bridge_contract: resp.bridge_contract,
            rgb_asset_id: resp.rgb_asset_id,
            ..Default::default()
        }),
        attestation_doc: resp.attestation_doc,
        attested_policy: resp.attested_policy,
    }
}

#[test]
fn export_refuses_what_does_not_verify() {
    let nonce = [0x42; 32];
    let (resp, root) = signed(&production(SignerRole::Burn), &nonce);
    let burn =
        expected_attested_policy(&production(SignerRole::Burn), &resp, &mock_pcrs()).unwrap();
    let combined =
        expected_attested_policy(&production(SignerRole::Combined), &resp, &mock_pcrs()).unwrap();
    let export = |answer, pcrs: &ExpectedPcrs, expected: &AttestedPolicy, evm| {
        export_bundle_with(answer, nonce, VerifyMode::Real, expected, evm, |doc| {
            Ok(verify_at_document_time_with_root(doc, pcrs, &nonce, &root)?)
        })
    };

    let bundle = export(enclave_answer(resp.clone()), &PCRS, &burn, Some([0x0E; 20])).unwrap();
    assert_eq!(bundle.verification_mode, VerifyMode::Real);
    let json = serde_json::to_string(&bundle).unwrap();
    assert!(json.contains(r#""verification_mode":"real""#), "{json}");
    verify_bundle_with(
        &json,
        VerifyMode::Real,
        &production(SignerRole::Burn),
        |doc, nonce| Ok(verify_at_document_time_with_root(doc, &PCRS, nonce, &root)?),
    )
    .unwrap();

    let no_key = GetAttestedPublicKeyResponse {
        public_keys: None,
        ..enclave_answer(resp.clone())
    };
    let other_pcrs = ExpectedPcrs::new([9; 48], [2; 48], [3; 48]);
    let cases = [
        (no_key, &PCRS, &burn, None, "no key"),
        (
            enclave_answer(resp.clone()),
            &PCRS,
            &combined,
            None,
            "signer_role mismatch",
        ),
        (
            enclave_answer(resp.clone()),
            &other_pcrs,
            &burn,
            None,
            "PCR0",
        ),
        (
            enclave_answer(resp.clone()),
            &PCRS,
            &burn,
            Some([1; 20]),
            "evm_address mismatch",
        ),
    ];
    for (answer, pcrs, expected, evm, message) in cases {
        let err = export(answer, pcrs, expected, evm).unwrap_err();
        assert!(format!("{err:#}").contains(message), "{message}: {err:#}");
    }
}

#[test]
fn export_verifies_real_development_policy_and_key_bindings() {
    let nonce = [0x42; 32];
    let (good, root) = signed(&ExpectedPolicy::Development, &nonce);
    let export = |answer, want_nonce, pcrs: &ExpectedPcrs, evm| {
        export_bundle_with(
            answer,
            want_nonce,
            VerifyMode::Real,
            &AttestedPolicy::Development,
            evm,
            |doc| {
                Ok(verify_at_document_time_with_root(
                    doc,
                    pcrs,
                    &want_nonce,
                    &root,
                )?)
            },
        )
    };
    let bundle = export(enclave_answer(good.clone()), nonce, &PCRS, Some([0x0E; 20])).unwrap();
    assert_eq!(bundle.verification_mode, VerifyMode::Real);
    assert_eq!(
        bundle.attested_policy,
        hex0x(&AttestedPolicy::Development.to_bytes())
    );

    let mut wrong_key = good.clone();
    wrong_key.evm_uncompressed_pub[0] ^= 1;
    let mut wrong_bundle = good.clone();
    wrong_bundle.bridge_contract[0] ^= 1;
    let mut wrong_policy = good.clone();
    wrong_policy.attested_policy = committed(&production(SignerRole::Burn)).0.attested_policy;
    let mut wrong_signature = good.clone();
    *wrong_signature.attestation_doc.last_mut().unwrap() ^= 1;
    for response in [wrong_key, wrong_bundle, wrong_policy, wrong_signature] {
        assert!(export(enclave_answer(response), nonce, &PCRS, None).is_err());
    }
    let other_pcrs = ExpectedPcrs::new([9; 48], [2; 48], [3; 48]);
    assert!(export(enclave_answer(good.clone()), nonce, &other_pcrs, None).is_err());
    assert!(export(enclave_answer(good.clone()), [9; 32], &PCRS, None).is_err());
    assert!(export(enclave_answer(good), nonce, &PCRS, Some([9; 20])).is_err());

    // Real Development verification still requires the AWS root, never raw CBOR.
    let mock = attested_by(&ExpectedPolicy::Development, &nonce);
    assert!(export_bundle(
        enclave_answer(mock),
        nonce,
        &PCRS,
        VerifyMode::Real,
        &AttestedPolicy::Development,
        None,
    )
    .is_err());
}

/// A cloning role commits the document PCR3 (the parent IAM
/// role). The mint signer commits none.
#[test]
fn a_cloning_role_commits_the_document_pcr3() {
    for (role, want) in [
        (SignerRole::Burn, Some(attestation_verify::MOCK_PCR3)),
        (SignerRole::Combined, Some(attestation_verify::MOCK_PCR3)),
        (SignerRole::Mint, None),
    ] {
        let got = expected_attested_policy(&production(role), &wire(), &mock_pcrs()).unwrap();
        let AttestedPolicy::Production {
            clone_peer_pcr3, ..
        } = got
        else {
            panic!("expected Production");
        };
        assert_eq!(clone_peer_pcr3, want, "{role:?}");
    }
}

/// A cloning role on an instance with no IAM role (all-zero or missing
/// PCR3) fails verification.
#[test]
fn a_cloning_role_without_an_iam_role_fails() {
    let mut zero = mock_pcrs();
    zero.insert(3, vec![0u8; 48]);
    let err = expected_attested_policy(&production(SignerRole::Burn), &wire(), &zero).unwrap_err();
    assert!(err.to_string().contains("no IAM role"), "{err}");

    let mut missing = mock_pcrs();
    missing.remove(&3);
    assert!(expected_attested_policy(&production(SignerRole::Burn), &wire(), &missing).is_err());

    // The mint signer does not clone, so it needs no PCR3.
    assert!(expected_attested_policy(&production(SignerRole::Mint), &wire(), &zero).is_ok());
}

/// The committed PCR3 must be the document's PCR3: a policy that names
/// another role does not verify.
#[test]
fn a_committed_pcr3_that_is_not_the_document_pcr3_fails() {
    let nonce = [0x42; 32];
    let attested = production(SignerRole::Burn);
    let pubkey = vec![0x04; 65];
    let mut resp = AttestedPublicKeyResponse {
        evm_uncompressed_pub: pubkey.clone(),
        chain_id: 1,
        bridge_contract: vec![0xAA; 20],
        rgb_asset_id: "rgb:asset".into(),
        ..Default::default()
    };
    let mut other_role = mock_pcrs();
    other_role.insert(3, vec![0x44; 48]);
    resp.attested_policy = expected_attested_policy(&attested, &resp, &other_role)
        .unwrap()
        .to_bytes();
    let mut preimage = canonical_bundle(&resp);
    preimage.extend_from_slice(&resp.attested_policy);
    let user_data: [u8; 32] = Sha256::digest(&preimage).into();
    let (doc, root) = signed_document(
        &PCRS,
        &nonce,
        Some(&pubkey),
        &user_data,
        1_577_880_000_000,
        None,
    );
    resp.attestation_doc = doc;
    let err = verify_policy(resp, &root, &attested).unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match the expected policy"),
        "{err}"
    );
}

fn assert_refused<T>(result: Result<T>) {
    let err = result.err().expect("mock mode with Production must fail");
    assert!(
        format!("{err:#}").contains("mock mode refuses a Production expectation"),
        "{err:#}"
    );
}

#[test]
fn mock_mode_refuses_a_production_expectation() {
    let nonce = [0x42; 32];
    let mock = VerifyMode::Mock;
    let prod = production(SignerRole::Burn);
    let prod_policy = expected_attested_policy(&prod, &wire(), &mock_pcrs()).unwrap();
    assert_refused(verify_attested_response(
        Default::default(),
        nonce,
        &PCRS,
        mock,
        &prod,
    ));
    assert_refused(verify_bundle("", &PCRS, mock, &prod));
    assert_refused(export_bundle(
        Default::default(),
        nonce,
        &PCRS,
        mock,
        &prod_policy,
        None,
    ));

    let dev = attested_by(&ExpectedPolicy::Development, &nonce);
    let zero = ExpectedPcrs::zero();
    let result = verify_attested_response(
        dev.clone(),
        nonce,
        &zero,
        mock,
        &ExpectedPolicy::Development,
    )
    .unwrap();
    assert_eq!(result.mode, mock);
    let bundle = export_bundle(
        enclave_answer(dev),
        nonce,
        &zero,
        mock,
        &AttestedPolicy::Development,
        None,
    )
    .unwrap();
    assert_eq!(bundle.verification_mode, mock);
    let json = serde_json::to_string(&bundle).unwrap();
    let result = verify_bundle(&json, &zero, mock, &ExpectedPolicy::Development).unwrap();
    assert_eq!(result.mode, mock);
}
