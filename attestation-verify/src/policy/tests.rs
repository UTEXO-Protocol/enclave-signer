use super::*;

/// Production policy with parameters, so each test changes one field.
/// Gas-tx fields are fixed here. The gas tests change them.
fn prod(
    vanilla: bool,
    evm: EvmDataSource,
    chain_id: u64,
    contract: u8,
    asset: &str,
) -> AttestedPolicy {
    AttestedPolicy::Production {
        allow_vanilla_psbt: vanilla,
        signer_role: SignerRole::Mint,
        attestation: AttestationMode::Real,
        evm_source: evm,
        btc_source: BtcDataSource::SpvVerified,
        chain_id,
        bitcoin_network: BitcoinNetwork::Mainnet,
        bridge_contract: [contract; 20],
        rgb_asset_id: asset.into(),
        funds_in_contract: [0x44; 20],
        evm_finality_tag: EvmFinalityTag::Safe,
        spv_min_confirmations: 6,
        electrum_host: "electrum.test".into(),
        evm_rpc_tls: None,
        gas_tx_allowed_to: [0xAA; 20],
        gas_tx_max_gas_limit: 21_000,
        gas_tx_max_fee_per_gas: 1_000,
        gas_tx_max_value_wei: 0,
        gas_tx_allowed_selectors: vec![[0xde, 0xad, 0xbe, 0xef]],
        token_contract: [0x77; 20],
        kms: None,
        clone_peer_pcr3: None,
    }
}

fn base() -> AttestedPolicy {
    prod(false, EvmDataSource::Disabled, 1, 0x11, "rgb:asset")
}

#[test]
fn finality_tags_are_strict_and_default_to_finalized() {
    assert_eq!(EvmFinalityTag::default(), EvmFinalityTag::Finalized);
    for (text, tag, wire) in [
        ("latest", EvmFinalityTag::Latest, 0),
        ("safe", EvmFinalityTag::Safe, 1),
        ("finalized", EvmFinalityTag::Finalized, 2),
    ] {
        assert_eq!(text.parse::<EvmFinalityTag>(), Ok(tag));
        assert_eq!(tag.as_str(), text);
        assert_eq!(tag.to_string(), text);
        assert_eq!(tag as u8, wire);
    }
    for invalid in ["", "SAFE", "Safe", " safe", "safe ", "pending", "12"] {
        assert!(invalid.parse::<EvmFinalityTag>().is_err(), "{invalid:?}");
    }
}

#[test]
fn finality_tag_is_committed_and_round_trips() {
    let mut encodings = Vec::new();
    for tag in [
        EvmFinalityTag::Latest,
        EvmFinalityTag::Safe,
        EvmFinalityTag::Finalized,
    ] {
        let mut policy = base();
        if let AttestedPolicy::Production {
            evm_finality_tag, ..
        } = &mut policy
        {
            *evm_finality_tag = tag;
        }
        let bytes = policy.to_bytes();
        assert_eq!(AttestedPolicy::from_bytes(&bytes), Ok(policy));
        encodings.push(bytes);
    }
    assert_ne!(encodings[0], encodings[1]);
    assert_ne!(encodings[0], encodings[2]);
    assert_ne!(encodings[1], encodings[2]);
}

#[test]
fn unknown_finality_tag_refuses_to_decode() {
    let mut bytes = base().to_bytes();
    // The tag immediately follows the fixed FundsIn emitter in this fixture.
    let tag_at = bytes.windows(20).position(|b| b == [0x44; 20]).unwrap() + 20;
    assert_eq!(bytes[tag_at], EvmFinalityTag::Safe as u8);
    for invalid in [3, 255] {
        bytes[tag_at] = invalid;
        assert_eq!(
            AttestedPolicy::from_bytes(&bytes),
            Err(PolicyDecodeError("unknown EVM finality tag"))
        );
    }
}

/// `base()` with the gas-tx fields overridden, for the gas tests.
fn base_with_gas(
    to: [u8; 20],
    max_gas: u64,
    max_fee: u128,
    max_value: u128,
    selectors: Vec<[u8; 4]>,
) -> AttestedPolicy {
    match base() {
        AttestedPolicy::Production {
            allow_vanilla_psbt,
            signer_role,
            attestation,
            evm_source,
            btc_source,
            chain_id,
            bitcoin_network,
            bridge_contract,
            rgb_asset_id,
            funds_in_contract,
            evm_finality_tag,
            spv_min_confirmations,
            electrum_host,
            evm_rpc_tls,
            token_contract,
            kms,
            clone_peer_pcr3,
            ..
        } => AttestedPolicy::Production {
            allow_vanilla_psbt,
            signer_role,
            attestation,
            evm_source,
            btc_source,
            chain_id,
            bitcoin_network,
            bridge_contract,
            rgb_asset_id,
            funds_in_contract,
            evm_finality_tag,
            spv_min_confirmations,
            electrum_host,
            evm_rpc_tls,
            gas_tx_allowed_to: to,
            gas_tx_max_gas_limit: max_gas,
            gas_tx_max_fee_per_gas: max_fee,
            gas_tx_max_value_wei: max_value,
            gas_tx_allowed_selectors: selectors,
            token_contract,
            kms,
            clone_peer_pcr3,
        },
        AttestedPolicy::Development => unreachable!(),
    }
}

#[test]
fn every_encoding_starts_with_the_version_tag() {
    assert_eq!(base().to_bytes()[0], POLICY_COMMITMENT_V1);
    assert_eq!(
        AttestedPolicy::Development.to_bytes()[0],
        POLICY_COMMITMENT_V1
    );
}

#[test]
fn rejects_every_version_other_than_v1() {
    for policy in [base(), AttestedPolicy::Development] {
        let current = policy.to_bytes();
        for version in (0..=u8::MAX).filter(|v| *v != POLICY_COMMITMENT_V1) {
            let mut other = current.clone();
            other[0] = version;
            assert_eq!(
                AttestedPolicy::from_bytes(&other).unwrap_err(),
                PolicyDecodeError("unknown policy version")
            );
            assert_ne!(policy_commitment(&other), policy_commitment(&current));
        }
    }
}

#[test]
fn production_and_development_never_collide() {
    assert_ne!(base().to_bytes(), AttestedPolicy::Development.to_bytes());
}

/// No build produces EVM source 1 or 2.
#[test]
fn reserved_evm_sources_are_refused() {
    let disabled = base().to_bytes();
    let pinned = prod(false, EvmDataSource::PinnedTlsRpc, 1, 0x11, "rgb:asset").to_bytes();
    let source_at = disabled
        .iter()
        .zip(&pinned)
        .position(|(a, b)| a != b)
        .unwrap();
    for reserved in [1u8, 2] {
        let mut bytes = disabled.clone();
        bytes[source_at] = reserved;
        assert_eq!(
            AttestedPolicy::from_bytes(&bytes),
            Err(PolicyDecodeError("unknown EVM data source"))
        );
    }
}

#[test]
fn every_posture_field_changes_the_bytes() {
    let cases = [
        prod(true, EvmDataSource::Disabled, 1, 0x11, "rgb:asset"),
        prod(false, EvmDataSource::PinnedTlsRpc, 1, 0x11, "rgb:asset"),
        prod(false, EvmDataSource::Disabled, 2, 0x11, "rgb:asset"),
        prod(false, EvmDataSource::Disabled, 1, 0x22, "rgb:asset"),
        prod(false, EvmDataSource::Disabled, 1, 0x11, "rgb:other"),
    ];
    for c in cases {
        assert_ne!(
            c.to_bytes(),
            base().to_bytes(),
            "posture change must alter the commitment"
        );
    }
}

#[test]
fn signer_role_changes_the_bytes() {
    let encodings: Vec<Vec<u8>> = [SignerRole::Combined, SignerRole::Mint, SignerRole::Burn]
        .into_iter()
        .map(|role| {
            let mut p = base();
            if let AttestedPolicy::Production { signer_role, .. } = &mut p {
                *signer_role = role;
            }
            p.to_bytes()
        })
        .collect();
    assert_ne!(encodings[0], encodings[1]);
    assert_ne!(encodings[0], encodings[2]);
    assert_ne!(encodings[1], encodings[2]);
}

/// A signet image with the production EVM pins attests a different policy.
#[test]
fn bitcoin_network_changes_the_bytes() {
    let encodings: Vec<Vec<u8>> = [
        BitcoinNetwork::Mainnet,
        BitcoinNetwork::Testnet3,
        BitcoinNetwork::Signet,
        BitcoinNetwork::Regtest,
        BitcoinNetwork::Testnet4,
        BitcoinNetwork::SignetCustom,
    ]
    .into_iter()
    .map(|network| {
        let mut p = base();
        if let AttestedPolicy::Production {
            bitcoin_network, ..
        } = &mut p
        {
            *bitcoin_network = network;
        }
        assert_eq!(AttestedPolicy::from_bytes(&p.to_bytes()), Ok(p.clone()));
        p.to_bytes()
    })
    .collect();
    for (i, a) in encodings.iter().enumerate() {
        for b in &encodings[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn bitcoin_network_parses_the_enclave_names() {
    for (name, want) in [
        ("bitcoin", BitcoinNetwork::Mainnet),
        ("mainnet", BitcoinNetwork::Mainnet),
        ("testnet", BitcoinNetwork::Testnet3),
        ("testnet3", BitcoinNetwork::Testnet3),
        ("signet", BitcoinNetwork::Signet),
        ("signetcustom", BitcoinNetwork::SignetCustom),
        ("testnet4", BitcoinNetwork::Testnet4),
        ("regtest", BitcoinNetwork::Regtest),
    ] {
        assert_eq!(BitcoinNetwork::from_env_str(name), Some(want), "{name}");
    }
    assert_eq!(BitcoinNetwork::from_env_str("testnet5"), None);
    assert_eq!(BitcoinNetwork::from_env_str(""), None);
}

#[test]
fn deposit_emitter_changes_the_bytes() {
    let mut emitter = base();
    if let AttestedPolicy::Production {
        funds_in_contract, ..
    } = &mut emitter
    {
        *funds_in_contract = [0x55; 20];
    }
    assert_ne!(base().to_bytes(), emitter.to_bytes());
}

#[test]
fn spv_min_confirmations_changes_the_bytes() {
    let mut deeper = base();
    if let AttestedPolicy::Production {
        spv_min_confirmations,
        ..
    } = &mut deeper
    {
        *spv_min_confirmations = 7;
    }
    assert_ne!(base().to_bytes(), deeper.to_bytes());
    assert_eq!(AttestedPolicy::from_bytes(&deeper.to_bytes()), Ok(deeper));
}

#[test]
fn token_contract_changes_the_bytes() {
    // The token is a burnId preimage input, so it must be in the bytes.
    let mut other = base();
    if let AttestedPolicy::Production { token_contract, .. } = &mut other {
        *token_contract = [0x78; 20];
    }
    assert_ne!(base().to_bytes(), other.to_bytes());
    // Only the token bytes change. The KMS and the PCR3 presence bytes
    // follow them.
    let a = base().to_bytes();
    let b = other.to_bytes();
    assert_eq!(a[..a.len() - 22], b[..b.len() - 22]);
    assert_eq!(&a[a.len() - 22..a.len() - 2], &[0x77; 20]);
}

#[test]
fn electrum_host_changes_the_bytes() {
    let mut other = base();
    if let AttestedPolicy::Production { electrum_host, .. } = &mut other {
        *electrum_host = "other.test".into();
    }
    assert_ne!(base().to_bytes(), other.to_bytes());
}

fn with_tls(host: &str, ca_sha256: [u8; 32]) -> AttestedPolicy {
    let mut p = base();
    if let AttestedPolicy::Production { evm_rpc_tls, .. } = &mut p {
        *evm_rpc_tls = Some(EvmRpcTlsPin {
            host: host.into(),
            ca_sha256,
        });
    }
    p
}

#[test]
fn evm_rpc_tls_pin_presence_host_and_ca_change_the_bytes() {
    let pinned = with_tls("rpc.test", [1; 32]).to_bytes();
    assert_ne!(base().to_bytes(), pinned);
    assert_ne!(with_tls("other.test", [1; 32]).to_bytes(), pinned);
    assert_ne!(with_tls("rpc.test", [2; 32]).to_bytes(), pinned);
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

fn with_kms(kms: Option<KmsPin>) -> AttestedPolicy {
    let mut p = base();
    if let AttestedPolicy::Production { kms: k, .. } = &mut p {
        *k = kms;
    }
    p
}

#[test]
fn kms_changes_the_bytes() {
    let pinned = with_kms(Some(a_kms_pin())).to_bytes();
    assert_ne!(base().to_bytes(), pinned);
    let edits: [fn(&mut KmsPin); 4] = [
        |k| k.key_arn.push('0'),
        |k| k.region = "eu-west-2".into(),
        |k| k.seed_id = "seed-2".into(),
        |k| k.expected_evm_address = None,
    ];
    for edit in edits {
        let mut pin = a_kms_pin();
        edit(&mut pin);
        assert_ne!(with_kms(Some(pin)).to_bytes(), pinned);
    }
}

/// `base()` as a burn signer with the given clone-peer PCR3.
fn with_clone_peer_pcr3(pcr3: Option<[u8; 48]>) -> AttestedPolicy {
    let mut p = base();
    if let AttestedPolicy::Production {
        signer_role,
        clone_peer_pcr3,
        ..
    } = &mut p
    {
        *signer_role = SignerRole::Burn;
        *clone_peer_pcr3 = pcr3;
    }
    p
}

/// Two enclaves under different IAM roles attest different policies, so a
/// verifier sees which role the clone peers are bound to.
#[test]
fn clone_peer_pcr3_changes_the_bytes() {
    let role_a = with_clone_peer_pcr3(Some([0x33; 48])).to_bytes();
    assert_ne!(role_a, with_clone_peer_pcr3(Some([0x34; 48])).to_bytes());
    assert_ne!(role_a, with_clone_peer_pcr3(None).to_bytes());
}

#[test]
fn from_bytes_inverts_to_bytes() {
    let mut policies = vec![AttestedPolicy::Development, base()];
    policies.push(with_kms(Some(a_kms_pin())));
    policies.push(with_kms(Some(KmsPin {
        expected_evm_address: None,
        ..a_kms_pin()
    })));
    let mut full = with_tls("rpc.test", [1; 32]);
    if let AttestedPolicy::Production {
        gas_tx_allowed_selectors,
        kms,
        ..
    } = &mut full
    {
        *gas_tx_allowed_selectors = vec![[1, 1, 1, 1], [2, 2, 2, 2]];
        *kms = Some(a_kms_pin());
    }
    policies.push(full);
    policies.push(with_clone_peer_pcr3(Some([0x33; 48])));
    for p in policies {
        assert_eq!(AttestedPolicy::from_bytes(&p.to_bytes()), Ok(p));
    }
}

#[test]
fn from_bytes_refuses_bad_input() {
    let good = with_kms(Some(a_kms_pin())).to_bytes();
    for n in 0..good.len() {
        assert!(AttestedPolicy::from_bytes(&good[..n]).is_err(), "{n}");
    }
    let mut bad = vec![[&good[..], &[0]].concat()];
    let mut version = good.clone();
    version[0] = 2;
    bad.push(version);
    // The last byte is the PCR3 presence flag. Only 0 and 1 are valid.
    let mut flag = good.clone();
    *flag.last_mut().unwrap() = 2;
    bad.push(flag);
    let mut kind = good.clone();
    kind[1] = 2;
    bad.push(kind);
    let mut role = good.clone();
    role[3] = 3;
    bad.push(role);
    // Byte 15 is the Bitcoin network, after the 8-byte chain id.
    let mut network = good.clone();
    network[15] = 6;
    bad.push(network);
    // EVM source 2 is not a valid source.
    let mut evm = good.clone();
    evm[5] = 2;
    bad.push(evm);
    // The Electrum host is "electrum.test"; make its first byte invalid UTF-8.
    let at = good
        .windows(13)
        .position(|w| w == b"electrum.test")
        .unwrap();
    let mut utf8 = good.clone();
    utf8[at] = 0xff;
    bad.push(utf8);
    let unsorted = base_with_gas(
        [0xAA; 20],
        21_000,
        1_000,
        0,
        vec![[1, 1, 1, 1], [2, 2, 2, 2]],
    )
    .to_bytes();
    let at = unsorted
        .windows(8)
        .position(|w| w == [1, 1, 1, 1, 2, 2, 2, 2])
        .unwrap();
    let mut swapped = unsorted.clone();
    swapped[at..at + 8].copy_from_slice(&[2, 2, 2, 2, 1, 1, 1, 1]);
    bad.push(swapped);
    for b in bad {
        assert!(AttestedPolicy::from_bytes(&b).is_err(), "{b:?}");
    }
}

#[test]
fn asset_length_prefix_matches_the_wire_contract() {
    // Fixed offset from the documented V1 layout: tags (7), chain (8),
    // network (1), bridge address (20). Do not discover it with to_bytes.
    const OFFSET: usize = 36;
    let policy = prod(false, EvmDataSource::Disabled, 1, 0x11, "ab");
    let bytes = policy.to_bytes();
    assert_eq!(&bytes[OFFSET..OFFSET + 6], b"\x00\x00\x00\x02ab");
    assert_eq!(AttestedPolicy::from_bytes(&bytes), Ok(policy));
    for wrong_length in [0u32, 1, 3, u32::MAX] {
        let mut corrupted = bytes.clone();
        corrupted[OFFSET..OFFSET + 4].copy_from_slice(&wrong_length.to_be_bytes());
        assert!(
            AttestedPolicy::from_bytes(&corrupted).is_err(),
            "{wrong_length}"
        );
    }
}

// ---- gas-tx rule commitment ----

#[test]
fn every_gas_tx_field_changes_the_bytes() {
    let base_gas = base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![[1, 2, 3, 4]]);
    let cases = [
        base_with_gas([0xBB; 20], 21_000, 1_000, 0, vec![[1, 2, 3, 4]]), // destination
        base_with_gas([0xAA; 20], 30_000, 1_000, 0, vec![[1, 2, 3, 4]]), // gas cap
        base_with_gas([0xAA; 20], 21_000, 2_000, 0, vec![[1, 2, 3, 4]]), // fee cap
        base_with_gas([0xAA; 20], 21_000, 1_000, 5, vec![[1, 2, 3, 4]]), // value ceiling
        base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![[9, 9, 9, 9]]), // selector
        base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![]),             // no selectors
    ];
    for c in cases {
        assert_ne!(
            c.to_bytes(),
            base_gas.to_bytes(),
            "a gas-tx rule change must alter the commitment"
        );
    }
}

#[test]
fn selector_allowlist_is_order_and_dup_independent() {
    // Selector order and duplicates do not change the attested bytes.
    let a = base_with_gas(
        [0xAA; 20],
        21_000,
        1_000,
        0,
        vec![[1, 1, 1, 1], [2, 2, 2, 2]],
    );
    let b = base_with_gas(
        [0xAA; 20],
        21_000,
        1_000,
        0,
        vec![[2, 2, 2, 2], [1, 1, 1, 1], [1, 1, 1, 1]],
    );
    assert_eq!(a.to_bytes(), b.to_bytes());
}

#[test]
fn selector_count_prefix_matches_the_wire_contract() {
    // V1 offset for base(): 9-byte asset, 13-byte indexer host, no TLS pin.
    const OFFSET: usize = 152;
    let one = base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![[1, 1, 1, 1]]);
    let two = base_with_gas(
        [0xAA; 20],
        21_000,
        1_000,
        0,
        vec![[1, 1, 1, 1], [2, 2, 2, 2]],
    );
    let one_bytes = one.to_bytes();
    let two_bytes = two.to_bytes();
    assert_eq!(&one_bytes[OFFSET..OFFSET + 8], &[0, 0, 0, 1, 1, 1, 1, 1]);
    assert_eq!(
        &two_bytes[OFFSET..OFFSET + 12],
        &[0, 0, 0, 2, 1, 1, 1, 1, 2, 2, 2, 2]
    );
    assert_eq!(AttestedPolicy::from_bytes(&one_bytes), Ok(one));
    assert_eq!(AttestedPolicy::from_bytes(&two_bytes), Ok(two));
    for wrong_count in [0u32, 2, u32::MAX] {
        let mut corrupted = one_bytes.clone();
        corrupted[OFFSET..OFFSET + 4].copy_from_slice(&wrong_count.to_be_bytes());
        assert!(
            AttestedPolicy::from_bytes(&corrupted).is_err(),
            "{wrong_count}"
        );
    }
}
