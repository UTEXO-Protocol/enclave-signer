use super::*;

/// A build context for a clean release bridge build (no dev features).
fn release_bridge_ctx() -> BuildContext {
    BuildContext {
        debug_or_test: false,
        mock_attestation: false,
        allow_seed_import: false,
        rgb_validation: true,
        // Both directions, so the gas and plain-BTC rules are live.
        signer_role: SignerRole::Combined,
    }
}

/// PCR3 of a parent instance with an IAM role.
const ROLE_PCR3: [u8; 48] = [0x33; 48];

/// `p` with the clone-peer PCR3 that `SetEndpoints` reads for a cloning role.
fn with_role(p: SecurityPolicy) -> SecurityPolicy {
    p.with_clone_peer_pcr3(|| Ok(ROLE_PCR3)).unwrap()
}

fn pinned_config() -> BridgeConfig {
    BridgeConfig {
        chain_id: 1,
        bridge_contract: [0x11; 20],
        rgb_asset_id: "rgb:asset".into(),
        funds_in_contract: [0x22; 20],
        token_contract: [0x33; 20],
        ..Default::default()
    }
}

#[test]
fn release_bridge_with_full_pins_is_production() {
    let p = with_role(SecurityPolicy::resolve(
        &release_bridge_ctx(),
        &pinned_config(),
        EvmDataSource::PinnedTlsRpc,
        a_tls_pin(),
        "e.test",
        12,
    ));
    match &p {
        SecurityPolicy::Production(pp) => {
            assert_eq!(pp.chain_id, 1);
            assert_eq!(pp.evm_source, EvmDataSource::PinnedTlsRpc);
            assert_eq!(pp.evm_rpc_tls, a_tls_pin());
            assert_eq!(pp.attestation, AttestationMode::Real);
            assert_eq!(pp.btc_source, BtcDataSource::SpvVerified);
        }
        other => panic!("expected Production, got {other:?}"),
    }
    assert!(p.assert_valid_for_build(&release_bridge_ctx()).is_ok());
}

/// The attested role reads the features, so compare it with the direction
/// cfgs the gates read. Catches drift between the two.
#[test]
fn build_context_reports_the_compiled_signer_role() {
    let want = match (cfg!(evm_to_rgb), cfg!(rgb_to_evm)) {
        (true, false) => SignerRole::Mint,
        (false, true) => SignerRole::Burn,
        (true, true) => SignerRole::Combined,
        (false, false) => unreachable!("build.rs always compiles one direction"),
    };
    assert_eq!(BuildContext::current().signer_role, want);
}

/// The role comes from the build, is carried into the production policy, and
/// changes the attested commitment.
#[test]
fn signer_role_is_attested() {
    let resolve = |signer_role| {
        SecurityPolicy::resolve(
            &BuildContext {
                signer_role,
                ..release_bridge_ctx()
            },
            &pinned_config(),
            EvmDataSource::RawRpc,
            None,
            "e.test",
            12,
        )
    };
    let mint = resolve(SignerRole::Mint);
    let burn = resolve(SignerRole::Burn);
    match &burn {
        SecurityPolicy::Production(p) => assert_eq!(p.signer_role, SignerRole::Burn),
        other => panic!("expected Production, got {other:?}"),
    }
    assert_ne!(mint.commitment_bytes(), burn.commitment_bytes());
}

/// A role never attests the other role's path as live, even with its pins set.
#[test]
fn signer_role_attests_the_other_roles_paths_as_off() {
    let config = BridgeConfig {
        btc_max_total_sats: 1_000_000,
        gas_tx_allowed_to: Some([0x33; 20]),
        gas_tx_max_gas_limit: 100_000,
        gas_tx_max_fee_per_gas: 1_000,
        gas_tx_allowed_selectors: vec![[0xde, 0xad, 0xbe, 0xef]],
        ..pinned_config()
    };
    let resolve = |signer_role| match SecurityPolicy::resolve(
        &BuildContext {
            signer_role,
            ..release_bridge_ctx()
        },
        &config,
        EvmDataSource::RawRpc,
        None,
        "e.test",
        12,
    ) {
        SecurityPolicy::Production(p) => p,
        other => panic!("expected Production, got {other:?}"),
    };

    let mint = resolve(SignerRole::Mint);
    assert!(mint.allow_vanilla_psbt);
    assert_eq!(mint.gas_tx_allowed_to, None);
    assert_eq!(mint.gas_tx_max_gas_limit, 0);
    assert_eq!(mint.gas_tx_max_fee_per_gas, 0);
    assert_eq!(mint.gas_tx_max_value_wei, None);
    assert!(mint.gas_tx_allowed_selectors.is_empty());

    let burn = resolve(SignerRole::Burn);
    assert!(!burn.allow_vanilla_psbt);
    assert_eq!(burn.gas_tx_allowed_to, Some([0x33; 20]));
    assert_eq!(burn.gas_tx_max_gas_limit, 100_000);

    let combined = resolve(SignerRole::Combined);
    assert!(combined.allow_vanilla_psbt);
    assert_eq!(combined.gas_tx_allowed_to, Some([0x33; 20]));
}

fn a_tls_pin() -> Option<EvmRpcTlsPin> {
    Some(EvmRpcTlsPin {
        host: "rpc.test".into(),
        ca_sha256: [0x0d; 32],
    })
}

#[test]
fn production_accepts_an_authenticated_evm_source_and_attests_it() {
    let ctx = release_bridge_ctx();
    // `Disabled` fails closed per request.
    for (source, pin) in [
        (EvmDataSource::Disabled, None),
        (EvmDataSource::PinnedTlsRpc, a_tls_pin()),
    ] {
        let p = with_role(SecurityPolicy::resolve(
            &ctx,
            &pinned_config(),
            source,
            pin,
            "e.test",
            12,
        ));
        match &p {
            SecurityPolicy::Production(pp) => assert_eq!(pp.evm_source, source),
            other => panic!("expected Production for {source:?}, got {other:?}"),
        }
        assert!(
            p.assert_valid_for_build(&ctx).is_ok(),
            "{source:?} must not be gated at boot"
        );
    }
}

/// The gate `SetEndpoints` runs, fed from a request as the handler feeds it.
#[cfg(feature = "evm-rpc")]
#[test]
fn production_launches_only_with_a_pinned_tls_evm_rpc() {
    let ca =
        hex::decode(include_str!("../../tests/fixtures/evm_rpc_tls/ca_a.der.hex").trim()).unwrap();
    let launch = |host: &str, ca_der: Vec<u8>| {
        let e = crate::config::Endpoints::parse(&crate::proto::SetEndpointsRequest {
            electrum_url: "ssl://electrum.test:50002".into(),
            evm_rpc_host: host.into(),
            evm_rpc_ca_der: ca_der,
            evm_rpc_tls_port: 443,
            ..Default::default()
        })?;
        let tls = e.evm_rpc_tls.as_ref().unwrap();
        let (source, pin) = crate::bootstrap::resolve_evm_data_source(tls);
        let ctx = release_bridge_ctx();
        let p = with_role(SecurityPolicy::resolve(
            &ctx,
            &pinned_config(),
            source,
            pin,
            &e.electrum_host,
            12,
        ));
        p.assert_valid_for_build(&ctx).map(|()| p)
    };
    assert!(launch("", ca.clone()).is_err());
    assert!(launch("rpc.test", Vec::new()).is_err());

    let Ok(SecurityPolicy::Production(p)) = launch("rpc.test", ca) else {
        panic!("a valid host and CA must launch");
    };
    assert_eq!(p.electrum_host, "electrum.test");
    assert_eq!(p.evm_source, EvmDataSource::PinnedTlsRpc);
    let pin = p.evm_rpc_tls.unwrap();
    assert_eq!(pin.host, "rpc.test");
    // `openssl x509 -in ca_a.pem -outform der | sha256sum`
    assert_eq!(
        hex::encode(pin.ca_sha256),
        "58c6acf2c15d81e939016026ec90047f88282fb3bef4d19dd2a1ff893f2349a8"
    );
}

#[test]
fn evm_rpc_tls_pin_is_carried_into_the_commitment() {
    let ctx = release_bridge_ctx();
    let commit = |host: &str, ca_sha256| {
        let pin = Some(EvmRpcTlsPin {
            host: host.into(),
            ca_sha256,
        });
        SecurityPolicy::resolve(
            &ctx,
            &pinned_config(),
            EvmDataSource::PinnedTlsRpc,
            pin,
            "e.test",
            12,
        )
        .commitment_bytes()
    };
    let base = commit("rpc.test", [0x0d; 32]);
    assert_ne!(base, commit("other.test", [0x0d; 32]));
    assert_ne!(base, commit("rpc.test", [0x0e; 32]));
}

#[test]
fn production_boots_without_endpoints_and_launches_only_with_them() {
    let ctx = release_bridge_ctx();
    let p = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::Disabled,
        None,
        "",
        12,
    );
    assert!(p.assert_valid_at_boot(&ctx).is_ok());
    let err = p.assert_valid_for_build(&ctx).unwrap_err();
    assert!(err.contains("Electrum host"), "got: {err}");
}

#[test]
fn production_rejects_a_zero_confirmation_rule() {
    let ctx = release_bridge_ctx();
    let policy = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::RawRpc,
        None,
        "e.test",
        0,
    );
    let err = policy.assert_valid_for_build(&ctx).unwrap_err();
    assert!(err.contains("confirmation"), "got: {err}");
}

#[test]
fn production_rejects_an_unpinned_token_contract() {
    // Without the token, the burnId check is skipped.
    let ctx = release_bridge_ctx();
    let mut cfg = pinned_config();
    cfg.token_contract = [0u8; 20];
    let policy = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None, "e.test", 12);
    let err = policy.assert_valid_for_build(&ctx).unwrap_err();
    assert!(err.contains("TOKEN_CONTRACT"), "got: {err}");
}

#[test]
fn production_rejects_btc_relay_mode_none() {
    // `none` is only for a local stand with no BtcRelay.
    let ctx = release_bridge_ctx();
    let mut cfg = pinned_config();
    cfg.btc_relay_mode = BtcRelayMode::None;
    let policy = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None, "e.test", 12);
    let err = policy.assert_valid_for_build(&ctx).unwrap_err();
    assert!(err.contains("BTC_RELAY_MODE=none"), "got: {err}");
}

/// The default is `required`, so a production config boots without the env var.
#[test]
fn production_defaults_to_btc_relay_required() {
    let ctx = release_bridge_ctx();
    let policy = with_role(SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::PinnedTlsRpc,
        a_tls_pin(),
        "e.test",
        12,
    ));
    match &policy {
        SecurityPolicy::Production(p) => assert!(p.btc_relay_required),
        other => panic!("expected Production, got {other:?}"),
    }
    assert!(policy.assert_valid_for_build(&ctx).is_ok());
}

/// A debug build uses the env value and does not gate on it: the policy is
/// `Development`.
#[test]
fn dev_build_ignores_btc_relay_mode_for_the_boot_gate() {
    let ctx = BuildContext {
        debug_or_test: true,
        ..release_bridge_ctx()
    };
    let mut cfg = pinned_config();
    cfg.btc_relay_mode = BtcRelayMode::None;
    let policy = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None, "e.test", 12);
    assert!(matches!(policy, SecurityPolicy::Development { .. }));
    assert!(policy.assert_valid_for_build(&ctx).is_ok());
}

#[test]
fn token_contract_is_carried_into_the_commitment() {
    let ctx = release_bridge_ctx();
    let base = pinned_config();
    let mut other = base.clone();
    other.token_contract = [0x44; 20];
    assert_ne!(
        SecurityPolicy::resolve(&ctx, &base, EvmDataSource::RawRpc, None, "e.test", 12)
            .commitment_bytes(),
        SecurityPolicy::resolve(&ctx, &other, EvmDataSource::RawRpc, None, "e.test", 12)
            .commitment_bytes(),
        "re-pinning TOKEN_CONTRACT must change the attested commitment"
    );
}

#[test]
fn deposit_authorization_rule_is_carried_into_the_commitment() {
    let ctx = release_bridge_ctx();
    let base = pinned_config();
    let mut other_emitter = base.clone();
    other_emitter.funds_in_contract = [0x33; 20];
    let expected = SecurityPolicy::resolve(&ctx, &base, EvmDataSource::RawRpc, None, "e.test", 12);
    let changed_emitter = SecurityPolicy::resolve(
        &ctx,
        &other_emitter,
        EvmDataSource::RawRpc,
        None,
        "e.test",
        12,
    );
    let changed_depth =
        SecurityPolicy::resolve(&ctx, &base, EvmDataSource::RawRpc, None, "e.test", 13);

    assert_ne!(
        expected.commitment_bytes(),
        changed_emitter.commitment_bytes()
    );
    assert_ne!(
        expected.commitment_bytes(),
        changed_depth.commitment_bytes()
    );
}

#[test]
fn release_bridge_unconfigured_is_rejected_at_boot() {
    let ctx = release_bridge_ctx();
    let p = SecurityPolicy::resolve(
        &ctx,
        &BridgeConfig::default(),
        EvmDataSource::RawRpc,
        None,
        "e.test",
        12,
    );
    assert_eq!(
        p,
        SecurityPolicy::Development {
            reason: DevReason::Unconfigured
        }
    );
    // A misconfigured production build never boots.
    let err = p.assert_valid_for_build(&ctx).unwrap_err();
    assert!(err.contains("Unconfigured"), "got: {err}");
}

#[test]
fn release_bridge_partially_pinned_is_rejected_at_boot() {
    let ctx = release_bridge_ctx();
    let partial = BridgeConfig {
        chain_id: 1,
        ..Default::default()
    };
    let p = SecurityPolicy::resolve(&ctx, &partial, EvmDataSource::RawRpc, None, "e.test", 12);
    assert!(matches!(p, SecurityPolicy::Development { .. }));
    assert!(p.assert_valid_for_build(&ctx).is_err());
}

#[test]
fn each_dev_feature_forces_development_even_when_fully_pinned() {
    let base = release_bridge_ctx();
    let cases = [
        (
            BuildContext {
                mock_attestation: true,
                ..base
            },
            DevReason::MockAttestation,
        ),
        (
            BuildContext {
                allow_seed_import: true,
                ..base
            },
            DevReason::AllowSeedImport,
        ),
    ];
    for (ctx, reason) in cases {
        let p = SecurityPolicy::resolve(
            &ctx,
            &pinned_config(),
            EvmDataSource::PinnedTlsRpc,
            a_tls_pin(),
            "e.test",
            12,
        );
        assert_eq!(p, SecurityPolicy::Development { reason });
        // Fully pinned, a dev feature in a release rgb build still does not boot.
        assert!(p.assert_valid_for_build(&ctx).is_err());
    }
}

#[test]
fn debug_build_is_development_and_exempt_from_the_boot_gate() {
    let ctx = BuildContext {
        debug_or_test: true,
        ..release_bridge_ctx()
    };
    let p = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::RawRpc,
        None,
        "e.test",
        12,
    );
    assert_eq!(
        p,
        SecurityPolicy::Development {
            reason: DevReason::DebugBuild
        }
    );
    assert!(p.assert_valid_for_build(&ctx).is_ok());
}

#[test]
fn minimal_non_bridge_release_is_exempt() {
    let ctx = BuildContext {
        rgb_validation: false,
        ..release_bridge_ctx()
    };
    let p = SecurityPolicy::resolve(
        &ctx,
        &BridgeConfig::default(),
        EvmDataSource::Disabled,
        None,
        "e.test",
        0,
    );
    assert_eq!(
        p,
        SecurityPolicy::Development {
            reason: DevReason::NonBridgeBuild
        }
    );
    // No bridge path, so the boot gate passes.
    assert!(p.assert_valid_for_build(&ctx).is_ok());
}

#[test]
fn allow_vanilla_psbt_tracks_the_btc_pins() {
    let ctx = release_bridge_ctx();
    let mut cfg = pinned_config();
    // Unset BTC pins: vanilla is off.
    let p = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None, "e.test", 12);
    assert!(matches!(
        p,
        SecurityPolicy::Production(ProductionPolicy {
            allow_vanilla_psbt: false,
            ..
        })
    ));
    // With the cap set, vanilla is on and attested.
    cfg.btc_max_total_sats = 100_000;
    let p = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None, "e.test", 12);
    assert!(matches!(
        p,
        SecurityPolicy::Production(ProductionPolicy {
            allow_vanilla_psbt: true,
            ..
        })
    ));
}

#[test]
fn gas_tx_rule_is_carried_into_the_commitment() {
    // The gas-tx pins change the commitment.
    let ctx = release_bridge_ctx();
    let unpinned = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::RawRpc,
        None,
        "e.test",
        12,
    );

    let mut cfg = pinned_config();
    cfg.gas_tx_allowed_to = Some([0x77; 20]);
    cfg.gas_tx_max_gas_limit = 30_000;
    cfg.gas_tx_max_fee_per_gas = 5_000;
    cfg.gas_tx_max_value_wei = Some(9_000);
    cfg.gas_tx_allowed_selectors = vec![[0xaa, 0xbb, 0xcc, 0xdd]];
    let pinned = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None, "e.test", 12);

    assert_ne!(
        unpinned.commitment_bytes(),
        pinned.commitment_bytes(),
        "pinning the gas-tx rule must change the attested commitment"
    );
    match &pinned {
        SecurityPolicy::Production(p) => {
            assert_eq!(p.gas_tx_allowed_to, Some([0x77; 20]));
            assert_eq!(p.gas_tx_max_gas_limit, 30_000);
            assert_eq!(p.gas_tx_max_fee_per_gas, 5_000);
            assert_eq!(p.gas_tx_max_value_wei, Some(9_000));
            assert_eq!(p.gas_tx_allowed_selectors, vec![[0xaa, 0xbb, 0xcc, 0xdd]]);
        }
        other => panic!("expected Production, got {other:?}"),
    }
}

#[test]
fn gas_tx_value_ceiling_alone_changes_the_commitment() {
    // The LayerZero value cap is part of the attested gas-tx rule.
    let ctx = release_bridge_ctx();
    let mut base = pinned_config();
    base.gas_tx_allowed_to = Some([0x77; 20]);
    base.gas_tx_max_gas_limit = 30_000;
    base.gas_tx_max_fee_per_gas = 5_000;
    base.gas_tx_allowed_selectors = vec![[0xaa, 0xbb, 0xcc, 0xdd]];

    let mut raised = base.clone();
    raised.gas_tx_max_value_wei = Some(1);

    assert_ne!(
        SecurityPolicy::resolve(&ctx, &base, EvmDataSource::RawRpc, None, "e.test", 12)
            .commitment_bytes(),
        SecurityPolicy::resolve(&ctx, &raised, EvmDataSource::RawRpc, None, "e.test", 12)
            .commitment_bytes(),
        "raising GAS_TX_MAX_VALUE_WEI must change the attested commitment"
    );
}

#[test]
fn unset_gas_tx_value_ceiling_commits_as_zero() {
    // `None` and `Some(0)` enforce the same rule, so they commit the same bytes.
    let ctx = release_bridge_ctx();
    let mut unset = pinned_config();
    unset.gas_tx_max_value_wei = None;
    let mut zero = pinned_config();
    zero.gas_tx_max_value_wei = Some(0);

    assert_eq!(
        SecurityPolicy::resolve(&ctx, &unset, EvmDataSource::RawRpc, None, "e.test", 12)
            .commitment_bytes(),
        SecurityPolicy::resolve(&ctx, &zero, EvmDataSource::RawRpc, None, "e.test", 12)
            .commitment_bytes(),
    );
}

#[test]
fn evm_source_is_carried_into_the_commitment() {
    let ctx = release_bridge_ctx();
    let raw = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::RawRpc,
        None,
        "e.test",
        12,
    );
    let disabled = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::Disabled,
        None,
        "e.test",
        12,
    );
    assert_ne!(raw.commitment_bytes(), disabled.commitment_bytes());
}

#[test]
fn development_commitment_is_stable_and_distinct() {
    let dev_a = SecurityPolicy::Development {
        reason: DevReason::DebugBuild,
    };
    let dev_b = SecurityPolicy::Development {
        reason: DevReason::MockAttestation,
    };
    // The reason is for logs only. It is not in the commitment.
    assert_eq!(dev_a.commitment_bytes(), dev_b.commitment_bytes());
    assert_ne!(
        dev_a.commitment_bytes(),
        SecurityPolicy::resolve(
            &release_bridge_ctx(),
            &pinned_config(),
            EvmDataSource::RawRpc,
            None,
            "e.test",
            12,
        )
        .commitment_bytes()
    );
}

#[test]
fn with_kms_is_committed_in_production_only() {
    let pin = Some(KmsPin {
        key_arn: "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef"
            .into(),
        region: "eu-west-1".into(),
        seed_id: "seed".into(),
        expected_evm_address: None,
    });
    let prod = SecurityPolicy::resolve(
        &release_bridge_ctx(),
        &pinned_config(),
        EvmDataSource::RawRpc,
        None,
        "e.test",
        12,
    );
    let pinned = prod.clone().with_kms(pin.clone());
    assert_ne!(prod.commitment_bytes(), pinned.commitment_bytes());
    assert!(matches!(pinned.attested(), AttestedPolicy::Production { kms, .. } if kms == pin));
    let dev = SecurityPolicy::Development {
        reason: DevReason::DebugBuild,
    };
    assert_eq!(dev.clone().with_kms(pin), dev);
}

/// Issue #270: a cloning role (burn, combined) launches only on an instance
/// with an IAM role. An all-zero or unread PCR3 refuses `SetEndpoints`.
#[test]
fn a_cloning_role_needs_a_non_zero_pcr3_to_launch() {
    for signer_role in [SignerRole::Burn, SignerRole::Combined] {
        let ctx = BuildContext {
            signer_role,
            ..release_bridge_ctx()
        };
        let resolve = || {
            SecurityPolicy::resolve(
                &ctx,
                &pinned_config(),
                EvmDataSource::PinnedTlsRpc,
                a_tls_pin(),
                "e.test",
                12,
            )
        };
        let unread = resolve();
        let err = unread.assert_valid_for_build(&ctx).unwrap_err();
        assert!(err.contains("no IAM role"), "{signer_role:?}: {err}");

        let zero = resolve().with_clone_peer_pcr3(|| Ok([0; 48])).unwrap();
        let err = zero.assert_valid_for_build(&ctx).unwrap_err();
        assert!(err.contains("no IAM role"), "{signer_role:?}: {err}");

        let role = with_role(resolve());
        assert!(role.assert_valid_for_build(&ctx).is_ok(), "{signer_role:?}");
        let SecurityPolicy::Production(p) = role else {
            panic!("expected Production")
        };
        assert_eq!(p.clone_peer_pcr3, Some(ROLE_PCR3));
    }
}

/// A failed PCR3 read refuses the launch.
#[test]
fn a_failed_pcr3_read_refuses_the_launch() {
    let ctx = BuildContext {
        signer_role: SignerRole::Burn,
        ..release_bridge_ctx()
    };
    let p = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::PinnedTlsRpc,
        a_tls_pin(),
        "e.test",
        12,
    );
    assert!(p
        .with_clone_peer_pcr3(|| Err(crate::error::EnclaveError::Attestation("nsm".into())))
        .is_err());
}

/// The mint signer refuses cloning, so it does not read PCR3 and launches
/// without an IAM role.
#[test]
fn the_mint_signer_does_not_read_pcr3() {
    let ctx = BuildContext {
        signer_role: SignerRole::Mint,
        ..release_bridge_ctx()
    };
    let p = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::PinnedTlsRpc,
        a_tls_pin(),
        "e.test",
        12,
    )
    .with_clone_peer_pcr3(|| panic!("the mint signer must not read PCR3"))
    .unwrap();
    assert!(p.assert_valid_for_build(&ctx).is_ok());
    let SecurityPolicy::Production(pp) = &p else {
        panic!("expected Production")
    };
    assert_eq!(pp.clone_peer_pcr3, None);
}

/// The clone-peer PCR3 is in the commitment: two instances under different
/// IAM roles attest different policies.
#[test]
fn the_clone_peer_pcr3_is_attested() {
    let ctx = BuildContext {
        signer_role: SignerRole::Burn,
        ..release_bridge_ctx()
    };
    let resolve = |pcr3: [u8; 48]| {
        SecurityPolicy::resolve(
            &ctx,
            &pinned_config(),
            EvmDataSource::PinnedTlsRpc,
            a_tls_pin(),
            "e.test",
            12,
        )
        .with_clone_peer_pcr3(|| Ok(pcr3))
        .unwrap()
    };
    let a = resolve(ROLE_PCR3);
    assert!(matches!(
        a.attested(),
        AttestedPolicy::Production {
            clone_peer_pcr3: Some(ROLE_PCR3),
            ..
        }
    ));
    assert_ne!(a.commitment_bytes(), resolve([0x44; 48]).commitment_bytes());
}

/// A development policy keeps no PCR3 and does not read it.
#[test]
fn a_development_policy_does_not_read_pcr3() {
    let ctx = BuildContext {
        debug_or_test: true,
        signer_role: SignerRole::Burn,
        ..release_bridge_ctx()
    };
    let p = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::Disabled, None, "", 0)
        .with_clone_peer_pcr3(|| panic!("a development policy must not read PCR3"))
        .unwrap();
    assert!(matches!(p, SecurityPolicy::Development { .. }));
}
