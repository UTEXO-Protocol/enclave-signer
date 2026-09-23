use super::*;

/// A build context for a clean release bridge build (no dev features).
fn release_bridge_ctx() -> BuildContext {
    BuildContext {
        debug_or_test: false,
        mock_attestation: false,
        allow_seed_import: false,
        rgb_validation: true,
    }
}

fn pinned_config() -> BridgeConfig {
    BridgeConfig {
        chain_id: 1,
        bridge_contract: [0x11; 20],
        rgb_asset_id: "rgb:asset".into(),
        funds_in_contract: [0x22; 20],
        ..Default::default()
    }
}

/// A pinned Helios checkpoint for tests that resolve a valid production
/// Helios policy (a real beacon block root is 32 bytes).
fn a_checkpoint() -> Option<[u8; 32]> {
    Some([0x0c; 32])
}

#[test]
fn release_bridge_with_full_pins_is_production() {
    let p = SecurityPolicy::resolve(
        &release_bridge_ctx(),
        &pinned_config(),
        EvmDataSource::HeliosVerified,
        a_checkpoint(),
        12,
    );
    match &p {
        SecurityPolicy::Production(pp) => {
            assert_eq!(pp.chain_id, 1);
            assert_eq!(pp.evm_source, EvmDataSource::HeliosVerified);
            assert_eq!(pp.evm_checkpoint, a_checkpoint());
            assert_eq!(pp.attestation, AttestationMode::Real);
            assert_eq!(pp.btc_source, BtcDataSource::SpvVerified);
        }
        other => panic!("expected Production, got {other:?}"),
    }
    assert!(p.assert_valid_for_build(&release_bridge_ctx()).is_ok());
}

#[test]
fn production_accepts_any_evm_source_but_still_attests_it() {
    let ctx = release_bridge_ctx();
    // Helios has no L2 light client, so an Arbitrum image runs on raw RPC.
    // Every source boots, and each is recorded and attested.
    for source in [EvmDataSource::Disabled, EvmDataSource::RawRpc] {
        let p = SecurityPolicy::resolve(&ctx, &pinned_config(), source, None, 12);
        match &p {
            SecurityPolicy::Production(pp) => assert_eq!(pp.evm_source, source),
            other => panic!("expected Production for {source:?}, got {other:?}"),
        }
        assert!(
            p.assert_valid_for_build(&ctx).is_ok(),
            "{source:?} must not be gated at boot"
        );
    }
    // Helios WITH a pinned checkpoint still passes.
    let p = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::HeliosVerified,
        a_checkpoint(),
        12,
    );
    assert!(p.assert_valid_for_build(&ctx).is_ok());
}

#[test]
fn production_helios_without_a_pinned_checkpoint_is_rejected_at_boot() {
    // Helios is the trustless source, but with no weak-subjectivity
    // checkpoint its trust root is unpinned and unattested. Such a build
    // resolves to Production (so the missing pin is visible) but must NOT
    // pass the boot gate.
    let ctx = release_bridge_ctx();
    let p = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::HeliosVerified,
        None,
        12,
    );
    assert!(matches!(p, SecurityPolicy::Production(_)));
    let err = p.assert_valid_for_build(&ctx).unwrap_err();
    assert!(err.contains("checkpoint"), "got: {err}");
}

#[test]
fn production_rejects_a_zero_confirmation_rule() {
    let ctx = release_bridge_ctx();
    let policy = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::RawRpc, None, 0);
    let err = policy.assert_valid_for_build(&ctx).unwrap_err();
    assert!(err.contains("confirmation"), "got: {err}");
}

#[test]
fn deposit_authorization_rule_is_carried_into_the_commitment() {
    let ctx = release_bridge_ctx();
    let base = pinned_config();
    let mut other_emitter = base.clone();
    other_emitter.funds_in_contract = [0x33; 20];
    let expected = SecurityPolicy::resolve(&ctx, &base, EvmDataSource::RawRpc, None, 12);
    let changed_emitter =
        SecurityPolicy::resolve(&ctx, &other_emitter, EvmDataSource::RawRpc, None, 12);
    let changed_depth = SecurityPolicy::resolve(&ctx, &base, EvmDataSource::RawRpc, None, 13);

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
        12,
    );
    assert_eq!(
        p,
        SecurityPolicy::Development {
            reason: DevReason::Unconfigured
        }
    );
    // The whole point of the policy: a misconfigured production build never boots.
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
    let p = SecurityPolicy::resolve(&ctx, &partial, EvmDataSource::RawRpc, None, 12);
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
            EvmDataSource::HeliosVerified,
            a_checkpoint(),
            12,
        );
        assert_eq!(p, SecurityPolicy::Development { reason });
        // Even fully pinned, a dev feature in a release rgb build must not boot.
        assert!(p.assert_valid_for_build(&ctx).is_err());
    }
}

#[test]
fn debug_build_is_development_and_exempt_from_the_boot_gate() {
    let ctx = BuildContext {
        debug_or_test: true,
        ..release_bridge_ctx()
    };
    let p = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::RawRpc, None, 12);
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
        0,
    );
    assert_eq!(
        p,
        SecurityPolicy::Development {
            reason: DevReason::NonBridgeBuild
        }
    );
    // No bridge path to protect -> the boot gate passes.
    assert!(p.assert_valid_for_build(&ctx).is_ok());
}

#[test]
fn allow_vanilla_psbt_tracks_the_btc_pins() {
    let ctx = release_bridge_ctx();
    let mut cfg = pinned_config();
    // Unset BTC pins -> vanilla disabled (fail-closed).
    let p = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None, 12);
    assert!(matches!(
        p,
        SecurityPolicy::Production(ProductionPolicy {
            allow_vanilla_psbt: false,
            ..
        })
    ));
    // Operator sets the cap -> vanilla enabled and attested.
    cfg.btc_max_total_sats = 100_000;
    let p = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None, 12);
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
    // The gas-tx pins flow from BridgeConfig into the attested
    // policy, so pinning them changes the commitment a verifier checks.
    let ctx = release_bridge_ctx();
    let unpinned = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::RawRpc, None, 12);

    let mut cfg = pinned_config();
    cfg.gas_tx_allowed_to = Some([0x77; 20]);
    cfg.gas_tx_max_gas_limit = 30_000;
    cfg.gas_tx_max_fee_per_gas = 5_000;
    cfg.gas_tx_max_value_wei = Some(9_000);
    cfg.gas_tx_allowed_selectors = vec![[0xaa, 0xbb, 0xcc, 0xdd]];
    let pinned = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None, 12);

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
    // The LayerZero carve-out's bound is part of the attested gas-tx rule:
    // raising it must be visible to a verifier, not a silent config change.
    let ctx = release_bridge_ctx();
    let mut base = pinned_config();
    base.gas_tx_allowed_to = Some([0x77; 20]);
    base.gas_tx_max_gas_limit = 30_000;
    base.gas_tx_max_fee_per_gas = 5_000;
    base.gas_tx_allowed_selectors = vec![[0xaa, 0xbb, 0xcc, 0xdd]];

    let mut raised = base.clone();
    raised.gas_tx_max_value_wei = Some(1);

    assert_ne!(
        SecurityPolicy::resolve(&ctx, &base, EvmDataSource::RawRpc, None, 12).commitment_bytes(),
        SecurityPolicy::resolve(&ctx, &raised, EvmDataSource::RawRpc, None, 12).commitment_bytes(),
        "raising GAS_TX_MAX_VALUE_WEI must change the attested commitment"
    );
}

#[test]
fn unset_gas_tx_value_ceiling_commits_as_zero() {
    // `None` and `Some(0)` enforce the same posture - no non-zero value is
    // signable - so they must commit identically rather than let an operator
    // produce two different attestations for one enforced rule.
    let ctx = release_bridge_ctx();
    let mut unset = pinned_config();
    unset.gas_tx_max_value_wei = None;
    let mut zero = pinned_config();
    zero.gas_tx_max_value_wei = Some(0);

    assert_eq!(
        SecurityPolicy::resolve(&ctx, &unset, EvmDataSource::RawRpc, None, 12).commitment_bytes(),
        SecurityPolicy::resolve(&ctx, &zero, EvmDataSource::RawRpc, None, 12).commitment_bytes(),
    );
}

#[test]
fn evm_source_is_carried_into_the_commitment() {
    let ctx = release_bridge_ctx();
    let raw = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::RawRpc, None, 12);
    let helios = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::HeliosVerified,
        a_checkpoint(),
        12,
    );
    // A raw-RPC deployment and a Helios deployment commit to different bytes,
    // so a verifier expecting one rejects the other (data source).
    assert_ne!(raw.commitment_bytes(), helios.commitment_bytes());
}

#[test]
fn evm_checkpoint_is_carried_into_the_commitment() {
    // Two Helios deployments identical except for the pinned checkpoint
    // commit different bytes, so a verifier bound to one trust root rejects
    // an enclave that synced from another.
    let ctx = release_bridge_ctx();
    let a = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::HeliosVerified,
        Some([0xAA; 32]),
        12,
    );
    let b = SecurityPolicy::resolve(
        &ctx,
        &pinned_config(),
        EvmDataSource::HeliosVerified,
        Some([0xBB; 32]),
        12,
    );
    assert_ne!(a.commitment_bytes(), b.commitment_bytes());
}

#[test]
fn development_commitment_is_stable_and_distinct() {
    let dev_a = SecurityPolicy::Development {
        reason: DevReason::DebugBuild,
    };
    let dev_b = SecurityPolicy::Development {
        reason: DevReason::MockAttestation,
    };
    // The reason is for logs only; it is NOT part of the commitment, so any
    // Development enclave commits the same bytes a verifier can reconstruct.
    assert_eq!(dev_a.commitment_bytes(), dev_b.commitment_bytes());
    assert_ne!(
        dev_a.commitment_bytes(),
        SecurityPolicy::resolve(
            &release_bridge_ctx(),
            &pinned_config(),
            EvmDataSource::RawRpc,
            None,
            12,
        )
        .commitment_bytes()
    );
}
