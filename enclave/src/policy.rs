//! The enclave's single, explicit security posture (audit C-01).
//!
//! [`SecurityPolicy`] holds the whole posture as one object, resolved once at
//! boot by [`SecurityPolicy::resolve`], rather than reconstructing it at
//! runtime from build features, [`BridgeConfig`] fields, and request shape. It
//! is:
//!
//!   * fail-closed: a release `rgb-validation` build that does not resolve to a
//!     valid [`SecurityPolicy::Production`] refuses to boot
//!     ([`SecurityPolicy::assert_valid_for_build`]);
//!   * attested: [`SecurityPolicy::commitment_bytes`] is folded into the
//!     attestation `user_data` commitment, so a verifier checks the posture as
//!     a single value;
//!   * authoritative: handlers consult it instead of re-deriving posture from
//!     features and empty fields.
//!
//! Resolution and the boot gate take an explicit [`BuildContext`], so release
//! behaviour is unit-testable without a release build.

use crate::config::BridgeConfig;

pub use attestation_verify::{AttestationMode, AttestedPolicy, BtcDataSource, EvmDataSource};

/// The enclave's resolved security posture. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityPolicy {
    /// A fully-pinned, fail-closed bridge-signing enclave.
    Production(ProductionPolicy),
    /// Anything that is not a production bridge signer: a debug build, a dev
    /// feature, a non-bridge build, or an unpinned config. Carries the reason so
    /// boot logs and the fail-closed panic say *why*.
    Development { reason: DevReason },
}

/// The pinned facts and enabled modes of a production bridge-signing enclave
/// (audit C-01): signing modes, chain/contract/asset pins, expected attestation
/// values, and allowed data sources, all committed into attestation
/// `user_data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPolicy {
    /// Pinned EVM chain id (`EVM_CHAIN_ID`).
    pub chain_id: u64,
    /// Pinned bridge (MultisigProxy) contract (`BRIDGE_CONTRACT`).
    pub bridge_contract: [u8; 20],
    /// Pinned RGB asset id (`RGB_ASSET_ID`).
    pub rgb_asset_id: String,
    /// Whether the plain-BTC (vanilla / create_utxo) signing path is authorised.
    /// Derived from the operator's `BTC_MAX_TOTAL_SATS` pin
    /// ([`BridgeConfig::allows_vanilla_btc`]); default fail-closed (false).
    pub allow_vanilla_psbt: bool,
    /// Expected attestation root of trust. Always [`AttestationMode::Real`] in a
    /// production build (mock is a `compile_error!` in release - see `lib.rs`).
    pub attestation: AttestationMode,
    /// EVM `FundsIn` deposit-verification source (raw RPC vs Helios-verified vs
    /// disabled). Recorded and attested so a verifier can tell a trustless
    /// deployment apart from a host-relayed one.
    pub evm_source: EvmDataSource,
    /// The Helios weak-subjectivity checkpoint (beacon block root) EVM
    /// verification trust-roots on. `Some`, and required, only when
    /// `evm_source` is [`EvmDataSource::HeliosVerified`]. Attested so a verifier
    /// confirms which checkpoint the enclave synced from (audit M-06).
    pub evm_checkpoint: Option<[u8; 32]>,
    /// Bitcoin anchor-verification source. Always SPV in a production build.
    pub btc_source: BtcDataSource,
    /// Gas-tx (`SignRawDigest`) allowed destination (`GAS_TX_ALLOWED_TO`), or
    /// `None` when unset, which fails the gas path closed per request. Attested
    /// as all-zero when `None` (audit C-02). See `networks::evm::gas_tx`.
    pub gas_tx_allowed_to: Option<[u8; 20]>,
    /// Gas-tx `gasLimit` ceiling (`GAS_TX_MAX_GAS_LIMIT`; 0 = unset -> fail closed).
    pub gas_tx_max_gas_limit: u64,
    /// Gas-tx per-gas fee ceiling in wei (`GAS_TX_MAX_FEE_PER_GAS`; 0 = unset ->
    /// fail closed).
    pub gas_tx_max_fee_per_gas: u128,
    /// Gas-tx native-value ceiling in wei (`GAS_TX_MAX_VALUE_WEI`) for the
    /// payable `lzFundsOutCall` carve-out, or `None` when unset, which makes no
    /// non-zero value signable. Attested as 0 when `None`.
    pub gas_tx_max_value_wei: Option<u128>,
    /// Gas-tx calldata selector allowlist (`GAS_TX_ALLOWED_SELECTORS`).
    pub gas_tx_allowed_selectors: Vec<[u8; 4]>,
}

/// Why an enclave resolved to [`SecurityPolicy::Development`] rather than
/// production. Included in boot logs and the fail-closed panic message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevReason {
    /// Built with `debug_assertions` (or under `cfg(test)`).
    DebugBuild,
    /// `dev-mode` feature: every signing cross-check is skipped.
    DevMode,
    /// `mock-attestation` feature: zero-PCR attestation documents.
    MockAttestation,
    /// `allow-seed-import` feature: the parent can install a chosen seed.
    AllowSeedImport,
    /// A non-bridge build (`rgb-validation` off): no bridge-signing path exists.
    NonBridgeBuild,
    /// A bridge build whose chain/contract/asset pins are not fully set.
    Unconfigured,
}

/// Compile-time posture inputs, captured so [`SecurityPolicy::resolve`] and
/// [`SecurityPolicy::assert_valid_for_build`] are pure and unit-testable. The
/// real values come from [`BuildContext::current`]; tests construct arbitrary
/// contexts to exercise the release paths.
#[derive(Clone, Copy, Debug)]
pub struct BuildContext {
    /// `cfg!(debug_assertions) || cfg!(test)` - the "not a release build" signal.
    pub debug_or_test: bool,
    pub dev_mode: bool,
    pub mock_attestation: bool,
    pub allow_seed_import: bool,
    /// `rgb-validation`: the feature that turns on bridge signing. A release
    /// build with this on is the one the production policy must protect.
    pub rgb_validation: bool,
}

impl BuildContext {
    /// The current build's posture inputs, read from `cfg!`.
    pub fn current() -> Self {
        Self {
            debug_or_test: cfg!(debug_assertions) || cfg!(test),
            dev_mode: cfg!(feature = "dev-mode"),
            mock_attestation: cfg!(feature = "mock-attestation"),
            allow_seed_import: cfg!(feature = "allow-seed-import"),
            rgb_validation: cfg!(feature = "rgb-validation"),
        }
    }
}

impl SecurityPolicy {
    /// Resolve the single security posture from the build context, the pinned
    /// [`BridgeConfig`], and the EVM data source selected at boot.
    ///
    /// Fail-closed by construction: any dev feature, a debug/test build, a
    /// non-bridge build, or an unpinned config yields
    /// [`SecurityPolicy::Development`]. Only a release bridge build with all
    /// three pins set becomes [`SecurityPolicy::Production`].
    pub fn resolve(
        ctx: &BuildContext,
        bridge: &BridgeConfig,
        evm_source: EvmDataSource,
        evm_checkpoint: Option<[u8; 32]>,
    ) -> Self {
        // Any dev feature collapses the posture regardless of everything else.
        // (These are `compile_error!` in a release build - lib.rs - so in a real
        // production binary they are all false; the checks make dev/test builds
        // resolve honestly and keep this function total.)
        if ctx.dev_mode {
            return Self::dev(DevReason::DevMode);
        }
        if ctx.mock_attestation {
            return Self::dev(DevReason::MockAttestation);
        }
        if ctx.allow_seed_import {
            return Self::dev(DevReason::AllowSeedImport);
        }
        if ctx.debug_or_test {
            return Self::dev(DevReason::DebugBuild);
        }
        // Release build from here.
        if !ctx.rgb_validation {
            // No bridge-signing path compiled in: not a production bridge signer.
            return Self::dev(DevReason::NonBridgeBuild);
        }
        if !bridge.is_configured() {
            return Self::dev(DevReason::Unconfigured);
        }
        Self::Production(ProductionPolicy {
            chain_id: bridge.chain_id,
            bridge_contract: bridge.bridge_contract,
            rgb_asset_id: bridge.rgb_asset_id.clone(),
            allow_vanilla_psbt: bridge.allows_vanilla_btc(),
            attestation: AttestationMode::Real,
            evm_source,
            evm_checkpoint,
            // `rgb-validation` implies `spv` (lib.rs `compile_error!`), so a
            // bridge build always anchors witness txs via the SPV header chain.
            btc_source: BtcDataSource::SpvVerified,
            // Gas-tx rule (audit C-02): reflect the same pins the request-time
            // `validate_gas_tx_request` enforces so the attested commitment and
            // the enforced policy cannot drift.
            gas_tx_allowed_to: bridge.gas_tx_allowed_to,
            gas_tx_max_gas_limit: bridge.gas_tx_max_gas_limit,
            gas_tx_max_fee_per_gas: bridge.gas_tx_max_fee_per_gas,
            gas_tx_max_value_wei: bridge.gas_tx_max_value_wei,
            gas_tx_allowed_selectors: bridge.gas_tx_allowed_selectors.clone(),
        })
    }

    fn dev(reason: DevReason) -> Self {
        Self::Development { reason }
    }

    /// The commitment form folded into attestation `user_data`.
    pub fn attested(&self) -> AttestedPolicy {
        match self {
            Self::Production(p) => AttestedPolicy::Production {
                allow_vanilla_psbt: p.allow_vanilla_psbt,
                attestation: p.attestation,
                evm_source: p.evm_source,
                btc_source: p.btc_source,
                chain_id: p.chain_id,
                bridge_contract: p.bridge_contract,
                rgb_asset_id: p.rgb_asset_id.clone(),
                evm_checkpoint: p.evm_checkpoint,
                // An unset destination commits as all-zero - a value the gas
                // path can never accept - so "unpinned" is itself attested.
                gas_tx_allowed_to: p.gas_tx_allowed_to.unwrap_or([0u8; 20]),
                gas_tx_max_gas_limit: p.gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas: p.gas_tx_max_fee_per_gas,
                // Same rule as the destination: an unset ceiling commits as 0,
                // which is exactly the posture it enforces (no non-zero value
                // is signable), so "unpinned" is itself attested.
                gas_tx_max_value_wei: p.gas_tx_max_value_wei.unwrap_or(0),
                gas_tx_allowed_selectors: p.gas_tx_allowed_selectors.clone(),
            },
            Self::Development { .. } => AttestedPolicy::Development,
        }
    }

    /// Canonical bytes appended to the attestation commitment preimage. Mirrored
    /// by every verifier via [`attestation_verify::AttestedPolicy::to_bytes`].
    pub fn commitment_bytes(&self) -> Vec<u8> {
        self.attested().to_bytes()
    }

    /// Fail-closed boot gate. A release bridge-signing (`rgb-validation`) build
    /// MUST resolve to a valid [`SecurityPolicy::Production`]; otherwise the
    /// enclave refuses to become reachable (the caller `panic!`s at boot, the
    /// same way a placeholder SPV checkpoint does).
    ///
    /// Debug/test builds and non-bridge builds are exempt - they have no
    /// production bridge-signing path to protect.
    pub fn assert_valid_for_build(&self, ctx: &BuildContext) -> Result<(), String> {
        if ctx.debug_or_test || !ctx.rgb_validation {
            return Ok(());
        }
        match self {
            Self::Production(p) => p.check_invariants(),
            Self::Development { reason } => Err(format!(
                "release rgb-validation (bridge-signing) build resolved to a non-production \
                 security policy ({reason:?}); refusing to boot. A production bridge enclave must \
                 pin EVM_CHAIN_ID / BRIDGE_CONTRACT / RGB_ASSET_ID and be built without any dev \
                 feature (dev-mode / mock-attestation / allow-seed-import). See audit C-01."
            )),
        }
    }
}

impl ProductionPolicy {
    /// Invariants that must hold before a production enclave signs anything.
    /// Both evidence sources must be trustless: Bitcoin anchors via SPV, EVM
    /// FundsIn deposits via Helios. `RawRpc`/`Disabled` are rejected (audit #77).
    pub fn check_invariants(&self) -> Result<(), String> {
        if self.chain_id == 0 || self.bridge_contract == [0u8; 20] || self.rgb_asset_id.is_empty() {
            return Err(
                "production policy is missing one or more of the chain/contract/asset pins".into(),
            );
        }
        if self.attestation != AttestationMode::Real {
            return Err(
                "production policy must use real (NSM) attestation, not the mock path".into(),
            );
        }
        if self.btc_source != BtcDataSource::SpvVerified {
            return Err(
                "production policy must anchor Bitcoin witness txs via the SPV header chain".into(),
            );
        }
        if self.evm_source != EvmDataSource::HeliosVerified {
            return Err(format!(
                "production policy must verify EVM FundsIn via the trustless Helios path, not \
                 {:?}. Build with `--features helios` and set HELIOS_EXECUTION_RPC. See #77.",
                self.evm_source
            ));
        }
        // Helios's trust root MUST be pinned and attested (audit M-06): without a
        // checkpoint the light client would bootstrap from an untrusted source,
        // and a verifier could not tell which chain the enclave synced. Fail
        // closed at boot rather than attesting Helios mode with no trust root.
        if self.evm_checkpoint.is_none() {
            return Err(
                "production policy uses the Helios EVM source but pins no weak-subjectivity \
                 checkpoint. Set HELIOS_CHECKPOINT to a recent beacon block root so the trust \
                 root is fixed and attested (audit M-06)."
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A build context for a clean release bridge build (no dev features).
    fn release_bridge_ctx() -> BuildContext {
        BuildContext {
            debug_or_test: false,
            dev_mode: false,
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
    fn production_requires_the_trustless_helios_evm_source() {
        let ctx = release_bridge_ctx();
        // Non-Helios sources still resolve to Production (recorded + attested)
        // but must not pass the boot gate.
        for source in [EvmDataSource::Disabled, EvmDataSource::RawRpc] {
            let p = SecurityPolicy::resolve(&ctx, &pinned_config(), source, None);
            assert!(
                matches!(p, SecurityPolicy::Production(_)),
                "expected Production for {source:?}"
            );
            let err = p.assert_valid_for_build(&ctx).unwrap_err();
            assert!(err.contains("Helios"), "got: {err}");
        }
        // Only Helios-verified WITH a pinned checkpoint passes the boot gate.
        let p = SecurityPolicy::resolve(
            &ctx,
            &pinned_config(),
            EvmDataSource::HeliosVerified,
            a_checkpoint(),
        );
        assert!(p.assert_valid_for_build(&ctx).is_ok());
    }

    #[test]
    fn production_helios_without_a_pinned_checkpoint_is_rejected_at_boot() {
        // M-06: Helios is the trustless source, but with no weak-subjectivity
        // checkpoint its trust root is unpinned and unattested. Such a build
        // resolves to Production (so the missing pin is visible) but must NOT
        // pass the boot gate.
        let ctx = release_bridge_ctx();
        let p =
            SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::HeliosVerified, None);
        assert!(matches!(p, SecurityPolicy::Production(_)));
        let err = p.assert_valid_for_build(&ctx).unwrap_err();
        assert!(err.contains("checkpoint"), "got: {err}");
    }

    #[test]
    fn release_bridge_unconfigured_is_rejected_at_boot() {
        let ctx = release_bridge_ctx();
        let p =
            SecurityPolicy::resolve(&ctx, &BridgeConfig::default(), EvmDataSource::RawRpc, None);
        assert_eq!(
            p,
            SecurityPolicy::Development {
                reason: DevReason::Unconfigured
            }
        );
        // The whole point of C-01: a misconfigured production build never boots.
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
        let p = SecurityPolicy::resolve(&ctx, &partial, EvmDataSource::RawRpc, None);
        assert!(matches!(p, SecurityPolicy::Development { .. }));
        assert!(p.assert_valid_for_build(&ctx).is_err());
    }

    #[test]
    fn each_dev_feature_forces_development_even_when_fully_pinned() {
        let base = release_bridge_ctx();
        let cases = [
            (
                BuildContext {
                    dev_mode: true,
                    ..base
                },
                DevReason::DevMode,
            ),
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
        let p = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::RawRpc, None);
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
        let p = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None);
        assert!(matches!(
            p,
            SecurityPolicy::Production(ProductionPolicy {
                allow_vanilla_psbt: false,
                ..
            })
        ));
        // Operator sets the cap -> vanilla enabled and attested.
        cfg.btc_max_total_sats = 100_000;
        let p = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None);
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
        // The gas-tx pins (audit C-02) flow from BridgeConfig into the attested
        // policy, so pinning them changes the commitment a verifier checks.
        let ctx = release_bridge_ctx();
        let unpinned = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::RawRpc, None);

        let mut cfg = pinned_config();
        cfg.gas_tx_allowed_to = Some([0x77; 20]);
        cfg.gas_tx_max_gas_limit = 30_000;
        cfg.gas_tx_max_fee_per_gas = 5_000;
        cfg.gas_tx_max_value_wei = Some(9_000);
        cfg.gas_tx_allowed_selectors = vec![[0xaa, 0xbb, 0xcc, 0xdd]];
        let pinned = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc, None);

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
            SecurityPolicy::resolve(&ctx, &base, EvmDataSource::RawRpc, None).commitment_bytes(),
            SecurityPolicy::resolve(&ctx, &raised, EvmDataSource::RawRpc, None).commitment_bytes(),
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
            SecurityPolicy::resolve(&ctx, &unset, EvmDataSource::RawRpc, None).commitment_bytes(),
            SecurityPolicy::resolve(&ctx, &zero, EvmDataSource::RawRpc, None).commitment_bytes(),
        );
    }

    #[test]
    fn evm_source_is_carried_into_the_commitment() {
        let ctx = release_bridge_ctx();
        let raw = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::RawRpc, None);
        let helios = SecurityPolicy::resolve(
            &ctx,
            &pinned_config(),
            EvmDataSource::HeliosVerified,
            a_checkpoint(),
        );
        // A raw-RPC deployment and a Helios deployment commit to different bytes,
        // so a verifier expecting one rejects the other (audit C-01 data source).
        assert_ne!(raw.commitment_bytes(), helios.commitment_bytes());
    }

    #[test]
    fn evm_checkpoint_is_carried_into_the_commitment() {
        // M-06: two Helios deployments identical except for the pinned checkpoint
        // commit different bytes, so a verifier bound to one trust root rejects
        // an enclave that synced from another.
        let ctx = release_bridge_ctx();
        let a = SecurityPolicy::resolve(
            &ctx,
            &pinned_config(),
            EvmDataSource::HeliosVerified,
            Some([0xAA; 32]),
        );
        let b = SecurityPolicy::resolve(
            &ctx,
            &pinned_config(),
            EvmDataSource::HeliosVerified,
            Some([0xBB; 32]),
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
            )
            .commitment_bytes()
        );
    }
}
