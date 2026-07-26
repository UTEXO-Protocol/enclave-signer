//! The enclave's single, explicit security posture (audit C-01).
//!
//! Before this module the posture was reconstructed at runtime from several
//! independent conditions — build features, the presence/absence of
//! [`BridgeConfig`] fields, request shape, and which chain-verification
//! components happened to be wired up. A verifier could not read the posture as
//! one value, and an unsafe build/deployment combination could become active.
//!
//! [`SecurityPolicy`] collapses all of that into ONE object, resolved once at
//! boot by [`SecurityPolicy::resolve`]:
//!
//!   * it is **fail-closed**: a release bridge-signing (`rgb-validation`) build
//!     that does not resolve to a valid [`SecurityPolicy::Production`] refuses to
//!     boot ([`SecurityPolicy::assert_valid_for_build`]);
//!   * it is **attested**: [`SecurityPolicy::commitment_bytes`] is folded into
//!     the attestation `user_data` commitment (see
//!     `server::handle_get_attested_public_key`), so a verifier checks the whole
//!     posture as a single value against its expected production policy;
//!   * it is **authoritative**: request handlers consult it (e.g. the plain-BTC
//!     path checks [`ProductionPolicy::allow_vanilla_psbt`]) instead of
//!     re-deriving posture from features and empty fields.
//!
//! Resolution and the boot gate are split into pure functions taking an explicit
//! [`BuildContext`] so the release behaviour is unit-testable without actually
//! being a release build (the same split `config.rs` uses for
//! `production_readiness_error` vs `assert_configured_in_release`).

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

/// The pinned facts and enabled modes of a production bridge-signing enclave.
/// Mirrors the recommendation in audit C-01: signing modes, the
/// chain/contract/asset pins, the expected attestation values, and the allowed
/// data sources — all in one place, all committed into attestation `user_data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPolicy {
    /// Pinned EVM chain id (`EVM_CHAIN_ID`).
    pub chain_id: u64,
    /// Pinned bridge (MultisigProxy) contract (`BRIDGE_CONTRACT`).
    pub bridge_contract: [u8; 20],
    /// Pinned RGB asset id (`RGB_ASSET_ID`).
    pub rgb_asset_id: String,
    /// Whether the plain-BTC (vanilla / create_utxo) signing path is authorised.
    /// Derived from the operator's `BTC_ALLOWED_SCRIPTS` + `BTC_MAX_TOTAL_SATS`
    /// pins ([`BridgeConfig::allows_vanilla_btc`]); default fail-closed (false).
    pub allow_vanilla_psbt: bool,
    /// Expected attestation root of trust. Always [`AttestationMode::Real`] in a
    /// production build (mock is a `compile_error!` in release — see `lib.rs`).
    pub attestation: AttestationMode,
    /// EVM `FundsIn` deposit-verification source (raw RPC vs Helios-verified vs
    /// disabled). Recorded and attested so a verifier can tell a trustless
    /// deployment apart from a host-relayed one.
    pub evm_source: EvmDataSource,
    /// Bitcoin anchor-verification source. Always SPV in a production build.
    pub btc_source: BtcDataSource,
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
    /// `cfg!(debug_assertions) || cfg!(test)` — the "not a release build" signal.
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
    pub fn resolve(ctx: &BuildContext, bridge: &BridgeConfig, evm_source: EvmDataSource) -> Self {
        // Any dev feature collapses the posture regardless of everything else.
        // (These are `compile_error!` in a release build — lib.rs — so in a real
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
            // `rgb-validation` implies `spv` (lib.rs `compile_error!`), so a
            // bridge build always anchors witness txs via the SPV header chain.
            btc_source: BtcDataSource::SpvVerified,
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
    /// Debug/test builds and non-bridge builds are exempt — they have no
    /// production bridge-signing path to protect. This mirrors the scope of the
    /// old `BridgeConfig::assert_configured_in_release`, which it supersedes.
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
    ///
    /// The EVM data source is deliberately NOT gated here: a `Disabled` source
    /// fails closed *per request* (see `server::handle_sign`) rather than being
    /// unsafe, and its value is attested for the external verifier to check
    /// against the operator's expected posture. What must hold at boot is that
    /// the identity pins are complete, the attestation is real, and Bitcoin
    /// anchors are SPV-verified.
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

    #[test]
    fn release_bridge_with_full_pins_is_production() {
        let p = SecurityPolicy::resolve(
            &release_bridge_ctx(),
            &pinned_config(),
            EvmDataSource::RawRpc,
        );
        match &p {
            SecurityPolicy::Production(pp) => {
                assert_eq!(pp.chain_id, 1);
                assert_eq!(pp.evm_source, EvmDataSource::RawRpc);
                assert_eq!(pp.attestation, AttestationMode::Real);
                assert_eq!(pp.btc_source, BtcDataSource::SpvVerified);
            }
            other => panic!("expected Production, got {other:?}"),
        }
        assert!(p.assert_valid_for_build(&release_bridge_ctx()).is_ok());
    }

    #[test]
    fn release_bridge_unconfigured_is_rejected_at_boot() {
        let ctx = release_bridge_ctx();
        let p = SecurityPolicy::resolve(&ctx, &BridgeConfig::default(), EvmDataSource::RawRpc);
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
        let p = SecurityPolicy::resolve(&ctx, &partial, EvmDataSource::RawRpc);
        assert!(matches!(p, SecurityPolicy::Development { .. }));
        assert!(p.assert_valid_for_build(&ctx).is_err());
    }

    #[test]
    fn each_dev_feature_forces_development_even_when_fully_pinned() {
        let base = release_bridge_ctx();
        for (mutate, reason) in [
            (
                (|c: &mut BuildContext| c.dev_mode = true) as fn(&mut BuildContext),
                DevReason::DevMode,
            ),
            (
                |c: &mut BuildContext| c.mock_attestation = true,
                DevReason::MockAttestation,
            ),
            (
                |c: &mut BuildContext| c.allow_seed_import = true,
                DevReason::AllowSeedImport,
            ),
        ] {
            let mut ctx = base;
            mutate(&mut ctx);
            let p = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::HeliosVerified);
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
        let p = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::RawRpc);
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
        let p = SecurityPolicy::resolve(&ctx, &BridgeConfig::default(), EvmDataSource::Disabled);
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
        let p = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc);
        assert!(matches!(
            p,
            SecurityPolicy::Production(ProductionPolicy {
                allow_vanilla_psbt: false,
                ..
            })
        ));
        // Operator sets the allowlist + cap -> vanilla enabled and attested.
        cfg.btc_allowed_scripts = vec![vec![0x00, 0x14]];
        cfg.btc_max_total_sats = 100_000;
        let p = SecurityPolicy::resolve(&ctx, &cfg, EvmDataSource::RawRpc);
        assert!(matches!(
            p,
            SecurityPolicy::Production(ProductionPolicy {
                allow_vanilla_psbt: true,
                ..
            })
        ));
    }

    #[test]
    fn evm_source_is_carried_into_the_commitment() {
        let ctx = release_bridge_ctx();
        let raw = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::RawRpc);
        let helios = SecurityPolicy::resolve(&ctx, &pinned_config(), EvmDataSource::HeliosVerified);
        // A raw-RPC deployment and a Helios deployment commit to different bytes,
        // so a verifier expecting one rejects the other (audit C-01 data source).
        assert_ne!(raw.commitment_bytes(), helios.commitment_bytes());
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
                EvmDataSource::RawRpc
            )
            .commitment_bytes()
        );
    }
}
