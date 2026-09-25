//! The enclave's single, explicit security posture.
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

pub use attestation_verify::{
    AttestationMode, AttestedPolicy, BtcDataSource, EvmDataSource, SignerRole,
};

/// The enclave's resolved security posture. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
// Resolved once at boot and committed to attestation user_data; the size
// difference between the variants costs nothing here.
#[allow(clippy::large_enum_variant)]
pub enum SecurityPolicy {
    /// A fully-pinned, fail-closed bridge-signing enclave.
    Production(ProductionPolicy),
    /// Anything that is not a production bridge signer: a debug build, a dev
    /// feature, a non-bridge build, or an unpinned config. Carries the reason so
    /// boot logs and the fail-closed panic say *why*.
    Development { reason: DevReason },
}

/// The pinned facts and enabled modes of a production bridge-signing enclave:
/// signing modes, chain/contract/asset pins, expected attestation
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
    /// Only this contract's FundsIn events may authorize bridge signing.
    pub funds_in_contract: [u8; 20],
    /// Minimum receipt depth required before a FundsIn deposit is accepted.
    pub evm_min_confirmations: u64,
    /// Whether the plain-BTC (vanilla / create_utxo) signing path is authorised.
    /// Derived from the operator's `BTC_MAX_TOTAL_SATS` pin
    /// ([`BridgeConfig::allows_vanilla_btc`]); default fail-closed (false).
    pub allow_vanilla_psbt: bool,
    /// Bridge directions this image signs, from the build features.
    pub signer_role: SignerRole,
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
    /// confirms which checkpoint the enclave synced from.
    pub evm_checkpoint: Option<[u8; 32]>,
    /// Bitcoin anchor-verification source. Always SPV in a production build.
    pub btc_source: BtcDataSource,
    /// Gas-tx (`SignRawDigest`) allowed destination (`GAS_TX_ALLOWED_TO`), or
    /// `None` when unset, which fails the gas path closed per request. Attested
    /// as all-zero when `None`. See `networks::evm::gas_tx`.
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
    pub mock_attestation: bool,
    pub allow_seed_import: bool,
    /// `rgb-validation`: the feature that turns on bridge signing. A release
    /// build with this on is the one the production policy must protect.
    pub rgb_validation: bool,
    /// `mint-signer` / `burn-signer`, or both directions.
    pub signer_role: SignerRole,
}

impl BuildContext {
    /// The current build's posture inputs, read from `cfg!`.
    pub fn current() -> Self {
        Self {
            debug_or_test: cfg!(debug_assertions) || cfg!(test),
            mock_attestation: cfg!(feature = "mock-attestation"),
            allow_seed_import: cfg!(feature = "allow-seed-import"),
            rgb_validation: cfg!(feature = "rgb-validation"),
            signer_role: if cfg!(feature = "mint-signer") {
                SignerRole::Mint
            } else if cfg!(feature = "burn-signer") {
                SignerRole::Burn
            } else {
                SignerRole::Combined
            },
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
        evm_min_confirmations: u64,
    ) -> Self {
        // Any dev feature collapses the posture regardless of everything else.
        // (These are `compile_error!` in a release build - lib.rs - so in a real
        // production binary they are all false; the checks make dev/test builds
        // resolve honestly and keep this function total.)
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
        // A path the role does not compile in is attested as off, whatever the
        // env pins say: `SignBtc` is mint-side, the gas tx burn-side.
        let signs_plain_btc = ctx.signer_role != SignerRole::Burn;
        let signs_gas_tx = ctx.signer_role != SignerRole::Mint;
        Self::Production(ProductionPolicy {
            chain_id: bridge.chain_id,
            bridge_contract: bridge.bridge_contract,
            rgb_asset_id: bridge.rgb_asset_id.clone(),
            funds_in_contract: bridge.funds_in_contract,
            evm_min_confirmations,
            allow_vanilla_psbt: signs_plain_btc && bridge.allows_vanilla_btc(),
            signer_role: ctx.signer_role,
            attestation: AttestationMode::Real,
            evm_source,
            evm_checkpoint,
            // `rgb-validation` implies `spv` (lib.rs `compile_error!`), so a
            // bridge build always anchors witness txs via the SPV header chain.
            btc_source: BtcDataSource::SpvVerified,
            // Gas-tx rule: reflect the same pins the request-time
            // `validate_gas_tx_request` enforces so the attested commitment and
            // the enforced policy cannot drift.
            gas_tx_allowed_to: bridge.gas_tx_allowed_to.filter(|_| signs_gas_tx),
            gas_tx_max_gas_limit: if signs_gas_tx {
                bridge.gas_tx_max_gas_limit
            } else {
                0
            },
            gas_tx_max_fee_per_gas: if signs_gas_tx {
                bridge.gas_tx_max_fee_per_gas
            } else {
                0
            },
            gas_tx_max_value_wei: bridge.gas_tx_max_value_wei.filter(|_| signs_gas_tx),
            gas_tx_allowed_selectors: if signs_gas_tx {
                bridge.gas_tx_allowed_selectors.clone()
            } else {
                Vec::new()
            },
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
                signer_role: p.signer_role,
                attestation: p.attestation,
                evm_source: p.evm_source,
                btc_source: p.btc_source,
                chain_id: p.chain_id,
                bridge_contract: p.bridge_contract,
                rgb_asset_id: p.rgb_asset_id.clone(),
                funds_in_contract: p.funds_in_contract,
                evm_min_confirmations: p.evm_min_confirmations,
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
                 feature (mock-attestation / allow-seed-import)."
            )),
        }
    }
}

impl ProductionPolicy {
    /// Invariants that must hold before a production enclave signs anything.
    /// Bitcoin anchors must be SPV-verified; the EVM source is attested, not
    /// gated.
    pub fn check_invariants(&self) -> Result<(), String> {
        if self.chain_id == 0 || self.bridge_contract == [0u8; 20] || self.rgb_asset_id.is_empty() {
            return Err(
                "production policy is missing one or more of the chain/contract/asset pins".into(),
            );
        }
        if self.funds_in_contract == [0u8; 20] {
            return Err("production policy must pin a non-zero FundsIn contract".into());
        }
        if self.evm_min_confirmations == 0 {
            return Err("production policy must require at least one EVM confirmation".into());
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
        // The EVM source is not gated: Helios has no Arbitrum light client, so
        // an L2 image runs on host-relayed RPC. It stays attested, so verifiers
        // judge the posture; `Disabled` fails closed per request. Helios with no
        // pinned checkpoint would bootstrap untrusted, so that stays rejected.
        if self.evm_source == EvmDataSource::HeliosVerified && self.evm_checkpoint.is_none() {
            return Err(
                "production policy uses the Helios EVM source but pins no weak-subjectivity \
                 checkpoint. Set HELIOS_CHECKPOINT to a recent beacon block root so the trust \
                 root is fixed and attested."
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
