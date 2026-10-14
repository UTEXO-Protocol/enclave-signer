//! The enclave security policy, as one object.
//!
//! [`SecurityPolicy::resolve`] makes it from the build features and the
//! [`BridgeConfig`]. It is:
//!
//!   * fail-closed: a release `rgb-validation` build without a valid
//!     [`SecurityPolicy::Production`] does not boot or launch
//!     ([`SecurityPolicy::assert_valid_at_boot`],
//!     [`SecurityPolicy::assert_valid_for_build`]);
//!   * attested: the attestation `user_data` commits
//!     [`SecurityPolicy::commitment_bytes`];
//!   * authoritative: handlers read it and do not derive the policy again.
//!
//! The functions take an explicit [`BuildContext`], so unit tests cover release
//! behavior without a release build.

use crate::config::{BridgeConfig, BtcRelayMode};

pub use attestation_verify::{
    AttestationMode, AttestedPolicy, BtcDataSource, EvmDataSource, EvmRpcTlsPin, KmsPin, SignerRole,
};

/// The resolved security policy. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
// One instance per enclave, so the variant size difference is not important.
#[allow(clippy::large_enum_variant)]
pub enum SecurityPolicy {
    /// A fully pinned, fail-closed bridge-signing enclave.
    Production(ProductionPolicy),
    /// Not a production bridge signer: a debug build, a dev feature, a
    /// non-bridge build or an unpinned config. The reason goes into logs and the
    /// fail-closed panic.
    Development { reason: DevReason },
}

/// The pins, signing modes and data sources of a production bridge signer.
/// The attestation `user_data` commits all of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPolicy {
    /// Pinned EVM chain id (`EVM_CHAIN_ID`).
    pub chain_id: u64,
    /// Pinned MultisigProxy contract (`EVM_PROXY_CONTRACT_ADDRESS`).
    pub bridge_contract: [u8; 20],
    /// Pinned RGB asset id (`RGB_ASSET_ID`).
    pub rgb_asset_id: String,
    /// Only this contract's FundsIn events may authorize bridge signing.
    pub funds_in_contract: [u8; 20],
    /// The ERC-20 that the Bridge releases (`TOKEN_CONTRACT`), a `burnId`
    /// preimage input.
    pub token_contract: [u8; 20],
    /// Min receipt depth of an accepted FundsIn deposit.
    pub evm_min_confirmations: u64,
    /// `fundsOut` proofs must carry BtcRelay commitments (`BTC_RELAY_MODE=required`).
    /// [`check_invariants`](Self::check_invariants) refuses `false`, so
    /// [`AttestedPolicy`] has no field for it.
    pub btc_relay_required: bool,
    /// If plain-BTC (vanilla, create_utxo) signing is allowed
    /// ([`BridgeConfig::allows_vanilla_btc`]). Default `false`.
    pub allow_vanilla_psbt: bool,
    /// Bridge directions this image signs, from the build features.
    pub signer_role: SignerRole,
    /// Attestation root of trust. Always [`AttestationMode::Real`] in
    /// production: mock is a release `compile_error!` in `lib.rs`.
    pub attestation: AttestationMode,
    /// EVM `FundsIn` verification source (pinned TLS, plaintext RPC or
    /// disabled). Attested.
    pub evm_source: EvmDataSource,
    /// Host of the Electrum server set at launch.
    pub electrum_host: String,
    /// The EVM RPC TLS host and CA hash. Required when `evm_source` is
    /// [`EvmDataSource::PinnedTlsRpc`].
    pub evm_rpc_tls: Option<EvmRpcTlsPin>,
    /// Bitcoin anchor-verification source. Always SPV in a production build.
    pub btc_source: BtcDataSource,
    /// Allowed gas-tx (`SignRawDigest`) destination (`GAS_TX_ALLOWED_TO`).
    /// `None` fails the gas path closed and is attested as all-zero.
    /// See `networks::evm::gas_tx`.
    pub gas_tx_allowed_to: Option<[u8; 20]>,
    /// Max gas-tx `gasLimit` (`GAS_TX_MAX_GAS_LIMIT`). 0 fails closed.
    pub gas_tx_max_gas_limit: u64,
    /// Max gas-tx per-gas fee in wei (`GAS_TX_MAX_FEE_PER_GAS`). 0 fails closed.
    pub gas_tx_max_fee_per_gas: u128,
    /// Max gas-tx native value in wei (`GAS_TX_MAX_VALUE_WEI`), for the payable
    /// `lzFundsOutCall`. `None` allows no non-zero value and is attested as 0.
    pub gas_tx_max_value_wei: Option<u128>,
    /// Gas-tx calldata selector allowlist (`GAS_TX_ALLOWED_SELECTORS`).
    pub gas_tx_allowed_selectors: Vec<[u8; 4]>,
    /// The KMS pin set at launch. See [`SecurityPolicy::with_kms`].
    pub kms: Option<KmsPin>,
}

/// Why the policy is [`SecurityPolicy::Development`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevReason {
    /// Built with `debug_assertions` (or under `cfg(test)`).
    DebugBuild,
    /// `mock-attestation` feature: zero-PCR attestation documents.
    MockAttestation,
    /// `allow-seed-import` feature: the parent can install a chosen seed.
    AllowSeedImport,
    /// A non-bridge build (`rgb-validation` off).
    NonBridgeBuild,
    /// A bridge build whose chain/contract/asset pins are not fully set.
    Unconfigured,
}

/// Compile-time policy inputs. [`BuildContext::current`] gives the real values.
/// Tests make other values to cover the release paths.
#[derive(Clone, Copy, Debug)]
pub struct BuildContext {
    /// `cfg!(debug_assertions) || cfg!(test)`: not a release build.
    pub debug_or_test: bool,
    pub mock_attestation: bool,
    pub allow_seed_import: bool,
    /// `rgb-validation`: the feature that enables bridge signing.
    pub rgb_validation: bool,
    /// `mint-signer` / `burn-signer`, or both directions.
    pub signer_role: SignerRole,
}

impl BuildContext {
    /// The inputs of the current build, from `cfg!`.
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
    /// Resolve the policy from the build context, the [`BridgeConfig`] and the
    /// launch endpoints.
    ///
    /// Only a release bridge build with all three pins set gives
    /// [`SecurityPolicy::Production`]. All other inputs give
    /// [`SecurityPolicy::Development`].
    pub fn resolve(
        ctx: &BuildContext,
        bridge: &BridgeConfig,
        evm_source: EvmDataSource,
        evm_rpc_tls: Option<EvmRpcTlsPin>,
        electrum_host: &str,
        evm_min_confirmations: u64,
    ) -> Self {
        // Dev features are a release `compile_error!` (lib.rs). These checks
        // keep dev and test builds correct.
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
            return Self::dev(DevReason::NonBridgeBuild);
        }
        if !bridge.is_configured() {
            return Self::dev(DevReason::Unconfigured);
        }
        // A path that the role does not compile is attested as off, for all env
        // pins. `SignBtc` is mint side, the gas tx is burn side.
        let signs_plain_btc = ctx.signer_role != SignerRole::Burn;
        let signs_gas_tx = ctx.signer_role != SignerRole::Mint;
        Self::Production(ProductionPolicy {
            chain_id: bridge.chain_id,
            bridge_contract: bridge.bridge_contract,
            rgb_asset_id: bridge.rgb_asset_id.clone(),
            funds_in_contract: bridge.funds_in_contract,
            token_contract: bridge.token_contract,
            evm_min_confirmations,
            btc_relay_required: bridge.btc_relay_mode == BtcRelayMode::Required,
            allow_vanilla_psbt: signs_plain_btc && bridge.allows_vanilla_btc(),
            signer_role: ctx.signer_role,
            attestation: AttestationMode::Real,
            evm_source,
            electrum_host: electrum_host.to_string(),
            evm_rpc_tls,
            // `rgb-validation` implies `spv` (lib.rs `compile_error!`).
            btc_source: BtcDataSource::SpvVerified,
            // The same pins that `validate_gas_tx_request` enforces, so the
            // attested and the enforced rules agree.
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
            kms: None,
        })
    }

    /// Set the KMS pin of a production policy. A development policy does not
    /// change.
    pub fn with_kms(mut self, kms: Option<KmsPin>) -> Self {
        if let Self::Production(p) = &mut self {
            p.kms = kms;
        }
        self
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
                token_contract: p.token_contract,
                evm_min_confirmations: p.evm_min_confirmations,
                electrum_host: p.electrum_host.clone(),
                evm_rpc_tls: p.evm_rpc_tls.clone(),
                // Unset commits as all-zero, which the gas path never accepts.
                gas_tx_allowed_to: p.gas_tx_allowed_to.unwrap_or([0u8; 20]),
                gas_tx_max_gas_limit: p.gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas: p.gas_tx_max_fee_per_gas,
                // Unset commits as 0, which is the enforced rule.
                gas_tx_max_value_wei: p.gas_tx_max_value_wei.unwrap_or(0),
                gas_tx_allowed_selectors: p.gas_tx_allowed_selectors.clone(),
                kms: p.kms.clone(),
            },
            Self::Development { .. } => AttestedPolicy::Development,
        }
    }

    /// Canonical bytes added to the attestation commitment preimage. Verifiers
    /// use [`attestation_verify::AttestedPolicy::to_bytes`].
    pub fn commitment_bytes(&self) -> Vec<u8> {
        self.attested().to_bytes()
    }

    /// Fail-closed launch gate. A release `rgb-validation` build MUST resolve
    /// to a valid [`SecurityPolicy::Production`], or `SetEndpoints` fails.
    /// [`Self::assert_valid_at_boot`] runs the checks that need no endpoints.
    ///
    /// Debug, test and non-bridge builds are exempt.
    pub fn assert_valid_for_build(&self, ctx: &BuildContext) -> Result<(), String> {
        if ctx.debug_or_test || !ctx.rgb_validation {
            return Ok(());
        }
        match self {
            Self::Production(p) => p.check_invariants(),
            Self::Development { reason } => Err(format!(
                "release rgb-validation (bridge-signing) build resolved to a non-production \
                 security policy ({reason:?}); refusing to boot. A production bridge enclave must \
                 pin EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID and be built \
                 without any dev feature (mock-attestation / allow-seed-import)."
            )),
        }
    }

    /// Boot gate: [`Self::assert_valid_for_build`] without the endpoint
    /// checks. The endpoints come at launch.
    pub fn assert_valid_at_boot(&self, ctx: &BuildContext) -> Result<(), String> {
        match self {
            Self::Production(p) if !ctx.debug_or_test && ctx.rgb_validation => {
                p.check_build_invariants()
            }
            _ => self.assert_valid_for_build(ctx),
        }
    }
}

impl ProductionPolicy {
    /// Invariants that must hold before a production enclave signs. Bitcoin
    /// anchors are SPV-verified and the EVM RPC is authenticated.
    pub fn check_invariants(&self) -> Result<(), String> {
        self.check_build_invariants()?;
        if self.electrum_host.is_empty() {
            return Err("production policy has no Electrum host. Set it at launch.".into());
        }
        // Plaintext lets the host forge a receipt. `Disabled` fails closed per
        // request.
        if self.evm_source == EvmDataSource::RawRpc {
            return Err(
                "production policy reads the EVM RPC over plaintext; plaintext is for dev and \
                 test builds only."
                    .into(),
            );
        }
        if self.evm_source == EvmDataSource::PinnedTlsRpc && self.evm_rpc_tls.is_none() {
            return Err(
                "production policy uses the pinned TLS EVM source without a valid pin. Set \
                 the EVM RPC host and CA at launch."
                    .into(),
            );
        }
        Ok(())
    }

    /// The invariants that do not depend on the endpoints.
    fn check_build_invariants(&self) -> Result<(), String> {
        if self.chain_id == 0 || self.bridge_contract == [0u8; 20] || self.rgb_asset_id.is_empty() {
            return Err(
                "production policy is missing one or more of the chain/contract/asset pins".into(),
            );
        }
        if self.funds_in_contract == [0u8; 20] {
            return Err("production policy must pin a non-zero FundsIn contract".into());
        }
        if self.token_contract == [0u8; 20] {
            return Err(
                "production policy must pin a non-zero TOKEN_CONTRACT (burnId preimage input)"
                    .into(),
            );
        }
        if self.evm_min_confirmations == 0 {
            return Err("production policy must require at least one EVM confirmation".into());
        }
        if !self.btc_relay_required {
            return Err(format!(
                "production policy must verify BtcRelay commitments on fundsOut: \
                 {}=none is only for a local stand that has no BtcRelay",
                crate::config::BTC_RELAY_MODE_ENV
            ));
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
mod tests;
