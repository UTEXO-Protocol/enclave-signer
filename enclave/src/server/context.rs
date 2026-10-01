//! The boot-time context every request handler reads.
//!
//! Built once in `main.rs` and shared immutably. The only mutable parts are
//! behind their own `Mutex` (the SPV header chain and its rate limiter) or
//! written once (`launch`).

use std::sync::{Mutex, OnceLock};

#[cfg(feature = "rgb-validation")]
use super::rate_limit::SubmitRateLimiter;
use crate::config::{BridgeConfig, Endpoints};
use crate::error::{EnclaveError, Result};
use crate::policy::{BuildContext, SecurityPolicy};
use crate::state::EnclaveState;

/// What the operator's one `SetEndpoints` installs.
pub struct Launch {
    pub endpoints: Endpoints,
    /// The enclave's single, explicit security posture, resolved once at
    /// launch. Committed into the attestation `user_data` commitment via
    /// [`crate::policy::SecurityPolicy::commitment_bytes`] and consulted by the
    /// signing handlers instead of re-deriving posture from build features and
    /// empty request fields.
    pub policy: SecurityPolicy,
    /// `SetEndpoints` always sets it. Tests may leave it `None`, and the
    /// handlers then refuse.
    #[cfg(feature = "rgb-validation")]
    pub rgb_validator: Option<crate::networks::rgb::validation::RgbValidator>,
    /// In-enclave EVM RPC client for independent `FundsIn` verification.
    /// `SetEndpoints` always sets it. Tests may leave it `None`, and
    /// `handle_sign` then fails closed in bridge mode. Reaches the RPC only
    /// through the loopback vsock forwarder, so responses are host-relayed -
    /// see [`crate::networks::evm::events`].
    #[cfg(feature = "evm-rpc")]
    pub evm_rpc_client:
        Option<Box<dyn crate::networks::evm::events::EvmReceiptProvider + Send + Sync>>,
}

/// Shared context passed to every request handler.
pub struct ServerContext {
    pub state: EnclaveState,
    /// Bridge config pinned at boot from env. Folded into the attestation
    /// `user_data` commitment and used to cross-check `SignEvm` requests
    /// against operator-pinned values.
    pub bridge_config: BridgeConfig,
    /// The build the launch policy is resolved for.
    pub build_ctx: BuildContext,
    /// Empty until `SetEndpoints`. Written once, under `launch_lock`.
    pub launch: OnceLock<Launch>,
    pub launch_lock: Mutex<()>,
    /// Pinned EVM-RPC config (min confirmations).
    #[cfg(feature = "evm-rpc")]
    pub evm_rpc_config: crate::config::EvmRpcConfig,
    /// In-enclave Bitcoin header chain for SPV verification. Populated at boot
    /// from the compile-time checkpoint and mutated by SubmitHeaders. `Mutex`
    /// rather than `RefCell` so multi-threaded handling needs no plumbing
    /// change.
    ///
    /// SPV-only: a `ccd`-only build carries no chain and rejects
    /// `SubmitHeaders` / `GetLastSavedBlock`.
    #[cfg(feature = "rgb-validation")]
    pub header_chain: std::sync::Mutex<crate::networks::rgb::spv::HeaderChain>,
    /// Cumulative rate limit for `SubmitHeaders`. The per-call cap lives
    /// in `HeaderChain::submit_headers`; this bounds the *aggregate* rate
    /// across calls so a flood of small batches can't keep the enclave busy.
    #[cfg(feature = "rgb-validation")]
    pub submit_rate_limiter: std::sync::Mutex<SubmitRateLimiter>,
}

impl ServerContext {
    /// A context with no endpoints: it signs nothing until `SetEndpoints`.
    /// `main.rs` builds this one.
    pub fn awaiting_launch(
        state: EnclaveState,
        bridge_config: BridgeConfig,
        #[cfg(feature = "rgb-validation")] header_chain: std::sync::Mutex<
            crate::networks::rgb::spv::HeaderChain,
        >,
        build_ctx: BuildContext,
    ) -> Self {
        Self {
            state,
            bridge_config,
            build_ctx,
            launch: OnceLock::new(),
            launch_lock: Mutex::new(()),
            #[cfg(feature = "evm-rpc")]
            evm_rpc_config: crate::config::EvmRpcConfig::from_env(),
            #[cfg(feature = "rgb-validation")]
            header_chain,
            #[cfg(feature = "rgb-validation")]
            submit_rate_limiter: std::sync::Mutex::new(SubmitRateLimiter::default()),
        }
    }

    /// Construct a `ServerContext` from the always-present fields, hiding
    /// feature-gated fields like `rgb_validator` so external callers
    /// (e.g. the parent's E2E tests) don't need to mirror our cfg flags.
    /// The launch is preset with no endpoints and no chain clients.
    #[cfg(feature = "rgb-validation")]
    pub fn new(
        state: EnclaveState,
        bridge_config: BridgeConfig,
        header_chain: std::sync::Mutex<crate::networks::rgb::spv::HeaderChain>,
    ) -> Self {
        let ctx =
            Self::awaiting_launch(state, bridge_config, header_chain, BuildContext::current());
        ctx.preset_dev_launch();
        ctx
    }

    /// `ccd`-only variant: no SPV header chain to pass in.
    #[cfg(not(feature = "rgb-validation"))]
    pub fn new(state: EnclaveState, bridge_config: BridgeConfig) -> Self {
        let ctx = Self::awaiting_launch(state, bridge_config, BuildContext::current());
        ctx.preset_dev_launch();
        ctx
    }

    fn preset_dev_launch(&self) {
        // No EVM source is wired here, so resolve `Disabled`.
        let policy = SecurityPolicy::resolve(
            &self.build_ctx,
            &self.bridge_config,
            crate::policy::EvmDataSource::Disabled,
            None,
            None,
            "",
            0,
        );
        let _ = self.launch.set(Launch {
            endpoints: Endpoints::default(),
            policy,
            #[cfg(feature = "rgb-validation")]
            rgb_validator: None,
            #[cfg(feature = "evm-rpc")]
            evm_rpc_client: None,
        });
    }

    /// The launch values, or `NotReady` before `SetEndpoints`.
    pub fn launch(&self) -> Result<&Launch> {
        self.launch.get().ok_or_else(|| EnclaveError::NotReady {
            state: "endpoints-unset".into(),
        })
    }
}
