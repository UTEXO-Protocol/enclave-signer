//! The boot-time context that all request handlers read.
//!
//! `main.rs` builds it once, and it is shared as immutable. The only mutable
//! parts are behind a `Mutex` (SPV header chain, rate limiter) or written
//! once (`launch`).

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
    /// The enclave security policy, resolved once at launch.
    /// The attestation `user_data` commits to it through
    /// [`crate::policy::SecurityPolicy::commitment_bytes`].
    /// Signing handlers read it. They do not derive the policy from build
    /// features or empty request fields.
    pub policy: SecurityPolicy,
    /// `SetEndpoints` always sets it. Tests can leave it `None`.
    /// Then the handlers refuse.
    #[cfg(feature = "rgb-validation")]
    pub rgb_validator: Option<crate::networks::rgb::validation::RgbValidator>,
    /// In-enclave EVM RPC client for independent `FundsIn` verification.
    /// `SetEndpoints` always sets it. Tests can leave it `None`.
    /// Then `handle_sign` fails closed in bridge mode.
    /// The host relays the RPC traffic through the loopback vsock forwarder.
    /// TLS ends inside the enclave. See [`crate::networks::evm::events`].
    #[cfg(feature = "evm-rpc")]
    pub evm_rpc_client:
        Option<Box<dyn crate::networks::evm::events::EvmReceiptProvider + Send + Sync>>,
}

/// Shared context passed to every request handler.
pub struct ServerContext {
    pub state: EnclaveState,
    /// Bridge config pinned at boot from env. The attestation `user_data`
    /// commits to it. `SignEvm` requests are cross-checked against it.
    pub bridge_config: BridgeConfig,
    /// The build that the launch policy applies to.
    pub build_ctx: BuildContext,
    /// Empty until `SetEndpoints`. Written once, under `launch_lock`.
    pub launch: OnceLock<Launch>,
    pub launch_lock: Mutex<()>,
    /// Pinned EVM-RPC config (min confirmations).
    #[cfg(feature = "evm-rpc")]
    pub evm_rpc_config: crate::config::EvmRpcConfig,
    /// In-enclave Bitcoin header chain for SPV verification.
    /// It starts from the compile-time checkpoint. SubmitHeaders changes it.
    ///
    /// A `ccd`-only build has no chain and refuses
    /// `SubmitHeaders` / `GetLastSavedBlock`.
    #[cfg(feature = "rgb-validation")]
    pub header_chain: std::sync::Mutex<crate::networks::rgb::spv::HeaderChain>,
    /// Total rate limit for `SubmitHeaders` across calls.
    /// `HeaderChain::submit_headers` has the per-call cap.
    /// This limit stops a flood of small batches from keeping the enclave busy.
    #[cfg(feature = "rgb-validation")]
    pub submit_rate_limiter: std::sync::Mutex<SubmitRateLimiter>,
}

impl ServerContext {
    /// A context with no endpoints. It signs nothing until `SetEndpoints`.
    /// `main.rs` uses this constructor.
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

    /// Make a `ServerContext` without feature-gated fields such as
    /// `rgb_validator`. External callers (for example parent E2E tests) do
    /// not need the same cfg flags.
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

    /// `ccd`-only variant without an SPV header chain.
    #[cfg(not(feature = "rgb-validation"))]
    pub fn new(state: EnclaveState, bridge_config: BridgeConfig) -> Self {
        let ctx = Self::awaiting_launch(state, bridge_config, BuildContext::current());
        ctx.preset_dev_launch();
        ctx
    }

    fn preset_dev_launch(&self) {
        // No EVM source exists here, so the policy is `Disabled`.
        let policy = SecurityPolicy::resolve(
            &self.build_ctx,
            &self.bridge_config,
            crate::policy::EvmDataSource::Disabled,
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
