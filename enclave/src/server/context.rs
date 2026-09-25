//! The boot-time context every request handler reads.
//!
//! Built once in `main.rs` and shared immutably. The only mutable parts are
//! behind their own `Mutex` (the SPV header chain and its rate limiter).

#[cfg(feature = "rgb-validation")]
use super::rate_limit::SubmitRateLimiter;
use crate::config::BridgeConfig;
use crate::state::EnclaveState;

/// Shared context passed to every request handler.
pub struct ServerContext {
    pub state: EnclaveState,
    /// Bridge config pinned at boot from env. Folded into the attestation
    /// `user_data` commitment and used to cross-check `SignEvm` requests
    /// against operator-pinned values.
    pub bridge_config: BridgeConfig,
    /// The enclave's single, explicit security posture, resolved once at
    /// boot. Committed into the attestation `user_data` commitment via
    /// [`crate::policy::SecurityPolicy::commitment_bytes`] and consulted by the
    /// signing handlers instead of re-deriving posture from build features and
    /// empty request fields.
    pub policy: crate::policy::SecurityPolicy,
    #[cfg(feature = "rgb-validation")]
    pub rgb_validator: Option<crate::networks::rgb::validation::RgbValidator>,
    /// In-enclave EVM RPC client for independent `FundsIn` verification.
    /// `None` when the client could not be built; `handle_sign` fails closed on
    /// `None` in bridge mode. Reaches the RPC only through the loopback vsock
    /// forwarder, so responses are host-relayed and untrusted - see
    /// [`crate::networks::evm::events`].
    #[cfg(feature = "evm-rpc")]
    pub evm_rpc_client:
        Option<Box<dyn crate::networks::evm::events::EvmReceiptProvider + Send + Sync>>,
    /// Pinned EVM-RPC config (loopback URL + min confirmations).
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
    /// Construct a `ServerContext` from the always-present fields, hiding
    /// feature-gated fields like `rgb_validator` so external callers
    /// (e.g. the parent's E2E tests) don't need to mirror our cfg flags.
    #[cfg(feature = "rgb-validation")]
    pub fn new(
        state: EnclaveState,
        bridge_config: BridgeConfig,
        header_chain: std::sync::Mutex<crate::networks::rgb::spv::HeaderChain>,
    ) -> Self {
        // The main binary sets `policy` explicitly, since it knows the selected
        // EVM data source. This constructor serves tests and the parent E2E
        // harness, where no EVM source is wired, so it resolves `Disabled`.
        let policy = crate::policy::SecurityPolicy::resolve(
            &crate::policy::BuildContext::current(),
            &bridge_config,
            crate::policy::EvmDataSource::Disabled,
            None,
            0,
        );
        Self {
            state,
            bridge_config,
            policy,
            rgb_validator: None,
            #[cfg(feature = "evm-rpc")]
            evm_rpc_client: None,
            #[cfg(feature = "evm-rpc")]
            evm_rpc_config: crate::config::EvmRpcConfig::default(),
            header_chain,
            submit_rate_limiter: std::sync::Mutex::new(SubmitRateLimiter::default()),
        }
    }

    /// `ccd`-only variant: no SPV header chain to pass in.
    #[cfg(not(feature = "rgb-validation"))]
    pub fn new(state: EnclaveState, bridge_config: BridgeConfig) -> Self {
        // No EVM source is wired here, so resolve `Disabled`. A ccd-only build
        // has no bridge-signing path and the boot gate exempts it.
        let policy = crate::policy::SecurityPolicy::resolve(
            &crate::policy::BuildContext::current(),
            &bridge_config,
            crate::policy::EvmDataSource::Disabled,
            None,
            0,
        );
        Self {
            state,
            bridge_config,
            policy,
            #[cfg(feature = "evm-rpc")]
            evm_rpc_client: None,
            #[cfg(feature = "evm-rpc")]
            evm_rpc_config: crate::config::EvmRpcConfig::default(),
        }
    }
}
