use std::io::{Read, Write};

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::framing;
use crate::networks::evm::signing::{build_evm_domain, funds_out_digest, lz_funds_out_digest};
use crate::networks::evm::validation::LZ_FUNDS_OUT_SELECTOR;
use crate::networks::{
    validate_destination, validate_route_proofs, validate_source, ValidationContext,
};
use crate::proto::enclave_request::Request;
use crate::proto::enclave_response::Response;
use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};
use crate::proto::*;
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
    /// [`crate::networks::evm::evm_event`].
    #[cfg(feature = "evm-rpc")]
    pub evm_rpc_client:
        Option<Box<dyn crate::networks::evm::evm_event::EvmReceiptProvider + Send + Sync>>,
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
    #[cfg(feature = "spv")]
    pub header_chain: std::sync::Mutex<crate::networks::rgb::spv::HeaderChain>,
    /// Cumulative rate limit for `SubmitHeaders`. The per-call cap lives
    /// in `HeaderChain::submit_headers`; this bounds the *aggregate* rate
    /// across calls so a flood of small batches can't keep the enclave busy.
    #[cfg(feature = "spv")]
    pub submit_rate_limiter: std::sync::Mutex<SubmitRateLimiter>,
}

/// Sliding-window rate limit for `SubmitHeaders` (cumulative cap): at most
/// [`MAX_HEADERS_PER_RATE_WINDOW`] headers submitted, validated or not, within
/// [`RATE_LIMIT_WINDOW`]. Generous enough for a cold-start sync, tight enough
/// that a flood of garbage headers cannot occupy the enclave.
///
/// SPV-only: a `ccd`-only build has no header chain to rate-limit.
#[cfg(feature = "spv")]
#[derive(Default)]
pub struct SubmitRateLimiter {
    window_start: Option<std::time::SystemTime>,
    headers_in_window: u64,
}

/// Max headers admitted per [`RATE_LIMIT_WINDOW`]. A cold-start sync from the
/// mainnet checkpoint to the tip is a few thousand blocks, well inside this.
#[cfg(feature = "spv")]
const MAX_HEADERS_PER_RATE_WINDOW: u64 = 100_000;
/// Length of the rate-limit window.
#[cfg(feature = "spv")]
const RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(feature = "spv")]
impl SubmitRateLimiter {
    /// Account for `count` submitted headers at time `now`. Returns `Err` if
    /// the rolling-window budget would be exceeded. The window resets once
    /// `RATE_LIMIT_WINDOW` has elapsed (or if the clock moves backwards).
    pub fn check(&mut self, count: u64, now: std::time::SystemTime) -> Result<()> {
        let reset = match self.window_start {
            None => true,
            Some(start) => now
                .duration_since(start)
                .map(|elapsed| elapsed >= RATE_LIMIT_WINDOW)
                .unwrap_or(true),
        };
        if reset {
            self.window_start = Some(now);
            self.headers_in_window = 0;
        }
        self.headers_in_window = self.headers_in_window.saturating_add(count);
        if self.headers_in_window > MAX_HEADERS_PER_RATE_WINDOW {
            return Err(EnclaveError::Spv(format!(
                "SubmitHeaders rate limit exceeded: {} headers within {}s (max {})",
                self.headers_in_window,
                RATE_LIMIT_WINDOW.as_secs(),
                MAX_HEADERS_PER_RATE_WINDOW,
            )));
        }
        Ok(())
    }
}

impl ServerContext {
    /// Construct a `ServerContext` from the always-present fields, hiding
    /// feature-gated fields like `rgb_validator` so external callers
    /// (e.g. the parent's E2E tests) don't need to mirror our cfg flags.
    #[cfg(feature = "spv")]
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
        );
        Self {
            state,
            bridge_config,
            policy,
            #[cfg(feature = "rgb-validation")]
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
    #[cfg(not(feature = "spv"))]
    pub fn new(state: EnclaveState, bridge_config: BridgeConfig) -> Self {
        // No EVM source is wired here, so resolve `Disabled`. A ccd-only build
        // has no bridge-signing path and the boot gate exempts it.
        let policy = crate::policy::SecurityPolicy::resolve(
            &crate::policy::BuildContext::current(),
            &bridge_config,
            crate::policy::EvmDataSource::Disabled,
            None,
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

/// Handle a single connection: read one request, dispatch, write one response, close.
pub fn handle_connection(stream: impl Read + Write, ctx: &ServerContext) {
    if let Err(e) = process_connection(stream, ctx) {
        tracing::error!("connection error: {}", e);
    }
}

fn process_connection(mut stream: impl Read + Write, ctx: &ServerContext) -> Result<()> {
    tracing::debug!("reading request");
    let request: EnclaveRequest = framing::read_message(&mut stream)?;

    let response = dispatch(request, ctx);

    framing::write_message(&mut stream, &response)?;
    tracing::debug!("response written");
    Ok(())
}

/// Error for a request whose owning network was not compiled into this build.
/// Single-network EIFs (RGB-only / CCD-only) return this for requests that
/// belong to the other network, so the separation is observable to callers
/// rather than a silent no-op.
#[allow(dead_code)]
fn unsupported_build(network: &str) -> EnclaveError {
    EnclaveError::InvalidRequest(format!(
        "enclave was not built with `{network}` support: this binary does not handle {network} \
         requests (rebuild with `--features {network}`)"
    ))
}

fn dispatch(request: EnclaveRequest, ctx: &ServerContext) -> EnclaveResponse {
    let result = match request.request {
        Some(Request::InitializeKey(req)) => {
            let path = if !req.mnemonic.is_empty() {
                "mnemonic-import"
            } else if req.seed.is_empty() {
                "entropy"
            } else {
                "seed-import"
            };
            tracing::info!("request: InitializeKey ({})", path);
            handle_initialize(ctx, req)
        }
        Some(Request::GetPublicKey(req)) => {
            tracing::info!("request: GetPublicKey");
            handle_get_public_key(ctx, req)
        }
        Some(Request::Sign(req)) => handle_sign(ctx, req),
        Some(Request::SignBtc(req)) => {
            tracing::info!("request: SignBtc");
            handle_sign_btc(ctx, req)
        }
        // Removed. The EIP-191 `personal_sign` path was
        // gated by no feature and no policy, and signed arbitrary caller-supplied
        // bytes with the main bridge key. The proto still carries the variant, so
        // refuse explicitly instead of dropping the arm.
        Some(Request::SignRawMessage(_)) => {
            tracing::warn!("request: SignRawMessage - removed, refusing");
            Err(EnclaveError::InvalidRequest(
                "SignRawMessage is removed; no replacement".into(),
            ))
        }
        Some(Request::SignRawDigest(req)) => {
            tracing::info!("request: SignRawDigest");
            handle_sign_raw_digest(ctx, req)
        }
        Some(Request::SignCcd(req)) => {
            tracing::info!("request: SignCcd");
            #[cfg(feature = "ccd")]
            {
                handle_sign_ccd(&ctx.state, req)
            }
            #[cfg(not(feature = "ccd"))]
            {
                let _ = req;
                Err(unsupported_build("ccd"))
            }
        }
        Some(Request::ProxyFederation(req)) => {
            tracing::info!("request: ProxyFederation");
            handle_proxy_federation(req)
        }
        Some(Request::InitiateCloning(req)) => {
            tracing::info!("request: InitiateCloning");
            handle_initiate_cloning(&ctx.state, req)
        }
        Some(Request::GetClone(req)) => {
            tracing::info!("request: GetClone");
            handle_get_clone(&ctx.state, req)
        }
        Some(Request::SetClone(req)) => {
            tracing::info!("request: SetClone");
            handle_set_clone(&ctx.state, req)
        }
        Some(Request::SubmitHeaders(req)) => {
            tracing::info!(
                headers_len = req.headers.len(),
                start_height = req.start_height,
                "request: SubmitHeaders"
            );
            #[cfg(feature = "spv")]
            {
                handle_submit_headers(ctx, req)
            }
            #[cfg(not(feature = "spv"))]
            {
                let _ = req;
                Err(unsupported_build("rgb"))
            }
        }
        Some(Request::GetLastSavedBlock(req)) => {
            tracing::info!("request: GetLastSavedBlock");
            #[cfg(feature = "spv")]
            {
                handle_get_last_saved_block(ctx, req)
            }
            #[cfg(not(feature = "spv"))]
            {
                let _ = req;
                Err(unsupported_build("rgb"))
            }
        }
        Some(Request::GetAttestedPublicKey(req)) => {
            tracing::info!("request: GetAttestedPublicKey");
            handle_get_attested_public_key(ctx, req)
        }
        None => {
            tracing::warn!("received empty request (no oneof variant set)");
            return EnclaveResponse {
                response: Some(Response::Error(ErrorResponse {
                    code: 1,
                    message: "empty request".into(),
                })),
            };
        }
    };

    match result {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!("handler error: {}", e);
            EnclaveResponse {
                response: Some(Response::Error(ErrorResponse {
                    code: e.error_code(),
                    message: e.to_string(),
                })),
            }
        }
    }
}

fn handle_sign(ctx: &ServerContext, req: SignRequest) -> Result<EnclaveResponse> {
    let source_ref = req
        .source_network
        .as_ref()
        .ok_or_else(|| EnclaveError::InvalidRequest("sign request has no source_network".into()))?;
    let destination_ref = req.destination_network.as_ref().ok_or_else(|| {
        EnclaveError::InvalidRequest("sign request has no destination_network".into())
    })?;

    // Self-owned-outpoint oracle for the send-RGB per-output recipient bind.
    // A closure, so the key lock is held only for the resolution and never
    // across validation's Esplora/Electrum calls.
    //
    // An outpoint on this PSBT is decided from its taproot metadata. One on an
    // earlier tx (rgb-lib parks the change on an existing UTXO when the
    // transfer has no BTC change) needs the tx fetched to read its script.
    #[cfg(feature = "rgb-validation")]
    let self_owned_psbt_outputs = |psbt: &bitcoin::psbt::Psbt, outpoint: bitcoin::OutPoint| {
        use crate::networks::rgb::btc_ownership;

        if outpoint.txid == psbt.unsigned_tx.compute_txid() {
            return ctx.state.with_keys(|keys| {
                Ok(btc_ownership::self_owned_output_indices(psbt, keys).contains(&outpoint.vout))
            });
        }

        // Fail closed: no indexer, no script, no way to tell change from payout.
        let validator = ctx.rgb_validator.as_ref().ok_or_else(|| {
            EnclaveError::CrossCheck(
                "send-RGB change seal names an outpoint outside the PSBT, but the RGB validator \
                 is not configured - the enclave cannot resolve that outpoint's script"
                    .into(),
            )
        })?;
        // Outside `with_keys`: network round-trip.
        let tx = validator.fetch_transaction(outpoint.txid)?;
        let Some(txout) = tx.output.get(outpoint.vout as usize) else {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB change seal names outpoint {outpoint}, but that transaction has only \
                 {} outputs",
                tx.output.len()
            )));
        };
        let script = txout.script_pubkey.as_bytes().to_vec();
        ctx.state.with_keys(|keys| {
            // `None` scope: bridge change sits on the Colored account. This
            // widens what counts as ours, never what gets signed.
            Ok(
                btc_ownership::self_controlled_input_scripts_scoped(psbt, keys, None)
                    .contains(&script),
            )
        })
    };

    let validation_ctx = ValidationContext {
        bridge_config: &ctx.bridge_config,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: ctx.rgb_validator.as_ref(),
        #[cfg(feature = "spv")]
        header_chain: &ctx.header_chain,
        #[cfg(feature = "rgb-validation")]
        self_owned_psbt_outputs: Some(&self_owned_psbt_outputs),
    };
    let source_validated = validate_source(req.amount, source_ref, &validation_ctx)?;

    // Commission per compiled source network. A CCD source is only present on a
    // `ccd` build; `validate_source` already rejected it otherwise, but the arm
    // is still required for the match to type-check.
    let source_commission = match source_ref {
        SourceNetwork::EvmSource(source) => source.commission,
        SourceNetwork::RgbSource(source) => source.commission,
        #[cfg(feature = "ccd")]
        SourceNetwork::CcdSource(source) => source.commission,
        #[allow(unreachable_patterns)]
        _ => return Err(unsupported_build("ccd")),
    };
    let destination_proof = validate_destination(
        req.amount,
        source_commission,
        destination_ref,
        &validation_ctx,
    )?;

    validate_route_proofs(
        source_ref,
        destination_ref,
        &source_validated.proof,
        &destination_proof.proof,
    )?;

    // Independent EVM `FundsIn` verification: confirm
    // the deposit on-chain through the enclave's own RPC call rather than the
    // listener's booleans. Fail-closed - a missing client or unmet predicate
    // refuses the signature. Runs after the cheap local cross-checks and before
    // the replay guard records the op, so the RPC is only paid on an otherwise
    // valid request. Fully trustless only once Helios verifies it.
    #[cfg(all(feature = "evm-rpc", not(feature = "dev-mode")))]
    if let (SourceNetwork::EvmSource(source), DestinationNetwork::RgbDestination(_)) =
        (source_ref, destination_ref)
    {
        let tx_hash: [u8; 32] = source.tx_hash.as_slice().try_into().map_err(|_| {
            EnclaveError::CrossCheck(format!(
                "evm_tx_hash must be 32 bytes, got {}",
                source.tx_hash.len()
            ))
        })?;
        // `funds_in_operation_id` is the on-chain BridgeFundsIn operationId as
        // the full 32-byte word. It is required; `verify_funds_in_event` fails
        // closed on an empty/short value.
        let client = ctx.evm_rpc_client.as_ref().ok_or_else(|| {
            EnclaveError::CrossCheck(
                "evm-rpc build but RPC client unavailable - refusing to sign a bridge PSBT \
                 without independently verifying the FundsIn deposit"
                    .into(),
            )
        })?;
        // Binds to the source's BridgeFundsIn.operationId, not
        // destination.operation_idx, which is a different id-space.
        let verified = crate::networks::evm::evm_event::verify_funds_in_event(
            &**client,
            // FundsIn is emitted by the bridge entry contract, which may differ
            // from the MultisigProxy pinned in EVM_PROXY_CONTRACT_ADDRESS (see config.rs).
            &ctx.bridge_config.funds_in_contract,
            ctx.evm_rpc_config.min_confirmations,
            &tx_hash,
            &source.funds_in_operation_id,
            req.amount,
            source.commission,
        )?;

        // Recipient bind: the checks above prove how much the recipient leg
        // pays, not who it pays. The invoice in the log just verified says
        // which seal the deposit authorised. Ungated: `evm-rpc` implies
        // `rgb-validation`, so reaching here means the bind is compiled in.
        let authorized = crate::networks::rgb::invoice::parse_authorized_recipient(
            &verified.destination_address,
        )?;
        crate::networks::rgb::invoice::assert_recipient_authorized(
            &destination_proof.rgb_recipient_seals,
            &authorized,
        )?;
    }

    // Fail-closed when the FundsIn verifier is not compiled in. Without
    // the `evm-rpc` feature there is no evidence the deposit
    // occurred: the consignment/PSBT checks prove the transfer shape, not that
    // an EVM deposit backs it. Mirrors the no-`spv` fundsOut refusal.
    // dev-mode keeps the legacy path for local testing.
    #[cfg(all(not(feature = "evm-rpc"), not(feature = "dev-mode")))]
    if matches!(
        (source_ref, destination_ref),
        (
            SourceNetwork::EvmSource(_),
            DestinationNetwork::RgbDestination(_)
        )
    ) {
        return Err(EnclaveError::CrossCheck(
            "enclave was not built with --features evm-rpc: refusing to sign a bridge-mode PSBT \
             without independently verifying the FundsIn deposit (the listener-supplied \
             event_valid/event_finalized booleans are no longer trusted). \
             Rebuild with `--features evm-rpc` (or `helios` for the trustless path)."
                .into(),
        ));
    }

    // Soft operation-uniqueness guard: reject a same-op
    // resubmission inside the TTL window. Defense in depth only - the guard is
    // in-memory, per-instance, and volatile. The key is reserved before signing
    // (so a concurrent duplicate is rejected up front) and committed only after
    // it succeeds, so a transient error does not self-block a retry.
    #[cfg(not(feature = "dev-mode"))]
    let _op_reservation = if let (
        SourceNetwork::EvmSource(source),
        DestinationNetwork::RgbDestination(destination),
    ) = (source_ref, destination_ref)
    {
        let op_key = crate::networks::rgb::psbt_validation::psbt_operation_key(
            ctx.bridge_config.chain_id,
            &ctx.bridge_config.bridge_contract,
            &source.tx_hash,
            &source.funds_in_operation_id,
            &destination.asset_id,
        );
        match ctx.state.op_replay_guard.reserve(op_key) {
            Ok(reservation) => Some(reservation),
            Err(EnclaveError::NonceReplay) => {
                tracing::warn!(
                    funds_in_operation_id = %hex::encode(&source.funds_in_operation_id),
                    evm_tx_hash = %hex::encode(&source.tx_hash),
                    "rejecting duplicate bridge PSBT operation (soft replay guard)"
                );
                return Err(EnclaveError::CrossCheck(
                    "duplicate bridge operation: this (chain, contract, evm_tx_hash, \
                     funds_in_operation_id, rgb_asset_id) was already signed recently - refusing \
                     to sign a replay (soft in-memory guard; durable guard is on-chain)"
                        .into(),
                ));
            }
            Err(e) => return Err(e),
        }
    } else {
        None
    };

    let destination = req.destination_network.ok_or_else(|| {
        EnclaveError::InvalidRequest("sign request has no destination_network".into())
    })?;

    let result = match destination {
        DestinationNetwork::EvmDestination(destination) => {
            // RGB->EVM `fundsOut` binding: tie the calldata about to be signed
            // to the operation `validate()` authenticated - witness
            // confirmation, BtcRelay agreement, and the consignment-bound
            // release amount.
            //
            // RGB-source-only. A CCD source carries no consignment and a
            // CcdSource -> EvmDestination release is already authorized above;
            // applying the binding unconditionally rejected those signs.
            #[cfg(feature = "rgb-validation")]
            if let SourceNetwork::RgbSource(rgb_source) = source_ref {
                apply_funds_out_binding(
                    ctx,
                    destination_proof.evm_funds_out.as_ref(),
                    source_validated.rgb_consignment.as_ref(),
                    &rgb_source.merkle_proofs,
                )?;
            }
            handle_sign_evm(ctx, destination, destination_proof.evm_funds_out.as_ref())
        }
        DestinationNetwork::RgbDestination(destination) => handle_sign_psbt(ctx, destination),
    };

    // Commit the soft-guard reservation only once signing has succeeded. On
    // error `_op_reservation` drops here un-committed and rolls the key back, so
    // a transient signing failure does not consume it.
    #[cfg(not(feature = "dev-mode"))]
    if result.is_ok() {
        if let Some(reservation) = _op_reservation {
            reservation.commit();
        }
    }

    result
}

/// Bind an RGB->EVM `fundsOut` calldata to the validated consignment before the
/// enclave signs it. Skipped in dev-mode (like the other cross-checks) and a
/// no-op for non-`fundsOut` calldata. For the currently enabled swap flow, the
/// backend-provided general bridge operation ids are validated but not rewritten.
#[cfg(feature = "rgb-validation")]
fn apply_funds_out_binding(
    ctx: &ServerContext,
    params: Option<&crate::networks::evm::validation::FundsOutParams>,
    validated: Option<&crate::networks::rgb::validation::ValidatedConsignment>,
    merkle_proofs: &[crate::proto::MerkleProofEntry],
) -> Result<()> {
    use crate::networks::evm::crosscheck;

    if cfg!(all(feature = "dev-mode", not(test))) {
        return Ok(());
    }

    // `Some` exactly when destination validation decoded a `fundsOut` calldata,
    // so the type replaces the old selector check.
    let Some(params) = params else {
        return Ok(());
    };

    // A `fundsOut` release requires the RGB source's validated consignment
    // (source == RgbSource, rgb_validator configured, consignment present).
    let validated = validated.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "fundsOut signing requires a validated RGB source consignment (the source must be an \
             RGB source with consignment bytes and a configured rgb_validator) - refusing to sign"
                .into(),
        )
    })?;

    // Defense-in-depth: every consignment witness tx must be mined.
    crosscheck::assert_witnesses_confirmed(validated)?;

    // BtcRelay agreement + source-block bind (#57 / #122): the calldata `proof`
    // must name headers the enclave holds, and its `source` pair must be the
    // block anchoring the consignment's last witness tx. Fail-closed on an
    // empty `proof`. The SPV header chain is always present under
    // rgb-validation (spv is implied - see lib.rs M-01 compile_error).
    #[cfg(feature = "spv")]
    {
        // Fail on a poisoned lock rather than reading through it, matching
        // `validate_source`: a poisoned header chain may be mid-reorg.
        let chain = ctx
            .header_chain
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("SPV header chain lock poisoned: {e}")))?;
        crosscheck::verify_btc_relay_agreement(params, validated, merkle_proofs, &chain)?;
    }
    #[cfg(not(feature = "spv"))]
    let _ = (ctx, merkle_proofs);

    // Consignment-bound release amount, under this build's RGB flow
    // (`rgb-swap` = Transfer, `rgb-mint-burn` = Burn).
    crosscheck::validate_funds_out_amount(params, validated)?;

    // The backend-provided burnId and settlement fundsInIds are preserved; the
    // EVM connector already selected the latter against the on-chain remaining
    // balance. Mint/burn still needs a network-id-routed path before its RGB
    // OpId binding can be enabled.

    Ok(())
}

fn handle_initialize(ctx: &ServerContext, req: InitializeKeyRequest) -> Result<EnclaveResponse> {
    let state = &ctx.state;
    if !req.mnemonic.is_empty() {
        // Testing path: import from BIP-39 mnemonic phrase
        #[cfg(feature = "allow-seed-import")]
        {
            state.initialize_from_mnemonic(&req.mnemonic)?;
            tracing::info!("key initialized from imported mnemonic");
        }
        #[cfg(not(feature = "allow-seed-import"))]
        {
            return Err(EnclaveError::InvalidRequest(
                "mnemonic import not allowed without allow-seed-import feature".into(),
            ));
        }
    } else if req.seed.is_empty() {
        // Production path: generate from OS entropy
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy)
            .map_err(|e| EnclaveError::Internal(format!("entropy generation failed: {}", e)))?;
        let _mnemonic = state.initialize_from_entropy(&mut entropy)?;
        tracing::info!("key initialized from new mnemonic");
    } else {
        // Testing path: import raw seed
        #[cfg(feature = "allow-seed-import")]
        {
            let seed: [u8; 64] = req.seed.try_into().map_err(|v: Vec<u8>| {
                EnclaveError::InvalidRequest(format!(
                    "seed must be exactly 64 bytes, got {}",
                    v.len()
                ))
            })?;
            state.initialize_from_seed(seed)?;
            tracing::info!("key initialized from imported seed");
        }
        #[cfg(not(feature = "allow-seed-import"))]
        {
            return Err(EnclaveError::InvalidRequest(
                "seed import not allowed without allow-seed-import feature".into(),
            ));
        }
    }

    // Donor-side cloning secret, delivered at runtime via the init message
    // (never baked into the EIF, so it stays out of the PCRs). Only required
    // for enclaves that will serve `GetClone`. Idempotent; empty = disabled.
    if !req.cloning_secret.is_empty() {
        state.set_donor_cloning_secret(req.cloning_secret)?;
        tracing::info!("donor cloning secret configured from init request");
    }

    let keys = state.get_keys()?;
    tracing::info!(
        evm_address = %hex::encode(keys.evm_address),
        evm_gas_tx_address = %hex::encode(keys.evm_gas_tx_address),
        btc_compressed_pub = %hex::encode(keys.btc_compressed_pubkey),
        ccd_ed25519_pub = %hex::encode(keys.ccd_ed25519_pub),
        master_fingerprint = %hex::encode(keys.master_fingerprint),
        account_xpub_vanilla = %keys.account_xpub_vanilla,
        account_xpub_colored = %keys.account_xpub_colored,
        "keys initialized"
    );
    Ok(EnclaveResponse {
        response: Some(Response::InitializeKey(InitializeKeyResponse {
            evm_address: keys.evm_address.to_vec(),
            btc_compressed_pub: keys.btc_compressed_pubkey.to_vec(),
            btc_xpub: keys.btc_xpub,
            master_fingerprint: keys.master_fingerprint.to_vec(),
            account_xpub_vanilla: keys.account_xpub_vanilla,
            account_xpub_colored: keys.account_xpub_colored,
            evm_uncompressed_pub: keys.evm_uncompressed_pub.to_vec(),
            chain_id: ctx.bridge_config.chain_id,
            bridge_contract: ctx.bridge_config.bridge_contract.to_vec(),
            rgb_asset_id: ctx.bridge_config.rgb_asset_id.clone(),
            evm_gas_tx_uncompressed_pub: keys.evm_gas_tx_uncompressed_pub.to_vec(),
            evm_gas_tx_address: keys.evm_gas_tx_address.to_vec(),
            ccd_ed25519_pub: keys.ccd_ed25519_pub.to_vec(),
        })),
    })
}

fn handle_get_public_key(
    ctx: &ServerContext,
    _req: GetPublicKeyRequest,
) -> Result<EnclaveResponse> {
    let keys = ctx.state.get_keys()?;
    tracing::debug!(
        evm_address = %hex::encode(keys.evm_address),
        evm_gas_tx_address = %hex::encode(keys.evm_gas_tx_address),
        "returning public keys"
    );
    Ok(EnclaveResponse {
        response: Some(Response::PublicKeys(build_public_keys_response(
            keys,
            &ctx.bridge_config,
        ))),
    })
}

/// Single place that assembles a `PublicKeysResponse`, keeping the field order
/// matching `canonical_pubkey_bundle`. A new field must be added to the bundle
/// and to the verifier mirror in
/// `parent/src/attest_verify.rs::canonical_bundle`.
fn build_public_keys_response(
    keys: crate::keys::KeyInfo,
    cfg: &BridgeConfig,
) -> PublicKeysResponse {
    PublicKeysResponse {
        evm_address: keys.evm_address.to_vec(),
        btc_compressed_pub: keys.btc_compressed_pubkey.to_vec(),
        btc_xpub: keys.btc_xpub,
        master_fingerprint: keys.master_fingerprint.to_vec(),
        account_xpub_vanilla: keys.account_xpub_vanilla,
        account_xpub_colored: keys.account_xpub_colored,
        evm_uncompressed_pub: keys.evm_uncompressed_pub.to_vec(),
        chain_id: cfg.chain_id,
        bridge_contract: cfg.bridge_contract.to_vec(),
        rgb_asset_id: cfg.rgb_asset_id.clone(),
        evm_gas_tx_uncompressed_pub: keys.evm_gas_tx_uncompressed_pub.to_vec(),
        evm_gas_tx_address: keys.evm_gas_tx_address.to_vec(),
        ccd_ed25519_pub: keys.ccd_ed25519_pub.to_vec(),
    }
}

/// Build the canonical bundle that the verifier hashes to check `user_data`.
///
/// Length-prefixed (u32 BE) concatenation of every field in
/// PublicKeysResponse, in proto field order. Strings are encoded as their
/// UTF-8 bytes; `chain_id` as 8-byte big-endian (its length prefix is the
/// constant 8). Order and field set MUST match the verifier - see
/// `docs/pubkey-attestation.md` and `parent/src/attest_verify.rs::canonical_bundle`.
fn canonical_pubkey_bundle(keys: &PublicKeysResponse) -> Vec<u8> {
    let chain_id_bytes = keys.chain_id.to_be_bytes();
    let parts: [&[u8]; 13] = [
        &keys.evm_address,
        &keys.btc_compressed_pub,
        keys.btc_xpub.as_bytes(),
        &keys.master_fingerprint,
        keys.account_xpub_vanilla.as_bytes(),
        keys.account_xpub_colored.as_bytes(),
        &keys.evm_uncompressed_pub,
        &chain_id_bytes,
        &keys.bridge_contract,
        keys.rgb_asset_id.as_bytes(),
        &keys.evm_gas_tx_uncompressed_pub,
        &keys.evm_gas_tx_address,
        &keys.ccd_ed25519_pub,
    ];
    let total: usize = parts.iter().map(|p| 4 + p.len()).sum();
    let mut out = Vec::with_capacity(total);
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

fn handle_get_attested_public_key(
    ctx: &ServerContext,
    req: GetAttestedPublicKeyRequest,
) -> Result<EnclaveResponse> {
    use sha2::{Digest, Sha256};

    let nonce: [u8; 32] = req.nonce.as_slice().try_into().map_err(|_| {
        EnclaveError::InvalidRequest(format!("nonce must be 32 bytes, got {}", req.nonce.len()))
    })?;

    // This endpoint attests over a caller-supplied nonce, so it can
    // mint attestations for arbitrary nonces. Safe for replay accounting: the
    // cloning handlers record a nonce only after a fully-authenticated
    // handshake, so an oracle-minted nonce cannot exhaust the guard.
    let keys = ctx.state.get_keys()?;
    let public_keys = build_public_keys_response(keys, &ctx.bridge_config);

    // The attestation `user_data` commits to BOTH the public-key bundle and the
    // enclave's resolved security policy, so a verifier checks the
    // whole posture as one value: sha256(pubkey_bundle || policy_commitment).
    // The verifier mirror is `parent/src/attest_verify.rs::verify_attested_pubkey`.
    let mut preimage = canonical_pubkey_bundle(&public_keys);
    preimage.extend_from_slice(&ctx.policy.commitment_bytes());
    let commitment: [u8; 32] = Sha256::digest(&preimage).into();

    let attestation_doc = crate::attestation::get_attestation(
        &nonce,
        Some(&public_keys.evm_uncompressed_pub),
        Some(&commitment),
    )?;

    tracing::info!(
        evm_address = %hex::encode(&public_keys.evm_address),
        commitment = %hex::encode(commitment),
        attestation_bytes = attestation_doc.len(),
        "returning attested public keys"
    );

    Ok(EnclaveResponse {
        response: Some(Response::GetAttestedPublicKey(
            GetAttestedPublicKeyResponse {
                public_keys: Some(public_keys),
                attestation_doc,
            },
        )),
    })
}

/// `params` comes from destination validation, so the digest commits to exactly
/// the fields cross-checked there. `None` in dev-mode, which skips
/// validation and therefore decodes here, and on the LayerZero route, whose
/// param shape is not `FundsOutParams` - `lz_funds_out_digest` decodes its own.
fn handle_sign_evm(
    ctx: &ServerContext,
    req: EvmDestination,
    params: Option<&crate::networks::evm::validation::FundsOutParams>,
) -> Result<EnclaveResponse> {
    // Domain name/version are pinned to the deployed MultisigProxy and
    // regression-guarded by `test_domain_separator_matches_deployed_contract`.
    let domain = build_evm_domain(&req)?;

    let domain_sep = domain.separator_hash();

    // Route by selector and lz_release. `lzFundsOutCall` carries LZ-specific
    // fields the digest commits to; the proto field is the authority and the
    // calldata selector is only a consistency check (see lz_funds_out_digest).
    let is_lz = req.call_data.len() >= 4
        && req.call_data[..4] == LZ_FUNDS_OUT_SELECTOR
        && req.lz_release.is_some();

    let digest = if is_lz {
        lz_funds_out_digest(
            &domain,
            &req.call_data,
            req.lz_release.as_ref().expect("checked above"),
            req.nonce,
            req.deadline,
        )?
    } else {
        // `params` is `Some` on the pools route whenever validation ran, so the
        // digest commits to exactly the fields cross-checked there. Dev-mode
        // skips validation and therefore decodes here.
        let decoded_here;
        let params = match params {
            Some(params) => params,
            None => {
                decoded_here =
                    crate::networks::evm::validation::decode_funds_out_params(&req.call_data)?;
                &decoded_here
            }
        };
        funds_out_digest(&domain, params, req.nonce, req.deadline)?
    };

    tracing::info!(
        domain_name = %domain.name,
        chain_id = domain.chain_id,
        proxy = %hex::encode(domain.verifying_contract),
        domain_sep = %hex::encode(domain_sep),
        call_data_len = req.call_data.len(),
        selector = %hex::encode(&req.call_data[..4.min(req.call_data.len())]),
        nonce = req.nonce,
        deadline = req.deadline,
        digest = %hex::encode(digest),
        "EVM digest computed"
    );

    let signature = ctx.state.sign_evm(&digest)?;

    tracing::info!(
        sig_hex = %hex::encode(signature),
        "EVM signature produced"
    );

    Ok(EnclaveResponse {
        response: Some(Response::EvmSignature(EvmSignatureResponse {
            signature: signature.to_vec(),
            // Echoed unchanged; nothing rewrites the calldata.
            call_data: req.call_data.clone(),
        })),
    })
}

fn handle_sign_psbt(ctx: &ServerContext, req: RgbDestination) -> Result<EnclaveResponse> {
    // Sats gate: every other send-RGB bind is in RGB asset units, so without
    // this a witness tx can satisfy the ledger and still sweep the Bitcoin
    // backing. dev-mode keeps the unbounded path.
    #[cfg(not(feature = "dev-mode"))]
    {
        let psbt = crate::networks::rgb::psbt_validation::parse_psbt_shape(&req.psbt_bytes)?;
        ctx.state.with_keys(|keys| {
            crate::networks::rgb::btc_crosscheck::validate_rgb_psbt_sats(
                &psbt,
                &ctx.bridge_config,
                keys,
            )
        })?;
    }

    // Colored account only: an unscoped sign co-signs every input the enclave
    // can derive a key for, including vanilla inputs no send-RGB bind examines.
    let (signed_psbt, inputs_signed) = ctx
        .state
        .sign_psbt_scoped(&req.psbt_bytes, Some(crate::keys::AccountType::Colored))?;

    // Reject a "successful" no-op: `sign_psbt` returns
    // Ok((bytes, 0)) when no input belongs to this enclave, which a caller
    // checking only RPC success would mis-count as a signer contribution.
    // Partial signing (0 < count < num_inputs) is still allowed. dev-mode keeps
    // the 0-count path for inspect/dry-run.
    #[cfg(not(feature = "dev-mode"))]
    if inputs_signed == 0 {
        return Err(EnclaveError::Signing(
            "sign_psbt signed 0 inputs: no PSBT input belongs to this enclave - refusing to \
             return a no-op as a successful signing response"
                .into(),
        ));
    }

    tracing::info!(inputs_signed, "PSBT signed");

    Ok(EnclaveResponse {
        response: Some(Response::SignedPsbt(SignedPsbtResponse {
            signed_psbt,
            inputs_signed: inputs_signed as u32,
        })),
    })
}

/// Sign a plain-BTC PSBT (create_utxo / UTXO management). Unlike
/// [`handle_sign_psbt`] this path carries no RGB consignment and no EVM event.
/// Authorized by proving every output pays back to a script the enclave
/// controls, plus the operator-pinned amount cap
/// ([`crate::networks::rgb::btc_crosscheck`]); a production build refuses to
/// sign while that cap is unset. Its own request type is the structural half of
/// the vanilla-bypass fix.
fn handle_sign_btc(ctx: &ServerContext, req: SignBtcRequest) -> Result<EnclaveResponse> {
    // Posture check: in production the plain-BTC path is reachable only when
    // the attested policy enables it. Same predicate
    // `validate_btc_request` enforces, but read from the resolved policy, whose
    // state is committed into attestation `user_data`.
    if let crate::policy::SecurityPolicy::Production(p) = &ctx.policy {
        if !p.allow_vanilla_psbt {
            return Err(EnclaveError::Signing(
                "plain-BTC (vanilla) signing is disabled by the enclave's production security \
                 policy (BTC_MAX_TOTAL_SATS unset) - refusing to sign"
                    .into(),
            ));
        }
    }

    // Output self-ownership + amount cap (skipped only in dev-mode). Runs
    // against the enclave's own keys, so an uninitialized enclave fails here
    // with KeyNotInitialized rather than reaching the signer.
    #[cfg(not(feature = "dev-mode"))]
    ctx.state.with_keys(|keys| {
        crate::networks::rgb::btc_crosscheck::validate_btc_request(&req, &ctx.bridge_config, keys)
    })?;

    // Restricted to the Vanilla account: no Colored (RGB-allocated) input is
    // co-signed here, so plain-BTC signing cannot move RGB funds. createUtxos
    // and sendBtc spend only vanilla UTXOs, so nothing legitimate is blocked.
    let (signed_psbt, inputs_signed) = ctx
        .state
        .sign_psbt_scoped(&req.psbt_bytes, Some(crate::keys::AccountType::Vanilla))?;

    // Mirror the bridge path's guard: a 0-input signing is a no-op and
    // must not be returned as a successful signature in production.
    #[cfg(not(feature = "dev-mode"))]
    if inputs_signed == 0 {
        return Err(EnclaveError::Signing(
            "sign_btc signed 0 inputs: no PSBT input belongs to this enclave - refusing to \
             return a no-op as a successful signing response"
                .into(),
        ));
    }

    tracing::info!(inputs_signed, "plain-BTC PSBT signed");

    Ok(EnclaveResponse {
        response: Some(Response::SignedPsbt(SignedPsbtResponse {
            signed_psbt,
            inputs_signed: inputs_signed as u32,
        })),
    })
}

fn handle_sign_raw_digest(
    ctx: &ServerContext,
    req: SignRawDigestRequest,
) -> Result<EnclaveResponse> {
    // Gas-tx shape allowlist. Production refuses to
    // blind-sign an opaque digest: the request must carry the unsigned tx
    // preimage, which the enclave decodes, checks against the operator pins, and
    // hashes itself (see `networks::evm::gas_tx`). dev-mode keeps the legacy
    // opaque-digest path for local testing.
    #[cfg(not(feature = "dev-mode"))]
    let digest = crate::networks::evm::gas_tx::validate_gas_tx_request(&req, &ctx.bridge_config)?;

    #[cfg(feature = "dev-mode")]
    let digest: [u8; 32] = {
        if req.digest.len() != 32 {
            return Err(EnclaveError::InvalidRequest(format!(
                "digest must be exactly 32 bytes, got {}",
                req.digest.len()
            )));
        }
        req.digest.as_slice().try_into().unwrap()
    };

    let signature = ctx.state.sign_evm_gas_tx(&digest)?;

    tracing::info!(
        sig_hex = %hex::encode(signature),
        digest_hex = %hex::encode(digest),
        "raw digest signature produced (evm_gas_tx key)"
    );

    Ok(EnclaveResponse {
        response: Some(Response::RawDigestSig(RawDigestSignatureResponse {
            signature: signature.to_vec(),
        })),
    })
}

/// Sign a 32-byte Concordium account-transaction hash with the governance
/// Ed25519 key. The listener has already re-derived the hash and verified the
/// transaction structure/amounts; the enclave signs the hash directly. Returns
/// a 64-byte Ed25519 signature.
#[cfg(feature = "ccd")]
fn handle_sign_ccd(state: &EnclaveState, req: SignCcdRequest) -> Result<EnclaveResponse> {
    if req.hash.len() != 32 {
        return Err(EnclaveError::InvalidRequest(format!(
            "hash must be exactly 32 bytes, got {}",
            req.hash.len()
        )));
    }

    let hash: [u8; 32] = req.hash.as_slice().try_into().unwrap();
    let (signature, public_key) = state.sign_ccd(&hash)?;

    tracing::info!(
        hash_hex = %hex::encode(hash),
        "concordium signature produced (ed25519 governance key)"
    );

    Ok(EnclaveResponse {
        response: Some(Response::CcdSignature(CcdSignatureResponse {
            signature: signature.to_vec(),
            // Ed25519 signatures are not recoverable, so the consumer needs the
            // key to locate this signature's index on the governance account.
            // Read from the same call that signed.
            public_key: public_key.to_vec(),
        })),
    })
}

fn handle_proxy_federation(_req: ProxyFederationRequest) -> Result<EnclaveResponse> {
    // Stub: federation proxy requires Listener integration (not yet wired)
    Ok(EnclaveResponse {
        response: Some(Response::Error(ErrorResponse {
            code: 2, // NOT_READY
            message: "federation proxy not yet connected to Listener".into(),
        })),
    })
}

// SPV header sync handlers. The chain itself lives in `ctx.header_chain`,
// initialised at boot from the compile-time checkpoint for the active
// network (see main.rs).
//
// A poisoned mutex means a previous handler panicked while holding the lock.
// The only mutation is `submit_headers`, which never panics, but if it happens
// the poison is cleared rather than wedging the enclave: all mutations are
// atomic, so the chain is still consistent.
#[cfg(feature = "spv")]
fn handle_submit_headers(
    ctx: &ServerContext,
    req: SubmitHeadersRequest,
) -> Result<EnclaveResponse> {
    // Cumulative rate limit: bound the aggregate submission rate across
    // calls. The per-call cap is enforced inside `submit_headers`.
    ctx.submit_rate_limiter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .check(req.headers.len() as u64, std::time::SystemTime::now())?;

    let mut chain = ctx
        .header_chain
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let outcome = chain.submit_headers(req.start_height, &req.headers)?;

    tracing::info!(
        last_block_height = outcome.last_block_height,
        headers_accepted = outcome.headers_accepted,
        reorg_depth = outcome.reorg_depth,
        "SubmitHeaders outcome"
    );

    Ok(EnclaveResponse {
        response: Some(Response::SubmitHeaders(SubmitHeadersResponse {
            last_block_height: outcome.last_block_height,
            last_block_hash: outcome.last_block_hash.to_vec(),
            headers_accepted: outcome.headers_accepted,
        })),
    })
}

#[cfg(feature = "spv")]
fn handle_get_last_saved_block(
    ctx: &ServerContext,
    _req: GetLastSavedBlockRequest,
) -> Result<EnclaveResponse> {
    let chain = ctx
        .header_chain
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let height = chain.tip_height();
    let hash = chain.tip_hash();

    tracing::debug!(
        block_height = height,
        block_hash = %hex::encode(hash),
        "GetLastSavedBlock"
    );

    Ok(EnclaveResponse {
        response: Some(Response::GetLastSavedBlock(GetLastSavedBlockResponse {
            block_height: height,
            block_hash: hash.to_vec(),
        })),
    })
}

// Cloning handshake
//
// See proto/enclave.proto for the full protocol description.

use crate::attestation;
use crate::cloning::{self, CloneSession};
use crate::state::CloningSession;

fn fresh_nonce() -> Result<[u8; 32]> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n)
        .map_err(|e| EnclaveError::Internal(format!("entropy generation failed: {}", e)))?;
    Ok(n)
}

/// Requester side. Transitions `Initial -> Cloning`. Generates an
/// ephemeral X25519 keypair, binds it into an NSM attestation together
/// with the HMAC digest of (cloning_secret, pubkey), and returns the
/// three fields the parent needs to relay to the donor.
fn handle_initiate_cloning(
    state: &EnclaveState,
    req: InitiateCloningRequest,
) -> Result<EnclaveResponse> {
    if req.cloning_secret.is_empty() {
        return Err(EnclaveError::InvalidRequest(
            "cloning_secret is required".into(),
        ));
    }
    let cluster_public_key: [u8; 20] =
        req.cluster_public_key.as_slice().try_into().map_err(|_| {
            EnclaveError::InvalidRequest(format!(
                "cluster_public_key must be 20 bytes, got {}",
                req.cluster_public_key.len()
            ))
        })?;

    let session = CloneSession::new();
    let encryption_pubkey = session.public_key();

    let nonce = fresh_nonce()?;
    let cloning_digest = cloning::make_cloning_digest(&req.cloning_secret, &encryption_pubkey);

    // Bind both the X25519 pubkey and the digest into the NSM signature:
    // the parent cannot rewrite either without invalidating the attestation.
    let attestation =
        attestation::get_attestation(&nonce, Some(&encryption_pubkey), Some(&cloning_digest))?;

    state.enter_cloning(CloningSession::new(session, cluster_public_key))?;

    tracing::info!(
        cluster_pk = %hex::encode(cluster_public_key),
        "InitiateCloning: entered Cloning phase"
    );

    Ok(EnclaveResponse {
        response: Some(Response::InitiateCloning(InitiateCloningResponse {
            requester_attestation: attestation,
            encryption_pubkey: encryption_pubkey.to_vec(),
            cloning_digest: cloning_digest.to_vec(),
        })),
    })
}

/// Donor side. Stays in `Phase::Active`. Verifies the requester's
/// attestation, matches PCRs, records the nonce against replay, checks
/// pubkey + digest binding, verifies the digest against the configured
/// donor-side cloning secret, and only then seals the seed.
fn handle_get_clone(state: &EnclaveState, req: GetCloneRequest) -> Result<EnclaveResponse> {
    let req_cluster_pk: [u8; 20] = req.cluster_public_key.as_slice().try_into().map_err(|_| {
        EnclaveError::InvalidRequest(format!(
            "cluster_public_key must be 20 bytes, got {}",
            req.cluster_public_key.len()
        ))
    })?;
    let req_encryption_pk: [u8; 32] =
        req.encryption_pubkey.as_slice().try_into().map_err(|_| {
            EnclaveError::InvalidRequest(format!(
                "encryption_pubkey must be 32 bytes, got {}",
                req.encryption_pubkey.len()
            ))
        })?;
    let req_digest: [u8; 32] = req.cloning_digest.as_slice().try_into().map_err(|_| {
        EnclaveError::InvalidRequest(format!(
            "cloning_digest must be 32 bytes, got {}",
            req.cloning_digest.len()
        ))
    })?;

    // 1. Donor identity check: the request must address *this* enclave's
    //    public key. Prevents the parent from fanning one request out to
    //    unintended donors.
    let our_evm = state.evm_address()?;
    if req_cluster_pk != our_evm {
        return Err(EnclaveError::Clone(format!(
            "cluster_public_key {} does not match this enclave's address {}",
            hex::encode(req_cluster_pk),
            hex::encode(our_evm)
        )));
    }

    // 2. Verify the requester attestation chain + PCRs. `None` for the
    //    expected nonce: we have not seen the requester's nonce before,
    //    so freshness is enforced by the replay guard once the binding and
    //    authenticity checks below have passed.
    let expected_pcrs = attestation::get_own_pcrs()?;
    let verified =
        attestation::verify_peer_attestation(&req.requester_attestation, &expected_pcrs, None)?;

    // 3. Pubkey binding: the attestation's `public_key` field must equal
    //    the one the parent put on the wire. Otherwise the parent could
    //    have swapped it for a key it controls.
    if verified.enclave_pubkey.as_slice() != req_encryption_pk {
        return Err(EnclaveError::PubkeyMismatch);
    }

    // 4. Digest binding: the attestation's `user_data` must equal the
    //    digest on the wire - NSM-signed, so parent-proof.
    let user_data = verified.user_data.as_deref().ok_or_else(|| {
        EnclaveError::Attestation("requester attestation missing user_data (cloning digest)".into())
    })?;
    if user_data != req_digest {
        return Err(EnclaveError::DigestMismatch);
    }

    // 5. Digest authenticity: HMAC(donor_secret, encryption_pubkey) must
    //    match. Proves the requester was issued by the same operator.
    state.with_donor_cloning_secret(|secret| {
        if !cloning::verify_cloning_digest(secret, &req_encryption_pk, &req_digest) {
            return Err(EnclaveError::DigestMismatch);
        }
        Ok(())
    })?;

    // 6. Replay-check + record the nonce from the verified document, only
    //    after the checks above have passed, so an unauthenticated handshake
    //    never consumes replay-guard capacity. With the count-cap removal
    // this closes the secret-less cloning-availability DoS.
    let nonce_array: [u8; 32] = verified
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Attestation("attestation nonce has wrong length".into()))?;
    state.replay_guard.check_and_record(nonce_array)?;

    // 7. Seal the seed under a fresh donor ephemeral keypair.
    let (encrypted_seed, donor_pubkey) =
        state.with_seed(|seed| cloning::encrypt_seed_for_peer(&req_encryption_pk, seed))?;

    // 8. Donor's own attestation. Fresh nonce, binds the donor pubkey we
    //    just produced so the requester can be sure this response is
    //    not an old one replayed by the parent.
    let donor_nonce = fresh_nonce()?;
    let donor_attestation = attestation::get_attestation(&donor_nonce, Some(&donor_pubkey), None)?;

    tracing::info!(
        cluster_pk = %hex::encode(our_evm),
        "GetClone: sealed seed for requester"
    );

    Ok(EnclaveResponse {
        response: Some(Response::GetClone(GetCloneResponse {
            encrypted_seed,
            donor_pubkey: donor_pubkey.to_vec(),
            donor_attestation,
        })),
    })
}

/// Requester side. Transitions `Cloning -> Active`. Verifies the donor's
/// attestation, unseals the ciphertext, and commits the derived keys
/// only if the resulting EVM address matches `cluster_public_key`.
fn handle_set_clone(state: &EnclaveState, req: SetCloneRequest) -> Result<EnclaveResponse> {
    let donor_pubkey: [u8; 32] = req.donor_pubkey.as_slice().try_into().map_err(|_| {
        EnclaveError::InvalidRequest(format!(
            "donor_pubkey must be 32 bytes, got {}",
            req.donor_pubkey.len()
        ))
    })?;

    // 1. Verify donor attestation chain + PCRs (no nonce match - freshness
    //    is enforced by the replay guard once the binding and seed/identity
    //    checks below have passed).
    let expected_pcrs = attestation::get_own_pcrs()?;
    let verified =
        attestation::verify_peer_attestation(&req.donor_attestation, &expected_pcrs, None)?;

    // 2. Pubkey binding: the donor's pubkey on the wire must equal the
    //    one inside their signed attestation.
    if verified.enclave_pubkey.as_slice() != donor_pubkey {
        return Err(EnclaveError::PubkeyMismatch);
    }

    // 3. Decrypt seed, derive KeyManager, identity check, and commit the
    //    Cloning -> Active transition - all atomically under the state
    //    lock via `complete_cloning`. On any failure the state stays in
    //    Cloning and the handshake can be retried.
    let network = state.network();
    let mut cluster_public_key = [0u8; 20];
    state.complete_cloning(|session| {
        let seed = session
            .session
            .decrypt_seed_from_peer(&donor_pubkey, &req.encrypted_seed)?;
        let km = crate::keys::KeyManager::from_seed(*seed, network)?;
        if km.evm_address() != &session.cluster_public_key {
            return Err(EnclaveError::IdentityMismatch);
        }
        cluster_public_key = session.cluster_public_key;
        Ok(km)
    })?;

    // 4. Replay-check + record the donor nonce only *after* the pubkey
    //    binding and the seed/identity checks above have passed, so a
    // rejected handshake never consumes replay-guard capacity.
    let nonce_array: [u8; 32] = verified
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Attestation("attestation nonce has wrong length".into()))?;
    state.replay_guard.check_and_record(nonce_array)?;

    tracing::info!(
        cluster_pk = %hex::encode(cluster_public_key),
        "SetClone: cloned, transitioned to Active"
    );

    Ok(EnclaveResponse {
        response: Some(Response::SetClone(SetCloneResponse {})),
    })
}

// These tests cover only the SPV `SubmitRateLimiter`, so they are gated with
// the RGB/BTC stack (`spv`).
#[cfg(all(test, feature = "spv"))]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn rate_limiter_allows_up_to_budget_then_rejects() {
        let mut limiter = SubmitRateLimiter::default();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        // Spending exactly the budget across several calls within the window
        // is fine.
        limiter
            .check(MAX_HEADERS_PER_RATE_WINDOW - 1, t0)
            .expect("under budget");
        limiter
            .check(1, t0 + Duration::from_secs(1))
            .expect("exactly at budget");

        // One more header in the same window trips the limit.
        let err = limiter.check(1, t0 + Duration::from_secs(2)).unwrap_err();
        assert!(matches!(err, EnclaveError::Spv(_)));
    }

    #[test]
    fn rate_limiter_resets_after_window() {
        let mut limiter = SubmitRateLimiter::default();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        limiter
            .check(MAX_HEADERS_PER_RATE_WINDOW, t0)
            .expect("fills the budget");
        // Still in-window: rejected.
        assert!(limiter
            .check(1, t0 + RATE_LIMIT_WINDOW - Duration::from_secs(1))
            .is_err());
        // After the window elapses, the budget resets.
        limiter
            .check(MAX_HEADERS_PER_RATE_WINDOW, t0 + RATE_LIMIT_WINDOW)
            .expect("window reset");
    }

    #[test]
    fn rate_limiter_handles_clock_going_backwards() {
        let mut limiter = SubmitRateLimiter::default();
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
        limiter.check(10, t1).expect("first call");
        // An earlier timestamp (clock skew) resets the window rather than
        // panicking or underflowing.
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        limiter
            .check(10, t0)
            .expect("backwards clock resets window");
    }
}
