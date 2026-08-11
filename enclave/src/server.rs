use std::io::{Read, Write};

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::framing;
use crate::networks::evm::signing::{build_evm_domain, evm_digest};
use crate::networks::{
    validate_destination, validate_route_proofs, validate_source, ValidationContext,
};
use crate::proto::enclave_request::Request;
use crate::proto::enclave_response::Response;
use crate::proto::*;
use crate::state::EnclaveState;
use federated_signer_proto::enclave::sign_request::{DestinationNetwork, SourceNetwork};

/// Shared context passed to every request handler.
pub struct ServerContext {
    pub state: EnclaveState,
    /// Bridge config pinned at boot from env. Folded into the attestation
    /// `user_data` commitment and used to cross-check `SignEvm` requests
    /// against operator-pinned values.
    pub bridge_config: BridgeConfig,
    #[cfg(feature = "rgb-validation")]
    pub rgb_validator: Option<crate::networks::rgb::validation::RgbValidator>,
    /// In-enclave EVM RPC client for independent `FundsIn` verification (#60).
    /// `None` when the client could not be built; `handle_sign` fails closed on
    /// `None` in bridge mode. Reaches the RPC only through the loopback vsock
    /// forwarder, so responses are host-relayed and untrusted - see
    /// [`crate::networks::evm::evm_event`].
    #[cfg(feature = "evm-rpc")]
    pub evm_rpc_client:
        Option<Box<dyn crate::networks::evm::evm_event::EvmReceiptProvider + Send + Sync>>,
    /// Pinned EVM-RPC config (loopback URL + min confirmations) for #60.
    #[cfg(feature = "evm-rpc")]
    pub evm_rpc_config: crate::config::EvmRpcConfig,
    /// In-enclave Bitcoin header chain for SPV verification. Populated at
    /// boot from the compile-time checkpoint; mutated by SubmitHeaders.
    /// `Mutex` because the enclave handles connections from a single
    /// thread today, but we want the type to stay correct if that ever
    /// changes — and `Mutex` over `RefCell` so a future move to
    /// multi-threaded handling needs no plumbing changes.
    pub header_chain: std::sync::Mutex<crate::networks::rgb::spv::HeaderChain>,
    /// Cumulative rate limit for `SubmitHeaders` (#86). The per-call cap lives
    /// in `HeaderChain::submit_headers`; this bounds the *aggregate* rate
    /// across calls so a flood of small batches can't keep the enclave busy.
    pub submit_rate_limiter: std::sync::Mutex<SubmitRateLimiter>,
}

/// Sliding-window rate limit for `SubmitHeaders` (#86 cumulative cap). At most
/// [`MAX_HEADERS_PER_RATE_WINDOW`] headers may be *submitted* (validated or
/// not) within [`RATE_LIMIT_WINDOW`]. Generous enough for a cold-start sync
/// from the checkpoint, tight enough that a sustained flood of replayed or
/// garbage headers can't occupy the enclave indefinitely.
#[derive(Default)]
pub struct SubmitRateLimiter {
    window_start: Option<std::time::SystemTime>,
    headers_in_window: u64,
}

/// Max headers admitted per [`RATE_LIMIT_WINDOW`]. A cold-start sync from the
/// mainnet checkpoint to the tip is a few thousand blocks, well inside this.
const MAX_HEADERS_PER_RATE_WINDOW: u64 = 100_000;
/// Length of the rate-limit window.
const RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

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
    pub fn new(
        state: EnclaveState,
        bridge_config: BridgeConfig,
        header_chain: std::sync::Mutex<crate::networks::rgb::spv::HeaderChain>,
    ) -> Self {
        Self {
            state,
            bridge_config,
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
        Some(Request::SignRawMessage(req)) => {
            tracing::info!("request: SignRawMessage");
            handle_sign_raw_message(&ctx.state, req)
        }
        Some(Request::SignRawDigest(req)) => {
            tracing::info!("request: SignRawDigest");
            handle_sign_raw_digest(ctx, req)
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
            handle_submit_headers(ctx, req)
        }
        Some(Request::GetLastSavedBlock(req)) => {
            tracing::info!("request: GetLastSavedBlock");
            handle_get_last_saved_block(ctx, req)
        }
        Some(Request::GetAttestedPublicKey(req)) => {
            tracing::info!("request: GetAttestedPublicKey");
            handle_get_attested_public_key(ctx, req)
        }
        Some(Request::SignCcd(_)) => {
            tracing::warn!("request: SignCcd - not supported by this build");
            Err(EnclaveError::InvalidRequest(
                "CCD signing is not supported by this enclave build".into(),
            ))
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

    let validation_ctx = ValidationContext {
        bridge_config: &ctx.bridge_config,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: ctx.rgb_validator.as_ref(),
        header_chain: &ctx.header_chain,
    };
    let source_validated = validate_source(req.amount, source_ref, &validation_ctx)?;

    let source_commission = match source_ref {
        SourceNetwork::EvmSource(source) => source.commission,
        SourceNetwork::RgbSource(source) => source.commission,
        SourceNetwork::CcdSource(_) => {
            return Err(EnclaveError::InvalidRequest(
                "CCD sources are not supported by this enclave build".into(),
            ))
        }
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
        &destination_proof,
    )?;

    // Independent EVM `FundsIn` verification (audit M-06 / #60, #51). In
    // EVM -> RGB bridge mode, confirm the deposit really happened on-chain - via
    // the enclave's own RPC call, not the listener's `event_valid` /
    // `event_finalized` booleans (which are no longer trusted; see
    // `evm::validation::validate_source`). Fail-closed: a missing client or any
    // unmet predicate refuses the signature. Runs after the cheap local
    // cross-checks and before the replay guard records the op, so the external
    // RPC is only paid once the request is otherwise valid.
    // NOTE: the RPC is reached through the untrusted host, so this becomes fully
    // trustless only once Helios (#77) verifies it; see
    // `crate::networks::evm::evm_event`.
    #[cfg(all(feature = "evm-rpc", not(feature = "dev-mode")))]
    if let (
        SourceNetwork::EvmSource(source),
        DestinationNetwork::RgbDestination(_) | DestinationNetwork::RgbInflationDestination(_),
    ) = (source_ref, destination_ref)
    {
        let tx_hash: [u8; 32] = source.tx_hash.as_slice().try_into().map_err(|_| {
            EnclaveError::CrossCheck(format!(
                "evm_tx_hash must be 32 bytes, got {}",
                source.tx_hash.len()
            ))
        })?;
        let client = ctx.evm_rpc_client.as_ref().ok_or_else(|| {
            EnclaveError::CrossCheck(
                "evm-rpc build but RPC client unavailable - refusing to sign a bridge PSBT \
                 without independently verifying the FundsIn deposit"
                    .into(),
            )
        })?;
        // Binds to the source's BridgeFundsIn.operationId, NOT to
        // destination.operation_idx — the RGB hub's index is a different id-space
        // and matching against it produced spurious mismatch refusals.
        crate::networks::evm::evm_event::verify_funds_in_event(
            &**client,
            // FundsIn is emitted by the bridge entry contract, which may differ
            // from the MultisigProxy pinned in BRIDGE_CONTRACT (see config.rs).
            &ctx.bridge_config.funds_in_contracts,
            ctx.evm_rpc_config.min_confirmations,
            &tx_hash,
            &source.funds_in_operation_id,
            req.amount,
            source.commission,
        )?;
    }

    // Fail-closed when the FundsIn verifier is not compiled in (audit M-06 /
    // #60, #51). An EVM -> RGB bridge request is authorised by an EVM deposit,
    // but #51 removed the listener-supplied `event_valid`/`event_finalized`
    // booleans that used to gate it and the independent replacement lives behind
    // the `evm-rpc` feature. A build without that feature therefore has NO
    // evidence the deposit occurred - the consignment/PSBT checks prove the
    // transfer shape but not that any EVM deposit backs it. Refuse rather than
    // sign on the missing authorisation. Mirrors the M-01/#61 no-`spv` fundsOut
    // refusal. dev-mode retains the legacy path for local testing. Compiled only
    // when `evm-rpc` is absent, so it and the verification block above are
    // mutually exclusive.
    #[cfg(all(not(feature = "evm-rpc"), not(feature = "dev-mode")))]
    if matches!(
        (source_ref, destination_ref),
        (
            SourceNetwork::EvmSource(_),
            DestinationNetwork::RgbDestination(_) | DestinationNetwork::RgbInflationDestination(_)
        )
    ) {
        return Err(EnclaveError::CrossCheck(
            "enclave was not built with --features evm-rpc: refusing to sign a bridge-mode PSBT \
             without independently verifying the FundsIn deposit (the listener-supplied \
             event_valid/event_finalized booleans are no longer trusted — audit M-06 / #60/#51). \
             Rebuild with `--features evm-rpc` (or `helios` for the trustless path)."
                .into(),
        ));
    }

    // Soft operation-uniqueness guard (audit W-02 / #84). In EVM -> RGB
    // bridge mode, reject a same-op resubmission inside the TTL window.
    // Defense-in-depth only: in-memory, per-instance, volatile across restart.
    //
    // RESERVE here (atomic test-and-reserve under one lock, so concurrent
    // same-op requests cannot both pass), PROMOTE only after the signature is
    // actually produced, RELEASE on failure so honest retries survive. See
    // NonceReplayGuard::reserve for the live incident this encodes.
    #[cfg(not(feature = "dev-mode"))]
    let mut reserved_replay_key: Option<[u8; 32]> = None;
    #[cfg(not(feature = "dev-mode"))]
    if let SourceNetwork::EvmSource(source) = source_ref {
        let rgb_op = match destination_ref {
            DestinationNetwork::RgbDestination(d) => Some((d.operation_idx, d.asset_id.as_str())),
            DestinationNetwork::RgbInflationDestination(d) => {
                Some((d.operation_idx, d.asset_id.as_str()))
            }
            DestinationNetwork::EvmDestination(_) => None,
        };
        if let Some((operation_idx, asset_id)) = rgb_op {
            let op_key = crate::networks::rgb::psbt_validation::psbt_operation_key(
                ctx.bridge_config.chain_id,
                &ctx.bridge_config.bridge_contracts_bytes(),
                &source.tx_hash,
                operation_idx,
                asset_id,
            );
            match ctx.state.op_replay_guard.reserve(op_key) {
                Ok(()) => reserved_replay_key = Some(op_key),
                Err(EnclaveError::NonceReplay) => {
                    tracing::warn!(
                        operation_idx,
                        evm_tx_hash = %hex::encode(&source.tx_hash),
                        "rejecting duplicate bridge PSBT operation (soft replay guard, #84)"
                    );
                    return Err(EnclaveError::CrossCheck(
                        "duplicate bridge operation: this (chain, contract, evm_tx_hash, \
                     operation_idx, rgb_asset_id) was already signed recently — refusing to \
                     sign a replay (soft in-memory guard; durable guard is on-chain)"
                            .into(),
                    ));
                }
                Err(e) => return Err(e),
            }
        }
    }

    let destination = req.destination_network.ok_or_else(|| {
        EnclaveError::InvalidRequest("sign request has no destination_network".into())
    })?;

    let result = match destination {
        DestinationNetwork::EvmDestination(destination) => {
            // RGB->EVM `fundsOut` binding: with the consignment the source
            // validation captured, bind the calldata the enclave is about to
            // sign to the operation `validate()` authenticated — witness
            // confirmation (4th I-03 / #95), BtcRelay agreement (#57 / #122),
            // the consignment-bound release amount. The current deployment
            // supports only the swap/send-receive flow, whose general bridge
            // `burnId` and `fundsInIds` must be preserved. Mint/burn OpId
            // rewriting stays disabled until the two flows are routed by
            // network id. On non-rgb-validation builds there is no consignment
            // to bind and fundsOut is refused upstream at source validation.
            #[cfg(feature = "rgb-validation")]
            let destination = {
                apply_funds_out_binding(
                    ctx,
                    &destination,
                    source_validated.rgb_consignment.as_ref(),
                )?;
                destination
            };
            handle_sign_evm(ctx, destination)
        }
        DestinationNetwork::RgbDestination(destination) => {
            handle_sign_psbt(ctx, &destination.psbt_bytes)
        }
        DestinationNetwork::RgbInflationDestination(destination) => {
            handle_sign_psbt(ctx, &destination.psbt_bytes)
        }
    };

    // Settle the reservation: a produced signature arms the guard durably; a
    // failed attempt releases the key so an honest retry is not refused. The
    // enclave always reaches this line, so a reservation cannot dangle.
    #[cfg(not(feature = "dev-mode"))]
    if let Some(op_key) = reserved_replay_key {
        let settle = if result.is_ok() {
            ctx.state.op_replay_guard.promote(op_key)
        } else {
            ctx.state.op_replay_guard.release(op_key)
        };
        if let Err(e) = settle {
            tracing::warn!("replay guard settle failed: {e}");
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
    destination: &EvmDestination,
    validated: Option<&crate::networks::rgb::validation::ValidatedConsignment>,
) -> Result<()> {
    use crate::networks::evm::crosscheck;
    use crate::networks::evm::validation::FUNDS_OUT_SELECTOR_POOLS;

    if cfg!(all(feature = "dev-mode", not(test))) {
        return Ok(());
    }

    // Only the `fundsOut` release flow is bound to a consignment; leave any
    // other calldata untouched.
    if destination.call_data.len() < 4 || destination.call_data[..4] != FUNDS_OUT_SELECTOR_POOLS {
        return Ok(());
    }

    // A `fundsOut` release requires the RGB source's validated consignment
    // (source == RgbSource, rgb_validator configured, consignment present).
    let validated = validated.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "fundsOut signing requires a validated RGB source consignment (the source must be an \
             RGB source with consignment bytes and a configured rgb_validator) — refusing to sign"
                .into(),
        )
    })?;

    // Defense-in-depth: every consignment witness tx must be mined (4th I-03 / #95).
    crosscheck::assert_witnesses_confirmed(validated)?;

    // BtcRelay agreement: bind the calldata's (blockHeight, commitmentHash)
    // `proof` to the header the enclave holds at that height (#57 / #122). Inert
    // until the listener populates `proof`. Requires the SPV header chain, which
    // is always present under rgb-validation (spv is implied — see lib.rs M-01
    // compile_error).
    #[cfg(feature = "spv")]
    {
        let chain = ctx
            .header_chain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crosscheck::verify_btc_relay_agreement(&destination.call_data, &chain)?;
    }
    #[cfg(not(feature = "spv"))]
    let _ = ctx;

    // Consignment-bound release amount (transfer flow).
    crosscheck::validate_funds_out_transfer(&destination.call_data, validated)?;

    // Current rollout is swap/send-receive only. Preserve the backend-provided
    // general bridge burnId and settlement fundsInIds; the EVM connector has
    // already selected the latter against the authoritative on-chain remaining
    // balance. Mint/burn needs a separate network-id-routed path before its RGB
    // OpId binding can be enabled here.

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

    let keys = state.get_keys()?;
    tracing::info!(
        evm_address = %hex::encode(keys.evm_address),
        evm_gas_tx_address = %hex::encode(keys.evm_gas_tx_address),
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
            bridge_contract: ctx.bridge_config.bridge_contracts_bytes(),
            rgb_asset_id: ctx.bridge_config.rgb_asset_id.clone(),
            evm_gas_tx_uncompressed_pub: keys.evm_gas_tx_uncompressed_pub.to_vec(),
            evm_gas_tx_address: keys.evm_gas_tx_address.to_vec(),
            // CCD governance keys are not derived on this branch; empty means
            // "not provisioned" to the reader, same as an unset bridge pin.
            ccd_ed25519_pub: Vec::new(),
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

/// Single place that assembles a `PublicKeysResponse` — keeps the field
/// order matching `canonical_pubkey_bundle` exactly. If you add a field
/// here, add it to the bundle too (and to the verifier mirror in
/// `parent/src/attest_verify.rs::canonical_bundle`).
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
        bridge_contract: cfg.bridge_contracts_bytes(),
        rgb_asset_id: cfg.rgb_asset_id.clone(),
        evm_gas_tx_uncompressed_pub: keys.evm_gas_tx_uncompressed_pub.to_vec(),
        evm_gas_tx_address: keys.evm_gas_tx_address.to_vec(),
        // Not derived on this branch - see the InitializeKey note.
        ccd_ed25519_pub: Vec::new(),
    }
}

/// Build the canonical bundle that the verifier hashes to check `user_data`.
///
/// Length-prefixed (u32 BE) concatenation of every field in
/// PublicKeysResponse, in proto field order. Strings are encoded as their
/// UTF-8 bytes; `chain_id` as 8-byte big-endian (its length prefix is the
/// constant 8). Order and field set MUST match the verifier — see
/// `docs/pubkey-attestation.md` and `parent/src/attest_verify.rs::canonical_bundle`.
fn canonical_pubkey_bundle(keys: &PublicKeysResponse) -> Vec<u8> {
    let chain_id_bytes = keys.chain_id.to_be_bytes();
    let parts: [&[u8]; 12] = [
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

    // NOTE (audit W-13): this endpoint attests over a *caller-supplied* nonce,
    // so it can act as an oracle that mints valid attestations for arbitrary
    // nonces. That is safe for replay accounting: the cloning handlers record a
    // nonce only after a fully-authenticated handshake (see `handle_get_clone` /
    // `handle_set_clone`), so an oracle-minted nonce carries no replay-guard
    // weight on its own and cannot be used to exhaust the guard.
    let keys = ctx.state.get_keys()?;
    let public_keys = build_public_keys_response(keys, &ctx.bridge_config);

    let bundle = canonical_pubkey_bundle(&public_keys);
    let commitment: [u8; 32] = Sha256::digest(&bundle).into();

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

fn handle_sign_evm(ctx: &ServerContext, req: EvmDestination) -> Result<EnclaveResponse> {
    // Domain name/version are pinned to the deployed MultisigProxy and
    // regression-guarded by `test_domain_separator_matches_deployed_contract`.
    let domain = build_evm_domain(&req)?;

    let domain_sep = domain.separator_hash();
    let digest = evm_digest(&domain, &req.call_data, req.nonce, req.deadline)?;

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
            // Non-fundsOut / non-rgb-validation paths sign the calldata as
            // received. The RGB->EVM fundsOut path rewrites the OpId-bound
            // fields before this point and returns the rewritten bytes here
            // (audit M-02 / #93, #63) — see `handle_sign`.
            call_data: req.call_data.clone(),
        })),
    })
}

fn handle_sign_psbt(ctx: &ServerContext, psbt_bytes: &[u8]) -> Result<EnclaveResponse> {
    let (signed_psbt, inputs_signed) = ctx.state.sign_psbt(psbt_bytes)?;

    // Reject a "successful" no-op (audit 3rd W-03 / #85). KeyManager::sign_psbt
    // returns Ok((bytes, 0)) when no PSBT input belongs to this enclave; a
    // caller that checks only RPC success would treat that as a valid signer
    // contribution and mis-account quorum. Fail closed in production signing
    // mode so a 0-signature response can never be mistaken for a contribution.
    // Partial signing (0 < count < num_inputs) is still allowed. The
    // KeyManager 0-return stays as a primitive; the policy lives here at the
    // handler boundary. dev-mode keeps the 0-count path for inspect/dry-run.
    #[cfg(not(feature = "dev-mode"))]
    if inputs_signed == 0 {
        return Err(EnclaveError::Signing(
            "sign_psbt signed 0 inputs: no PSBT input belongs to this enclave — refusing to \
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

/// Sign a plain-BTC PSBT (create_utxo / plain withdrawals). Distinct from
/// [`handle_sign_psbt`]: this path carries no RGB consignment and no EVM event.
/// The enclave authorizes it solely against the operator-pinned output
/// allowlist + amount cap ([`crate::networks::rgb::btc_crosscheck`]); a
/// production (rgb-validation) build refuses to sign when that policy is
/// unconfigured. Routing plain-BTC ops through their own request type is the
/// structural half of the M-01/#69 fix — the bridge `SignPsbt` (RgbDestination)
/// path can no longer be reached by omitting its fields.
fn handle_sign_btc(ctx: &ServerContext, req: SignBtcRequest) -> Result<EnclaveResponse> {
    // Pinned output allowlist + amount cap (skipped only in dev-mode).
    #[cfg(not(feature = "dev-mode"))]
    crate::networks::rgb::btc_crosscheck::validate_btc_request(&req, &ctx.bridge_config)?;

    // Sign restricted to the VANILLA (plain-BTC) account: the enclave will not
    // co-sign a Colored (RGB-allocated) input on this path, so it is
    // structurally impossible for plain-BTC signing to move federation/RGB
    // funds — those move only via the consignment-bound SignPsbt path. createUtxos
    // and sendBtc spend only vanilla-account UTXOs, so this never blocks a
    // legitimate plain-BTC op.
    let (signed_psbt, inputs_signed) = ctx
        .state
        .sign_psbt_scoped(&req.psbt_bytes, Some(crate::keys::AccountType::Vanilla))?;

    // Mirror the bridge path's W-03 guard: a 0-input signing is a no-op and
    // must not be returned as a successful signature in production.
    #[cfg(not(feature = "dev-mode"))]
    if inputs_signed == 0 {
        return Err(EnclaveError::Signing(
            "sign_btc signed 0 inputs: no PSBT input belongs to this enclave — refusing to \
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

fn handle_sign_raw_message(
    state: &EnclaveState,
    req: SignRawMessageRequest,
) -> Result<EnclaveResponse> {
    if req.message.is_empty() {
        return Err(EnclaveError::InvalidRequest("message is empty".into()));
    }

    // EIP-191 personal_sign envelope: keccak256("\x19Ethereum Signed Message:\n" || len || msg).
    // The 0x19 prefix byte is not a valid first byte for any Ethereum transaction
    // envelope (legacy RLP starts at 0xc0+, typed txs use 0x01..=0x7f), so a
    // signature produced here can never be replayed as a transaction signature
    // — which is the whole point of EIP-191 and why this RPC must use it.
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    hasher.update(req.message.len().to_string().as_bytes());
    hasher.update(&req.message);
    let hash: [u8; 32] = hasher.finalize().into();
    let signature = state.sign_evm(&hash)?;

    tracing::info!(
        sig_hex = %hex::encode(signature),
        msg_len = req.message.len(),
        "raw message signature produced (EIP-191)"
    );

    Ok(EnclaveResponse {
        response: Some(Response::RawSignature(RawSignatureResponse {
            signature: signature.to_vec(),
        })),
    })
}

fn handle_sign_raw_digest(
    ctx: &ServerContext,
    req: SignRawDigestRequest,
) -> Result<EnclaveResponse> {
    // Gas-tx shape allowlist (audit TEE-XC-09 / #68). Production builds refuse
    // to blind-sign an opaque digest: the request must carry the unsigned tx
    // preimage, which the enclave decodes, checks against the operator pins
    // (chain id + destination, zero value), and hashes itself — see
    // `networks::evm::gas_tx`. Skipped under dev-mode like the other
    // cross-checks (dev-mode is compile-guarded out of release), where the
    // legacy opaque-digest path is retained for local testing.
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
// Note: a poisoned mutex (lock returns Err) means a previous handler
// panicked while holding the lock. That should never happen because the
// only mutation is `submit_headers` which never panics, but if it does
// the safe thing is to clear the poison and continue rather than wedge
// the entire enclave — the chain is in a consistent state because all
// mutations are atomic.
fn handle_submit_headers(
    ctx: &ServerContext,
    req: SubmitHeadersRequest,
) -> Result<EnclaveResponse> {
    // Cumulative rate limit (#86): bound the aggregate submission rate across
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

// ============================================================================
// Cloning handshake
// ============================================================================
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
    //    digest on the wire — NSM-signed, so parent-proof.
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

    // 6. Replay-check + record the nonce from the verified document. This
    //    runs only *after* the pubkey, digest and donor-secret checks above
    //    have passed, so a rejected (unauthenticated) handshake never
    //    consumes replay-guard capacity. Combined with the count-cap removal
    //    (#80), this closes the secret-less cloning-availability DoS in which
    //    an attacker mints attestations over arbitrary nonces via
    //    `get_attested_public_key` and burns them on doomed handshakes
    //    (audit W-13).
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

    // 1. Verify donor attestation chain + PCRs (no nonce match — freshness
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
    //    Cloning -> Active transition — all atomically under the state
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
    //    rejected handshake never consumes replay-guard capacity (audit W-13).
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

#[cfg(test)]
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
