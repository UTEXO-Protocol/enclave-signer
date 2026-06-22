use std::io::{Read, Write};

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::framing;
use crate::proto::enclave_request::Request;
use crate::proto::enclave_response::Response;
use crate::proto::*;
use crate::signing::evm::{sign_request_digest, Eip712Domain};
use crate::state::EnclaveState;
#[cfg(not(feature = "dev-mode"))]
use crate::validation;

/// Shared context passed to every request handler.
pub struct ServerContext {
    pub state: EnclaveState,
    /// Bridge config pinned at boot from env. Folded into the attestation
    /// `user_data` commitment and used to cross-check `SignEvm` requests
    /// against operator-pinned values.
    pub bridge_config: BridgeConfig,
    #[cfg(feature = "rgb-validation")]
    pub rgb_validator: Option<crate::validation::rgb::RgbValidator>,
    /// In-enclave Bitcoin header chain for SPV verification. Populated at
    /// boot from the compile-time checkpoint; mutated by SubmitHeaders.
    /// `Mutex` because the enclave handles connections from a single
    /// thread today, but we want the type to stay correct if that ever
    /// changes — and `Mutex` over `RefCell` so a future move to
    /// multi-threaded handling needs no plumbing changes.
    pub header_chain: std::sync::Mutex<crate::spv::HeaderChain>,
}

impl ServerContext {
    /// Construct a `ServerContext` from the always-present fields, hiding
    /// feature-gated fields like `rgb_validator` so external callers
    /// (e.g. the parent's E2E tests) don't need to mirror our cfg flags.
    pub fn new(
        state: EnclaveState,
        bridge_config: BridgeConfig,
        header_chain: std::sync::Mutex<crate::spv::HeaderChain>,
    ) -> Self {
        Self {
            state,
            bridge_config,
            #[cfg(feature = "rgb-validation")]
            rgb_validator: None,
            header_chain,
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
        Some(Request::SignEvm(req)) => {
            tracing::info!("request: SignEvm");
            handle_sign_evm(ctx, req)
        }
        Some(Request::SignPsbt(req)) => {
            tracing::info!("request: SignPsbt");
            handle_sign_psbt(ctx, req)
        }
        Some(Request::SignRawMessage(req)) => {
            tracing::info!("request: SignRawMessage");
            handle_sign_raw_message(&ctx.state, req)
        }
        Some(Request::SignRawDigest(req)) => {
            tracing::info!("request: SignRawDigest");
            handle_sign_raw_digest(&ctx.state, req)
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
            bridge_contract: ctx.bridge_config.bridge_contract.to_vec(),
            rgb_asset_id: ctx.bridge_config.rgb_asset_id.clone(),
            evm_gas_tx_uncompressed_pub: keys.evm_gas_tx_uncompressed_pub.to_vec(),
            evm_gas_tx_address: keys.evm_gas_tx_address.to_vec(),
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
        bridge_contract: cfg.bridge_contract.to_vec(),
        rgb_asset_id: cfg.rgb_asset_id.clone(),
        evm_gas_tx_uncompressed_pub: keys.evm_gas_tx_uncompressed_pub.to_vec(),
        evm_gas_tx_address: keys.evm_gas_tx_address.to_vec(),
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

fn handle_sign_evm(ctx: &ServerContext, req: SignEvmRequest) -> Result<EnclaveResponse> {
    // Fail-closed against build mismatch: if the listener built with SPV on
    // and we built without it, the request will carry `merkle_proofs[]`
    // that we cannot verify. Refuse loudly rather than sign as if SPV
    // hadn't been requested.
    #[cfg(not(feature = "spv"))]
    if !req.merkle_proofs.is_empty() {
        return Err(EnclaveError::Spv(
            "enclave was not built with --features spv but request carries \
             merkle_proofs; refusing to sign without verification (rebuild \
             with `--features spv,rgb-validation` to enable SPV)"
                .into(),
        ));
    }

    // In-enclave RGB consignment validation (when feature enabled and bytes present).
    // This replaces trusting the Listener's consignment_valid boolean.
    // The result is held across the rest of the function so the SPV block
    // (below, gated by feature `spv`) can use witness_txids + chain_net.
    #[cfg(feature = "rgb-validation")]
    let validated_consignment = if !req.consignment.is_empty() {
        if let Some(ref validator) = ctx.rgb_validator {
            let v = validator.validate_consignment(&req.consignment)?;
            tracing::info!(
                contract_id = %v.contract_id,
                chain_net = %v.chain_net,
                witness_txids_count = v.witness_txids.len(),
                "RGB consignment validated in-enclave"
            );
            // Asset-identity binding (audit TEE-SE-01). Bind the validated
            // consignment's authoritative `contract_id` to the pinned
            // RGB_ASSET_ID and fail closed when either is absent — closes
            // the bypass where an empty `req.rgb_asset_id` skipped the
            // identity check entirely. Skipped under dev-mode like the
            // other cross-checks (#64 compile-guards dev-mode out of
            // release); the qualified path avoids depending on the
            // dev-mode-gated `validation` import alias.
            #[cfg(not(feature = "dev-mode"))]
            crate::validation::evm_crosscheck::bind_asset_identity(
                &v.contract_id,
                &req.rgb_asset_id,
                &ctx.bridge_config.rgb_asset_id,
            )?;
            Some(v)
        } else {
            tracing::warn!("RGB validator not configured, skipping in-enclave validation");
            None
        }
    } else {
        None
    };

    // Cross-check enriched fields before signing (skipped in dev-mode)
    #[cfg(not(feature = "dev-mode"))]
    validation::evm_crosscheck::validate_evm_request(&req, &ctx.bridge_config)?;

    // Consignment-bound amount cross-check for the `fundsOut` transfer
    // flow. Every fundsOut signature must be backed by a validated
    // consignment and an amount the consignment's last transition
    // actually accounts for. This is the second half of the bypass
    // closure started in `validate_evm_request`: that function rejects
    // empty bytes; this block rejects "bytes present but validator
    // didn't run" and binds the EVM-side amount to the RGB-side amount.
    //
    // The contract exposes a single `fundsOut` selector shared by the
    // pools/transfer flow (live) and the future mint/burn unlock flow,
    // disambiguated by contract address. Only the transfer check is
    // wired today — a burn consignment on this selector is rejected by
    // `validate_funds_out_transfer` ("requires a Transfer transition").
    // `validate_funds_out_burn` is wired in the mint/burn epic (by the
    // dedicated mint/burn contract address).
    #[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
    if req.call_data.len() >= 4
        && req.call_data[..4] == validation::evm_crosscheck::FUNDS_OUT_SELECTOR_POOLS
    {
        let validated = validated_consignment.as_ref().ok_or_else(|| {
            EnclaveError::CrossCheck(
                "fundsOut signing requires a validated consignment (rgb_validator must be \
                 configured and consignment bytes must be present)"
                    .into(),
            )
        })?;
        validation::evm_crosscheck::validate_funds_out_transfer(&req, validated)?;
    }

    // OpId binding (audit TEE-SE-02, spec §6/§7). The enclave derives the
    // cross-domain identifiers from the consignment it validated itself — it
    // does NOT trust any listener-supplied OpId — and binds the calldata it is
    // about to sign to them:
    //   - `burnId` (offset 68) == keccak256(last transition's OpId); and
    //   - every `fundsInIds[]` entry (in `settlementData`) corresponds to a
    //     TS_INFLATION (mint) OpId in the consignment's history.
    // Because the MultisigProxy signature commits to keccak256(callData),
    // these embedded values are cryptographically bound by the signature, so a
    // compromised backend cannot route the release to a different replay slot
    // or consume locks this consignment did not authorise.
    //
    // NOTE: this requires the backend (`bridge-utexo`) to derive on-chain
    // `burnId`/`fundsInIds` as keccak256(RGB OpId) too — see PR description.
    #[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
    if req.call_data.len() >= 4
        && req.call_data[..4] == validation::evm_crosscheck::FUNDS_OUT_SELECTOR_POOLS
    {
        if let Some(ref validated) = validated_consignment {
            validation::evm_crosscheck::bind_burn_id(&req, validated)?;
            validation::evm_crosscheck::bind_funds_in_ids(&req, validated)?;
        }
    }

    // SPV verification: every consignment-anchor Bitcoin tx must be in our
    // validated header chain at sufficient depth. With `spv = ["rgb-validation"]`
    // in Cargo.toml, having the spv feature implies the rgb-validation
    // block above ran, so `validated_consignment` is in scope and meaningful.
    #[cfg(feature = "spv")]
    {
        let validated = validated_consignment.as_ref().ok_or_else(|| {
            EnclaveError::Spv(
                "spv: signEVM requires a non-empty validated consignment, \
                 but the request had no consignment bytes (or the validator \
                 is not configured)"
                    .into(),
            )
        })?;
        let chain = ctx
            .header_chain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Staleness: tip header time must be within bounds of wall clock.
        // Catches the "frozen time" attack where the listener feeds
        // real-but-old headers, never reaching the actual chain head.
        validation::spv_crosscheck::assert_chain_not_stale(
            &chain,
            std::time::SystemTime::now(),
            std::time::Duration::from_secs(validation::spv_crosscheck::SPV_MAX_TIP_AGE_SECS),
            std::time::Duration::from_secs(validation::spv_crosscheck::SPV_MAX_TIP_FUTURE_SECS),
        )?;
        // Cross-network replay: regtest consignment to mainnet enclave etc.
        validation::spv_crosscheck::assert_chain_net(&validated.chain_net, chain.network())?;
        // Inclusion + confirmation depth for every witness tx.
        validation::spv_crosscheck::validate_spv_proofs(
            &chain,
            &validated.witness_txids,
            &req.merkle_proofs,
            validation::spv_crosscheck::SPV_MIN_CONFIRMATIONS,
        )?;
        tracing::info!(
            proofs_count = req.merkle_proofs.len(),
            "SPV verification passed"
        );
    }

    // TODO: confirm domain name/version with contract team
    let domain = build_evm_domain(&req)?;

    let domain_sep = domain.separator_hash();
    let digest = sign_request_digest(&domain, &req.call_data, req.nonce, req.deadline);

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
        })),
    })
}

fn handle_sign_psbt(ctx: &ServerContext, req: SignPsbtRequest) -> Result<EnclaveResponse> {
    // Cross-check enriched fields before signing (skipped in dev-mode)
    #[cfg(not(feature = "dev-mode"))]
    validation::psbt_crosscheck::validate_psbt_request(&req)?;

    // Send-RGB (EVM-lock → RGB-send) consignment binding. In bridge mode the
    // PSBT being signed IS the RGB transfer's witness transaction; bind it to
    // the validated consignment so a signed PSBT can't move bridge BTC without
    // finalizing the claimed RGB transition. Vanilla mode (empty evm_tx_hash,
    // e.g. create_utxo) carries no consignment and skips this entirely.
    #[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
    if !req.evm_tx_hash.is_empty() {
        psbt_consignment_crosscheck(ctx, &req)?;
    }

    let (signed_psbt, inputs_signed) = ctx.state.sign_psbt(&req.psbt_bytes)?;

    tracing::info!(inputs_signed, "PSBT signed");

    Ok(EnclaveResponse {
        response: Some(Response::SignedPsbt(SignedPsbtResponse {
            signed_psbt,
            inputs_signed: inputs_signed as u32,
        })),
    })
}

/// Bind a send-RGB (EVM-lock → RGB-send) PSBT to the RGB consignment it
/// claims to finalize. Mirrors the consignment-validation block of
/// [`handle_sign_evm`]: full rgbstd validation → keccak integrity →
/// asset-identity pin → then the PSBT-specific anchor check
/// ([`validation::psbt_crosscheck::validate_psbt_anchors_transition`]).
///
/// Fail-closed posture for an **absent** consignment is compile-time gated by
/// the `rgb-validation` feature (so the posture is PCR-attested and
/// cannot be weakened at runtime): on → hard reject; off → warn and fall back
/// to the legacy shape-only checks while the listener is updated to send it.
#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
fn psbt_consignment_crosscheck(ctx: &ServerContext, req: &SignPsbtRequest) -> Result<()> {
    use sha3::{Digest, Keccak256};

    if req.consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "send-RGB PSBT signing requires a consignment to bind the PSBT to the RGB \
                 transition (rgb-validation is enabled)"
                .into(),
        ));
    }

    let Some(ref validator) = ctx.rgb_validator else {
        return Err(EnclaveError::CrossCheck(
            "send-RGB PSBT carries a consignment but the RGB validator is not configured — \
             refusing to sign on unvalidated bytes"
                .into(),
        ));
    };

    // Wire-tamper detection, mirroring the EVM path's defence-in-depth check.
    if req.consignment_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "consignment present but consignment_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(&req.consignment);
    if computed[..] != req.consignment_hash[..] {
        return Err(EnclaveError::CrossCheck(
            "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
        ));
    }

    // Full rgbstd validation (Esplora resolver + DBC commitment check). The
    // txid-identity bind below is only meaningful because this ran.
    let validated = validator.validate_consignment(&req.consignment)?;
    tracing::info!(
        contract_id = %validated.contract_id,
        chain_net = %validated.chain_net,
        "send-RGB PSBT consignment validated in-enclave"
    );

    // Asset-identity binding to the pinned RGB_ASSET_ID (audit TEE-SE-01),
    // same as the EVM path.
    crate::validation::evm_crosscheck::bind_asset_identity(
        &validated.contract_id,
        &req.rgb_asset_id,
        &ctx.bridge_config.rgb_asset_id,
    )?;

    let psbt = bitcoin::psbt::Psbt::deserialize(&req.psbt_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("psbt_bytes is not a valid PSBT: {e}")))?;
    match validated.last_transition {
        Some(ref last) if last.transition_type == crate::validation::rgb::ifa::TS_TRANSFER => {
            crate::validation::psbt_crosscheck::validate_psbt_anchors_transition(
                &psbt,
                &validated,
                req.evm_amount,
                req.evm_commission,
            )?;
        }
        // A consignment whose last transition isn't a Transfer cannot
        // authorise a pools-mode send. Reject rather than sign an unanchored
        // PSBT.
        _ => {
            return Err(EnclaveError::CrossCheck(
                "send-RGB PSBT consignment's last transition is not a Transfer — refusing to \
                 sign a PSBT that doesn't finalize a pools-mode send"
                    .into(),
            ));
        }
    }

    Ok(())
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
    state: &EnclaveState,
    req: SignRawDigestRequest,
) -> Result<EnclaveResponse> {
    if req.digest.len() != 32 {
        return Err(EnclaveError::InvalidRequest(format!(
            "digest must be exactly 32 bytes, got {}",
            req.digest.len()
        )));
    }

    let digest: [u8; 32] = req.digest.as_slice().try_into().unwrap();
    let signature = state.sign_evm_gas_tx(&digest)?;

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

/// Build EIP-712 domain from enriched request fields.
/// In dev-mode, falls back to defaults if fields are missing.
fn build_evm_domain(req: &SignEvmRequest) -> Result<Eip712Domain> {
    let chain_id = if req.chain_id > 0 {
        req.chain_id
    } else {
        #[cfg(feature = "dev-mode")]
        {
            1
        }
        #[cfg(not(feature = "dev-mode"))]
        {
            return Err(EnclaveError::CrossCheck("chain_id must be > 0".into()));
        }
    };

    let verifying_contract: [u8; 20] = if req.proxy_contract.len() == 20 {
        req.proxy_contract
            .as_slice()
            .try_into()
            .map_err(|_| EnclaveError::CrossCheck("proxy_contract must be 20 bytes".into()))?
    } else {
        #[cfg(feature = "dev-mode")]
        {
            [0u8; 20]
        }
        #[cfg(not(feature = "dev-mode"))]
        {
            return Err(EnclaveError::CrossCheck(format!(
                "proxy_contract must be 20 bytes, got {}",
                req.proxy_contract.len()
            )));
        }
    };

    Ok(Eip712Domain {
        name: "MultisigProxy".to_string(),
        version: "1".to_string(),
        chain_id,
        verifying_contract,
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
    //    so freshness is enforced by the replay guard immediately after.
    let expected_pcrs = attestation::get_own_pcrs()?;
    let verified =
        attestation::verify_peer_attestation(&req.requester_attestation, &expected_pcrs, None)?;

    // 3. Replay-check the nonce pulled from the verified document.
    let nonce_array: [u8; 32] = verified
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Attestation("attestation nonce has wrong length".into()))?;
    state.replay_guard.check_and_record(nonce_array)?;

    // 4. Pubkey binding: the attestation's `public_key` field must equal
    //    the one the parent put on the wire. Otherwise the parent could
    //    have swapped it for a key it controls.
    if verified.enclave_pubkey.as_slice() != req_encryption_pk {
        return Err(EnclaveError::PubkeyMismatch);
    }

    // 5. Digest binding: the attestation's `user_data` must equal the
    //    digest on the wire — NSM-signed, so parent-proof.
    let user_data = verified.user_data.as_deref().ok_or_else(|| {
        EnclaveError::Attestation("requester attestation missing user_data (cloning digest)".into())
    })?;
    if user_data != req_digest {
        return Err(EnclaveError::DigestMismatch);
    }

    // 6. Digest authenticity: HMAC(donor_secret, encryption_pubkey) must
    //    match. Proves the requester was issued by the same operator.
    state.with_donor_cloning_secret(|secret| {
        if !cloning::verify_cloning_digest(secret, &req_encryption_pk, &req_digest) {
            return Err(EnclaveError::DigestMismatch);
        }
        Ok(())
    })?;

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

    // 1. Verify donor attestation chain + PCRs (no nonce match — we
    //    enforce freshness via the replay guard).
    let expected_pcrs = attestation::get_own_pcrs()?;
    let verified =
        attestation::verify_peer_attestation(&req.donor_attestation, &expected_pcrs, None)?;

    let nonce_array: [u8; 32] = verified
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Attestation("attestation nonce has wrong length".into()))?;
    state.replay_guard.check_and_record(nonce_array)?;

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

    tracing::info!(
        cluster_pk = %hex::encode(cluster_public_key),
        "SetClone: cloned, transitioned to Active"
    );

    Ok(EnclaveResponse {
        response: Some(Response::SetClone(SetCloneResponse {})),
    })
}
