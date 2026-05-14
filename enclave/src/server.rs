use std::io::{Read, Write};

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
            handle_initialize(&ctx.state, req)
        }
        Some(Request::GetPublicKey(req)) => {
            tracing::info!("request: GetPublicKey");
            handle_get_public_key(&ctx.state, req)
        }
        Some(Request::SignEvm(req)) => {
            tracing::info!("request: SignEvm");
            handle_sign_evm(ctx, req)
        }
        Some(Request::SignPsbt(req)) => {
            tracing::info!("request: SignPsbt");
            handle_sign_psbt(&ctx.state, req)
        }
        Some(Request::SignRawMessage(req)) => {
            tracing::info!("request: SignRawMessage");
            handle_sign_raw_message(&ctx.state, req)
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

fn handle_initialize(state: &EnclaveState, req: InitializeKeyRequest) -> Result<EnclaveResponse> {
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
        })),
    })
}

fn handle_get_public_key(
    state: &EnclaveState,
    _req: GetPublicKeyRequest,
) -> Result<EnclaveResponse> {
    let keys = state.get_keys()?;
    tracing::debug!(
        evm_address = %hex::encode(keys.evm_address),
        "returning public keys"
    );
    Ok(EnclaveResponse {
        response: Some(Response::PublicKeys(PublicKeysResponse {
            evm_address: keys.evm_address.to_vec(),
            btc_compressed_pub: keys.btc_compressed_pubkey.to_vec(),
            btc_xpub: keys.btc_xpub,
            master_fingerprint: keys.master_fingerprint.to_vec(),
            account_xpub_vanilla: keys.account_xpub_vanilla,
            account_xpub_colored: keys.account_xpub_colored,
            evm_uncompressed_pub: keys.evm_uncompressed_pub.to_vec(),
        })),
    })
}

fn handle_sign_evm(ctx: &ServerContext, req: SignEvmRequest) -> Result<EnclaveResponse> {
    // In-enclave RGB consignment validation (when feature enabled and bytes present).
    // This replaces trusting the Listener's consignment_valid boolean.
    #[cfg(feature = "rgb-validation")]
    if !req.consignment.is_empty() {
        if let Some(ref validator) = ctx.rgb_validator {
            let validated = validator.validate_consignment(&req.consignment)?;
            tracing::info!(
                contract_id = %validated.contract_id,
                "RGB consignment validated in-enclave"
            );
            // Cross-check contract_id against declared rgb_asset_id if present
            if !req.rgb_asset_id.is_empty() && validated.contract_id != req.rgb_asset_id {
                return Err(EnclaveError::CrossCheck(format!(
                    "contract_id mismatch: consignment has {} but request declares {}",
                    validated.contract_id, req.rgb_asset_id
                )));
            }
        } else {
            tracing::warn!("RGB validator not configured, skipping in-enclave validation");
        }
    }

    // Cross-check enriched fields before signing (skipped in dev-mode)
    #[cfg(not(feature = "dev-mode"))]
    validation::evm_crosscheck::validate_evm_request(&req)?;

    // TODO: confirm domain name/version with contract team
    let domain = build_evm_domain(&req)?;

    let digest = sign_request_digest(&domain, &req.call_data, req.nonce, req.deadline);
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

fn handle_sign_psbt(state: &EnclaveState, req: SignPsbtRequest) -> Result<EnclaveResponse> {
    // Cross-check enriched fields before signing (skipped in dev-mode)
    #[cfg(not(feature = "dev-mode"))]
    validation::psbt_crosscheck::validate_psbt_request(&req)?;

    let (signed_psbt, inputs_signed) = state.sign_psbt(&req.psbt_bytes)?;

    tracing::info!(inputs_signed, "PSBT signed");

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

    // Hash the raw message with keccak256 to produce a 32-byte digest
    use sha3::{Digest, Keccak256};
    let hash: [u8; 32] = Keccak256::digest(&req.message).into();
    let signature = state.sign_evm(&hash)?;

    tracing::info!(
        sig_hex = %hex::encode(signature),
        msg_len = req.message.len(),
        "raw message signature produced"
    );

    Ok(EnclaveResponse {
        response: Some(Response::RawSignature(RawSignatureResponse {
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
        name: "Tricorn".to_string(),
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
