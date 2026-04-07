use std::io::{Read, Write};

use crate::error::{EnclaveError, Result};
use crate::framing;
use crate::keys::EnclaveState;
use crate::proto::enclave_request::Request;
use crate::proto::enclave_response::Response;
use crate::proto::*;
use crate::signing::evm::{sign_request_digest, Eip712Domain};
#[cfg(not(feature = "dev-mode"))]
use crate::validation;

/// Shared context passed to every request handler.
pub struct ServerContext {
    pub state: EnclaveState,
    #[cfg(feature = "rgb-validation")]
    pub rgb_validator: Option<crate::validation::rgb::RgbValidator>,
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
