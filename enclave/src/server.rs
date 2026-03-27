use std::io::{Read, Write};

use crate::error::{EnclaveError, Result};
use crate::framing;
use crate::keys::EnclaveState;
use crate::proto::enclave_request::Request;
use crate::proto::enclave_response::Response;
use crate::proto::*;
use crate::signing::evm::{sign_request_digest, Eip712Domain};

/// Handle a single connection: read one request, dispatch, write one response, close.
pub fn handle_connection(stream: impl Read + Write, state: &EnclaveState) {
    if let Err(e) = process_connection(stream, state) {
        tracing::error!("connection error: {}", e);
    }
}

fn process_connection(mut stream: impl Read + Write, state: &EnclaveState) -> Result<()> {
    tracing::debug!("reading request");
    let request: EnclaveRequest = framing::read_message(&mut stream)?;

    let response = dispatch(request, state);

    framing::write_message(&mut stream, &response)?;
    tracing::debug!("response written");
    Ok(())
}

fn dispatch(request: EnclaveRequest, state: &EnclaveState) -> EnclaveResponse {
    let result = match request.request {
        Some(Request::InitializeKey(req)) => {
            let path = if req.seed.is_empty() {
                "entropy"
            } else {
                "seed-import"
            };
            tracing::info!("request: InitializeKey ({})", path);
            handle_initialize(state, req)
        }
        Some(Request::GetPublicKey(req)) => {
            tracing::info!("request: GetPublicKey");
            handle_get_public_key(state, req)
        }
        Some(Request::SignEvm(req)) => {
            tracing::info!("request: SignEvm");
            handle_sign_evm(state, req)
        }
        Some(Request::SignPsbt(req)) => {
            tracing::info!("request: SignPsbt");
            handle_sign_psbt(state, req)
        }
        Some(Request::SignRawMessage(req)) => {
            tracing::info!("request: SignRawMessage");
            handle_sign_raw_message(state, req)
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
                    code: 1,
                    message: e.to_string(),
                })),
            }
        }
    }
}

fn handle_initialize(state: &EnclaveState, req: InitializeKeyRequest) -> Result<EnclaveResponse> {
    if req.seed.is_empty() {
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
        btc_xpub = %keys.btc_xpub,
        "keys initialized"
    );
    Ok(EnclaveResponse {
        response: Some(Response::InitializeKey(InitializeKeyResponse {
            evm_address: keys.evm_address.to_vec(),
            btc_compressed_pub: keys.btc_compressed_pubkey.to_vec(),
            btc_xpub: keys.btc_xpub,
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
        })),
    })
}

fn handle_sign_evm(state: &EnclaveState, req: SignEvmRequest) -> Result<EnclaveResponse> {
    // TODO: load from config
    let domain = Eip712Domain {
        name: "Tricorn".to_string(),
        version: "1".to_string(),
        chain_id: 1,
        verifying_contract: [0u8; 20],
    };

    let digest = sign_request_digest(&domain, &req.call_data, req.nonce, req.deadline);
    let signature = state.sign_evm(&digest)?;

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
