//! The leaf signers: one function per thing the enclave will put a signature
//! on. Each one assumes authorization already happened - in [`super::sign`]
//! for a bridge route, or in its own cross-check module for the direct paths.

use super::context::ServerContext;
use crate::error::{EnclaveError, Result};
use crate::networks::evm::signing::{build_evm_domain, funds_out_digest, lz_funds_out_digest};
use crate::networks::evm::validation::LZ_FUNDS_OUT_SELECTOR;
use crate::proto::enclave_response::Response;
use crate::proto::*;
#[cfg(feature = "ccd")]
use crate::state::EnclaveState;

/// Check that every pinned Bitcoin block still has the same hash. Takes a
/// fresh header-chain lock. Call it just before the signing key is used.
///
/// Each SPV check drops the lock at return. Another worker can accept a reorg
/// in that gap (F05-NEW-AF-08). An extension leaves the pinned heights alone
/// and still signs. A reorg that replaces one refuses here.
#[cfg(feature = "spv")]
fn assert_chain_pins_unchanged(
    ctx: &ServerContext,
    pins: &crate::networks::rgb::spv_crosscheck::ChainPins,
) -> Result<()> {
    if pins.is_empty() {
        return Ok(());
    }
    // Fail on a poisoned lock, like the validation checks do. A poisoned
    // header chain can be mid-reorg.
    let chain = ctx
        .header_chain
        .lock()
        .map_err(|e| EnclaveError::Internal(format!("SPV header chain lock poisoned: {e}")))?;
    pins.assert_unchanged(&chain)
}

/// `params` comes from destination validation, so the digest commits to exactly
/// the fields cross-checked there. `None` in dev-mode, which skips
/// validation and therefore decodes here, and on the LayerZero route, whose
/// param shape is not `FundsOutParams` - `lz_funds_out_digest` decodes its own.
pub(super) fn handle_sign_evm(
    ctx: &ServerContext,
    req: EvmDestination,
    params: Option<&crate::networks::evm::validation::FundsOutParams>,
    #[cfg(feature = "spv")] pins: &crate::networks::rgb::spv_crosscheck::ChainPins,
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

    // Last gate before the key. The chain the checks read must still be the
    // chain the enclave holds. Both routes use it. The LayerZero digest skips
    // the `fundsOut` binding, so the source check is its only SPV evidence.
    #[cfg(feature = "spv")]
    assert_chain_pins_unchanged(ctx, pins)?;

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

pub(super) fn handle_sign_psbt(
    ctx: &ServerContext,
    req: RgbDestination,
    #[cfg(feature = "spv")] pins: &crate::networks::rgb::spv_crosscheck::ChainPins,
) -> Result<EnclaveResponse> {
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

    // Same gate as the EVM route. An RGB source's SPV evidence must still hold
    // on the chain the enclave holds now. No-op when nothing is pinned. An EVM
    // source carries no Bitcoin proof.
    #[cfg(feature = "spv")]
    assert_chain_pins_unchanged(ctx, pins)?;

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
pub(super) fn handle_sign_btc(ctx: &ServerContext, req: SignBtcRequest) -> Result<EnclaveResponse> {
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

pub(super) fn handle_sign_raw_digest(
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
pub(super) fn handle_sign_ccd(
    state: &EnclaveState,
    req: SignCcdRequest,
) -> Result<EnclaveResponse> {
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
