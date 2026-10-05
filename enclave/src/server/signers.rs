//! The leaf signers, with one function for each signature type.
//! Each one assumes that authorization is complete: in [`super::sign`] for a
//! bridge route, or in its own cross-check module for the direct paths.

use super::context::ServerContext;
use crate::error::{EnclaveError, Result};
#[cfg(rgb_to_evm)]
use crate::networks::evm::signing::{build_evm_domain, funds_out_digest, lz_funds_out_digest};
#[cfg(rgb_to_evm)]
use crate::networks::evm::validation::LZ_FUNDS_OUT_SELECTOR;
use crate::proto::enclave_response::Response;
use crate::proto::*;
#[cfg(feature = "ccd")]
use crate::state::EnclaveState;

/// Check that all pinned Bitcoin blocks still have the same hash.
/// Call it immediately before the signing key is used.
///
/// Each SPV check releases the lock at return. Another worker can accept a
/// reorg in that gap (F05-NEW-AF-08). An extension does not change the pinned
/// heights, so signing continues. A reorg that replaces a pin is refused here.
#[cfg(feature = "rgb-validation")]
fn assert_chain_pins_unchanged(
    ctx: &ServerContext,
    pins: &crate::networks::rgb::spv_crosscheck::ChainPins,
) -> Result<()> {
    if pins.is_empty() {
        return Ok(());
    }
    // Fail on a poisoned lock, as the validation checks do.
    // A poisoned header chain can be in the middle of a reorg.
    let chain = ctx
        .header_chain
        .lock()
        .map_err(|e| EnclaveError::Internal(format!("SPV header chain lock poisoned: {e}")))?;
    pins.assert_unchanged(&chain)
}

/// `params` comes from destination validation, so the digest commits to the
/// fields checked there. It is `None` on the LayerZero route, which has a
/// different shape. `lz_funds_out_digest` decodes its own params.
#[cfg(rgb_to_evm)]
pub(super) fn handle_sign_evm(
    ctx: &ServerContext,
    req: EvmDestination,
    params: Option<&crate::networks::evm::validation::FundsOutParams>,
    #[cfg(feature = "rgb-validation")] pins: &crate::networks::rgb::spv_crosscheck::ChainPins,
) -> Result<EnclaveResponse> {
    // Domain name and version are pinned to the deployed MultisigProxy.
    // See `test_domain_separator_matches_deployed_contract`.
    let domain = build_evm_domain(&req)?;

    let domain_sep = domain.separator_hash();

    // Route by selector and lz_release. The digest commits to the LZ fields
    // of `lzFundsOutCall`. The proto field is the authority. The calldata
    // selector is only a consistency check (see lz_funds_out_digest).
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
        // Validation gives `params` for all non-LayerZero selectors. `None` here
        // is an LZ selector without `lz_release`. Refuse, and do not decode again.
        let params = params.ok_or_else(|| {
            EnclaveError::CrossCheck(
                "fundsOut digest requires validated calldata params (LayerZero selector without \
                 lz_release?)"
                    .into(),
            )
        })?;
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

    // Last gate before the key, for both routes. The checked chain must still
    // be the chain that the enclave holds.
    #[cfg(feature = "rgb-validation")]
    assert_chain_pins_unchanged(ctx, pins)?;

    let signature = ctx.state.sign_evm(&digest)?;

    tracing::info!(
        sig_hex = %hex::encode(signature),
        "EVM signature produced"
    );

    Ok(EnclaveResponse {
        response: Some(Response::EvmSignature(EvmSignatureResponse {
            signature: signature.to_vec(),
            call_data: req.call_data.clone(),
        })),
    })
}

#[cfg(evm_to_rgb)]
pub(super) fn handle_sign_psbt(
    ctx: &ServerContext,
    req: RgbDestination,
    #[cfg(feature = "rgb-validation")] pins: &crate::networks::rgb::spv_crosscheck::ChainPins,
) -> Result<EnclaveResponse> {
    // Sats gate. All other send-RGB binds use RGB asset units. Without this
    // gate, a witness tx can satisfy the ledger and still take the BTC backing.
    let psbt = crate::networks::rgb::psbt_validation::parse_psbt_shape(&req.psbt_bytes)?;
    ctx.state.with_keys(|keys| {
        crate::networks::rgb::btc_crosscheck::validate_rgb_psbt_sats(
            &psbt,
            &ctx.bridge_config,
            keys,
        )
    })?;

    // Same gate as the EVM route. RGB source SPV evidence must still hold on
    // the current chain. No-op when nothing is pinned (an EVM source).
    #[cfg(feature = "rgb-validation")]
    assert_chain_pins_unchanged(ctx, pins)?;

    // Colored account only. An unscoped sign co-signs all inputs with a known
    // key, including vanilla inputs that no send-RGB bind checks.
    let (signed_psbt, inputs_signed) = ctx
        .state
        .sign_psbt_scoped(&req.psbt_bytes, Some(crate::keys::AccountType::Colored))?;

    // Refuse a no-op. `sign_psbt_scoped` returns Ok((bytes, 0)) when no input is ours.
    // A caller that checks only RPC success would count it as a signature.
    // Partial signing (0 < count < num_inputs) is allowed.
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

/// Sign a plain-BTC PSBT (create_utxo, UTXO management).
/// Unlike [`handle_sign_psbt`], it has no RGB consignment and no EVM event.
/// Authorization: outputs pay to enclave scripts or fit the unowned budget,
/// the pinned fee policy passes, and the operator amount cap holds
/// ([`crate::networks::rgb::btc_crosscheck`]).
/// A production build refuses to sign when the cap is not set.
/// The separate request type is the structural part of the vanilla-bypass fix.
#[cfg(evm_to_rgb)]
pub(super) fn handle_sign_btc(ctx: &ServerContext, req: SignBtcRequest) -> Result<EnclaveResponse> {
    // In production, the plain-BTC path runs only if the attested policy
    // enables it. `validate_btc_request` has the same rule, but this check
    // reads the policy that attestation `user_data` commits to.
    if let crate::policy::SecurityPolicy::Production(p) = &ctx.launch()?.policy {
        if !p.allow_vanilla_psbt {
            return Err(EnclaveError::Signing(
                "plain-BTC (vanilla) signing is disabled by the enclave's production security \
                 policy (BTC_MAX_TOTAL_SATS unset) - refusing to sign"
                    .into(),
            ));
        }
    }

    // Output self-ownership, fee policy and amount cap. These use the enclave
    // keys, so an uninitialized enclave fails here with KeyNotInitialized.
    ctx.state.with_keys(|keys| {
        crate::networks::rgb::btc_crosscheck::validate_btc_request(&req, &ctx.bridge_config, keys)
    })?;

    // Vanilla account only, so plain-BTC signing cannot move RGB funds.
    // createUtxos and sendBtc spend only vanilla UTXOs.
    let (signed_psbt, inputs_signed) = ctx
        .state
        .sign_psbt_scoped(&req.psbt_bytes, Some(crate::keys::AccountType::Vanilla))?;

    // Same guard as the bridge path: refuse a 0-input no-op.
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

#[cfg(rgb_to_evm)]
pub(super) fn handle_sign_raw_digest(
    ctx: &ServerContext,
    req: SignRawDigestRequest,
) -> Result<EnclaveResponse> {
    // Gas-tx shape allowlist. Production does not blind-sign a digest.
    // The request must carry the unsigned tx preimage. The enclave decodes it,
    // checks it against the operator pins, and hashes it
    // (see `networks::evm::gas_tx`).
    let digest = crate::networks::evm::gas_tx::validate_gas_tx_request(&req, &ctx.bridge_config)?;

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
/// Ed25519 key. The listener derives the hash and checks the transaction
/// structure and amounts. The enclave signs the hash directly.
/// Returns the 64-byte signature and the public key.
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
            // Ed25519 signatures are not recoverable. The consumer needs the key
            // to find the signer index on the governance account.
            public_key: public_key.to_vec(),
        })),
    })
}
