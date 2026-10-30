//! The leaf signers, with one function for each signature type.
//! Each one assumes that authorization is complete: in [`super::sign`] for a
//! bridge route, or in its own cross-check module for the direct paths.

use super::context::ServerContext;
use crate::error::{EnclaveError, Result};
#[cfg(rgb_to_evm)]
use crate::networks::evm::signing::{build_evm_domain, funds_out_digest, lz_funds_out_digest};
use crate::proto::enclave_response::Response;
use crate::proto::*;
#[cfg(feature = "ccd")]
use crate::state::EnclaveState;

/// Check that all pinned Bitcoin blocks still have the same hash, then run
/// `sign` with the header-chain lock still held.
///
/// Each SPV check releases the lock at return. Another worker can accept a
/// reorg in that gap (F05-NEW-AF-08). An extension does not change the pinned
/// heights, so signing continues. A reorg that replaces a pin is refused here.
/// The lock is held until `sign` returns, so no header update can land between
/// the check and the key use. Lock order: header chain, then key state.
#[cfg(feature = "rgb-validation")]
fn sign_with_chain_pins_unchanged<T>(
    ctx: &ServerContext,
    pins: &crate::networks::rgb::spv_crosscheck::ChainPins,
    sign: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if pins.is_empty() {
        return sign();
    }
    // Fail on a poisoned lock, as the validation checks do.
    // A poisoned header chain can be in the middle of a reorg.
    let chain = ctx
        .header_chain
        .lock()
        .map_err(|e| EnclaveError::Internal(format!("SPV header chain lock poisoned: {e}")))?;
    pins.assert_unchanged(&chain)?;
    let signed = sign();
    drop(chain);
    signed
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

    // Validation picks the route (F05-NEW-AF-12): `params` is `Some` on the
    // direct route, and `None` on the LayerZero route, which has `lz_release`.
    // The digest commits to the LZ fields of `lzFundsOutCall`.
    let digest = match (params, req.lz_release.as_ref()) {
        (Some(params), None) => funds_out_digest(&domain, params, req.nonce, req.deadline)?,
        (None, Some(lz_release)) => {
            lz_funds_out_digest(&domain, &req.call_data, lz_release, req.nonce, req.deadline)?
        }
        // Validation refuses these forms. Fail closed if it did not run.
        _ => {
            return Err(EnclaveError::CrossCheck(
                "EVM route mismatch: lz_release does not match the calldata selector".into(),
            ))
        }
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
    let signature = sign_with_chain_pins_unchanged(ctx, pins, || ctx.state.sign_evm(&digest))?;
    #[cfg(not(feature = "rgb-validation"))]
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

/// M8: a mint pays no sat out, so it needs no unowned-sats budget.
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
fn check_sats_gate(
    psbt: &bitcoin::psbt::Psbt,
    _cfg: &crate::config::BridgeConfig,
    keys: &crate::keys::KeyManager,
) -> Result<()> {
    crate::networks::rgb::psbt_validation::assert_keeps_all_sats(psbt, keys, "mint")
}

/// Bounds the sats that leave to outputs the enclave cannot prove it owns.
#[cfg(all(not(feature = "bfa-mint"), evm_to_rgb))]
fn check_sats_gate(
    psbt: &bitcoin::psbt::Psbt,
    cfg: &crate::config::BridgeConfig,
    keys: &crate::keys::KeyManager,
) -> Result<()> {
    crate::networks::rgb::btc_crosscheck::validate_rgb_psbt_sats(psbt, cfg, keys)
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
    ctx.state
        .with_keys(|keys| check_sats_gate(&psbt, &ctx.bridge_config, keys))?;

    // Colored account only. An unscoped sign co-signs all inputs with a known
    // key, including vanilla inputs that no send-RGB bind checks.
    let sign_colored = || {
        ctx.state
            .sign_psbt_scoped(&req.psbt_bytes, Some(crate::keys::AccountType::Colored))
    };
    // Same gate as the EVM route. RGB source SPV evidence must still hold on
    // the current chain. No-op when nothing is pinned (an EVM source).
    #[cfg(feature = "rgb-validation")]
    let signed = sign_with_chain_pins_unchanged(ctx, pins, sign_colored)?;
    #[cfg(not(feature = "rgb-validation"))]
    let signed = sign_colored()?;

    signed_psbt_response(signed)
}

/// Signs the Colored inputs of a PSBT the caller validated: a rights refill.
/// It has no chain pins to hold. Refuses a no-op.
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
pub(super) fn sign_colored_psbt(ctx: &ServerContext, psbt_bytes: &[u8]) -> Result<EnclaveResponse> {
    // Colored account only. An unscoped sign co-signs all inputs with a known
    // key, including vanilla inputs that no send-RGB bind checks.
    signed_psbt_response(
        ctx.state
            .sign_psbt_scoped(psbt_bytes, Some(crate::keys::AccountType::Colored))?,
    )
}

#[cfg(evm_to_rgb)]
fn signed_psbt_response((signed_psbt, inputs_signed): (Vec<u8>, usize)) -> Result<EnclaveResponse> {
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

#[cfg(all(test, feature = "rgb-validation", rgb_to_evm))]
mod tests {
    use super::*;
    use crate::config::BridgeConfig;
    use crate::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
    use crate::networks::rgb::spv_crosscheck::ChainPins;
    use crate::state::EnclaveState;
    use std::cell::Cell;

    fn pinned_context() -> (ServerContext, ChainPins) {
        let ctx = ServerContext::new(
            EnclaveState::default(),
            BridgeConfig::default(),
            crate::test_support::regtest_header_chain(),
        );
        let pins = ChainPins::new();
        {
            let chain = ctx.header_chain.lock().unwrap();
            pins.pin(&chain, chain.tip_height()).unwrap();
        }
        (ctx, pins)
    }

    // F05-NEW-AF-08: no header update can land between the check and the key.
    #[test]
    fn header_chain_stays_locked_until_sign_returns() {
        let (ctx, pins) = pinned_context();

        let locked_during_sign = sign_with_chain_pins_unchanged(&ctx, &pins, || {
            Ok(ctx.header_chain.try_lock().is_err())
        })
        .unwrap();

        assert!(
            locked_during_sign,
            "header chain was unlocked while signing"
        );
        assert!(
            ctx.header_chain.try_lock().is_ok(),
            "lock not released after signing"
        );
    }

    #[test]
    fn replaced_pin_refuses_without_signing() {
        let (ctx, pins) = pinned_context();
        *ctx.header_chain.lock().unwrap() =
            HeaderChain::new(Network::Signet, checkpoint_for(Network::Signet));

        let signed = Cell::new(false);
        let result = sign_with_chain_pins_unchanged(&ctx, &pins, || {
            signed.set(true);
            Ok(())
        });

        assert!(result.is_err());
        assert!(!signed.get(), "sign ran after the pin check failed");
    }
}
