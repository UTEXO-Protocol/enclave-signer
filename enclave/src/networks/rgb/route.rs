//! Route-level RGB validation: the entry points that `networks::route` calls.
//!
//! This layer only selects the check for this build. The checks are in the
//! sibling modules: consignment parsing and rgbstd validation in
//! [`super::validation`], PSBT anchoring in [`super::psbt_validation`], the
//! mint signer's PSBT core in [`super::psbt_commit`] and
//! [`super::parent_proof`], and per-flow rules in [`super::flow`].
//!
//! The mint signer validates from the PSBT and its parent alone. Every other
//! RGB build validates a consignment.

#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
use super::flow;
#[cfg(evm_to_rgb)]
use super::psbt_validation;
#[cfg(feature = "rgb-validation")]
use super::validation;
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
use super::{parent_proof, psbt_commit};
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
use crate::config::BridgeConfig;
#[cfg(all(not(feature = "rgb-validation"), rgb_to_evm))]
use crate::error::EnclaveError;
use crate::error::Result;
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
use crate::networks::RouteProof;
use crate::networks::ValidationContext;
#[cfg(evm_to_rgb)]
use crate::proto::RgbDestination;
#[cfg(rgb_to_evm)]
use crate::proto::RgbSource;
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
use crate::proto::SignRightsRefillRequest;
#[cfg(all(feature = "rgb-swap", evm_to_rgb))]
use sha3::{Digest, Keccak256};

/// Validates an RGB source. The route amount comes from the consignment,
/// never from the wire. The checks are in [`super::validation`].
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
pub fn validate_source(
    source: &RgbSource,
    ctx: &ValidationContext<'_>,
) -> Result<crate::networks::SourceProof> {
    let validated = validation::validate_source(source, ctx)?;
    let proof = route_proof_from_validated_consignment(&validated)?;
    Ok(crate::networks::SourceProof {
        proof,
        rgb_consignment: Some(validated),
    })
}

/// A build without RGB validation refuses every RGB source.
#[cfg(all(not(feature = "rgb-validation"), rgb_to_evm))]
pub fn validate_source(
    _source: &RgbSource,
    _ctx: &ValidationContext<'_>,
) -> Result<crate::networks::SourceProof> {
    Err(EnclaveError::CrossCheck(
        "RGB source validation requires the enclave to be built with --features rgb-validation"
            .into(),
    ))
}

#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
fn route_proof_from_validated_consignment(
    validated: &validation::ValidatedConsignment,
) -> Result<RouteProof> {
    use crate::error::EnclaveError;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "RGB source requires a consignment with at least one transition".into(),
        )
    })?;

    // The flow decides which transition proves the withdrawal and where its
    // amount is.
    let amount = flow::funds_out_source_amount(last)?;

    Ok(RouteProof {
        amount,
        operation_id: Some(normalize_rgb_operation_id(&last.op_id)?),
    })
}

#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
fn normalize_rgb_operation_id(op_id: &str) -> Result<String> {
    use crate::error::EnclaveError;

    let normalized = op_id.strip_prefix("0x").unwrap_or(op_id);
    if normalized.len() != 64 {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB operation_id must be 32-byte hex, got {} hex chars",
            normalized.len()
        )));
    }
    if !normalized.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(EnclaveError::CrossCheck(
            "RGB operation_id is not hex-decodable".into(),
        ));
    }

    Ok(normalized.to_ascii_lowercase())
}

/// Validate fields owned by an RGB destination before route-level validation.
#[cfg(evm_to_rgb)]
pub fn validate_destination(
    destination: &RgbDestination,
    _ctx: &ValidationContext<'_>,
) -> Result<()> {
    psbt_validation::validate_psbt_bytes(&destination.psbt_bytes)
}

/// Returns the **recipient leg** of the bound consignment in asset units and
/// its `utxob:` seals (see
/// [`psbt_validation::validate_psbt_anchors_transition`]). The route-level
/// cross-check uses this amount, not the host-supplied `psbt_output_amount`.
#[cfg(all(feature = "rgb-swap", evm_to_rgb))]
pub fn validate_destination_anchor(
    destination: &RgbDestination,
    source_amount: u64,
    source_commission: u64,
    ctx: &ValidationContext<'_>,
) -> Result<(u64, Vec<String>)> {
    use crate::error::EnclaveError;

    let validated = validated_destination_consignment(
        &destination.consignment,
        &destination.consignment_hash,
        &destination.asset_id,
        ctx,
    )?;

    crate::config::check_psbt_size("psbt_bytes", &destination.psbt_bytes)?;
    let psbt = bitcoin::psbt::Psbt::deserialize(&destination.psbt_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("psbt_bytes is not a valid PSBT: {e}")))?;
    // Fail closed. The per-output recipient bind needs the enclave keys to
    // tell bridge change from a payout. No resolver means no bind.
    let self_owned = ctx.self_owned_psbt_outputs.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT cannot be bound: no self-owned-output resolver is wired in, so the \
             enclave cannot distinguish bridge change from a payout to a third party"
                .into(),
        )
    })?;
    // `legs.recipient_seals` is returned, not compared here. `handle_sign`
    // authenticates the invoice after it verifies the FundsIn receipt.
    let legs = psbt_validation::validate_psbt_anchors_transition(
        &psbt,
        &validated,
        source_amount,
        source_commission,
        self_owned,
    )?;

    // The colored inputs the enclave signs, from its own keys.
    let resolve_colored = ctx.psbt_fee_key_paths.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT cannot be bound: no key-path resolver is wired in, so the enclave \
             cannot tell which inputs it signs"
                .into(),
        )
    })?;
    let key_path_inputs = resolve_colored(&psbt)?;
    psbt_validation::assert_colored_inputs_close_seals(
        &psbt,
        &key_path_inputs,
        &validated.last_closed_seals,
    )?;
    // Pinned fee policy, shared with the plain-BTC path. No fee estimate is
    // fetched. A dynamic bound can strand a mint whose EVM lock is settled.
    // Also, the host controls that egress.
    psbt_validation::check_psbt_fee(&psbt, &key_path_inputs, "send-RGB")?;

    Ok((legs.recipient, legs.recipient_seals))
}

/// The consignment of a swap-flow PSBT: intact, valid under consensus, of the
/// pinned asset and not on the reject list.
#[cfg(all(feature = "rgb-swap", evm_to_rgb))]
fn validated_destination_consignment(
    consignment: &[u8],
    consignment_hash: &[u8],
    asset_id: &str,
    ctx: &ValidationContext<'_>,
) -> Result<validation::ValidatedConsignment> {
    use crate::error::EnclaveError;

    if consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "send-RGB PSBT signing requires a consignment to bind the PSBT to the RGB transition"
                .into(),
        ));
    }
    // Without this check, only the generic wire frame limits the size.
    validation::assert_consignment_size(consignment, ctx.bridge_config, "send-RGB")?;
    // Integrity, not authorization. The listener controls both `consignment`
    // and `consignment_hash`, so a match only proves the wire copy is intact.
    // Authorization comes from rgbstd validation and the witness-txid bind.
    if consignment_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "consignment present but consignment_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(consignment);
    if computed[..] != *consignment_hash {
        return Err(EnclaveError::CrossCheck(
            "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
        ));
    }
    if asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB destination asset_id is empty".into(),
        ));
    }

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT carries a consignment but the RGB validator is not configured".into(),
        )
    })?;
    // History witnesses must be mined, per the indexer. Only the signed tx
    // (last) may be unbroadcast; the PSBT bind requires it to be the PSBT's tx.
    let indexer = validator.indexer_witnesses(ctx.bridge_config.spv_min_confirmations);
    let witnesses = validation::WitnessCheck {
        chain: &indexer,
        allow_unbroadcast_last: true,
        infer_spent_ancestors: true,
    };
    // The binder derives the lock of each mint in the history.
    let validated = validator.validate_consignment(consignment, ctx.anchor_binder, &witnesses)?;

    // Fail closed on a missing pin, unlike the source direction. An enclave
    // with rgb-validation but no config must not trust the listener.
    // Same as the EVM funds-out `!is_configured()` gate.
    validation::assert_asset_binding(
        &validated.contract_id,
        asset_id,
        ctx.bridge_config,
        validation::AssetBindMode::Destination,
    )?;
    // After the bind, so only the pinned asset's list is read. The recipient
    // refuses a transfer whose outputs the list reaches.
    validation::assert_not_rejected(
        &validated,
        ctx.reject_list_reader,
        validation::RejectCheck::SettlingInputsAndOutputs,
    )?;
    Ok(validated)
}

/// The mint its PSBT commits, bound to the deposit and the right's UTXO (F1-F7,
/// PP, M1-M7; M8 runs in the signer). Returns the units and the `utxob:` seal.
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
pub fn validate_destination_anchor(
    destination: &RgbDestination,
    source_amount: u64,
    source_commission: u64,
    ctx: &ValidationContext<'_>,
) -> Result<(u64, Vec<String>)> {
    let psbt = psbt_validation::parse_psbt_shape(&destination.psbt_bytes)?;
    psbt_validation::assert_txid_and_sighash_fixed(&psbt)?;
    let (pin, committed) = pinned_commitment(&psbt, &destination.asset_id, ctx.bridge_config)?;
    let mint = psbt_validation::mint_facts(&committed)?;
    psbt_validation::assert_mints_net_deposit(&mint, source_amount, source_commission)?;
    let colored = mint_inputs(&psbt, ctx)?;
    parent_proof::right_input(&psbt, &destination.parent_psbt, mint.right, pin)?;
    // Pinned fee policy, shared with the plain-BTC path. No fee estimate is
    // fetched: the host controls that egress.
    psbt_validation::check_psbt_fee(&psbt, &colored, "mint")?;
    // Last: the only network read on this path.
    let bind = ctx.mint_binder.ok_or_else(|| {
        crate::error::EnclaveError::CrossCheck(
            "mint cannot be bound: no deposit binder is wired in".into(),
        )
    })?;
    bind(&mint)?;
    Ok((mint.issued, vec![mint.recipient_seal]))
}

/// F3-F6 under the `RGB_ASSET_ID` pin, which the request's `asset_id` must
/// name too. Returns the pin and the committed transition.
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
fn pinned_commitment(
    psbt: &bitcoin::psbt::Psbt,
    asset_id: &str,
    cfg: &BridgeConfig,
) -> Result<(rgbstd::ContractId, psbt_commit::Committed)> {
    let pin = psbt_commit::pinned_contract(cfg)?;
    let committed = psbt_commit::committed_transition(psbt, pin)?;
    validation::assert_asset_binding(
        &pin.to_string(),
        asset_id,
        cfg,
        validation::AssetBindMode::Destination,
    )?;
    Ok((pin, committed))
}

/// F7: the mint spends one input, a Colored key-path input of this enclave.
/// Returns it, for the fee bound.
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
fn mint_inputs(psbt: &bitcoin::psbt::Psbt, ctx: &ValidationContext<'_>) -> Result<Vec<usize>> {
    use crate::error::EnclaveError;

    let inputs = psbt.unsigned_tx.input.len();
    if inputs != psbt_validation::MINT_INPUTS {
        return Err(EnclaveError::CrossCheck(format!(
            "mint PSBT spends {inputs} inputs - a mint spends its right alone, and that UTXO's \
             sats pay the fee"
        )));
    }
    let resolve_colored = ctx.psbt_fee_key_paths.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "mint cannot be bound: no key-path resolver is wired in, so the enclave cannot tell \
             which inputs it signs"
                .into(),
        )
    })?;
    let colored = resolve_colored(psbt)?;
    psbt_validation::assert_only_colored_inputs(psbt, &colored, "mint")?;
    Ok(colored)
}

/// A rights refill from its PSBT and parent alone (F2-F6, RR6-RR8, RR11), no
/// network. Returns the new rights' vouts, which the caller proves ours (RR9).
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
pub fn validate_rights_refill(
    req: &SignRightsRefillRequest,
    psbt: &bitcoin::psbt::Psbt,
    cfg: &BridgeConfig,
) -> Result<Vec<u32>> {
    psbt_validation::assert_txid_and_sighash_fixed(psbt)?;
    let (pin, committed) = pinned_commitment(psbt, &req.asset_id, cfg)?;
    let (right, vouts) = psbt_validation::refill_rights(&committed)?;
    parent_proof::right_input(psbt, &req.parent_psbt, right, pin)?;
    Ok(vouts)
}

#[cfg(all(test, feature = "rgb-validation"))]
mod tests;
