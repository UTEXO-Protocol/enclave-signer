//! `Sign`: the bridge route request.
//!
//! Orchestration only. It validates source against destination, verifies the
//! EVM deposit, holds the replay reservation, then hands the actual signature
//! to [`super::signers`]. Every individual check lives in `networks/`.

#[cfg(all(feature = "bfa-validation", feature = "rgb-mint-burn"))]
use super::bfa::bfa_mint_events;
#[cfg(all(feature = "bfa-validation", feature = "rgb-swap"))]
use super::bfa::bfa_transfer_ancestry_events;
#[cfg(feature = "bfa-validation")]
use super::bfa::{bfa_burn_ancestry_events, cea_events};
use super::context::ServerContext;
use super::dispatch::unsupported_build;
use super::signers::{handle_sign_evm, handle_sign_psbt};
use crate::error::{EnclaveError, Result};
use crate::networks::{
    validate_destination, validate_route_proofs, validate_source, ValidationContext,
};
use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};
use crate::proto::*;

pub(super) fn handle_sign(ctx: &ServerContext, req: SignRequest) -> Result<EnclaveResponse> {
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

    // Before destination validation, not after: a BFA mint's consignment cannot
    // be validated at all until the lock it commits to has been verified.
    #[cfg(feature = "bfa-validation")]
    let bfa_locks = verified_bfa_locks(ctx, source_ref, destination_ref)?;
    #[cfg(feature = "bfa-validation")]
    let bfa_bridge_events = cea_events(&bfa_locks);
    // Not gated on `bfa-mint`: `validate_consignment` takes the events
    // unconditionally, so an empty set is already how "no BFA here" is spelled
    // and every call site is spared a `#[cfg]` pair.
    #[cfg(all(feature = "rgb-validation", not(feature = "bfa-validation")))]
    let bfa_bridge_events: Vec<rgbstd::vm::ether_extension::Event> = Vec::new();

    let validation_ctx = ValidationContext {
        bridge_config: &ctx.bridge_config,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: ctx.rgb_validator.as_ref(),
        #[cfg(feature = "spv")]
        header_chain: &ctx.header_chain,
        #[cfg(feature = "rgb-validation")]
        self_owned_psbt_outputs: Some(&self_owned_psbt_outputs),
        #[cfg(feature = "rgb-validation")]
        bridge_events: &bfa_bridge_events,
    };
    let source_validated = validate_source(req.amount, source_ref, &validation_ctx)?;

    let source_commission = source_commission(source_ref)?;
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

    // Independent EVM `FundsIn` verification: confirm the deposit on-chain
    // through the enclave's own RPC call rather than the listener's booleans.
    // Runs after the cheap local cross-checks and before the replay guard
    // records the op, so the RPC is only paid on an otherwise valid request.
    verify_funds_in_deposit(
        ctx,
        req.amount,
        source_ref,
        destination_ref,
        &destination_proof,
    )?;

    // Soft operation-uniqueness guard. The key is reserved before signing, and
    // committed further down only once signing has succeeded.
    #[cfg(not(feature = "dev-mode"))]
    let _op_reservation = reserve_operation(ctx, source_ref, destination_ref)?;

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
                    #[cfg(feature = "bfa-mint")]
                    &bfa_locks,
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
    #[cfg(feature = "bfa-mint")] locks: &[crate::networks::evm::events::VerifiedLock],
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

    // A burn settles a redemption, so it additionally binds the payout target
    // to the 32 bytes the burner committed to (`MS_BURN_RECIPIENT`). Only the
    // mint/burn flow has a burn, and `validate_funds_out_amount` has already
    // rejected anything that is not one, so this needs no runtime type test -
    // the swap enclave carries no redemption rule at all.
    #[cfg(feature = "rgb-mint-burn")]
    crosscheck::validate_funds_out_burn_recipient(params, validated)?;

    // Settlement bind (spec P6): the deposits `settlementData` cites must be
    // exactly the verified locks behind the burn's mint ancestry. On-chain
    // `burnId` hashes every release field, so this is what makes one burn map
    // to one `burnId` instead of one per `settlementData` the backend picks.
    #[cfg(feature = "bfa-mint")]
    crosscheck::validate_funds_out_settlement(params, locks)?;

    // `burnId` itself is not recomputed here: the contract derives and
    // checks it from the same fields (`InvalidBurnId`).

    Ok(())
}

/// The commission the source network declares, per compiled build.
///
/// A CCD source is only present on a `ccd` build; `validate_source` already
/// rejected it otherwise, but the arm is still required for the match to
/// type-check.
fn source_commission(source: &SourceNetwork) -> Result<u64> {
    match source {
        SourceNetwork::EvmSource(source) => Ok(source.commission),
        SourceNetwork::RgbSource(source) => Ok(source.commission),
        #[cfg(feature = "ccd")]
        SourceNetwork::CcdSource(source) => Ok(source.commission),
        #[allow(unreachable_patterns)]
        _ => Err(unsupported_build("ccd")),
    }
}

/// Verify the EVM lock behind every BFA mint this request touches, in whichever
/// direction it runs. Empty when neither side carries a BFA consignment, which
/// is how "nothing for `cea` to check" is spelled.
#[cfg(feature = "bfa-validation")]
fn verified_bfa_locks(
    ctx: &ServerContext,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> Result<Vec<crate::networks::evm::events::VerifiedLock>> {
    match (source, destination) {
        // A burn: the events prove the locks behind the mints it descends from.
        (SourceNetwork::RgbSource(rgb), _) => bfa_burn_ancestry_events(ctx, rgb),
        // A mint: the events prove the locks it and its ancestry were minted
        // against.
        (SourceNetwork::EvmSource(evm), DestinationNetwork::RgbDestination(rgb)) => {
            #[cfg(feature = "rgb-mint-burn")]
            {
                bfa_mint_events(ctx, evm, rgb)
            }
            #[cfg(feature = "rgb-swap")]
            {
                let _ = evm;
                bfa_transfer_ancestry_events(ctx, rgb)
            }
        }
        // No BFA consignment on either side, so nothing for `cea` to check.
        _ => Ok(Vec::new()),
    }
}

/// Prove the EVM `FundsIn` deposit behind an EVM->RGB request, fail-closed.
///
/// Three builds, three behaviours, one name, so `handle_sign` needs no `#[cfg]`
/// for this step:
///
///   * `evm-rpc` (not dev-mode): fetch the receipt through the enclave's own
///     RPC client, then bind the recipient seal to the invoice in that log.
///     Fully trustless only once Helios verifies the RPC.
///   * no `evm-rpc` (not dev-mode): refuse. There is no evidence the deposit
///     occurred - the consignment/PSBT checks prove the transfer shape, not
///     that an EVM deposit backs it. Mirrors the no-`spv` `fundsOut` refusal.
///   * dev-mode: no-op, the legacy path for local testing.
#[cfg(all(feature = "evm-rpc", not(feature = "dev-mode")))]
fn verify_funds_in_deposit(
    ctx: &ServerContext,
    amount: u64,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
    destination_proof: &crate::networks::DestinationProof,
) -> Result<()> {
    if let (SourceNetwork::EvmSource(source), DestinationNetwork::RgbDestination(_)) =
        (source, destination)
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
        let verified = crate::networks::evm::events::verify_funds_in_event(
            &**client,
            // FundsIn is emitted by the bridge entry contract, which may differ
            // from the MultisigProxy pinned in EVM_PROXY_CONTRACT_ADDRESS (see config.rs).
            &ctx.bridge_config.funds_in_contract,
            ctx.evm_rpc_config.min_confirmations,
            &tx_hash,
            &source.funds_in_operation_id,
            amount,
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

    Ok(())
}

#[cfg(all(not(feature = "evm-rpc"), not(feature = "dev-mode")))]
fn verify_funds_in_deposit(
    _ctx: &ServerContext,
    _amount: u64,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
    _destination_proof: &crate::networks::DestinationProof,
) -> Result<()> {
    if matches!(
        (source, destination),
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

    Ok(())
}

#[cfg(feature = "dev-mode")]
fn verify_funds_in_deposit(
    _ctx: &ServerContext,
    _amount: u64,
    _source: &SourceNetwork,
    _destination: &DestinationNetwork,
    _destination_proof: &crate::networks::DestinationProof,
) -> Result<()> {
    Ok(())
}

/// Reserve the operation key for an EVM->RGB bridge sign, rejecting a same-op
/// resubmission inside the TTL window.
///
/// Defense in depth only - the guard is in-memory, per-instance, and volatile;
/// the durable guard is on-chain. The caller commits the reservation once
/// signing succeeds, and dropping it un-committed rolls the key back, so a
/// transient signing failure does not consume it.
#[cfg(not(feature = "dev-mode"))]
fn reserve_operation<'ctx>(
    ctx: &'ctx ServerContext,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> Result<Option<crate::state::ReplayReservation<'ctx>>> {
    if let (SourceNetwork::EvmSource(source), DestinationNetwork::RgbDestination(destination)) =
        (source, destination)
    {
        let op_key = crate::networks::rgb::psbt_validation::psbt_operation_key(
            ctx.bridge_config.chain_id,
            &ctx.bridge_config.bridge_contract,
            &source.tx_hash,
            &source.funds_in_operation_id,
            &destination.asset_id,
        );
        match ctx.state.op_replay_guard.reserve(op_key) {
            Ok(reservation) => Ok(Some(reservation)),
            Err(EnclaveError::NonceReplay) => {
                tracing::warn!(
                    funds_in_operation_id = %hex::encode(&source.funds_in_operation_id),
                    evm_tx_hash = %hex::encode(&source.tx_hash),
                    "rejecting duplicate bridge PSBT operation (soft replay guard)"
                );
                Err(EnclaveError::CrossCheck(
                    "duplicate bridge operation: this (chain, contract, evm_tx_hash, \
                     funds_in_operation_id, rgb_asset_id) was already signed recently - refusing \
                     to sign a replay (soft in-memory guard; durable guard is on-chain)"
                        .into(),
                ))
            }
            Err(e) => Err(e),
        }
    } else {
        Ok(None)
    }
}
