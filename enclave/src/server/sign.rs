//! `Sign`: the bridge route request.
//!
//! Orchestration only. It validates source against destination, verifies the
//! EVM deposit and holds the replay reservation. Then [`super::signers`] signs.
//! The individual checks are in `networks/`.

#[cfg(all(feature = "bfa-validation", rgb_to_evm))]
use super::bfa::bfa_burn_ancestry_events;
#[cfg(all(feature = "bfa-validation", feature = "rgb-mint-burn", evm_to_rgb))]
use super::bfa::bfa_mint_events;
#[cfg(all(feature = "bfa-validation", feature = "rgb-swap"))]
use super::bfa::bfa_transfer_ancestry_events;
#[cfg(feature = "bfa-validation")]
use super::bfa::cea_events;
use super::context::ServerContext;
use super::dispatch::{unsupported_build, wrong_signer_role};
#[cfg(rgb_to_evm)]
use super::signers::handle_sign_evm;
#[cfg(evm_to_rgb)]
use super::signers::handle_sign_psbt;
use crate::error::{EnclaveError, Result};
use crate::networks::{
    validate_destination, validate_route_proofs, validate_source, ValidationContext,
};
use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};
use crate::proto::*;
use crate::state::ReplayReservation;

/// Sign one bridge request. Returns the response and the uncommitted replay
/// reservation.
pub(super) fn handle_sign(
    ctx: &ServerContext,
    req: SignRequest,
) -> Result<(EnclaveResponse, Option<ReplayReservation<'_>>)> {
    let source_ref = req
        .source_network
        .as_ref()
        .ok_or_else(|| EnclaveError::InvalidRequest("sign request has no source_network".into()))?;
    let destination_ref = req.destination_network.as_ref().ok_or_else(|| {
        EnclaveError::InvalidRequest("sign request has no destination_network".into())
    })?;

    // Refuse the other signer direction before any work.
    check_signer_role(source_ref, destination_ref)?;

    // No deposit verifier in this build: refuse before the replay guard.
    #[cfg(not(feature = "evm-rpc"))]
    refuse_unverifiable_funds_in(source_ref, destination_ref)?;

    // Refuse before any validation work while the key is not ready.
    ctx.state.with_keys(|_| Ok(()))?;

    // Idempotent retry (issue #220): an identical request whose signature was
    // already produced but never reached the caller returns the stored
    // response instead of being refused as a duplicate. A conflicting retry
    // (same operation key, different signing data) misses the cache and stays
    // refused by the guard below.
    #[cfg(evm_to_rgb)]
    let replay_id: Option<([u8; 32], [u8; 32])> = operation_key(ctx, source_ref, destination_ref)
        .map(|op_key| {
            (
                op_key,
                request_fingerprint(req.amount, source_ref, destination_ref),
            )
        });
    #[cfg(evm_to_rgb)]
    if let Some((op_key, fingerprint)) = &replay_id {
        if let Some(stored) = ctx.state.op_replay_guard.op_response(op_key, fingerprint) {
            return Ok((
                EnclaveResponse {
                    response: Some(Response::SignedPsbt(SignedPsbtResponse {
                        signed_psbt: stored.signed_psbt,
                        inputs_signed: stored.inputs_signed,
                    })),
                },
                None,
            ));
        }
    }

    // Refuse known replays before network I/O. An invalid request must not
    // use guard capacity, so this only checks. The reservation is made later.
    #[cfg(evm_to_rgb)]
    precheck_operation(ctx, source_ref, destination_ref)?;

    // Refuse an invalid deposit before RGB validation and fee/indexer I/O.
    // Keep the authorized recipient to compare with the proven RGB seals.
    #[cfg(evm_to_rgb)]
    let authorized_recipient =
        verify_funds_in_deposit(ctx, req.amount, source_ref, destination_ref)?;

    // Self-owned-outpoint oracle for the send-RGB per-output recipient bind.
    // The key lock is held only for each lookup, not across Electrum calls.
    //
    // An outpoint on this PSBT is resolved from its taproot metadata.
    // An outpoint on an earlier tx needs a fetch to read its script. rgb-lib
    // puts change on an existing UTXO when the transfer has no BTC change.
    #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
    let self_owned_psbt_outputs = |psbt: &bitcoin::psbt::Psbt, outpoint: bitcoin::OutPoint| {
        use crate::networks::rgb::btc_ownership;

        if outpoint.txid == psbt.unsigned_tx.compute_txid() {
            return ctx.state.with_keys(|keys| {
                Ok(btc_ownership::self_owned_output_indices(psbt, keys).contains(&outpoint.vout))
            });
        }

        // Fail closed: without an indexer, change and payout look the same.
        let validator = ctx.launch()?.rgb_validator.as_ref().ok_or_else(|| {
            EnclaveError::CrossCheck(
                "send-RGB change seal names an outpoint outside the PSBT, but the RGB validator \
                 is not configured - the enclave cannot resolve that outpoint's script"
                    .into(),
            )
        })?;
        // Network round-trip, so it is outside `with_keys`.
        let tx = validator.fetch_transaction(outpoint.txid)?;
        let Some(txout) = tx.output.get(outpoint.vout as usize) else {
            return Err(EnclaveError::CrossCheck(format!(
                "send-RGB change seal names outpoint {outpoint}, but that transaction has only \
                 {} outputs",
                tx.output.len()
            )));
        };
        let script = txout.script_pubkey.as_bytes().to_vec();
        ctx.state
            .with_keys(|keys| Ok(btc_ownership::asset_change_scripts(psbt, keys).contains(&script)))
    };

    #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
    let psbt_fee_key_paths = |psbt: &bitcoin::psbt::Psbt| {
        // Colored is the scope that `sign_psbt_scoped` uses on the send-RGB path.
        ctx.state.with_keys(|keys| {
            Ok(
                crate::networks::rgb::psbt_validation::fee_key_path_inputs_scoped(
                    psbt,
                    keys,
                    crate::keys::AccountType::Colored,
                ),
            )
        })
    };

    // Must run before destination validation. A BFA mint consignment cannot
    // be validated until its lock is verified.
    #[cfg(feature = "bfa-validation")]
    let bfa_locks = verified_bfa_locks(ctx, source_ref, destination_ref)?;
    #[cfg(feature = "bfa-validation")]
    let bfa_bridge_events = cea_events(&bfa_locks);
    // `validate_consignment` always takes the events. An empty set means
    // "no BFA", so call sites need no `#[cfg]`.
    #[cfg(all(feature = "rgb-validation", not(feature = "bfa-validation")))]
    let bfa_bridge_events: Vec<rgbstd::vm::ether_extension::Event> = Vec::new();

    // Records the Bitcoin blocks that the SPV checks use. Each check releases
    // the header-chain lock at return. `assert_chain_pins_unchanged` reads these
    // blocks again immediately before the key is used (F05-NEW-AF-08).
    #[cfg(feature = "rgb-validation")]
    let chain_pins = crate::networks::rgb::spv_crosscheck::ChainPins::new();

    let validation_ctx = ValidationContext {
        bridge_config: &ctx.bridge_config,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: ctx.launch()?.rgb_validator.as_ref(),
        #[cfg(feature = "rgb-validation")]
        header_chain: &ctx.header_chain,
        #[cfg(feature = "rgb-validation")]
        chain_pins: &chain_pins,
        // Only the RGB-destination (mint) bind uses it.
        #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
        self_owned_psbt_outputs: Some(&self_owned_psbt_outputs),
        #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
        psbt_fee_key_paths: Some(&psbt_fee_key_paths),
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

    // Must run after RGB validation, which proves the seals.
    #[cfg(evm_to_rgb)]
    bind_funds_in_recipient(authorized_recipient, &destination_proof)?;

    // Soft operation-uniqueness guard. Reserve before signing. The caller
    // commits after the response write succeeds. A failed write releases the
    // reservation. A successful write does not prove receipt by the caller.
    #[cfg(evm_to_rgb)]
    let op_reservation = reserve_operation(ctx, source_ref, destination_ref)?;
    // The replay key is the EVM deposit, so only the mint direction has one.
    #[cfg(not(evm_to_rgb))]
    let op_reservation = None;

    let destination = req.destination_network.ok_or_else(|| {
        EnclaveError::InvalidRequest("sign request has no destination_network".into())
    })?;

    let result = match destination {
        #[cfg(rgb_to_evm)]
        DestinationNetwork::EvmDestination(destination) => {
            // RGB->EVM `fundsOut` binding: bind the calldata to the operation
            // that validation authenticated (witness confirmation, BtcRelay
            // agreement, consignment-bound release amount).
            //
            // RGB source only. A CCD source has no consignment, and the
            // validation above already authorizes a CCD -> EVM release.
            //
            // Burn identity comes first, on both release routes. It needs only
            // the calldata and the pins.
            let release = destination_proof
                .evm_release_identity
                .as_ref()
                .ok_or_else(|| {
                    EnclaveError::Internal(
                        "EVM destination validated without a release identity".into(),
                    )
                })?;
            // An RGB-source release must use the RGB network id as
            // `sourceChainId` and an empty `sourceAddress`. On chain,
            // `sourceChainId` selects the verifier, settlement module and
            // commission rate.
            if matches!(source_ref, SourceNetwork::RgbSource(_)) {
                crate::networks::evm::validation::validate_rgb_source_identity(release)?;
            }
            // `burnId` must equal the Bridge derivation from the bound fields
            // and the pinned Bridge, chain id and token. The contract also
            // reverts on a mismatch. This check fails earlier with a reason.
            crate::networks::evm::validation::validate_burn_id(&ctx.bridge_config, release)?;
            #[cfg(feature = "rgb-validation")]
            if let SourceNetwork::RgbSource(rgb_source) = source_ref {
                apply_funds_out_binding(
                    ctx,
                    release,
                    source_validated.rgb_consignment.as_ref(),
                    &rgb_source.merkle_proofs,
                    &chain_pins,
                    #[cfg(feature = "bfa-mint")]
                    &bfa_locks,
                )?;
            }
            handle_sign_evm(
                ctx,
                destination,
                destination_proof.evm_funds_out.as_ref(),
                #[cfg(feature = "rgb-validation")]
                &chain_pins,
            )
        }
        #[cfg(evm_to_rgb)]
        DestinationNetwork::RgbDestination(destination) => handle_sign_psbt(
            ctx,
            destination,
            #[cfg(feature = "rgb-validation")]
            &chain_pins,
        ),
        // `check_signer_role` refuses the other direction.
        #[allow(unreachable_patterns)]
        _ => Err(wrong_signer_role("this route")),
    };

    // Cache the completed signature so an identical retry whose response was
    // lost in transit returns the same signature instead of being refused as
    // a duplicate (issue #220). Only successful signs are stored; validation
    // and signing errors never reach here, so a failed attempt stays retryable.
    // A conflicting retry (same key, different fingerprint) is not stored and
    // stays refused by the guard.
    #[cfg(evm_to_rgb)]
    if let (Some((op_key, fingerprint)), Ok(response)) = (&replay_id, &result) {
        if let Some(Response::SignedPsbt(signed)) = &response.response {
            ctx.state.op_replay_guard.store_op_response(
                *op_key,
                crate::state::StoredOpResponse {
                    fingerprint: *fingerprint,
                    signed_psbt: signed.signed_psbt.clone(),
                    inputs_signed: signed.inputs_signed,
                },
            );
        }
    }

    // On error, the reservation drops here and rolls the key back.
    result.map(|response| (response, op_reservation))
}

/// Hash of the complete EVM->RGB signing request. The operation key binds the
/// deposit identity; the fingerprint additionally binds the exact signing
/// data, so a mutated retry (same key, different PSBT/consignment) does not
/// match the cache.
#[cfg(evm_to_rgb)]
fn request_fingerprint(
    amount: u64,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> [u8; 32] {
    use sha3::{Digest, Keccak256};

    let mut h = Keccak256::new();
    h.update(b"utexo:sign-req:v1");
    h.update(amount.to_be_bytes());
    match source {
        SourceNetwork::EvmSource(s) => {
            h.update([0x01]);
            h.update((s.tx_hash.len() as u64).to_be_bytes());
            h.update(&s.tx_hash);
            h.update((s.funds_in_operation_id.len() as u64).to_be_bytes());
            h.update(&s.funds_in_operation_id);
            h.update((s.token.len() as u64).to_be_bytes());
            h.update(&s.token);
            h.update((s.recipient.len() as u64).to_be_bytes());
            h.update(&s.recipient);
            h.update(s.commission.to_be_bytes());
        }
        _ => {
            h.update([0x00]);
        }
    }
    match destination {
        DestinationNetwork::RgbDestination(d) => {
            h.update([0x01]);
            h.update((d.psbt_bytes.len() as u64).to_be_bytes());
            h.update(&d.psbt_bytes);
            h.update((d.consignment.len() as u64).to_be_bytes());
            h.update(&d.consignment);
            h.update(d.operation_idx.to_be_bytes());
            h.update(d.psbt_output_amount.to_be_bytes());
            h.update((d.asset_id.len() as u64).to_be_bytes());
            h.update(d.asset_id.as_bytes());
        }
        _ => {
            h.update([0x00]);
        }
    }
    h.finalize().into()
}

/// Refuse a route of the other signer role. No-op on a build with both
/// directions. It refuses by exclusion, so a burn build with `ccd` still signs
/// CCD -> EVM.
fn check_signer_role(source: &SourceNetwork, destination: &DestinationNetwork) -> Result<()> {
    #[cfg(not(evm_to_rgb))]
    if matches!(source, SourceNetwork::EvmSource(_))
        || matches!(destination, DestinationNetwork::RgbDestination(_))
    {
        return Err(wrong_signer_role("EVM -> RGB bridge PSBTs"));
    }
    #[cfg(not(rgb_to_evm))]
    if matches!(source, SourceNetwork::RgbSource(_))
        || matches!(destination, DestinationNetwork::EvmDestination(_))
    {
        return Err(wrong_signer_role("RGB -> EVM fundsOut releases"));
    }
    let _ = (source, destination);
    Ok(())
}

/// Bind RGB->EVM release calldata to the validated consignment before
/// signing. It runs on both routes, `fundsOut` and `lzFundsOut` (#264).
/// Backend-supplied bridge operation ids are validated, not rewritten.
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
fn apply_funds_out_binding(
    ctx: &ServerContext,
    release: &crate::networks::evm::validation::ReleaseIdentity,
    validated: Option<&crate::networks::rgb::validation::ValidatedConsignment>,
    merkle_proofs: &[crate::proto::MerkleProofEntry],
    pins: &crate::networks::rgb::spv_crosscheck::ChainPins,
    #[cfg(feature = "bfa-mint")] locks: &[crate::networks::evm::events::VerifiedLock],
) -> Result<()> {
    use crate::networks::evm::crosscheck;

    // A `fundsOut` release needs the validated RGB source consignment
    // (RgbSource, rgb_validator set, consignment present).
    let validated = validated.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "fundsOut signing requires a validated RGB source consignment (the source must be an \
             RGB source with consignment bytes and a configured rgb_validator) - refusing to sign"
                .into(),
        )
    })?;

    // Defense in depth: all consignment witness txs must be mined.
    crosscheck::assert_witnesses_confirmed(validated)?;

    // BtcRelay agreement and source-block bind (#57 / #122).
    // The calldata `proof` must name headers that the enclave holds.
    // Its `source` pair must be the block of the last consignment witness tx.
    // An empty `proof` fails closed.
    // `BTC_RELAY_MODE` sets if the commitment words are compared to the
    // enclave-built relay records. Default is `required`, and production
    // accepts only `required`.
    // rgb-validation always has the SPV header chain (lib.rs M-01 compile_error).
    {
        // Fail on a poisoned lock, as `validate_source` does.
        // A poisoned header chain can be in the middle of a reorg.
        let chain = ctx
            .header_chain
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("SPV header chain lock poisoned: {e}")))?;
        crosscheck::verify_btc_relay_agreement(
            release,
            validated,
            merkle_proofs,
            &chain,
            pins,
            ctx.bridge_config.btc_relay_mode,
        )?;
    }

    // Consignment-bound release amount for the RGB flow of this build
    // (`rgb-swap` = Transfer, `rgb-mint-burn` = Burn).
    crosscheck::validate_funds_out_amount(release, validated)?;

    // Burn identity (bridge PR #152). `sourceBurnTxId` is the only `burnId`
    // input that names the settled RGB operation. The contract trusts the
    // enclave for it. Bind it to the OpId of the settling transition.
    // `validate_rgb_source_identity` in `handle_sign` binds
    // `sourceChainId` / `sourceAddress` before this.
    crosscheck::validate_funds_out_source_burn_tx_id(release, validated)?;

    // A burn settles a redemption. Thus it also binds the payout target to
    // the 32 bytes that the burner committed to (`MS_BURN_RECIPIENT`).
    // `validate_funds_out_amount` already refused all non-burns, so no
    // runtime type test is necessary.
    #[cfg(feature = "rgb-mint-burn")]
    crosscheck::validate_funds_out_burn_recipient(release, validated)?;

    // Settlement bind (spec P6). The deposits in `settlementData` must be
    // exactly the verified locks of the burn mint ancestry.
    #[cfg(feature = "bfa-mint")]
    crosscheck::validate_funds_out_settlement(release, locks)?;

    Ok(())
}

/// The commission the source network declares, per compiled build.
///
/// Only a `ccd` build has a CCD source. Other builds need the fallback arm
/// to type-check. `validate_source` already refused the request there.
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

/// Verify the EVM lock of each BFA mint in this request, in each direction.
/// Empty when no side has a BFA consignment.
#[cfg(feature = "bfa-validation")]
fn verified_bfa_locks(
    ctx: &ServerContext,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> Result<Vec<crate::networks::evm::events::VerifiedLock>> {
    match (source, destination) {
        // A burn: the events prove the locks of its mint ancestry.
        #[cfg(rgb_to_evm)]
        (SourceNetwork::RgbSource(rgb), _) => bfa_burn_ancestry_events(ctx, rgb),
        // A mint: the events prove the locks of the mint and its ancestry.
        #[cfg(evm_to_rgb)]
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
        _ => Ok(Vec::new()),
    }
}

/// The recipient that a verified deposit authorizes. Uninhabited on builds
/// without a deposit verifier, so their `Option` is always `None`.
#[cfg(all(feature = "evm-rpc", evm_to_rgb))]
use crate::networks::rgb::invoice::AuthorizedRecipient;
#[cfg(all(not(feature = "evm-rpc"), evm_to_rgb))]
type AuthorizedRecipient = std::convert::Infallible;

/// Prove the EVM `FundsIn` deposit of an EVM->RGB request. Fails closed.
///
/// One name for two builds, so `handle_sign` needs no `#[cfg]` here:
///
///   * `evm-rpc`: fetch the receipt with the enclave RPC client. Return the
///     recipient that the deposit invoice authorizes.
///   * no `evm-rpc`: no-op. [`refuse_unverifiable_funds_in`] already refused
///     all EVM->RGB requests.
///
/// [`bind_funds_in_recipient`] uses the result after RGB validation proves the
/// recipient seals.
#[cfg(all(feature = "evm-rpc", evm_to_rgb))]
fn verify_funds_in_deposit(
    ctx: &ServerContext,
    amount: u64,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> Result<Option<AuthorizedRecipient>> {
    let (SourceNetwork::EvmSource(source), DestinationNetwork::RgbDestination(_)) =
        (source, destination)
    else {
        return Ok(None);
    };
    let tx_hash: [u8; 32] = source.tx_hash.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "evm_tx_hash must be 32 bytes, got {}",
            source.tx_hash.len()
        ))
    })?;
    // `funds_in_operation_id` is the full 32-byte on-chain BridgeFundsIn
    // operationId. `verify_funds_in_event` fails closed on an empty or short value.
    let client = ctx.launch()?.evm_rpc_client.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "evm-rpc build but RPC client unavailable - refusing to sign a bridge PSBT \
             without independently verifying the FundsIn deposit"
                .into(),
        )
    })?;
    // Bind to the source BridgeFundsIn.operationId. `destination.operation_idx`
    // is a different id space.
    let verified = crate::networks::evm::events::verify_funds_in_event(
        &**client,
        // The bridge entry contract emits FundsIn. It can differ from the
        // MultisigProxy in EVM_PROXY_CONTRACT_ADDRESS (see config.rs).
        &ctx.bridge_config.funds_in_contract,
        ctx.evm_rpc_config.min_confirmations,
        &tx_hash,
        &source.funds_in_operation_id,
        amount,
        source.commission,
    )?;

    // Recipient bind. The checks above prove the amount, not the recipient.
    // The v2 Bridge `fundsIn` refuses a non-empty RGB destinationAddress, so
    // the deposit has no invoice. Then the OpId binds the recipient:
    // `decode_funds_in` requires the deposit rgbOpId to be the signed mint
    // transition, and that transition commits to its recipient seals.
    // A legacy deposit with an invoice also gets the seal bind.
    if verified.destination_address.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(
        crate::networks::rgb::invoice::parse_authorized_recipient(&verified.destination_address)?,
    ))
}

#[cfg(all(not(feature = "evm-rpc"), evm_to_rgb))]
fn verify_funds_in_deposit(
    _ctx: &ServerContext,
    _amount: u64,
    _source: &SourceNetwork,
    _destination: &DestinationNetwork,
) -> Result<Option<AuthorizedRecipient>> {
    Ok(None)
}

/// Refuse an EVM->RGB request on a build without `evm-rpc`.
/// The consignment and PSBT checks prove the transfer shape only.
/// They do not prove that an EVM deposit backs it.
#[cfg(not(feature = "evm-rpc"))]
fn refuse_unverifiable_funds_in(
    source: &SourceNetwork,
    destination: &DestinationNetwork,
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
             Rebuild with `--features evm-rpc`."
                .into(),
        ));
    }

    Ok(())
}

/// Compare the seals that RGB validation proved with the recipient that the
/// verified deposit authorized. No-op when [`verify_funds_in_deposit`]
/// returns no recipient.
#[cfg(all(feature = "evm-rpc", evm_to_rgb))]
fn bind_funds_in_recipient(
    authorized: Option<AuthorizedRecipient>,
    destination_proof: &crate::networks::DestinationProof,
) -> Result<()> {
    match authorized {
        Some(authorized) => crate::networks::rgb::invoice::assert_recipient_authorized(
            &destination_proof.rgb_recipient_seals,
            &authorized,
        ),
        None => Ok(()),
    }
}

#[cfg(all(not(feature = "evm-rpc"), evm_to_rgb))]
fn bind_funds_in_recipient(
    _authorized: Option<AuthorizedRecipient>,
    _destination_proof: &crate::networks::DestinationProof,
) -> Result<()> {
    Ok(())
}

/// Replay-guard key of an EVM->RGB bridge sign. `None` for all other routes.
#[cfg(evm_to_rgb)]
fn operation_key(
    ctx: &ServerContext,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> Option<[u8; 32]> {
    let (SourceNetwork::EvmSource(source), DestinationNetwork::RgbDestination(destination)) =
        (source, destination)
    else {
        return None;
    };
    Some(crate::networks::rgb::psbt_validation::psbt_operation_key(
        ctx.bridge_config.chain_id,
        &ctx.bridge_config.bridge_contract,
        &source.tx_hash,
        &source.funds_in_operation_id,
        &destination.asset_id,
    ))
}

/// Refuse a known replay without a record, so an invalid request does not use
/// guard capacity. [`reserve_operation`] still runs before signing to close
/// the concurrent race.
#[cfg(evm_to_rgb)]
fn precheck_operation(
    ctx: &ServerContext,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> Result<()> {
    let Some(op_key) = operation_key(ctx, source, destination) else {
        return Ok(());
    };
    ctx.state.op_replay_guard.check(&op_key).map_err(|e| {
        if matches!(e, EnclaveError::NonceReplay) {
            EnclaveError::CrossCheck(
                "duplicate bridge operation: refusing to sign a replay (soft in-memory guard; \
                 durable guard is on-chain)"
                    .into(),
            )
        } else {
            e
        }
    })
}

/// Reserve the operation key for an EVM->RGB bridge sign. Refuses a repeated
/// operation inside the TTL window.
///
/// Defense in depth only. The guard is in-memory and per instance. The durable
/// guard is on-chain. The caller commits after the response is written.
/// An uncommitted drop rolls the key back, so a transient error or a lost
/// response does not consume it.
#[cfg(evm_to_rgb)]
fn reserve_operation<'ctx>(
    ctx: &'ctx ServerContext,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> Result<Option<crate::state::ReplayReservation<'ctx>>> {
    if let (Some(op_key), SourceNetwork::EvmSource(source)) =
        (operation_key(ctx, source, destination), source)
    {
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

/// A signature that the caller did not receive must not consume the replay
/// key, so the retry is signed. Not for `bfa-validation`: it needs EVM lock events.
#[cfg(all(
    test,
    feature = "evm-rpc",
    feature = "rgb-swap",
    not(feature = "bfa-validation")
))]
mod bridge_operation_retry;

/// The early deposit and replay checks run before RGB work.
#[cfg(all(test, feature = "evm-rpc", evm_to_rgb))]
mod early_bridge_checks {
    use super::*;
    use crate::config::BridgeConfig;
    use crate::networks::evm::events::{EvmReceiptProvider, ReceiptData};
    use crate::state::EnclaveState;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct MissingDeposit(Arc<AtomicUsize>);

    impl EvmReceiptProvider for MissingDeposit {
        fn get_transaction_receipt(&self, _: &[u8; 32]) -> Result<Option<ReceiptData>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn get_block_number(&self) -> Result<u64> {
            panic!("a missing deposit must be rejected before querying the head")
        }
    }

    fn context(calls: &Arc<AtomicUsize>) -> ServerContext {
        let mut ctx = ServerContext::new(
            EnclaveState::default(),
            BridgeConfig::default(),
            crate::test_support::regtest_header_chain(),
        );
        ctx.state.initialize_from_seed([7; 64]).unwrap();
        ctx.launch.get_mut().unwrap().evm_rpc_client =
            Some(Box::new(MissingDeposit(Arc::clone(calls))));
        ctx
    }

    fn request() -> SignRequest {
        SignRequest {
            amount: 1000,
            source_network: Some(SourceNetwork::EvmSource(crate::proto::EvmSource {
                tx_hash: vec![1; 32],
                funds_in_operation_id: vec![2; 32],
                ..Default::default()
            })),
            // Invalid RGB data on purpose. The early checks must refuse before
            // consignment decoding, including BFA ancestry parsing.
            destination_network: Some(DestinationNetwork::RgbDestination(RgbDestination {
                asset_id: "rgb:test".into(),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn missing_deposit_rejects_before_rgb_without_consuming_replay_capacity() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = context(&calls);
        ctx.state.op_replay_guard =
            crate::state::NonceReplayGuard::with_capacity(1, std::time::Duration::from_secs(60));
        let existing = [9; 32];
        ctx.state
            .op_replay_guard
            .reserve(existing)
            .unwrap()
            .commit();
        for expected_calls in 1..=2 {
            let err = handle_sign(&ctx, request())
                .map(|(response, _)| response)
                .unwrap_err();
            assert!(err.to_string().contains("receipt not found"), "{err}");
            assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
            assert!(matches!(
                ctx.state.op_replay_guard.check(&existing),
                Err(EnclaveError::NonceReplay)
            ));
        }
    }

    #[test]
    fn duplicate_rejects_before_deposit_rpc_and_rgb() {
        let calls = Arc::new(AtomicUsize::new(0));
        let ctx = context(&calls);
        let key = crate::networks::rgb::psbt_validation::psbt_operation_key(
            ctx.bridge_config.chain_id,
            &ctx.bridge_config.bridge_contract,
            &[1; 32],
            &[2; 32],
            "rgb:test",
        );
        let reservation = ctx.state.op_replay_guard.reserve(key).unwrap();
        let err = handle_sign(&ctx, request())
            .map(|(response, _)| response)
            .unwrap_err();
        assert!(
            err.to_string().contains("duplicate bridge operation"),
            "{err}"
        );
        reservation.commit();
        let err = handle_sign(&ctx, request())
            .map(|(response, _)| response)
            .unwrap_err();
        assert!(
            err.to_string().contains("duplicate bridge operation"),
            "{err}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(ctx.state.op_replay_guard.seen_count(), 1);
    }
}

/// A signer with no ready key refuses a burn before any validation work.
#[cfg(all(test, feature = "bfa-validation", rgb_to_evm))]
mod key_not_ready {
    use super::*;
    use crate::cloning::CloneSession;
    use crate::config::BridgeConfig;
    use crate::networks::evm::events::{EvmReceiptProvider, ReceiptData};
    use crate::networks::rgb::validation::{bfa_binding, RgbValidator};
    use crate::proto::enclave_request::Request;
    use crate::proto::enclave_response::Response;
    use crate::state::{CloningSession, EnclaveState};
    use sha3::{Digest, Keccak256};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    /// A signet BFA burn with one mint (see `tests/fixtures`).
    const BURN: &[u8] = include_bytes!("../../tests/fixtures/bfa_burn_consignment.rgbc");

    /// Counts EVM RPC calls. A burn's locks are derived from its mints, not
    /// read from the chain (see `bfa::burn_locks::NoRpc`), so this must stay
    /// at 0 through the whole test.
    struct CountingEvmRpc(Arc<AtomicUsize>);

    impl EvmReceiptProvider for CountingEvmRpc {
        fn get_transaction_receipt(&self, _: &[u8; 32]) -> Result<Option<ReceiptData>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn get_block_number(&self) -> Result<u64> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(0)
        }
    }

    /// Sends the burn. Returns the response, the count of indexer
    /// connections that RGB validation made, and the count of EVM RPC calls.
    fn sign_burn(state: EnclaveState) -> (Response, usize, usize) {
        let binding = bfa_binding(BURN).unwrap().expect("a BFA consignment");
        let mut bridge = [0u8; 20];
        hex::decode_to_slice(
            binding.bridge_location.trim_start_matches("0x"),
            &mut bridge,
        )
        .unwrap();
        let cfg = BridgeConfig {
            funds_in_contract: bridge,
            token_contract: [0x7e; 20],
            chain_id: 42161,
            ..BridgeConfig::default()
        };
        let mut ctx = ServerContext::new(state, cfg, crate::test_support::regtest_header_chain());
        let (url, hits) =
            crate::test_support::electrum_stub::spawn_counted(bitcoin::Network::Signet);
        let rpc_calls = Arc::new(AtomicUsize::new(0));
        let launch = ctx.launch.get_mut().unwrap();
        launch.rgb_validator = Some(RgbValidator::new(url, "signet").unwrap());
        launch.evm_rpc_client = Some(Box::new(CountingEvmRpc(Arc::clone(&rpc_calls))));

        let request = EnclaveRequest {
            request: Some(Request::Sign(SignRequest {
                amount: 100_000,
                source_network: Some(SourceNetwork::RgbSource(RgbSource {
                    consignment: BURN.to_vec(),
                    consignment_hash: Keccak256::digest(BURN).to_vec(),
                    asset_id: "rgb:psO2jKZI-i4fudyA-ORTT8a~-SMaLO6u-69ELk2p-yPRGPJY".into(),
                    ..Default::default()
                })),
                destination_network: Some(DestinationNetwork::EvmDestination(
                    EvmDestination::default(),
                )),
            })),
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let response = super::super::dispatch::dispatch(request, &ctx, deadline)
            .0
            .response
            .unwrap();
        (
            response,
            hits.load(Ordering::SeqCst),
            rpc_calls.load(Ordering::SeqCst),
        )
    }

    #[test]
    fn a_sign_is_refused_before_validation_while_the_key_is_not_ready() {
        let cloning = EnclaveState::default();
        cloning
            .enter_cloning(CloningSession::new(CloneSession::new(), [1; 20]))
            .unwrap();
        for state in [EnclaveState::default(), cloning] {
            let (response, hits, rpc_calls) = sign_burn(state);
            assert_eq!(rpc_calls, 0, "an EVM RPC call ran: {response:?}");
            assert_eq!(hits, 0, "RGB validation ran: {response:?}");
            assert_eq!(
                response,
                Response::Error(ErrorResponse {
                    code: 1,
                    message: EnclaveError::KeyNotInitialized.to_string(),
                })
            );
        }
    }

    /// Control: the same request reaches RGB validation with a ready key.
    #[test]
    fn a_ready_key_lets_the_same_sign_reach_rgb_validation() {
        let state = EnclaveState::default();
        state.initialize_from_seed([7; 64]).unwrap();
        let (response, hits, rpc_calls) = sign_burn(state);
        assert!(hits >= 1, "RGB validation did not run: {response:?}");
        assert_eq!(
            rpc_calls, 0,
            "a burn must not read the EVM chain: {response:?}"
        );
    }
}
