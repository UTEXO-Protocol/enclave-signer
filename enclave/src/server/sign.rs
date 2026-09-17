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
use crate::state::ReplayReservation;

/// Sign one bridge request. Returns the response and the replay reservation,
/// un-committed.
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

    // Reject known replays before network I/O without letting invalid requests
    // consume guard capacity. Reserve again immediately before signing.
    #[cfg(not(feature = "dev-mode"))]
    precheck_operation(ctx, source_ref, destination_ref)?;

    // Reject an invalid deposit before RGB validation and fee/indexer I/O.
    // Keep the authorized recipient for comparison with the proven RGB seals.
    let authorized_recipient =
        verify_funds_in_deposit(ctx, req.amount, source_ref, destination_ref)?;

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
        ctx.state
            .with_keys(|keys| Ok(btc_ownership::asset_change_scripts(psbt, keys).contains(&script)))
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

    // Holds every Bitcoin block the SPV checks below use. Each check drops the
    // header-chain lock at return. `assert_chain_pins_unchanged` reads these
    // blocks again just before the key is used (F05-NEW-AF-08).
    #[cfg(feature = "spv")]
    let chain_pins = crate::networks::rgb::spv_crosscheck::ChainPins::new();

    let validation_ctx = ValidationContext {
        bridge_config: &ctx.bridge_config,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: ctx.rgb_validator.as_ref(),
        #[cfg(feature = "spv")]
        header_chain: &ctx.header_chain,
        #[cfg(feature = "spv")]
        chain_pins: &chain_pins,
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

    // The recipient comparison needs the seals proven by RGB validation.
    bind_funds_in_recipient(authorized_recipient, &destination_proof)?;

    // Soft operation-uniqueness guard. The key is reserved before signing and
    // committed only after the response reaches the caller, so neither a
    // transient error nor a lost response self-blocks a retry.
    #[cfg(not(feature = "dev-mode"))]
    let op_reservation = reserve_operation(ctx, source_ref, destination_ref)?;

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
                    #[cfg(feature = "spv")]
                    &chain_pins,
                    #[cfg(feature = "bfa-mint")]
                    &bfa_locks,
                )?;
            }
            handle_sign_evm(
                ctx,
                destination,
                destination_proof.evm_funds_out.as_ref(),
                #[cfg(feature = "spv")]
                &chain_pins,
            )
        }
        DestinationNetwork::RgbDestination(destination) => handle_sign_psbt(
            ctx,
            destination,
            #[cfg(feature = "spv")]
            &chain_pins,
        ),
    };

    #[cfg(feature = "dev-mode")]
    let op_reservation = None;

    // On error the reservation drops here and rolls the key back.
    result.map(|response| (response, op_reservation))
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
    #[cfg(feature = "spv")] pins: &crate::networks::rgb::spv_crosscheck::ChainPins,
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
        crosscheck::verify_btc_relay_agreement(params, validated, merkle_proofs, &chain, pins)?;
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

/// The recipient a verified deposit authorizes. Uninhabited on builds that
/// never verify one, so their `Option` is always `None`.
#[cfg(all(feature = "evm-rpc", not(feature = "dev-mode")))]
use crate::networks::rgb::invoice::AuthorizedRecipient;
#[cfg(not(all(feature = "evm-rpc", not(feature = "dev-mode"))))]
type AuthorizedRecipient = std::convert::Infallible;

/// Prove the EVM `FundsIn` deposit behind an EVM->RGB request, fail-closed.
///
/// Three builds, three behaviours, one name, so `handle_sign` needs no `#[cfg]`
/// for this step:
///
///   * `evm-rpc` (not dev-mode): fetch the receipt through the enclave's own
///     RPC client and return the recipient the deposit's invoice authorizes.
///     Fully trustless only once Helios verifies the RPC.
///   * no `evm-rpc` (not dev-mode): refuse. There is no evidence the deposit
///     occurred - the consignment/PSBT checks prove the transfer shape, not
///     that an EVM deposit backs it. Mirrors the no-`spv` `fundsOut` refusal.
///   * dev-mode: no-op, the legacy path for local testing.
///
/// The result goes to [`bind_funds_in_recipient`] once RGB validation has
/// proven the recipient seals.
#[cfg(all(feature = "evm-rpc", not(feature = "dev-mode")))]
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
    Ok(Some(
        crate::networks::rgb::invoice::parse_authorized_recipient(&verified.destination_address)?,
    ))
}

#[cfg(all(not(feature = "evm-rpc"), not(feature = "dev-mode")))]
fn verify_funds_in_deposit(
    _ctx: &ServerContext,
    _amount: u64,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> Result<Option<AuthorizedRecipient>> {
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

    Ok(None)
}

#[cfg(feature = "dev-mode")]
fn verify_funds_in_deposit(
    _ctx: &ServerContext,
    _amount: u64,
    _source: &SourceNetwork,
    _destination: &DestinationNetwork,
) -> Result<Option<AuthorizedRecipient>> {
    Ok(None)
}

/// Check the recipient seals RGB validation proved against the recipient the
/// verified deposit authorized. A no-op wherever [`verify_funds_in_deposit`]
/// returns no recipient.
#[cfg(all(feature = "evm-rpc", not(feature = "dev-mode")))]
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

#[cfg(not(all(feature = "evm-rpc", not(feature = "dev-mode"))))]
fn bind_funds_in_recipient(
    _authorized: Option<AuthorizedRecipient>,
    _destination_proof: &crate::networks::DestinationProof,
) -> Result<()> {
    Ok(())
}

/// Replay-guard key of an EVM->RGB bridge sign. `None` for every other route.
#[cfg(not(feature = "dev-mode"))]
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

/// Reject a known replay without recording anything, so an invalid request
/// never consumes guard capacity. [`reserve_operation`] still runs before
/// signing to close the concurrent-check race.
#[cfg(not(feature = "dev-mode"))]
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

/// Reserve the operation key for an EVM->RGB bridge sign, rejecting a same-op
/// resubmission inside the TTL window.
///
/// Defense in depth only - the guard is in-memory, per-instance, and volatile;
/// the durable guard is on-chain. The caller commits the reservation once the
/// response reaches the caller, and dropping it un-committed rolls the key
/// back, so neither a transient error nor a lost response consumes it.
#[cfg(not(feature = "dev-mode"))]
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

/// A signature the caller never received must not consume the replay key,
/// so its retry is signed. `bfa-validation` is excluded: it needs EVM lock events.
#[cfg(all(
    test,
    feature = "spv",
    feature = "evm-rpc",
    feature = "rgb-swap",
    not(feature = "bfa-validation"),
    not(feature = "dev-mode")
))]
mod bridge_operation_retry {
    use std::io::{Cursor, Read, Write};

    use sha3::{Digest, Keccak256};

    use crate::config::{BridgeConfig, EvmRpcConfig};
    use crate::error::Result;
    use crate::framing;
    use crate::networks::evm::events::{EvmReceiptProvider, LogEntry, ReceiptData};
    use crate::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
    use crate::networks::rgb::validation::{
        bfa, OutputSeal, RgbValidator, TransitionOutput, TransitionSummary, ValidatedConsignment,
    };
    use crate::policy::{BuildContext, EvmDataSource, SecurityPolicy};
    use crate::proto::enclave_request::Request;
    use crate::proto::enclave_response::Response;
    use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};
    use crate::proto::*;
    use crate::server::{handle_connection, ServerContext, SubmitRateLimiter};
    use crate::state::EnclaveState;

    /// Fixed seed, so every derived key and every txid is the same on each
    /// run.
    const SEED: [u8; 64] = [0x21; 64];
    const ASSET_ID: &str = "rgb:test-asset";
    const BRIDGE_CONTRACT: [u8; 20] = [0xAA; 20];
    const FUNDS_IN_CONTRACT: [u8; 20] = [0xBB; 20];
    const DEPOSIT_TX: [u8; 32] = [0xCC; 32];
    const OPERATION_ID: [u8; 32] = [0x33; 32];
    const DEPOSIT_BLOCK: u64 = 100;
    const GROSS: u64 = 100_000;
    const COMMISSION: u64 = 1_000;
    const NET: u64 = GROSS - COMMISSION;

    /// Canonical `BridgeFundsIn` signature, as the deposit verifier selects
    /// logs by.
    const FUNDS_IN_SIG: &str = "BridgeFundsIn(bytes32,bytes32,address,uint256,uint256,\
         uint256,uint256,uint256,uint256,uint256,string)";

    /// The deposit's invoice and the blinded seal it names.
    const INVOICE: &str =
        "rgb:~/~/~/bc:utxob:dYwB28dy-yD6EBgm-MO~UKN_-FyEEdBL-E9hw8Oj-i9KxH5b-e9vZL";
    const RECIPIENT_SEAL: &str = "utxob:dYwB28dy-yD6EBgm-MO~UKN_-FyEEdBL-E9hw8Oj-i9KxH5b-e9vZL";

    /// NUMS internal key (BIP-341 unspendable key path), as the bridge's
    /// taproot addresses use.
    const NUMS_INTERNAL: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];

    /// A caller that is gone: the request still reads back, every write
    /// fails.
    struct DeadCaller(Cursor<Vec<u8>>);

    impl Read for DeadCaller {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for DeadCaller {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "caller is gone",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Stands in for the EVM RPC: one confirmed `BridgeFundsIn` deposit.
    struct StubDeposit;

    impl EvmReceiptProvider for StubDeposit {
        fn get_transaction_receipt(&self, _tx_hash: &[u8; 32]) -> Result<Option<ReceiptData>> {
            Ok(Some(ReceiptData {
                status_success: true,
                block_number: DEPOSIT_BLOCK,
                logs: vec![LogEntry {
                    address: FUNDS_IN_CONTRACT,
                    topics: vec![
                        Keccak256::digest(FUNDS_IN_SIG.as_bytes()).into(),
                        OPERATION_ID,
                    ],
                    data: funds_in_data(),
                }],
            }))
        }

        fn get_block_number(&self) -> Result<u64> {
            Ok(DEPOSIT_BLOCK + EvmRpcConfig::default().min_confirmations)
        }
    }

    fn word(value: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&value.to_be_bytes());
        w
    }

    /// `BridgeFundsIn` data: senderNonce, amount, netAmount, tokenCommission,
    /// nativeCommission, sourceChainId, destinationChainId, then the
    /// `destinationAddress` head word and its tail. `operationId` is indexed.
    fn funds_in_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&word(0));
        data.extend_from_slice(&word(GROSS));
        data.extend_from_slice(&word(NET));
        data.extend_from_slice(&word(COMMISSION));
        data.extend_from_slice(&[0u8; 32 * 3]);
        data.extend_from_slice(&word(8 * 32));
        data.extend_from_slice(&word(INVOICE.len() as u64));
        let mut tail = INVOICE.as_bytes().to_vec();
        tail.resize(tail.len().div_ceil(32) * 32, 0);
        data.extend_from_slice(&tail);
        data
    }

    fn foreign_xonly(b: u8) -> bitcoin::XOnlyPublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[b; 32]).unwrap();
        bitcoin::XOnlyPublicKey::from_keypair(&bitcoin::secp256k1::Keypair::from_secret_key(
            &secp, &sk,
        ))
        .0
    }

    /// A taproot address the enclave has no key in.
    fn foreign_address() -> bitcoin::ScriptBuf {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        bitcoin::ScriptBuf::new_p2tr(&secp, foreign_xonly(0xB1), None)
    }

    /// The witness transaction of the deposit: one input on the enclave's
    /// colored address `m/86'/827166'/0'/0/0` (a 2-of-3 taproot address, the
    /// federation shape), the recipient's output, and colored change.
    fn deposit_psbt(state: &EnclaveState) -> Vec<u8> {
        use bitcoin::bip32::ChildNumber;
        use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
        use bitcoin::blockdata::script::Builder;
        use bitcoin::hashes::Hash;
        use bitcoin::psbt::Psbt;
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        use std::str::FromStr;

        let keys = state.get_keys().expect("keys");
        let account_xpub =
            bitcoin::bip32::Xpub::from_str(&keys.account_xpub_colored).expect("colored xpub");
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let child = [
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 0 },
        ];
        let ours = account_xpub
            .derive_pub(&secp, &child.to_vec())
            .expect("derive child xpub")
            .to_x_only_pub();

        let mut keyset = [ours, foreign_xonly(0xA1), foreign_xonly(0xA2)];
        keyset.sort();
        let leaf = Builder::new()
            .push_x_only_key(&keyset[0])
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&keyset[1])
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&keyset[2])
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script();
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let internal = bitcoin::XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let spk = ScriptBuf::new_p2tr(&secp, internal, info.merkle_root());
        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        let path = bitcoin::bip32::DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(827166).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            child[0],
            child[1],
        ]);

        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                        [0u8; 32],
                    )),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: foreign_address(),
                },
                TxOut {
                    value: Amount::from_sat(58_000),
                    script_pubkey: spk.clone(),
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(60_000),
            script_pubkey: spk,
        });
        psbt.inputs[0].tap_internal_key = Some(internal);
        psbt.inputs[0]
            .tap_scripts
            .insert(control, (leaf, LeafVersion::TapScript));
        psbt.inputs[0].tap_key_origins.insert(
            ours,
            (
                vec![leaf_hash],
                (
                    bitcoin::bip32::Fingerprint::from(keys.master_fingerprint),
                    path,
                ),
            ),
        );
        psbt.serialize()
    }

    /// One BFA transfer paying the deposit's invoice, anchored to `txid`.
    fn validated_consignment(txid: bitcoin::Txid) -> ValidatedConsignment {
        let transition = TransitionSummary {
            op_id: "11".repeat(32),
            transition_type: bfa::TS_TRANSFER,
            total_output_amount: NET,
            asset_output_amount: NET,
            outputs: vec![TransitionOutput {
                assignment_type: bfa::OS_ASSET,
                amount: NET,
                seal: OutputSeal::Confidential {
                    secret_seal: RECIPIENT_SEAL.into(),
                },
            }],
            burned_asset_amount: None,
            burn_recipient: None,
        };
        ValidatedConsignment {
            contract_id: ASSET_ID.into(),
            chain_net: "bc".into(),
            witness_txids: vec![],
            all_op_ids: vec![transition.op_id.clone()],
            mint_op_ids: vec![],
            last_transition: Some(transition.clone()),
            last_witness_txid: Some(txid),
            last_transfer_witness_prevouts: None,
            last_transfer_op_id: None,
            non_mined_witness_txids: vec![],
            transitions_by_witness: vec![(txid, vec![transition])],
        }
    }

    fn deposit_request(psbt_bytes: Vec<u8>) -> EnclaveRequest {
        let consignment = b"answered by the canned validator".to_vec();
        EnclaveRequest {
            request: Some(Request::Sign(SignRequest {
                amount: GROSS,
                source_network: Some(SourceNetwork::EvmSource(EvmSource {
                    tx_hash: DEPOSIT_TX.to_vec(),
                    event_valid: true,
                    event_finalized: true,
                    token: vec![],
                    recipient: vec![],
                    commission: COMMISSION,
                    funds_in_operation_id: OPERATION_ID.to_vec(),
                })),
                destination_network: Some(DestinationNetwork::RgbDestination(RgbDestination {
                    operation_idx: 0,
                    psbt_bytes,
                    psbt_output_amount: NET,
                    asset_id: ASSET_ID.into(),
                    consignment_hash: Keccak256::digest(&consignment).to_vec(),
                    consignment,
                    mint_ancestors: Vec::new(),
                })),
            })),
        }
    }

    fn framed(request: &EnclaveRequest) -> Vec<u8> {
        let mut bytes = Vec::new();
        framing::write_message(&mut bytes, request).expect("frame request");
        bytes
    }

    /// Handle one request over a connection that stays up, and decode what
    /// the caller received.
    fn respond(ctx: &ServerContext, request: &EnclaveRequest) -> EnclaveResponse {
        let request = framed(request);
        let request_len = request.len();
        let mut caller = Cursor::new(request);
        handle_connection(&mut caller, ctx);
        framing::read_message(&mut &caller.into_inner()[request_len..]).expect("response frame")
    }

    /// The caller never reads the first signature. The retry must be signed,
    /// not refused as a duplicate.
    #[test]
    fn a_retry_is_signed_when_the_first_response_never_reached_the_caller() {
        let bridge_config = BridgeConfig {
            chain_id: 1,
            bridge_contract: BRIDGE_CONTRACT,
            funds_in_contract: FUNDS_IN_CONTRACT,
            rgb_asset_id: ASSET_ID.into(),
            rgb_max_unowned_sats: 5_000,
            ..Default::default()
        };
        let policy = SecurityPolicy::resolve(
            &BuildContext::current(),
            &bridge_config,
            EvmDataSource::Disabled,
            None,
            0,
        );
        let state = EnclaveState::new(bitcoin::Network::Bitcoin);
        state.initialize_from_seed(SEED).expect("initialize keys");

        let psbt_bytes = deposit_psbt(&state);
        let txid = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
            .expect("psbt")
            .unsigned_tx
            .compute_txid();

        let ctx = ServerContext {
            state,
            bridge_config,
            policy,
            rgb_validator: Some(RgbValidator::canned(validated_consignment(txid), 50.0)),
            evm_rpc_client: Some(Box::new(StubDeposit)),
            evm_rpc_config: EvmRpcConfig::default(),
            header_chain: std::sync::Mutex::new(HeaderChain::new(
                Network::Regtest,
                checkpoint_for(Network::Regtest),
            )),
            submit_rate_limiter: std::sync::Mutex::new(SubmitRateLimiter::default()),
        };

        let request = deposit_request(psbt_bytes);
        handle_connection(DeadCaller(Cursor::new(framed(&request))), &ctx);

        match respond(&ctx, &request).response {
            Some(Response::SignedPsbt(r)) => assert_eq!(r.inputs_signed, 1),
            other => panic!(
                "the retry of an undelivered signature must be signed, got {:?}",
                other
            ),
        }
    }
}

/// The early deposit and replay checks run before any RGB work.
#[cfg(all(test, feature = "spv", feature = "evm-rpc", not(feature = "dev-mode")))]
mod early_bridge_checks {
    use super::*;
    use crate::config::BridgeConfig;
    use crate::networks::evm::events::{EvmReceiptProvider, ReceiptData};
    use crate::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
    use crate::state::EnclaveState;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
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
            Mutex::new(HeaderChain::new(
                Network::Regtest,
                checkpoint_for(Network::Regtest),
            )),
        );
        ctx.evm_rpc_client = Some(Box::new(MissingDeposit(Arc::clone(calls))));
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
            // Deliberately invalid RGB data: the early checks must reject
            // before consignment decoding, including BFA ancestry parsing.
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
