//! Runs RGB consensus over a consignment.
//!
//! This is the only place where raw consignment bytes become a
//! [`super::types::ValidatedConsignment`]. Validation has two phases:
//!
//! 1. `validate_deterministic`: everything that depends on the consignment
//!    only. It leaves open the witnesses and the BFA mint anchors.
//! 2. The anchors resolve only against the locks an [`AnchorBinder`] bound to
//!    them. Each witness takes its tx from the consignment and its on-chain
//!    status from a [`WitnessCheck`]: it must be mined, at
//!    `SPV_MIN_CONFIRMATIONS` depth. Then `finalize`.
//!
//! The enclave never calls `Consignment::validate`, and never confirms an
//! anchor without a bound lock (`PendingValidation::resolve_anchor`).

use std::collections::BTreeSet;
use std::io::Cursor;

use rgbstd::containers::{
    ConsignmentExt, FileContent, PendingConsignment, Transfer, ValidConsignment,
};
use rgbstd::validation::{Status, ValidationConfig, ValidationError};
use rgbstd::vm::WitnessOrd;

use super::bfa::{self, AnchorBinder, BfaBridge, BoundAnchors, MintAnchor};
use super::consignment::{extract_transition_summary, read_last_bundle, LastBundle};
use super::indexer::RgbValidator;
use super::reject_list::{RejectListContract, RejectScope};
use super::schema::{assert_bfa_genesis, reject_list, BFA_RULES};
use super::types::ValidatedConsignment;
use super::witness::{OnChainResolver, WitnessCheck};
use crate::error::{EnclaveError, Result};

impl RgbValidator {
    /// Validates raw consignment bytes and returns the extracted data.
    ///
    /// `bind` binds every mint anchor to a lock. Builds without
    /// `bfa-validation` pass `None`, and then a consignment with any mint in
    /// its history is refused. `witnesses` says which witness txs are mined.
    pub fn validate_consignment(
        &self,
        consignment_bytes: &[u8],
        bind: Option<AnchorBinder<'_>>,
        witnesses: &WitnessCheck<'_>,
    ) -> Result<ValidatedConsignment> {
        #[cfg(test)]
        if let Some(validated) = &self.canned {
            return Ok(validated.clone());
        }
        let start = std::time::Instant::now();
        let bytes_len = consignment_bytes.len();
        tracing::info!(bytes_len, "starting RGB consignment validation");

        // TFR only: a validated copy (VTF), a contract (CON) and V0 fail here.
        let decoded = Transfer::load(Cursor::new(consignment_bytes)).map_err(|e| {
            tracing::warn!(bytes_len, "consignment deserialization failed: {e}");
            EnclaveError::CrossCheck(format!("consignment deserialization failed: {e}"))
        })?;
        // The decoder doubles a list when it grows, so a decoded list can take
        // twice the heap of its items. A clone keeps each list at its length.
        // Phase 1 keeps the consignment until it ends, so the clone lowers the
        // validation peak (`memory.rs`).
        let transfer = decoded.clone();
        drop(decoded);
        assert_bfa_genesis(&transfer.genesis)?;
        assert_terminals_within_limit(&transfer)?;
        let list = reject_list(&transfer.genesis)?;
        let contract_id = transfer.contract_id().to_string();

        let mut pending = self.phase_one(transfer, &contract_id)?;
        let anchors = open_anchors(&mut pending);
        let mint_locks = resolve_mint_anchors(&mut pending, &anchors, bind)?;
        self.resolve_witnesses(&mut pending, &contract_id, witnesses)?;
        let valid = pending.finalize();
        for warning in &valid.validation_status().warnings {
            tracing::warn!(%contract_id, "RGB validation warning: {warning}");
        }

        let non_mined = non_mined_witnesses(valid.validation_status());
        let scope = list.map(|list| reject_scope(list, &valid)).transpose()?;
        let validated = summarize(
            valid,
            consignment_bytes,
            contract_id,
            mint_locks,
            non_mined,
            scope,
        )?;
        tracing::info!(
            contract_id = %validated.contract_id,
            chain_net = %validated.chain_net,
            witness_txids_count = validated.witness_txids.len(),
            mint_anchors = anchors.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "RGB consignment validated successfully"
        );
        Ok(validated)
    }

    /// Builds no opouts DAG: its edges are inputs x outputs per transition.
    fn phase_one(&self, transfer: Transfer, contract_id: &str) -> Result<PendingConsignment<true>> {
        let config = ValidationConfig {
            chain_net: self.chain_net,
            safe_height: None,
            build_opouts_dag: false,
        };
        transfer
            .validate_deterministic(&BFA_RULES, &config)
            .map_err(|e| validation_error(contract_id, e))
    }
}

impl RgbValidator {
    /// Phase 2 for the witnesses: each must be confirmed on chain. Leaves
    /// nothing open: `finalize` panics on that, and the enclave aborts.
    fn resolve_witnesses(
        &self,
        pending: &mut PendingConsignment<true>,
        contract_id: &str,
        witnesses: &WitnessCheck<'_>,
    ) -> Result<()> {
        let resolver = OnChainResolver::new(pending.consignment(), self.chain_net, witnesses);
        pending
            .pending()
            .resolve_all(&resolver)
            .map_err(|e| validation_error(contract_id, e))?;
        if !pending.pending().is_resolved() {
            return Err(EnclaveError::CrossCheck(
                "RGB validation left a witness or mint anchor unresolved - refusing to sign".into(),
            ));
        }
        Ok(())
    }
}

/// Phase 2 for the mint anchors: bind each to a lock, then confirm it
/// against that lock only. Returns the locks.
fn resolve_mint_anchors(
    pending: &mut PendingConsignment<true>,
    anchors: &[MintAnchor],
    bind: Option<AnchorBinder<'_>>,
) -> Result<Vec<bfa::VerifiedLock>> {
    if anchors.is_empty() {
        return Ok(Vec::new());
    }
    let bridge = BfaBridge::from_genesis(pending.consignment().genesis())?;
    let bound = bind_anchors(&bridge, anchors, bind)?;
    bfa::resolve_anchors(pending, &bridge, &bound)?;
    Ok(bound.locks)
}

/// The most outputs that the terminals of a consignment can name. Phase 1
/// keeps an entry of about 130 bytes for each of these outputs. A burn that
/// rgb-lib makes names one seal, the seal of its recipient. Without this
/// limit, a consignment can name one seal that tens of thousands of rights
/// share. Then the entries add about 9 bytes of heap for each byte of
/// consignment (`memory.rs`).
pub(crate) const MAX_TERMINAL_OUTPUTS: usize = 4096;

/// Refuses a consignment whose terminals name more than
/// [`MAX_TERMINAL_OUTPUTS`] outputs, before phase 1. It counts the outputs
/// as phase 1 does: each output of a bundle whose seal is a terminal of that
/// bundle. The count reads each output once.
fn assert_terminals_within_limit(transfer: &Transfer) -> Result<()> {
    let mut named = 0usize;
    for wb in transfer.bundles.iter() {
        let Some(terminals) = transfer.terminals.get(&wb.bundle.bundle_id()) else {
            continue;
        };
        let seals: BTreeSet<_> = terminals.into_iter().collect();
        for known in wb.bundle.known_transitions.iter() {
            for (_, assigns) in known.transition.assignments.iter() {
                named += assigns.seals().filter(|seal| seals.contains(*seal)).count();
            }
        }
        if named > MAX_TERMINAL_OUTPUTS {
            return Err(EnclaveError::CrossCheck(format!(
                "consignment terminals name more than {MAX_TERMINAL_OUTPUTS} outputs - refusing \
                 to validate"
            )));
        }
    }
    Ok(())
}

/// The mint anchors phase 1 left open.
fn open_anchors(pending: &mut PendingConsignment<true>) -> Vec<MintAnchor> {
    let last_bundle: BTreeSet<_> = pending
        .consignment()
        .bundles
        .iter()
        .last()
        .map(|wb| wb.bundle.known_transitions.iter().map(|k| k.opid).collect())
        .unwrap_or_default();
    bfa::mint_anchors(pending.pending().unresolved_anchors(), &last_bundle)
}

/// Asks the binder for the anchors' locks. A build with no binder refuses
/// anchors rather than confirming them blind.
fn bind_anchors(
    bridge: &BfaBridge,
    anchors: &[MintAnchor],
    bind: Option<AnchorBinder<'_>>,
) -> Result<BoundAnchors> {
    let Some(bind) = bind else {
        return Err(EnclaveError::CrossCheck(format!(
            "consignment carries {} BFA mint anchor(s), but this build binds none (built \
             without bfa-validation) - refusing to validate",
            anchors.len()
        )));
    };
    let bound = bind(bridge, anchors)?;
    bfa::check_bijection(anchors, &bound.locks)?;
    Ok(bound)
}

/// Reads what the rest of the enclave binds from the validated consignment.
fn summarize(
    valid: ValidConsignment<true>,
    consignment_bytes: &[u8],
    contract_id: String,
    mint_locks: Vec<bfa::VerifiedLock>,
    non_mined_witness_txids: Vec<[u8; 32]>,
    reject_scope: Option<RejectScope>,
) -> Result<ValidatedConsignment> {
    let transfer: &Transfer = &valid;
    // Display-order bytes, deduplicated and sorted, as the SPV proofs carry them.
    let witness_txids: Vec<[u8; 32]> = transfer
        .bundles
        .iter()
        .map(|wb| {
            let mut bytes = bitcoin::hashes::Hash::to_byte_array(wb.witness_id());
            bytes.reverse();
            bytes
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let last = read_last_bundle(transfer)?;
    let chain_net = transfer.genesis.chain_net.prefix().to_string();
    // The flat parser reads the bytes a second time, and only those consensus
    // accepted. Release the decoded copy first, so the two copies never take
    // memory together (`memory.rs`). The parser decodes every bundle again,
    // but it summarizes only the settling one.
    drop(valid);
    let settling_witness = last.as_ref().map(|l| l.witness_txid);
    let transitions_by_witness = extract_transition_summary(consignment_bytes, settling_witness)?;
    let last_transition = settling_summary(&transitions_by_witness, last.as_ref())?;

    Ok(ValidatedConsignment {
        contract_id,
        chain_net,
        witness_txids,
        last_transition,
        last_witness_txid: last.as_ref().map(|l| l.witness_txid),
        last_transfer_witness_prevouts: last
            .as_ref()
            .map(|l| l.prevouts.clone())
            .unwrap_or_default(),
        last_closed_seals: last
            .as_ref()
            .map(|l| l.closed_seals.clone())
            .unwrap_or_default(),
        last_bundle_fully_disclosed: last.as_ref().is_some_and(|l| l.fully_disclosed),
        last_mint_rights: last
            .as_ref()
            .map(|l| l.settling.mint_rights.clone())
            .unwrap_or_default(),
        last_transfer_op_id: last.as_ref().map(|l| l.settling.opid),
        non_mined_witness_txids,
        transitions_by_witness,
        mint_locks,
        reject_scope,
    })
}

/// The reject-list scope of the settling transition. Built after consensus,
/// and linear in the consignment, so an unpinned asset costs no more.
fn reject_scope(list: RejectListContract, valid: &Transfer) -> Result<RejectScope> {
    let settling = read_last_bundle(valid)?
        .ok_or_else(|| {
            EnclaveError::CrossCheck(
                "consignment has no transition for the reject list to check".into(),
            )
        })?
        .settling;
    let inputs = settling.inputs.into_iter().map(Into::into).collect();
    Ok(RejectScope::new(list, valid, settling.opid, inputs))
}

/// Witnesses consensus did not see mined: at most the mint's own tx.
fn non_mined_witnesses(status: &Status) -> Vec<[u8; 32]> {
    status
        .tx_ord_map
        .iter()
        .filter(|(_, ord)| !matches!(ord, WitnessOrd::Mined(_)))
        .map(|(txid, _)| {
            let mut bytes = bitcoin::hashes::Hash::to_byte_array(*txid);
            bytes.reverse();
            bytes
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The flat summary of the settling transition, with the burn facts of the
/// validated one. The two walks must name the same transition: a mismatch is
/// a parser change or a bug, so no bind may mix the fields of two transitions.
fn settling_summary(
    by_witness: &[(bitcoin::Txid, Vec<super::types::TransitionSummary>)],
    last: Option<&LastBundle>,
) -> Result<Option<super::types::TransitionSummary>> {
    let Some(last) = last else {
        return Ok(None);
    };
    let flat = by_witness
        .last()
        .filter(|(txid, _)| *txid == last.witness_txid)
        .and_then(|(_, summaries)| {
            summaries
                .iter()
                .find(|t| bfa::decode_opid(&t.op_id).is_ok_and(|id| id == last.settling.opid))
        })
        .ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "consignment settling transition 0x{} is missing from the flat parser's last \
                 bundle - refusing to sign",
                hex::encode(last.settling.opid)
            ))
        })?;
    if flat.transition_type != last.settling.transition_type {
        return Err(EnclaveError::CrossCheck(format!(
            "consignment settling transition type {} disagrees with the parsed type {}",
            last.settling.transition_type, flat.transition_type
        )));
    }
    Ok(Some(super::types::TransitionSummary {
        burned_asset_amount: last.settling.burned_asset,
        burn_reason: last.settling.burn_reason,
        ..flat.clone()
    }))
}

/// The `ValidationError` Display drops the failure, so log and keep it.
fn validation_error(contract_id: &str, e: ValidationError) -> EnclaveError {
    let detail = match &e {
        ValidationError::InvalidConsignment(failure) => failure.to_string(),
        ValidationError::ResolverError(resolver) => resolver.to_string(),
        other => other.to_string(),
    };
    tracing::warn!(%contract_id, %detail, "RGB validation failed: {e}");
    EnclaveError::CrossCheck(format!("RGB consignment validation failed: {e}: {detail}"))
}
