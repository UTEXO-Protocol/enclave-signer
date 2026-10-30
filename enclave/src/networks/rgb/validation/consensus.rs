//! Runs RGB consensus over a consignment: one call of rgb-lib's
//! `validate_consignment_with_resolver`.
//!
//! This is the only place where raw consignment bytes become a
//! [`super::types::ValidatedConsignment`]. rgb-lib runs both phases and the
//! reject-list check, and asks three resolvers for what is outside the file:
//!
//! - each witness takes its tx from the consignment and its on-chain status
//!   from a [`WitnessCheck`]: it must be mined, at `SPV_MIN_CONFIRMATIONS`
//!   depth from the enclave's tip;
//! - each BFA mint anchor is confirmed only against the lock an
//!   [`AnchorBinder`] binds to it, with no RPC;
//! - the reject list comes from the enclave's reader, after the asset bind.
//!
//! rgb-lib returns no amounts or burn facts, so the summary is read from the
//! same bytes once they pass.

use std::collections::BTreeSet;
use std::io::Cursor;

use rgb_lib::no_wallet::{
    validate_consignment_with_resolver, ConsignmentValidation, ResolveRejectList,
    ValidationOptions, WitnessValidationStatus,
};
use rgb_lib::BitcoinNetwork;
use rgbstd::containers::{ConsignmentExt, FileContent, ResolveAnchor, Transfer};

use super::bfa::{self, AnchorBinder, BindingResolver};
use super::consignment::{extract_transition_summary, read_last_bundle, LastBundle};
use super::cost::assert_bounded_for_rgb_lib;
use super::indexer::RgbValidator;
use super::reject_list::{ListAccess, ListResolver, RejectListContract};
use super::schema::{assert_bfa_genesis, reject_list};
use super::scratch::with_scratch_file;
use super::types::ValidatedConsignment;
use super::witness::{OnChainResolver, WitnessCheck};
use crate::error::{EnclaveError, Result};

impl RgbValidator {
    /// Validates raw consignment bytes and returns the extracted data.
    ///
    /// `bind` binds every mint anchor to a lock. Builds without
    /// `bfa-validation` pass `None`, and then a consignment with any mint in
    /// its history is refused. `witnesses` says which witness txs are mined.
    /// `lists` binds the asset before rgb-lib runs, and reads its reject list.
    pub fn validate_consignment(
        &self,
        consignment_bytes: &[u8],
        bind: Option<AnchorBinder<'_>>,
        witnesses: &WitnessCheck<'_>,
        lists: &ListAccess<'_>,
    ) -> Result<ValidatedConsignment> {
        #[cfg(test)]
        if let Some(validated) = &self.canned {
            return Ok(validated.clone());
        }
        let start = std::time::Instant::now();
        tracing::info!(
            bytes_len = consignment_bytes.len(),
            "starting RGB consignment validation"
        );

        let (transfer, list) = load_bounded(consignment_bytes, lists)?;
        let resolvers = Resolvers {
            witnesses: OnChainResolver::new(&transfer, self.chain_net, witnesses),
            anchors: bind.map(|bind| BindingResolver::new(&transfer, bind)),
            list: list
                .zip(lists.read)
                .map(|(l, read)| ListResolver::new(l, read)),
        };
        let validation = self.run_rgb_lib(consignment_bytes, &resolvers, list.as_ref())?;
        check_validation(&validation, &transfer)?;
        let mint_locks = match resolvers.anchors {
            Some(anchors) => anchors.into_locks()?,
            None => Vec::new(),
        };

        let mint_anchors = mint_locks.len();
        let non_mined = non_mined_witnesses(&validation)?;
        let validated = summarize(&transfer, consignment_bytes, mint_locks, non_mined)?;
        tracing::info!(
            contract_id = %validated.contract_id,
            chain_net = %validated.chain_net,
            witness_txids_count = validated.witness_txids.len(),
            mint_anchors,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "RGB consignment validated successfully"
        );
        Ok(validated)
    }

    /// rgb-lib reads only a file. No `safe_height`: the witness resolver
    /// already marks a witness mined only at the required depth.
    fn run_rgb_lib(
        &self,
        consignment_bytes: &[u8],
        resolvers: &Resolvers<'_>,
        list: Option<&RejectListContract>,
    ) -> Result<ConsignmentValidation> {
        let options = ValidationOptions {
            bitcoin_network: BitcoinNetwork::try_from(self.chain_net).map_err(|e| {
                EnclaveError::CrossCheck(format!("unsupported RGB chain {}: {e}", self.chain_net))
            })?,
            offchain_txid: None,
        };
        with_scratch_file(consignment_bytes, |path| {
            let path = path.to_str().ok_or_else(|| {
                EnclaveError::Internal(format!("scratch path {} is not UTF-8", path.display()))
            })?;
            let validation = validate_consignment_with_resolver(
                path,
                &resolvers.witnesses,
                resolvers.anchors.as_ref().map(|a| a as &dyn ResolveAnchor),
                resolvers.list.as_ref().map(|l| l as &dyn ResolveRejectList),
                None,
                &options,
            );
            resolver_failure_first(validation, resolvers.take_failure(), list)
        })
    }
}

/// A resolver's own failure refuses, even if rgb-lib went on past it.
pub(super) fn resolver_failure_first<T>(
    validation: std::result::Result<T, rgb_lib::Error>,
    failure: Option<EnclaveError>,
    list: Option<&RejectListContract>,
) -> Result<T> {
    match (validation, failure) {
        (_, Some(failure)) => Err(failure),
        (Ok(validation), None) => Ok(validation),
        (Err(e), None) => Err(validation_error(e, list)),
    }
}

/// Parses the transfer and runs every check that needs no resolver, so a
/// foreign or oversized history never reaches rgb-lib. Returns its list.
fn load_bounded(
    bytes: &[u8],
    lists: &ListAccess<'_>,
) -> Result<(Transfer, Option<RejectListContract>)> {
    // TFR only: a validated copy (VTF), a contract (CON) and V0 fail here.
    let transfer = Transfer::load(Cursor::new(bytes)).map_err(|e| {
        tracing::warn!(
            bytes_len = bytes.len(),
            "consignment deserialization failed: {e}"
        );
        EnclaveError::CrossCheck(format!("consignment deserialization failed: {e}"))
    })?;
    assert_bfa_genesis(&transfer.genesis)?;
    (lists.bind_asset)(&transfer.contract_id().to_string())?;
    let list = reject_list(&transfer.genesis)?;
    assert_bounded_for_rgb_lib(&transfer, bytes.len(), list.is_some())?;
    Ok((transfer, list))
}

/// The three resolvers rgb-lib asks, over one parsed transfer.
struct Resolvers<'a> {
    witnesses: OnChainResolver<'a>,
    anchors: Option<BindingResolver<'a>>,
    list: Option<ListResolver<'a>>,
}

impl Resolvers<'_> {
    /// Our own error behind an rgb-lib one, so the refusal says what failed.
    fn take_failure(&self) -> Option<EnclaveError> {
        let list = self.list.as_ref().and_then(ListResolver::take_failure);
        list.or_else(|| {
            self.anchors
                .as_ref()
                .and_then(BindingResolver::take_failure)
        })
    }
}

/// rgb-lib validated the transfer we parsed, and warned about nothing.
pub(super) fn check_validation(
    validation: &ConsignmentValidation,
    transfer: &Transfer,
) -> Result<()> {
    let ours = transfer.consignment_id().to_string();
    if !validation.is_transfer || validation.consignment_id != ours {
        return Err(EnclaveError::CrossCheck(format!(
            "rgb-lib validated consignment {} (transfer: {}), not the transfer {ours} - refusing \
             to sign",
            validation.consignment_id, validation.is_transfer
        )));
    }
    // Neither rgb-lib warning can arise with no headers and no safe_height:
    // one that does means the setup changed, so it refuses.
    if let Some(warning) = validation.warnings.first() {
        return Err(EnclaveError::CrossCheck(format!(
            "rgb-lib validated the consignment with the warning {warning:?} - refusing to sign"
        )));
    }
    Ok(())
}

/// Reads what the rest of the enclave binds from the validated consignment.
fn summarize(
    transfer: &Transfer,
    consignment_bytes: &[u8],
    mint_locks: Vec<bfa::VerifiedLock>,
    non_mined_witness_txids: Vec<[u8; 32]>,
) -> Result<ValidatedConsignment> {
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

    // The flat parser runs only on bytes consensus accepted.
    let transitions_by_witness = extract_transition_summary(consignment_bytes)?;
    let last = read_last_bundle(transfer)?;
    let last_transition = settling_summary(&transitions_by_witness, last.as_ref())?;

    Ok(ValidatedConsignment {
        contract_id: transfer.contract_id().to_string(),
        chain_net: transfer.genesis.chain_net.prefix().to_string(),
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
    })
}

/// Witnesses rgb-lib did not see mined, in display order: at most the one the
/// swap flow signs.
fn non_mined_witnesses(validation: &ConsignmentValidation) -> Result<Vec<[u8; 32]>> {
    let mut txids = BTreeSet::new();
    for witness in &validation.witnesses {
        if matches!(witness.status, WitnessValidationStatus::Mined { .. }) {
            continue;
        }
        let txid: [u8; 32] = hex::decode(&witness.txid)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "rgb-lib reported a witness txid {:?} that is not 32-byte hex",
                    witness.txid
                ))
            })?;
        txids.insert(txid);
    }
    Ok(txids.into_iter().collect())
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

/// rgb-lib's refusal, with what it means for this enclave.
pub(super) fn validation_error(
    e: rgb_lib::Error,
    list: Option<&RejectListContract>,
) -> EnclaveError {
    use rgb_lib::Error as E;
    let text = match &e {
        E::NoAnchorResolver => "consignment carries BFA mint anchors, but this build binds none \
                                (built without bfa-validation) - refusing to validate"
            .to_string(),
        E::NoRejectListResolver => "the asset declares a reject list, but this build cannot read \
                                    it - refusing to sign"
            .to_string(),
        // The bridge gateway answers 422 on "descends from an opout the reject list".
        // One origin only: a wide burn can reject thousands.
        E::ConsignmentRejected { opouts } => format!(
            "RGB consignment validation failed: Consignment rejected by the reject list, {} \
             rejected opouts, the first {} - reject list: an opout this consignment proves \
             descends from an opout the reject list{} rejects - refusing to sign",
            opouts.len(),
            opouts.first().map_or("none", String::as_str),
            list.map(|l| format!(" 0x{} on chain {}", hex::encode(l.address), l.chain_id))
                .unwrap_or_default()
        ),
        E::EvmChainIdMismatch { expected, actual } => format!(
            "RGB consignment validation failed: the mint anchors were bound on EVM chain \
             {actual}, but the asset's bridge lives on chain {expected} - refusing to validate"
        ),
        E::MintEventNotFound { opid } => format!(
            "RGB consignment validation failed: mint {opid} has no bound lock that confirms it - \
             refusing to validate"
        ),
        E::MintEventExpired { opid, before_block } => format!(
            "RGB consignment validation failed: the lock of mint {opid} was not included before \
             EVM block {before_block}, so the mint is never backed - refusing to validate"
        ),
        E::InvalidBeforeBlock { details } => format!(
            "RGB consignment validation failed: a mint's beforeBlock leaves no block for its \
             lock ({details}) - refusing to validate"
        ),
        E::Network { details } => format!(
            "RGB consignment validation failed: a witness is not proven on chain: {details}"
        ),
        e => format!("RGB consignment validation failed: {e}"),
    };
    tracing::warn!("RGB validation failed: {text}");
    EnclaveError::CrossCheck(text)
}
