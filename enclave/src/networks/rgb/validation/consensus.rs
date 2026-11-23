//! Validates consignments through rgb-lib's `validate_consignment_with_resolver`.
//!
//! This is the only code that turns a consignment file into a
//! [`super::types::ValidatedConsignment`]. The burn signer runs it in a
//! validator child (`child.rs`) and rebuilds the result from the child's
//! verdict (`runner.rs`). It decodes the file, binds the asset and checks work
//! limits before using these resolvers:
//!
//! - `HeadersOnlyResolver` feeds the SPV-verified witness positions.
//! - [`AnchorBinder`] binds each mint claim to its lock, without RPC.
//! - The enclave's reader supplies the asset's reject list.
//!
//! Every validation warning rejects the consignment. The burn summary is read
//! from the same file only after validation succeeds.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::BufReader;
use std::num::NonZeroU32;
use std::path::Path;

use rgb_lib::no_wallet::{
    validate_consignment_with_resolver, ConsignmentValidation, ResolveRejectList,
    ValidationOptions, WitnessValidationStatus,
};
use rgb_lib::BitcoinNetwork;
use rgb_lib::{ConsignmentExt, FileContent, ResolveClaim, RgbTransfer as Transfer};

#[cfg(test)]
use super::super::scratch::with_scratch_file;
use super::bfa::{self, AnchorBinder, BindingResolver};
use super::consignment::extract_transition_summary;
use super::cost::assert_bounded_for_rgb_lib;
use super::reject_list::{ListAccess, ListResolver, RejectListContract};
use super::schema::reject_list;
use super::types::WitnessBlock;
use super::types::{TransitionSummary, ValidatedConsignment};
use super::validator::RgbValidator;
use super::witness::{BuriedHeaders, HeadersOnlyResolver};
use rgb_lib::TypeOfTransition;

use crate::error::{EnclaveError, Result};

impl RgbValidator {
    /// Validates the consignment in the file at `path` and returns the
    /// extracted data.
    ///
    /// `bind` is required for histories containing mints. `headers` is the
    /// enclave chain the consignment's SPV proofs are checked against; `lists`
    /// binds the asset and supplies its reject list.
    // Only the validator child of the burn signer calls it.
    #[cfg_attr(not(all(rgb_to_evm, unix)), allow(dead_code))]
    pub(super) fn validate_consignment_file(
        &self,
        path: &Path,
        bind: Option<AnchorBinder<'_>>,
        headers: &dyn BuriedHeaders,
        lists: &ListAccess<'_>,
    ) -> Result<ValidatedConsignment> {
        let start = std::time::Instant::now();
        let (transfer, list, bytes_len) = load_bounded(path, lists)?;
        let resolvers = Resolvers {
            witnesses: HeadersOnlyResolver::new(self.chain_net, headers),
            anchors: bind.map(BindingResolver::new),
            list: list
                .zip(lists.read)
                .map(|(l, read)| ListResolver::new(l, read)),
        };
        let path = path.to_str().ok_or_else(|| {
            EnclaveError::Internal(format!("scratch path {} is not UTF-8", path.display()))
        })?;
        let (validation, transitions_by_witness) = self.run_rgb_lib(
            path,
            &resolvers,
            list.as_ref(),
            &transfer,
            headers.safe_height(),
        )?;
        let witness_blocks = witness_blocks(&validation, &resolvers.witnesses)?;
        let mint_locks = match resolvers.anchors {
            Some(anchors) => anchors.into_locks()?,
            None => Vec::new(),
        };

        let mint_anchors = mint_locks.len();
        let validated = summarize(
            &transfer,
            transitions_by_witness,
            mint_locks,
            witness_blocks,
        )?;
        tracing::info!(
            contract_id = %validated.contract_id,
            chain_net = %validated.chain_net,
            bytes_len,
            witness_txids_count = validated.witness_txids.len(),
            mint_anchors,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "RGB consignment validated successfully"
        );
        Ok(validated)
    }

    /// [`Self::validate_consignment_file`] of `bytes`, through a scratch file.
    #[cfg(test)]
    pub fn validate_consignment(
        &self,
        bytes: &[u8],
        bind: Option<AnchorBinder<'_>>,
        headers: &dyn BuriedHeaders,
        lists: &ListAccess<'_>,
    ) -> Result<ValidatedConsignment> {
        with_scratch_file("consignment", bytes, |path| {
            self.validate_consignment_file(path, bind, headers, lists)
        })
    }

    /// Validates the file before inspecting it. A witness above `safe_height`
    /// is a warning, and every warning refuses.
    fn run_rgb_lib(
        &self,
        path: &str,
        resolvers: &Resolvers<'_>,
        list: Option<&RejectListContract>,
        transfer: &Transfer,
        safe_height: Option<NonZeroU32>,
    ) -> Result<(ConsignmentValidation, Summary)> {
        let options = ValidationOptions {
            bitcoin_network: BitcoinNetwork::try_from(self.chain_net).map_err(|e| {
                EnclaveError::CrossCheck(format!("unsupported RGB chain {}: {e}", self.chain_net))
            })?,
            offchain_txid: None,
        };
        let validation = validate_consignment_with_resolver(
            path,
            &resolvers.witnesses,
            resolvers.anchors.as_ref().map(|a| a as &dyn ResolveClaim),
            resolvers.list.as_ref().map(|l| l as &dyn ResolveRejectList),
            safe_height,
            &options,
        );
        let validation = resolver_failure_first(validation, resolvers.take_failure(), list)?;
        check_validation(&validation, transfer)?;
        // Only what validation passed; the gate counted the inspection too.
        Ok((validation, extract_transition_summary(path)?))
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

/// Parses the transfer in the file at `path` and runs every check that needs
/// no resolver, so a foreign or oversized history never reaches rgb-lib.
/// Returns its list and the length of the file.
fn load_bounded(
    path: &Path,
    lists: &ListAccess<'_>,
) -> Result<(Transfer, Option<RejectListContract>, usize)> {
    let file = File::open(path).map_err(|e| file_error(path, e))?;
    // Saturates where a length has no `usize`: the gate then refuses it.
    let bytes_len = file.metadata().map_err(|e| file_error(path, e))?.len();
    let bytes_len = usize::try_from(bytes_len).unwrap_or(usize::MAX);
    tracing::info!(bytes_len, "starting RGB consignment validation");
    // TFR only: a validated copy (VTF), a contract (CON) and V0 fail here.
    let decoded = Transfer::load(BufReader::new(file)).map_err(|e| {
        tracing::warn!(bytes_len, "consignment deserialization failed: {e}");
        EnclaveError::CrossCheck(format!("consignment deserialization failed: {e}"))
    })?;
    // The decoder doubles a list when it grows, so a decoded list can take
    // twice the heap of its items. A clone keeps each list at its length.
    // This copy stays alive while rgb-lib validates, so the clone lowers the
    // validation peak (`memory.rs`).
    let transfer = decoded.clone();
    drop(decoded);
    // The asset pin runs before the reject-list location is read, because the
    // enclave reaches that address over the network: a foreign genesis must
    // not choose it. The pin admits one contract id, hence one genesis, hence
    // one schema. Refusing here also spares rgb-lib the work.
    (lists.bind_asset)(&transfer.contract_id().to_string())?;
    let list = reject_list(&transfer.genesis)?;
    assert_bounded_for_rgb_lib(&transfer, bytes_len, list.is_some())?;
    Ok((transfer, list, bytes_len))
}

/// An enclave fault: the enclave wrote the file it reads.
fn file_error(path: &Path, e: std::io::Error) -> EnclaveError {
    EnclaveError::Internal(format!(
        "could not read the consignment file {}: {e}",
        path.display()
    ))
}

/// The three resolvers rgb-lib asks, over one parsed transfer.
struct Resolvers<'a> {
    witnesses: HeadersOnlyResolver<'a>,
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
        .or_else(|| self.witnesses.take_failure())
    }
}

/// Every transition, grouped by the witness tx that commits it.
type Summary = Vec<(bitcoin::Txid, Vec<TransitionSummary>)>;

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
    // Every warning refuses.
    match validation.warnings.first() {
        None => Ok(()),
        Some(warning) => Err(EnclaveError::CrossCheck(format!(
            "rgb-lib validated the consignment with the warning {warning:?} - refusing to sign"
        ))),
    }
}

/// Reads what the rest of the enclave binds from the validated consignment.
fn summarize(
    transfer: &Transfer,
    transitions_by_witness: Summary,
    mint_locks: Vec<bfa::VerifiedLock>,
    witness_blocks: Vec<WitnessBlock>,
) -> Result<ValidatedConsignment> {
    // Display-order bytes, deduplicated and sorted.
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

    // Every witness is placed in a block: the chain checks read these.
    let placed: Vec<[u8; 32]> = witness_blocks.iter().map(|block| block.txid).collect();
    if placed != witness_txids {
        return Err(EnclaveError::CrossCheck(format!(
            "rgb-lib placed {} witness tx(s) in a block, the consignment has {} - refusing to sign",
            placed.len(),
            witness_txids.len()
        )));
    }

    let settling = settling_summary(&transitions_by_witness)?;
    let settling_op_id = settling
        .as_ref()
        .map(|(_, t)| bfa::decode_opid(&t.op_id))
        .transpose()?;
    let (settling_witness_txid, settling_transition) = match settling {
        Some((txid, transition)) => (Some(txid), Some(transition)),
        None => (None, None),
    };

    Ok(ValidatedConsignment {
        contract_id: transfer.contract_id().to_string(),
        chain_net: transfer.genesis.chain_net.prefix().to_string(),
        witness_txids,
        settling_witness_txid,
        settling_transition,
        settling_op_id,
        witness_blocks,
        transitions_by_witness,
        mint_locks,
    })
}

/// The block of every witness, sorted by display-order txid. A witness rgb-lib
/// did not see mined, or mined where no header was served, refuses.
fn witness_blocks(
    validation: &ConsignmentValidation,
    resolver: &HeadersOnlyResolver<'_>,
) -> Result<Vec<WitnessBlock>> {
    let mut blocks = BTreeMap::new();
    for witness in &validation.witnesses {
        let WitnessValidationStatus::Mined { height, .. } = witness.status else {
            return Err(EnclaveError::CrossCheck(format!(
                "rgb-lib validated witness tx {} as {:?}, not mined - refusing to sign",
                witness.txid, witness.status
            )));
        };
        let txid: [u8; 32] = hex::decode(&witness.txid)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "rgb-lib reported a witness txid {:?} that is not 32-byte hex",
                    witness.txid
                ))
            })?;
        let hash = resolver.served_hash(height).ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "rgb-lib placed witness tx {} at height {height}, where the enclave served no \
                 header - refusing to sign",
                witness.txid
            ))
        })?;
        blocks.insert(txid, WitnessBlock { txid, height, hash });
    }
    Ok(blocks.into_values().collect())
}

/// The settling transition and the witness tx that anchors it: the one burn of
/// the inspected bundles.
///
/// The inspection reads the terminal bundles, and a burn is always terminal, so
/// a burn anywhere in the consignment is here. Two of them are refused, since
/// only one could ever be released, and the file order of their bundles must
/// not decide which. Without a burn this settles on the last transition read,
/// which every caller of the result refuses: the flow check states that a
/// release needs a burn.
pub(super) fn settling_summary(
    by_witness: &[(bitcoin::Txid, Vec<TransitionSummary>)],
) -> Result<Option<(bitcoin::Txid, TransitionSummary)>> {
    let read = || {
        by_witness
            .iter()
            .flat_map(|(txid, summaries)| summaries.iter().map(move |t| (*txid, t)))
    };
    let mut burns = read().filter(|(_, t)| t.transition_type == TypeOfTransition::Burn);
    let first = burns.next();
    let count = 1 + burns.count();
    match first {
        Some(burn) if count > 1 => Err(EnclaveError::CrossCheck(format!(
            "the terminal operations carry {count} burns - a release settles exactly one, and \
             {} is one of them",
            burn.1.op_id
        ))),
        Some((txid, burn)) => Ok(Some((txid, burn.clone()))),
        None => Ok(read().last().map(|(txid, t)| (txid, t.clone()))),
    }
}

/// rgb-lib's refusal, with what it means for this enclave.
pub(super) fn validation_error(
    e: rgb_lib::Error,
    list: Option<&RejectListContract>,
) -> EnclaveError {
    use rgb_lib::Error as E;
    let text = match &e {
        E::NoClaimResolver => "consignment carries BFA mint claims, but no lock binder is set - \
                                refusing to validate"
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
        E::MintLockNotFound { opid } => format!(
            "RGB consignment validation failed: mint {opid} has no bound lock that confirms it - \
             refusing to validate"
        ),
        E::Network { details } => format!(
            "RGB consignment validation failed: a witness is not proven on chain: {details}"
        ),
        e => format!("RGB consignment validation failed: {e}"),
    };
    tracing::warn!("RGB validation failed: {text}");
    EnclaveError::CrossCheck(text)
}
