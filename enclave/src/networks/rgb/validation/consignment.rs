//! Decodes a validated rgbstd `Transfer`.
//!
//! Decode only. Nothing here accepts or rejects a consignment. It converts
//! rgbstd and rgb-lib inspection output into the shapes in [`super::types`]. It fails
//! closed on data that it cannot read exactly.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use amplify::{ByteArray, Wrapper};
use bitcoin::hashes::Hash;
use rgb_lib::no_wallet::{
    inspect_consignment, BundleFilter, ConsignmentInspection, RgbOutputInfo, RgbTransitionInfo,
};
use rgb_lib::{Assignment, TypeOfTransition};
use rgbstd::containers::{Transfer, WitnessBundle};
use rgbstd::{
    Assign, Assignments, GraphSeal, KnownTransition, OpId, Operation, Opout, TransitionType,
};

use super::transition::{output_seal, single_global};
use super::types::{OutputSeal, TransitionOutput, TransitionSummary};
use crate::error::{EnclaveError, Result};

/// Index of the transition a witness settles: its last `TS_BURN`, or its last
/// transition when it burns nothing. One tx can carry a burn and a plain transfer.
pub(super) fn settling_index<T>(transitions: &[T], is_burn: impl Fn(&T) -> bool) -> Option<usize> {
    transitions
        .iter()
        .rposition(is_burn)
        .or(transitions.len().checked_sub(1))
}

/// Returns true for a mint transition, which maps 1:1 to an EVM lock record.
/// In BFA, only `TS_MINT` creates units.
pub fn is_mint_transition(transition_type: u16) -> bool {
    TransitionType::with(transition_type) == schemata::TS_MINT
}

/// What the enclave binds about the last bundle, read from the validated
/// rgbstd `Transfer`, not from the flat parser.
pub(super) struct LastBundle {
    pub witness_txid: bitcoin::Txid,
    pub prevouts: Vec<bitcoin::OutPoint>,
    pub closed_seals: Vec<bitcoin::OutPoint>,
    pub fully_disclosed: bool,
    pub settling: SettlingFacts,
}

/// The settling transition of the last bundle, as consensus validated it.
pub(super) struct SettlingFacts {
    pub opid: [u8; 32],
    pub transition_type: u16,
    pub burned_asset: Option<u64>,
    pub burn_reason: Option<[u8; 32]>,
    pub mint_rights: Vec<OutputSeal>,
    pub inputs: Vec<Opout>,
}

/// Reads the last bundle. `None` for a transfer with no bundles.
pub(super) fn read_last_bundle(transfer: &Transfer) -> Result<Option<LastBundle>> {
    let Some(last) = transfer.bundles.iter().last() else {
        return Ok(None);
    };
    let known = &last.bundle.known_transitions;
    let Some(settling) = settling_known_transition(known)? else {
        return Ok(None);
    };
    Ok(Some(LastBundle {
        witness_txid: last.witness_id(),
        prevouts: last.tx.input.iter().map(|i| i.previous_output).collect(),
        closed_seals: closed_seals(transfer, last)?,
        fully_disclosed: fully_disclosed(last),
        settling: settling_facts(settling)?,
    }))
}

/// The settling known transition, by [`settling_index`]. Two burns in one
/// bundle are refused: only one of them could ever be released.
fn settling_known_transition(known: &[KnownTransition]) -> Result<Option<&KnownTransition>> {
    let is_burn = |k: &KnownTransition| k.transition.transition_type == schemata::TS_BURN;
    let burns = known.iter().filter(|k| is_burn(k)).count();
    if burns > 1 {
        return Err(EnclaveError::CrossCheck(format!(
            "the last bundle carries {burns} burns - a release settles exactly one"
        )));
    }
    Ok(settling_index(known, is_burn).map(|i| &known[i]))
}

fn settling_facts(known: &KnownTransition) -> Result<SettlingFacts> {
    let transition = &known.transition;
    let globals = &transition.globals;
    let burned_asset = single_global::<8>(globals, schemata::GS_BURNED_ASSET, "burnedAsset")?
        .map(u64::from_le_bytes);
    let burn_reason = single_global::<32>(globals, schemata::GS_BURN_REASON, "burnReason")?;
    let mint_rights = transition
        .assignments
        .get(&schemata::OS_MINT)
        .map(|typed| typed.seals().map(output_seal).collect())
        .unwrap_or_default();
    Ok(SettlingFacts {
        opid: known.opid.to_byte_array(),
        transition_type: transition.transition_type.to_inner(),
        burned_asset,
        burn_reason,
        mint_rights,
        inputs: transition.inputs.iter().copied().collect(),
    })
}

/// Every transition the bundle commits to is in the consignment.
fn fully_disclosed(bundle: &WitnessBundle) -> bool {
    let committed: BTreeSet<OpId> = bundle.bundle.input_map.values().copied().collect();
    let known: BTreeSet<OpId> = bundle
        .bundle
        .known_transitions
        .iter()
        .map(|k| k.opid)
        .collect();
    committed == known
}

/// The outpoints of the seals the bundle's known transitions close.
/// Consensus proved each one is spent by the bundle's witness tx.
fn closed_seals(transfer: &Transfer, bundle: &WitnessBundle) -> Result<Vec<bitcoin::OutPoint>> {
    bundle
        .bundle
        .known_transitions
        .iter()
        .flat_map(|k| k.transition.inputs.iter())
        .map(|&input| {
            seal_outpoint(transfer, input).ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "input {input} has no revealed seal in the consignment"
                ))
            })
        })
        .collect()
}

/// The outpoint of the seal `input` spends, from the operation that made it.
fn seal_outpoint(transfer: &Transfer, input: Opout) -> Option<bitcoin::OutPoint> {
    let genesis = &transfer.genesis;
    if input.op == genesis.id() {
        return revealed_seal(&genesis.assignments.transmutate_seals(), input, None);
    }
    let (known, witness_id) = transfer.bundles.iter().find_map(|wb| {
        wb.bundle
            .known_transitions
            .iter()
            .find(|k| k.opid == input.op)
            .map(|k| (k, wb.witness_id()))
    })?;
    revealed_seal(&known.transition.assignments, input, Some(witness_id))
}

fn revealed_seal(
    assignments: &Assignments<GraphSeal>,
    input: Opout,
    witness_id: Option<bitcoin::Txid>,
) -> Option<bitcoin::OutPoint> {
    let (seal, _) = assignments
        .get(&input.ty)?
        .to_revealed_assign_at(input.no, witness_id)
        .ok()
        .and_then(Assign::into_revealed)?;
    Some(seal.to_outpoint())
}

/// The flat transition summary of a consignment that consensus validated:
/// all transitions grouped by witness tx. rgb-lib's wallet-free inspection
/// reads it, mapped to our `TransitionSummary`.
pub(super) fn extract_transition_summary(
    consignment_bytes: &[u8],
) -> Result<Vec<(bitcoin::Txid, Vec<TransitionSummary>)>> {
    summary_from_inspection(&inspect(consignment_bytes)?)
}

/// Runs `inspect_consignment` over `bytes`. It reads only a file, so the bytes
/// go through a scratch file that is always removed. A panic inside rgb-lib
/// aborts the enclave (`panic = "abort"`), as one anywhere else does.
fn inspect(bytes: &[u8]) -> Result<ConsignmentInspection> {
    inspect_at(&scratch_path(), bytes)
}

/// [`inspect`] through a new file at `path`. An existing file is refused, not
/// overwritten or removed.
pub(super) fn inspect_at(path: &Path, bytes: &[u8]) -> Result<ConsignmentInspection> {
    let file = File::create_new(path).map_err(|e| scratch_error("create", path, e))?;
    let inspected = inspect_file(file, path, bytes);
    match (inspected, std::fs::remove_file(path)) {
        (inspected, Ok(())) => inspected,
        (Ok(_), Err(e)) => Err(scratch_error("remove", path, e)),
        (Err(err), Err(e)) => {
            tracing::warn!(path = %path.display(), "could not remove the consignment scratch file: {e}");
            Err(err)
        }
    }
}

fn inspect_file(mut file: File, path: &Path, bytes: &[u8]) -> Result<ConsignmentInspection> {
    file.write_all(bytes)
        .map_err(|e| scratch_error("write", path, e))?;
    drop(file);
    inspect_consignment(path.to_string_lossy().into_owned(), BundleFilter::All).map_err(|e| {
        EnclaveError::CrossCheck(format!("rgb-lib consignment inspection failed: {e}"))
    })
}

fn scratch_error(action: &str, path: &Path, e: std::io::Error) -> EnclaveError {
    EnclaveError::CrossCheck(format!(
        "could not {action} the consignment scratch file {}: {e}",
        path.display()
    ))
}

/// A file name no other request of this or another enclave process uses.
fn scratch_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "utexo-enclave-consignment-{}-{n}.rgb",
        std::process::id()
    ))
}

pub(super) fn summary_from_inspection(
    inspection: &ConsignmentInspection,
) -> Result<Vec<(bitcoin::Txid, Vec<TransitionSummary>)>> {
    if !inspection.is_transfer {
        return Err(EnclaveError::CrossCheck(
            "consignment is a Contract, expected Transfer".into(),
        ));
    }
    let chain_net = &inspection.genesis.chain_net;
    // One tx can commit many transitions. A bind of only the settling one
    // leaves the other value unbound, so the PSBT cross-check binds the group.
    inspection
        .witnesses
        .iter()
        .map(|w| {
            let txid = txid_from_display_hex(&w.txid)?;
            let summaries = w
                .operations
                .iter()
                .flat_map(|op| op.transitions.iter())
                .map(|t| inspected_summary(t, &w.txid, chain_net))
                .collect::<Result<Vec<_>>>()?;
            Ok((txid, summaries))
        })
        .collect()
}

pub(super) fn inspected_summary(
    t: &RgbTransitionInfo,
    witness_txid: &str,
    chain_net: &str,
) -> Result<TransitionSummary> {
    let outputs = t
        .outputs
        .iter()
        .filter_map(|o| inspected_output(o, witness_txid, chain_net).transpose())
        .collect::<Result<Vec<_>>>()?;
    let total = outputs
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.amount))
        .ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "consignment transition output amount overflow (op_id {})",
                t.opid
            ))
        })?;
    Ok(TransitionSummary {
        op_id: t.opid.clone(),
        transition_type: transition_type_id(t.r#type),
        // Every output is an `OS_ASSET` one, so the two sums are the same.
        total_output_amount: total,
        asset_output_amount: total,
        outputs,
        // Validation fills these from the rgbstd transition, for the settling
        // transition only.
        burned_asset_amount: None,
        burn_reason: None,
    })
}

/// rgb-lib names the type; the summary keeps the schema id (the table of
/// rgb-lib `database/enums.rs`).
fn transition_type_id(t: TypeOfTransition) -> u16 {
    match t {
        TypeOfTransition::Transfer => schemata::TS_TRANSFER,
        TypeOfTransition::Inflate => schemata::TS_INFLATION,
        TypeOfTransition::Burn => schemata::TS_BURN,
        TypeOfTransition::Mint => schemata::TS_MINT,
    }
    .to_inner()
}

/// Only fungible units are outputs: `OS_ASSET` is the one fungible type
/// rgb-lib reads.
fn inspected_output(
    o: &RgbOutputInfo,
    witness_txid: &str,
    chain_net: &str,
) -> Result<Option<TransitionOutput>> {
    let Assignment::Fungible(amount) = o.assignment else {
        return Ok(None);
    };
    Ok(Some(TransitionOutput {
        assignment_type: schemata::OS_ASSET.to_inner(),
        amount,
        seal: inspected_seal(o, witness_txid, chain_net)?,
    }))
}

fn inspected_seal(o: &RgbOutputInfo, witness_txid: &str, chain_net: &str) -> Result<OutputSeal> {
    if o.is_concealed {
        // rgb-lib prefixes the chain ("bcrt:utxob:..."); the parser gave the bare seal.
        let secret_seal = o
            .recipient_id
            .as_deref()
            .and_then(|r| r.strip_prefix(chain_net)?.strip_prefix(':'))
            .ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "concealed output has no {chain_net} recipient id (got {:?})",
                    o.recipient_id
                ))
            })?;
        return Ok(OutputSeal::Confidential {
            secret_seal: secret_seal.to_string(),
        });
    }
    let (Some(txid), Some(vout)) = (o.txid.as_deref(), o.vout) else {
        return Err(EnclaveError::CrossCheck(format!(
            "revealed output has no outpoint (txid {:?}, vout {:?})",
            o.txid, o.vout
        )));
    };
    // rgb-lib fills a witness-relative seal with the witness txid; the parser
    // left it `None`. A seal cannot name its own witness tx explicitly.
    let txid = (txid != witness_txid)
        .then(|| decode_display_txid(txid))
        .transpose()?;
    Ok(OutputSeal::Revealed { txid, vout })
}

/// Parses a display-order (big-endian) txid hex string into a `bitcoin::Txid`.
///
/// rgb-lib writes txids in display order, and `bitcoin::Txid` stores them
/// reversed. The reversal is here, not at each comparison.
pub(super) fn txid_from_display_hex(display_hex: &str) -> Result<bitcoin::Txid> {
    let mut raw = decode_display_txid(display_hex)?;
    raw.reverse();
    Ok(bitcoin::Txid::from_byte_array(raw))
}

pub(super) fn decode_display_txid(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "seal txid hex decode failed: {e} (got {hex_str:?})"
        ))
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "seal txid is not 32 bytes (got {} bytes from {hex_str:?})",
            bytes.len()
        ))
    })
}
