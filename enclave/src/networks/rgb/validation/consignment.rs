//! Decodes a validated rgbstd `Transfer`.
//!
//! Decode only. Nothing here accepts or rejects a consignment. It converts
//! rgbstd and parser output into the shapes in [`super::types`]. It fails
//! closed on data that it cannot read exactly.

use std::collections::BTreeSet;

use amplify::{ByteArray, Wrapper};
use bitcoin::hashes::Hash;
use rgb_consignment::{
    ConsignmentInfo, FungibleAllocation, FungibleEntry, SealInfo, TransitionInfo,
};
use rgbstd::containers::{Transfer, WitnessBundle};
use rgbstd::txout::TxoSeal;
use rgbstd::{
    Assign, Assignments, BuilderSeal, GlobalStateType, GraphSeal, KnownTransition, OpId, Operation,
    Opout, TransitionType,
};

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

/// The one value of a global, as exactly `N` raw bytes. `Ok(None)` when the
/// transition does not declare it.
///
/// The bytes are the strict encoding: an `Amount` is a little-endian `u64`, a
/// `BurnReason` its 32 bytes. Decoded by hand to keep the strict-encoding
/// crate out of the enclave's own code.
fn single_global<const N: usize>(
    globals: &rgbstd::GlobalState,
    ty: GlobalStateType,
    name: &str,
) -> Result<Option<[u8; N]>> {
    let Some(values) = globals.get(&ty) else {
        return Ok(None);
    };
    let [value] = values.as_slice() else {
        return Err(EnclaveError::CrossCheck(format!(
            "settling transition carries {} {name} values, expected one",
            values.len()
        )));
    };
    let bytes: [u8; N] = value.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "{name} is {} bytes, expected {N}",
            value.as_slice().len()
        ))
    })?;
    Ok(Some(bytes))
}

/// The seal of an output as the flat parser shows it.
fn output_seal(seal: &BuilderSeal<GraphSeal>) -> OutputSeal {
    match seal {
        BuilderSeal::Revealed(seal) => OutputSeal::Revealed {
            txid: seal.txid().map(display_bytes),
            vout: seal.vout().into_u32(),
        },
        BuilderSeal::Concealed(secret) => OutputSeal::Confidential {
            secret_seal: secret.to_string(),
        },
    }
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

/// Display-order (big-endian) bytes of a txid, as the wire carries it.
fn display_bytes(txid: bitcoin::Txid) -> [u8; 32] {
    let mut bytes = txid.to_byte_array();
    bytes.reverse();
    bytes
}

/// The flat transition summary of a consignment that consensus validated:
/// all transitions grouped by witness tx.
pub(super) fn extract_transition_summary(
    consignment_bytes: &[u8],
) -> Result<Vec<(bitcoin::Txid, Vec<TransitionSummary>)>> {
    let info = rgb_consignment::parse(consignment_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("rgb-consignment parse failed: {e}")))?;
    let ConsignmentInfo::Transfer(transfer) = info else {
        return Err(EnclaveError::CrossCheck(
            "consignment is a Contract, expected Transfer".into(),
        ));
    };

    // One tx can commit many transitions. A bind of only the settling one
    // leaves the other value unbound, so the PSBT cross-check binds the group.
    transfer
        .witnesses
        .iter()
        .map(|w| {
            let txid = txid_from_display_hex(&w.txid)?;
            let summaries = w
                .transitions
                .iter()
                .map(transition_summary)
                .collect::<Result<Vec<_>>>()?;
            Ok((txid, summaries))
        })
        .collect()
}

/// Parses a display-order (big-endian) txid hex string into a `bitcoin::Txid`.
///
/// The parser writes txids in display order, and `bitcoin::Txid` stores them
/// reversed. The reversal is here, not at each comparison.
pub(super) fn txid_from_display_hex(display_hex: &str) -> Result<bitcoin::Txid> {
    let mut raw = decode_display_txid(display_hex)?;
    raw.reverse();
    Ok(bitcoin::Txid::from_byte_array(raw))
}

pub(super) fn transition_summary(t: &TransitionInfo) -> Result<TransitionSummary> {
    let total_output_amount = checked_total(t.fungible_allocations.iter(), t)?;
    let asset_output_amount = checked_total(
        t.fungible_allocations
            .iter()
            .filter(|a| a.assignment_type == schemata::OS_ASSET.to_inner()),
        t,
    )?;

    let outputs = t
        .fungible_allocations
        .iter()
        .flat_map(|a| {
            a.entries
                .iter()
                .map(move |e| transition_output(a.assignment_type, e))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(TransitionSummary {
        op_id: t.op_id.clone(),
        transition_type: t.transition_type,
        total_output_amount,
        asset_output_amount,
        outputs,
        // Validation fills these from the rgbstd transition, for the settling
        // transition only.
        burned_asset_amount: None,
        burn_reason: None,
    })
}

fn checked_total<'a>(
    mut allocations: impl Iterator<Item = &'a FungibleAllocation>,
    t: &TransitionInfo,
) -> Result<u64> {
    allocations.try_fold(0u64, |acc, a| {
        acc.checked_add(a.total).ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "consignment transition output amount overflow (op_id {})",
                t.op_id
            ))
        })
    })
}

pub(super) fn transition_output(
    assignment_type: u16,
    e: &FungibleEntry,
) -> Result<TransitionOutput> {
    let seal = match &e.seal {
        SealInfo::Revealed { txid, vout } => OutputSeal::Revealed {
            txid: txid.as_deref().map(decode_display_txid).transpose()?,
            vout: *vout,
        },
        SealInfo::Confidential { secret_seal } => OutputSeal::Confidential {
            secret_seal: secret_seal.clone(),
        },
    };
    Ok(TransitionOutput {
        assignment_type,
        amount: e.amount,
        seal,
    })
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
