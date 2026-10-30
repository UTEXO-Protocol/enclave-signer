//! Decodes a validated rgbstd `Transfer`, and rgb-lib's inspection of its file.
//!
//! The inspection rechecks commitments and refuses what it cannot read, which
//! validation has already refused. Both readings become the shapes in
//! [`super::types`], failing closed on data that cannot be read exactly.

use std::collections::{BTreeSet, HashMap};

use amplify::{ByteArray, Wrapper};
use bitcoin::hashes::Hash;
use rgb_lib::no_wallet::{
    inspect_consignment, BundleFilter, RgbInspection, RgbOutputInfo, RgbTransitionInfo,
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
/// rgbstd `Transfer`, not from the flat summary.
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
    let makers = SealMakers::of(transfer);
    bundle
        .bundle
        .known_transitions
        .iter()
        .flat_map(|k| k.transition.inputs.iter())
        .map(|&input| {
            makers.outpoint(input).ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "input {input} has no revealed seal in the consignment"
                ))
            })
        })
        .collect()
}

/// The operations that made the seals, indexed once: a genesis id or a
/// witness id hashes all of it, and a burn can spend 65535 inputs.
struct SealMakers<'a> {
    genesis_id: OpId,
    genesis: Assignments<GraphSeal>,
    transitions: HashMap<OpId, (&'a KnownTransition, bitcoin::Txid)>,
}

impl<'a> SealMakers<'a> {
    /// A transition in two bundles keeps its first.
    fn of(transfer: &'a Transfer) -> Self {
        let mut transitions = HashMap::new();
        for wb in &transfer.bundles {
            let witness_id = wb.witness_id();
            for known in &wb.bundle.known_transitions {
                transitions.entry(known.opid).or_insert((known, witness_id));
            }
        }
        Self {
            genesis_id: transfer.genesis.id(),
            genesis: transfer.genesis.assignments.transmutate_seals(),
            transitions,
        }
    }

    /// The outpoint of the seal `input` spends, from the operation that made it.
    fn outpoint(&self, input: Opout) -> Option<bitcoin::OutPoint> {
        if input.op == self.genesis_id {
            return revealed_seal(&self.genesis, input, None);
        }
        let (known, witness_id) = self.transitions.get(&input.op)?;
        revealed_seal(&known.transition.assignments, input, Some(*witness_id))
    }
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
/// all transitions grouped by witness tx, from rgb-lib's inspection of the
/// file it validated at `path`.
pub(super) fn extract_transition_summary(
    path: &str,
) -> Result<Vec<(bitcoin::Txid, Vec<TransitionSummary>)>> {
    // Every bundle: `Terminals` would skip a history burn, and its checks.
    let inspection = inspect_consignment(path.to_string(), BundleFilter::All).map_err(|e| {
        EnclaveError::CrossCheck(format!("rgb-lib inspect_consignment failed: {e}"))
    })?;
    if !inspection.is_transfer {
        return Err(EnclaveError::CrossCheck(
            "consignment is a Contract, expected Transfer".into(),
        ));
    }
    // A concealed seal reads as an invoice recipient: `<chain_net>:utxob:...`.
    let recipient_prefix = format!("{}:", inspection.genesis.chain_net);
    // One tx can commit many transitions. A bind of only the settling one
    // leaves the other value unbound, so the PSBT cross-check binds the group.
    inspection
        .witnesses
        .iter()
        .map(|w| witness_summary(w, &recipient_prefix))
        .collect()
}

fn witness_summary(
    witness: &RgbInspection,
    recipient_prefix: &str,
) -> Result<(bitcoin::Txid, Vec<TransitionSummary>)> {
    let [operation] = witness.operations.as_slice() else {
        return Err(EnclaveError::CrossCheck(format!(
            "rgb-lib inspected {} operations in witness {}, expected one",
            witness.operations.len(),
            witness.txid
        )));
    };
    let witness_txid = decode_display_txid(&witness.txid)?;
    let summaries = operation
        .transitions
        .iter()
        .map(|t| transition_summary(t, witness_txid, recipient_prefix))
        .collect::<Result<_>>()?;
    Ok((txid_from_display_hex(&witness.txid)?, summaries))
}

/// Only `OS_ASSET` units are outputs, the one fungible type of BFA; the
/// declarative rights are not. `witness_txid` is in display order.
pub(super) fn transition_summary(
    t: &RgbTransitionInfo,
    witness_txid: [u8; 32],
    recipient_prefix: &str,
) -> Result<TransitionSummary> {
    let outputs: Vec<TransitionOutput> = t
        .outputs
        .iter()
        .filter_map(|o| match o.assignment {
            Assignment::Fungible(amount) => {
                Some(asset_output(o, amount, witness_txid, recipient_prefix))
            }
            _ => None,
        })
        .collect::<Result<_>>()?;
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
        total_output_amount: total,
        asset_output_amount: total,
        outputs,
        // Validation fills these from the rgbstd transition, for the settling
        // transition only.
        burned_asset_amount: None,
        burn_reason: None,
    })
}

/// The BFA schema id of an inspected type: rgb-lib maps it from these ids.
fn transition_type_id(ty: TypeOfTransition) -> u16 {
    let ty = match ty {
        TypeOfTransition::Transfer => schemata::TS_TRANSFER,
        TypeOfTransition::Inflate => schemata::TS_INFLATION,
        TypeOfTransition::Burn => schemata::TS_BURN,
        TypeOfTransition::Link => schemata::TS_LINK,
        TypeOfTransition::Mint => schemata::TS_MINT,
        TypeOfTransition::TransferInflation => schemata::TS_TRANSFER_INFLATION,
        TypeOfTransition::TransferLink => schemata::TS_TRANSFER_LINK,
        TypeOfTransition::Propagate => schemata::TS_PROPAGATE,
    };
    ty.to_inner()
}

/// The seal as rgbstd holds it: inspect names the witness of a witness seal,
/// which reads as `None` here.
fn asset_output(
    o: &RgbOutputInfo,
    amount: u64,
    witness_txid: [u8; 32],
    recipient_prefix: &str,
) -> Result<TransitionOutput> {
    let seal = if o.is_concealed {
        let secret_seal = o
            .recipient_id
            .as_deref()
            .and_then(|r| r.strip_prefix(recipient_prefix))
            .ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "concealed output {:?} is not a {recipient_prefix} recipient",
                    o.recipient_id
                ))
            })?;
        OutputSeal::Confidential {
            secret_seal: secret_seal.to_string(),
        }
    } else {
        let (Some(txid), Some(vout)) = (&o.txid, o.vout) else {
            return Err(EnclaveError::CrossCheck(
                "revealed output without a txid and vout".into(),
            ));
        };
        let txid = decode_display_txid(txid)?;
        OutputSeal::Revealed {
            txid: (txid != witness_txid).then_some(txid),
            vout,
        }
    };
    Ok(TransitionOutput {
        assignment_type: schemata::OS_ASSET.to_inner(),
        amount,
        seal,
    })
}

/// Parses a display-order (big-endian) txid hex string into a `bitcoin::Txid`.
///
/// rgb-lib writes txids in display order, and `bitcoin::Txid` stores them
/// reversed. The reversal is here, not at each comparison.
fn txid_from_display_hex(display_hex: &str) -> Result<bitcoin::Txid> {
    let mut raw = decode_display_txid(display_hex)?;
    raw.reverse();
    Ok(bitcoin::Txid::from_byte_array(raw))
}

fn decode_display_txid(hex_str: &str) -> Result<[u8; 32]> {
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
