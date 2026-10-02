//! Decodes an rgbstd `Transfer`.
//!
//! Decode only. Nothing here accepts or rejects a consignment. It converts
//! parser output into the shapes in [`super::types`]. It fails closed on data
//! that it cannot read exactly.

use super::bfa;
use super::types::{OutputSeal, TransitionOutput, TransitionSummary};
use crate::error::EnclaveError;
use crate::error::Result;
use rgb_consignment::ConsignmentInfo;
use rgb_consignment::FungibleAllocation;
use rgb_consignment::FungibleEntry;
use rgb_consignment::SealInfo;
use rgb_consignment::TransitionInfo;
use rgb_consignment::WitnessInfo;
use rgbstd::containers::Transfer;
use rgbstd::schema::MetaType;
use rgbstd::schema::TransitionType;

/// Reads the witness-tx bind data for the **last** transition from the rgbstd
/// `Transfer`: the input prevouts, if the bundle embeds the full witness tx
/// (`PubWitness::Tx`). The send-RGB PSBT cross-check uses them with
/// [`super::types::ValidatedConsignment::last_witness_txid`], which names the same bundle.
///
/// It reads the same last bundle as [`read_last_transition_burned_asset`]. It
/// asserts that the last known transition type equals `expected_type` from
/// the flat parser. The two walks are independent, so a mismatch fails closed.
///
/// Also returns the validated OpId of that transition, from the rgbstd bundle,
/// not the flat parser.
///
/// Returns `(None, None)` only for a transfer with no bundles, which rgbstd
/// rejects.
pub(super) fn read_last_transfer_witness(
    transfer: &Transfer,
    expected_type: u16,
) -> Result<LastTransferBinding> {
    let Some(last_bundle) = transfer.bundles.iter().last() else {
        return Ok((None, None));
    };

    // The rgbstd `OpId` displays as lowercase hex of its 32-byte commitment
    // hash, so decode the hex.
    let mut op_id: Option<[u8; 32]> = None;
    if let Some(known) = last_bundle.bundle().known_transitions.iter().last() {
        let actual = known.transition.transition_type;
        let expected = TransitionType::with(expected_type);
        if actual != expected {
            return Err(EnclaveError::CrossCheck(format!(
                "consignment last-bundle transition type {actual} disagrees with parsed last \
                 transition type {expected} - refusing to bind PSBT to an ambiguous witness"
            )));
        }
        let opid_hex = known.opid.to_string();
        let bytes = hex::decode(&opid_hex).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "validated opid hex decode failed: {e} ({opid_hex:?})"
            ))
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            EnclaveError::CrossCheck(format!("validated opid is not 32 bytes (got {})", v.len()))
        })?;
        op_id = Some(arr);
    }

    let prevouts = last_bundle
        .pub_witness
        .tx()
        .map(|tx| tx.input.iter().map(|txin| txin.previous_output).collect());

    Ok((prevouts, op_id))
}

/// Bind data for the last bundle:
/// `(witness input prevouts, validated last-transition OpId)`. See
/// [`read_last_transfer_witness`].
type LastTransferBinding = (Option<Vec<bitcoin::OutPoint>>, Option<[u8; 32]>);

/// Returns true for a mint transition, which maps 1:1 to an EVM lock record.
/// In BFA, only `TS_BRIDGE` creates units.
pub fn is_mint_transition(transition_type: u16) -> bool {
    transition_type == bfa::TS_BRIDGE
}

/// Parses the consignment with `rgb_consignment::parse` and returns the flat
/// transition summary: all op_ids, the mint op_ids, the last transition, and
/// all transitions grouped by witness tx. Fails if the consignment is not a
/// Transfer or if a field does not decode.
#[allow(clippy::type_complexity)]
pub(super) fn extract_transition_summary(
    consignment_bytes: &[u8],
) -> Result<(
    Vec<String>,
    Vec<String>,
    Option<TransitionSummary>,
    Vec<(bitcoin::Txid, Vec<TransitionSummary>)>,
)> {
    let info = rgb_consignment::parse(consignment_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("rgb-consignment parse failed: {e}")))?;

    let transfer = match info {
        ConsignmentInfo::Transfer(t) => t,
        // A Contract or Kit cannot authorize an EVM action.
        ConsignmentInfo::Contract(_) => {
            return Err(EnclaveError::CrossCheck(
                "consignment is a Contract, expected Transfer".into(),
            ));
        }
        ConsignmentInfo::Kit(_) => {
            return Err(EnclaveError::CrossCheck(
                "consignment is a Kit, expected Transfer".into(),
            ));
        }
    };

    let all_op_ids: Vec<String> = transfer
        .witnesses
        .iter()
        .flat_map(|w: &WitnessInfo| w.transitions.iter())
        .map(|t: &TransitionInfo| t.op_id.clone())
        .collect();

    // The mint (BFA `TS_BRIDGE`) subset. Each one maps to one EVM `fundsIn`
    // lock record.
    let mint_op_ids: Vec<String> = transfer
        .witnesses
        .iter()
        .flat_map(|w: &WitnessInfo| w.transitions.iter())
        .filter(|t: &&TransitionInfo| is_mint_transition(t.transition_type))
        .map(|t: &TransitionInfo| t.op_id.clone())
        .collect();

    // One tx can commit many transitions. A bind of only `last_transition`
    // leaves the other value unbound, so the PSBT cross-check binds the group.
    let mut transitions_by_witness: Vec<(bitcoin::Txid, Vec<TransitionSummary>)> =
        Vec::with_capacity(transfer.witnesses.len());
    for w in transfer.witnesses.iter() {
        let txid = txid_from_display_hex(&w.txid)?;
        let summaries: Result<Vec<TransitionSummary>> =
            w.transitions.iter().map(transition_summary).collect();
        transitions_by_witness.push((txid, summaries?));
    }

    // The last transition of the last witness, taken from the group.
    let last_transition = transitions_by_witness
        .last()
        .and_then(|(_, summaries)| summaries.last())
        .cloned();

    Ok((
        all_op_ids,
        mint_op_ids,
        last_transition,
        transitions_by_witness,
    ))
}

/// Parses a display-order (big-endian) txid hex string into a `bitcoin::Txid`.
///
/// The parser writes txids in display order, and `bitcoin::Txid` stores them
/// reversed. The reversal is here, not at each comparison.
pub(super) fn txid_from_display_hex(display_hex: &str) -> Result<bitcoin::Txid> {
    use bitcoin::hashes::Hash;

    let mut raw = decode_display_txid(display_hex)?;
    raw.reverse();
    Ok(bitcoin::Txid::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(raw),
    ))
}

pub(super) fn transition_summary(t: &TransitionInfo) -> Result<TransitionSummary> {
    let total_output_amount: u64 =
        t.fungible_allocations
            .iter()
            .try_fold(0u64, |acc, a: &FungibleAllocation| {
                acc.checked_add(a.total).ok_or_else(|| {
                    EnclaveError::CrossCheck(format!(
                        "consignment transition total_output_amount overflow (op_id {})",
                        t.op_id
                    ))
                })
            })?;

    // `OS_ASSET` allocations only. A Bridge transition also carries an
    // `OS_BRIDGE` output that is the mint right, not value.
    let asset_output_amount: u64 = t
        .fungible_allocations
        .iter()
        .filter(|a: &&FungibleAllocation| a.assignment_type == bfa::OS_ASSET)
        .try_fold(0u64, |acc, a: &FungibleAllocation| {
            acc.checked_add(a.total).ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "consignment transition asset_output_amount overflow (op_id {})",
                    t.op_id
                ))
            })
        })?;

    let outputs: Result<Vec<TransitionOutput>> = t
        .fungible_allocations
        .iter()
        .flat_map(|a: &FungibleAllocation| {
            let assignment_type = a.assignment_type;
            a.entries
                .iter()
                .map(move |e| transition_output(assignment_type, e))
        })
        .collect();

    Ok(TransitionSummary {
        op_id: t.op_id.clone(),
        transition_type: t.transition_type,
        total_output_amount,
        asset_output_amount,
        outputs: outputs?,
        // The parser has no metadata. For a burn, the
        // `read_last_transition_burn*` functions fill these later.
        burned_asset_amount: None,
        burn_recipient: None,
    })
}

/// Raw `meta_type` metadata value on the last known transition of the last
/// bundle. The flat parser drops `Transition.metadata`, so read it from the
/// rgbstd `Transfer`.
///
/// `None` if there is no bundle, no known transition, or no value for the key.
/// This means "not declared", not an error. Each caller decides what it means.
pub(super) fn last_transition_meta(transfer: &Transfer, meta_type: u16) -> Option<&[u8]> {
    let known = transfer
        .bundles
        .iter()
        .last()?
        .bundle()
        .known_transitions
        .iter()
        .last()?;
    let key = MetaType::with(meta_type);
    known
        .transition
        .metadata
        .iter()
        .find(|(mt, _)| **mt == key)
        .map(|(_, mv)| mv.as_unconfined().as_slice())
}

/// The BFA `MS_BURN_RECIPIENT` metadata on the last transition: 32 bytes that
/// name the redemption recipient.
///
/// `Ok(None)` if the key is absent. `Err` if the blob is not exactly 32 bytes,
/// so a release never goes to a truncated or padded address.
pub(super) fn read_last_transition_burn_recipient(transfer: &Transfer) -> Result<Option<Vec<u8>>> {
    let Some(raw) = last_transition_meta(transfer, bfa::MS_BURN_RECIPIENT) else {
        return Ok(None);
    };
    if raw.len() != 32 {
        return Err(EnclaveError::CrossCheck(format!(
            "MS_BURN_RECIPIENT metadata is {} bytes, expected 32",
            raw.len()
        )));
    }
    Ok(Some(raw.to_vec()))
}

/// The BFA `MS_BURNED_ASSET` metadata on the last transition: the destroyed
/// amount that the unlock cross-check binds.
///
/// The value is a strict-encoded `rgbstd::Amount` (`u64`, 8 bytes,
/// little-endian). Decoded by hand, not with
/// `StrictDeserialize::from_strict_serialized`, to avoid the
/// `rgb-strict-encoding`-as-`strict_encoding` rename in the dependencies.
///
/// `Ok(None)` if the key is absent (for a `TS_BURN`, a schema mismatch).
/// `Err` if the blob is not the size of a `u64`.
pub(super) fn read_last_transition_burned_asset(transfer: &Transfer) -> Result<Option<u64>> {
    let Some(raw) = last_transition_meta(transfer, bfa::MS_BURNED_ASSET) else {
        return Ok(None);
    };
    let bytes: [u8; 8] = raw.try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "MS_BURNED_ASSET metadata is {} bytes, expected 8 (strict-encoded u64)",
            raw.len()
        ))
    })?;
    Ok(Some(u64::from_le_bytes(bytes)))
}

pub(super) fn transition_output(
    assignment_type: u16,
    e: &FungibleEntry,
) -> Result<TransitionOutput> {
    let seal = match &e.seal {
        SealInfo::Revealed { txid, vout } => {
            let txid_bytes = txid
                .as_ref()
                .map(|hex_str| decode_display_txid(hex_str))
                .transpose()?;
            OutputSeal::Revealed {
                txid: txid_bytes,
                vout: *vout,
            }
        }
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
