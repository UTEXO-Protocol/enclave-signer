//! Reading an rgbstd `Transfer` apart.
//!
//! Decode-only. Nothing here decides whether a consignment is acceptable; it
//! turns parser output into the shapes in [`super::types`] and fails closed on
//! anything it cannot read exactly.

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

/// Extract the rest of the witness-tx identity binding for the consignment's
/// **last** transition out of the rgbstd `Transfer`: when that bundle embeds
/// the full witness tx (`PubWitness::Tx`), its Bitcoin input prevouts.
/// Consumed by the send-RGB PSBT cross-check alongside
/// [`ValidatedConsignment::last_witness_txid`], which names the same bundle.
///
/// Reads the same `transfer.bundles.iter().last()` bundle as
/// [`read_last_transition_burned_asset`] and asserts its last known transition
/// type equals `expected_type`, the type the flat parser reported. The two
/// walks are independent traversals of the same data, so a disagreement is
/// rejected fail-closed.
///
/// Also returns the validated OpId of that transition, read from the rgbstd
/// bundle rather than the flat parser.
///
/// Returns `(None, None)` only for a bundle-less transfer, which rgbstd
/// rejects upstream.
pub(super) fn read_last_transfer_witness(
    transfer: &Transfer,
    expected_type: u16,
) -> Result<LastTransferBinding> {
    let Some(last_bundle) = transfer.bundles.iter().last() else {
        return Ok((None, None));
    };

    // OpId of the validated last transition, from the same bundle. rgbstd's
    // `OpId` displays as lowercase hex of its 32-byte commitment hash, so
    // hex-decode it back. Sourced from the validated object, not the flat
    // parser.
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

/// Binding data for the consignment's last transfer bundle:
/// `(witness input prevouts, validated last-transition OpId)`. Both `Option`
/// because a bundle-less transfer (rejected upstream by rgbstd) yields
/// `(None, None)`. See [`read_last_transfer_witness`].
type LastTransferBinding = (Option<Vec<bitcoin::OutPoint>>, Option<[u8; 32]>);

/// Mint transitions - the ones that map 1:1 to an EVM lock record. BFA mints
/// only through `TS_BRIDGE`; no other transition type creates units.
pub fn is_mint_transition(transition_type: u16) -> bool {
    transition_type == bfa::TS_BRIDGE
}

/// Parse the consignment with `rgb_consignment::parse` and pull out the
/// flat transition summary (every op_id, the most recent transition's shape,
/// and every transition grouped by the witness tx that commits it). Errors if
/// the consignment isn't a Transfer or if any field fails to decode.
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
        // A Contract / Kit cannot authorise an EVM action. Rejected
        // explicitly so a mistaken upload fails closed.
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

    // The mint (BFA `TS_BRIDGE`) subset - these map 1:1 to EVM lock
    // records (`fundsIn`). The `fundsOut` `fundsInIds[]` must each correspond
    // to one of these (spec section 6).
    let mint_op_ids: Vec<String> = transfer
        .witnesses
        .iter()
        .flat_map(|w: &WitnessInfo| w.transitions.iter())
        .filter(|t: &&TransitionInfo| is_mint_transition(t.transition_type))
        .map(|t: &TransitionInfo| t.op_id.clone())
        .collect();

    // Every transition, grouped by the witness tx that commits it. One tx can
    // carry several, so reading only `last_transition` would leave the rest of
    // the value it moves unbound. The PSBT cross-check binds the whole group.
    let mut transitions_by_witness: Vec<(bitcoin::Txid, Vec<TransitionSummary>)> =
        Vec::with_capacity(transfer.witnesses.len());
    for w in transfer.witnesses.iter() {
        let txid = txid_from_display_hex(&w.txid)?;
        let summaries: Result<Vec<TransitionSummary>> =
            w.transitions.iter().map(transition_summary).collect();
        transitions_by_witness.push((txid, summaries?));
    }

    // Taken from the group rather than summarised a second time - it is the
    // last witness's last transition either way.
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

/// Parse a display-order (big-endian) txid hex string into a `bitcoin::Txid`.
///
/// The parser stringifies txids in display order while `bitcoin::Txid` stores
/// them reversed, so the flip lives here rather than at each comparison site.
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
        // Filled by `read_last_transition_burned_asset` /
        // `read_last_transition_burn_recipient` if the transition is a burn;
        // the parser doesn't expose metadata so we leave these `None` here.
        burned_asset_amount: None,
        burn_recipient: None,
    })
}

/// Raw metadata value `meta_type` carries on the last witness bundle's last
/// known transition, if any. The flat parser drops `Transition.metadata`, so
/// the cross-checks that need it walk the rgbstd `Transfer` through here.
///
/// `None` when the transfer has no bundle, that bundle no known transition, or
/// the transition no value under that key - all three are "not declared" rather
/// than errors, and each caller decides what a missing value means for it.
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

/// The BFA `MS_BURN_RECIPIENT` metadata on the last transition - the 32 bytes
/// naming where the redemption is owed.
///
/// `Ok(None)` when the key is absent, and `Err` when the blob is not exactly
/// 32 bytes, because a release must never be pointed at a truncated or padded
/// address.
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

/// The BFA `MS_BURNED_ASSET` metadata on the last transition - the destroyed
/// amount the unlock cross-check binds against.
///
/// The value is a strict-encoded `rgbstd::Amount` (`u64`, 8 bytes,
/// little-endian). Decoded manually rather than via
/// `StrictDeserialize::from_strict_serialized`, to avoid threading the
/// `rgb-strict-encoding`-as-`strict_encoding` rename through our deps.
///
/// `Ok(None)` when the key is absent (which for a `TS_BURN` implies a schema
/// mismatch), and `Err` when the blob is the wrong size for a `u64`.
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
