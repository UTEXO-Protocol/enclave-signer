//! Reads rgb-lib's inspection of the consignment file that validation accepted.
//!
//! The inspection is the only reading. Over every bundle it reverifies each
//! witness commitment, resolves every transition input to the outpoint its
//! witness spends, and refuses an input it cannot resolve, a transition stored
//! under an id that is not its own, a transition in two bundles, and any type
//! the pinned BFA schema does not define. It becomes the shapes in
//! [`super::types`], failing closed on data that cannot be read exactly.

use bitcoin::hashes::Hash;
use rgb_lib::no_wallet::{
    inspect_consignment, BundleFilter, RgbInspection, RgbOutputInfo, RgbTransitionInfo,
    TransitionGlobal,
};
use rgb_lib::Assignment;

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
    // One tx can commit many transitions, so the summary keeps them grouped
    // by witness tx.
    inspection
        .witnesses
        .iter()
        .map(|w| witness_summary(w, &recipient_prefix))
        .collect()
}

/// No rule here counts the transitions a bundle discloses against the ones it
/// commits. The export builds each bundle with `to_concealed_except` and
/// reveals only what the history needs, so a bundle that commits more than it
/// carries is the normal shape, at any point of a history and in the bundle of
/// the burn itself. Consensus refuses a consignment that conceals a transition
/// the burned units descend from, so what a bundle may conceal is a transition
/// no release pays for. The fascia of the mint signer is the other way round:
/// see [`super::super::psbt_commit`].
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
    let (burned_asset_amount, burn_reason) = burn_globals(t)?;
    Ok(TransitionSummary {
        op_id: t.opid.clone(),
        transition_type: t.r#type,
        asset_output_amount: total,
        outputs,
        burned_asset_amount,
        burn_reason,
    })
}

/// The `burnedAsset` and `burnReason` of a transition that carries them. A
/// burn sets the EVM release amount with the first and its destination with
/// the second, so each must appear at most once and read exactly.
fn burn_globals(t: &RgbTransitionInfo) -> Result<(Option<u64>, Option<[u8; 32]>)> {
    let mut burned = None;
    let mut reason = None;
    for global in &t.globals {
        let slot = match global {
            TransitionGlobal::BurnedAsset(amount) => {
                if burned.replace(*amount).is_some() {
                    Some("burnedAsset")
                } else {
                    None
                }
            }
            TransitionGlobal::BurnReason(hex) => {
                let bytes = hex::decode(hex)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok());
                let bytes = bytes.ok_or_else(|| {
                    EnclaveError::CrossCheck(format!(
                        "transition {} carries a burnReason that is not 32 bytes of hex: {hex:?}",
                        t.opid
                    ))
                })?;
                if reason.replace(bytes).is_some() {
                    Some("burnReason")
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(name) = slot {
            return Err(EnclaveError::CrossCheck(format!(
                "transition {} carries two {name} globals - a burn carries one",
                t.opid
            )));
        }
    }
    Ok((burned, reason))
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
    Ok(TransitionOutput { amount, seal })
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
