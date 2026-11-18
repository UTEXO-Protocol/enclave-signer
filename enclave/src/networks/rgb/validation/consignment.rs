//! Reads rgb-lib's inspection of the consignment file that validation accepted.
//!
//! The inspection is the only reading. It indexes every transition of the file
//! to resolve inputs from, and refuses a transition that two bundles commit.
//! For each bundle it is asked for it reverifies the witness commitment,
//! resolves every transition input to the outpoint its witness spends, and
//! refuses an input it cannot resolve, a transition the bundle does not commit
//! under its own id, and any type the pinned BFA schema does not define. It
//! becomes the shapes in [`super::types`], failing closed on data that cannot
//! be read exactly.

use bitcoin::hashes::Hash;
use rgb_lib::no_wallet::{
    inspect_consignment, BundleFilter, RgbInspection, RgbOutputInfo, RgbTransitionInfo,
    TransitionGlobal,
};
use rgb_lib::Assignment;

use super::types::{OutputSeal, TransitionOutput, TransitionSummary};
use crate::error::{EnclaveError, Result};

/// The flat transition summary of a consignment that consensus validated: the
/// transitions of its terminal bundles, grouped by witness tx, from rgb-lib's
/// inspection of the file it validated at `path`.
///
/// A terminal operation is one that nothing in the consignment builds on:
/// rgb-lib selects the bundles holding one, and skips the rest. A burn has no
/// assignments, so nothing can spend its state and it is always terminal, which
/// is what makes this filter sound for the burn path: the settling burn is
/// always read, wherever its bundle sits. The history behind it is what
/// validation covers, and reading it again here would prove nothing. An
/// ancestor is not terminal, since the operation that spends its state is in
/// the same file.
///
/// An export may end in more than one terminal operation, so this can select
/// several bundles; `super::consensus::settling_summary` is what requires one
/// burn among them. The group of a terminal bundle holds every transition the
/// bundle discloses, terminal or not.
pub(super) fn extract_transition_summary(
    path: &str,
) -> Result<Vec<(bitcoin::Txid, Vec<TransitionSummary>)>> {
    inspect_filtered(path, BundleFilter::Terminals)
}

/// The summary of the bundles `filter` selects.
fn inspect_filtered(
    path: &str,
    filter: BundleFilter,
) -> Result<Vec<(bitcoin::Txid, Vec<TransitionSummary>)>> {
    let inspection = inspect_consignment(path.to_string(), filter).map_err(|e| {
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

/// Every bundle's summary, for the tests that compare each one with their own
/// reading of the rgbstd types and of the bridge's parser. Production reads
/// the terminal bundles alone.
#[cfg(test)]
pub(super) fn summary_of_every_bundle(
    path: &str,
) -> Result<Vec<(bitcoin::Txid, Vec<TransitionSummary>)>> {
    inspect_filtered(path, BundleFilter::All)
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
