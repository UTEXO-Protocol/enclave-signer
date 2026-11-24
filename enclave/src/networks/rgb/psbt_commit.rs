//! The core of the mint signer's PSBT rules: the one transition of the pinned
//! contract that the signer reads, from the fascia rgb-lib writes for the tx
//! being signed (rgb-lib strips the RGB keys from the PSBT). No consignment:
//! each step below is a commitment, so the txid fixes the transition.
//!
//! rgb-lib's wallet-less `inspect_fascia` is the only reader of the fascia. It
//! proves the commitments: the fascia is of the PSBT's tx, that tx commits
//! exactly the bundles the fascia discloses under the entropy the fascia
//! carries, and each bundle commits the transitions it holds. It reports each
//! transition typed: an unknown transition, assignment, global or metadata
//! type, and a global or metadata value of the wrong length, are refused
//! there. It compares no type with the asset's schema, which a fascia does not
//! carry, and it validates no operation. So the shape rules are the enclave's
//! own, as are the rules around the inspection: the one transition of the
//! pinned asset that the signer reads, every other transition a move of state
//! to this enclave's own outputs, and an opret host the enclave can read. The
//! rule ids (F3-F6, M9) are those of `docs/mint-flow.md` section 5.

use std::str::FromStr;

use bitcoin::psbt::Psbt;
use bitcoin::Transaction;
use rgb_lib::no_wallet::{inspect_fascia, RgbInputInfo, RgbInspection, RgbOutputInfo};
use rgb_lib::{BitcoinNetwork, CloseMethod, ContractId, OpId, TypeOfAssignment, TypeOfTransition};

use super::validation::decode_opid;
use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};

/// Tells whether `vout` of the tx being signed is an output of this enclave's
/// Colored account, which is where rgb-lib puts the RGB change of a mint.
pub type OwnVout<'a> = &'a dyn Fn(&Psbt, u32) -> bool;

/// The types rgb-lib moves the other allocations of a spent UTXO with. In the
/// pinned contract a burn, a mint, an inflation or a link is therefore never a
/// side transition. rgb-lib names the type from its number alone, as it knows
/// no schema of another contract; M9 keeps the state there.
const MOVE_TYPES: [TypeOfTransition; 4] = [
    TypeOfTransition::Transfer,
    TypeOfTransition::Propagate,
    TypeOfTransition::TransferInflation,
    TypeOfTransition::TransferLink,
];

/// The transition of the pinned contract that the signer reads, as rgb-lib
/// inspected it.
#[derive(Debug, Clone)]
pub struct Committed {
    pub txid: bitcoin::Txid,
    pub opid: OpId,
    pub transition: rgb_lib::no_wallet::RgbTransitionInfo,
}

/// What the core reads a fascia under: the pinned asset and the image's
/// Bitcoin network.
#[derive(Debug, Clone, Copy)]
pub struct Pin {
    /// `RGB_ASSET_ID`, parsed. Bundles are compared as ids, never as strings.
    pub contract: ContractId,
    /// rgb-lib renders a concealed seal as an invoice recipient id, which
    /// carries this network's prefix. That id is the blinded recipient the
    /// mint rules report (M7). No binding, hash or signed value reads it: the
    /// lock binds the seal through the OpId, so the prefix only has to name
    /// the image's network.
    network: BitcoinNetwork,
}

impl Pin {
    /// The pins of this image, or a refusal when `RGB_ASSET_ID` is unset or
    /// not a contract id.
    pub fn of(cfg: &BridgeConfig) -> Result<Self> {
        if cfg.rgb_asset_id.is_empty() {
            return Err(EnclaveError::CrossCheck(
                "asset-identity pin missing: RGB_ASSET_ID is not configured - refusing to sign \
                 for an unpinned asset"
                    .into(),
            ));
        }
        let contract = ContractId::from_str(&cfg.rgb_asset_id).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "RGB_ASSET_ID {} is not a contract id: {e}",
                cfg.rgb_asset_id
            ))
        })?;
        Ok(Self {
            contract,
            network: rgb_lib_network(cfg),
        })
    }
}

#[cfg(test)]
impl Pin {
    /// A regtest image pinned to `contract`, for the tests of the mint paths.
    /// The fixtures build regtest seals.
    pub fn for_test(contract: ContractId) -> Self {
        Self {
            contract,
            network: BitcoinNetwork::Regtest,
        }
    }
}

/// The network rgb-lib renders a concealed seal's recipient id with. The match
/// is exhaustive, so a new network must be mapped here.
fn rgb_lib_network(cfg: &BridgeConfig) -> BitcoinNetwork {
    use attestation_verify::BitcoinNetwork as Image;
    match cfg.bitcoin_network {
        Image::Mainnet => BitcoinNetwork::Mainnet,
        Image::Testnet3 => BitcoinNetwork::Testnet,
        Image::Testnet4 => BitcoinNetwork::Testnet4,
        Image::Signet => BitcoinNetwork::Signet,
        Image::SignetCustom => BitcoinNetwork::SignetCustom,
        Image::Regtest => BitcoinNetwork::Regtest,
    }
}

/// F3-F6: the fascia `bytes` encode is of the PSBT's tx, whose first OP_RETURN
/// commits exactly its bundles, and the bundle of the pinned contract discloses
/// every transition it commits, one of which the signer reads.
///
/// The size bound runs before the bytes reach a scratch file or rgb-lib. A
/// fascia holds a tx and its RGB data, so the PSBT size limit applies to it
/// too (`memory.rs`), and it is what bounds the work of the MPC rebuild in
/// [`inspect`].
pub fn committed_transition(
    psbt: &Psbt,
    bytes: &[u8],
    field: &str,
    pin: Pin,
    own_vout: OwnVout<'_>,
) -> Result<Committed> {
    if bytes.is_empty() {
        return Err(EnclaveError::CrossCheck(format!(
            "{field} required: rgb-lib strips the RGB data from the PSBT and keeps it in the \
             tx's fascia"
        )));
    }
    crate::config::check_psbt_size(field, bytes)?;
    let txid = psbt.unsigned_tx.compute_txid();
    assert_opret_host(&psbt.unsigned_tx)?;
    let inspection = inspect(psbt, bytes, field, pin)?;
    let transition = pinned_transition(&inspection, field, pin, txid, psbt, own_vout)?;
    let opid = OpId::from(decode_opid(&transition.opid)?);
    Ok(Committed {
        txid,
        opid,
        transition,
    })
}

/// F3: consensus reads the commitment from the first OP_RETURN or P2TR output.
/// A P2TR first would make it a tapret host that our opret check never sees.
fn assert_opret_host(tx: &Transaction) -> Result<()> {
    let host = tx
        .output
        .iter()
        .position(|out| out.script_pubkey.is_op_return() || out.script_pubkey.is_p2tr());
    match host {
        Some(i) if tx.output[i].script_pubkey.is_op_return() => Ok(()),
        Some(i) => Err(EnclaveError::CrossCheck(format!(
            "tx output {i} is a P2TR before the OP_RETURN, so RGB consensus reads a tapret \
             commitment there - refusing to sign"
        ))),
        None => Err(EnclaveError::CrossCheck(
            "tx has no OP_RETURN output to commit its RGB bundle".into(),
        )),
    }
}

/// rgb-lib's wallet-less fascia inspection, over the request bytes in a
/// scratch file: rgb-lib reads a fascia only from a path.
///
/// F5: no entropy is passed, so rgb-lib takes the one the fascia's MPC
/// commitment carries, and refuses a concealed commitment that carries none.
///
/// rgb-lib rebuilds the MPC tree of the bundles the file discloses. The tree
/// is as wide as the smallest power of two that holds one leaf per bundle, and
/// `root()` hashes every leaf of that width, so the work follows the bundle
/// count. `max_psbt_bytes`, checked above, bounds that count: a bundle entry
/// carries a contract id and a non-empty input map, so the limit admits far
/// fewer bundles than the 65535 of rgb-lib's message map.
fn inspect(psbt: &Psbt, bytes: &[u8], field: &str, pin: Pin) -> Result<RgbInspection> {
    // rgb-lib parses the PSBT from its base64 form.
    let psbt = psbt.to_string();
    super::scratch::with_scratch_file(field, bytes, |path| {
        let path = path.to_str().ok_or_else(|| {
            EnclaveError::Internal(format!("scratch path {} is not UTF-8", path.display()))
        })?;
        inspect_fascia(psbt, path.to_string(), None, pin.network).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "rgb-lib refused the {field} of this tx: {e} - refusing to sign state moves the \
                 enclave cannot see"
            ))
        })
    })
}

/// F4-F6: the one transition of the pinned asset that the signer reads, under
/// an opret proof, beside moves of state to this enclave's own outputs.
///
/// F3: rgb-lib verifies the commitment with the DBC proof of the fascia, so a
/// tapret proof is refused here; F3 then makes the OP_RETURN the host that
/// consensus reads. F5 and F6: the counts bind the whole input map, which
/// rgb-lib checks only for the transitions it inspects, so a bundle that
/// closes a seal for a transition the inspection does not report is refused.
///
/// A fascia is the RGB data of the transaction being built, so it discloses
/// every transition its bundle commits and F6 requires that disclosure. A
/// consignment is the opposite: its export conceals the history a later
/// holder does not need, so [`super::validation`] requires no such disclosure
/// of one of those.
fn pinned_transition(
    inspection: &RgbInspection,
    field: &str,
    pin: Pin,
    txid: bitcoin::Txid,
    psbt: &Psbt,
    own_vout: OwnVout<'_>,
) -> Result<rgb_lib::no_wallet::RgbTransitionInfo> {
    let refuse = |what: String| Err(EnclaveError::CrossCheck(format!("the {field} {what}")));
    if inspection.close_method != CloseMethod::OpretFirst {
        return refuse(format!(
            "commits with the close method {:?} - the mint signer signs an opret commitment only",
            inspection.close_method
        ));
    }
    if inspection.txid != txid.to_string() {
        return refuse(format!(
            "commits tx {}, not the PSBT's tx {txid}",
            inspection.txid
        ));
    }
    let pinned = pin.contract.to_string();
    let mut signing = None;
    for operation in &inspection.operations {
        assert_fully_disclosed(operation, field)?;
        for transition in &operation.transitions {
            if is_own_move(transition, txid, psbt, own_vout) {
                continue;
            }
            if operation.asset_id != pinned {
                return refuse(format!(
                    "discloses transition {} of asset {}, which is not a move of state to this \
                     enclave's own outputs - beside the pinned RGB_ASSET_ID {pinned} the signer \
                     takes only such moves",
                    transition.opid, operation.asset_id
                ));
            }
            if let Some(first) = signing.replace(transition) {
                return refuse(format!(
                    "discloses transitions {} and {}, neither a move of state to this enclave's \
                     own outputs - the signer reads exactly one",
                    first.opid, transition.opid
                ));
            }
        }
    }
    let Some(signing) = signing else {
        return refuse(format!(
            "discloses no transition of the pinned RGB_ASSET_ID {pinned} to sign for"
        ));
    };
    Ok(signing.clone())
}

/// F5 and F6: the bundle discloses every transition it commits, and its input
/// map closes exactly their inputs.
fn assert_fully_disclosed(
    operation: &rgb_lib::no_wallet::RgbOperationInfo,
    field: &str,
) -> Result<()> {
    let refuse = |what: String| Err(EnclaveError::CrossCheck(format!("the {field} {what}")));
    let asset = &operation.asset_id;
    if operation.has_concealed_transitions() {
        return refuse(format!(
            "commits {} transitions of asset {asset} and discloses {} - refusing to sign a \
             bundle that closes seals for a transition the enclave cannot see",
            operation.committed_transition_count,
            operation.transitions.len()
        ));
    }
    let inputs: usize = operation.transitions.iter().map(|t| t.inputs.len()).sum();
    if operation.committed_input_count as usize != inputs {
        return refuse(format!(
            "has an input map for asset {asset} that closes {} seal(s), but the transitions it \
             discloses spend {inputs} - refusing to sign a bundle that closes seals the enclave \
             cannot see",
            operation.committed_input_count
        ));
    }
    Ok(())
}

/// F6 and M9: a side transition, as rgb-lib moves any other allocation of a
/// spent UTXO, of the pinned asset or of another. It is of a move type and
/// assigns one seal for each input it closes, so it cannot turn one right
/// into many. Every seal is revealed on an output of the tx being signed that
/// this enclave derives on its Colored account and that carries sats, so the
/// state stays in the wallet. Any other transition is one the enclave must
/// read, and it reads exactly one.
fn is_own_move(
    transition: &rgb_lib::no_wallet::RgbTransitionInfo,
    txid: bitcoin::Txid,
    psbt: &Psbt,
    own_vout: OwnVout<'_>,
) -> bool {
    let funded = |vout: u32| {
        let output = psbt.unsigned_tx.output.get(vout as usize);
        output.is_some_and(|output| output.value.to_sat() > 0)
    };
    MOVE_TYPES.contains(&transition.r#type)
        && !transition.outputs.is_empty()
        && transition.outputs.len() == transition.inputs.len()
        && transition.outputs.iter().all(|output| {
            !output.is_concealed
                && output.txid.as_deref() == Some(&txid.to_string())
                && output
                    .vout
                    .is_some_and(|vout| funded(vout) && own_vout(psbt, vout))
        })
}

/// M2, RR7: the transition closes exactly one input, a `mintRight`.
pub fn assert_single_right_input(inputs: &[RgbInputInfo], what: &str) -> Result<()> {
    match inputs {
        [input] if input.opout.assignment_type == TypeOfAssignment::MintRight => Ok(()),
        inputs => {
            let types: Vec<_> = inputs.iter().map(|i| i.opout.assignment_type).collect();
            Err(EnclaveError::CrossCheck(format!(
                "{what} must close exactly one mintRight - it closes {types:?}"
            )))
        }
    }
}

/// The vout of a seal on the tx that commits its transition. A blinded seal
/// could be the host's, and a seal on another tx could be any UTXO. rgb-lib
/// reports a revealed seal of the inspected tx under that tx's txid, so a seal
/// naming any other txid is on another transaction.
pub fn witness_vout(output: &RgbOutputInfo, txid: bitcoin::Txid, what: &str) -> Result<u32> {
    if output.is_concealed {
        return Err(EnclaveError::CrossCheck(format!(
            "{what} is on blinded seal {} - the enclave cannot prove where a blinded seal is",
            output.recipient_id.as_deref().unwrap_or("(unnamed)")
        )));
    }
    let (Some(seal_txid), Some(vout)) = (output.txid.as_deref(), output.vout) else {
        return Err(EnclaveError::CrossCheck(format!(
            "{what} has no revealed outpoint - it must be on an output of the transaction that \
             makes it"
        )));
    };
    if seal_txid != txid.to_string() {
        return Err(EnclaveError::CrossCheck(format!(
            "{what} is on vout {vout} of transaction {seal_txid} - it must be on an output of \
             {txid}, the transaction that makes it"
        )));
    }
    Ok(vout)
}

#[cfg(test)]
mod tests;
