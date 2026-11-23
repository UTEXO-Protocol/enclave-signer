//! The core of the mint signer's PSBT rules: the transitions a tx commits,
//! read from the fascia rgb-lib writes for that tx (rgb-lib strips the RGB
//! keys from the PSBT). No consignment: each step below is a commitment, so
//! the txid fixes every transition.
//!
//! rgb-lib's wallet-less `inspect_fascia` proves the commitments: the fascia is
//! of the PSBT's tx, that tx commits exactly the bundles the fascia discloses
//! under the entropy the fascia carries, and each bundle commits the
//! transitions it holds. The rules around it are the enclave's: one main
//! transition of the pinned asset, every other transition a disclosed move of
//! state to an output of the same tx, and an opret host the enclave can read.
//! The rule ids (F3-F6) are those of `docs/mint-flow.md` section 5, Stage 3.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use amplify::confinement::{Confined, U24};
use amplify::Wrapper;
use bitcoin::psbt::Psbt;
use bitcoin::Transaction;
use rgb_lib::no_wallet::{inspect_fascia, RgbInspection};
use rgb_lib::{BitcoinNetwork, CloseMethod};
use rgbstd::containers::Fascia;
use rgbstd::{ContractId, OpId, Operation, Transition, TransitionBundle, TransitionType};
use strict_encoding::StrictDeserialize;

use super::validation::{output_seal, OutputSeal};
use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};

/// Most side transitions a mint may commit. rgb-lib builds one per other
/// allocation of the spent UTXO, which holds few. It also bounds the bundles,
/// over which rgb-lib rebuilds an MPC tree, and the transitions it inspects.
pub const MAX_SIDE_TRANSITIONS: usize = 16;

/// The types rgb-lib moves the other allocations of a spent UTXO with, by
/// their number in the pinned schemas. In the pinned contract a burn, a mint,
/// an inflation or a link is therefore never a side transition. The enclave
/// knows no other contract's schema: there the type is only a number, and M9
/// keeps the state.
const MOVE_TYPES: [TransitionType; 4] = [
    schemata::TS_TRANSFER,
    schemata::TS_PROPAGATE,
    schemata::TS_TRANSFER_INFLATION,
    schemata::TS_TRANSFER_LINK,
];

/// What a tx commits: the main transition of the pinned contract, and the
/// outputs every other transition moves state to.
#[derive(Debug, Clone)]
pub struct Committed {
    pub txid: bitcoin::Txid,
    pub opid: OpId,
    pub transition: Transition,
    /// The vouts of this tx the side transitions assign state to. The caller
    /// proves each the enclave's own.
    pub moved_to: Vec<u32>,
}

/// The transitions one contract's bundle must disclose, and the seals they close.
#[derive(Debug, Default, PartialEq, Eq)]
struct Disclosed {
    opids: BTreeSet<String>,
    inputs: usize,
}

/// What the core reads a fascia under: the pinned asset and the image's
/// Bitcoin network.
#[derive(Debug, Clone, Copy)]
pub struct Pin {
    /// `RGB_ASSET_ID`, parsed. Bundles are compared as ids, never as strings.
    pub contract: ContractId,
    /// Only rgb-lib's recipient ids carry it. The mint rules read the
    /// recipient seal from the transition, so no check depends on it.
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

/// The strict-encoded fascia in the request field `field`, decoded as rgb-lib
/// reads its fascia file. A fascia holds a tx and its RGB data, so the PSBT
/// size limit applies to it too (`memory.rs`).
pub fn parse_fascia(bytes: &[u8], field: &str) -> Result<Fascia> {
    if bytes.is_empty() {
        return Err(EnclaveError::CrossCheck(format!(
            "{field} required: rgb-lib strips the RGB data from the PSBT and keeps it in the \
             tx's fascia"
        )));
    }
    crate::config::check_psbt_size(field, bytes)?;
    let bytes = Confined::<Vec<u8>, 0, U24>::try_from(bytes.to_vec())
        .map_err(|e| EnclaveError::CrossCheck(format!("{field} is too large: {e}")))?;
    Fascia::from_strict_serialized::<U24>(bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("{field} is not an rgb-lib fascia: {e}")))
}

/// F3-F6: `fascia`, which `bytes` encodes, is of the PSBT's tx, whose first
/// OP_RETURN commits exactly its bundles. The pinned contract's bundle holds
/// one transition of type `main`. The tx commits at most `max_side` other
/// transitions, and each only moves state to an output of this tx.
///
/// The fascia is dropped before rgb-lib decodes its own copy, so only one
/// decoded fascia is live at a time (`memory.rs`).
pub fn committed_transition(
    psbt: &Psbt,
    fascia: Fascia,
    bytes: &[u8],
    field: &str,
    pin: Pin,
    main: TransitionType,
    max_side: usize,
) -> Result<Committed> {
    let txid = psbt.unsigned_tx.compute_txid();
    assert_opret_host(&psbt.unsigned_tx)?;
    let bundles = fascia.bundles();
    assert_side_count(bundles, max_side)?;
    let transition = main_transition(pinned_bundle(bundles, pin.contract)?, main)?;
    let opid = transition.id();
    let mut disclosed = BTreeMap::new();
    let mut moved_to = BTreeSet::new();
    for (cid, bundle) in bundles {
        for known in bundle.known_transitions.iter() {
            if *cid != pin.contract || known.transition.id() != opid {
                moved_to.extend(move_vouts(&known.transition)?);
            }
        }
        disclosed.insert(cid.to_string(), disclosed_by(bundle));
    }
    drop(fascia);
    let inspection = inspect(psbt, bytes, field, pin)?;
    assert_inspects_as(&inspection, field, &disclosed, txid)?;
    Ok(Committed {
        txid,
        opid,
        transition,
        moved_to: moved_to.into_iter().collect(),
    })
}

/// F4: the fascia discloses the main transition and at most `max_side` more.
/// It runs before rgb-lib reads the fascia, whose work grows with them.
fn assert_side_count(
    bundles: &BTreeMap<ContractId, TransitionBundle>,
    max_side: usize,
) -> Result<()> {
    let disclosed: usize = bundles.values().map(|b| b.known_transitions.len()).sum();
    let side = disclosed.saturating_sub(1);
    if side > max_side {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia discloses {side} transition(s) beside the main one - at most {max_side}"
        )));
    }
    Ok(())
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

/// F4: one of the bundles is the pinned contract's.
fn pinned_bundle(
    bundles: &BTreeMap<ContractId, TransitionBundle>,
    pin: ContractId,
) -> Result<&TransitionBundle> {
    bundles.get(&pin).ok_or_else(|| {
        EnclaveError::CrossCheck(format!(
            "the fascia discloses no bundle of the pinned RGB_ASSET_ID {pin}"
        ))
    })
}

/// F6: the pinned bundle holds exactly one transition of type `main`. That
/// each transition is stored under its own id and of its bundle's contract,
/// and that the input map closes its inputs for it, is what
/// [`assert_inspects_as`] takes from rgb-lib.
fn main_transition(bundle: &TransitionBundle, main: TransitionType) -> Result<Transition> {
    let of_type: Vec<&Transition> = bundle
        .known_transitions
        .iter()
        .map(|known| &known.transition)
        .filter(|transition| transition.transition_type == main)
        .collect();
    let [transition] = of_type.as_slice() else {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia discloses {} transitions of type {} in the pinned asset's bundle - the \
             mint signer signs exactly one",
            of_type.len(),
            main.to_inner()
        )));
    };
    Ok((*transition).clone())
}

/// F6: a side transition is of a move type, assigns one seal per input it
/// closes, as rgb-lib moves an allocation, and every seal is an output of this
/// tx. So it cannot turn one right into many. Returns those vouts.
fn move_vouts(transition: &Transition) -> Result<Vec<u32>> {
    let (opid, ty) = (transition.id(), transition.transition_type);
    if !MOVE_TYPES.contains(&ty) {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia discloses transition {opid} of type {} beside the main one - a side \
             transition only moves state on",
            ty.to_inner()
        )));
    }
    let seals: Vec<_> = transition
        .assignments
        .values()
        .flat_map(|typed| typed.seals())
        .collect();
    if seals.len() != transition.inputs.len() {
        return Err(EnclaveError::CrossCheck(format!(
            "side transition {opid} closes {} seal(s) and assigns {} - a side transition moves \
             each allocation on as one",
            transition.inputs.len(),
            seals.len()
        )));
    }
    let what = format!("state that side transition {opid} moves");
    seals
        .into_iter()
        .map(|seal| witness_vout(&output_seal(seal), &what))
        .collect()
}

/// The transitions `bundle` discloses and the seals they close together.
fn disclosed_by(bundle: &TransitionBundle) -> Disclosed {
    let transitions = bundle.known_transitions.iter().map(|k| &k.transition);
    Disclosed {
        opids: transitions.clone().map(|t| t.id().to_string()).collect(),
        inputs: transitions.map(|t| t.inputs.len()).sum(),
    }
}

/// rgb-lib's wallet-less fascia inspection, over the request bytes in a
/// scratch file: rgb-lib reads a fascia only from a path.
///
/// F5: no entropy is passed, so rgb-lib takes the one the fascia's MPC
/// commitment carries, and refuses a concealed commitment that carries none.
///
/// rgb-lib builds its MPC source from the bundles of the file it reads, in a
/// map of at most 65535 entries. That holds because [`assert_side_count`] has
/// already bounded the transitions, and each bundle holds one or more, and
/// the file carries the same bytes.
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

/// The inspection names the transitions the enclave read, under an opret proof.
///
/// F3: rgb-lib verifies the commitment with the DBC proof of the fascia, so a
/// tapret proof is refused here; F3 then makes the OP_RETURN the host that
/// consensus reads. F5 and F6: the counts bind the whole input map of each
/// bundle, which rgb-lib checks only for the transitions it inspects.
fn assert_inspects_as(
    inspection: &RgbInspection,
    field: &str,
    disclosed: &BTreeMap<String, Disclosed>,
    txid: bitcoin::Txid,
) -> Result<()> {
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
    if inspection.operations.len() != disclosed.len() {
        return refuse(format!(
            "commits {} operations, but the enclave read {} bundles from the same bytes",
            inspection.operations.len(),
            disclosed.len()
        ));
    }
    for operation in &inspection.operations {
        let asset = &operation.asset_id;
        let Some(read) = disclosed.get(asset) else {
            return refuse(format!(
                "commits an operation of asset {asset}, which the enclave did not read from the \
                 same bytes"
            ));
        };
        if operation.committed_transition_count as usize != read.opids.len() {
            return refuse(format!(
                "has an input map for asset {asset} that names {} transitions, but discloses {} \
                 - refusing to sign a bundle that closes seals for a transition the enclave \
                 cannot see",
                operation.committed_transition_count,
                read.opids.len()
            ));
        }
        if operation.committed_input_count as usize != read.inputs {
            return refuse(format!(
                "has an input map for asset {asset} that closes {} seal(s), but its transitions \
                 spend {} - refusing to sign a bundle that closes seals the enclave cannot see",
                operation.committed_input_count, read.inputs
            ));
        }
        let inspected: BTreeSet<String> = operation
            .transitions
            .iter()
            .map(|t| t.opid.clone())
            .collect();
        if inspected != read.opids {
            return refuse(format!(
                "commits transitions {inspected:?} of asset {asset}, not {:?}, which the enclave \
                 read from the same bytes",
                read.opids
            ));
        }
    }
    Ok(())
}

/// M2, RR7: `transition` closes exactly one input, a `mintRight`.
pub fn assert_single_right_input(transition: &Transition, what: &str) -> Result<()> {
    match transition.inputs.iter().collect::<Vec<_>>().as_slice() {
        [input] if input.ty == schemata::OS_MINT => Ok(()),
        inputs => Err(EnclaveError::CrossCheck(format!(
            "{what} must close exactly one mintRight - it closes {inputs:?}"
        ))),
    }
}

/// The vout of a seal on the tx that commits its transition. A blinded seal
/// could be the host's, and a seal on another tx could be any UTXO.
pub fn witness_vout(seal: &OutputSeal, what: &str) -> Result<u32> {
    match seal {
        OutputSeal::Revealed { txid: None, vout } => Ok(*vout),
        OutputSeal::Revealed {
            txid: Some(_),
            vout,
        } => Err(EnclaveError::CrossCheck(format!(
            "{what} is on vout {vout} of another transaction - it must be on an output of the \
             transaction that makes it"
        ))),
        OutputSeal::Confidential { secret_seal } => Err(EnclaveError::CrossCheck(format!(
            "{what} is on blinded seal {secret_seal} - the enclave cannot prove where a blinded \
             seal is"
        ))),
    }
}

#[cfg(test)]
mod tests;
