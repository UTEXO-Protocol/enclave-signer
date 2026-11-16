//! The core of the mint signer's PSBT rules: the one transition of the pinned
//! contract that a tx commits, read from the fascia rgb-lib writes for that tx
//! (rgb-lib strips the RGB keys from the PSBT). No consignment: each step below
//! is a commitment, so the txid fixes the transition.
//!
//! rgb-lib's wallet-less `inspect_fascia` proves the commitments: the fascia is
//! of the PSBT's tx, that tx commits exactly the bundles the fascia discloses
//! under the entropy the fascia carries, and each bundle commits the
//! transitions it holds. The rules around it are the enclave's: one bundle of
//! the pinned asset, one transition, and an opret host the enclave can read.
//! The rule ids (F3-F6) are those of `docs/mint-flow.md` section 5, Stage 3.

use std::collections::BTreeMap;
use std::str::FromStr;

use amplify::confinement::{Confined, U24};
use bitcoin::psbt::Psbt;
use bitcoin::Transaction;
use rgb_lib::no_wallet::{inspect_fascia, RgbInspection};
use rgb_lib::{BitcoinNetwork, CloseMethod};
use rgbstd::containers::Fascia;
use rgbstd::{ContractId, OpId, Operation, Opout, Transition, TransitionBundle};
use strict_encoding::StrictDeserialize;

use super::validation::OutputSeal;
use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};

/// The one transition of the pinned contract that a tx commits.
#[derive(Debug, Clone)]
pub struct Committed {
    pub txid: bitcoin::Txid,
    pub opid: OpId,
    pub transition: Transition,
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
/// OP_RETURN commits exactly its bundles, and the pinned contract's bundle is
/// one known transition.
///
/// The fascia is dropped before rgb-lib decodes its own copy, so only one
/// decoded fascia is live at a time (`memory.rs`).
pub fn committed_transition(
    psbt: &Psbt,
    fascia: Fascia,
    bytes: &[u8],
    field: &str,
    pin: Pin,
) -> Result<Committed> {
    let txid = psbt.unsigned_tx.compute_txid();
    assert_opret_host(&psbt.unsigned_tx)?;
    let bundle = pinned_bundle(fascia.bundles(), pin.contract)?;
    let transition = disclosed_transition(bundle, pin.contract)?;
    let opid = transition.id();
    drop(fascia);
    let inspection = inspect(psbt, bytes, field, pin)?;
    assert_inspects_as(&inspection, field, pin, opid, &transition, txid)?;
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

/// F4: one bundle, of the pinned contract. F5 binds every bundle anyway, so
/// this is policy.
fn pinned_bundle(
    bundles: &BTreeMap<ContractId, TransitionBundle>,
    pin: ContractId,
) -> Result<&TransitionBundle> {
    match bundles.iter().collect::<Vec<_>>().as_slice() {
        [(cid, bundle)] if **cid == pin => Ok(*bundle),
        [(cid, _)] => Err(EnclaveError::CrossCheck(format!(
            "the fascia discloses a bundle of contract {cid}, not of the pinned RGB_ASSET_ID \
             {pin}"
        ))),
        all => Err(EnclaveError::CrossCheck(format!(
            "the fascia discloses {} contract bundles - exactly one, of the pinned asset",
            all.len()
        ))),
    }
}

/// F6: the bundle holds one transition, of the pinned contract. That it is
/// stored under its own id, and that the input map closes its inputs for it,
/// is what [`assert_inspects_as`] takes from rgb-lib.
fn disclosed_transition(bundle: &TransitionBundle, pin: ContractId) -> Result<Transition> {
    let [known] = bundle.known_transitions.as_slice() else {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia discloses {} transitions in its bundle - the mint signer signs exactly \
             one",
            bundle.known_transitions.len()
        )));
    };
    let transition = &known.transition;
    if transition.contract_id != pin {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia's transition {} belongs to contract {}, not the pinned {pin}",
            transition.id(),
            transition.contract_id
        )));
    }
    Ok(transition.clone())
}

/// rgb-lib's wallet-less fascia inspection, over the request bytes in a
/// scratch file: rgb-lib reads a fascia only from a path.
///
/// F5: no entropy is passed, so rgb-lib takes the one the fascia's MPC
/// commitment carries, and refuses a concealed commitment that carries none.
///
/// rgb-lib builds its MPC source from the bundles of the file it reads, in a
/// map of at most 65535 entries. That holds because [`pinned_bundle`] has
/// already refused every fascia but one that discloses a single bundle, and
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

/// The inspection names the transition the enclave read, under an opret proof.
///
/// F3: rgb-lib verifies the commitment with the DBC proof of the fascia, so a
/// tapret proof is refused here; F3 then makes the OP_RETURN the host that
/// consensus reads. F5 and F6: the counts bind the whole input map, which
/// rgb-lib checks only for the transitions it inspects.
fn assert_inspects_as(
    inspection: &RgbInspection,
    field: &str,
    pin: Pin,
    opid: OpId,
    transition: &Transition,
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
    let [operation] = inspection.operations.as_slice() else {
        return refuse(format!(
            "commits {} operations - exactly one, of the pinned asset",
            inspection.operations.len()
        ));
    };
    if operation.asset_id != pin.contract.to_string() {
        return refuse(format!(
            "commits an operation of asset {}, not of the pinned RGB_ASSET_ID {}",
            operation.asset_id, pin.contract
        ));
    }
    if operation.committed_transition_count != 1 {
        return refuse(format!(
            "has an input map that names {} transitions - refusing to sign a bundle that closes \
             seals for a transition the enclave cannot see",
            operation.committed_transition_count
        ));
    }
    let inputs = transition.inputs.len();
    if operation.committed_input_count as usize != inputs {
        return refuse(format!(
            "has an input map that closes {} seal(s), but transition {opid} spends {inputs} - \
             refusing to sign a bundle that closes seals the enclave cannot see",
            operation.committed_input_count
        ));
    }
    let [inspected] = operation.transitions.as_slice() else {
        return refuse(format!(
            "discloses {} transitions in its bundle - the mint signer signs exactly one",
            operation.transitions.len()
        ));
    };
    if inspected.opid != opid.to_string() {
        return refuse(format!(
            "commits transition {}, not transition {opid}, which the enclave read from the same \
             bytes",
            inspected.opid
        ));
    }
    Ok(())
}

/// The one input `transition` closes, which must be a `mintRight` (M2, RR7).
pub fn single_right_input(transition: &Transition, what: &str) -> Result<Opout> {
    match transition.inputs.iter().collect::<Vec<_>>().as_slice() {
        [input] if input.ty == schemata::OS_MINT => Ok(**input),
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
