//! The core of the mint signer's PSBT rules: the one transition of the pinned
//! contract that a tx commits, read from the fascia rgb-lib writes for that tx
//! (rgb-lib strips the RGB keys from the PSBT). No consignment: each step below
//! is a commitment, so the txid fixes the transition. The rule ids (F3-F6) are
//! those of `docs/mint-flow.md` section 5, Stage 3.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use amplify::confinement::{Confined, U24};
use bitcoin::Transaction;
use rgbstd::containers::Fascia;
use rgbstd::opret::OpretProof;
use rgbstd::rgbcore::commit_verify::mpc::{
    MerkleTree, Message, MultiSource, ProtocolId, MPC_MINIMAL_DEPTH,
};
use rgbstd::rgbcore::commit_verify::{CommitId, TryCommitVerify};
use rgbstd::rgbcore::dbc::Proof;
use rgbstd::validation::DbcProof;
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

/// `RGB_ASSET_ID`, parsed. Bundles are compared as ids, never as strings.
pub fn pinned_contract(cfg: &BridgeConfig) -> Result<ContractId> {
    if cfg.rgb_asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "asset-identity pin missing: RGB_ASSET_ID is not configured - refusing to sign for \
             an unpinned asset"
                .into(),
        ));
    }
    ContractId::from_str(&cfg.rgb_asset_id).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "RGB_ASSET_ID {} is not a contract id: {e}",
            cfg.rgb_asset_id
        ))
    })
}

/// The strict-encoded fascia in the request field `field`, decoded as rgb-lib
/// reads its fascia file. Capped at U24 (16 MiB), below the 24 MiB frame.
pub fn parse_fascia(bytes: &[u8], field: &str) -> Result<Fascia> {
    if bytes.is_empty() {
        return Err(EnclaveError::CrossCheck(format!(
            "{field} required: rgb-lib strips the RGB data from the PSBT and keeps it in the \
             tx's fascia"
        )));
    }
    let bytes = Confined::<Vec<u8>, 0, U24>::try_from(bytes.to_vec())
        .map_err(|e| EnclaveError::CrossCheck(format!("{field} is too large: {e}")))?;
    Fascia::from_strict_serialized::<U24>(bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("{field} is not an rgb-lib fascia: {e}")))
}

/// F3-F6: `fascia` is of `tx`, whose first OP_RETURN commits exactly its
/// bundles, and the pinned contract's bundle is one known transition.
pub fn committed_transition(
    tx: &Transaction,
    fascia: &Fascia,
    pin: ContractId,
) -> Result<Committed> {
    let txid = tx.compute_txid();
    if fascia.witness_id() != txid {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia is of tx {}, not of the PSBT's tx {txid} - refusing to sign a tx whose \
             RGB data the enclave cannot see",
            fascia.witness_id()
        )));
    }
    assert_opret_host(tx)?;
    let bundles = fascia.bundles();
    let bundle = pinned_bundle(bundles, pin)?;
    assert_commits_exactly(tx, fascia, bundles)?;
    let (opid, transition) = disclosed_transition(bundle, pin)?;
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

/// F5: the MPC tree of every fascia bundle under its entropy gives the opret
/// commitment. Unlike rgb-lib, the fascia's DBC proof is not read: F3 rules out a tapret.
fn assert_commits_exactly(
    tx: &Transaction,
    fascia: &Fascia,
    bundles: &BTreeMap<ContractId, TransitionBundle>,
) -> Result<()> {
    let entropy = fascia
        .seal_witness()
        .mpc_merkle_block
        .entropy()
        .ok_or_else(|| {
            EnclaveError::CrossCheck(
                "the fascia's MPC block carries no MPC entropy to rebuild the commitment".into(),
            )
        })?;
    let messages = bundles
        .iter()
        .map(|(cid, bundle)| (ProtocolId::from(*cid), Message::from(bundle.bundle_id())));
    let source = MultiSource {
        min_depth: MPC_MINIMAL_DEPTH,
        messages: Confined::try_from_iter(messages)
            .map_err(|e| EnclaveError::CrossCheck(format!("fascia MPC messages: {e}")))?,
        static_entropy: Some(entropy),
    };
    let tree = MerkleTree::try_commit(&source)
        .map_err(|e| EnclaveError::CrossCheck(format!("fascia MPC tree: {e}")))?;
    DbcProof::Opret(OpretProof::default())
        .verify(&tree.commit_id(), tx)
        .map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "the OP_RETURN does not commit exactly the bundles the fascia discloses: {e} - \
                 refusing to sign state moves the enclave cannot see"
            ))
        })
}

/// F6: the bundle holds one transition, stored under its own id, of the
/// pinned contract, and its input map is exactly that transition's inputs.
fn disclosed_transition(bundle: &TransitionBundle, pin: ContractId) -> Result<(OpId, Transition)> {
    let [known] = bundle.known_transitions.as_slice() else {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia discloses {} transitions in its bundle - the mint signer signs exactly \
             one",
            bundle.known_transitions.len()
        )));
    };
    let transition = &known.transition;
    let id = transition.id();
    if id != known.opid {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia stores a transition under opid {} but its id is {id}",
            known.opid
        )));
    }
    if transition.contract_id != pin {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia's transition {id} belongs to contract {}, not the pinned {pin}",
            transition.contract_id
        )));
    }
    assert_input_map_is(bundle, transition, id)?;
    Ok((id, transition.clone()))
}

/// The bundle id commits only the input map, so each entry must close an
/// input of the disclosed transition, for that transition.
fn assert_input_map_is(bundle: &TransitionBundle, transition: &Transition, id: OpId) -> Result<()> {
    let inputs: BTreeSet<Opout> = transition.inputs.iter().copied().collect();
    let keys: BTreeSet<Opout> = bundle.input_map.keys().copied().collect();
    if keys != inputs {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia's input map closes {} seal(s), but transition {id} spends {} - refusing \
             to sign a bundle that closes seals the enclave cannot see",
            keys.len(),
            inputs.len()
        )));
    }
    if let Some(other) = bundle.input_map.values().find(|opid| **opid != id) {
        return Err(EnclaveError::CrossCheck(format!(
            "the fascia's input map assigns a seal to transition {other}, not to the disclosed \
             {id}"
        )));
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
