//! The core of the mint signer's PSBT rules: the one transition of the pinned
//! contract that a PSBT's tx commits, read from the RGB keys rgb-lib stores in
//! the PSBT. No consignment: each step below is a commitment, so the txid fixes
//! the transition. The rule ids (F2-F6) are those of `docs/mint-flow.md`
//! section 5, Stage 3.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use amplify::confinement::Confined;
use bitcoin::psbt::Psbt;
use bitcoin::Transaction;
use psrgbt::{RgbOutExt, RgbPsbtExt};
use rgbstd::opret::OpretProof;
use rgbstd::rgbcore::commit_verify::mpc::{
    MerkleTree, Message, MultiSource, ProtocolId, MPC_MINIMAL_DEPTH,
};
use rgbstd::rgbcore::commit_verify::{CommitId, TryCommitVerify};
use rgbstd::rgbcore::dbc::Proof;
use rgbstd::validation::DbcProof;
use rgbstd::{ContractId, OpId, Operation, Opout, Transition, TransitionBundle};

use super::validation::OutputSeal;
use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};

/// The one transition of the pinned contract that a PSBT's tx commits.
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

/// F3-F6: the tx commits, in its first OP_RETURN, exactly the bundles the
/// PSBT discloses, and the pinned contract's bundle is one known transition.
pub fn committed_transition(psbt: &Psbt, pin: ContractId) -> Result<Committed> {
    let host = opret_host(&psbt.unsigned_tx)?;
    let bundles = psbt.rgb_bundles().map_err(|e| {
        EnclaveError::CrossCheck(format!("PSBT RGB data does not decode to bundles: {e}"))
    })?;
    let bundle = pinned_bundle(&bundles, pin)?;
    assert_commits_exactly(psbt, host, &bundles)?;
    let (opid, transition) = disclosed_transition(bundle, pin)?;
    Ok(Committed {
        txid: psbt.unsigned_tx.compute_txid(),
        opid,
        transition,
    })
}

/// F3: consensus reads the commitment from the first OP_RETURN or P2TR output.
/// A P2TR first would make it a tapret host that our opret check never sees.
fn opret_host(tx: &Transaction) -> Result<usize> {
    let host = tx
        .output
        .iter()
        .position(|out| out.script_pubkey.is_op_return() || out.script_pubkey.is_p2tr());
    match host {
        Some(i) if tx.output[i].script_pubkey.is_op_return() => Ok(i),
        Some(i) => Err(EnclaveError::CrossCheck(format!(
            "PSBT output {i} is a P2TR before the OP_RETURN, so RGB consensus reads a tapret \
             commitment there - refusing to sign"
        ))),
        None => Err(EnclaveError::CrossCheck(
            "PSBT has no OP_RETURN output to commit its RGB bundle".into(),
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
            "PSBT commits a bundle of contract {cid}, not of the pinned RGB_ASSET_ID {pin}"
        ))),
        all => Err(EnclaveError::CrossCheck(format!(
            "PSBT commits {} contract bundles - exactly one, of the pinned asset",
            all.len()
        ))),
    }
}

/// F5: rebuilds the MPC tree from the disclosed bundles and the host's entropy
/// and checks its root is the opret commitment. A hidden bundle changes the
/// root. The PSBT's own MPC message, commitment and proof keys are not read.
fn assert_commits_exactly(
    psbt: &Psbt,
    host: usize,
    bundles: &BTreeMap<ContractId, TransitionBundle>,
) -> Result<()> {
    let entropy = psbt
        .outputs
        .get(host)
        .and_then(|output| output.mpc_entropy())
        .ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "PSBT output {host} hosts the commitment but carries no MPC entropy"
            ))
        })?;
    let messages = bundles
        .iter()
        .map(|(cid, bundle)| (ProtocolId::from(*cid), Message::from(bundle.bundle_id())));
    let source = MultiSource {
        min_depth: MPC_MINIMAL_DEPTH,
        messages: Confined::try_from_iter(messages)
            .map_err(|e| EnclaveError::CrossCheck(format!("PSBT MPC messages: {e}")))?,
        static_entropy: Some(entropy),
    };
    let tree = MerkleTree::try_commit(&source)
        .map_err(|e| EnclaveError::CrossCheck(format!("PSBT MPC tree: {e}")))?;
    DbcProof::Opret(OpretProof::default())
        .verify(&tree.commit_id(), &psbt.unsigned_tx)
        .map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "the OP_RETURN does not commit exactly the bundles the PSBT discloses: {e} - \
                 refusing to sign state moves the enclave cannot see"
            ))
        })
}

/// F6: the bundle holds one transition, stored under its own id, of the
/// pinned contract, and its input map is exactly that transition's inputs.
fn disclosed_transition(bundle: &TransitionBundle, pin: ContractId) -> Result<(OpId, Transition)> {
    let [known] = bundle.known_transitions.as_slice() else {
        return Err(EnclaveError::CrossCheck(format!(
            "PSBT discloses {} transitions in its bundle - the mint signer signs exactly one",
            bundle.known_transitions.len()
        )));
    };
    let transition = &known.transition;
    let id = transition.id();
    if id != known.opid {
        return Err(EnclaveError::CrossCheck(format!(
            "PSBT stores a transition under opid {} but its id is {id}",
            known.opid
        )));
    }
    if transition.contract_id != pin {
        return Err(EnclaveError::CrossCheck(format!(
            "PSBT transition {id} belongs to contract {}, not the pinned {pin}",
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
            "PSBT input map closes {} seal(s), but transition {id} spends {} - refusing to sign \
             a bundle that closes seals the enclave cannot see",
            keys.len(),
            inputs.len()
        )));
    }
    if let Some(other) = bundle.input_map.values().find(|opid| **opid != id) {
        return Err(EnclaveError::CrossCheck(format!(
            "PSBT input map assigns a seal to transition {other}, not to the disclosed {id}"
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
