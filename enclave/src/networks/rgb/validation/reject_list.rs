//! The BFA reject list, with rgb-lib 98a8af6 semantics (`api/evm.rs`
//! `RejectListLog::decisions`, `wallet/online.rs` `check_dag`).
//!
//! The genesis may name an `IRgbRejectList` contract. Each entry rejects or
//! allows one opout. An opout is refused when a rejected opout is in its
//! history on a path that no allowed opout cuts first. The server reads the
//! list over the pinned EVM RPC; this module only decides.

use std::collections::{BTreeMap, BTreeSet};

use amplify::{ByteArray, Wrapper};
use rgbstd::containers::Transfer;
use rgbstd::{Assignments, ExposedSeal, Operation, Opout};

use super::types::ValidatedConsignment;
use crate::error::{EnclaveError, Result};

/// One operation output: OpId, assignment type and output number, the
/// layout of the contract's `Entry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpoutKey {
    pub op: [u8; 32],
    pub ty: u16,
    pub no: u16,
}

impl From<Opout> for OpoutKey {
    fn from(opout: Opout) -> Self {
        Self {
            op: opout.op.to_byte_array(),
            ty: opout.ty.to_inner(),
            no: opout.no,
        }
    }
}

impl std::fmt::Display for OpoutKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}/{}/{}", hex::encode(self.op), self.ty, self.no)
    }
}

/// The `IRgbRejectList` contract a BFA genesis names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectListContract {
    pub chain_id: u64,
    pub address: [u8; 20],
}

/// One list entry: `reject = false` allows the opout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectListEntry {
    pub opout: OpoutKey,
    pub reject: bool,
}

/// The opouts the list rejects and allows now. Disjoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decisions {
    pub reject: BTreeSet<OpoutKey>,
    pub allow: BTreeSet<OpoutKey>,
}

/// Decisions from the entries in append order, the first `finalized` of them
/// in finalized blocks. The latest finalized entry wins; a pending reject
/// counts at once, a pending allow not at all.
pub fn decisions(entries: &[RejectListEntry], finalized: usize) -> Decisions {
    let (finalized, pending) = entries.split_at(finalized.min(entries.len()));
    let latest: BTreeMap<OpoutKey, bool> = finalized.iter().map(|e| (e.opout, e.reject)).collect();
    let mut out = Decisions {
        reject: pending
            .iter()
            .filter(|e| e.reject)
            .map(|e| e.opout)
            .collect(),
        allow: BTreeSet::new(),
    };
    for (opout, rejected) in latest {
        if rejected {
            out.reject.insert(opout);
        } else if !out.reject.contains(&opout) {
            out.allow.insert(opout);
        }
    }
    out
}

/// What a reject-list check needs from a validated consignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectScope {
    pub list: RejectListContract,
    pub history: OpoutGraph,
    pub settling_inputs: Vec<OpoutKey>,
    pub settling_outputs: Vec<OpoutKey>,
}

impl RejectScope {
    /// The scope of the settling transition `settling` over `transfer`.
    pub(super) fn new(
        list: RejectListContract,
        transfer: &Transfer,
        settling: [u8; 32],
        settling_inputs: Vec<OpoutKey>,
    ) -> Self {
        let history = OpoutGraph::of(transfer);
        let settling_outputs = history.outputs_of(settling).collect();
        Self {
            list,
            history,
            settling_inputs,
            settling_outputs,
        }
    }
}

/// The consensus opouts DAG without its edges: an opout's parents are the
/// inputs of the operation that made it. Linear in the consignment, where
/// the DAG holds inputs x outputs edges per transition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpoutGraph {
    opouts: BTreeSet<OpoutKey>,
    inputs: BTreeMap<[u8; 32], Vec<OpoutKey>>,
}

impl OpoutGraph {
    /// The genesis and every transition consensus validated.
    fn of(transfer: &Transfer) -> Self {
        let mut graph = Self::default();
        let genesis = transfer.genesis.id().to_byte_array();
        graph.add(
            genesis,
            Vec::new(),
            opouts(genesis, &transfer.genesis.assignments),
        );
        for known in transfer
            .bundles
            .iter()
            .flat_map(|wb| &wb.bundle.known_transitions)
        {
            let op = known.opid.to_byte_array();
            let inputs = known.transition.inputs.iter().copied().map(Into::into);
            graph.add(
                op,
                inputs.collect(),
                opouts(op, &known.transition.assignments),
            );
        }
        graph
    }

    /// Adds operation `op` with its inputs and the opouts it makes.
    pub fn add(
        &mut self,
        op: [u8; 32],
        inputs: Vec<OpoutKey>,
        outputs: impl IntoIterator<Item = OpoutKey>,
    ) {
        self.opouts.extend(outputs);
        self.inputs.insert(op, inputs);
    }

    pub fn contains(&self, opout: &OpoutKey) -> bool {
        self.opouts.contains(opout)
    }

    /// The parents of every opout of `op`.
    pub fn inputs_of(&self, op: &[u8; 32]) -> &[OpoutKey] {
        self.inputs.get(op).map(Vec::as_slice).unwrap_or_default()
    }

    fn outputs_of(&self, op: [u8; 32]) -> impl Iterator<Item = OpoutKey> + '_ {
        let first = OpoutKey { op, ty: 0, no: 0 };
        let last = OpoutKey {
            op,
            ty: u16::MAX,
            no: u16::MAX,
        };
        self.opouts.range(first..=last).copied()
    }
}

/// An opout per assignment of `op`.
fn opouts<S: ExposedSeal>(op: [u8; 32], assignments: &Assignments<S>) -> Vec<OpoutKey> {
    assignments
        .iter()
        .flat_map(|(ty, typed)| {
            let ty = ty.to_inner();
            (0..typed.len_u16()).map(move |no| OpoutKey { op, ty, no })
        })
        .collect()
}

/// The first of `check` whose history reaches a rejected opout before an
/// allowed one, as rgb-lib `check_dag` decides. An opout missing from the
/// history is an error.
pub fn first_rejected(
    history: &OpoutGraph,
    decisions: &Decisions,
    check: &[OpoutKey],
) -> Result<Option<OpoutKey>> {
    let mut walk = Walk::default();
    for start in check {
        if !history.contains(start) {
            return Err(EnclaveError::CrossCheck(format!(
                "opout {start} is not in the consignment's history graph - refusing to sign"
            )));
        }
        if walk.reaches_reject(history, decisions, *start) {
            return Ok(Some(*start));
        }
    }
    Ok(None)
}

/// A depth-first walk shared by all start opouts. A node a clean walk saw
/// reaches no reject, and each operation's inputs are pushed once, so the
/// whole check is linear in the history.
#[derive(Default)]
struct Walk {
    visited: BTreeSet<OpoutKey>,
    expanded: BTreeSet<[u8; 32]>,
}

impl Walk {
    fn reaches_reject(
        &mut self,
        history: &OpoutGraph,
        decisions: &Decisions,
        start: OpoutKey,
    ) -> bool {
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            // The consensus DAG has no node for an opout outside the history.
            if !history.contains(&node)
                || !self.visited.insert(node)
                || decisions.allow.contains(&node)
            {
                continue;
            }
            if decisions.reject.contains(&node) {
                return true;
            }
            if self.expanded.insert(node.op) {
                stack.extend(history.inputs_of(&node.op));
            }
        }
        false
    }
}

/// Reads a list's current decisions. The server reads it over the pinned EVM
/// RPC; a build without one passes `None` and refuses an asset with a list.
pub type RejectListReader<'a> = &'a dyn Fn(&RejectListContract) -> Result<Decisions>;

/// The opouts a path checks, as rgb-lib does on its side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCheck {
    /// A release: the units the settling burn destroys. The change stays on
    /// the split transfer, which is not released, so it does not count.
    SettlingInputs,
    /// A mint: its right lineage, and the outputs its recipient checks.
    SettlingInputsAndOutputs,
}

/// Refuses the settling transition if the reject list reaches it. No-op for an
/// asset without a list. Run it after the asset bind, so only the pinned
/// asset's list is ever read.
pub fn assert_not_rejected(
    validated: &ValidatedConsignment,
    reader: Option<RejectListReader<'_>>,
    check: RejectCheck,
) -> Result<()> {
    let Some(scope) = &validated.reject_scope else {
        return Ok(());
    };
    let reader = reader.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "the asset declares a reject list, but this build cannot read it - refusing to sign"
                .into(),
        )
    })?;
    let decisions = reader(&scope.list)?;
    let mut checked = scope.settling_inputs.clone();
    if check == RejectCheck::SettlingInputsAndOutputs {
        checked.extend(&scope.settling_outputs);
    }
    match first_rejected(&scope.history, &decisions, &checked)? {
        None => Ok(()),
        Some(opout) => Err(EnclaveError::CrossCheck(format!(
            "reject list: opout {opout} descends from an opout the reject list 0x{} on chain {} \
             rejects - refusing to sign",
            hex::encode(scope.list.address),
            scope.list.chain_id
        ))),
    }
}
