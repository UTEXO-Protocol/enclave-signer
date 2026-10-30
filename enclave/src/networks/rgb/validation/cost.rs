//! Bounds the work rgb-lib does on a consignment, before it runs. In phase 1,
//! before any witness is checked, it checks each BFA transition against the
//! whole witness tx, anchor and input map of its bundle, hashes every opout
//! into its operation id more than once, and the whole genesis once per
//! operation. For a listed asset it walks the operations DAG once per origin.
//! Each superlinear part has its cap, and all of them with the file, its opouts
//! and the genesis hashes have one time budget.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rgbstd::containers::Transfer;
use rgbstd::tapret::TapretNodePartner;
use rgbstd::validation::DbcProof;
use rgbstd::{Anchor, KnownTransition, OpId, Opout};

use crate::error::{EnclaveError, Result};

/// Forged bundles at the cap take rgb-lib 1.6 to 2.5 s. The burn of 2810 mints
/// costs 8.5M (`tests/caps.rs`, docs/burn-flow.md).
pub(super) const MAX_WITNESS_CHECK_COST: u64 = 128 * 1_024 * 1_024;

/// 512 transitions in one bundle (one over) take rgb-lib 1.2 s, 2048 take 15.5 s.
/// The burn of 2810 mints costs 11k (`tests/caps.rs`, docs/burn-flow.md).
pub(super) const MAX_BUNDLE_ID_COST: u64 = 256 * 1_024;

/// About 5 s of rgb-lib walk at the measured 45 to 73 ns per step. The burn of
/// 2810 mints costs 14k (`tests/caps.rs`, docs/burn-flow.md).
pub(super) const MAX_REJECT_WALK_COST: u64 = 64 * 1_024 * 1_024;

/// A 12 MiB history of transfers takes rgb-lib 15 s alone, and the caps add up.
/// So the modeled time of file, opouts, genesis hashes and costs is held to 18 s.
pub(super) const MAX_RGB_LIB_NS: u64 = 18_000_000_000;

/// rgb-lib's ns per file byte, per opout, per genesis leaf hashed and per step
/// of each cost, rounded up from release timings on an M-series Mac (`tests/caps.rs`).
const NS_PER_FILE_BYTE: u64 = 1_100;
const NS_PER_OPOUT: u64 = 55_000;
const NS_PER_GENESIS_LEAF: u64 = 15_000;
const NS_PER_WITNESS_STEP: u64 = 14;
const NS_PER_BUNDLE_ID_STEP: u64 = 4_500;
const NS_PER_WALK_STEP: u64 = 75;

/// Refuses a consignment of `file_len` bytes whose witness checks, bundle ids,
/// or reject walk when `listed`, pass a cap, or whose total time would.
pub(super) fn assert_bounded_for_rgb_lib(
    transfer: &Transfer,
    file_len: usize,
    listed: bool,
) -> Result<()> {
    let costs = capped_costs(transfer, listed)?;
    assert_within(
        rgb_lib_ns(file_len, uncapped_costs(transfer), costs),
        MAX_RGB_LIB_NS,
        "ns of rgb-lib time on its file and work together",
        "its file is too large for the work it also asks",
    )
}

/// The witness, bundle id and walk costs, each refused above its cap. The
/// walk is 0 when not `listed`.
fn capped_costs(transfer: &Transfer, listed: bool) -> Result<[u64; 3]> {
    let witness = witness_check_cost(transfer);
    assert_within(
        witness,
        MAX_WITNESS_CHECK_COST,
        "steps to check its transitions against their witness txs",
        "a bundle carries too many transitions or seals for the size of its tx and anchor",
    )?;
    let ids = bundle_id_cost(transfer);
    assert_within(
        ids,
        MAX_BUNDLE_ID_COST,
        "steps to hash its bundle ids",
        "a bundle carries too many transitions for the size of its input map",
    )?;
    if !listed {
        return Ok([witness, ids, 0]);
    }
    let walk = reject_walk_cost(transfer, MAX_REJECT_WALK_COST);
    assert_within(
        walk,
        MAX_REJECT_WALK_COST,
        "steps to check against its reject list",
        "too many origins over too long a history",
    )?;
    Ok([witness, ids, walk])
}

/// The opouts and genesis leaf hashes, which only the time budget bounds.
pub(super) fn uncapped_costs(transfer: &Transfer) -> [u64; 2] {
    [opout_count(transfer), genesis_hash_cost(transfer)]
}

/// rgb-lib's modeled time on a file of `file_len` bytes with `costs`.
pub(super) fn rgb_lib_ns(
    file_len: usize,
    [opouts, genesis]: [u64; 2],
    [witness, ids, walk]: [u64; 3],
) -> u64 {
    [
        (file_len as u64, NS_PER_FILE_BYTE),
        (opouts, NS_PER_OPOUT),
        (genesis, NS_PER_GENESIS_LEAF),
        (witness, NS_PER_WITNESS_STEP),
        (ids, NS_PER_BUNDLE_ID_STEP),
        (walk, NS_PER_WALK_STEP),
    ]
    .into_iter()
    .map(|(units, ns)| units.saturating_mul(ns))
    .fold(0, u64::saturating_add)
}

/// Refuses a `cost` above `cap`; `what` costs it, `why` names the shape.
pub(super) fn assert_within(cost: u64, cap: u64, what: &str, why: &str) -> Result<()> {
    if cost <= cap {
        return Ok(());
    }
    Err(EnclaveError::CrossCheck(format!(
        "consignment would cost {cost} {what} (max {cap}): {why} - refusing to validate"
    )))
}

/// The opouts the genesis and the transitions create, plus those they spend:
/// rgb-consensus merklizes each into its operation id three times or more.
pub(super) fn opout_count(transfer: &Transfer) -> u64 {
    let genesis = transfer.genesis.assignments.iter();
    let created = genesis.map(|(_, a)| u64::from(a.len_u16())).sum();
    known_transitions(transfer)
        .map(|k| {
            let outputs = k.transition.assignments.iter();
            let outputs: u64 = outputs.map(|(_, a)| u64::from(a.len_u16())).sum();
            outputs.saturating_add(k.transition.inputs.len() as u64)
        })
        .fold(created, u64::saturating_add)
}

/// rgb-consensus `validate_state` merklizes every genesis global and
/// assignment into the contract id again for each operation it validates.
pub(super) fn genesis_hash_cost(transfer: &Transfer) -> u64 {
    let genesis = &transfer.genesis;
    let globals = genesis.globals.values().map(|g| g.len() as u64);
    let assigns = genesis.assignments.values().map(|a| u64::from(a.len_u16()));
    let leaves: u64 = globals.chain(assigns).sum();
    let operations = known_transitions(transfer).count() as u64 + 1;
    operations.saturating_mul(leaves)
}

/// Per transition, rgb-consensus `validate_transition` clones, hashes and
/// compares the bundle's whole tx and anchor, then scans its inputs once per seal.
pub(super) fn witness_check_cost(transfer: &Transfer) -> u64 {
    transfer
        .bundles
        .iter()
        .map(|wb| {
            let transitions = &wb.bundle.known_transitions;
            let seals: u64 = transitions
                .iter()
                .map(|k| k.transition.inputs.len() as u64)
                .sum();
            let witness = (wb.tx.total_size() as u64).saturating_add(partner_leaf_len(&wb.anchor));
            let copies = (transitions.len() as u64).saturating_mul(witness);
            copies.saturating_add(seals.saturating_mul(wb.tx.input.len() as u64))
        })
        .fold(0, u64::saturating_add)
}

/// The part of an anchor that grows with the file: a Tapret partner leaf
/// script. The rest is a few keys and hashes, and an MPC path of 31 at most.
fn partner_leaf_len(anchor: &Anchor<DbcProof>) -> u64 {
    let DbcProof::Tapret(proof) = &anchor.dbc_proof else {
        return 0;
    };
    match proof.path_proof.partner_node() {
        Some(TapretNodePartner::RightLeaf(leaf)) => leaf.script.len() as u64,
        _ => 0,
    }
}

/// rgb-consensus hashes the bundle id, a commitment to the whole input map,
/// once per bundle (`next_bundle`) and once per transition.
pub(super) fn bundle_id_cost(transfer: &Transfer) -> u64 {
    transfer
        .bundles
        .iter()
        .map(|wb| {
            let hashes = wb.bundle.known_transitions.len() as u64 + 1;
            hashes.saturating_mul(wb.bundle.input_map.len() as u64)
        })
        .fold(0, u64::saturating_add)
}

/// rgb-lib's walk (`rejected_opouts`) with no list entry to cut it short:
/// one walk per origin, with its own visited set. Counts up to just past `cap`.
pub(super) fn reject_walk_cost(transfer: &Transfer, cap: u64) -> u64 {
    let mut graph = OpGraph::of(transfer);
    // Origins of one operation walk the same way, so each operation walks once.
    let mut origins: BTreeMap<usize, u64> = BTreeMap::new();
    for origin in reject_check_origins(transfer) {
        *origins.entry(graph.node(origin.op)).or_default() += 1;
    }
    let mut seen = vec![0; graph.parents.len()];
    let mut total = 0u64;
    for (walk, (node, count)) in (1..).zip(origins) {
        let budget = ((cap - total) / count).saturating_add(1);
        let steps = graph.walk_steps(node, walk, &mut seen, budget);
        total = total.saturating_add(count.saturating_mul(steps));
        if total > cap {
            break;
        }
    }
    total
}

/// rgb-lib's operations DAG: each operation, and the operations it spends from.
struct OpGraph {
    index: HashMap<OpId, usize>,
    parents: Vec<Vec<usize>>,
}

impl OpGraph {
    fn of(transfer: &Transfer) -> Self {
        let mut graph = Self {
            index: HashMap::new(),
            parents: Vec::new(),
        };
        for known in known_transitions(transfer) {
            let node = graph.node(known.opid);
            let inputs = known
                .transition
                .inputs
                .iter()
                .map(|i| graph.node(i.op))
                .collect();
            graph.parents[node] = inputs;
        }
        graph
    }

    /// The node of `op`, added if new.
    fn node(&mut self, op: OpId) -> usize {
        let next = self.parents.len();
        let node = *self.index.entry(op).or_insert(next);
        if node == next {
            self.parents.push(Vec::new());
        }
        node
    }

    /// The steps of one depth-first walk from `from`, as rgb-lib takes them:
    /// each node popped and each opout it spends. Stops past `budget`.
    fn walk_steps(&self, from: usize, walk: u32, seen: &mut [u32], budget: u64) -> u64 {
        let mut stack = vec![from];
        let mut steps = 0u64;
        while let Some(node) = stack.pop() {
            steps += 1;
            if steps > budget {
                break;
            }
            if seen[node] == walk {
                continue;
            }
            seen[node] = walk;
            steps += self.parents[node].len() as u64;
            stack.extend_from_slice(&self.parents[node]);
        }
        steps
    }
}

/// The inputs and outputs of the terminal operations, as rgb-lib
/// `reject_check_origins` collects them.
fn reject_check_origins(transfer: &Transfer) -> BTreeSet<Opout> {
    let terminal = transfer.terminal_ops();
    let mut origins = BTreeSet::new();
    for known in known_transitions(transfer).filter(|k| terminal.contains(&k.opid)) {
        origins.extend(known.transition.inputs());
        for (ty, assigns) in known.transition.assignments.iter() {
            origins.extend((0..assigns.len_u16()).map(|no| Opout::new(known.opid, *ty, no)));
        }
    }
    origins
}

fn known_transitions(transfer: &Transfer) -> impl Iterator<Item = &KnownTransition> {
    transfer
        .bundles
        .iter()
        .flat_map(|wb| wb.bundle.known_transitions.iter())
}
