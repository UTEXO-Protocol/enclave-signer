//! Tests for all of `validation/`. They are in one file because they share
//! the generated consignments (`test_support::bfa_consignment`).

use std::cell::RefCell;
use std::collections::BTreeMap;

use amplify::Wrapper;
use bitcoin::OutPoint;
use rgbstd::containers::FileContent;
use rgbstd::contract::AllocatedState;
use rgbstd::vm::WitnessPos;
use rgbstd::{BuilderSeal, GraphSeal, RevealedValue};
#[cfg(rgb_to_evm)]
use sha3::{Digest, Keccak256};

use super::asset_bind::*;
use super::bfa::*;
use super::consignment::*;
use super::indexer::*;
use super::reject_list::*;
use super::schema::*;
#[cfg(rgb_to_evm)]
use super::source::*;
use super::types::*;
use super::witness::*;
use crate::config::BridgeConfig;
use crate::error::Result;
use crate::test_support::bfa_consignment::{self as gen, History, Issue, Utxo};

/// The Bridge the generated assets name, and its chain.
const BRIDGE: [u8; 20] = [0xB1; 20];
const EVM_CHAIN_ID: u64 = 42161;
/// The burner's EVM payout address.
const PAYEE: [u8; 20] = [0x43; 20];
const MINTED: u64 = 100_000;

/// The outpoint of the genesis mint right.
fn right_utxo() -> OutPoint {
    gen::outpoint(0xA0, 0)
}

fn issue() -> History {
    History::issue(Issue::new(EVM_CHAIN_ID, BRIDGE, vec![right_utxo()]))
}

/// A mint of `MINTED` units to a revealed seal, as a burner holds them.
fn minted() -> (History, Utxo) {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let units = history.mint_owned(right, MINTED, 90);
    (history, units)
}

/// A mint, then a burn of `burned` with the rest as change.
fn burn_history(burned: Option<u64>, reason: Option<[u8; 32]>) -> (History, gen::Committed) {
    let (mut history, units) = minted();
    let burn = history.burn(units, MINTED, burned, reason);
    (history, burn)
}

fn burn_bytes() -> Vec<u8> {
    burn_history(Some(60_000), Some(gen::burn_reason_for(PAYEE)))
        .0
        .consignment(vec![])
}

fn validator() -> RgbValidator {
    RgbValidator::new("tcp://indexer.invalid:1".into(), "regtest").unwrap()
}

fn lock_for(anchor: &MintAnchor) -> VerifiedLock {
    VerifiedLock {
        mint_opid: anchor.opid,
        minted: anchor.amount,
        operation_id: [0xd0; 32],
        net_amount: anchor.amount,
    }
}

/// Binds every anchor to a lock with its own `(OpId, amount)`.
fn bind_all(bridge: &BfaBridge, anchors: &[MintAnchor]) -> Result<BoundAnchors> {
    Ok(BoundAnchors {
        evm_chain_id: bridge.chain_id,
        locks: anchors.iter().map(lock_for).collect(),
    })
}

fn validate(bytes: &[u8]) -> Result<ValidatedConsignment> {
    validate_bound(bytes, Some(&bind_all))
}

/// Validates on the burn path's terms, with every witness of `bytes` mined.
fn validate_bound(bytes: &[u8], bind: Option<AnchorBinder<'_>>) -> Result<ValidatedConsignment> {
    let chain = mined(&witness_ids(bytes));
    validator().validate_consignment(bytes, bind, &on_chain(&chain))
}

/// The burn path's check: no witness may be unmined.
fn on_chain(chain: &dyn ConfirmedWitnesses) -> WitnessCheck<'_> {
    WitnessCheck {
        chain,
        allow_unbroadcast_last: false,
        infer_spent_ancestors: false,
    }
}

/// The witness txids of `bytes`, in bundle order. Empty if they do not load.
fn witness_ids(bytes: &[u8]) -> Vec<bitcoin::Txid> {
    rgbstd::containers::Transfer::load(std::io::Cursor::new(bytes))
        .map(|t| t.bundles.iter().map(|wb| wb.witness_id()).collect())
        .unwrap_or_default()
}

/// `txids` mined deep enough, at increasing heights.
fn mined(txids: &[bitcoin::Txid]) -> BTreeMap<bitcoin::Txid, WitnessPos> {
    txids
        .iter()
        .zip(100u32..)
        .map(|(txid, height)| {
            let height = std::num::NonZeroU32::new(height).unwrap();
            (*txid, WitnessPos::bitcoin(height, 1_700_000_000).unwrap())
        })
        .collect()
}

fn error_of(result: Result<ValidatedConsignment>) -> String {
    result
        .expect_err("the consignment must be refused")
        .to_string()
}

// ===== format and schema =====

#[test]
fn rejects_invalid_bytes() {
    let err = error_of(validate(b"not-a-consignment"));
    assert!(err.contains("deserialization failed"), "{err}");
}

/// The V0 BFA burn of the old stack: a hard cutover refuses it.
#[test]
fn rejects_a_v0_consignment() {
    let v0 = include_bytes!("../../../../tests/fixtures/legacy_v0_bfa_burn.rgbc");
    let err = error_of(validate(v0));
    assert!(err.contains("deserialization failed"), "{err}");
}

/// Only a TFR file: the validated copy (VTF) and a contract (CON) are refused.
#[test]
fn rejects_other_containers() {
    let tfr = burn_bytes();
    for magic in [b"VTF", b"CON"] {
        let mut bytes = tfr.clone();
        bytes[4..7].copy_from_slice(magic);
        let err = error_of(validate(&bytes));
        assert!(err.contains("deserialization failed"), "{err}");
    }
}

/// BFA is the only schema the enclave validates.
#[test]
fn rejects_a_non_bfa_schema() {
    let mut transfer = issue().transfer_with(vec![]);
    transfer.genesis.schema_id = schemata::CFA_SCHEMA_ID;
    let err = error_of(validate(&gen::save(&transfer)));
    assert!(err.contains("validates only the bridged fungible"), "{err}");
}

// ===== reject list =====

const LIST: [u8; 20] = [0x4e; 20];

/// An asset whose genesis names a reject list on the bridge's chain.
fn listed() -> History {
    History::issue(Issue {
        reject_list: Some(gen::evm_reject_list(EVM_CHAIN_ID, LIST)),
        ..Issue::new(EVM_CHAIN_ID, BRIDGE, vec![right_utxo()])
    })
}

/// A listed asset: a mint, then a burn of 60_000 with change. Returns the
/// genesis right, the minted units and the burn.
fn listed_burn() -> (History, Utxo, Utxo, gen::Committed) {
    let mut history = listed();
    let right = history.genesis_right(0, right_utxo());
    let units = history.mint_owned(right, MINTED, 90);
    let burn = history.burn(
        units,
        MINTED,
        Some(60_000),
        Some(gen::burn_reason_for(PAYEE)),
    );
    (history, right, units, burn)
}

fn key(opout: rgbstd::Opout) -> OpoutKey {
    opout.into()
}

/// The hand decode of an EVM list location equals its strict encoding.
#[test]
fn evm_reject_list_decodes_as_its_strict_encoding() {
    use strict_encoding::StrictSerialize;
    let location = gen::evm_reject_list(0x0102_0304_0506_0708, LIST);
    let bytes = location.to_strict_serialized::<64>().unwrap();
    let mut expected = vec![1u8];
    expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
    expected.extend_from_slice(&LIST);
    assert_eq!(bytes.as_slice(), expected.as_slice());
    assert_eq!(
        reject_list(&listed().genesis).unwrap(),
        Some(RejectListContract {
            chain_id: EVM_CHAIN_ID,
            address: LIST
        })
    );
}

/// The enclave has no egress to a URL, and its host would be untrusted.
#[test]
fn url_reject_list_is_refused() {
    use rgbstd::stl::RejectListLocation;
    let url = "https://example.com/list".parse().unwrap();
    let history = History::issue(Issue {
        reject_list: Some(RejectListLocation::Url(url)),
        ..Issue::new(EVM_CHAIN_ID, BRIDGE, vec![right_utxo()])
    });
    let err = error_of(validate(&history.consignment(vec![])));
    assert!(err.contains("not an EVM contract"), "{err}");
}

#[test]
fn scope_is_none_without_a_list() {
    assert!(validate(&burn_bytes()).unwrap().reject_scope.is_none());
}

#[test]
fn burn_scope_checks_burned_inputs() {
    let (history, right, units, burn) = listed_burn();
    let scope = validate(&history.consignment(vec![]))
        .unwrap()
        .reject_scope
        .unwrap();
    assert_eq!(
        scope.list,
        RejectListContract {
            chain_id: EVM_CHAIN_ID,
            address: LIST
        }
    );
    assert_eq!(scope.settling_inputs, vec![key(units.opout)]);
    let change = rgbstd::Opout::new(burn.opid, schemata::OS_ASSET, 0);
    assert_eq!(scope.settling_outputs, vec![key(change)]);
    // The units descend from the mint, which spent the genesis right.
    assert_eq!(
        scope.history.inputs_of(&key(units.opout).op),
        &[key(right.opout)]
    );
    assert!(scope.history.inputs_of(&key(right.opout).op).is_empty());
}

/// One transfer of `n` rights to `n` rights is n x n edges in the consensus
/// opouts DAG. The scope keeps only the n inputs.
#[test]
fn a_wide_transition_keeps_the_scope_linear() {
    const N: u16 = 200;
    let outpoints: Vec<OutPoint> = (0..N).map(|i| gen::outpoint(0xA0, i.into())).collect();
    let mut history = History::issue(Issue {
        reject_list: Some(gen::evm_reject_list(EVM_CHAIN_ID, LIST)),
        ..Issue::new(EVM_CHAIN_ID, BRIDGE, outpoints.clone())
    });
    let mut wide = history.transition("transfer");
    for no in 0..N {
        let right = history.genesis_right(no, outpoints[no as usize]);
        let seal = GraphSeal::with_blinded_vout(1u32, 0x3000 + u64::from(no));
        wide = wide
            .add_input(right.opout, AllocatedState::Void)
            .unwrap()
            .add_rights("mintRight", seal)
            .unwrap();
    }
    let wide = wide.complete_transition().unwrap();
    let wide_op = gen::opid_bytes(rgbstd::Operation::id(&wide));
    history.commit(vec![wide], outpoints, vec![gen::dust(6)]);

    let scope = validate(&history.consignment(vec![]))
        .unwrap()
        .reject_scope
        .unwrap();
    assert_eq!(scope.settling_inputs.len(), usize::from(N));
    assert_eq!(scope.settling_outputs.len(), usize::from(N));
    assert_eq!(scope.history.inputs_of(&wide_op).len(), usize::from(N));
    let rejected = key(history.genesis_right(N - 1, right_utxo()).opout);
    let list = Decisions {
        reject: [rejected].into(),
        ..Decisions::default()
    };
    let got = first_rejected(&scope.history, &list, &scope.settling_outputs).unwrap();
    assert_eq!(got, Some(scope.settling_outputs[0]));
}

#[test]
fn mint_scope_checks_inputs_and_outputs() {
    let mut history = listed();
    let right = history.genesis_right(0, right_utxo());
    let units = history.mint_owned(right, MINTED, 90);
    let scope = validate(&history.consignment(vec![]))
        .unwrap()
        .reject_scope
        .unwrap();
    assert_eq!(scope.settling_inputs, vec![key(right.opout)]);
    assert_eq!(scope.settling_outputs, vec![key(units.opout)]);
}

/// A right from a rights send still descends from the genesis right, so a
/// rejected genesis right reaches the mint through the send.
#[test]
fn mint_scope_reaches_the_genesis_right_through_a_rights_send() {
    let mut history = listed();
    let genesis_right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(genesis_right, 3);
    history.mint_owned(rights[1], MINTED, 90);
    let scope = validate(&history.consignment(vec![]))
        .unwrap()
        .reject_scope
        .unwrap();
    assert_eq!(scope.settling_inputs, vec![key(rights[1].opout)]);
    let list = Decisions {
        reject: [key(genesis_right.opout)].into(),
        ..Decisions::default()
    };
    let got = first_rejected(&scope.history, &list, &scope.settling_inputs).unwrap();
    assert_eq!(got, Some(key(rights[1].opout)));
}

/// The reject-list rules, ported from rgb-lib `api/evm.rs` and `check_dag`.
mod reject_list_rules {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn op(n: u8) -> OpoutKey {
        OpoutKey {
            op: [n; 32],
            ty: 4000,
            no: 0,
        }
    }

    fn entry(n: u8, reject: bool) -> RejectListEntry {
        RejectListEntry {
            opout: op(n),
            reject,
        }
    }

    fn set(ns: &[u8]) -> BTreeSet<OpoutKey> {
        ns.iter().map(|n| op(*n)).collect()
    }

    fn log(entries: &[(u8, bool)], finalized: usize) -> Decisions {
        let entries: Vec<_> = entries.iter().map(|(n, r)| entry(*n, *r)).collect();
        decisions(&entries, finalized)
    }

    #[test]
    fn latest_finalized_entry_wins() {
        let got = log(&[(1, true), (2, false), (3, false), (3, true)], 4);
        assert_eq!(got.reject, set(&[1, 3]));
        assert_eq!(got.allow, set(&[2]));
        let got = log(
            &[(1, false), (1, true), (1, false), (2, true), (2, false)],
            5,
        );
        assert!(got.reject.is_empty());
        assert_eq!(got.allow, set(&[1, 2]));
    }

    #[test]
    fn pending_reject_overrides_finalized_allow() {
        let got = log(&[(2, false), (1, true), (2, true)], 1);
        assert_eq!(got.reject, set(&[1, 2]));
        assert!(got.allow.is_empty());
        // A later pending allow does not undo a pending reject.
        let got = log(
            &[(1, false), (1, true), (1, false), (2, true), (2, false)],
            1,
        );
        assert_eq!(got.reject, set(&[1, 2]));
        assert!(got.allow.is_empty());
    }

    #[test]
    fn pending_allow_is_ignored() {
        let got = log(&[(1, true), (2, false), (1, false)], 1);
        assert_eq!(got.reject, set(&[1]));
        assert!(got.allow.is_empty());
    }

    #[test]
    fn reject_of_one_output_leaves_its_sibling() {
        let sibling = OpoutKey { no: 1, ..op(1) };
        let got = log(&[(1, true)], 1);
        assert!(got.reject.contains(&op(1)));
        assert!(!got.reject.contains(&sibling));
    }

    /// `child -> [parents]`, each node the only opout of its own op.
    fn graph(edges: &[(u8, &[u8])]) -> OpoutGraph {
        let mut parents: BTreeMap<u8, Vec<OpoutKey>> = BTreeMap::new();
        for (child, ups) in edges {
            for up in *ups {
                parents.entry(*up).or_default();
            }
            parents
                .entry(*child)
                .or_default()
                .extend(ups.iter().map(|u| op(*u)));
        }
        let mut graph = OpoutGraph::default();
        for (n, inputs) in parents {
            graph.add([n; 32], inputs, [op(n)]);
        }
        graph
    }

    fn rejected(edges: &[(u8, &[u8])], entries: &[(u8, bool)], check: u8) -> bool {
        first_rejected(&graph(edges), &log(entries, entries.len()), &[op(check)])
            .unwrap()
            .is_some()
    }

    #[test]
    fn listed_opout_is_rejected() {
        assert!(rejected(&[(1, &[])], &[(1, true)], 1));
    }

    #[test]
    fn rejected_ancestor_taints_the_opout() {
        assert!(rejected(&[(3, &[2]), (2, &[1])], &[(1, true)], 3));
        assert!(!rejected(&[(3, &[2]), (2, &[1])], &[(9, true)], 3));
    }

    #[test]
    fn allowed_ancestor_shields_its_branch() {
        assert!(!rejected(
            &[(3, &[2]), (2, &[1])],
            &[(1, true), (2, false)],
            3
        ));
    }

    #[test]
    fn shield_does_not_cover_a_second_path() {
        let edges: &[(u8, &[u8])] = &[(4, &[2, 3]), (2, &[1]), (3, &[1])];
        assert!(rejected(edges, &[(1, true), (2, false)], 4));
        assert!(!rejected(edges, &[(1, true), (2, false), (3, false)], 4));
    }

    #[test]
    fn missing_opout_is_an_error() {
        let err = first_rejected(&graph(&[(1, &[])]), &Decisions::default(), &[op(7)])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not in the consignment's history graph"),
            "{err}"
        );
    }

    /// The walk is shared across start opouts: a shield seen first must not
    /// hide a second, unshielded path to the same reject.
    #[test]
    fn shared_walk_still_finds_a_second_path() {
        let edges: &[(u8, &[u8])] = &[(1, &[]), (2, &[1]), (3, &[2]), (4, &[1])];
        let got = first_rejected(
            &graph(edges),
            &log(&[(1, true), (2, false)], 2),
            &[op(3), op(4)],
        )
        .unwrap();
        assert_eq!(got, Some(op(4)));
    }

    /// Every output of one op has the same parents: one reject among the
    /// inputs taints them all, and outputs outside the history are skipped.
    #[test]
    fn outputs_of_one_op_share_its_inputs() {
        let mut history = OpoutGraph::default();
        let input = |no| OpoutKey { no, ..op(1) };
        let output = |no| OpoutKey { no, ..op(2) };
        history.add([1; 32], vec![], (0..3).map(input));
        let inputs = (0..3).map(input).chain([op(9)]).collect();
        history.add([2; 32], inputs, (0..3).map(output));
        let check: Vec<_> = (0..3).map(output).collect();
        let none = first_rejected(&history, &log(&[(9, true)], 1), &check).unwrap();
        assert_eq!(none, None);
        let list = decisions(
            &[RejectListEntry {
                opout: input(2),
                reject: true,
            }],
            1,
        );
        let got = first_rejected(&history, &list, &check).unwrap();
        assert_eq!(got, Some(output(0)));
    }

    /// The first failing opout is named.
    #[test]
    fn names_the_first_rejected_opout() {
        let parents = graph(&[(2, &[]), (3, &[1]), (1, &[])]);
        let got = first_rejected(&parents, &log(&[(1, true)], 1), &[op(2), op(3)]).unwrap();
        assert_eq!(got, Some(op(3)));
    }
}

/// An rc bump that changes the schema id forces a reissue and a new PCR0, so
/// it must fail loudly here.
#[test]
fn bfa_schema_id_is_pinned() {
    assert_eq!(
        schemata::BFA_SCHEMA_ID.to_string(),
        "rgb:sch:Ryl5eQZ3IHrU05e3AWdQZJR4FB5GvxZPy96cwhJiApc#amazon-norway-harris"
    );
    assert_eq!(BFA_RULES.schema().schema_id(), schemata::BFA_SCHEMA_ID);
}

/// The ids the bridge also uses (consignment-utils readers, mint ancestry),
/// and the u16 copies the tests use.
#[test]
fn bfa_ids_the_bridge_shares_are_pinned() {
    use crate::test_support::bfa_ids;
    use rgbstd::{AssignmentType, GlobalStateType, MetaType, TransitionType};
    assert_eq!(schemata::TS_MINT, TransitionType::with(bfa_ids::TS_MINT));
    assert_eq!(schemata::TS_BURN, TransitionType::with(bfa_ids::TS_BURN));
    assert_eq!(
        schemata::TS_TRANSFER,
        TransitionType::with(bfa_ids::TS_TRANSFER)
    );
    assert_eq!(schemata::OS_ASSET, AssignmentType::with(bfa_ids::OS_ASSET));
    assert_eq!(schemata::OS_MINT, AssignmentType::with(bfa_ids::OS_MINT));
    assert_eq!(bfa_ids::TS_MINT, 8013);
    assert_eq!(bfa_ids::TS_BURN, 8010);
    assert_eq!(schemata::GS_BURNED_ASSET, GlobalStateType::with(2015));
    assert_eq!(schemata::GS_BURN_REASON, GlobalStateType::with(3009));
    assert_eq!(schemata::MS_AFTER_BLOCK, MetaType::with(1003));
}

/// A V1 spec with an invalid precision byte is an error, not a panic.
#[test]
fn an_invalid_asset_spec_is_refused_without_a_panic() {
    let mut transfer = issue().transfer_with(vec![]);
    let globals = &mut transfer.genesis.globals;
    let mut bytes = globals.get(&schemata::GS_NOMINAL).expect("a spec")[0]
        .as_slice()
        .to_vec();
    // Ticker, name, precision, then the `None` details tag.
    let precision = bytes.len() - 2;
    bytes[precision] = 0xff;
    let blob = amplify::confinement::SmallBlob::try_from(bytes).unwrap();
    globals
        .insert(
            schemata::GS_NOMINAL,
            rgbstd::GlobalValues::with(rgbstd::RevealedData::new(blob)),
        )
        .unwrap();
    let err = error_of(validate(&gen::save(&transfer)));
    assert!(err.contains("validation failed"), "{err}");
}

// ===== a burn, end to end =====

#[test]
fn validates_a_burn_and_reads_its_globals() {
    let (history, burn) = burn_history(Some(60_000), Some(gen::burn_reason_for(PAYEE)));
    let validated = validate(&history.consignment(vec![])).expect("the burn is valid");

    assert_eq!(validated.contract_id, history.contract_id.to_string());
    assert_eq!(validated.chain_net, "bcrt");
    assert_eq!(validated.witness_txids.len(), 2);
    assert_eq!(
        validated.last_transfer_op_id,
        Some(gen::opid_bytes(burn.opid))
    );
    assert_eq!(validated.last_witness_txid, Some(burn.tx.compute_txid()));
    assert_eq!(
        validated.last_transfer_witness_prevouts,
        burn.tx
            .input
            .iter()
            .map(|i| i.previous_output)
            .collect::<Vec<_>>()
    );

    let last = validated.last_transition.expect("the settling burn");
    assert_eq!(
        rgbstd::TransitionType::with(last.transition_type),
        schemata::TS_BURN
    );
    assert_eq!(last.op_id, burn.opid.to_string());
    assert_eq!(last.burned_asset_amount, Some(60_000));
    assert_eq!(last.burn_reason, Some(gen::burn_reason_for(PAYEE)));
    assert_eq!(last.asset_output_amount, 40_000, "the burner keeps change");

    // The mint's anchor was confirmed against its lock, and only it.
    let mint = history.mints[0];
    assert_eq!(
        validated.mint_locks,
        vec![VerifiedLock {
            mint_opid: gen::opid_bytes(mint.opid),
            minted: MINTED,
            operation_id: [0xd0; 32],
            net_amount: MINTED,
        }]
    );
}

/// A rights send carries no anchor, so only the mint of the burned units is
/// bound.
#[test]
fn a_burn_after_a_rights_send_binds_only_its_mint() {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(right, 3);
    let units = history.mint_owned(rights[2], MINTED, 90);
    history.burn(
        units,
        MINTED,
        Some(MINTED),
        Some(gen::burn_reason_for(PAYEE)),
    );
    let validated = validate(&history.consignment(vec![])).expect("the burn is valid");
    assert_eq!(validated.witness_txids.len(), 3);
    let locked: Vec<[u8; 32]> = validated.mint_locks.iter().map(|l| l.mint_opid).collect();
    assert_eq!(locked, vec![gen::opid_bytes(history.mints[0].opid)]);
}

/// The enclave's burn facts equal the globals rgb-lib's inspection reads from
/// the same bytes.
#[test]
fn burn_facts_agree_with_rgb_lib_inspection() {
    use rgb_lib::no_wallet::TransitionGlobal;
    let bytes = burn_bytes();
    let last = validate(&bytes).unwrap().last_transition.unwrap();

    let path = scratch("burn-facts");
    let inspection = inspect_at(&path, &bytes).unwrap();
    let burn = inspection.witnesses.last().unwrap().operations[0]
        .transitions
        .last()
        .unwrap();
    let burned = burn.globals.iter().find_map(|g| match g {
        TransitionGlobal::BurnedAsset(amount) => Some(*amount),
        _ => None,
    });
    let reason = burn.globals.iter().find_map(|g| match g {
        TransitionGlobal::BurnReason(hex) => Some(hex.clone()),
        _ => None,
    });
    assert_eq!(burned, last.burned_asset_amount);
    assert_eq!(reason, last.burn_reason.map(hex::encode));
}

/// The hand decode of the globals equals their strict encoding.
#[test]
fn burn_globals_decode_as_their_strict_encoding() {
    use rgbstd::stl::BurnReason;
    use strict_encoding::StrictSerialize;

    let amount = rgbstd::Amount::from(0x0102_0304_0506_0708u64);
    assert_eq!(
        amount.to_strict_serialized::<8>().unwrap().as_slice(),
        0x0102_0304_0506_0708u64.to_le_bytes()
    );
    let reason = BurnReason::from(amplify::Bytes32::from_array(gen::burn_reason_for(PAYEE)));
    assert_eq!(
        reason.to_strict_serialized::<32>().unwrap().as_slice(),
        gen::burn_reason_for(PAYEE)
    );
}

/// A burn with no `burnedAsset` destroys nothing: consensus refuses it when it
/// spends asset units.
#[test]
fn refuses_a_burn_without_burned_asset() {
    let (history, _) = burn_history(None, Some(gen::burn_reason_for(PAYEE)));
    let err = error_of(validate(&history.consignment(vec![])));
    assert!(err.contains("validation failed"), "{err}");
}

/// The schema does not require `burnReason`: validation passes and the release
/// bind refuses it (see `evm::crosscheck`).
#[test]
fn a_burn_without_burn_reason_validates_with_no_reason() {
    let (history, _) = burn_history(Some(MINTED), None);
    let last = validate(&history.consignment(vec![]))
        .unwrap()
        .last_transition
        .unwrap();
    assert_eq!(last.burn_reason, None);
    assert_eq!(last.burned_asset_amount, Some(MINTED));
}

/// A burn that declares more, or less, than it destroys is refused.
#[test]
fn refuses_a_burn_that_misstates_what_it_destroyed() {
    for (burned, change) in [(MINTED, 1u64), (MINTED - 1, 0), (1, 0)] {
        let (mut history, units) = minted();
        let mut burn = history
            .transition("burn")
            .add_input(
                units.opout,
                AllocatedState::from(RevealedValue::from(MINTED)),
            )
            .unwrap()
            .add_global_state("burnedAsset", rgbstd::Amount::from(burned))
            .unwrap();
        if change > 0 {
            burn = burn
                .add_fungible_state("assetOwner", GraphSeal::with_blinded_vout(1u32, 7), change)
                .unwrap();
        }
        let burn = burn.complete_transition().unwrap();
        history.commit(vec![burn], vec![units.outpoint], vec![gen::dust(9)]);
        let err = error_of(validate(&history.consignment(vec![])));
        assert!(
            err.contains("validation failed"),
            "{burned}/{change}: {err}"
        );
    }
}

/// A mint, then a transfer that splits the units into two halves on vout 1
/// and vout 2 of its witness tx.
fn minted_in_halves() -> (History, [Utxo; 2]) {
    let (mut history, units) = minted();
    let half = MINTED / 2;
    let split = history
        .transition("transfer")
        .add_input(
            units.opout,
            AllocatedState::from(RevealedValue::from(MINTED)),
        )
        .unwrap()
        .add_fungible_state("assetOwner", GraphSeal::with_blinded_vout(1u32, 1), half)
        .unwrap()
        .add_fungible_state("assetOwner", GraphSeal::with_blinded_vout(2u32, 2), half)
        .unwrap()
        .complete_transition()
        .unwrap();
    let split_opid = rgbstd::Operation::id(&split);
    let tx = history.commit(
        vec![split],
        vec![units.outpoint],
        vec![gen::dust(1), gen::dust(2)],
    );
    let half_at = |no: u16| Utxo {
        opout: rgbstd::Opout::new(split_opid, schemata::OS_ASSET, no),
        outpoint: OutPoint::new(tx.compute_txid(), u32::from(no) + 1),
    };
    (history, [half_at(0), half_at(1)])
}

/// Two burns in the settling bundle: only one could ever be released.
#[test]
fn refuses_two_burns_in_the_last_bundle() {
    let (mut history, halves) = minted_in_halves();
    let half = MINTED / 2;
    let burns = halves
        .iter()
        .map(|units| history.burn_transition(*units, half, Some(half), None))
        .collect();
    let inputs = halves.iter().map(|units| units.outpoint).collect();
    history.commit(burns, inputs, vec![gen::dust(3)]);
    let err = error_of(validate(&history.consignment(vec![])));
    assert!(err.contains("2 burns"), "{err}");
}

/// rgb-lib's burn shape: the burn and a companion transfer in one bundle.
/// In either order, both walks settle the burn and the group holds both.
#[test]
fn settles_the_burn_beside_a_companion_transfer_in_either_order() {
    for burn_first in [true, false] {
        let (mut history, [kept, burned]) = minted_in_halves();
        let half = MINTED / 2;
        let transfer = history
            .transition("transfer")
            .add_input(kept.opout, AllocatedState::from(RevealedValue::from(half)))
            .unwrap()
            .add_fungible_state("assetOwner", GraphSeal::with_blinded_vout(1u32, 3), half)
            .unwrap()
            .complete_transition()
            .unwrap();
        let burn =
            history.burn_transition(burned, half, Some(half), Some(gen::burn_reason_for(PAYEE)));
        let burn_opid = rgbstd::Operation::id(&burn);
        let bundle = if burn_first {
            vec![burn, transfer]
        } else {
            vec![transfer, burn]
        };
        let tx = history.commit(
            bundle,
            vec![kept.outpoint, burned.outpoint],
            vec![gen::dust(3)],
        );

        let validated = validate(&history.consignment(vec![])).expect("burn and transfer");
        let last = validated
            .last_transition
            .clone()
            .expect("the settling burn");
        assert_eq!(
            last.op_id,
            burn_opid.to_string(),
            "burn first: {burn_first}"
        );
        assert_eq!(last.burned_asset_amount, Some(half));
        assert_eq!(last.burn_reason, Some(gen::burn_reason_for(PAYEE)));
        assert_eq!(
            validated.last_transfer_op_id,
            Some(gen::opid_bytes(burn_opid))
        );
        assert_eq!(
            validated.transitions_committed_by(tx.compute_txid()).len(),
            2
        );
    }
}

/// A burn that spends no asset units (here a mint right) cannot declare any
/// burned. The same burn without `burnedAsset` is valid.
#[test]
fn refuses_a_burn_with_no_asset_inputs() {
    for burned in [Some(1_000u64), None] {
        let mut history = issue();
        let right = history.genesis_right(0, right_utxo());
        let mut burn = history
            .transition("burn")
            .add_input(right.opout, AllocatedState::Void)
            .unwrap();
        if let Some(burned) = burned {
            burn = burn
                .add_global_state("burnedAsset", rgbstd::Amount::from(burned))
                .unwrap();
        }
        let burn = burn.complete_transition().unwrap();
        history.commit(vec![burn], vec![right.outpoint], vec![gen::dust(5)]);
        let result = validate(&history.consignment(vec![]));
        match burned {
            Some(_) => {
                let err = error_of(result);
                let errno = format!("Some({})", schemata::ERRNO_BURN_MISMATCH);
                assert!(err.contains(&errno), "{err}");
            }
            None => {
                result.expect("burning the right alone is valid");
            }
        }
    }
}

// ===== mint anchors =====

/// The mint a PSBT signs: its anchor is in the last bundle, it consumes its
/// right, and the right's seal is what the bundle closes.
#[test]
fn reads_a_mint_and_its_anchor() {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let recipient = GraphSeal::with_blinding(gen::outpoint(0xC0, 0).txid, 0u32, 7);
    let secret = recipient.to_secret_seal();
    let mint = history.mint(
        right,
        MINTED,
        90,
        BuilderSeal::Concealed(secret),
        vec![],
        vec![gen::dust(1)],
    );
    let bytes = history.consignment(vec![BuilderSeal::Concealed(secret)]);

    let seen = RefCell::new(Vec::new());
    let record = |bridge: &BfaBridge, anchors: &[MintAnchor]| {
        seen.borrow_mut().extend_from_slice(anchors);
        bind_all(bridge, anchors)
    };
    let validated = validate_bound(&bytes, Some(&record)).expect("the mint is valid");

    assert_eq!(
        *seen.borrow(),
        vec![MintAnchor {
            opid: gen::opid_bytes(mint.opid),
            amount: MINTED,
            after_block: 90,
            in_last_bundle: true,
        }]
    );
    assert!(validated.last_bundle_fully_disclosed);
    assert_eq!(validated.last_closed_seals, vec![right_utxo()]);
    assert!(validated.last_mint_rights.is_empty());
    let last = validated.last_transition.unwrap();
    assert!(is_mint_transition(last.transition_type));
    assert_eq!(last.asset_output_amount, MINTED);
    assert!(matches!(
        last.outputs[0].seal,
        OutputSeal::Confidential { .. }
    ));
}

/// A mint in the old form, which passes its right on to vout 1. Returns that
/// right.
fn old_form_mint() -> (History, Utxo) {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let to = BuilderSeal::from(GraphSeal::with_blinded_vout(2u32, 7));
    let (_, kept) = history.mint_keeping_right(
        right,
        MINTED,
        90,
        to,
        vec![],
        vec![gen::dust(1), gen::dust(2)],
    );
    (history, kept)
}

/// Consensus allows the old form, so the PSBT bind needs the right it passes
/// on to refuse it.
#[test]
fn reads_the_right_an_old_form_mint_passes_on() {
    let (history, _) = old_form_mint();
    let validated = validate(&history.consignment(vec![])).expect("consensus allows it");
    assert_eq!(
        validated.last_mint_rights,
        vec![OutputSeal::Revealed {
            txid: None,
            vout: 1
        }]
    );
}

/// Rights that old-form mints passed on still mint: only the settling
/// transition must consume its right.
#[test]
fn a_mint_on_a_right_an_old_form_mint_passed_on_is_valid() {
    let (mut history, kept) = old_form_mint();
    history.mint_owned(kept, MINTED, 91);
    let validated = validate(&history.consignment(vec![])).expect("the history is valid");
    assert!(validated.last_mint_rights.is_empty());
    assert_eq!(validated.mint_locks.len(), 2);
}

/// A mint of `MINTED` on `right`, to vout 2 of a witness tx that also spends
/// `fee_inputs`.
fn mint_spending(right: Utxo, fee_inputs: Vec<OutPoint>) -> History {
    let mut history = issue();
    let to = BuilderSeal::from(GraphSeal::with_blinded_vout(2u32, 7));
    history.mint(
        right,
        MINTED,
        90,
        to,
        fee_inputs,
        vec![gen::dust(1), gen::dust(2)],
    );
    history
}

/// Consensus refuses a mint whose witness tx does not spend the UTXO of its
/// right. So every tx that commits a mint spends that one UTXO, and only one
/// of them can confirm. `last_closed_seals` relies on it.
#[test]
fn refuses_a_mint_witness_tx_that_does_not_spend_the_mint_right() {
    let right = issue().genesis_right(0, right_utxo());
    let elsewhere = Utxo {
        outpoint: gen::outpoint(0xEE, 0),
        ..right
    };
    let err = error_of(validate(
        &mint_spending(elsewhere, vec![]).consignment(vec![]),
    ));
    assert!(err.contains("does not closes seal"), "{err}");
    assert!(err.contains(&right_utxo().to_string()), "{err}");
}

/// Control: the fee inputs of the mint witness tx do not matter.
#[test]
fn a_mint_witness_tx_may_spend_any_fee_input() {
    let right = issue().genesis_right(0, right_utxo());
    for fee in [gen::outpoint(0xF1, 0), gen::outpoint(0xF2, 3)] {
        let validated = validate(&mint_spending(right, vec![fee]).consignment(vec![]))
            .expect("a different fee input keeps the mint valid");
        assert_eq!(validated.last_closed_seals, vec![right_utxo()]);
    }
}

/// The genesis names the bridge the binder checks.
#[test]
fn the_binder_sees_the_genesis_bridge() {
    let bytes = burn_bytes();
    let seen = RefCell::new(None);
    let record = |bridge: &BfaBridge, anchors: &[MintAnchor]| {
        *seen.borrow_mut() = Some(*bridge);
        bind_all(bridge, anchors)
    };
    validate_bound(&bytes, Some(&record)).unwrap();
    assert_eq!(
        *seen.borrow(),
        Some(BfaBridge {
            chain_id: EVM_CHAIN_ID,
            address: BRIDGE,
        })
    );
}

/// A build with no binder refuses any mint ancestry; it never confirms an
/// anchor blind, and never panics in `finalize`.
#[test]
fn refuses_mint_anchors_without_a_binder() {
    let err = error_of(validate_bound(&burn_bytes(), None));
    assert!(err.contains("binds none"), "{err}");
}

#[test]
fn passes_a_binder_error_through() {
    let refuse = |_: &BfaBridge, _: &[MintAnchor]| -> Result<BoundAnchors> {
        Err(crate::error::EnclaveError::CrossCheck("no deposit".into()))
    };
    let err = error_of(validate_bound(&burn_bytes(), Some(&refuse)));
    assert!(err.contains("no deposit"), "{err}");
}

/// Every anchor needs exactly its own lock: one too few, one too many, or one
/// for another amount is refused.
#[test]
fn refuses_locks_that_do_not_match_the_anchors_one_for_one() {
    let bytes = burn_bytes();
    let none = |bridge: &BfaBridge, _: &[MintAnchor]| {
        Ok(BoundAnchors {
            evm_chain_id: bridge.chain_id,
            locks: vec![],
        })
    };
    let extra = |bridge: &BfaBridge, anchors: &[MintAnchor]| {
        let mut bound = bind_all(bridge, anchors)?;
        bound.locks.push(VerifiedLock {
            mint_opid: [0x77; 32],
            ..lock_for(&anchors[0])
        });
        Ok(bound)
    };
    let other_amount = |bridge: &BfaBridge, anchors: &[MintAnchor]| {
        let mut bound = bind_all(bridge, anchors)?;
        bound.locks[0].minted += 1;
        Ok(bound)
    };
    let binders: [AnchorBinder<'_>; 3] = [&none, &extra, &other_amount];
    for bind in binders {
        let err = error_of(validate_bound(&bytes, Some(bind)));
        assert!(err.contains("exactly its own lock"), "{err}");
    }
}

/// The bound chain id must be the genesis one, or the checked resolver
/// refuses before it confirms anything.
#[test]
fn refuses_locks_bound_on_another_chain() {
    let other_chain = |bridge: &BfaBridge, anchors: &[MintAnchor]| {
        Ok(BoundAnchors {
            evm_chain_id: 1,
            ..bind_all(bridge, anchors)?
        })
    };
    let err = error_of(validate_bound(&burn_bytes(), Some(&other_chain)));
    assert!(err.contains("anchor not confirmed"), "{err}");
}

/// A bundle that commits a transition the consignment does not show.
#[test]
fn reports_a_hidden_transition_in_the_last_bundle() {
    let (mut history, units) = minted();
    let burn = history
        .transition("burn")
        .add_input(
            units.opout,
            AllocatedState::from(RevealedValue::from(MINTED)),
        )
        .unwrap()
        .add_global_state("burnedAsset", rgbstd::Amount::from(MINTED))
        .unwrap()
        .complete_transition()
        .unwrap();
    let mut bundle = gen::bundle_of(vec![burn]);
    let hidden_input = rgbstd::Opout::new(rgbstd::OpId::from([0x99; 32]), schemata::OS_MINT, 0);
    bundle
        .input_map
        .insert(hidden_input, rgbstd::OpId::from([0x98; 32]))
        .unwrap();
    history.commit_bundle(bundle, vec![units.outpoint], vec![gen::dust(5)]);
    let validated = validate(&history.consignment(vec![])).unwrap();
    assert!(!validated.last_bundle_fully_disclosed);
}

// ===== the flat summary =====

#[test]
fn settling_index_takes_the_burn_beside_a_transfer() {
    let burn = |t: &u16| *t == 8010;
    assert_eq!(settling_index(&[8010u16, 10000], burn), Some(0));
    assert_eq!(settling_index(&[10000u16, 8010], burn), Some(1));
    assert_eq!(settling_index(&[10000u16, 8013], burn), Some(1));
    assert_eq!(settling_index::<u16>(&[], burn), None);
}

/// A scratch path of its own for each test.
fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "utexo-enclave-test-{name}-{}.rgb",
        std::process::id()
    ))
}

fn inspected_output(
    assignment: rgb_lib::Assignment,
    seal: OutputSeal,
) -> rgb_lib::no_wallet::RgbOutputInfo {
    let (txid, vout, recipient_id) = match seal {
        OutputSeal::Revealed { txid, vout } => (txid.map(hex::encode), Some(vout), None),
        OutputSeal::Confidential { secret_seal } => (None, None, Some(secret_seal)),
    };
    rgb_lib::no_wallet::RgbOutputInfo {
        txid,
        vout,
        assignment,
        is_concealed: recipient_id.is_some(),
        recipient_id,
        is_ours: None,
        is_terminal: Some(false),
    }
}

fn inspected_transition(
    r#type: rgb_lib::TypeOfTransition,
    outputs: Vec<rgb_lib::no_wallet::RgbOutputInfo>,
) -> rgb_lib::no_wallet::RgbTransitionInfo {
    rgb_lib::no_wallet::RgbTransitionInfo {
        r#type,
        opid: "mint-op".into(),
        inputs: vec![],
        outputs,
        globals: vec![],
        metadata: vec![],
    }
}

const WITNESS: [u8; 32] = [0x77; 32];

fn revealed(txid: Option<[u8; 32]>, vout: u32) -> OutputSeal {
    OutputSeal::Revealed { txid, vout }
}

/// Only fungible units are outputs: rights and other states are not.
#[test]
fn inspected_summary_lists_only_asset_units() {
    use rgb_lib::Assignment;
    let t = inspected_transition(
        rgb_lib::TypeOfTransition::Mint,
        vec![
            inspected_output(Assignment::MintRight, revealed(Some(WITNESS), 1)),
            inspected_output(Assignment::Fungible(500), revealed(Some([0x11; 32]), 2)),
            inspected_output(Assignment::InflationRight(1_000_000), revealed(None, 3)),
            inspected_output(Assignment::NonFungible, revealed(None, 4)),
        ],
    );
    let summary = inspected_summary(&t, &hex::encode(WITNESS), "bcrt").unwrap();
    assert_eq!(
        summary.outputs,
        vec![TransitionOutput {
            assignment_type: schemata::OS_ASSET.to_inner(),
            amount: 500,
            seal: revealed(Some([0x11; 32]), 2),
        }]
    );
    assert_eq!(summary.asset_output_amount, 500);
    assert_eq!(summary.total_output_amount, 500);
    assert_eq!(summary.op_id, "mint-op");
}

#[test]
fn inspected_summary_refuses_an_overflowing_total() {
    use rgb_lib::Assignment;
    let t = inspected_transition(
        rgb_lib::TypeOfTransition::Transfer,
        vec![
            inspected_output(Assignment::Fungible(u64::MAX), revealed(Some(WITNESS), 1)),
            inspected_output(Assignment::Fungible(1), revealed(Some(WITNESS), 2)),
        ],
    );
    let err = inspected_summary(&t, &hex::encode(WITNESS), "bcrt")
        .unwrap_err()
        .to_string();
    assert!(err.contains("output amount overflow"), "{err}");
}

/// Each rgb-lib type maps back to its schema id.
#[test]
fn inspected_summary_keeps_the_schema_transition_type() {
    use rgb_lib::TypeOfTransition as T;
    for (ty, id) in [
        (T::Transfer, schemata::TS_TRANSFER),
        (T::Burn, schemata::TS_BURN),
        (T::Mint, schemata::TS_MINT),
        (T::Inflate, schemata::TS_INFLATION),
    ] {
        let summary = inspected_summary(&inspected_transition(ty, vec![]), "", "bcrt").unwrap();
        assert_eq!(summary.transition_type, id.to_inner(), "{ty:?}");
    }
}

/// rgb-lib fills a witness-relative seal with the witness txid: it reads
/// back as `None`. Another txid stays.
#[test]
fn a_seal_on_the_witness_reads_as_witness_relative() {
    let witness = hex::encode(WITNESS);
    for (txid, expected) in [(WITNESS, None), ([0x11; 32], Some([0x11; 32]))] {
        let t = inspected_transition(
            rgb_lib::TypeOfTransition::Transfer,
            vec![inspected_output(
                rgb_lib::Assignment::Fungible(7),
                revealed(Some(txid), 1),
            )],
        );
        let summary = inspected_summary(&t, &witness, "bcrt").unwrap();
        assert_eq!(summary.outputs[0].seal, revealed(expected, 1));
    }
}

/// A concealed seal reads as the bare `utxob:` seal, without the chain
/// prefix rgb-lib puts on the recipient id. Another chain is refused.
#[test]
fn a_concealed_seal_reads_without_its_chain_prefix() {
    let concealed = |recipient: &str| {
        let t = inspected_transition(
            rgb_lib::TypeOfTransition::Transfer,
            vec![inspected_output(
                rgb_lib::Assignment::Fungible(7),
                OutputSeal::Confidential {
                    secret_seal: recipient.into(),
                },
            )],
        );
        inspected_summary(&t, "", "bcrt")
    };
    let summary = concealed("bcrt:utxob:abc").unwrap();
    assert_eq!(
        summary.outputs[0].seal,
        OutputSeal::Confidential {
            secret_seal: "utxob:abc".into()
        }
    );
    for other in ["bc:utxob:abc", "bcrtutxob:abc", "utxob:abc"] {
        let err = concealed(other).unwrap_err().to_string();
        assert!(err.contains("no bcrt recipient id"), "{other}: {err}");
    }
}

#[test]
fn a_revealed_output_without_a_vout_is_refused() {
    let mut output = inspected_output(rgb_lib::Assignment::Fungible(7), revealed(Some(WITNESS), 1));
    output.vout = None;
    let t = inspected_transition(rgb_lib::TypeOfTransition::Transfer, vec![output]);
    let err = inspected_summary(&t, "", "bcrt").unwrap_err().to_string();
    assert!(err.contains("has no outpoint"), "{err}");
}

#[test]
fn the_flat_summary_refuses_a_contract() {
    let contract = issue().transfer_with(vec![]).into_contract();
    let mut bytes = Vec::new();
    contract.save(&mut bytes).unwrap();
    let err = extract_transition_summary(&bytes).unwrap_err().to_string();
    assert!(err.contains("expected Transfer"), "{err}");
}

#[test]
fn the_flat_summary_refuses_random_bytes() {
    let err = extract_transition_summary(&[0u8; 64])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("rgb-lib consignment inspection failed"),
        "{err}"
    );
}

/// The scratch file is gone after a read, and after a refused one.
#[test]
fn inspection_removes_its_scratch_file() {
    for (name, bytes) in [("removed-ok", burn_bytes()), ("removed-err", vec![0u8; 64])] {
        let path = scratch(name);
        let _ = inspect_at(&path, &bytes);
        assert!(!path.exists(), "{name}");
    }
}

/// A file already at the scratch path is refused and left in place.
#[test]
fn inspection_never_reuses_an_existing_file() {
    let path = scratch("existing");
    std::fs::write(&path, b"someone else's").unwrap();
    let err = inspect_at(&path, &burn_bytes()).unwrap_err().to_string();
    let kept = std::fs::read(&path);
    std::fs::remove_file(&path).unwrap();
    assert!(
        err.contains("could not create the consignment scratch file"),
        "{err}"
    );
    assert_eq!(kept.unwrap(), b"someone else's");
}

/// A BFA `mint` is the only mint shape. It is a signing shape only in the
/// mint/burn flow.
#[test]
fn mint_transitions_are_the_only_mint_shape() {
    assert!(is_mint_transition(8013));
    assert!(!is_mint_transition(10000));
    assert!(!is_mint_transition(8010));
    assert_eq!(
        super::super::flow::is_signing_transition(8013),
        cfg!(feature = "rgb-mint-burn")
    );
}

// ===== the validator and its indexer =====

#[test]
fn rejects_unknown_network() {
    let err = RgbValidator::new("tcp://localhost:1".to_string(), "foonet").unwrap_err();
    assert!(err.to_string().contains("unknown bitcoin network"));
}

#[test]
fn maps_each_network_to_its_rgb_chain_net() {
    for (network, prefix) in [
        ("bitcoin", "bc"),
        ("testnet4", "tb4"),
        ("signet", "sb"),
        ("signetcustom", "sbc"),
        ("regtest", "bcrt"),
    ] {
        let v = RgbValidator::new("tcp://localhost:1".to_string(), network).unwrap();
        assert_eq!(v.chain_net.prefix(), prefix, "{network}");
    }
}

/// A consignment of another network fails consensus.
#[test]
fn refuses_a_consignment_of_another_network() {
    let v = RgbValidator::new("tcp://indexer.invalid:1".into(), "testnet4").unwrap();
    let bytes = burn_bytes();
    let chain = mined(&witness_ids(&bytes));
    let err = error_of(v.validate_consignment(&bytes, Some(&bind_all), &on_chain(&chain)));
    assert!(err.contains("validation failed"), "{err}");
}

#[test]
fn rejects_an_unknown_indexer_scheme() {
    for url in ["ftp://localhost:1", "ws://localhost:1", "localhost:1"] {
        let err = RgbValidator::new(url.to_string(), "regtest").unwrap_err();
        assert!(
            err.to_string().contains("not ssl:// or tcp://"),
            "{url}: {err}"
        );
    }
}

#[test]
fn accepts_an_esplora_url() {
    for url in ["https://esplora.test", "http://127.0.0.1:3000"] {
        RgbValidator::new(url.to_string(), "signet").expect(url);
    }
}

/// A host that accepts the connection and never answers costs at most the
/// socket timeout.
fn stalled_host() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stalled stub");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        // Keep each connection open with no data. An early RST would fail
        // fast for the wrong reason.
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            held.push(stream);
        }
    });
    addr
}

#[test]
fn stalled_electrum_fetch_times_out_instead_of_hanging() {
    let validator = RgbValidator::new(format!("tcp://{}", stalled_host()), "bitcoin")
        .unwrap()
        .with_timeout(2);
    let start = std::time::Instant::now();
    let err = validator
        .fetch_transaction(gen::outpoint(1, 0).txid)
        .unwrap_err();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(60),
        "stalled Electrum must be bounded by the socket timeout: {err}"
    );
}

#[test]
fn stalled_esplora_fetch_times_out_instead_of_hanging() {
    let validator = RgbValidator::new(format!("http://{}", stalled_host()), "bitcoin")
        .unwrap()
        .with_timeout(2);
    let start = std::time::Instant::now();
    let err = validator
        .fetch_transaction(gen::outpoint(1, 0).txid)
        .unwrap_err();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(60),
        "stalled Esplora must be bounded by the HTTP timeout: {err}"
    );
}

/// The burn path reads witness status from its SPV proofs, never the indexer.
#[test]
fn burn_path_validation_makes_no_indexer_call() {
    let validator = RgbValidator::new(format!("tcp://{}", stalled_host()), "regtest")
        .unwrap()
        .with_timeout(30);
    let bytes = burn_bytes();
    let chain = mined(&witness_ids(&bytes));
    let start = std::time::Instant::now();
    validator
        .validate_consignment(&bytes, Some(&bind_all), &on_chain(&chain))
        .unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(20));
}

// ===== on-chain witnesses =====

/// A mint, a transfer of all of it, then a burn of the moved units.
fn burn_after_transfer() -> Vec<u8> {
    let (mut history, units) = minted();
    let moved = history.transfer(units, MINTED);
    history.burn(
        moved,
        MINTED,
        Some(MINTED),
        Some(gen::burn_reason_for(PAYEE)),
    );
    history.consignment(vec![])
}

/// A rights send of the genesis right, then a mint a PSBT would sign on one
/// of the new rights.
fn mint_after_a_rights_send() -> Vec<u8> {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(right, 2);
    history.mint_owned(rights[0], MINTED, 90);
    history.consignment(vec![])
}

/// Every witness but `unmined` mined, checked with `allow_unbroadcast_last`.
fn validate_without(
    bytes: &[u8],
    unmined: bitcoin::Txid,
    allow_unbroadcast_last: bool,
) -> Result<ValidatedConsignment> {
    let mut chain = mined(&witness_ids(bytes));
    chain.remove(&unmined);
    let check = WitnessCheck {
        chain: &chain,
        allow_unbroadcast_last,
        infer_spent_ancestors: allow_unbroadcast_last,
    };
    validator().validate_consignment(bytes, Some(&bind_all), &check)
}

fn display_bytes(txid: bitcoin::Txid) -> [u8; 32] {
    let mut bytes = bitcoin::hashes::Hash::to_byte_array(txid);
    bytes.reverse();
    bytes
}

#[test]
fn a_fully_mined_history_passes() {
    let bytes = burn_after_transfer();
    let validated = validate(&bytes).expect("every witness is mined");
    assert_eq!(validated.witness_txids.len(), 3);
    assert!(validated.non_mined_witness_txids.is_empty());
}

/// Two conflicting off-chain transfers are each valid alone. Only the mined
/// one may back a burn.
#[test]
fn burn_path_refuses_an_unmined_transfer_in_the_history() {
    let bytes = burn_after_transfer();
    let transfer = witness_ids(&bytes)[1];
    let err = error_of(validate_without(&bytes, transfer, false));
    assert!(err.contains("not confirmed on chain"), "{err}");
    assert!(err.contains(&transfer.to_string()), "{err}");
}

#[test]
fn mint_path_refuses_an_unmined_transfer_in_the_history() {
    let bytes = burn_after_transfer();
    let transfer = witness_ids(&bytes)[1];
    let err = error_of(validate_without(&bytes, transfer, true));
    assert!(err.contains("not confirmed on chain"), "{err}");
}

/// The send is history, and the mint consumes the right it made.
#[test]
fn accepts_a_mint_on_a_right_from_a_rights_send() {
    let validated = validate(&mint_after_a_rights_send()).expect("the history is valid");
    assert!(validated.last_mint_rights.is_empty());
    assert_eq!(validated.mint_locks.len(), 1);
}

#[test]
fn mint_path_refuses_an_unmined_rights_send() {
    let bytes = mint_after_a_rights_send();
    let send = witness_ids(&bytes)[0];
    let err = error_of(validate_without(&bytes, send, true));
    assert!(err.contains("not confirmed on chain"), "{err}");
}

/// The burn itself needs its proof too: the burn path allows no unmined tx.
#[test]
fn burn_path_refuses_an_unmined_last_witness() {
    let bytes = burn_bytes();
    let burn = *witness_ids(&bytes).last().unwrap();
    let err = error_of(validate_without(&bytes, burn, false));
    assert!(err.contains("not confirmed on chain"), "{err}");
}

/// The mint tx being signed is the one witness that may be unbroadcast, and
/// the result names it so the PSBT bind can check it.
#[test]
fn mint_path_allows_only_the_last_witness_unmined() {
    let bytes = mint_after_a_rights_send();
    let last = *witness_ids(&bytes).last().unwrap();
    let validated = validate_without(&bytes, last, true).expect("the mint tx may be unbroadcast");
    assert_eq!(validated.last_witness_txid, Some(last));
    assert_eq!(validated.non_mined_witness_txids, vec![display_bytes(last)]);
}

/// A dead indexer refuses the mint history instead of passing it.
#[test]
fn mint_path_refuses_history_an_unreachable_indexer_cannot_confirm() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    let validator = RgbValidator::new(format!("tcp://{addr}"), "regtest").unwrap();
    let indexer = validator.indexer_witnesses(1);
    let check = WitnessCheck {
        chain: &indexer,
        allow_unbroadcast_last: true,
        infer_spent_ancestors: true,
    };
    let err = error_of(validator.validate_consignment(
        &mint_after_a_rights_send(),
        Some(&bind_all),
        &check,
    ));
    assert!(err.contains("not confirmed on chain"), "{err}");
}

/// The mint of a fresh right has no history, so it needs no indexer.
#[test]
fn a_first_mint_needs_no_indexer() {
    let validator = RgbValidator::new(format!("tcp://{}", stalled_host()), "regtest")
        .unwrap()
        .with_timeout(30);
    let indexer = validator.indexer_witnesses(6);
    let check = WitnessCheck {
        chain: &indexer,
        allow_unbroadcast_last: true,
        infer_spent_ancestors: true,
    };
    let bytes = mint_spending(issue().genesis_right(0, right_utxo()), vec![]).consignment(vec![]);
    let start = std::time::Instant::now();
    validator
        .validate_consignment(&bytes, Some(&bind_all), &check)
        .unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(20));
}

/// Two rights sends, the second spending a right of the first, then a mint
/// on a right of the second.
fn mint_after_two_rights_sends() -> Vec<u8> {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(right, 2);
    let rights = history.duplicate_right(rights[0], 2);
    history.mint_owned(rights[1], MINTED, 90);
    history.consignment(vec![])
}

/// A witness source that records each witness it is asked about.
struct Recording<'a> {
    chain: &'a BTreeMap<bitcoin::Txid, WitnessPos>,
    asked: RefCell<Vec<bitcoin::Txid>>,
}

impl ConfirmedWitnesses for Recording<'_> {
    fn confirmed(&self, tx: &bitcoin::Transaction) -> std::result::Result<WitnessPos, String> {
        self.asked.borrow_mut().push(tx.compute_txid());
        self.chain.confirmed(tx)
    }
}

/// Validates `bytes` on the mint path's terms against `chain`, and returns
/// the witnesses the source was asked about.
fn mint_path_asks(
    bytes: &[u8],
    chain: &BTreeMap<bitcoin::Txid, WitnessPos>,
) -> (Result<ValidatedConsignment>, Vec<bitcoin::Txid>) {
    let source = Recording {
        chain,
        asked: RefCell::new(Vec::new()),
    };
    let check = WitnessCheck {
        chain: &source,
        allow_unbroadcast_last: true,
        infer_spent_ancestors: true,
    };
    let result = validator().validate_consignment(bytes, Some(&bind_all), &check);
    (result, source.asked.into_inner())
}

/// The mint tx's parent is mined, so every older send it builds on is too.
#[test]
fn mint_path_asks_the_indexer_only_about_the_parent_of_the_mint_tx() {
    let bytes = mint_after_two_rights_sends();
    let ids = witness_ids(&bytes);
    let (result, asked) = mint_path_asks(&bytes, &mined(&ids[1..2]));
    result.expect("the older send is as deep as the mined parent");
    assert_eq!(asked, vec![ids[1]]);
}

#[test]
fn mint_path_refuses_an_unmined_parent_even_over_a_mined_older_send() {
    let bytes = mint_after_two_rights_sends();
    let ids = witness_ids(&bytes);
    let (result, _) = mint_path_asks(&bytes, &mined(&ids[..1]));
    let err = error_of(result);
    assert!(err.contains("not confirmed on chain"), "{err}");
}

/// The burn path proves each witness itself: its proofs are checked anyway.
#[test]
fn burn_path_asks_about_every_witness() {
    let bytes = mint_after_two_rights_sends();
    let ids = witness_ids(&bytes);
    let chain = mined(&ids);
    let source = Recording {
        chain: &chain,
        asked: RefCell::new(Vec::new()),
    };
    validator()
        .validate_consignment(&bytes, Some(&bind_all), &on_chain(&source))
        .unwrap();
    let mut asked = source.asked.into_inner();
    asked.sort();
    let mut all = ids.clone();
    all.sort();
    assert_eq!(asked, all);
}

/// A fake Electrum server that serves only non-verbose calls, as
/// romanz/electrs does. One block at [`BLOCK`] holds a sibling, then `tx`.
mod electrum_indexer {
    use super::*;
    use bitcoin::block::Header;
    use bitcoin::hashes::{sha256d, Hash};
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Write};

    const BLOCK: u32 = 200;
    const SIBLING: [u8; 32] = [0x5b; 32];

    #[derive(Clone)]
    struct Server {
        tx: bitcoin::Transaction,
        header: Header,
        tip: u32,
        history_height: i32,
        known: bool,
        unspent_height: Option<u32>,
    }

    fn witness() -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![gen::dust(7)],
        }
    }

    /// `witness` mined at [`BLOCK`], 6 deep.
    fn server() -> Server {
        let tx = witness();
        let mut leaves = [0u8; 64];
        leaves[..32].copy_from_slice(&SIBLING);
        leaves[32..].copy_from_slice(&tx.compute_txid().to_byte_array());
        let root = sha256d::Hash::hash(&leaves).to_byte_array();
        let header = Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(root),
            time: 1_700_000_000,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        Server {
            tx,
            header,
            tip: BLOCK + 5,
            history_height: BLOCK as i32,
            known: true,
            unspent_height: Some(BLOCK),
        }
    }

    fn answer(server: &Server, method: &str, params: &Value) -> std::result::Result<Value, String> {
        let hex = |h: &Header| bitcoin::consensus::encode::serialize_hex(h);
        let txid = server.tx.compute_txid().to_string();
        Ok(match method {
            "server.version" => json!(["fake-electrs", "1.4"]),
            "blockchain.block.header" => match params[0].as_u64() {
                Some(0) => json!(hex(&bitcoin::constants::genesis_block(
                    bitcoin::Network::Regtest
                )
                .header)),
                Some(h) if h == u64::from(BLOCK) => json!(hex(&server.header)),
                other => return Err(format!("no header at {other:?}")),
            },
            "blockchain.headers.subscribe" => {
                json!({"height": server.tip, "hex": hex(&server.header)})
            }
            "blockchain.scripthash.get_history" if server.known => {
                json!([{"height": server.history_height, "tx_hash": txid}])
            }
            "blockchain.scripthash.get_history" => json!([]),
            "blockchain.transaction.get_merkle" => {
                let mut sibling = SIBLING;
                sibling.reverse();
                json!({"block_height": BLOCK, "pos": 1, "merkle": [hex::encode(sibling)]})
            }
            "blockchain.scripthash.listunspent" => match server.unspent_height {
                Some(height) => {
                    json!([{"height": height, "tx_hash": txid, "tx_pos": 0, "value": 1000}])
                }
                None => json!([]),
            },
            other => return Err(format!("unsupported method {other}")),
        })
    }

    /// Serves `server` and returns its `tcp://` URL.
    fn serve(server: Server) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let server = server.clone();
                std::thread::spawn(move || {
                    let mut out = stream.try_clone().unwrap();
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { break };
                        let req: Value = serde_json::from_str(&line).unwrap();
                        let method = req["method"].as_str().unwrap_or_default();
                        let body = match answer(&server, method, &req["params"]) {
                            Ok(result) => {
                                json!({"jsonrpc": "2.0", "id": req["id"], "result": result})
                            }
                            Err(message) => json!({"jsonrpc": "2.0", "id": req["id"],
                                "error": {"code": -32601, "message": message}}),
                        };
                        if writeln!(out, "{body}").is_err() {
                            break;
                        }
                    }
                });
            }
        });
        format!("tcp://{addr}")
    }

    fn validator_for(server: Server, network: &str) -> RgbValidator {
        RgbValidator::new(serve(server), network)
            .unwrap()
            .with_timeout(5)
    }

    fn confirmed(server: Server) -> std::result::Result<WitnessPos, String> {
        let tx = server.tx.clone();
        validator_for(server, "regtest")
            .indexer_witnesses(6)
            .confirmed(&tx)
    }

    #[test]
    fn confirms_a_mined_witness_with_non_verbose_calls_only() {
        let pos = confirmed(server()).unwrap();
        assert_eq!(pos.height().get(), BLOCK);
    }

    #[test]
    fn refuses_a_witness_one_block_too_shallow() {
        let err = confirmed(Server {
            tip: BLOCK + 4,
            ..server()
        })
        .unwrap_err();
        assert!(err.contains("only 5 confirmation(s)"), "{err}");
    }

    #[test]
    fn refuses_a_merkle_proof_that_does_not_match_the_block() {
        let mut lying = server();
        lying.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x11; 32]);
        let err = confirmed(lying).unwrap_err();
        assert!(err.contains("does not match block"), "{err}");
    }

    #[test]
    fn sees_a_mempool_witness_as_unmined() {
        for height in [0, -1] {
            let err = confirmed(Server {
                history_height: height,
                ..server()
            })
            .unwrap_err();
            assert!(err.contains("unmined"), "{height}: {err}");
        }
    }

    #[test]
    fn sees_a_witness_missing_from_the_history_as_unknown() {
        let err = confirmed(Server {
            known: false,
            ..server()
        })
        .unwrap_err();
        assert!(err.contains("does not know"), "{err}");
    }

    #[test]
    fn refuses_a_server_of_another_network() {
        let server = server();
        let tx = server.tx.clone();
        let err = validator_for(server, "bitcoin")
            .indexer_witnesses(1)
            .confirmed(&tx)
            .unwrap_err();
        assert!(err.contains("does not serve"), "{err}");
    }

    fn check_outpoint(server: Server) -> Result<()> {
        let outpoint = bitcoin::OutPoint::new(server.tx.compute_txid(), 0);
        let script = server.tx.output[0].script_pubkey.clone();
        validator_for(server, "regtest").assert_unspent_and_mined(outpoint, &script)
    }

    #[test]
    fn accepts_a_mined_unspent_outpoint() {
        check_outpoint(server()).unwrap();
    }

    #[test]
    fn refuses_a_spent_or_unmined_outpoint() {
        for unspent_height in [None, Some(0)] {
            let err = check_outpoint(Server {
                unspent_height,
                ..server()
            })
            .unwrap_err()
            .to_string();
            assert!(
                err.contains("spent or not mined"),
                "{unspent_height:?}: {err}"
            );
        }
    }
}

mod indexer_answer {
    use super::*;
    use rgbstd::validation::WitnessStatus;
    use rgbstd::vm::WitnessOrd;

    fn tx() -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![gen::dust(1)],
        }
    }

    fn pos(height: u32) -> WitnessPos {
        let height = std::num::NonZeroU32::new(height).unwrap();
        WitnessPos::bitcoin(height, 1_700_000_000).unwrap()
    }

    #[test]
    fn accepts_a_tx_mined_exactly_min_confirmations_deep() {
        let pos = mined_deep_enough(TxPlace::Mined(pos(95)), 100, 6).unwrap();
        assert_eq!(pos.height().get(), 95);
    }

    #[test]
    fn refuses_a_tx_one_block_short_of_min_confirmations() {
        let err = mined_deep_enough(TxPlace::Mined(pos(96)), 100, 6).unwrap_err();
        assert!(err.contains("only 5 confirmation(s)"), "{err}");
    }

    #[test]
    fn refuses_a_tx_in_the_mempool() {
        let err = mined_deep_enough(TxPlace::Unmined, 100, 1).unwrap_err();
        assert!(err.contains("unmined"), "{err}");
    }

    #[test]
    fn refuses_a_tx_the_indexer_does_not_know() {
        let err = mined_deep_enough(TxPlace::Unknown, 100, 1).unwrap_err();
        assert!(err.contains("does not know"), "{err}");
    }

    #[test]
    fn refuses_a_block_above_the_indexer_tip() {
        let err = mined_deep_enough(TxPlace::Mined(pos(101)), 100, 1).unwrap_err();
        assert!(err.contains("above the indexer tip"), "{err}");
    }

    #[test]
    fn esplora_answer_for_another_tx_is_refused() {
        let asked = gen::outpoint(0x55, 0).txid;
        let answer = WitnessStatus::Resolved(tx(), WitnessOrd::Mined(pos(90)));
        let err = esplora_place(answer, asked).unwrap_err();
        assert!(err.contains("answered with tx"), "{err}");
    }

    #[test]
    fn esplora_answer_maps_to_mined_unmined_and_unknown() {
        let txid = tx().compute_txid();
        let mined = WitnessStatus::Resolved(tx(), WitnessOrd::Mined(pos(90)));
        assert!(matches!(esplora_place(mined, txid), Ok(TxPlace::Mined(p)) if p == pos(90)));
        let tentative = WitnessStatus::Resolved(tx(), WitnessOrd::Tentative);
        assert!(matches!(
            esplora_place(tentative, txid),
            Ok(TxPlace::Unmined)
        ));
        assert!(matches!(
            esplora_place(WitnessStatus::Unresolved, txid),
            Ok(TxPlace::Unknown)
        ));
    }
}

// ===== asset binding rule =====

/// Rule tests for the asset binding. The end-to-end `asset_bind` suites prove
/// that the binding is in the request path. These need no consignment.
mod asset_binding_rule {
    use super::*;

    const VALIDATED: &str = "rgb:the-real-asset";

    fn cfg(rgb_asset_id: &str, configured: bool) -> BridgeConfig {
        BridgeConfig {
            chain_id: if configured { 1 } else { 0 },
            bridge_contract: if configured { [0x11; 20] } else { [0u8; 20] },
            rgb_asset_id: rgb_asset_id.into(),
            gas_tx_allowed_to: None,
            ..Default::default()
        }
    }

    fn bind(validated: &str, declared: &str, c: &BridgeConfig, m: AssetBindMode) -> String {
        match assert_asset_binding(validated, declared, c, m) {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn binds_when_validated_declared_and_pin_all_agree() {
        for mode in [AssetBindMode::Source, AssetBindMode::Destination] {
            let err = bind(VALIDATED, VALIDATED, &cfg(VALIDATED, true), mode);
            assert!(err.is_empty(), "{mode:?} should bind, got: {err}");
        }
    }

    #[test]
    fn rejects_empty_validated_contract_id() {
        for mode in [AssetBindMode::Source, AssetBindMode::Destination] {
            let err = bind("", "", &cfg("", true), mode);
            assert!(err.contains("empty contract_id"), "{mode:?}: {err}");
        }
    }

    #[test]
    fn rejects_when_declared_disagrees_with_validated() {
        let err = bind(
            VALIDATED,
            "rgb:listener-lied",
            &cfg(VALIDATED, true),
            AssetBindMode::Source,
        );
        assert!(err.contains("contract_id mismatch") && err.contains("RGB source declares"));
        let err = bind(
            VALIDATED,
            "rgb:listener-lied",
            &cfg(VALIDATED, true),
            AssetBindMode::Destination,
        );
        assert!(err.contains("contract_id mismatch") && err.contains("RGB destination declares"));
    }

    /// Theft path: a colluding listener declares the foreign asset of the
    /// consignment. The pin must still reject it.
    #[test]
    fn rejects_foreign_asset_even_when_declared_agrees() {
        for mode in [AssetBindMode::Source, AssetBindMode::Destination] {
            let err = bind(
                VALIDATED,
                VALIDATED,
                &cfg("rgb:some-other-pinned-asset", true),
                mode,
            );
            assert!(
                err.contains("contract_id mismatch") && err.contains("pinned RGB_ASSET_ID"),
                "{mode:?}: {err}"
            );
        }
    }

    /// The direction asymmetry, both sides.
    #[test]
    fn missing_pin_is_fatal_only_on_the_destination_side() {
        let err = bind(
            VALIDATED,
            VALIDATED,
            &cfg("", false),
            AssetBindMode::Destination,
        );
        assert!(err.contains("asset-identity pin missing"), "{err}");

        let err = bind(VALIDATED, VALIDATED, &cfg("", false), AssetBindMode::Source);
        assert!(
            err.is_empty(),
            "unconfigured source should bind, got: {err}"
        );
        assert!(!cfg("", true).is_configured());
    }
}

// ===== the RGB source payload and path =====

#[cfg(rgb_to_evm)]
fn keccak(bytes: &[u8]) -> Vec<u8> {
    Keccak256::digest(bytes).to_vec()
}

/// A well-formed `RgbSource` around a generated burn. `consignment_valid` is
/// `false` on purpose: a pass proves the flag cannot override the bytes.
#[cfg(rgb_to_evm)]
fn burn_source(asset_id: &str) -> crate::proto::RgbSource {
    let consignment = burn_bytes();
    crate::proto::RgbSource {
        consignment_valid: false,
        asset_id: asset_id.into(),
        consignment_hash: keccak(&consignment),
        consignment,
        merkle_proofs: vec![],
        commission: 0,
    }
}

#[cfg(rgb_to_evm)]
mod source_payload {
    use super::*;
    use crate::config::{
        DEFAULT_MAX_CONSIGNMENT_BYTES, DEFAULT_MAX_MERKLE_PROOFS, DEFAULT_MAX_TOTAL_PROOF_BYTES,
    };
    use crate::proto::MerkleProofEntry;

    #[test]
    fn accepts_valid_consignment_hash() {
        assert!(validate_source_payload(&burn_source("rgb:any"), &BridgeConfig::default()).is_ok());
    }

    /// The cap is checked before the rgbstd parse.
    #[test]
    fn rejects_oversized_consignment_before_parse() {
        let mut source = burn_source("rgb:any");
        source.consignment = vec![0u8; DEFAULT_MAX_CONSIGNMENT_BYTES + 1];
        source.consignment_hash = keccak(&source.consignment);
        let err = validate_source_payload(&source, &BridgeConfig::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("consignment too large"), "unexpected: {err}");
    }

    #[test]
    fn accepts_consignment_at_size_cap() {
        let mut source = burn_source("rgb:any");
        source.consignment = vec![0u8; DEFAULT_MAX_CONSIGNMENT_BYTES];
        source.consignment_hash = keccak(&source.consignment);
        assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
    }

    #[test]
    fn honors_configured_consignment_cap() {
        let mut source = burn_source("rgb:any");
        source.consignment = vec![0u8; 200];
        source.consignment_hash = keccak(&source.consignment);
        assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
        let cfg = BridgeConfig {
            max_consignment_bytes: 100,
            ..BridgeConfig::default()
        };
        let err = validate_source_payload(&source, &cfg)
            .unwrap_err()
            .to_string();
        assert!(err.contains("consignment too large"), "unexpected: {err}");
    }

    #[test]
    fn rejects_too_many_merkle_proofs() {
        let mut source = burn_source("rgb:any");
        source.merkle_proofs = (0..DEFAULT_MAX_MERKLE_PROOFS + 1)
            .map(|_| MerkleProofEntry::default())
            .collect();
        let err = validate_source_payload(&source, &BridgeConfig::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("too many merkle proofs"), "unexpected: {err}");
    }

    #[test]
    fn rejects_aggregate_proof_bytes_over_budget() {
        let per_proof = 32 + 32 * 32;
        let n = DEFAULT_MAX_TOTAL_PROOF_BYTES / per_proof + 1;
        assert!(
            n <= DEFAULT_MAX_MERKLE_PROOFS,
            "would trip the count cap first"
        );
        let proof = MerkleProofEntry {
            txid: vec![0u8; 32],
            block_height: 0,
            tx_position: 0,
            merkle_path: vec![vec![0u8; 32]; 32],
        };
        let mut source = burn_source("rgb:any");
        source.merkle_proofs = vec![proof; n];
        let err = validate_source_payload(&source, &BridgeConfig::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("too large in aggregate"), "unexpected: {err}");
    }

    #[test]
    fn ignores_consignment_valid_flag_when_bytes_present() {
        let mut source = burn_source("rgb:any");
        source.consignment_valid = true;
        assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
    }

    #[test]
    fn rejects_empty_consignment_even_with_valid_flag() {
        let mut source = burn_source("rgb:any");
        source.consignment = vec![];
        source.consignment_hash = vec![];
        source.consignment_valid = true;
        let err = validate_source_payload(&source, &BridgeConfig::default()).unwrap_err();
        assert!(err.to_string().contains("requires raw consignment bytes"));
    }

    #[test]
    fn rejects_consignment_hash_mismatch_even_with_valid_flag() {
        let mut source = burn_source("rgb:any");
        source.consignment_hash = vec![0xDE; 32];
        source.consignment_valid = true;
        let err = validate_source_payload(&source, &BridgeConfig::default()).unwrap_err();
        assert!(err.to_string().contains("consignment hash mismatch"));
    }
}

/// The source path end to end: the SPV proofs, consensus over them, the asset
/// bind, then proof coverage.
#[cfg(rgb_to_evm)]
mod source_path {
    use super::*;
    use crate::networks::rgb::spv::HeaderChain;
    use crate::networks::ValidationContext;
    use std::sync::Mutex;

    fn pinned_config(rgb_asset_id: &str) -> BridgeConfig {
        BridgeConfig {
            chain_id: 1,
            bridge_contract: [0x11; 20],
            rgb_asset_id: rgb_asset_id.into(),
            gas_tx_allowed_to: None,
            ..Default::default()
        }
    }

    /// The display-order txids of `ids`, as the proofs carry them.
    fn display(ids: &[bitcoin::Txid]) -> Vec<[u8; 32]> {
        ids.iter().copied().map(display_bytes).collect()
    }

    /// Runs `source` with a proof, 6 deep, for every witness.
    fn run(
        source: &crate::proto::RgbSource,
        config: &BridgeConfig,
    ) -> Result<ValidatedConsignment> {
        run_proving(source, config, &display(&witness_ids(&source.consignment)))
    }

    /// Runs `source` with a proof, 6 deep, for each of `proven` only.
    fn run_proving(
        source: &crate::proto::RgbSource,
        config: &BridgeConfig,
        proven: &[[u8; 32]],
    ) -> Result<ValidatedConsignment> {
        let (chain, proofs) = crate::test_support::chain_with_witnesses(proven, 5);
        let source = crate::proto::RgbSource {
            merkle_proofs: proofs,
            ..source.clone()
        };
        run_on(&source, config, &chain)
    }

    fn run_on(
        source: &crate::proto::RgbSource,
        config: &BridgeConfig,
        chain: &Mutex<HeaderChain>,
    ) -> Result<ValidatedConsignment> {
        run_reading(source, config, chain, None)
    }

    fn run_reading(
        source: &crate::proto::RgbSource,
        config: &BridgeConfig,
        chain: &Mutex<HeaderChain>,
        reader: Option<RejectListReader<'_>>,
    ) -> Result<ValidatedConsignment> {
        let validator = validator();
        let ctx = ValidationContext {
            bridge_config: config,
            rgb_validator: Some(&validator),
            header_chain: chain,
            chain_pins: &crate::networks::rgb::spv_crosscheck::ChainPins::new(),
            #[cfg(evm_to_rgb)]
            self_owned_psbt_outputs: None,
            #[cfg(evm_to_rgb)]
            psbt_fee_key_paths: None,
            anchor_binder: Some(&bind_all),
            reject_list_reader: reader,
        };
        validate_source(source, &ctx)
    }

    fn asset_id() -> String {
        issue().contract_id.to_string()
    }

    #[test]
    fn binds_when_contract_id_matches_pin() {
        let id = asset_id();
        let validated = run(&burn_source(&id), &pinned_config(&id)).unwrap();
        assert_eq!(validated.contract_id, id);
        assert!(validated.non_mined_witness_txids.is_empty());
    }

    /// A history witness without a proof is unmined to consensus, which
    /// refuses before any later check.
    #[test]
    fn refuses_a_history_witness_without_a_proof() {
        let id = asset_id();
        let source = burn_source(&id);
        let ids = witness_ids(&source.consignment);
        let err = run_proving(&source, &pinned_config(&id), &display(&ids[1..]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not confirmed on chain"), "{err}");
        assert!(err.contains(&ids[0].to_string()), "{err}");
    }

    /// The unmined transfer of a double spend has no proof to offer.
    #[test]
    fn refuses_a_burn_after_an_unmined_transfer() {
        let bytes = burn_after_transfer();
        let id = issue().contract_id.to_string();
        let source = crate::proto::RgbSource {
            consignment_hash: keccak(&bytes),
            consignment: bytes.clone(),
            ..burn_source(&id)
        };
        let ids = witness_ids(&bytes);
        let err = run_proving(&source, &pinned_config(&id), &display(&[ids[0], ids[2]]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not confirmed on chain"), "{err}");
        assert!(err.contains(&ids[1].to_string()), "{err}");
    }

    #[test]
    fn rejects_when_declared_is_empty() {
        let err = run(&burn_source(""), &pinned_config(&asset_id()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("RGB source asset_id is empty"), "{err}");
    }

    #[test]
    fn rejects_foreign_asset_even_when_declared_agrees() {
        let id = asset_id();
        let err = run(&burn_source(&id), &pinned_config("rgb:some-other"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("pinned RGB_ASSET_ID"), "{err}");
    }

    #[test]
    fn rejects_when_declared_disagrees_with_validated() {
        let err = run(
            &burn_source("rgb:listener-lied"),
            &pinned_config(&asset_id()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("RGB source declares"), "{err}");
    }

    /// The depth comes from `BridgeConfig::spv_min_confirmations`. The last
    /// witness is 2 deep: a config of 2 passes, 3 refuses.
    #[test]
    fn confirmation_depth_comes_from_the_config() {
        let id = asset_id();
        let mut source = burn_source(&id);
        let witnesses = validate(&source.consignment).unwrap().witness_txids;
        let (chain, proofs) = crate::test_support::chain_with_witnesses(&witnesses, 1);
        source.merkle_proofs = proofs;

        let mut config = pinned_config(&id);
        config.spv_min_confirmations = 2;
        run_on(&source, &config, &chain).unwrap();

        config.spv_min_confirmations = 3;
        let err = run_on(&source, &config, &chain).unwrap_err().to_string();
        assert!(err.contains("insufficient confirmations"), "{err}");
    }

    #[test]
    fn pin_check_skipped_when_config_unconfigured() {
        let id = asset_id();
        run(&burn_source(&id), &BridgeConfig::default()).unwrap();
    }

    /// The listed burn as a source, every witness proven 6 deep, its chain
    /// and its asset id.
    fn listed_source() -> (crate::proto::RgbSource, Mutex<HeaderChain>, String) {
        let (history, ..) = listed_burn();
        let bytes = history.consignment(vec![]);
        let id = history.contract_id.to_string();
        let source = crate::proto::RgbSource {
            consignment_hash: keccak(&bytes),
            consignment: bytes.clone(),
            ..burn_source(&id)
        };
        let (chain, proofs) =
            crate::test_support::chain_with_witnesses(&display(&witness_ids(&bytes)), 5);
        let source = crate::proto::RgbSource {
            merkle_proofs: proofs,
            ..source
        };
        (source, chain, id)
    }

    /// Runs the listed burn, 6 deep, with a reader of `entries`, all
    /// finalized. Returns the result and how often the list was read.
    fn run_listed(
        config_asset: Option<&str>,
        entries: &[(rgbstd::Opout, bool)],
    ) -> (Result<ValidatedConsignment>, usize) {
        let (source, chain, id) = listed_source();
        let entries: Vec<RejectListEntry> = entries
            .iter()
            .map(|(opout, reject)| RejectListEntry {
                opout: key(*opout),
                reject: *reject,
            })
            .collect();
        let reads = RefCell::new(0);
        let reader = |list: &RejectListContract| {
            *reads.borrow_mut() += 1;
            assert_eq!(list.address, LIST);
            Ok(decisions(&entries, entries.len()))
        };
        let config = pinned_config(config_asset.unwrap_or(&id));
        let result = run_reading(&source, &config, &chain, Some(&reader));
        (result, reads.into_inner())
    }

    fn unrelated() -> rgbstd::Opout {
        rgbstd::Opout::new(
            rgbstd::OpId::copy_from_slice([0x99; 32]).unwrap(),
            schemata::OS_ASSET,
            0,
        )
    }

    #[test]
    fn burn_with_rejected_ancestry_is_refused() {
        let (_, right, ..) = listed_burn();
        let (result, reads) = run_listed(None, &[(right.opout, true)]);
        let err = error_of(result);
        assert!(err.contains("reject list: opout"), "{err}");
        assert_eq!(reads, 1);
    }

    #[test]
    fn burn_with_unrelated_entries_is_signed() {
        let (result, reads) = run_listed(None, &[(unrelated(), true)]);
        assert!(result.unwrap().reject_scope.is_some());
        assert_eq!(reads, 1);
    }

    #[test]
    fn an_allowed_burn_input_shields_a_rejected_ancestor() {
        let (_, right, units, _) = listed_burn();
        let (result, _) = run_listed(None, &[(right.opout, true), (units.opout, false)]);
        result.unwrap();
    }

    /// The change is not released, so a list entry on it does not block.
    #[test]
    fn a_rejected_burn_change_does_not_block_the_release() {
        let (_, _, _, burn) = listed_burn();
        let change = rgbstd::Opout::new(burn.opid, schemata::OS_ASSET, 0);
        let (result, _) = run_listed(None, &[(change, true)]);
        result.unwrap();
    }

    /// The pin is checked first, so a foreign genesis cannot make the
    /// enclave read a contract of its choice.
    #[test]
    fn foreign_asset_list_is_never_read() {
        let (result, reads) = run_listed(Some("rgb:some-other"), &[]);
        assert!(error_of(result).contains("pinned RGB_ASSET_ID"));
        assert_eq!(reads, 0);
    }

    #[test]
    fn burn_is_refused_when_the_list_cannot_be_read() {
        let (source, chain, id) = listed_source();
        let failing = |_: &RejectListContract| -> Result<Decisions> {
            Err(crate::error::EnclaveError::CrossCheck(
                "evm-rpc: down".into(),
            ))
        };
        let config = pinned_config(&id);
        let err = error_of(run_reading(&source, &config, &chain, Some(&failing)));
        assert!(err.contains("evm-rpc: down"), "{err}");
        let err = error_of(run_reading(&source, &config, &chain, None));
        assert!(err.contains("cannot read it"), "{err}");
    }
}

// ===== long histories =====

/// A mint, `transfers` transfers, then a full burn.
fn long_history(transfers: usize) -> History {
    let (mut history, mut units) = minted();
    for _ in 0..transfers {
        units = history.transfer(units, MINTED);
    }
    history.burn(
        units,
        MINTED,
        Some(MINTED),
        Some(gen::burn_reason_for(PAYEE)),
    );
    history
}

#[test]
fn validates_a_history_of_200_transfers() {
    let validated = validate(&long_history(200).consignment(vec![])).unwrap();
    // The mint, 200 transfers and the burn.
    assert_eq!(validated.witness_txids.len(), 202);
    assert_eq!(validated.mint_locks.len(), 1);
    let last = validated.last_transition.unwrap();
    assert_eq!(last.burned_asset_amount, Some(MINTED));
}

/// A burn with a history of 10_000 transfers and an SPV proof on every bundle
/// passes with the default limits: consensus, the request caps
/// (`MAX_CONSIGNMENT_BYTES`, `MAX_MERKLE_PROOFS`, `MAX_TOTAL_PROOF_BYTES`) and
/// the frame. Each proof has 13 siblings, the depth of a full mainnet block.
///
/// Ignored by default because it is slow in a debug build.
#[cfg(rgb_to_evm)]
#[test]
#[ignore = "validates a history of 10_000 transfers; run it on request"]
fn a_history_of_10_000_transfers_fits_the_default_limits() {
    use crate::framing::{self, MAX_MESSAGE_SIZE};
    use crate::networks::evm::validation::MAX_FUNDS_OUT_CALL_DATA_LEN;
    use crate::proto::enclave_request::Request;
    use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};
    use crate::proto::{EnclaveRequest, EvmDestination, MerkleProofEntry, SignRequest};
    use bitcoin::hashes::Hash;

    const TRANSFERS: usize = 10_000;
    const DEPTH: usize = 13;

    let mut history = long_history(TRANSFERS);
    for (i, bundle) in history.bundles.iter_mut().enumerate() {
        bundle.spv_proof = Some(rgbstd::validation::SpvProof {
            block_height: std::num::NonZeroU32::new(900_000 + i as u32).unwrap(),
            pos: 4_000,
            merkle: amplify::confinement::Confined::try_from(vec![
                bitcoin::TxMerkleNode::from_byte_array(
                    [0x5a; 32]
                );
                DEPTH
            ])
            .unwrap(),
        });
    }
    let consignment = history.consignment(vec![]);

    let start = std::time::Instant::now();
    let validated = validate(&consignment).unwrap();
    let validate_ms = start.elapsed().as_millis();
    assert_eq!(validated.witness_txids.len(), TRANSFERS + 2);

    let cfg = BridgeConfig::default();
    assert!(
        consignment.len() <= cfg.max_consignment_bytes,
        "{} bytes over the cap",
        consignment.len()
    );
    let source = crate::proto::RgbSource {
        consignment_hash: keccak(&consignment),
        consignment: consignment.clone(),
        merkle_proofs: validated
            .witness_txids
            .iter()
            .enumerate()
            .map(|(i, txid)| MerkleProofEntry {
                txid: txid.to_vec(),
                block_height: 900_000 + i as u32,
                tx_position: 4_000,
                merkle_path: vec![vec![0x5a; 32]; DEPTH],
            })
            .collect(),
        ..burn_source("rgb:any")
    };
    validate_source_payload(&source, &cfg).expect("the source passes the default caps");

    let request = EnclaveRequest {
        request: Some(Request::Sign(SignRequest {
            amount: MINTED,
            source_network: Some(SourceNetwork::RgbSource(source)),
            destination_network: Some(DestinationNetwork::EvmDestination(EvmDestination {
                call_data: vec![0x11; MAX_FUNDS_OUT_CALL_DATA_LEN],
                ..Default::default()
            })),
        })),
    };
    let mut frame = Vec::new();
    framing::write_message(&mut frame, &request).unwrap();
    let body = frame.len() - 4;
    assert!(body <= MAX_MESSAGE_SIZE as usize, "request of {body} bytes");

    println!(
        "10_000 transfers: consignment {} bytes, request {body} bytes, consensus {validate_ms} ms",
        consignment.len()
    );
}

mod summary;
