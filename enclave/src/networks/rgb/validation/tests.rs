//! Tests for all of `validation/`. They are in one file because they share
//! the generated consignments (`test_support::bfa_consignment`).

use std::cell::RefCell;

use amplify::ByteArray;
use bitcoin::hashes::Hash as _;
use bitcoin::OutPoint;
use rgb_lib::no_wallet::{RgbOutputInfo, RgbTransitionInfo};
use rgb_lib::{Assignment, TypeOfTransition};
use rgbstd::containers::FileContent;
use rgbstd::contract::AllocatedState;
use rgbstd::{BuilderSeal, GraphSeal, RevealedValue};
#[cfg(rgb_to_evm)]
use sha3::{Digest, Keccak256};

use super::asset_bind::*;
use super::bfa::*;
use super::consignment::*;
use super::reject_list::*;
use super::schema::*;
#[cfg(rgb_to_evm)]
use super::source::*;
use super::types::*;
use super::validator::*;
use super::witness::*;
use crate::config::BridgeConfig;
use crate::error::Result;
use crate::networks::rgb::bfa_schema;
use crate::test_support::bfa_consignment::{self as gen, History, Issue, Utxo};
use crate::test_support::MinedBlocks;

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

/// The bundle of `witness`, exported as `rgb-ops` exports a history: only the
/// transition the later history needs stays disclosed
/// (`TransitionBundle::to_concealed_except`). The bundle still commits every
/// transition, since its input map is untouched.
fn conceal_except(history: &mut History, witness: bitcoin::Txid, keep: rgbstd::OpId) {
    let bundle = history
        .bundles
        .iter_mut()
        .find(|wb| wb.witness_id() == witness)
        .expect("a bundle of that witness");
    bundle.bundle = bundle
        .bundle
        .to_concealed_except(keep)
        .expect("the bundle holds the transition to keep");
}

/// A wallet burns part of its units, then burns what the first burn's bundle
/// left. A `TS_BURN` has no owned state: the change is an output of the
/// `TS_TRANSFER` that splits the input before it. Exporting the second burn's
/// history keeps that transfer, which its units descend from, and conceals the
/// burn beside it, so the bundle commits two transitions and discloses one.
/// The second burn must still pay out.
#[test]
fn accepts_a_burn_of_the_change_an_earlier_split_left() {
    let (mut history, units) = minted();
    let reason = gen::burn_reason_for(PAYEE);
    let (first, change) = history.burn_keeping_change(units, MINTED, 60_000, Some(reason));
    let rest = MINTED - 60_000;
    history.burn(change, rest, Some(rest), Some(reason));
    // `change.opout.op` is the split transfer, the transition the later
    // history descends from and the only one its export discloses.
    conceal_except(&mut history, first.tx.compute_txid(), change.opout.op);

    let validated = validate(&history.consignment()).expect("the second burn is valid");
    let last = validated.settling_transition.expect("the settling burn");
    assert_eq!(last.burned_asset_amount, Some(rest));
    assert_eq!(last.burn_reason, Some(reason));
}

/// The other half: concealing a transition the later history descends from is
/// refused, by consensus rather than by any rule of the enclave. Here the
/// first bundle keeps its burn and conceals the split, so the second burn's
/// units have no disclosed origin.
#[test]
fn refuses_a_burn_whose_origin_the_history_conceals() {
    let (mut history, units) = minted();
    let reason = gen::burn_reason_for(PAYEE);
    let (first, change) = history.burn_keeping_change(units, MINTED, 60_000, Some(reason));
    let rest = MINTED - 60_000;
    history.burn(change, rest, Some(rest), Some(reason));
    // Keep the burn, conceal the split the second burn's units come from.
    conceal_except(&mut history, first.tx.compute_txid(), first.opid);

    let err = error_of(validate(&history.consignment()));
    assert!(err.contains("cannot be found"), "{err}");
}

fn burn_bytes() -> Vec<u8> {
    burn_history(Some(60_000), Some(gen::burn_reason_for(PAYEE)))
        .0
        .consignment()
}

fn validator() -> RgbValidator {
    RgbValidator::new("regtest").unwrap()
}

fn lock_for(anchor: &MintAnchor) -> VerifiedLock {
    VerifiedLock {
        lock_id: anchor.lock_id,
        minted: anchor.amount,
        operation_id: [0xd0; 32],
        net_amount: anchor.amount,
    }
}

/// Binds every anchor to a lock with its own `(lockId, amount)`.
fn bind_all(anchors: &[MintAnchor]) -> Result<BoundAnchors> {
    Ok(BoundAnchors {
        evm_chain_id: EVM_CHAIN_ID,
        locks: anchors.iter().map(lock_for).collect(),
    })
}

fn any_asset(_: &str) -> Result<()> {
    Ok(())
}

fn empty_list(_: &RejectListContract) -> Result<Decisions> {
    Ok(Decisions::default())
}

/// Any asset binds, and a listed one reads an empty list.
fn open_lists() -> ListAccess<'static> {
    ListAccess {
        bind_asset: &any_asset,
        read: Some(&empty_list),
    }
}

fn validate(bytes: &[u8]) -> Result<ValidatedConsignment> {
    validate_bound(bytes, Some(&bind_all))
}

/// Validates on the burn path's terms, with every witness of `bytes` mined.
fn validate_bound(bytes: &[u8], bind: Option<AnchorBinder<'_>>) -> Result<ValidatedConsignment> {
    let chain = mined(&witness_ids(bytes));
    validator().validate_consignment(bytes, bind, &chain, &open_lists())
}

/// The witness txids of `bytes`, in bundle order. Empty if they do not load.
fn witness_ids(bytes: &[u8]) -> Vec<bitcoin::Txid> {
    rgbstd::containers::Transfer::load(std::io::Cursor::new(bytes))
        .map(|t| t.bundles.iter().map(|wb| wb.witness_id()).collect())
        .unwrap_or_default()
}

/// `txids` mined deep enough, one per block, as the generator proves them.
fn mined(txids: &[bitcoin::Txid]) -> MinedBlocks {
    MinedBlocks::of(txids)
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

/// A V0 BFA burn does not deserialize, so the enclave refuses it.
#[test]
fn rejects_a_v0_consignment() {
    let v0 = include_bytes!("../../../../tests/fixtures/v0_bfa_burn.rgbc");
    let err = error_of(validate(v0));
    assert!(err.contains("deserialization failed"), "{err}");
}

/// A V1 file that carries a terminals map does not load: the format has no
/// terminals map.
#[test]
fn rejects_a_consignment_with_a_terminals_map() {
    let terminals = include_bytes!("../../../../tests/fixtures/terminals_map_bfa_transfer.rgb");
    let err = error_of(validate(terminals));
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
    let err = error_of(validate(&history.consignment()));
    assert!(err.contains("not an EVM contract"), "{err}");
}

/// Validates `bytes` with every witness mined, against a list of `entries`
/// whose first `finalized` are final. Returns the result and the reads.
fn validate_listed(
    bytes: &[u8],
    entries: &[(rgbstd::Opout, bool)],
    finalized: usize,
) -> (Result<ValidatedConsignment>, usize) {
    let entries: Vec<RejectListEntry> = entries
        .iter()
        .map(|(opout, reject)| RejectListEntry {
            opout: key(*opout),
            reject: *reject,
        })
        .collect();
    let reads = RefCell::new(0);
    let read = |list: &RejectListContract| {
        *reads.borrow_mut() += 1;
        assert_eq!(list.address, LIST);
        Ok(decisions(&entries, finalized))
    };
    let lists = ListAccess {
        bind_asset: &any_asset,
        read: Some(&read),
    };
    let chain = mined(&witness_ids(bytes));
    let result = validator().validate_consignment(bytes, Some(&bind_all), &chain, &lists);
    (result, reads.into_inner())
}

/// [`validate_listed`] with every entry final.
fn listed_result(bytes: &[u8], entries: &[(rgbstd::Opout, bool)]) -> Result<ValidatedConsignment> {
    validate_listed(bytes, entries, entries.len()).0
}

fn assert_rejected(result: Result<ValidatedConsignment>) {
    let err = error_of(result);
    assert!(
        err.contains("Consignment rejected by the reject list"),
        "{err}"
    );
    assert!(err.contains(REJECT_LIST_REFUSAL), "{err}");
    assert!(err.contains(&hex::encode(LIST)), "{err}");
}

/// bridge-utexo's gateway (`unlock.go` rejectListRefusalMsg) answers HTTP 422
/// on this text, so it must not drift.
const REJECT_LIST_REFUSAL: &str = "descends from an opout the reject list";

/// (a) The burned units descend from a rejected opout: the genesis right, or
/// the mint's units.
#[test]
fn a_burn_of_a_rejected_lineage_is_refused() {
    let (history, right, units, _) = listed_burn();
    let bytes = history.consignment();
    for rejected in [right.opout, units.opout] {
        let (result, reads) = validate_listed(&bytes, &[(rejected, true)], 1);
        assert_rejected(result);
        assert_eq!(reads, 1);
    }
}

/// (b) An allowed opout on the path stops the walk before the reject.
#[test]
fn an_allowed_ancestor_shields_the_burn() {
    let (history, right, units, _) = listed_burn();
    listed_result(
        &history.consignment(),
        &[(right.opout, true), (units.opout, false)],
    )
    .expect("the allowed units shield the rejected right");
}

/// (c) An allow counts only once finalized; a pending one shields nothing.
#[test]
fn a_pending_allow_does_not_shield_the_burn() {
    let (history, right, units, _) = listed_burn();
    let entries = [(right.opout, true), (units.opout, false)];
    assert_rejected(validate_listed(&history.consignment(), &entries, 1).0);
}

/// (d) The change stays on the split, which the burn spends, so the split is
/// not terminal and a list entry on its change does not block.
#[test]
fn a_rejected_split_change_does_not_block_the_release() {
    let (history, ..) = listed_burn();
    let change = split_change(&history);
    listed_result(&history.consignment(), &[(change, true)]).expect("the change is not released");
}

/// The change output the burn's split keeps for the holder.
fn split_change(history: &History) -> rgbstd::Opout {
    let split = &history.bundles.last().unwrap().bundle.known_transitions[0];
    let outputs = split
        .transition
        .assignments
        .get(&bfa_schema::OS_ASSET)
        .unwrap()
        .as_fungible();
    let no = outputs
        .iter()
        .position(|a| a.as_state().as_u64() == MINTED - 60_000)
        .expect("the split's change");
    rgbstd::Opout::new(split.opid, bfa_schema::OS_ASSET, u16::try_from(no).unwrap())
}

/// A listed mint, then a transfer that splits the units into two halves on
/// vout 1 and vout 2 of its witness tx.
fn listed_halves() -> (History, [Utxo; 2]) {
    let mut history = listed();
    let right = history.genesis_right(0, right_utxo());
    let units = history.mint_owned(right, MINTED, 90);
    split_in_halves(history, units)
}

/// (e) rgb-lib checks every terminal operation: a rejected line in a companion
/// transfer of the burn's bundle refuses the release, unlike the burn's alone.
#[test]
fn a_rejected_line_in_a_companion_transfer_refuses_the_burn() {
    let (mut history, [kept, burned]) = listed_halves();
    let half = MINTED / 2;
    let companion = history
        .transition("transfer")
        .add_input(kept.opout, AllocatedState::from(RevealedValue::from(half)))
        .unwrap()
        .add_fungible_state("assetOwner", GraphSeal::with_blinded_vout(1u32, 3), half)
        .unwrap()
        .complete_transition()
        .unwrap();
    let burn = history.burn_transition(burned, half, Some(half), Some(gen::burn_reason_for(PAYEE)));
    history.commit(
        vec![companion, burn],
        vec![kept.outpoint, burned.outpoint],
        vec![gen::dust(3)],
    );
    let bytes = history.consignment();
    listed_result(&bytes, &[]).expect("control: nothing rejected");
    assert_rejected(listed_result(&bytes, &[(kept.opout, true)]));
}

/// An allowed opout shields only its own branch: the burn of both halves is
/// refused while one half still reaches the rejected units.
#[test]
fn an_allowed_opout_shields_only_its_own_branch() {
    let (mut history, halves) = listed_halves();
    let units = history.bundles[0].bundle.known_transitions[0].opid;
    let units = rgbstd::Opout::new(units, bfa_schema::OS_ASSET, 0);
    let mut burn = history.transition("burn");
    for half in &halves {
        burn = burn
            .add_input(
                half.opout,
                AllocatedState::from(RevealedValue::from(MINTED / 2)),
            )
            .unwrap();
    }
    let burn = burn
        .add_global_state("burnedAsset", rgbstd::Amount::from(MINTED))
        .unwrap()
        .complete_transition()
        .unwrap();
    let inputs = halves.iter().map(|half| half.outpoint).collect();
    history.commit(vec![burn], inputs, vec![gen::dust(3)]);
    let bytes = history.consignment();
    let one_shield = [(units, true), (halves[0].opout, false)];
    assert_rejected(listed_result(&bytes, &one_shield));
    let both = [one_shield[0], one_shield[1], (halves[1].opout, false)];
    listed_result(&bytes, &both).expect("both halves are shielded");
}

/// A terminal transition's outputs are checked as well as its inputs: a
/// listed mint with its own units rejected is refused.
#[test]
fn the_outputs_of_a_terminal_transition_are_checked() {
    let mut history = listed();
    let right = history.genesis_right(0, right_utxo());
    let units = history.mint_owned(right, MINTED, 90);
    let bytes = history.consignment();
    listed_result(&bytes, &[]).expect("control: nothing rejected");
    assert_rejected(listed_result(&bytes, &[(units.opout, true)]));
}

/// A right from a rights send still descends from the genesis right, so a
/// rejected genesis right reaches the mint through the send.
#[test]
fn a_rights_send_carries_a_rejected_genesis_right_to_the_mint() {
    let mut history = listed();
    let genesis_right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(genesis_right, 3);
    history.mint_owned(rights[1], MINTED, 90);
    assert_rejected(listed_result(
        &history.consignment(),
        &[(genesis_right.opout, true)],
    ));
}

/// (f) The reader runs only for a listed asset, and only after the asset
/// bind passed: a foreign genesis never reaches rgb-lib, listed or not.
#[test]
fn the_list_is_read_only_for_a_listed_asset_after_the_bind() {
    let reads = RefCell::new(0);
    let read = |_: &RejectListContract| {
        *reads.borrow_mut() += 1;
        Ok(Decisions::default())
    };
    let foreign = |_: &str| -> Result<()> {
        Err(crate::error::EnclaveError::CrossCheck(
            "not the pinned asset".into(),
        ))
    };
    let run = |bytes: &[u8], bind_asset: &dyn Fn(&str) -> Result<()>| {
        let lists = ListAccess {
            bind_asset,
            read: Some(&read),
        };
        let chain = mined(&witness_ids(bytes));
        validator().validate_consignment(bytes, Some(&bind_all), &chain, &lists)
    };
    let listed = listed_burn().0.consignment();
    for bytes in [&listed, &burn_bytes()] {
        assert!(error_of(run(bytes, &foreign)).contains("not the pinned asset"));
    }
    assert_eq!(*reads.borrow(), 0);
    run(&burn_bytes(), &any_asset).unwrap();
    assert_eq!(*reads.borrow(), 0);
    run(&listed, &any_asset).unwrap();
    assert_eq!(*reads.borrow(), 1);
}

/// A build with no reader refuses a listed asset, and a failing reader's own
/// error is the refusal, not an rgb-lib network error.
#[test]
fn a_listed_asset_is_refused_when_its_list_cannot_be_read() {
    let bytes = listed_burn().0.consignment();
    let chain = mined(&witness_ids(&bytes));
    let failing = |_: &RejectListContract| -> Result<Decisions> { Err(not_ready("evm-rpc")) };
    let run = |read| {
        let lists = ListAccess {
            bind_asset: &any_asset,
            read,
        };
        validator()
            .validate_consignment(&bytes, Some(&bind_all), &chain, &lists)
            .expect_err("a listed asset needs its list")
    };
    let err = run(None).to_string();
    assert!(err.contains("cannot read it"), "{err}");
    assert_own_error(run(Some(&failing)), "evm-rpc");
}

/// A failure that is not a cross-check, so its variant shows it came through.
fn not_ready(what: &str) -> crate::error::EnclaveError {
    crate::error::EnclaveError::NotReady {
        state: format!("{what} down"),
    }
}

/// `err` is the resolver's own error, not rgb-lib's network error about it.
fn assert_own_error(err: crate::error::EnclaveError, what: &str) {
    let text = err.to_string();
    assert!(
        matches!(&err, crate::error::EnclaveError::NotReady { state } if *state == format!("{what} down")),
        "{text}"
    );
    assert!(!text.contains("witness is not proven"), "{text}");
}

/// The resolver reads only the genesis list: any other source rgb-lib names
/// is refused unread, and the refusal is ours.
#[test]
fn the_list_resolver_refuses_a_source_other_than_the_genesis_list() {
    use rgb_lib::no_wallet::{RejectListSource, ResolveRejectList};
    let reads = RefCell::new(0);
    let read = |_: &RejectListContract| {
        *reads.borrow_mut() += 1;
        Ok(Decisions::default())
    };
    let genesis_list = RejectListContract {
        chain_id: EVM_CHAIN_ID,
        address: LIST,
    };
    let resolver = ListResolver::new(genesis_list, &read);
    for other in [
        RejectListSource::from(gen::evm_reject_list(EVM_CHAIN_ID, [0x77; 20])),
        RejectListSource::from(gen::evm_reject_list(1, LIST)),
        RejectListSource::Url("https://example.com/list".into()),
    ] {
        assert!(resolver.get_reject_list(&other).is_err(), "{other:?}");
        let failure = resolver
            .take_failure()
            .expect("our own refusal")
            .to_string();
        assert!(failure.contains("not the genesis list"), "{failure}");
    }
    assert_eq!(*reads.borrow(), 0);
    let genesis = RejectListSource::from(gen::evm_reject_list(EVM_CHAIN_ID, LIST));
    resolver
        .get_reject_list(&genesis)
        .expect("the genesis list is read");
    assert_eq!(*reads.borrow(), 1);
}

/// The reject-list decisions, ported from rgb-lib `api/evm.rs`.
mod reject_list_rules {
    use super::*;
    use std::collections::BTreeSet;

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
}

/// The pinned asset admits one genesis, under the schema that `rgb-schemas`
/// compiles. A rev bump that changes the schema id therefore changes the
/// consensus rules the pinned asset validates under, which needs a reissue and
/// a new PCR0. It must fail loudly here.
#[test]
fn bfa_schema_id_is_pinned() {
    assert_eq!(
        bfa_schema::BFA_SCHEMA_ID.to_string(),
        "rgb:sch:3I0xZVEQnQxYVk7vDnh5uNtQyUfsmThw6dX9n_Gvb5o#mama-swing-album"
    );
    use rgbstd::contract::IssuerWrapper;
    let rules = schemata::BridgedFungibleAsset::schema_rules();
    assert_eq!(rules.schema().schema_id(), bfa_schema::BFA_SCHEMA_ID);
}

// ===== a burn, end to end =====

/// rgb-lib's burn with change: a split transfer, then the burn of its output,
/// in one bundle. The burn settles and has no outputs.
#[test]
fn validates_rgb_libs_split_burn_shape() {
    let (history, burn) = burn_history(Some(60_000), Some(gen::burn_reason_for(PAYEE)));
    let validated = validate(&history.consignment()).expect("the burn is valid");

    assert_eq!(validated.contract_id, history.contract_id.to_string());
    assert_eq!(validated.chain_net, "bcrt");
    assert_eq!(validated.witness_txids.len(), 2);
    assert_eq!(validated.settling_op_id, Some(gen::opid_bytes(burn.opid)));
    assert_eq!(
        validated.settling_witness_txid,
        Some(burn.tx.compute_txid())
    );

    let last = validated
        .settling_transition
        .as_ref()
        .expect("the settling burn");
    assert_eq!(last.transition_type, TypeOfTransition::Burn);
    assert_eq!(last.op_id, burn.opid.to_string());
    assert_eq!(last.burned_asset_amount, Some(60_000));
    assert_eq!(last.burn_reason, Some(gen::burn_reason_for(PAYEE)));
    assert!(
        last.outputs.is_empty(),
        "the schema gives a burn no outputs"
    );
    assert_eq!(last.asset_output_amount, 0);

    let group = validated.transitions_committed_by(burn.tx.compute_txid());
    let types: Vec<TypeOfTransition> = group.iter().map(|t| t.transition_type).collect();
    assert_eq!(types, [TypeOfTransition::Transfer, TypeOfTransition::Burn]);
    let change = TransitionOutput {
        amount: 40_000,
        seal: OutputSeal::Revealed {
            txid: None,
            vout: 1,
        },
    };
    assert!(
        group[0].outputs.contains(&change),
        "the burner keeps change"
    );
    assert_eq!(group[0].asset_output_amount, MINTED);

    // The mint's claim was confirmed against its lock, and only it.
    let mint = history.mints[0];
    assert_eq!(
        validated.mint_locks,
        vec![VerifiedLock {
            lock_id: mint.lock_id(),
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
    let validated = validate(&history.consignment()).expect("the burn is valid");
    assert_eq!(validated.witness_txids.len(), 3);
    let locked: Vec<[u8; 32]> = validated.mint_locks.iter().map(|l| l.lock_id).collect();
    assert_eq!(locked, vec![history.mints[0].lock_id()]);
}

/// rgb-lib inspects the bundles holding a terminal operation. The rights send
/// and the mint are spent by what follows them, so only the burn's bundle is
/// read. Validation is what covers the two it skips.
#[test]
fn inspects_the_terminal_bundle_alone() {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(right, 3);
    let units = history.mint_owned(rights[2], MINTED, 90);
    let burn = history.burn(
        units,
        MINTED,
        Some(MINTED),
        Some(gen::burn_reason_for(PAYEE)),
    );
    let validated = validate(&history.consignment()).expect("the burn is valid");

    assert_eq!(
        validated.witness_txids.len(),
        3,
        "the rights send, the mint and the burn"
    );
    let inspected: Vec<bitcoin::Txid> = validated
        .transitions_by_witness
        .iter()
        .map(|(txid, _)| *txid)
        .collect();
    assert_eq!(inspected, vec![burn.tx.compute_txid()]);
    assert!(
        validated
            .transitions_committed_by(history.mints[0].witness_id)
            .is_empty(),
        "the mint's bundle is not inspected"
    );
    assert_eq!(
        validated.settling_transition.map(|t| t.op_id),
        Some(burn.opid.to_string()),
        "the settling burn comes from the one inspected bundle"
    );
}

/// A burn and a later transfer of what it left are both terminal, so both
/// bundles are inspected. The burn settles, with its own witness: the order of
/// the bundles does not decide it.
#[test]
fn settles_the_burn_before_a_terminal_transfer() {
    let (mut history, [burned, kept]) = minted_in_halves();
    let half = MINTED / 2;
    let burn = history.burn(burned, half, Some(half), Some(gen::burn_reason_for(PAYEE)));
    let sent = history.transfer(kept, half);
    assert_ne!(sent.outpoint.txid, burn.tx.compute_txid());

    let validated = validate(&history.consignment()).expect("the burn is valid");
    assert_eq!(
        validated.transitions_by_witness.len(),
        2,
        "the burn and the transfer are both terminal"
    );
    assert_eq!(
        validated.settling_witness_txid,
        Some(burn.tx.compute_txid())
    );
    let settling = validated.settling_transition.expect("the settling burn");
    assert_eq!(settling.transition_type, TypeOfTransition::Burn);
    assert_eq!(settling.burned_asset_amount, Some(half));
    assert_eq!(settling.op_id, burn.opid.to_string());
}

/// The enclave and consignment-utils (which the bridge uses) read the same
/// burn facts from the same bytes.
#[test]
fn burn_facts_agree_with_the_bridge_parser() {
    let bytes = burn_bytes();
    let validated = validate(&bytes).unwrap();
    let last = validated.settling_transition.unwrap();

    let rgb_consignment::ConsignmentInfo::Transfer(info) = rgb_consignment::parse(&bytes).unwrap()
    else {
        panic!("a transfer");
    };
    let anchor = info.witnesses.last().unwrap();
    let burn = anchor.transitions.last().unwrap();
    assert_eq!(burn.op_id, last.op_id);
    assert_eq!(
        Some(anchor.txid.parse::<bitcoin::Txid>().unwrap()),
        validated.settling_witness_txid
    );
    let global = |ty: u16| {
        let entry = burn.globals.iter().find(|g| g.global_type == ty).unwrap();
        hex::decode(&entry.value_hex).unwrap()
    };
    let burned = u64::from_le_bytes(global(2015).try_into().unwrap());
    assert_eq!(Some(burned), last.burned_asset_amount);
    assert_eq!(global(3009), last.burn_reason.unwrap().to_vec());
}

/// The schema does not require `burnReason`: validation passes and the release
/// bind refuses it (see `evm::crosscheck`).
#[test]
fn a_burn_without_burn_reason_validates_with_no_reason() {
    let (history, _) = burn_history(Some(MINTED), None);
    let last = validate(&history.consignment())
        .unwrap()
        .settling_transition
        .unwrap();
    assert_eq!(last.burn_reason, None);
    assert_eq!(last.burned_asset_amount, Some(MINTED));
}

/// rgb-lib puts the split before the burn that spends its output. Consensus
/// reads a bundle in order, so the burn first spends state it has not seen.
#[test]
fn refuses_a_split_burn_bundle_with_the_burn_before_the_split() {
    let (mut history, units) = minted();
    let mut burn = history.burn_transitions(units, MINTED, Some(MINTED / 4), None);
    burn.reverse();
    history.commit(burn, vec![units.outpoint], vec![gen::dust(9)]);
    let err = error_of(validate(&history.consignment()));
    assert!(err.contains("cannot be found"), "{err}");
}

/// A mint, then a transfer that splits the units into two halves on vout 1
/// and vout 2 of its witness tx.
fn minted_in_halves() -> (History, [Utxo; 2]) {
    let (history, units) = minted();
    split_in_halves(history, units)
}

/// A transfer that splits `units` (holding `MINTED`) into two halves on vout 1
/// and vout 2 of its witness tx.
fn split_in_halves(mut history: History, units: Utxo) -> (History, [Utxo; 2]) {
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
        opout: rgbstd::Opout::new(split_opid, bfa_schema::OS_ASSET, no),
        outpoint: OutPoint::new(tx.compute_txid(), u32::from(no) + 1),
    };
    (history, [half_at(0), half_at(1)])
}

/// Two burns in one bundle: only one could ever be released.
#[test]
fn refuses_two_burns_of_one_consignment() {
    let (mut history, halves) = minted_in_halves();
    let half = MINTED / 2;
    let burns = halves
        .iter()
        .map(|units| history.burn_transition(*units, half, Some(half), None))
        .collect();
    let inputs = halves.iter().map(|units| units.outpoint).collect();
    history.commit(burns, inputs, vec![gen::dust(3)]);
    let err = error_of(validate(&history.consignment()));
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

        let validated = validate(&history.consignment()).expect("burn and transfer");
        let last = validated
            .settling_transition
            .clone()
            .expect("the settling burn");
        assert_eq!(
            last.op_id,
            burn_opid.to_string(),
            "burn first: {burn_first}"
        );
        assert_eq!(last.burned_asset_amount, Some(half));
        assert_eq!(last.burn_reason, Some(gen::burn_reason_for(PAYEE)));
        assert_eq!(validated.settling_op_id, Some(gen::opid_bytes(burn_opid)));
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
        let result = validate(&history.consignment());
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
    let bytes = history.consignment();

    let seen = RefCell::new(Vec::new());
    let record = |anchors: &[MintAnchor]| {
        seen.borrow_mut().extend_from_slice(anchors);
        bind_all(anchors)
    };
    let validated = validate_bound(&bytes, Some(&record)).expect("the mint is valid");

    assert_eq!(
        *seen.borrow(),
        vec![MintAnchor {
            opid: gen::opid_bytes(mint.opid),
            lock_id: lock_id(mint.opid, mint.tx.compute_txid()),
            amount: MINTED,
            before_block: 90,
        }]
    );
    let last = validated.settling_transition.unwrap();
    assert_eq!(last.transition_type, TypeOfTransition::Mint);
    assert_eq!(last.asset_output_amount, MINTED);
    assert!(matches!(
        last.outputs[0].seal,
        OutputSeal::Confidential { .. }
    ));
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
    let err = error_of(validate(&mint_spending(elsewhere, vec![]).consignment()));
    assert!(err.contains("does not closes seal"), "{err}");
    assert!(err.contains(&right_utxo().to_string()), "{err}");
}

/// Control: the fee inputs of the mint witness tx do not matter.
#[test]
fn a_mint_witness_tx_may_spend_any_fee_input() {
    let right = issue().genesis_right(0, right_utxo());
    for fee in [gen::outpoint(0xF1, 0), gen::outpoint(0xF2, 3)] {
        validate(&mint_spending(right, vec![fee]).consignment())
            .expect("a different fee input keeps the mint valid");
    }
}

/// A build with no binder refuses any mint ancestry; it never confirms an
/// anchor blind, and never panics in `finalize`.
#[test]
fn refuses_mint_anchors_without_a_binder() {
    let err = error_of(validate_bound(&burn_bytes(), None));
    assert!(err.contains("no lock binder"), "{err}");
}

/// Every anchor needs exactly its own lock: one too few, one too many, or one
/// for another amount is refused.
#[test]
fn refuses_locks_that_do_not_match_the_anchors_one_for_one() {
    let bytes = burn_bytes();
    let none = |_: &[MintAnchor]| {
        Ok(BoundAnchors {
            evm_chain_id: EVM_CHAIN_ID,
            locks: vec![],
        })
    };
    let extra = |anchors: &[MintAnchor]| {
        let mut bound = bind_all(anchors)?;
        if let Some(anchor) = anchors.first() {
            bound.locks.push(VerifiedLock {
                lock_id: [0x77; 32],
                ..lock_for(anchor)
            });
        }
        Ok(bound)
    };
    let other_amount = |anchors: &[MintAnchor]| {
        let mut bound = bind_all(anchors)?;
        if let Some(lock) = bound.locks.first_mut() {
            lock.minted += 1;
        }
        Ok(bound)
    };
    let binders: [AnchorBinder<'_>; 3] = [&none, &extra, &other_amount];
    for bind in binders {
        let err = error_of(validate_bound(&bytes, Some(bind)));
        assert!(err.contains("exactly its own lock"), "{err}");
    }
}

/// Binds every anchor to a lock keyed by `key` instead of its lockId.
fn bind_keyed_by(
    key: impl Fn(&MintAnchor) -> [u8; 32],
) -> impl Fn(&[MintAnchor]) -> Result<BoundAnchors> {
    move |anchors| {
        let mut bound = bind_all(anchors)?;
        for (lock, anchor) in bound.locks.iter_mut().zip(anchors) {
            lock.lock_id = key(anchor);
        }
        Ok(bound)
    }
}

/// The claim names `LockId(opid, witness txid)`: a lock under the bare OpId,
/// or under the same OpId in another tx, backs nothing.
#[test]
fn refuses_a_lock_not_keyed_by_the_mint_lock_id() {
    let bytes = burn_bytes();
    let other_tx = bitcoin::Txid::from_byte_array([0x42; 32]);
    let bare_opid = bind_keyed_by(|a| a.opid);
    let in_other_tx = bind_keyed_by(|a| lock_id(rgbstd::OpId::from(a.opid), other_tx));
    let binders: [AnchorBinder<'_>; 2] = [&bare_opid, &in_other_tx];
    for bind in binders {
        let err = error_of(validate_bound(&bytes, Some(bind)));
        assert!(err.contains("exactly its own lock"), "{err}");
    }
}

/// The two upstream vectors (rgb-ops 0.11.2-rc.2 `claim.rs`). The txid bytes are in
/// internal order, and the digest is the ABI word with no byte reversal.
#[test]
fn lock_id_matches_the_upstream_vectors() {
    let opid = rgbstd::OpId::from(std::array::from_fn::<u8, 32, _>(|i| i as u8));
    let txid = bitcoin::Txid::from_byte_array(std::array::from_fn(|i| 32 + i as u8));
    assert_eq!(
        txid.to_string(),
        "3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"
    );
    let zero = (
        rgbstd::OpId::from([0u8; 32]),
        bitcoin::Txid::from_byte_array([0; 32]),
    );
    let cases = [
        (
            (opid, txid),
            "1ce683c92fdfb3ef54e39c7b461e731dad02cd240b366441f34a2c2e849a9876",
        ),
        (
            zero,
            "9b30b6d0fcafbb02dea72ca6f0a1829fe643dfc3ea394df702d96688ff3906a9",
        ),
    ];
    for ((opid, txid), expected) in cases {
        assert_eq!(hex::encode(lock_id(opid, txid)), expected);
        assert_eq!(gen::lock_id_bytes(opid, txid), lock_id(opid, txid));
    }
}

/// The bound chain id must be the genesis one, or rgb-lib's checked resolver
/// refuses before it confirms anything.
#[test]
fn refuses_locks_bound_on_another_chain() {
    let asked = RefCell::new(0);
    let other_chain = |anchors: &[MintAnchor]| {
        *asked.borrow_mut() += anchors.len();
        Ok(BoundAnchors {
            evm_chain_id: 1,
            ..bind_all(anchors)?
        })
    };
    let err = error_of(validate_bound(&burn_bytes(), Some(&other_chain)));
    assert!(err.contains("bound on EVM chain 1"), "{err}");
    assert!(
        err.contains(&format!("lives on chain {EVM_CHAIN_ID}")),
        "{err}"
    );
    assert_eq!(*asked.borrow(), 0, "no anchor is bound on the wrong chain");
}

/// rgb-lib asks the binder once with no anchor, for the pins and the chain
/// id, then once for each mint of the history.
#[test]
fn the_binder_is_asked_once_for_the_pins_and_once_per_mint() {
    let outpoints = vec![right_utxo(), gen::outpoint(0xA1, 0)];
    let mut history = History::issue(Issue::new(EVM_CHAIN_ID, BRIDGE, outpoints.clone()));
    let rights = [0, 1].map(|no| history.genesis_right(no, outpoints[usize::from(no)]));
    let units = rights.map(|right| history.mint_owned(right, MINTED, 90));
    let mut burn = history.transition("burn");
    for unit in &units {
        burn = burn
            .add_input(
                unit.opout,
                AllocatedState::from(RevealedValue::from(MINTED)),
            )
            .unwrap();
    }
    let burn = burn
        .add_global_state("burnedAsset", rgbstd::Amount::from(2 * MINTED))
        .unwrap()
        .complete_transition()
        .unwrap();
    let inputs = units.iter().map(|unit| unit.outpoint).collect();
    history.commit(vec![burn], inputs, vec![gen::dust(4)]);

    let calls = RefCell::new(Vec::new());
    let record = |anchors: &[MintAnchor]| {
        calls.borrow_mut().push(anchors.to_vec());
        bind_all(anchors)
    };
    let validated = validate_bound(&history.consignment(), Some(&record)).unwrap();
    let calls = calls.into_inner();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls[0].is_empty());
    let mut asked: Vec<[u8; 32]> = calls[1..].iter().map(|c| c[0].lock_id).collect();
    asked.sort();
    let mut minted: Vec<[u8; 32]> = history.mints.iter().map(gen::Mint::lock_id).collect();
    minted.sort();
    assert_eq!(asked, minted);
    assert!(calls[1..].iter().all(|c| c.len() == 1));
    assert_eq!(validated.mint_locks.len(), 2);
}

/// The locks must be the anchors one for one: a missing, an extra or a twice
/// bound pair is refused.
#[test]
fn check_bijection_refuses_a_missing_extra_or_repeated_lock() {
    let anchor = |n: u8| MintAnchor {
        opid: [n; 32],
        lock_id: [n + 0x10; 32],
        amount: MINTED,
        before_block: 90,
    };
    let anchors = [anchor(1), anchor(2)];
    let locks: Vec<VerifiedLock> = anchors.iter().map(lock_for).collect();
    check_bijection(&anchors, &locks).unwrap();
    let cases: [(&[MintAnchor], Vec<VerifiedLock>); 3] = [
        (&anchors, locks[..1].to_vec()),
        (&anchors[..1], locks.clone()),
        (
            &[anchor(1), anchor(1)],
            vec![locks[0].clone(), locks[0].clone()],
        ),
    ];
    for (anchors, locks) in cases {
        let err = check_bijection(anchors, &locks).unwrap_err().to_string();
        assert!(err.contains("exactly its own lock"), "{err}");
    }
}

// ===== the flat summary =====

/// The settling transition is the one burn the terminal bundles hold, with the
/// witness of its own bundle, whichever bundle that is. Two burns are refused,
/// and without a burn the last transition read settles, which the flow check
/// then refuses.
#[test]
fn settling_summary_takes_the_one_burn_of_the_terminal_bundles() {
    use super::consensus::settling_summary;
    let txid = |b: u8| bitcoin::Txid::from_byte_array([b; 32]);
    let of = |ty| transition_summary(&inspected_transition(ty, vec![]), WITNESS, "bcrt:").unwrap();
    let transfer = of(TypeOfTransition::Transfer);
    let burn = of(TypeOfTransition::Burn);

    assert!(settling_summary(&[]).unwrap().is_none());

    for burn_first in [true, false] {
        let groups = if burn_first {
            vec![
                (txid(1), vec![burn.clone()]),
                (txid(2), vec![transfer.clone()]),
            ]
        } else {
            vec![
                (txid(1), vec![transfer.clone()]),
                (txid(2), vec![burn.clone()]),
            ]
        };
        let (witness, settling) = settling_summary(&groups).unwrap().unwrap();
        assert_eq!(settling.transition_type, TypeOfTransition::Burn);
        assert_eq!(witness, txid(if burn_first { 1 } else { 2 }));
    }

    let two_burns = vec![(txid(1), vec![burn.clone()]), (txid(2), vec![burn.clone()])];
    let err = settling_summary(&two_burns).unwrap_err().to_string();
    assert!(err.contains("2 burns"), "{err}");

    let no_burn = vec![
        (txid(1), vec![transfer.clone()]),
        (txid(2), vec![transfer.clone(), transfer.clone()]),
    ];
    let (witness, settling) = settling_summary(&no_burn).unwrap().unwrap();
    assert_eq!(settling.transition_type, TypeOfTransition::Transfer);
    assert_eq!(witness, txid(2));
}

/// The display-order txid of the witness the inspected transitions sit in.
const WITNESS: [u8; 32] = [0x77; 32];

fn output(assignment: Assignment, txid: [u8; 32], vout: u32) -> RgbOutputInfo {
    RgbOutputInfo {
        txid: Some(hex::encode(txid)),
        vout: Some(vout),
        assignment,
        is_concealed: false,
        recipient_id: None,
        is_ours: None,
        is_terminal: Some(true),
        blinding: None,
    }
}

fn concealed(amount: u64, recipient: Option<&str>) -> RgbOutputInfo {
    RgbOutputInfo {
        txid: None,
        vout: None,
        is_concealed: true,
        recipient_id: recipient.map(str::to_string),
        ..output(Assignment::Fungible(amount), WITNESS, 0)
    }
}

fn inspected_transition(ty: TypeOfTransition, outputs: Vec<RgbOutputInfo>) -> RgbTransitionInfo {
    RgbTransitionInfo {
        r#type: ty,
        opid: "mint-op".into(),
        inputs: vec![],
        outputs,
        globals: vec![],
        metadata: vec![],
    }
}

/// The summary of `outputs` in a transfer on regtest.
fn summary_of(outputs: Vec<RgbOutputInfo>) -> Result<TransitionSummary> {
    let t = inspected_transition(TypeOfTransition::Transfer, outputs);
    transition_summary(&t, WITNESS, "bcrt:")
}

/// rgb-lib lists amounts per output: their sum is checked here.
#[test]
fn transition_summary_refuses_an_overflowing_total() {
    let err = summary_of(vec![
        output(Assignment::Fungible(u64::MAX), WITNESS, 1),
        output(Assignment::Fungible(1), WITNESS, 2),
    ])
    .unwrap_err()
    .to_string();
    assert!(err.contains("output amount overflow"), "{err}");
}

/// Each inspected type reads as the BFA schema id rgb-lib maps it from.
#[test]
fn transition_summary_keeps_the_schema_transition_type() {
    for ty in [
        bfa_schema::TS_TRANSFER,
        bfa_schema::TS_INFLATION,
        bfa_schema::TS_BURN,
        bfa_schema::TS_LINK,
        bfa_schema::TS_MINT,
        bfa_schema::TS_PROPAGATE,
        bfa_schema::TS_TRANSFER_INFLATION,
        bfa_schema::TS_TRANSFER_LINK,
    ] {
        let t = inspected_transition(bfa_schema::type_of(ty), vec![]);
        let summary = transition_summary(&t, WITNESS, "bcrt:").unwrap();
        assert_eq!(summary.transition_type, bfa_schema::type_of(ty), "{ty}");
    }
}

#[test]
fn transition_summary_refuses_a_concealed_seal_of_another_chain_or_none() {
    for recipient in [Some("bc:utxob:abc"), Some("utxob:abc"), None] {
        let err = summary_of(vec![concealed(1, recipient)])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("is not a bcrt: recipient"),
            "{recipient:?}: {err}"
        );
    }
}

#[test]
fn transition_summary_refuses_a_seal_it_cannot_read_exactly() {
    let short = RgbOutputInfo {
        txid: Some("abcd".into()),
        ..output(Assignment::Fungible(1), WITNESS, 0)
    };
    let err = summary_of(vec![short]).unwrap_err().to_string();
    assert!(err.contains("not 32 bytes"), "{err}");
    let no_vout = RgbOutputInfo {
        vout: None,
        ..output(Assignment::Fungible(1), WITNESS, 0)
    };
    let err = summary_of(vec![no_vout]).unwrap_err().to_string();
    assert!(err.contains("without a txid and vout"), "{err}");
}

/// A BFA `mint` is the only mint shape, and a signing shape only in the
/// mint/burn flow. The ids are the schema's, which `bfa_schema::tests` pins.
#[test]
fn mint_transitions_are_the_only_mint_shape() {
    assert_eq!(bfa_schema::type_of(8013), TypeOfTransition::Mint);
    assert_eq!(bfa_schema::type_of(10000), TypeOfTransition::Transfer);
    assert_eq!(bfa_schema::type_of(8010), TypeOfTransition::Burn);
    assert!(super::super::flow::is_signing_transition(
        rgb_lib::TypeOfTransition::Mint
    ));
    assert!(!super::super::flow::is_signing_transition(
        rgb_lib::TypeOfTransition::Propagate
    ));
}

// ===== the validator =====

#[test]
fn rejects_unknown_network() {
    let err = RgbValidator::new("foonet").unwrap_err();
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
        let v = RgbValidator::new(network).unwrap();
        assert_eq!(v.chain_net.prefix(), prefix, "{network}");
    }
}

/// The rgb-lib report of the transfer we parsed, as it gives it for `bytes`.
fn rgb_lib_report(bytes: &[u8]) -> rgb_lib::no_wallet::ConsignmentValidation {
    use rgbstd::containers::ConsignmentExt;
    let transfer = rgbstd::containers::Transfer::load(std::io::Cursor::new(bytes)).unwrap();
    rgb_lib::no_wallet::ConsignmentValidation {
        consignment_id: transfer.consignment_id().to_string(),
        is_transfer: true,
        asset_id: transfer.contract_id().to_string(),
        asset_schema: rgb_lib::AssetSchema::Bfa,
        safe_height: None,
        witnesses: vec![],
        warnings: vec![],
    }
}

/// rgb-lib must have validated our transfer, and any warning refuses.
#[test]
fn an_rgb_lib_report_of_another_file_or_with_a_warning_is_refused() {
    use super::consensus::check_validation;
    use rgb_lib::no_wallet::ValidationWarning;
    let bytes = burn_bytes();
    let transfer = rgbstd::containers::Transfer::load(std::io::Cursor::new(&bytes[..])).unwrap();
    check_validation(&rgb_lib_report(&bytes), &transfer).unwrap();
    let other = rgb_lib_report(&listed_burn().0.consignment());
    let err = check_validation(&other, &transfer).unwrap_err().to_string();
    assert!(err.contains("not the transfer"), "{err}");
    let contract = rgb_lib::no_wallet::ConsignmentValidation {
        is_transfer: false,
        ..rgb_lib_report(&bytes)
    };
    assert!(check_validation(&contract, &transfer).is_err());
    for warning in [
        ValidationWarning::InvalidSpvProof {
            bundle_id: "b".into(),
            txid: "t".into(),
        },
        ValidationWarning::Other {
            details: "d".into(),
        },
        ValidationWarning::UnsafeHistory {
            txids: vec!["t".into()],
        },
    ] {
        let warned = rgb_lib::no_wallet::ConsignmentValidation {
            warnings: vec![warning],
            ..rgb_lib_report(&bytes)
        };
        let err = check_validation(&warned, &transfer)
            .unwrap_err()
            .to_string();
        assert!(err.contains("with the warning"), "{err}");
    }
}

/// The split-burn shape has one terminal bundle, and its burn settles.
#[test]
fn the_settling_transition_is_the_burn_of_the_terminal_bundle() {
    use super::consensus::settling_summary;
    let inspected = summary::terminal_bundles(&burn_bytes()).unwrap();
    assert_eq!(inspected.len(), 1, "the burn is the one terminal operation");
    let (witness, settling) = settling_summary(&inspected).unwrap().unwrap();
    assert_eq!(settling.transition_type, TypeOfTransition::Burn);
    assert_eq!(settling.burned_asset_amount, Some(60_000));
    assert_eq!(witness, inspected[0].0);
}

/// The rgb-lib refusals no resolver of ours can raise still read as what they
/// mean for a release.
#[test]
fn each_rgb_lib_refusal_names_what_failed() {
    use super::consensus::validation_error;
    use rgb_lib::Error as E;
    let list = RejectListContract {
        chain_id: EVM_CHAIN_ID,
        address: LIST,
    };
    let cases = [
        (E::MintLockNotFound { opid: "op".into() }, "no bound lock"),
        (E::NoClaimResolver, "no lock binder"),
        (E::NoRejectListResolver, "cannot read it"),
        (
            E::ConsignmentRejected { opouts: vec![] },
            "Consignment rejected by the reject list",
        ),
        (
            E::EvmChainIdMismatch {
                expected: 1,
                actual: 2,
            },
            "bound on EVM chain 2",
        ),
        (
            E::ConsignmentValidationFailed {
                details: "bad".into(),
            },
            "RGB consignment validation failed",
        ),
    ];
    for (e, expected) in cases {
        let err = validation_error(e, Some(&list)).to_string();
        assert!(err.contains(expected), "{err}");
    }
    let rejected = validation_error(E::ConsignmentRejected { opouts: vec![] }, Some(&list));
    assert!(
        rejected.to_string().contains(&hex::encode(LIST)),
        "{rejected}"
    );
}

/// The reject refusal counts the rejected origins and names only the first:
/// a wide burn can reject thousands, and the gateway returns the whole text.
#[test]
fn a_reject_refusal_names_one_rejected_origin_of_many() {
    use super::consensus::validation_error;
    let opouts = ["a/4000/0", "b/4000/1", "c/4000/2"]
        .map(String::from)
        .to_vec();
    let err = validation_error(rgb_lib::Error::ConsignmentRejected { opouts }, None).to_string();
    assert!(
        err.contains("3 rejected opouts, the first a/4000/0"),
        "{err}"
    );
    assert!(
        !err.contains("b/4000/1") && !err.contains("c/4000/2"),
        "{err}"
    );
    assert!(err.contains(REJECT_LIST_REFUSAL), "{err}");
}

/// A failure a resolver recorded refuses, even when rgb-lib returned Ok past it.
#[test]
fn a_recorded_resolver_failure_wins_over_rgb_libs_result() {
    use super::consensus::resolver_failure_first;
    let recorded = || {
        Some(crate::error::EnclaveError::CrossCheck(
            "the list read failed".into(),
        ))
    };
    for rgb_lib in [Ok(()), Err(rgb_lib::Error::NoRejectListResolver)] {
        let err = resolver_failure_first(rgb_lib, recorded(), None).unwrap_err();
        assert!(err.to_string().contains("the list read failed"), "{err}");
    }
    resolver_failure_first(Ok(()), None, None).unwrap();
    let err = resolver_failure_first::<()>(Err(rgb_lib::Error::NoRejectListResolver), None, None);
    assert!(err.unwrap_err().to_string().contains("cannot read it"));
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
    history.consignment()
}

/// A rights send of the genesis right, then a mint a PSBT would sign on one
/// of the new rights.
fn mint_after_a_rights_send() -> Vec<u8> {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(right, 2);
    history.mint_owned(rights[0], MINTED, 90);
    history.consignment()
}

/// `bytes` with each bundle's SPV proof passed through `change`.
fn reproven(
    bytes: &[u8],
    mut change: impl FnMut(bitcoin::Txid, &mut Option<rgbstd::validation::SpvProof>),
) -> Vec<u8> {
    let mut transfer = rgbstd::containers::Transfer::load(std::io::Cursor::new(bytes)).unwrap();
    for bundle in transfer.bundles.iter_mut() {
        change(bundle.witness_id(), &mut bundle.spv_proof);
    }
    gen::save(&transfer)
}

/// Every witness is mined, but the consignment proves all except `unproven`.
fn validate_without(bytes: &[u8], unproven: bitcoin::Txid) -> Result<ValidatedConsignment> {
    let chain = mined(&witness_ids(bytes));
    let bytes = reproven(bytes, |txid, proof| {
        if txid == unproven {
            *proof = None;
        }
    });
    validator().validate_consignment(&bytes, Some(&bind_all), &chain, &open_lists())
}

#[cfg(rgb_to_evm)]
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
    // Each witness is placed in the block the generator proved it in.
    let chain = mined(&witness_ids(&bytes));
    let mut heights = Vec::new();
    for (block, txid) in validated
        .witness_blocks
        .iter()
        .zip(&validated.witness_txids)
    {
        assert_eq!(block.txid, *txid);
        let header = chain.headers[&block.height];
        assert_eq!(block.hash, header.block_hash().to_byte_array());
        heights.push(block.height);
    }
    assert_eq!(heights, vec![1, 2, 3]);
}

/// Two conflicting off-chain transfers are each valid alone. Only the mined
/// one may back a burn.
#[test]
fn burn_path_refuses_an_unmined_transfer_in_the_history() {
    let bytes = burn_after_transfer();
    let transfer = witness_ids(&bytes)[1];
    let err = error_of(validate_without(&bytes, transfer));
    assert!(err.contains("not proven on chain"), "{err}");
    assert!(err.contains(&transfer.to_string()), "{err}");
}

/// The send is history, and the mint consumes the right it made.
#[test]
fn accepts_a_mint_on_a_right_from_a_rights_send() {
    let validated = validate(&mint_after_a_rights_send()).expect("the history is valid");
    assert_eq!(validated.mint_locks.len(), 1);
}

/// The burn itself needs its proof too: the burn path allows no unmined tx.
#[test]
fn burn_path_refuses_an_unmined_burn_witness() {
    let bytes = burn_bytes();
    let burn = *witness_ids(&bytes).last().unwrap();
    let err = error_of(validate_without(&bytes, burn));
    assert!(err.contains("not proven on chain"), "{err}");
}

/// The enclave checks a proof only against a header of its own chain.
#[test]
fn a_proof_at_a_height_the_enclave_has_no_header_for_is_refused() {
    let bytes = burn_bytes();
    let chain = mined(&witness_ids(&bytes));
    let burn = *witness_ids(&bytes).last().unwrap();
    let bytes = reproven(&bytes, |txid, proof| {
        if txid == burn {
            proof.as_mut().unwrap().block_height = std::num::NonZeroU32::new(900_000).unwrap();
        }
    });
    let err =
        error_of(validator().validate_consignment(&bytes, Some(&bind_all), &chain, &open_lists()));
    assert!(err.contains("no header at height 900000"), "{err}");
}

/// A proof that does not lead to the enclave's header proves nothing, and the
/// enclave looks no transaction up in its place.
#[test]
fn a_proof_that_does_not_hold_against_the_enclave_header_is_refused() {
    use bitcoin::hashes::Hash;
    let bytes = burn_bytes();
    let chain = mined(&witness_ids(&bytes));
    let burn = *witness_ids(&bytes).last().unwrap();
    let bytes = reproven(&bytes, |txid, proof| {
        if txid == burn {
            let proof = proof.as_mut().unwrap();
            proof.pos = 1;
            proof.merkle = amplify::confinement::Confined::try_from(vec![
                bitcoin::TxMerkleNode::from_byte_array([0x5a; 32]),
            ])
            .unwrap();
        }
    });
    let err =
        error_of(validator().validate_consignment(&bytes, Some(&bind_all), &chain, &open_lists()));
    assert!(err.contains("not proven on chain"), "{err}");
    assert!(err.contains(&burn.to_string()), "{err}");
}

/// A header source that serves a block above its safe height: rgb-lib's own
/// depth warning refuses the history.
#[test]
fn a_witness_above_the_safe_height_is_refused() {
    struct Shallow(MinedBlocks);
    impl BuriedHeaders for Shallow {
        fn buried_header(&self, height: u32) -> Result<bitcoin::block::Header> {
            self.0.buried_header(height)
        }
        fn safe_height(&self) -> Option<std::num::NonZeroU32> {
            let safe = self.0.safe_height()?.get() - 1;
            std::num::NonZeroU32::new(safe)
        }
    }
    let bytes = burn_bytes();
    let chain = Shallow(mined(&witness_ids(&bytes)));
    let err =
        error_of(validator().validate_consignment(&bytes, Some(&bind_all), &chain, &open_lists()));
    assert!(err.contains("UnsafeHistory"), "{err}");
}

/// A failing header source, binder or list reader refuses with its own
/// error; none of them is ever read as a pass.
#[test]
fn a_failing_resolver_refuses_with_its_own_error() {
    struct Down;
    impl BuriedHeaders for Down {
        fn buried_header(&self, _: u32) -> Result<bitcoin::block::Header> {
            Err(not_ready("headers"))
        }
        fn safe_height(&self) -> Option<std::num::NonZeroU32> {
            None
        }
    }
    let binder = |_: &[MintAnchor]| -> Result<BoundAnchors> { Err(not_ready("binder")) };
    let reader = |_: &RejectListContract| -> Result<Decisions> { Err(not_ready("reader")) };
    let read_failing = ListAccess {
        bind_asset: &any_asset,
        read: Some(&reader),
    };
    let bytes = listed_burn().0.consignment();
    let chain = mined(&witness_ids(&bytes));
    let v = validator();
    let headers_down = v.validate_consignment(&bytes, Some(&bind_all), &Down, &open_lists());
    assert_own_error(
        headers_down.expect_err("the header source is down"),
        "headers",
    );
    let binder_down = v.validate_consignment(&bytes, Some(&binder), &chain, &open_lists());
    assert_own_error(binder_down.expect_err("the binder is down"), "binder");
    let reader_down = v.validate_consignment(&bytes, Some(&bind_all), &chain, &read_failing);
    assert_own_error(reader_down.expect_err("the reader is down"), "reader");
}

/// Two rights sends, the second spending a right of the first, then a mint
/// on a right of the second.
fn mint_after_two_rights_sends() -> Vec<u8> {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(right, 2);
    let rights = history.duplicate_right(rights[0], 2);
    history.mint_owned(rights[1], MINTED, 90);
    history.consignment()
}

/// A header source that records each height it is asked for.
struct Recording<'a> {
    chain: &'a MinedBlocks,
    asked: RefCell<Vec<u32>>,
}

impl BuriedHeaders for Recording<'_> {
    fn buried_header(&self, height: u32) -> Result<bitcoin::block::Header> {
        self.asked.borrow_mut().push(height);
        self.chain.buried_header(height)
    }

    fn safe_height(&self) -> Option<std::num::NonZeroU32> {
        self.chain.safe_height()
    }
}

/// The burn path places each witness from its own proof and header.
#[test]
fn burn_path_reads_a_header_for_every_witness() {
    let bytes = mint_after_two_rights_sends();
    let ids = witness_ids(&bytes);
    let chain = mined(&ids);
    let source = Recording {
        chain: &chain,
        asked: RefCell::new(Vec::new()),
    };
    validator()
        .validate_consignment(&bytes, Some(&bind_all), &source, &open_lists())
        .unwrap();
    let mut asked = source.asked.into_inner();
    asked.sort_unstable();
    let all: Vec<u32> = (1..=u32::try_from(ids.len()).unwrap()).collect();
    assert_eq!(asked, all);
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

/// The source path end to end: consensus over the consignment's SPV proofs,
/// the asset bind, then the chain check of the witness blocks.
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

    /// The chain with every witness of `consignment` mined, 6 deep.
    fn chain_of(consignment: &[u8]) -> Mutex<HeaderChain> {
        crate::test_support::chain_with_witnesses(&display(&witness_ids(consignment)), 5)
    }

    /// Runs `source` with every witness mined, 6 deep.
    fn run(
        source: &crate::proto::RgbSource,
        config: &BridgeConfig,
    ) -> Result<ValidatedConsignment> {
        run_on(source, config, &chain_of(&source.consignment))
    }

    /// Runs `source` with every witness mined, 6 deep, and the proof of
    /// `unproven` taken out of the consignment.
    fn run_without_proof(
        source: &crate::proto::RgbSource,
        config: &BridgeConfig,
        unproven: bitcoin::Txid,
    ) -> Result<ValidatedConsignment> {
        let chain = chain_of(&source.consignment);
        let consignment = reproven(&source.consignment, |txid, proof| {
            if txid == unproven {
                *proof = None;
            }
        });
        let source = crate::proto::RgbSource {
            consignment_hash: keccak(&consignment),
            consignment,
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
        assert_eq!(
            validated.witness_blocks.len(),
            validated.witness_txids.len()
        );
    }

    /// A history witness the consignment does not prove is unmined to
    /// consensus, which refuses before any later check.
    #[test]
    fn refuses_a_history_witness_without_a_proof() {
        let id = asset_id();
        let source = burn_source(&id);
        let ids = witness_ids(&source.consignment);
        let err = run_without_proof(&source, &pinned_config(&id), ids[0])
            .unwrap_err()
            .to_string();
        assert!(err.contains("not proven on chain"), "{err}");
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
        let err = run_without_proof(&source, &pinned_config(&id), ids[1])
            .unwrap_err()
            .to_string();
        assert!(err.contains("not proven on chain"), "{err}");
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
        let source = burn_source(&id);
        let witnesses = validate(&source.consignment).unwrap().witness_txids;
        let chain = crate::test_support::chain_with_witnesses(&witnesses, 1);

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
        let bytes = history.consignment();
        let id = history.contract_id.to_string();
        let source = crate::proto::RgbSource {
            consignment_hash: keccak(&bytes),
            consignment: bytes.clone(),
            ..burn_source(&id)
        };
        let chain = chain_of(&bytes);
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
            bfa_schema::OS_ASSET,
            0,
        )
    }

    #[test]
    fn burn_with_rejected_ancestry_is_refused() {
        let (_, right, ..) = listed_burn();
        let (result, reads) = run_listed(None, &[(right.opout, true)]);
        assert_rejected(result);
        assert_eq!(reads, 1);
    }

    #[test]
    fn burn_with_unrelated_entries_is_signed() {
        let (result, reads) = run_listed(None, &[(unrelated(), true)]);
        result.unwrap();
        assert_eq!(reads, 1);
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

/// Validates one small burn before a measurement, as `measure_dispatch` does.
/// The one-time build of the schema rules then stays outside the meter. Boot
/// builds them in production.
fn warm_up() {
    validate(&burn_bytes()).unwrap();
}

/// The request memory model (`memory.rs`): validating a consignment stays
/// within the memory factor. A history of 2_000 transfers is about 1 MiB.
#[test]
fn consignment_validation_stays_within_the_request_memory_factor() {
    use crate::memory::peak;

    warm_up();
    let (consignment, validated, peak) = peak::measure(
        || long_history(2_000).consignment(),
        |consignment| validate(consignment),
    );
    assert_eq!(validated.unwrap().witness_txids.len(), 2_002);
    peak::assert_within_factor("consignment validation", consignment.len(), peak);
}

/// A mint, then one transfer that splits the units into `outputs` outputs,
/// all on one vout with their own blinding.
fn wide_split(outputs: u16) -> History {
    let (mut history, units) = minted();
    let share = MINTED / u64::from(outputs);
    let mut split = history
        .transition("transfer")
        .add_input(
            units.opout,
            AllocatedState::from(RevealedValue::from(MINTED)),
        )
        .unwrap();
    for no in 0..outputs {
        let seal = GraphSeal::with_blinded_vout(1u32, 0x3000 + u64::from(no));
        split = split.add_fungible_state("assetOwner", seal, share).unwrap();
    }
    let split = split.complete_transition().unwrap();
    history.commit(vec![split], vec![units.outpoint], vec![gen::dust(1)]);
    history
}

/// One transfer that turns the mint right `input` into `outputs` mint
/// rights. The first right sits alone on vout 2, and the others share vout 1
/// with their own blinding. Returns the right on vout 2, which the next
/// transfer can spend.
fn send_wide_rights(history: &mut History, input: Utxo, outputs: u16, salt: u64) -> Utxo {
    let mut send = history
        .transition("propagate")
        .add_input(input.opout, AllocatedState::Void)
        .unwrap();
    for no in 0..outputs {
        let vout = if no == 0 { 2u32 } else { 1u32 };
        let seal = GraphSeal::with_blinded_vout(vout, salt + u64::from(no));
        send = send.add_rights("mintRight", seal).unwrap();
    }
    let send = send.complete_transition().unwrap();
    let index = send
        .assignments
        .get(&bfa_schema::OS_MINT)
        .unwrap()
        .seals()
        .position(|seal| matches!(seal, BuilderSeal::Revealed(s) if s.vout.to_u32() == 2))
        .unwrap() as u16;
    let opid = rgbstd::Operation::id(&send);
    let tx = history.commit(
        vec![send],
        vec![input.outpoint],
        vec![gen::dust(1), gen::dust(2)],
    );
    Utxo {
        opout: rgbstd::Opout::new(opid, bfa_schema::OS_MINT, index),
        outpoint: OutPoint::new(tx.compute_txid(), 2),
    }
}

/// `sends` chained transfers of `outputs` mint rights each on the asset of
/// `history`, then a mint on the last right and a full burn. The history of
/// the burn carries the wide transfers.
fn wide_rights_burn(mut history: History, sends: u64, outputs: u16) -> History {
    let mut right = history.genesis_right(0, right_utxo());
    for k in 1..=sends {
        right = send_wide_rights(&mut history, right, outputs, 0x10_0000 * k);
    }
    let units = history.mint_owned(right, MINTED, 90);
    history.burn(
        units,
        MINTED,
        Some(MINTED),
        Some(gen::burn_reason_for(PAYEE)),
    );
    history
}

/// A genesis of five mint rights whose OpId sorts above every transfer of
/// [`dense_rights_burn`], and the tag of their outpoints.
fn high_genesis() -> (History, u8) {
    (0u8..=255)
        .map(|tag| {
            let rights = (0..5).map(|no| gen::outpoint(tag, no)).collect();
            (
                History::issue(Issue::new(EVM_CHAIN_ID, BRIDGE, rights)),
                tag,
            )
        })
        .find(|(history, _)| rgbstd::Operation::id(&history.genesis).to_byte_array()[0] >= 0xF8)
        .expect("a tag gives a genesis OpId that starts with 0xF8 or more")
}

/// Sets the nonce of `send` so that the first byte of its OpId is in
/// `first`, and returns the OpId. Only the nonce of the commitment changes,
/// so each try is one hash.
fn opid_in(send: &mut rgbstd::Transition, first: std::ops::Range<u8>) -> rgbstd::OpId {
    use rgbstd::rgbcore::commit_verify::CommitId;

    let mut commitment = send.commit();
    send.nonce = (1u64..)
        .find(|&nonce| {
            commitment.nonce = nonce;
            first.contains(&commitment.commit_id().to_byte_array()[0])
        })
        .unwrap();
    rgbstd::Operation::id(&*send)
}

/// The densest rights chain found: `sends` transfers of `outputs` mint
/// rights each, then a mint on the last right and a full burn. The sender
/// sets two layouts that add heap to each right:
///
/// - The number of rights in a transfer. strict_encoding reserves at most
///   64 KiB of a decoded list, which is 1 365 assignments, and then doubles
///   the list. So a decoded list of 1 366, 21 841 or 43 681 rights takes
///   twice its length. Validation clones the decoded consignment, so this
///   layout does not add heap at the peak.
/// - The OpIds. Each transfer has an OpId below the transfer before it.
///   So its opouts go in front of exactly five opouts in a leaf of the two
///   B-trees that RGB validation fills. Then each leaf that they fill keeps
///   5 keys, not 6. The genesis has five rights, and the second transfer
///   spends the first right of the first transfer, so both B-trees start
///   that way.
fn dense_rights_burn(sends: u8, outputs: u16) -> History {
    assert!(sends <= 18, "the OpId ranges are for 18 transfers at most");
    let (mut history, tag) = high_genesis();
    let mut right = history.genesis_right(4, gen::outpoint(tag, 4));
    for k in 1..=sends {
        // The right that the next transfer spends. On vout 1 it sorts first,
        // and on vout 3 it sorts last. The other rights share vout 2.
        let vout = if k == 1 { 1u32 } else { 3 };
        let mut send = history
            .transition("propagate")
            .add_input(right.opout, AllocatedState::Void)
            .unwrap()
            .add_rights("mintRight", GraphSeal::with_blinded_vout(vout, 1))
            .unwrap();
        for no in 1..outputs {
            let blinding = 0x10_0000 * u64::from(k) + u64::from(no);
            send = send
                .add_rights("mintRight", GraphSeal::with_blinded_vout(2u32, blinding))
                .unwrap();
        }
        let mut send = send.complete_transition().unwrap();
        let opid = opid_in(&mut send, 0xF0 - 13 * k..0xF0 - 13 * (k - 1));
        let index = send
            .assignments
            .get(&bfa_schema::OS_MINT)
            .unwrap()
            .seals()
            .position(|seal| matches!(seal, BuilderSeal::Revealed(s) if s.vout.to_u32() == vout))
            .unwrap() as u16;
        assert_eq!(index, if k == 1 { 0 } else { outputs - 1 });
        let tx = history.commit(
            vec![send],
            vec![right.outpoint],
            vec![gen::dust(1), gen::dust(2), gen::dust(3)],
        );
        right = Utxo {
            opout: rgbstd::Opout::new(opid, bfa_schema::OS_MINT, index),
            outpoint: OutPoint::new(tx.compute_txid(), vout),
        };
    }
    let units = history.mint_owned(right, MINTED, 90);
    history.burn(
        units,
        MINTED,
        Some(MINTED),
        Some(gen::burn_reason_for(PAYEE)),
    );
    history
}

/// Size of the consignment of `history`, and the peak heap of [`validate`]
/// on it.
fn validation_peak(history: impl FnOnce() -> History) -> (usize, usize) {
    use crate::memory::peak;

    warm_up();
    let (consignment, validated, peak) = peak::measure(
        || history().consignment(),
        |consignment| validate(consignment).map(|_| ()),
    );
    validated.unwrap();
    (consignment.len(), peak)
}

/// The request memory model (`memory.rs`): consignment validation of the
/// densest shapes measured takes more than the factor. Each output of a wide
/// transfer of rights is about 14 bytes of consignment, and of a split about
/// 23. RGB validation keeps two records of more than 100 bytes for each, in
/// two B-trees. Each further byte of mint rights takes about 46 to 53 bytes
/// of heap, and each further byte of a fungible split about 31. The mint and
/// the burn add about 2 MiB that does not grow with the consignment.
///
/// The test measures each shape at two sizes. It takes the heap of each
/// further byte from the difference, and the rest as the part that does not
/// grow. The rate changes a little with the size. The sender also sets it
/// through the order of the OpIds ([`dense_rights_burn`]). At the test sizes,
/// rights with random OpIds give 46.0, the same on the asset with a reject
/// list. The densest layout found gives 52.7. The split gives 31.2 between
/// 10 000 and 20 000 outputs. A split of fewer outputs takes less per output,
/// so the test measures the split at 10 000 outputs or more. The test adds
/// 1.5 to each rate it measures.
///
/// It then checks that a whole burn request at the limits fits the heap
/// each worker holds. That request carries a consignment of the shape at
/// `DEFAULT_MAX_CONSIGNMENT_BYTES` and the decoded elements. The read and
/// decode of its frame of `MAX_MESSAGE_SIZE` take 3 times the frame. Then
/// `read_request` releases the frame, so validation runs beside the decoded
/// request, which is at most one frame.
#[test]
fn the_densest_consignments_at_the_limit_fit_the_heap_each_worker_holds() {
    use crate::config::DEFAULT_MAX_CONSIGNMENT_BYTES;
    use crate::framing::MAX_MESSAGE_SIZE;
    use crate::memory::{request_bound, ELEMENTS_BYTES};

    type Shape = fn() -> History;
    let shapes: [(&str, Shape, Shape, f64); 4] = [
        (
            "transfers of mint rights, then a burn",
            || wide_rights_burn(issue(), 1, 1_000),
            || wide_rights_burn(issue(), 2, 30_000),
            35.0,
        ),
        (
            "the same on an asset with a reject list",
            || wide_rights_burn(listed(), 1, 1_000),
            || wide_rights_burn(listed(), 2, 30_000),
            35.0,
        ),
        (
            "the same in the densest layout found",
            || dense_rights_burn(2, 1_366),
            || dense_rights_burn(3, 21_841),
            40.0,
        ),
        (
            "one transfer split into many outputs",
            || wide_split(10_000),
            || wide_split(20_000),
            20.0,
        ),
    ];
    let limit = DEFAULT_MAX_CONSIGNMENT_BYTES as f64;
    let frame = MAX_MESSAGE_SIZE as usize;
    let held = request_bound(frame) as f64;
    let mib = |bytes: f64| bytes / (1024.0 * 1024.0);
    for (what, small, large, dense) in shapes {
        let (small_bytes, small_peak) = validation_peak(small);
        let (large_bytes, large_peak) = validation_peak(large);
        let rate = (large_peak as f64 - small_peak as f64) / (large_bytes - small_bytes) as f64;
        let fixed = (large_peak as f64 - rate * large_bytes as f64).max(0.0);
        let validation = (rate + 1.5) * limit + fixed;
        // The read and decode of the frame, or validation beside the decoded
        // request.
        let request = ((3 * frame) as f64).max(frame as f64 + validation) + ELEMENTS_BYTES as f64;
        println!(
            "{what}: {small_bytes} and {large_bytes} bytes, {rate:.1} bytes of heap for each \
             further byte, {:.1} MiB that does not grow; a burn request at the limits \
             {:.0} MiB, heap each worker holds {:.0} MiB",
            mib(fixed),
            mib(request),
            mib(held)
        );
        assert!(rate > dense, "{what}: the shape is not dense: {rate:.1}");
        assert!(
            request <= held,
            "{what}: a burn request at the limits takes {request:.0} bytes, over the heap \
             each worker holds, {held:.0} bytes"
        );
    }
}

/// The 2 000-transfer measurement at a history of 10 000 transfers, the
/// history the default limits are sized for (`config.rs`). Ignored by default
/// because it is slow in a debug build.
#[test]
#[ignore = "measures a history of 10_000 transfers; the burn-signer CI job runs it"]
fn consignment_validation_of_10_000_transfers_stays_within_the_factor() {
    use crate::memory::peak;

    warm_up();
    let (consignment, validated, peak) = peak::measure(
        || long_history(10_000).consignment(),
        |consignment| validate(consignment),
    );
    assert_eq!(validated.unwrap().witness_txids.len(), 10_002);
    peak::assert_within_factor("consignment validation", consignment.len(), peak);
}

/// A burn with a history of 10_000 transfers and an SPV proof on every bundle
/// passes with the default limits: consensus, the request limits
/// (`MAX_CONSIGNMENT_BYTES`, `MAX_MERKLE_PROOFS`, `MAX_TOTAL_PROOF_BYTES`) and
/// the frame. Each proof has 13 siblings, the depth of a full mainnet block.
///
/// Ignored by default because it is slow in a debug build.
#[cfg(rgb_to_evm)]
#[test]
#[ignore = "validates a history of 10_000 transfers; the burn-signer CI job runs it"]
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
    let consignment = history.consignment();

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

mod caps;
mod summary;
