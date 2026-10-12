//! Tests for all of `validation/`. They are in one file because they share
//! the generated consignments (`test_support::bfa_consignment`).

use std::cell::RefCell;

use bitcoin::OutPoint;
use rgb_consignment::{FungibleAllocation, FungibleEntry, SealInfo, TransitionInfo};
use rgbstd::containers::FileContent;
use rgbstd::contract::AllocatedState;
use rgbstd::{BuilderSeal, GraphSeal, RevealedValue};
#[cfg(rgb_to_evm)]
use sha3::{Digest, Keccak256};

use super::asset_bind::*;
use super::bfa::*;
use super::consignment::*;
use super::indexer::*;
use super::schema::*;
#[cfg(rgb_to_evm)]
use super::source::*;
use super::types::*;
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
    let (_, units) = history.mint_owned(right, MINTED, 90);
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
    validator().validate_consignment(bytes, Some(&bind_all))
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

/// The enclave does not read a reject list, so it refuses such an asset.
#[test]
fn rejects_an_asset_with_a_reject_list() {
    let history = History::issue(Issue {
        reject_list: true,
        ..Issue::new(EVM_CHAIN_ID, BRIDGE, vec![right_utxo()])
    });
    let err = error_of(validate(&history.consignment(vec![])));
    assert!(err.contains("reject list"), "{err}");
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

/// The enclave and consignment-utils (which the bridge uses) read the same
/// burn facts from the same bytes.
#[test]
fn burn_facts_agree_with_the_bridge_parser() {
    let bytes = burn_bytes();
    let last = validate(&bytes).unwrap().last_transition.unwrap();

    let rgb_consignment::ConsignmentInfo::Transfer(info) = rgb_consignment::parse(&bytes).unwrap()
    else {
        panic!("a transfer");
    };
    let burn = info.witnesses.last().unwrap().transitions.last().unwrap();
    let global = |ty: u16| {
        let entry = burn.globals.iter().find(|g| g.global_type == ty).unwrap();
        hex::decode(&entry.value_hex).unwrap()
    };
    let burned = u64::from_le_bytes(global(2015).try_into().unwrap());
    assert_eq!(Some(burned), last.burned_asset_amount);
    assert_eq!(global(3009), last.burn_reason.unwrap().to_vec());
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

/// The mint a PSBT signs: its anchor is in the last bundle, its right goes
/// back to vout 1, and the right's seal is what the bundle closes.
#[test]
fn reads_a_mint_and_its_anchor() {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let recipient = GraphSeal::with_blinding(gen::outpoint(0xC0, 0).txid, 0u32, 7);
    let secret = recipient.to_secret_seal();
    let (mint, _) = history.mint(
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
    let validated = validator()
        .validate_consignment(&bytes, Some(&record))
        .expect("the mint is valid");

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
    assert_eq!(
        validated.last_mint_rights,
        vec![OutputSeal::Revealed {
            txid: None,
            vout: 1
        }]
    );
    let last = validated.last_transition.unwrap();
    assert!(is_mint_transition(last.transition_type));
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
    validator()
        .validate_consignment(&bytes, Some(&record))
        .unwrap();
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
    let err = error_of(validator().validate_consignment(&burn_bytes(), None));
    assert!(err.contains("binds none"), "{err}");
}

#[test]
fn passes_a_binder_error_through() {
    let refuse = |_: &BfaBridge, _: &[MintAnchor]| -> Result<BoundAnchors> {
        Err(crate::error::EnclaveError::CrossCheck("no deposit".into()))
    };
    let err = error_of(validator().validate_consignment(&burn_bytes(), Some(&refuse)));
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
        let err = error_of(validator().validate_consignment(&bytes, Some(bind)));
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
    let err = error_of(validator().validate_consignment(&burn_bytes(), Some(&other_chain)));
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

/// `asset_output_amount` counts only `OS_ASSET` allocations.
#[test]
fn transition_summary_counts_only_asset_outputs() {
    let alloc = |assignment_type: u16, amount: u64| FungibleAllocation {
        assignment_type,
        entries: vec![FungibleEntry {
            amount,
            seal: SealInfo::Revealed {
                txid: None,
                vout: 0,
            },
        }],
        total: amount,
    };
    let info = TransitionInfo {
        op_id: "mint-op".into(),
        transition_type: 8013,
        input_count: 1,
        fungible_allocations: vec![alloc(4000, 500), alloc(4999, 1_000_000)],
        metadata: vec![],
        globals: vec![],
    };
    let summary = transition_summary(&info).unwrap();
    assert_eq!(summary.asset_output_amount, 500);
    assert_eq!(summary.total_output_amount, 1_000_500);
}

#[test]
fn transition_summary_refuses_an_overflowing_total() {
    let alloc = |amount: u64| FungibleAllocation {
        assignment_type: 4000,
        entries: vec![],
        total: amount,
    };
    let info = TransitionInfo {
        op_id: "op".into(),
        transition_type: 10000,
        input_count: 1,
        fungible_allocations: vec![alloc(u64::MAX), alloc(1)],
        metadata: vec![],
        globals: vec![],
    };
    assert!(transition_summary(&info).is_err());
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
    assert!(err.contains("rgb-consignment parse failed"), "{err}");
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
    let err = error_of(v.validate_consignment(&burn_bytes(), Some(&bind_all)));
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

/// Validation makes no network call: the witnesses come from the consignment.
#[test]
fn validation_needs_no_indexer() {
    let validator = RgbValidator::new(format!("tcp://{}", stalled_host()), "regtest")
        .unwrap()
        .with_timeout(30);
    let start = std::time::Instant::now();
    validator
        .validate_consignment(&burn_bytes(), Some(&bind_all))
        .unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(20));
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

/// The source path end to end: consensus, the asset bind, then SPV. A bound
/// source reaches the Merkle-proof coverage check, whose "missing merkle
/// proofs" error proves every earlier check passed.
#[cfg(rgb_to_evm)]
mod source_path {
    use super::*;
    use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
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

    /// A regtest chain whose checkpoint time is now, so freshness passes.
    fn fresh_chain() -> Mutex<HeaderChain> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        Mutex::new(HeaderChain::new(
            Network::Regtest,
            Checkpoint {
                height: 0,
                hash: [0u8; 32],
                bits: 0x207f_ffff,
                time: now,
                is_real: false,
                chain_work: None,
            },
        ))
    }

    fn run(
        source: &crate::proto::RgbSource,
        config: &BridgeConfig,
    ) -> Result<ValidatedConsignment> {
        let validator = validator();
        let chain = fresh_chain();
        let ctx = ValidationContext {
            bridge_config: config,
            rgb_validator: Some(&validator),
            header_chain: &chain,
            chain_pins: &crate::networks::rgb::spv_crosscheck::ChainPins::new(),
            #[cfg(evm_to_rgb)]
            self_owned_psbt_outputs: None,
            #[cfg(evm_to_rgb)]
            psbt_fee_key_paths: None,
            anchor_binder: Some(&bind_all),
        };
        validate_source(source, &ctx)
    }

    fn asset_id() -> String {
        issue().contract_id.to_string()
    }

    #[test]
    fn binds_when_contract_id_matches_pin() {
        let id = asset_id();
        let err = run(&burn_source(&id), &pinned_config(&id))
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing merkle proofs"), "{err}");
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

    #[test]
    fn pin_check_skipped_when_config_unconfigured() {
        let id = asset_id();
        let err = run(&burn_source(&id), &BridgeConfig::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing merkle proofs"), "{err}");
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
