//! `validate_destination_anchor` and `validate_rights_refill` on the mint
//! signer: generated rgb-lib-shaped PSBTs, each with the PSBT of the tx that
//! made its right. Then parity with the consensus path on the same fixtures.

use std::cell::RefCell;
use std::collections::BTreeMap;

use amplify::confinement::SmallBlob;
use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::{Amount, TxOut};
use psrgbt::{RgbPropKeyExt, RgbPsbtExt};
use rgbstd::contract::{AllocatedState, TransitionBuilder};
use rgbstd::{
    BuilderSeal, GlobalValues, GraphSeal, MetaValue, Operation, RevealedData, SecretSeal,
    Transition,
};

use super::*;
use crate::config::BridgeConfig;
use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::btc_ownership::tests as fx;
use crate::networks::rgb::psbt_validation::{fee_key_path_inputs_scoped, MintFacts};
use crate::networks::rgb::spv_crosscheck::ChainPins;
use crate::proto::SignRightsRefillRequest;
use crate::test_support::bfa_consignment::{self as gen, Committed as Made, History, Issue, Utxo};

const MINTED: u64 = 100_000;
const BEFORE_BLOCK: u64 = 110;
/// Sats on each right's UTXO; they pay the mint's fee.
const RIGHT_SATS: u64 = 3_000;
const CHANGE_SATS: u64 = 2_000;

/// Our Colored key-path output at `[0, index]`.
fn ours(keys: &KeyManager, index: u32, sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: fx::our_address(keys, AccountType::Colored, 0, index),
    }
}

/// An asset with one genesis right, which the issuer seeds to our rights on
/// vouts 1 and 2 (keys `[0, 1]`, `[0, 2]`). Returns the seed and its rights.
fn seeded(keys: &KeyManager) -> (History, Made, Vec<Utxo>) {
    let genesis_right = gen::outpoint(0xA0, 0);
    let mut history = History::issue(Issue::new(42161, [0xB1; 20], vec![genesis_right]));
    let right = history.genesis_right(0, genesis_right);
    let outputs = vec![ours(keys, 1, RIGHT_SATS), ours(keys, 2, RIGHT_SATS)];
    let seed = history.send_rights(right, &[1, 2], vec![], outputs);
    let rights = gen::rights_made(&seed, &[1, 2]);
    (history, seed, rights)
}

/// The depositor's blinded seal.
fn recipient() -> SecretSeal {
    GraphSeal::with_blinding(gen::outpoint(0xC0, 0).txid, 0u32, 7).to_secret_seal()
}

/// Input 0 of `psbt` as rgb-lib writes it: our right at `[0, index]`.
fn our_input(psbt: &mut Psbt, keys: &KeyManager, index: u32) {
    fx::anchor_input(psbt, 0, keys, AccountType::Colored, 0, index, RIGHT_SATS);
}

/// A mint of `MINTED` on seed right 0 to the depositor, change to `[0, 99]`.
fn mint_on(history: &mut History, right: Utxo, keys: &KeyManager) -> Made {
    let to = BuilderSeal::Concealed(recipient());
    let change = ours(keys, 99, CHANGE_SATS);
    let mut mint = history.mint(right, MINTED, BEFORE_BLOCK, to, vec![], vec![change]);
    our_input(&mut mint.psbt, keys, 1);
    mint
}

/// The mint destination of `mint`, whose right `parent` made.
fn destination(history: &History, mint: &Made, parent: &Made) -> RgbDestination {
    RgbDestination {
        psbt_bytes: mint.psbt.serialize(),
        asset_id: history.contract_id.to_string(),
        parent_psbt: parent.psbt.serialize(),
        ..Default::default()
    }
}

fn pinned(history: &History) -> BridgeConfig {
    BridgeConfig {
        rgb_asset_id: history.contract_id.to_string(),
        ..Default::default()
    }
}

/// Runs the mint route with the fixture keys. The binder records the mint.
fn run_mint(destination: &RgbDestination, cfg: &BridgeConfig) -> (Result<u64>, Option<MintFacts>) {
    let keys = fx::km();
    let chain = crate::test_support::regtest_header_chain();
    let bound = RefCell::new(None);
    let key_paths = |psbt: &Psbt| {
        Ok(fee_key_path_inputs_scoped(
            psbt,
            &keys,
            AccountType::Colored,
        ))
    };
    let binder = |mint: &MintFacts| {
        *bound.borrow_mut() = Some(mint.clone());
        Ok(())
    };
    let ctx = ValidationContext {
        bridge_config: cfg,
        header_chain: &chain,
        chain_pins: &ChainPins::new(),
        psbt_fee_key_paths: Some(&key_paths),
        mint_binder: Some(&binder),
    };
    let result = validate_destination_anchor(destination, MINTED, 0, &ctx).map(|(units, _)| units);
    (result, bound.into_inner())
}

fn mint_refusal(destination: &RgbDestination, history: &History) -> String {
    run_mint(destination, &pinned(history))
        .0
        .unwrap_err()
        .to_string()
}

/// A valid mint, built and committed, with its parent.
fn valid_mint() -> (History, Made, Made) {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let mint = mint_on(&mut history, rights[0], &keys);
    (history, seed, mint)
}

/// Commits `mint` (an edited mint transition) on seed right 0, rgb-lib style.
fn committed_mint(history: &mut History, mint: Transition, right: Utxo) -> Made {
    let keys = fx::km();
    let opid = mint.id();
    let mut psbt = history.commit_psbt(
        vec![mint],
        vec![right.outpoint],
        vec![ours(&keys, 99, CHANGE_SATS)],
    );
    our_input(&mut psbt, &keys, 1);
    Made {
        opid,
        tx: psbt.unsigned_tx.clone(),
        psbt,
    }
}

/// A mint transition on `right` of `issued`, open for edits.
fn mint_builder(history: &mut History, right: Utxo, issued: u64) -> TransitionBuilder {
    history
        .transition("mint")
        .add_input(right.opout, AllocatedState::Void)
        .unwrap()
        .add_metadata("beforeBlock", rgbstd::stl::BlockNumber::from(BEFORE_BLOCK))
        .unwrap()
        .add_global_state("issuedSupply", rgbstd::Amount::from(issued))
        .unwrap()
}

/// A mint of `MINTED` to the depositor on `right`, with `extra` built in.
fn mint_with(
    history: &mut History,
    right: Utxo,
    extra: impl FnOnce(TransitionBuilder) -> TransitionBuilder,
) -> Transition {
    let mint = mint_builder(history, right, MINTED)
        .add_fungible_state("assetOwner", BuilderSeal::Concealed(recipient()), MINTED)
        .unwrap();
    extra(mint).complete_transition().unwrap()
}

/// The refusal of a mint on seed right 0 that `build` extends and `edit`
/// changes after it is built.
fn mint_refusal_of(
    build: impl FnOnce(TransitionBuilder) -> TransitionBuilder,
    edit: impl FnOnce(&mut Transition),
) -> String {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let mut mint = mint_with(&mut history, rights[0], build);
    edit(&mut mint);
    let mint = committed_mint(&mut history, mint, rights[0]);
    mint_refusal(&destination(&history, &mint, &seed), &history)
}

fn edited_mint_refusal(edit: impl FnOnce(&mut Transition)) -> String {
    mint_refusal_of(|mint| mint, edit)
}

fn blob(bytes: &[u8]) -> SmallBlob {
    SmallBlob::try_from(bytes.to_vec()).unwrap()
}

// ===== the mint =====

#[test]
fn binds_a_valid_mint_to_its_deposit_and_recipient() {
    let (history, seed, mint) = valid_mint();
    let (units, bound) = run_mint(&destination(&history, &mint, &seed), &pinned(&history));
    assert_eq!(units.unwrap(), MINTED);
    let bound = bound.expect("the binder ran");
    assert_eq!(bound.opid, gen::opid_bytes(mint.opid));
    assert_eq!((bound.issued, bound.before_block), (MINTED, BEFORE_BLOCK));
    assert_eq!(bound.recipient_seal, recipient().to_string());
}

#[test]
fn refuses_missing_parent_psbt() {
    let (history, seed, mint) = valid_mint();
    let destination = RgbDestination {
        parent_psbt: vec![],
        ..destination(&history, &mint, &seed)
    };
    let (result, bound) = run_mint(&destination, &pinned(&history));
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("parent_psbt required"));
    assert!(bound.is_none(), "no deposit is read for a refused mint");
}

/// An old-form mint passed its right on. A mint from that right names a mint
/// as its parent: PP4.
#[test]
fn refuses_a_mint_whose_right_a_mint_made() {
    let keys = fx::km();
    let (mut history, _, rights) = seeded(&keys);
    let to = BuilderSeal::from(GraphSeal::with_blinded_vout(2u32, 7));
    let outputs = vec![ours(&keys, 3, RIGHT_SATS), ours(&keys, 4, 1_000)];
    let (old, kept) = history.mint_keeping_right(rights[0], 5, 80, to, vec![], outputs);
    let mint = mint_on(&mut history, kept, &keys);
    let err = mint_refusal(&destination(&history, &mint, &old), &history);
    assert!(err.contains("not a propagate"), "{err}");
}

/// Review P1: the mined mint's transition in a new tx that spends another of
/// our Colored UTXOs.
#[test]
fn refuses_replay_with_a_different_input() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let mint = mint_on(&mut history, rights[0], &keys);
    let transition = mint.psbt.rgb_transition(mint.opid).unwrap().unwrap();
    let replay = committed_mint(&mut history, transition, rights[1]);
    let err = mint_refusal(&destination(&history, &replay, &seed), &history);
    assert!(err.contains("does not spend"), "{err}");
}

/// The tx commits another contract's bundle too; the PSBT drops its keys.
#[test]
fn refuses_a_hidden_bundle() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let (mut other, other_right) = seeded_other();
    let mint = mint_with(&mut history, rights[0], |mint| mint);
    let hidden = other.rights_transition(other_right, &[1, 2]);
    let inputs = vec![rights[0].outpoint, other_right.outpoint];
    let mut psbt = gen::witness_psbt(inputs, vec![ours(&keys, 99, CHANGE_SATS)]);
    psbt.push_rgb_transition(mint).unwrap();
    psbt.push_rgb_transition(hidden).unwrap();
    gen::rgb_commit(&mut psbt, 0, 0x5eed);
    psbt.proprietary
        .remove(&ProprietaryKey::rgb_consumed_by(other.contract_id));
    our_input(&mut psbt, &keys, 1);
    fx::anchor_input(&mut psbt, 1, &keys, AccountType::Colored, 0, 2, RIGHT_SATS);
    let destination = RgbDestination {
        psbt_bytes: psbt.serialize(),
        ..destination(&history, &seed, &seed)
    };
    let err = mint_refusal(&destination, &history);
    assert!(err.contains("does not commit exactly"), "{err}");
}

#[test]
fn refuses_non_mint_type() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let outputs = vec![ours(&keys, 3, 1_000), ours(&keys, 4, 1_000)];
    let mut send = history.send_rights(rights[0], &[1, 2], vec![], outputs);
    our_input(&mut send.psbt, &keys, 1);
    let err = mint_refusal(&destination(&history, &send, &seed), &history);
    assert!(err.contains("not a mint"), "{err}");
}

#[test]
fn refuses_mint_without_one_mint_right_input() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let mint = mint_builder(&mut history, rights[0], MINTED)
        .add_input(rights[1].opout, AllocatedState::Void)
        .unwrap()
        .add_fungible_state("assetOwner", BuilderSeal::Concealed(recipient()), MINTED)
        .unwrap()
        .complete_transition()
        .unwrap();
    let mint = committed_mint(&mut history, mint, rights[0]);
    let err = mint_refusal(&destination(&history, &mint, &seed), &history);
    assert!(err.contains("exactly one mintRight"), "{err}");
}

#[test]
fn refuses_mint_passing_a_right_on() {
    let seal = GraphSeal::with_blinded_vout(1u32, 3);
    let err = mint_refusal_of(|mint| mint.add_rights("mintRight", seal).unwrap(), |_| {});
    assert!(err.contains("passes 1 mintRight"), "{err}");
}

#[test]
fn refuses_mint_with_link_output() {
    let seal = GraphSeal::with_blinded_vout(1u32, 3);
    let err = mint_refusal_of(|mint| mint.add_rights("linkRight", seal).unwrap(), |_| {});
    assert!(err.contains("assigns asset units only"), "{err}");
}

#[test]
fn refuses_extra_global_or_metadata() {
    let err = edited_mint_refusal(|mint| {
        let value = GlobalValues::with(RevealedData::new(blob(&[0; 8])));
        mint.globals
            .insert(schemata::GS_BURNED_ASSET, value)
            .unwrap();
    });
    assert!(err.contains("issuedSupply and beforeBlock only"), "{err}");
    let err = edited_mint_refusal(|mint| {
        let extra = rgbstd::MetaType::with(9_999);
        mint.metadata
            .insert(extra, MetaValue::from(blob(&[1])))
            .unwrap();
    });
    assert!(err.contains("issuedSupply and beforeBlock only"), "{err}");
}

#[test]
fn refuses_issued_supply_not_8_bytes() {
    let err = edited_mint_refusal(|mint| {
        let value = GlobalValues::with(RevealedData::new(blob(&[0xa0, 0x86, 0x01, 0, 0, 0, 0])));
        mint.globals
            .insert(schemata::GS_ISSUED_SUPPLY, value)
            .unwrap();
    });
    assert!(err.contains("issuedSupply is 7 bytes"), "{err}");
}

#[test]
fn refuses_zero_issued_supply() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let to = BuilderSeal::Concealed(recipient());
    let change = ours(&keys, 99, CHANGE_SATS);
    let mut mint = history.mint(rights[0], 0, BEFORE_BLOCK, to, vec![], vec![change]);
    our_input(&mut mint.psbt, &keys, 1);
    let err = mint_refusal(&destination(&history, &mint, &seed), &history);
    assert!(err.contains("issuedSupply is 0"), "{err}");
}

#[test]
fn refuses_before_block_not_8_bytes() {
    let err = edited_mint_refusal(|mint| {
        mint.metadata
            .insert(
                schemata::MS_BEFORE_BLOCK,
                MetaValue::from(blob(&[90, 0, 0, 0])),
            )
            .unwrap();
    });
    assert!(err.contains("beforeBlock is 4 bytes"), "{err}");
}

#[test]
fn refuses_asset_sum_not_issued_supply() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let mint = mint_builder(&mut history, rights[0], MINTED)
        .add_fungible_state(
            "assetOwner",
            BuilderSeal::Concealed(recipient()),
            MINTED + 1,
        )
        .unwrap()
        .complete_transition()
        .unwrap();
    let mint = committed_mint(&mut history, mint, rights[0]);
    let err = mint_refusal(&destination(&history, &mint, &seed), &history);
    assert!(err.contains("declares issuedSupply"), "{err}");
}

#[test]
fn refuses_revealed_asset_leg() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let to = BuilderSeal::from(GraphSeal::with_blinded_vout(1u32, 5));
    let change = ours(&keys, 99, CHANGE_SATS);
    let mut mint = history.mint(rights[0], MINTED, BEFORE_BLOCK, to, vec![], vec![change]);
    our_input(&mut mint.psbt, &keys, 1);
    let err = mint_refusal(&destination(&history, &mint, &seed), &history);
    assert!(err.contains("revealed seal"), "{err}");
}

#[test]
fn refuses_two_asset_legs() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let other = GraphSeal::with_blinding(gen::outpoint(0xC1, 0).txid, 0u32, 8).to_secret_seal();
    let mint = mint_builder(&mut history, rights[0], MINTED)
        .add_fungible_state(
            "assetOwner",
            BuilderSeal::Concealed(recipient()),
            MINTED / 2,
        )
        .unwrap()
        .add_fungible_state("assetOwner", BuilderSeal::Concealed(other), MINTED / 2)
        .unwrap()
        .complete_transition()
        .unwrap();
    let mint = committed_mint(&mut history, mint, rights[0]);
    let err = mint_refusal(&destination(&history, &mint, &seed), &history);
    assert!(err.contains("pays 2 asset legs"), "{err}");
}

/// M5: the minted units are the net deposit.
#[test]
fn refuses_a_mint_above_the_net_deposit() {
    let (history, seed, mint) = valid_mint();
    let keys = fx::km();
    let chain = crate::test_support::regtest_header_chain();
    let key_paths = |psbt: &Psbt| {
        Ok(fee_key_path_inputs_scoped(
            psbt,
            &keys,
            AccountType::Colored,
        ))
    };
    let binder = |_: &MintFacts| Ok(());
    let ctx = ValidationContext {
        bridge_config: &pinned(&history),
        header_chain: &chain,
        chain_pins: &ChainPins::new(),
        psbt_fee_key_paths: Some(&key_paths),
        mint_binder: Some(&binder),
    };
    let err = validate_destination_anchor(&destination(&history, &mint, &seed), MINTED, 1, &ctx)
        .unwrap_err();
    assert!(err.to_string().contains("amount mismatch"), "{err}");
}

#[test]
fn refuses_non_all_sighash() {
    let (history, seed, mut mint) = valid_mint();
    mint.psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0x83));
    let err = mint_refusal(&destination(&history, &mint, &seed), &history);
    assert!(err.contains("non-ALL sighash 0x83"), "{err}");
}

#[test]
fn refuses_foreign_input() {
    let (history, seed, mut mint) = valid_mint();
    let input = &mut mint.psbt.inputs[0];
    input.witness_utxo.as_mut().unwrap().script_pubkey = fx::foreign_address(0xB1);
    input.tap_internal_key = None;
    input.tap_key_origins.clear();
    let err = mint_refusal(&destination(&history, &mint, &seed), &history);
    assert!(
        err.contains("input 0 is not a Colored key-path input"),
        "{err}"
    );
}

/// A fee input beside the right: a mint spends its right alone (F7).
#[test]
fn refuses_a_mint_with_a_fee_input() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let to = BuilderSeal::Concealed(recipient());
    let change = ours(&keys, 99, CHANGE_SATS);
    let extra = vec![rights[1].outpoint];
    let mut mint = history.mint(rights[0], MINTED, BEFORE_BLOCK, to, extra, vec![change]);
    our_input(&mut mint.psbt, &keys, 1);
    fx::anchor_input(
        &mut mint.psbt,
        1,
        &keys,
        AccountType::Colored,
        0,
        2,
        RIGHT_SATS,
    );
    let err = mint_refusal(&destination(&history, &mint, &seed), &history);
    assert!(err.contains("spends 2 inputs"), "{err}");
}

#[test]
fn refuses_a_declared_asset_that_is_not_the_pin() {
    let (history, seed, mint) = valid_mint();
    let destination = RgbDestination {
        asset_id: "rgb:listener-lied".into(),
        ..destination(&history, &mint, &seed)
    };
    let err = mint_refusal(&destination, &history);
    assert!(err.contains("contract_id mismatch"), "{err}");
}

#[test]
fn refuses_a_mint_without_a_deposit_binder() {
    let (history, seed, mint) = valid_mint();
    let keys = fx::km();
    let chain = crate::test_support::regtest_header_chain();
    let key_paths = |psbt: &Psbt| {
        Ok(fee_key_path_inputs_scoped(
            psbt,
            &keys,
            AccountType::Colored,
        ))
    };
    let ctx = ValidationContext {
        bridge_config: &pinned(&history),
        header_chain: &chain,
        chain_pins: &ChainPins::new(),
        psbt_fee_key_paths: Some(&key_paths),
        mint_binder: None,
    };
    let err = validate_destination_anchor(&destination(&history, &mint, &seed), MINTED, 0, &ctx)
        .unwrap_err();
    assert!(err.to_string().contains("no deposit binder"), "{err}");
}

// ===== the rights refill =====

/// A refill of `right` to our rights on vouts 1..=3, with its parent.
fn refill_request(
    history: &mut History,
    right: Utxo,
    parent: &Made,
) -> (Made, SignRightsRefillRequest) {
    let keys = fx::km();
    let outputs = (3..=5).map(|i| ours(&keys, i, 1_000)).collect();
    let mut refill = history.send_rights(right, &[1, 2, 3], vec![], outputs);
    our_input(&mut refill.psbt, &keys, 1);
    let request = SignRightsRefillRequest {
        psbt_bytes: refill.psbt.serialize(),
        asset_id: history.contract_id.to_string(),
        parent_psbt: parent.psbt.serialize(),
    };
    (refill, request)
}

fn run_refill(
    refill: &Made,
    request: &SignRightsRefillRequest,
    history: &History,
) -> Result<Vec<u32>> {
    validate_rights_refill(request, &refill.psbt, &pinned(history))
}

#[test]
fn accepts_a_refill_of_an_issuer_seed_right() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let (refill, request) = refill_request(&mut history, rights[0], &seed);
    assert_eq!(
        run_refill(&refill, &request, &history).unwrap(),
        vec![1, 2, 3]
    );
}

#[test]
fn accepts_a_refill_of_a_refill_made_right() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let (first, _) = refill_request(&mut history, rights[0], &seed);
    let made = gen::rights_made(&first, &[1, 2, 3]);
    let (refill, request) = refill_request(&mut history, made[0], &first);
    assert_eq!(
        run_refill(&refill, &request, &history).unwrap(),
        vec![1, 2, 3]
    );
}

#[test]
fn refuses_a_refill_without_its_parent_psbt() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let (refill, mut request) = refill_request(&mut history, rights[0], &seed);
    request.parent_psbt.clear();
    let err = run_refill(&refill, &request, &history).unwrap_err();
    assert!(err.to_string().contains("parent_psbt required"), "{err}");
}

#[test]
fn refuses_a_refill_whose_right_a_mint_made() {
    let keys = fx::km();
    let (mut history, _, rights) = seeded(&keys);
    let to = BuilderSeal::from(GraphSeal::with_blinded_vout(2u32, 7));
    let outputs = vec![ours(&keys, 3, RIGHT_SATS), ours(&keys, 4, 1_000)];
    let (old, kept) = history.mint_keeping_right(rights[0], 5, 80, to, vec![], outputs);
    let (refill, request) = refill_request(&mut history, kept, &old);
    let err = run_refill(&refill, &request, &history).unwrap_err();
    assert!(err.to_string().contains("not a propagate"), "{err}");
}

#[test]
fn refuses_a_refill_of_another_asset() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let (refill, request) = refill_request(&mut history, rights[0], &seed);
    let (other, ..) = seeded_other();
    let err = validate_rights_refill(&request, &refill.psbt, &pinned(&other)).unwrap_err();
    assert!(
        err.to_string().contains("not of the pinned RGB_ASSET_ID"),
        "{err}"
    );
}

/// A second asset, so its contract id differs.
fn seeded_other() -> (History, Utxo) {
    let right = gen::outpoint(0xA9, 0);
    let history = History::issue(Issue::new(42161, [0xB9; 20], vec![right]));
    let utxo = history.genesis_right(0, right);
    (history, utxo)
}

#[test]
fn refuses_a_refill_with_a_non_all_sighash() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let (mut refill, request) = refill_request(&mut history, rights[0], &seed);
    refill.psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0x02));
    let err = run_refill(&refill, &request, &history).unwrap_err();
    assert!(err.to_string().contains("non-ALL sighash 0x02"), "{err}");
}

/// Two transfers in one bundle: a sibling could move a co-located right.
#[test]
fn refuses_two_transfers_in_the_signed_bundle() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let sends = vec![
        history.rights_transition(rights[0], &[1, 2]),
        history.rights_transition(rights[1], &[3, 4]),
    ];
    let outputs = (3..=6).map(|i| ours(&keys, i, 1_000)).collect();
    let mut psbt =
        history.commit_psbt(sends, vec![rights[0].outpoint, rights[1].outpoint], outputs);
    our_input(&mut psbt, &keys, 1);
    fx::anchor_input(&mut psbt, 1, &keys, AccountType::Colored, 0, 2, RIGHT_SATS);
    let request = SignRightsRefillRequest {
        psbt_bytes: psbt.serialize(),
        asset_id: history.contract_id.to_string(),
        parent_psbt: seed.psbt.serialize(),
    };
    let err = validate_rights_refill(&request, &psbt, &pinned(&history)).unwrap_err();
    assert!(err.to_string().contains("discloses 2 transitions"), "{err}");
}

// ===== parity with the consensus path, while both compile =====

/// Consensus over `bytes` with every witness mined. Returns what it derived
/// and the mint anchors it asked to bind.
fn consensus(
    bytes: &[u8],
) -> (
    validation::ValidatedConsignment,
    Vec<validation::MintAnchor>,
) {
    let validator =
        validation::RgbValidator::new("tcp://indexer.invalid:1".into(), "regtest").unwrap();
    let transfer = <rgbstd::containers::Transfer as rgbstd::containers::FileContent>::load(
        std::io::Cursor::new(bytes),
    )
    .unwrap();
    let chain: BTreeMap<bitcoin::Txid, rgbstd::vm::WitnessPos> = transfer
        .bundles
        .iter()
        .zip(100u32..)
        .map(|(wb, height)| {
            let height = std::num::NonZeroU32::new(height).unwrap();
            (
                wb.witness_id(),
                rgbstd::vm::WitnessPos::bitcoin(height, 1_700_000_000).unwrap(),
            )
        })
        .collect();
    let witnesses = validation::WitnessCheck {
        chain: &chain,
        allow_unbroadcast_last: false,
        infer_spent_ancestors: false,
    };
    let anchors = RefCell::new(Vec::new());
    let bind = |bridge: &validation::BfaBridge, seen: &[validation::MintAnchor]| {
        anchors.borrow_mut().extend_from_slice(seen);
        Ok(validation::BoundAnchors {
            evm_chain_id: bridge.chain_id,
            locks: seen
                .iter()
                .map(|a| validation::VerifiedLock {
                    mint_opid: a.opid,
                    minted: a.amount,
                    operation_id: [0xd0; 32],
                    net_amount: a.amount,
                })
                .collect(),
        })
    };
    let validated = validator
        .validate_consignment(bytes, Some(&bind), &witnesses)
        .unwrap();
    (validated, anchors.into_inner())
}

#[test]
fn a_mint_reads_the_same_from_the_psbt_as_from_consensus() {
    let (history, seed, mint) = valid_mint();
    let (_, bound) = run_mint(&destination(&history, &mint, &seed), &pinned(&history));
    let from_psbt = bound.expect("the mint is valid");

    let (validated, anchors) = consensus(&history.consignment());
    let [anchor] = anchors.as_slice() else {
        panic!("one mint anchor, got {anchors:?}");
    };
    assert_eq!(validated.last_transfer_op_id, Some(from_psbt.opid));
    assert_eq!(anchor.opid, from_psbt.opid);
    assert_eq!(anchor.amount, from_psbt.issued);
    assert_eq!(anchor.before_block, from_psbt.before_block);
    let last = validated.last_transition.unwrap();
    assert_eq!(last.asset_output_amount, from_psbt.issued);
    let seals: Vec<_> = last.outputs.iter().map(|o| o.seal.clone()).collect();
    assert_eq!(
        seals,
        vec![validation::OutputSeal::Confidential {
            secret_seal: from_psbt.recipient_seal
        }]
    );
    assert!(validated.last_mint_rights.is_empty());
    // PP7 pins the UTXO consensus closes.
    let parent = seed.psbt.serialize();
    let spent =
        parent_proof::right_input(&mint.psbt, &parent, from_psbt.right, history.contract_id)
            .unwrap();
    let pinned = mint.psbt.unsigned_tx.input[spent].previous_output;
    assert_eq!(validated.last_closed_seals, vec![pinned]);
}

#[test]
fn a_refill_reads_the_same_from_the_psbt_as_from_consensus() {
    let keys = fx::km();
    let (mut history, seed, rights) = seeded(&keys);
    let (refill, request) = refill_request(&mut history, rights[0], &seed);
    let vouts = run_refill(&refill, &request, &history).unwrap();
    let committed = psbt_commit::committed_transition(&refill.psbt, history.contract_id).unwrap();

    let (validated, anchors) = consensus(&history.consignment());
    assert!(anchors.is_empty());
    assert_eq!(
        validated.last_transfer_op_id,
        Some(gen::opid_bytes(committed.opid))
    );
    let from_consensus: Vec<u32> = validated
        .last_mint_rights
        .iter()
        .map(|seal| psbt_commit::witness_vout(seal, "a right").unwrap())
        .collect();
    assert_eq!(from_consensus, vouts);
    assert_eq!(validated.last_closed_seals, vec![rights[0].outpoint]);
}
