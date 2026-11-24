//! `validate_destination_anchor` and `validate_rights_refill` on the mint
//! signer: generated rgb-lib-shaped PSBTs, stripped of their RGB keys, each with
//! its fascia. Then parity with the consensus path on the same fixtures.

use std::cell::RefCell;

use amplify::confinement::SmallBlob;
use bitcoin::bip32::ChildNumber;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::{Amount, ScriptBuf, TxOut};
use psrgbt::RgbPsbtExt;
use rgbstd::contract::{AllocatedState, TransitionBuilder};
use rgbstd::{
    BuilderSeal, GlobalValues, GraphSeal, MetaValue, RevealedData, SecretSeal, Transition,
};
use rgbstd::{Operation, RevealedValue};

use super::*;
use crate::config::{BridgeConfig, DEFAULT_MINT_WITNESS_SAT};
use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::bfa_schema;
use crate::networks::rgb::btc_ownership::tests as fx;
use crate::networks::rgb::psbt_validation::{
    assert_mint_sats, fee_key_path_inputs_scoped, MintFacts, MintRecipient,
};
use crate::networks::rgb::spv_crosscheck::ChainPins;
use crate::proto::SignRightsRefillRequest;
use crate::test_support::bfa_consignment::{self as gen, Committed as Made, History, Issue, Utxo};

/// The EVM chain the fixture genesis names in its `bridgeLocation`. The anchor
/// binder must report it: rgb-ops refuses a claim resolver on another chain.
const GENESIS_CHAIN_ID: u64 = 42161;
const MINTED: u64 = 100_000;
const BEFORE_BLOCK: u64 = 110;
/// Sats on each right's UTXO; they pay the mint's fee.
const RIGHT_SATS: u64 = 3_000;
const CHANGE_SATS: u64 = 2_000;
/// What a witness mint pays its depositor, at the default `MINT_WITNESS_SAT`.
const WITNESS_SATS: u64 = DEFAULT_MINT_WITNESS_SAT;
/// The fee of a witness mint: its right pays it, the witness output and the change.
const WITNESS_MINT_FEE: u64 = 300;
const WITNESS_CHANGE_SATS: u64 = RIGHT_SATS - WITNESS_SATS - WITNESS_MINT_FEE;

/// Our Colored key-path output at `[0, index]`.
fn ours(keys: &KeyManager, index: u32, sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: fx::our_address(keys, AccountType::Colored, 0, index),
    }
}

/// An asset with one genesis right, which the issuer seeds to our rights on
/// vouts 1 and 2 (keys `[0, 1]`, `[0, 2]`). Returns the seed's rights.
fn seeded(keys: &KeyManager) -> (History, Vec<Utxo>) {
    let genesis_right = gen::outpoint(0xA0, 0);
    let mut history = History::issue(Issue::new(
        GENESIS_CHAIN_ID,
        [0xB1; 20],
        vec![genesis_right],
    ));
    let right = history.genesis_right(0, genesis_right);
    let outputs = vec![ours(keys, 1, RIGHT_SATS), ours(keys, 2, RIGHT_SATS)];
    let seed = history.send_rights(right, &[1, 2], vec![], outputs);
    let rights = gen::rights_made(&seed, &[1, 2]);
    (history, rights)
}

/// The depositor's blinded seal.
fn recipient() -> SecretSeal {
    GraphSeal::with_blinding(gen::outpoint(0xC0, 0).txid, 0u32, 7).to_secret_seal()
}

/// Input 0 of `psbt` as rgb-lib writes it: our right at `[0, index]`.
fn our_input(psbt: &mut Psbt, keys: &KeyManager, index: u32) {
    fx::anchor_input(psbt, 0, keys, AccountType::Colored, 0, index, RIGHT_SATS);
}

/// The rule C metadata the wallet writes for our change at `[0, 99]` on `vout`.
fn claim_change(psbt: &mut Psbt, keys: &KeyManager, vout: usize) {
    let change = [ChildNumber::from(0), ChildNumber::from(99)];
    fx::claim_output(psbt, vout, keys, AccountType::Colored, &change);
}

/// A mint of `MINTED` on seed right 0 to the depositor, change to `[0, 99]`.
fn mint_on(history: &mut History, right: Utxo, keys: &KeyManager) -> Made {
    mint_to(history, right, keys, recipient())
}

/// A mint of `MINTED` on seed right 0 to the blinded `seal`, change to `[0, 99]`.
fn mint_to(history: &mut History, right: Utxo, keys: &KeyManager, seal: SecretSeal) -> Made {
    let to = BuilderSeal::Concealed(seal);
    let change = ours(keys, 99, CHANGE_SATS);
    let mut mint = history.mint(right, MINTED, BEFORE_BLOCK, to, vec![], vec![change]);
    our_input(&mut mint.psbt, keys, 1);
    claim_change(&mut mint.psbt, keys, 1);
    mint
}

/// The depositor's witness output: a script the enclave does not hold.
fn depositor(sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: fx::foreign_address(0xD1),
    }
}

/// A mint of `MINTED` on seed right 0 to the witness seal on `seal_vout`. The
/// tx pays `outputs` from vout 1, then our change of the rest less the fee.
fn witness_mint_paying(seal_vout: u32, outputs: Vec<TxOut>) -> (History, Made) {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let to = BuilderSeal::from(GraphSeal::with_blinded_vout(seal_vout, 5));
    let change = outputs.len() + 1;
    let paid: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
    let change_sats = RIGHT_SATS - WITNESS_MINT_FEE - paid;
    let outputs = [outputs, vec![ours(&keys, 99, change_sats)]].concat();
    let mut mint = history.mint(rights[0], MINTED, BEFORE_BLOCK, to, vec![], outputs);
    our_input(&mut mint.psbt, &keys, 1);
    claim_change(&mut mint.psbt, &keys, change);
    (history, mint)
}

/// A valid witness mint: `WITNESS_SATS` to the depositor on vout 1.
fn valid_witness_mint() -> (History, Made) {
    witness_mint_paying(1, vec![depositor(WITNESS_SATS)])
}

/// The mint destination of `mint`.
fn destination(history: &History, mint: &Made) -> RgbDestination {
    RgbDestination {
        psbt_bytes: mint.psbt.serialize(),
        asset_id: history.contract_id.to_string(),
        fascia: mint.fascia_bytes(),
    }
}

fn pinned(history: &History) -> BridgeConfig {
    BridgeConfig {
        rgb_asset_id: history.contract_id.to_string(),
        ..Default::default()
    }
}

type Minted = Result<u64>;

/// Runs the mint route with the fixture keys, M8 on `cfg`'s witness amount
/// and a binder that records the mint. `edit` can unwire either.
fn route_mint(
    destination: &RgbDestination,
    cfg: &BridgeConfig,
    commission: u64,
    edit: impl FnOnce(&mut ValidationContext<'_>),
) -> (Minted, Option<MintFacts>) {
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
    let own_vout = |psbt: &Psbt, vout: u32| {
        crate::networks::rgb::btc_ownership::output_is_self_derived(
            psbt,
            vout as usize,
            &keys,
            Some(AccountType::Colored),
        )
    };
    let sats = |psbt: &Psbt, recipient: &MintRecipient| {
        assert_mint_sats(psbt, &keys, recipient, cfg.mint_witness_sat)
    };
    let binder = |mint: &MintFacts| {
        *bound.borrow_mut() = Some(mint.clone());
        Ok(())
    };
    let mut ctx = ValidationContext {
        bridge_config: cfg,
        header_chain: &chain,
        chain_pins: &ChainPins::new(),
        psbt_fee_key_paths: Some(&key_paths),
        mint_binder: Some(&binder),
        mint_sats: Some(&sats),
        own_colored_vout: Some(&own_vout),
    };
    edit(&mut ctx);
    let result = validate_destination_anchor(destination, MINTED, commission, &ctx);
    (result, bound.into_inner())
}

fn run_mint(destination: &RgbDestination, cfg: &BridgeConfig) -> (Minted, Option<MintFacts>) {
    route_mint(destination, cfg, 0, |_| {})
}

fn mint_refusal(destination: &RgbDestination, history: &History) -> String {
    run_mint(destination, &pinned(history))
        .0
        .unwrap_err()
        .to_string()
}

/// A valid mint, built and committed.
fn valid_mint() -> (History, Made) {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let mint = mint_on(&mut history, rights[0], &keys);
    (history, mint)
}

/// Commits `mint` (an edited mint transition) on seed right 0, rgb-lib style.
fn committed_mint(history: &mut History, mint: Transition, right: Utxo) -> Made {
    committed_bundle(history, vec![mint], right)
}

/// Commits `transitions` in one bundle on seed right 0, rgb-lib style.
fn committed_bundle(history: &mut History, transitions: Vec<Transition>, right: Utxo) -> Made {
    let keys = fx::km();
    let mut made = history.commit_psbt(
        transitions,
        vec![right.outpoint],
        vec![ours(&keys, 99, CHANGE_SATS)],
    );
    our_input(&mut made.psbt, &keys, 1);
    claim_change(&mut made.psbt, &keys, 1);
    made
}

/// A transfer of `amount` units, held on a seal of the outpoint the tx
/// spends, to the blinded vout `to`: the shape rgb-lib gives the other
/// allocations of a spent UTXO.
fn sibling_transfer(history: &mut History, right: Utxo, amount: u64, to: u32) -> Transition {
    let held = GraphSeal::with_blinding(right.outpoint.txid, right.outpoint.vout, 0x7700);
    let units = history
        .transition("transfer")
        .add_input(right.opout, AllocatedState::Void)
        .unwrap()
        .add_fungible_state("assetOwner", held, amount)
        .unwrap()
        .complete_transition()
        .unwrap();
    let opout = rgbstd::Opout::new(units.id(), bfa_schema::OS_ASSET, 0);
    history
        .transition("transfer")
        .add_input(opout, AllocatedState::from(RevealedValue::from(amount)))
        .unwrap()
        .add_fungible_state(
            "assetOwner",
            GraphSeal::with_blinded_vout(to, 0x7701),
            amount,
        )
        .unwrap()
        .complete_transition()
        .unwrap()
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
    let (mut history, rights) = seeded(&keys);
    let mut mint = mint_with(&mut history, rights[0], build);
    edit(&mut mint);
    let mint = committed_mint(&mut history, mint, rights[0]);
    mint_refusal(&destination(&history, &mint), &history)
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
    let (history, mint) = valid_mint();
    let (minted, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
    assert_eq!(minted.unwrap(), MINTED);
    let bound = bound.expect("the binder ran");
    assert_eq!(bound.opid, gen::opid_bytes(mint.opid));
    // M6 reads the lock of this mint in this exact tx.
    assert_eq!(bound.lock_id, mint.lock_id());
    assert_eq!((bound.issued, bound.before_block), (MINTED, BEFORE_BLOCK));
    // rgb-lib renders a concealed seal as an invoice recipient id, which
    // carries the chain-net prefix of the image.
    assert_eq!(
        bound.recipient,
        MintRecipient::Blinded(format!("bc:{}", recipient()))
    );
}

/// rgb-lib strips the PSBT, so a mint without its fascia shows nothing.
#[test]
fn refuses_a_mint_without_its_fascia() {
    let (history, mint) = valid_mint();
    let destination = RgbDestination {
        fascia: vec![],
        ..destination(&history, &mint)
    };
    let (result, bound) = run_mint(&destination, &pinned(&history));
    let err = result.unwrap_err().to_string();
    assert!(err.contains("fascia required"), "{err}");
    assert!(bound.is_none(), "no deposit is read for a refused mint");
}

/// RGB keys a host leaves in the PSBT are not read: the fascia's mint binds.
#[test]
fn a_mint_ignores_rgb_keys_left_in_its_psbt() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let mut mint = mint_on(&mut history, rights[0], &keys);
    let other = history.rights_transition(rights[1], &[1]);
    mint.psbt.push_rgb_transition(other).unwrap();
    assert!(!mint.psbt.rgb_bundles().unwrap().is_empty());
    let (minted, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
    assert_eq!(minted.unwrap(), MINTED);
    assert_eq!(bound.unwrap().opid, gen::opid_bytes(mint.opid));
}

/// rgb-lib moves the other allocations of a spent UTXO by a transition of its
/// own in the same bundle. A mint may come beside such a transfer when it pays
/// this enclave's own output: the signer reads the mint and lets the transfer
/// be.
#[test]
fn accepts_a_mint_beside_a_transfer_of_our_own_units() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let mint = mint_with(&mut history, rights[0], |m| m);
    // vout 1 is the change `committed_bundle` claims at `[0, 99]`.
    let ours = sibling_transfer(&mut history, rights[1], 5_000, 1);
    let made = committed_bundle(&mut history, vec![ours, mint], rights[0]);
    let (_, bound) = run_mint(&destination(&history, &made), &pinned(&history));
    let mint = bound.expect("the mint is read beside our own transfer");
    assert_eq!(mint.issued, MINTED);
}

/// The same bundle, with the transfer paying an output this enclave does not
/// derive. The signer then has two transitions it must read and refuses.
#[test]
fn refuses_a_mint_beside_a_transfer_of_units_to_anyone_else() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let mint = mint_with(&mut history, rights[0], |m| m);
    // vout 2 is no output of this enclave: `committed_bundle` claims vout 1.
    let theirs = sibling_transfer(&mut history, rights[1], 5_000, 2);
    let made = committed_bundle(&mut history, vec![theirs, mint], rights[0]);
    let err = mint_refusal(&destination(&history, &made), &history);
    assert!(
        err.contains("neither a move of state to this enclave's own outputs"),
        "{err}"
    );
}

/// A propagate of another right in the mint's bundle, to our change: the
/// right stays in the wallet, so the mint is signed.
#[test]
fn accepts_a_mint_beside_a_move_of_another_right_to_our_change() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let mint = mint_with(&mut history, rights[0], |mint| mint);
    let side = history.rights_transition(rights[1], &[1]);
    let made = committed_bundle(&mut history, vec![side, mint], rights[0]);
    let (minted, bound) = run_mint(&destination(&history, &made), &pinned(&history));
    assert_eq!(minted.unwrap(), MINTED);
    assert_eq!(bound.unwrap().opid, gen::opid_bytes(made.opid));
}

/// The same propagate making two rights of one: a refill, which a mint does
/// not carry.
#[test]
fn refuses_a_mint_beside_a_propagate_that_makes_two_rights_of_one() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let mint = mint_with(&mut history, rights[0], |mint| mint);
    let side = history.rights_transition(rights[1], &[1, 1]);
    let made = committed_bundle(&mut history, vec![side, mint], rights[0]);
    let err = mint_refusal(&destination(&history, &made), &history);
    assert!(
        err.contains("neither a move of state to this enclave's own outputs"),
        "{err}"
    );
}

/// A link right and units beside the right, each moved to the change by its
/// own transition: two side transitions on one output, as rgb-lib builds a
/// UTXO that holds several allocations.
#[test]
fn accepts_a_mint_beside_moves_of_a_link_right_and_units_to_our_change() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let units = sibling_transfer(&mut history, rights[1], 5_000, 1);
    let link = rgbstd::Opout::new(rights[1].opout.op, rgbstd::AssignmentType::with(4012), 0);
    let linked = history
        .transition("transferLink")
        .add_input(link, AllocatedState::Void)
        .unwrap()
        .add_rights("linkRight", GraphSeal::with_blinded_vout(1u32, 11))
        .unwrap()
        .complete_transition()
        .unwrap();
    let mint = mint_with(&mut history, rights[0], |mint| mint);
    let made = committed_bundle(&mut history, vec![units, linked, mint], rights[0]);
    let (minted, bound) = run_mint(&destination(&history, &made), &pinned(&history));
    assert_eq!(minted.unwrap(), MINTED);
    assert_eq!(bound.unwrap().opid, gen::opid_bytes(made.opid));
}

/// A mint of `MINTED` to `to` on seed right 0 beside a transfer of units to
/// `moved_to`. The tx pays `paid` from vout 1, then our change at `[0, 99]`.
fn mint_beside_transfer(
    to: BuilderSeal<GraphSeal>,
    paid: Vec<TxOut>,
    moved_to: u32,
) -> (History, Made) {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let moved = sibling_transfer(&mut history, rights[1], 5_000, moved_to);
    let mint = mint_builder(&mut history, rights[0], MINTED)
        .add_fungible_state("assetOwner", to, MINTED)
        .unwrap()
        .complete_transition()
        .unwrap();
    let change = paid.len() + 1;
    let paid_sats: u64 = paid.iter().map(|o| o.value.to_sat()).sum();
    let change_sats = RIGHT_SATS - WITNESS_MINT_FEE - paid_sats;
    let outputs = [paid, vec![ours(&keys, 99, change_sats)]].concat();
    let mut made = history.commit_psbt(vec![moved, mint], vec![rights[0].outpoint], outputs);
    our_input(&mut made.psbt, &keys, 1);
    claim_change(&mut made.psbt, &keys, change);
    (history, made)
}

/// M9: moved state lands only on a funded Colored output of ours. Each output
/// below passes M8, so only M9 keeps the units in the wallet.
#[test]
fn m9_refuses_a_mint_that_moves_units_off_our_funded_colored_outputs() {
    let keys = fx::km();
    let blinded = || BuilderSeal::Concealed(recipient());
    let empty = ours(&keys, 98, 0);
    let vanilla = TxOut {
        value: Amount::from_sat(500),
        script_pubkey: fx::our_address(&keys, AccountType::Vanilla, 0, 7),
    };
    let witness = BuilderSeal::from(GraphSeal::with_blinded_vout(1u32, 5));
    type Claim = Option<(AccountType, u32)>;
    let cases: [(BuilderSeal<GraphSeal>, Vec<TxOut>, u32, Claim); 5] = [
        (witness, vec![depositor(WITNESS_SATS)], 1, None),
        (blinded(), vec![], 0, None),
        (blinded(), vec![], 9, None),
        (blinded(), vec![empty], 1, Some((AccountType::Colored, 98))),
        (blinded(), vec![vanilla], 1, Some((AccountType::Vanilla, 7))),
    ];
    for (to, paid, moved_to, claim) in cases {
        let (history, mut mint) = mint_beside_transfer(to, paid, moved_to);
        if let Some((account, index)) = claim {
            let child = [ChildNumber::from(0), ChildNumber::from(index)];
            fx::claim_output(&mut mint.psbt, 1, &keys, account, &child);
        }
        let (result, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("neither a move of state to this enclave's own outputs"),
            "vout {moved_to}: {err}"
        );
        assert!(bound.is_none(), "no deposit is read for a refused mint");
    }
}

/// A mint to a witness recipient beside the same transfer to our change.
#[test]
fn accepts_a_witness_mint_beside_a_transfer_of_our_own_units() {
    let witness = BuilderSeal::from(GraphSeal::with_blinded_vout(1u32, 5));
    let (history, mint) = mint_beside_transfer(witness, vec![depositor(WITNESS_SATS)], 2);
    let (minted, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
    assert_eq!(minted.unwrap(), MINTED);
    assert_eq!(bound.unwrap().opid, gen::opid_bytes(mint.opid));
}

/// A second contract with a right on the UTXO of `right`, and the propagate
/// that moves it to `vout`: rgb-lib's extra transition for another asset.
fn other_asset_moved(right: Utxo, vout: u32) -> Transition {
    let issue = Issue::new(GENESIS_CHAIN_ID, [0xB2; 20], vec![right.outpoint]);
    let mut other = History::issue(issue);
    let beside = other.genesis_right(0, right.outpoint);
    other.rights_transition(beside, &[vout])
}

/// `main` on seed right 0 in a tx that also moves another asset's state from
/// the same UTXO to `moved_to`. The tx pays `outputs` from vout 1.
fn beside_another_asset(right: Utxo, main: Transition, moved_to: u32, outputs: Vec<TxOut>) -> Made {
    let keys = fx::km();
    let mut psbt = gen::witness_psbt(vec![right.outpoint], outputs);
    let opid = main.id();
    psbt.push_rgb_transition(main).unwrap();
    psbt.push_rgb_transition(other_asset_moved(right, moved_to))
        .unwrap();
    let fascia = gen::rgb_commit(&mut psbt, 0, 0x7a11);
    our_input(&mut psbt, &keys, 1);
    Made {
        opid,
        tx: psbt.unsigned_tx.clone(),
        psbt,
        fascia,
    }
}

/// A mint to `to` beside another asset's state moved to `moved_to`. The tx
/// pays `paid` from vout 1, then our change.
fn mint_beside_another_asset(
    to: BuilderSeal<GraphSeal>,
    paid: Vec<TxOut>,
    moved_to: u32,
) -> (History, Made) {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let mint = mint_builder(&mut history, rights[0], MINTED)
        .add_fungible_state("assetOwner", to, MINTED)
        .unwrap()
        .complete_transition()
        .unwrap();
    let change = paid.len() + 1;
    let paid_sats: u64 = paid.iter().map(|o| o.value.to_sat()).sum();
    let change_sats = RIGHT_SATS - WITNESS_MINT_FEE - paid_sats;
    let outputs = [paid, vec![ours(&keys, 99, change_sats)]].concat();
    let mut made = beside_another_asset(rights[0], mint, moved_to, outputs);
    claim_change(&mut made.psbt, &keys, change);
    (history, made)
}

/// Another asset's state on the right's UTXO moves to our change in its own
/// bundle, as rgb-lib builds it. It stays in the wallet, so the mint is signed.
#[test]
fn accepts_a_mint_beside_another_assets_state_moved_to_our_change() {
    let witness = BuilderSeal::from(GraphSeal::with_blinded_vout(1u32, 5));
    let cases = [
        (BuilderSeal::Concealed(recipient()), vec![], 1),
        (witness, vec![depositor(WITNESS_SATS)], 2),
    ];
    for (to, paid, change) in cases {
        let (history, mint) = mint_beside_another_asset(to, paid, change);
        assert_eq!(mint.fascia.bundles().len(), 2);
        let (minted, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
        assert_eq!(minted.unwrap(), MINTED);
        assert_eq!(bound.unwrap().opid, gen::opid_bytes(mint.opid));
    }
}

/// M9 binds the pinned asset only. Another asset's state may leave with the
/// depositor's output: the enclave could not keep it by refusing.
#[test]
fn signs_a_mint_that_moves_another_assets_state_to_the_depositor() {
    let witness = BuilderSeal::from(GraphSeal::with_blinded_vout(1u32, 5));
    let (history, mint) = mint_beside_another_asset(witness, vec![depositor(WITNESS_SATS)], 1);
    let (minted, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
    assert_eq!(minted.unwrap(), MINTED);
    assert_eq!(bound.unwrap().opid, gen::opid_bytes(mint.opid));
}

/// The mint's transition in another tx, which spends another of our Colored
/// UTXOs. That tx names another lockId, so M6 refuses it.
#[test]
fn m6_refuses_the_mint_transition_in_another_tx() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let mint = mint_on(&mut history, rights[0], &keys);
    let replay = committed_mint(&mut history, mint.transition(), rights[1]);
    assert_eq!(replay.opid, mint.opid);
    assert_ne!(replay.lock_id(), mint.lock_id());
    m6_against(mint.lock_id(), &history, &mint).expect("the locked tx");
    let err = m6_against(mint.lock_id(), &history, &replay).unwrap_err();
    assert!(err.to_string().contains("no FundsIn log"), "{err}");
}

#[test]
fn refuses_non_mint_type() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let outputs = vec![ours(&keys, 3, 1_000), ours(&keys, 4, 1_000)];
    let mut send = history.send_rights(rights[0], &[1, 2], vec![], outputs);
    our_input(&mut send.psbt, &keys, 1);
    let err = mint_refusal(&destination(&history, &send), &history);
    assert!(err.contains("not a mint"), "{err}");
}

#[test]
fn refuses_mint_without_one_mint_right_input() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let mint = mint_builder(&mut history, rights[0], MINTED)
        .add_input(rights[1].opout, AllocatedState::Void)
        .unwrap()
        .add_fungible_state("assetOwner", BuilderSeal::Concealed(recipient()), MINTED)
        .unwrap()
        .complete_transition()
        .unwrap();
    let mint = committed_mint(&mut history, mint, rights[0]);
    let err = mint_refusal(&destination(&history, &mint), &history);
    assert!(err.contains("exactly one mintRight"), "{err}");
}

#[test]
fn refuses_mint_passing_a_right_on() {
    let seal = GraphSeal::with_blinded_vout(1u32, 3);
    let err = mint_refusal_of(|mint| mint.add_rights("mintRight", seal).unwrap(), |_| {});
    assert!(err.contains("mint assigns [MintRight]"), "{err}");
}

#[test]
fn refuses_mint_with_link_output() {
    let seal = GraphSeal::with_blinded_vout(1u32, 3);
    let err = mint_refusal_of(|mint| mint.add_rights("linkRight", seal).unwrap(), |_| {});
    assert!(err.contains("assigns asset units only"), "{err}");
}

/// A global the BFA schema defines but a mint must not carry: M4 refuses it.
#[test]
fn refuses_extra_global() {
    let err = edited_mint_refusal(|mint| {
        let value = GlobalValues::with(RevealedData::new(blob(&[0; 8])));
        mint.globals
            .insert(bfa_schema::GS_BURNED_ASSET, value)
            .unwrap();
    });
    assert!(err.contains("issuedSupply and beforeBlock only"), "{err}");
}

/// A metadata type of no schema: rgb-lib's fascia inspection cannot name it,
/// so it refuses before M4 reads the transition.
#[test]
fn refuses_unknown_metadata() {
    let err = edited_mint_refusal(|mint| {
        let extra = rgbstd::MetaType::with(9_999);
        mint.metadata
            .insert(extra, MetaValue::from(blob(&[1])))
            .unwrap();
    });
    assert!(err.contains("unknown metadata type"), "{err}");
}

/// An amount is 8 bytes. rgb-lib's fascia inspection decodes the global, so
/// it refuses a short one before M4 reads it.
#[test]
fn refuses_issued_supply_not_8_bytes() {
    let err = edited_mint_refusal(|mint| {
        let value = GlobalValues::with(RevealedData::new(blob(&[0xa0, 0x86, 0x01, 0, 0, 0, 0])));
        mint.globals
            .insert(bfa_schema::GS_ISSUED_SUPPLY, value)
            .unwrap();
    });
    assert!(err.contains("invalid issuedSupply global"), "{err}");
}

#[test]
fn refuses_zero_issued_supply() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let to = BuilderSeal::Concealed(recipient());
    let change = ours(&keys, 99, CHANGE_SATS);
    let mut mint = history.mint(rights[0], 0, BEFORE_BLOCK, to, vec![], vec![change]);
    our_input(&mut mint.psbt, &keys, 1);
    let err = mint_refusal(&destination(&history, &mint), &history);
    assert!(err.contains("issuedSupply is 0"), "{err}");
}

/// A block number is 8 bytes, and rgb-lib's inspection decodes it too.
#[test]
fn refuses_before_block_not_8_bytes() {
    let err = edited_mint_refusal(|mint| {
        mint.metadata
            .insert(
                bfa_schema::MS_BEFORE_BLOCK,
                MetaValue::from(blob(&[90, 0, 0, 0])),
            )
            .unwrap();
    });
    assert!(err.contains("invalid beforeBlock metadata"), "{err}");
}

#[test]
fn refuses_asset_sum_not_issued_supply() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
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
    let err = mint_refusal(&destination(&history, &mint), &history);
    assert!(err.contains("declares issuedSupply"), "{err}");
}

#[test]
fn refuses_two_asset_legs() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
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
    let err = mint_refusal(&destination(&history, &mint), &history);
    assert!(err.contains("pays 2 asset legs"), "{err}");
}

/// M5: the minted units are the net deposit.
#[test]
fn refuses_a_mint_above_the_net_deposit() {
    let (history, mint) = valid_mint();
    let destination = destination(&history, &mint);
    let (result, _) = route_mint(&destination, &pinned(&history), 1, |_| {});
    let err = result.unwrap_err();
    assert!(err.to_string().contains("amount mismatch"), "{err}");
}

#[test]
fn refuses_non_all_sighash() {
    let (history, mut mint) = valid_mint();
    mint.psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0x83));
    let err = mint_refusal(&destination(&history, &mint), &history);
    assert!(err.contains("non-ALL sighash 0x83"), "{err}");
}

#[test]
fn refuses_foreign_input() {
    let (history, mut mint) = valid_mint();
    let input = &mut mint.psbt.inputs[0];
    input.witness_utxo.as_mut().unwrap().script_pubkey = fx::foreign_address(0xB1);
    input.tap_internal_key = None;
    input.tap_key_origins.clear();
    let err = mint_refusal(&destination(&history, &mint), &history);
    assert!(
        err.contains("input 0 is not a Colored key-path input"),
        "{err}"
    );
}

/// A fee input beside the right: F7 refuses a second input.
#[test]
fn refuses_a_mint_with_a_fee_input() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
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
    let err = mint_refusal(&destination(&history, &mint), &history);
    assert!(err.contains("spends 2 inputs"), "{err}");
}

#[test]
fn refuses_a_declared_asset_that_is_not_the_pin() {
    let (history, mint) = valid_mint();
    let destination = RgbDestination {
        asset_id: "rgb:listener-lied".into(),
        ..destination(&history, &mint)
    };
    let err = mint_refusal(&destination, &history);
    assert!(err.contains("contract_id mismatch"), "{err}");
}

#[test]
fn refuses_a_mint_without_a_deposit_binder() {
    let (history, mint) = valid_mint();
    let destination = destination(&history, &mint);
    let (result, _) = route_mint(&destination, &pinned(&history), 0, |ctx| {
        ctx.mint_binder = None;
    });
    let err = result.unwrap_err();
    assert!(err.to_string().contains("no deposit binder"), "{err}");
}

/// M8 needs the enclave keys; without them the mint fails closed.
#[test]
fn refuses_a_mint_without_a_sats_check() {
    for (history, mint) in [valid_mint(), valid_witness_mint()] {
        let destination = destination(&history, &mint);
        let (result, bound) = route_mint(&destination, &pinned(&history), 0, |ctx| {
            ctx.mint_sats = None;
        });
        let err = result.unwrap_err();
        assert!(err.to_string().contains("no sats check"), "{err}");
        assert!(bound.is_none(), "no deposit is read for a refused mint");
    }
}

/// M8 refuses on the route, before M6 reads the deposit.
#[test]
fn refuses_a_blinded_mint_paying_sats_out() {
    let (history, mut mint) = valid_mint();
    mint.psbt.outputs[1] = Default::default();
    let (result, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
    let err = result.unwrap_err().to_string();
    assert!(err.contains("mint PSBT pays 2000 sat"), "{err}");
    assert!(bound.is_none(), "no deposit is read for a refused mint");
}

// ===== the witness mint =====

#[test]
fn binds_a_valid_witness_mint() {
    let (history, mint) = valid_witness_mint();
    let (minted, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
    assert_eq!(minted.unwrap(), MINTED);
    let bound = bound.expect("the binder ran");
    assert_eq!(bound.opid, gen::opid_bytes(mint.opid));
    assert_eq!(bound.lock_id, mint.lock_id());
    assert_eq!(bound.recipient, MintRecipient::Witness { vout: 1 });
}

/// BDK drops change below dust; the right then pays only the witness and the fee.
#[test]
fn binds_a_witness_mint_without_change() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let to = BuilderSeal::from(GraphSeal::with_blinded_vout(1u32, 5));
    let outputs = vec![depositor(WITNESS_SATS)];
    let mut mint = history.mint(rights[0], MINTED, BEFORE_BLOCK, to, vec![], outputs);
    our_input(&mut mint.psbt, &keys, 1);
    let (minted, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
    assert_eq!(minted.unwrap(), MINTED);
    assert_eq!(
        bound.expect("the binder ran").recipient,
        MintRecipient::Witness { vout: 1 }
    );
}

/// Vout 2 is our change; vout 3 is past the tx's three outputs.
#[test]
fn refuses_a_witness_mint_whose_seal_names_another_vout() {
    for (vout, refusal) in [
        (2, "vout 2, an output of this enclave"),
        (3, "vout 3, but its tx has 3 outputs"),
    ] {
        let (history, mint) = witness_mint_paying(vout, vec![depositor(WITNESS_SATS)]);
        let (result, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
        let err = result.unwrap_err().to_string();
        assert!(err.contains(refusal), "{vout}: {err}");
        assert!(bound.is_none(), "no deposit is read for a refused mint");
    }
}

/// The enclave cannot see another tx's output, so it cannot check what it pays.
#[test]
fn refuses_a_witness_seal_on_another_tx() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let elsewhere = gen::outpoint(0xC0, 0).txid;
    let to = BuilderSeal::from(GraphSeal::with_blinding(elsewhere, 1u32, 5));
    let outputs = vec![
        depositor(WITNESS_SATS),
        ours(&keys, 99, WITNESS_CHANGE_SATS),
    ];
    let mut mint = history.mint(rights[0], MINTED, BEFORE_BLOCK, to, vec![], outputs);
    our_input(&mut mint.psbt, &keys, 1);
    claim_change(&mut mint.psbt, &keys, 2);
    let err = mint_refusal(&destination(&history, &mint), &history);
    assert!(err.contains("the transaction that makes it"), "{err}");
}

/// The OpId commits the seal's vout, not the script on it. One mint transition in a tx paying the user and in one paying
/// anyone else passes every route rule under one OpId. The lockId commits the
/// tx too, so M6 binds the user's lock to the user's tx alone.
#[test]
fn witness_mint_lock_id_binds_the_recipient_script() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let to = BuilderSeal::from(GraphSeal::with_blinded_vout(1u32, 5));
    let mint = mint_builder(&mut history, rights[0], MINTED)
        .add_fungible_state("assetOwner", to, MINTED)
        .unwrap()
        .complete_transition()
        .unwrap();
    let mut commit_paying = |recipient: ScriptBuf| {
        let outputs = vec![
            TxOut {
                value: Amount::from_sat(WITNESS_SATS),
                script_pubkey: recipient,
            },
            ours(&keys, 99, WITNESS_CHANGE_SATS),
        ];
        let mut made = history.commit_psbt(vec![mint.clone()], vec![rights[0].outpoint], outputs);
        our_input(&mut made.psbt, &keys, 1);
        claim_change(&mut made.psbt, &keys, 2);
        made
    };
    let to_user = commit_paying(fx::foreign_address(0xAA));
    let to_host = commit_paying(fx::foreign_address(0xBB));

    assert_ne!(
        to_user.tx.output[1].script_pubkey,
        to_host.tx.output[1].script_pubkey
    );
    assert_ne!(to_user.tx.compute_txid(), to_host.tx.compute_txid());
    assert_eq!(to_user.opid, to_host.opid);
    assert_ne!(to_user.lock_id(), to_host.lock_id());

    // The depositor locked the user's tx; M6 checks that lock's FundsIn.
    let m6 = |made: &Made| m6_against(to_user.lock_id(), &history, made);
    m6(&to_user).expect("the user's tx is the one locked");
    let err = m6(&to_host).unwrap_err().to_string();
    assert!(err.contains("no FundsIn log"), "{err}");
}

/// The route on `made`, then M6 against a deposit that locks `locked`.
fn m6_against(locked: [u8; 32], history: &History, made: &Made) -> Result<()> {
    let bridge = [0xB1; 20];
    let deposit = crate::test_support::mint_deposit(bridge, locked, MINTED, [0xd0; 32]);
    let (minted, bound) = run_mint(&destination(history, made), &pinned(history));
    assert_eq!(minted.unwrap(), MINTED);
    let bound = bound.expect("the binder ran");
    crate::networks::evm::events::verify_rgb_funds_in(
        &deposit,
        &bridge,
        attestation_verify::EvmFinalityTag::Safe,
        &[0xee; 32],
        &bound.lock_id,
        &[0xd0; 32],
        MINTED,
        bound.before_block,
    )
    .map(|_| ())
}

/// The OpId commits a blinded seal. So the same mint to another seal names
/// another lock, and M6 binds the user's lock to the mint that pays the user.
#[test]
fn blinded_mint_lock_id_binds_the_recipient_seal() {
    let keys = fx::km();
    let mint_paying = |seal: SecretSeal| {
        let (mut history, rights) = seeded(&keys);
        let mint = mint_to(&mut history, rights[0], &keys, seal);
        (history, mint)
    };
    let (history, to_user) = mint_paying(recipient());
    let host = GraphSeal::with_blinding(gen::outpoint(0xC1, 0).txid, 0u32, 7).to_secret_seal();
    let (host_history, to_host) = mint_paying(host);

    // The two mints differ in their seal only.
    assert_eq!(history.contract_id, host_history.contract_id);
    assert_eq!(to_user.tx.input, to_host.tx.input);
    assert_ne!(to_user.opid, to_host.opid);
    assert_ne!(to_user.lock_id(), to_host.lock_id());

    // The depositor locked the mint to the user's seal.
    let m6 = |made: &Made| m6_against(to_user.lock_id(), &history, made);
    m6(&to_user).expect("the user's mint is the one locked");
    let err = m6(&to_host).unwrap_err().to_string();
    assert!(err.contains("no FundsIn log"), "{err}");
}

// ===== the rights refill =====

/// A refill of `right` to our rights on vouts 1..=3.
fn refill_request(history: &mut History, right: Utxo) -> (Made, SignRightsRefillRequest) {
    let keys = fx::km();
    let outputs = (3..=5).map(|i| ours(&keys, i, 1_000)).collect();
    let mut refill = history.send_rights(right, &[1, 2, 3], vec![], outputs);
    our_input(&mut refill.psbt, &keys, 1);
    let request = SignRightsRefillRequest {
        psbt_bytes: refill.psbt.serialize(),
        asset_id: history.contract_id.to_string(),
        fascia: refill.fascia_bytes(),
    };
    (refill, request)
}

fn run_refill(
    refill: &Made,
    request: &SignRightsRefillRequest,
    history: &History,
) -> Result<Vec<u32>> {
    validate_rights_refill(request, &refill.psbt, &pinned(history), &|_, _| false)
}

/// A refill's UTXO can hold other state too, which rgb-lib moves the same
/// way. The refill is read beside another asset's move wherever it lands: on
/// our own output, or on vout 9, which the tx does not have.
#[test]
fn a_refill_takes_another_assets_state_wherever_it_moves() {
    let keys = fx::km();
    for moved_to in [1, 9] {
        let (mut history, rights) = seeded(&keys);
        let refill = history.rights_transition(rights[0], &[1, 2, 3]);
        let outputs = (3..=5).map(|i| ours(&keys, i, 1_000)).collect();
        let made = beside_another_asset(rights[0], refill, moved_to, outputs);
        let request = SignRightsRefillRequest {
            psbt_bytes: made.psbt.serialize(),
            asset_id: history.contract_id.to_string(),
            fascia: made.fascia_bytes(),
        };
        let read = validate_rights_refill(&request, &made.psbt, &pinned(&history), &|_, _| true);
        assert_eq!(read.unwrap(), vec![1, 2, 3], "moved to vout {moved_to}");
    }
}

#[test]
fn accepts_a_refill_of_an_issuer_seed_right() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let (refill, request) = refill_request(&mut history, rights[0]);
    assert_eq!(
        run_refill(&refill, &request, &history).unwrap(),
        vec![1, 2, 3]
    );
}

#[test]
fn accepts_a_refill_of_a_refill_made_right() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let (first, _) = refill_request(&mut history, rights[0]);
    let made = gen::rights_made(&first, &[1, 2, 3]);
    let (refill, request) = refill_request(&mut history, made[0]);
    assert_eq!(
        run_refill(&refill, &request, &history).unwrap(),
        vec![1, 2, 3]
    );
}

#[test]
fn refuses_a_refill_of_another_asset() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let (refill, request) = refill_request(&mut history, rights[0]);
    let (other, ..) = seeded_other();
    let err =
        validate_rights_refill(&request, &refill.psbt, &pinned(&other), &|_, _| false).unwrap_err();
    assert!(
        err.to_string()
            .contains("no transition of the pinned RGB_ASSET_ID"),
        "{err}"
    );
}

/// A second asset, so its contract id differs.
fn seeded_other() -> (History, Utxo) {
    let right = gen::outpoint(0xA9, 0);
    let history = History::issue(Issue::new(GENESIS_CHAIN_ID, [0xB9; 20], vec![right]));
    let utxo = history.genesis_right(0, right);
    (history, utxo)
}

#[test]
fn refuses_a_refill_with_a_non_all_sighash() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let (mut refill, request) = refill_request(&mut history, rights[0]);
    refill.psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0x02));
    let err = run_refill(&refill, &request, &history).unwrap_err();
    assert!(err.to_string().contains("non-ALL sighash 0x02"), "{err}");
}

// ===== parity with the consensus path, while both compile =====

/// rgb-lib's `validate_consignment_with_resolver` over `bytes`, with every
/// witness mined. Returns what it derived and the mint anchors it asked to bind.
fn consensus(
    bytes: &[u8],
) -> (
    validation::ValidatedConsignment,
    Vec<validation::MintAnchor>,
) {
    let validator = validation::RgbValidator::new("regtest").unwrap();
    let transfer = <rgbstd::containers::Transfer as rgbstd::containers::FileContent>::load(
        std::io::Cursor::new(bytes),
    )
    .unwrap();
    let witnesses: Vec<bitcoin::Txid> = transfer.bundles.iter().map(|wb| wb.witness_id()).collect();
    let chain = crate::test_support::MinedBlocks::of(&witnesses);
    let anchors = RefCell::new(Vec::new());
    let bind = |seen: &[validation::MintAnchor]| {
        anchors.borrow_mut().extend_from_slice(seen);
        Ok(validation::BoundAnchors {
            evm_chain_id: GENESIS_CHAIN_ID,
            locks: seen
                .iter()
                .map(|a| validation::VerifiedLock {
                    lock_id: a.lock_id,
                    minted: a.amount,
                    operation_id: [0xd0; 32],
                    net_amount: a.amount,
                })
                .collect(),
        })
    };
    let lists = validation::ListAccess {
        bind_asset: &|_: &str| Ok(()),
        read: None,
    };
    let validated = validator
        .validate_consignment(bytes, Some(&bind), &chain, &lists)
        .unwrap();
    (validated, anchors.into_inner())
}

#[test]
fn a_mint_reads_the_same_from_the_fascia_as_from_consensus() {
    let (history, mint) = valid_mint();
    let (_, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
    let from_fascia = bound.expect("the mint is valid");

    let (validated, anchors) = consensus(&history.consignment());
    let [anchor] = anchors.as_slice() else {
        panic!("one mint anchor, got {anchors:?}");
    };
    assert_eq!(validated.settling_op_id, Some(from_fascia.opid));
    assert_eq!(anchor.opid, from_fascia.opid);
    assert_eq!(anchor.amount, from_fascia.issued);
    assert_eq!(anchor.before_block, from_fascia.before_block);
    let last = validated.settling_transition.unwrap();
    assert_eq!(last.asset_output_amount, from_fascia.issued);
    let seals: Vec<_> = last.outputs.iter().map(|o| o.seal.clone()).collect();
    assert_eq!(
        seals,
        vec![validation::OutputSeal::Confidential {
            secret_seal: recipient().to_string()
        }]
    );
}

#[test]
fn a_witness_mint_reads_the_same_from_the_fascia_as_from_consensus() {
    let (history, mint) = valid_witness_mint();
    let (_, bound) = run_mint(&destination(&history, &mint), &pinned(&history));
    let from_fascia = bound.expect("the mint is valid");
    assert_eq!(from_fascia.recipient, MintRecipient::Witness { vout: 1 });

    let (validated, anchors) = consensus(&history.consignment());
    let [anchor] = anchors.as_slice() else {
        panic!("one mint anchor, got {anchors:?}");
    };
    assert_eq!(anchor.opid, from_fascia.opid);
    let last = validated.settling_transition.unwrap();
    assert_eq!(last.asset_output_amount, from_fascia.issued);
    let seals: Vec<_> = last.outputs.iter().map(|o| o.seal.clone()).collect();
    assert_eq!(
        seals,
        vec![validation::OutputSeal::Revealed {
            txid: None,
            vout: 1
        }]
    );
}

#[test]
fn a_refill_reads_the_same_from_the_fascia_as_from_consensus() {
    let keys = fx::km();
    let (mut history, rights) = seeded(&keys);
    let (refill, request) = refill_request(&mut history, rights[0]);
    let vouts = run_refill(&refill, &request, &history).unwrap();
    let bytes = refill.fascia_bytes();
    let committed = psbt_commit::committed_transition(
        &refill.psbt,
        &bytes,
        "fascia",
        psbt_commit::Pin::for_test(history.contract_id),
        &|_, _| false,
    )
    .unwrap();

    let (validated, anchors) = consensus(&history.consignment());
    assert!(anchors.is_empty());
    assert_eq!(
        validated.settling_op_id,
        Some(gen::opid_bytes(committed.opid))
    );
    assert_eq!(
        validated.settling_transition.map(|t| t.transition_type),
        Some(rgb_lib::TypeOfTransition::Propagate)
    );
    // The rights themselves are the mint signer's rule (RR8, RR9): a refill
    // moves no units, so the burn path's summary carries no output for them.
    assert_eq!(
        vouts,
        (1..=u32::try_from(vouts.len()).unwrap()).collect::<Vec<_>>()
    );
}
