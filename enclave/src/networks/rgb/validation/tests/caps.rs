//! The caps on the work rgb-lib does, checked before it runs, and the
//! release-mode timings their values come from: `cargo test --release -p
//! utexo-bridge-enclave --no-default-features --features rgb,burn-signer --lib
//! caps -- --ignored --nocapture`.

use std::str::FromStr;
use std::time::{Duration, Instant};

use bitcoin::key::{TweakedPublicKey, UntweakedPublicKey};
use bitcoin::taproot::{LeafScript, LeafVersion};
use bitcoin::{Amount, ScriptBuf, TxOut};
use rgb_lib::no_wallet::{
    validate_consignment_with_resolver, ResolveRejectList, ValidationOptions,
};
use rgb_lib::BitcoinNetwork;
use rgbstd::containers::Transfer;
use rgbstd::rgbcore::commit_verify::mpc::Message;
use rgbstd::rgbcore::commit_verify::ConvolveCommit;
use rgbstd::tapret::{TapretNodePartner, TapretPathProof, TapretProof};
use rgbstd::validation::DbcProof;
use rgbstd::{ChainNet, Operation, Opout};

use super::super::cost::{
    assert_bounded_for_rgb_lib, assert_within, bundle_id_cost, opouts_dag_cost, reject_walk_cost,
    rgb_lib_ns, witness_check_cost, MAX_BUNDLE_ID_COST, MAX_OPOUTS_DAG_COST, MAX_REJECT_WALK_COST,
    MAX_RGB_LIB_NS, MAX_WITNESS_CHECK_COST,
};
use super::super::scratch::with_scratch_file;
use super::*;

fn load(bytes: &[u8]) -> Transfer {
    Transfer::load(std::io::Cursor::new(bytes)).unwrap()
}

/// Our gate on `bytes`, as `load_bounded` runs it.
fn gate(bytes: &[u8], listed: bool) -> Result<()> {
    assert_bounded_for_rgb_lib(&load(bytes), bytes.len(), listed)
}

/// The exact walk cost, with no cap to stop it early.
fn walk_cost(bytes: &[u8]) -> u64 {
    reject_walk_cost(&load(bytes), u64::MAX)
}

/// A propagate of the genesis right to `n` rights, then a burn of all of
/// them: schema-valid, no mint, about n^2 steps of DAG.
fn rights_burn(mut history: History, n: u16) -> Vec<u8> {
    let right = history.genesis_right(0, right_utxo());
    burn_rights_of(&mut history, right, n, 0);
    history.consignment()
}

/// [`rights_burn`] of genesis right `right`, in two new bundles. The burn tx
/// spends `d` dummy inputs before the real one.
fn burn_rights_of(history: &mut History, right: Utxo, n: u16, d: u32) {
    let (rights, at) = propagate_rights(history, right, n);
    let mut burn = history.transition("burn");
    for no in 0..n {
        let right = Opout::new(rights, schemata::OS_MINT, no);
        burn = burn.add_input(right, AllocatedState::Void).unwrap();
    }
    let burn = burn.complete_transition().unwrap();
    history.commit_bundle(
        gen::bundle_of(vec![burn]),
        dummies_then(d, at),
        vec![gen::dust(4)],
    );
}

/// `d` dummy outpoints, then `real`.
fn dummies_then(d: u32, real: OutPoint) -> Vec<OutPoint> {
    let mut inputs: Vec<OutPoint> = (0..d).map(|i| gen::outpoint(0xD0, i)).collect();
    inputs.push(real);
    inputs
}

/// A propagate of `right` to `n` rights, all on vout 1 of its tx. Returns the
/// propagate and that outpoint.
fn propagate_rights(history: &mut History, right: Utxo, n: u16) -> (rgbstd::OpId, OutPoint) {
    let mut propagate = history
        .transition("propagate")
        .add_input(right.opout, AllocatedState::Void)
        .unwrap();
    for no in 0..u64::from(n) {
        let seal = GraphSeal::with_blinded_vout(1u32, 0x7000 + no);
        propagate = propagate.add_rights("mintRight", seal).unwrap();
    }
    let propagate = propagate.complete_transition().unwrap();
    let rights = propagate.id();
    let tx = history.commit_bundle(
        gen::bundle_of(vec![propagate]),
        vec![right.outpoint],
        vec![gen::dust(5)],
    );
    (rights, OutPoint::new(tx.compute_txid(), 1))
}

/// `t` rights, then one bundle of `t` one-right burns in a tx with `d` dummy
/// inputs before the real one: rgb-lib checks each burn against the whole tx.
fn many_burns(mut history: History, t: u16, d: u32) -> Vec<u8> {
    commit_many_burns(&mut history, t, d);
    history.consignment()
}

/// [`many_burns`] committed in a Tapret output instead, whose script tree
/// has a partner leaf of `leaf` bytes.
fn many_tapret_burns(t: u16, leaf: usize) -> Vec<u8> {
    let mut history = issue();
    commit_many_burns(&mut history, t, 0);
    tapret_last_bundle(&mut history, leaf);
    history.consignment()
}

/// Moves the last bundle's commitment from its OP_RETURN to a Tapret output
/// beside a partner leaf of `leaf` bytes, which rgb-lib hashes per transition.
fn tapret_last_bundle(history: &mut History, leaf: usize) {
    let protocol = history.contract_id;
    let wb = history.bundles.last_mut().unwrap();
    let message = Message::from(wb.bundle.bundle_id());
    let commitment = wb.anchor.convolve(protocol, message).unwrap();
    // The x coordinate of the secp256k1 generator.
    let internal_pk = UntweakedPublicKey::from_str(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    wb.tx.output[0] = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
            internal_pk,
        )),
    };
    let partner = TapretNodePartner::RightLeaf(LeafScript {
        version: LeafVersion::TapScript,
        script: ScriptBuf::from_bytes(vec![0x51; leaf]),
    });
    // The commitment leaf must sort before its partner: about one nonce in two.
    let (tx, proof) = (0..=u8::MAX)
        .find_map(|nonce| {
            let path_proof = TapretPathProof::with(partner.clone(), nonce).unwrap();
            let supplement = TapretProof {
                path_proof,
                internal_pk,
            };
            wb.tx.convolve_commit(&supplement, &commitment).ok()
        })
        .unwrap();
    wb.tx = tx;
    wb.anchor.dbc_proof = DbcProof::Tapret(proof);
}

fn commit_many_burns(history: &mut History, t: u16, d: u32) {
    let right = history.genesis_right(0, right_utxo());
    let (rights, at) = propagate_rights(history, right, t);
    let burns = (0..t)
        .map(|no| {
            let right = Opout::new(rights, schemata::OS_MINT, no);
            let burn = history.transition("burn");
            let burn = burn.add_input(right, AllocatedState::Void).unwrap();
            burn.complete_transition().unwrap()
        })
        .collect();
    history.commit_bundle(
        gen::bundle_of(burns),
        dummies_then(d, at),
        vec![gen::dust(4)],
    );
}

/// A mint of `k` units, a spread of them to `k` allocations, then a transfer
/// of all of them to `k` outputs: a walk of 2k(k + 5) steps.
fn wide_transfer(mut history: History, k: u16) -> Vec<u8> {
    let right = history.genesis_right(0, right_utxo());
    let units = history.mint_owned(right, u64::from(k), 90);
    let (spread, spread_tx) = fan_out(&mut history, units, k, 0x4000);
    let mut wide = history.transition("transfer");
    for no in 0..k {
        let unit = Opout::new(spread, schemata::OS_ASSET, no);
        let seal = GraphSeal::with_blinded_vout(1u32, 0x3000 + u64::from(no));
        wide = wide
            .add_input(unit, AllocatedState::from(RevealedValue::from(1u64)))
            .unwrap()
            .add_fungible_state("assetOwner", seal, 1u64)
            .unwrap();
    }
    let wide = wide.complete_transition().unwrap();
    history.commit_bundle(
        gen::bundle_of(vec![wide]),
        vec![OutPoint::new(spread_tx, 1)],
        vec![gen::dust(7)],
    );
    history.consignment()
}

/// Moves `units` (holding `k`) to `k` outputs of one unit on vout 1 of a new
/// tx. Returns the transition and its tx.
fn fan_out(
    history: &mut History,
    units: Utxo,
    k: u16,
    blinding: u64,
) -> (rgbstd::OpId, bitcoin::Txid) {
    let mut spread = history.transition("transfer").add_input(
        units.opout,
        AllocatedState::from(RevealedValue::from(u64::from(k))),
    );
    for no in 0..u64::from(k) {
        let seal = GraphSeal::with_blinded_vout(1u32, blinding + no);
        spread = spread.unwrap().add_fungible_state("assetOwner", seal, 1u64);
    }
    let spread = spread.unwrap().complete_transition().unwrap();
    let opid = spread.id();
    let tx = history.commit_bundle(
        gen::bundle_of(vec![spread]),
        vec![units.outpoint],
        vec![gen::dust(6)],
    );
    (opid, tx.compute_txid())
}

/// A mint of `k` units, `l` transfers of all of them, then a fan-out to `k`
/// outputs: k + 1 origins, each walking the whole chain.
fn fanned_chain(mut history: History, k: u16, l: usize) -> Vec<u8> {
    let right = history.genesis_right(0, right_utxo());
    let mut units = history.mint_owned(right, u64::from(k), 90);
    for _ in 0..l {
        units = history.transfer(units, u64::from(k));
    }
    fan_out(&mut history, units, k, 0x5000);
    history.consignment()
}

/// [`fanned_chain`] with each unit moved on by its own transfer, then all
/// merged: k origins of distinct operations, so k walks of the chain.
fn merged_chain(mut history: History, k: u16, l: usize) -> Vec<u8> {
    let right = history.genesis_right(0, right_utxo());
    let mut units = history.mint_owned(right, u64::from(k), 90);
    for _ in 0..l {
        units = history.transfer(units, u64::from(k));
    }
    let seals: Vec<GraphSeal> = (0..u32::from(k))
        .map(|no| GraphSeal::with_blinded_vout(1 + no, 0x5000 + u64::from(no)))
        .collect();
    let mut spread = history.transition("transfer").add_input(
        units.opout,
        AllocatedState::from(RevealedValue::from(u64::from(k))),
    );
    for seal in &seals {
        spread = spread
            .unwrap()
            .add_fungible_state("assetOwner", *seal, 1u64);
    }
    let spread = spread.unwrap().complete_transition().unwrap();
    let outputs = (0..k).map(|_| gen::dust(6)).collect();
    let spread_id = spread.id();
    let spread_out = spread
        .assignments
        .get(&schemata::OS_ASSET)
        .unwrap()
        .as_fungible()
        .to_vec();
    let tx = history.commit_bundle(gen::bundle_of(vec![spread]), vec![units.outpoint], outputs);
    let moved: Vec<Utxo> = (1..)
        .zip(&seals)
        .map(|(vout, seal)| {
            let no = spread_out
                .iter()
                .position(|a| a.revealed_seal() == Some(*seal));
            let opout = Opout::new(
                spread_id,
                schemata::OS_ASSET,
                u16::try_from(no.unwrap()).unwrap(),
            );
            let outpoint = OutPoint::new(tx.compute_txid(), vout);
            history.transfer(Utxo { opout, outpoint }, 1)
        })
        .collect();
    let mut merge = history.transition("transfer");
    for unit in &moved {
        let one = AllocatedState::from(RevealedValue::from(1u64));
        merge = merge.add_input(unit.opout, one).unwrap();
    }
    let seal = GraphSeal::with_blinded_vout(1u32, 0x5fff);
    let merge = merge.add_fungible_state("assetOwner", seal, u64::from(k));
    let merge = merge.unwrap().complete_transition().unwrap();
    let inputs = moved.iter().map(|unit| unit.outpoint).collect();
    history.commit_bundle(gen::bundle_of(vec![merge]), inputs, vec![gen::dust(8)]);
    history.consignment()
}

/// Validates `bytes` with nothing mined. Returns the refusal and how many
/// witnesses rgb-lib asked about: none when the caps refuse first.
fn validate_unmined(bytes: &[u8]) -> (String, usize) {
    let chain = BTreeMap::new();
    let source = Recording {
        chain: &chain,
        asked: RefCell::new(Vec::new()),
    };
    let result =
        validator().validate_consignment(bytes, Some(&bind_all), &on_chain(&source), &open_lists());
    (error_of(result), source.asked.into_inner().len())
}

fn assert_capped(bytes: &[u8], cap: &str) {
    let (err, asked) = validate_unmined(bytes);
    assert!(err.contains(cap), "{err}");
    assert_eq!(asked, 0, "refused before rgb-lib: {err}");
}

/// The largest `n` whose `cost(n)` stays within `cap`.
fn largest_within(cap: u64, cost: impl Fn(u64) -> u64) -> u16 {
    let n = (1..=u64::from(u16::MAX))
        .take_while(|n| cost(*n) <= cap)
        .last()
        .unwrap();
    u16::try_from(n).unwrap()
}

fn rights_burn_cost(n: u64) -> u64 {
    n * n + 1
}

fn wide_walk_cost(k: u64) -> u64 {
    2 * k * (k + 5)
}

#[test]
fn each_cap_admits_its_own_value_and_refuses_one_more() {
    for cap in [
        MAX_OPOUTS_DAG_COST,
        MAX_WITNESS_CHECK_COST,
        MAX_BUNDLE_ID_COST,
        MAX_REJECT_WALK_COST,
        MAX_RGB_LIB_NS,
    ] {
        assert_within(cap, cap, "do it", "a shape").unwrap();
        let err = assert_within(cap + 1, cap, "do it", "a shape").unwrap_err();
        assert!(err.to_string().contains(&format!("(max {cap})")), "{err}");
    }
}

#[test]
fn the_dag_cost_is_the_square_of_each_transitions_inputs() {
    let bytes = rights_burn(issue(), 3);
    assert_eq!(opouts_dag_cost(&load(&bytes)), rights_burn_cost(3));
    let bytes = wide_transfer(issue(), 3);
    assert_eq!(opouts_dag_cost(&load(&bytes)), 1 + 1 + 9);
}

/// Per bundle: its transitions times its tx size and Tapret partner leaf,
/// plus its seals times its tx inputs.
#[test]
fn the_witness_cost_is_each_transition_over_its_whole_tx_and_anchor() {
    let transfer = load(&many_burns(issue(), 3, 5));
    let size = |no: usize| transfer.bundles[no].tx.total_size() as u64;
    let propagate = size(0) + 1;
    let burns = 3 * size(1) + 3 * 6;
    assert_eq!(witness_check_cost(&transfer), propagate + burns);
    let transfer = load(&many_tapret_burns(3, 1_000));
    let size = |no: usize| transfer.bundles[no].tx.total_size() as u64;
    let propagate = size(0) + 1;
    let burns = 3 * (size(1) + 1_000) + 3;
    assert_eq!(witness_check_cost(&transfer), propagate + burns);
}

/// Per bundle: its transitions and the bundle itself, times its input map.
#[test]
fn the_bundle_id_cost_is_each_transition_over_its_whole_input_map() {
    assert_eq!(bundle_id_cost(&load(&many_burns(issue(), 3, 5))), 2 + 4 * 3);
    assert_eq!(bundle_id_cost(&load(&rights_burn(issue(), 3))), 2 + 2 * 3);
}

/// rgb-lib walks from each origin on its own, so only a shared history makes
/// it superlinear; a burn of separate lines costs a few steps per line.
#[test]
fn the_walk_cost_is_rgb_libs_walk_from_each_origin() {
    assert_eq!(walk_cost(&wide_transfer(listed(), 3)), wide_walk_cost(3));
    // The fan-out's input walks 7 steps, each of its 2 outputs 9.
    assert_eq!(walk_cost(&fanned_chain(listed(), 2, 2)), 7 + 2 * 9);
    // The split is not terminal: only the burn's input is an origin.
    assert_eq!(walk_cost(&listed_burn().0.consignment()), 5);
    // 3 lines of a mint and 2 transfers each: 2 * 2 + 5 steps a line.
    assert_eq!(walk_cost(&honest_burn(listed(), 3, 2)), 3 * 9);
}

/// The count stops just past its cap, at the cap as anywhere else.
#[test]
fn the_walk_cost_stops_past_its_cap() {
    let transfer = load(&wide_transfer(listed(), 3));
    let exact = wide_walk_cost(3);
    assert_eq!(reject_walk_cost(&transfer, exact), exact);
    assert!(reject_walk_cost(&transfer, exact - 1) > exact - 1);
    assert!(reject_walk_cost(&transfer, 1) > 1);
}

/// A burn of n rights from one propagate passes the gate at the cap and is
/// refused before rgb-lib at the next n, listed or not.
#[test]
fn a_burn_of_too_many_rights_is_refused_before_rgb_lib() {
    let n = largest_within(MAX_OPOUTS_DAG_COST, rights_burn_cost);
    let at_cap = rights_burn(issue(), n);
    assert_eq!(opouts_dag_cost(&load(&at_cap)), rights_burn_cost(n.into()));
    gate(&at_cap, false).unwrap();
    assert_capped(&rights_burn(issue(), n + 1), "opouts DAG");
    assert_capped(&rights_burn(listed(), n + 1), "opouts DAG");
}

/// The dummy inputs that bring 256 one-right burns to about `cost`: each
/// costs its 41 bytes and one seal scan per burn.
fn dummies_for(cost: u64) -> u32 {
    u32::try_from(cost / 256 / 42).unwrap()
}

/// Many burns in one bundle with a wide tx pass under the witness cap and
/// are refused before rgb-lib over it.
#[test]
fn a_bundle_of_many_transitions_in_a_wide_tx_is_refused_before_rgb_lib() {
    let under = many_burns(issue(), 256, dummies_for(MAX_WITNESS_CHECK_COST / 8 * 7));
    assert!(witness_check_cost(&load(&under)) > MAX_WITNESS_CHECK_COST / 4 * 3);
    gate(&under, false).unwrap();
    let over = many_burns(issue(), 256, dummies_for(MAX_WITNESS_CHECK_COST / 8 * 9));
    let cost = witness_check_cost(&load(&over));
    assert!(cost > MAX_WITNESS_CHECK_COST, "{cost}");
    assert!(opouts_dag_cost(&load(&over)) <= MAX_OPOUTS_DAG_COST);
    assert_capped(&over, "witness txs");
}

/// Many burns in one bundle with a wide Tapret partner leaf, which rgb-lib
/// hashes per burn, pass under the witness cap and are refused before rgb-lib
/// over it. The shape is valid: rgb-lib checks its witnesses.
#[test]
fn a_bundle_of_many_transitions_with_a_wide_anchor_is_refused_before_rgb_lib() {
    let leaf = |cost: u64| usize::try_from(cost / 256).unwrap();
    let under = many_tapret_burns(256, leaf(MAX_WITNESS_CHECK_COST / 8 * 7));
    gate(&under, false).unwrap();
    let over = many_tapret_burns(256, leaf(MAX_WITNESS_CHECK_COST / 8 * 9));
    let cost = witness_check_cost(&load(&over));
    assert!(cost > MAX_WITNESS_CHECK_COST, "{cost}");
    assert_capped(&over, "witness txs");
    let (err, asked) = validate_unmined(&many_tapret_burns(2, 64));
    assert!(err.contains("not proven on chain"), "{err}");
    assert!(asked > 0, "rgb-lib ran: {err}");
}

/// t one-right burns in one bundle cost (t + 1) t + 2 bundle-id steps: they
/// pass at the cap and are refused before rgb-lib one burn over it.
#[test]
fn a_bundle_of_too_many_transitions_is_refused_before_rgb_lib() {
    let cost = |t: u64| (t + 1) * t + 2;
    let t = largest_within(MAX_BUNDLE_ID_COST, cost);
    let at_cap = many_burns(issue(), t, 0);
    assert_eq!(bundle_id_cost(&load(&at_cap)), cost(t.into()));
    gate(&at_cap, false).unwrap();
    assert_capped(&many_burns(issue(), t + 1, 0), "bundle ids");
}

/// A listed wide transfer passes at the walk cap and is refused before rgb-lib
/// one wider; the same shape unlisted has no walk to cap.
#[test]
fn a_listed_asset_caps_the_reject_walk_and_an_unlisted_one_does_not() {
    let k = largest_within(MAX_REJECT_WALK_COST, wide_walk_cost);
    let at_cap = wide_transfer(listed(), k);
    assert_eq!(
        reject_walk_cost(&load(&at_cap), MAX_REJECT_WALK_COST),
        wide_walk_cost(k.into())
    );
    gate(&at_cap, true).unwrap();
    let over = wide_transfer(listed(), k + 1);
    assert!(opouts_dag_cost(&load(&over)) <= MAX_OPOUTS_DAG_COST);
    assert_capped(&over, "reject list");
    let unlisted = wide_transfer(issue(), k + 1);
    assert!(walk_cost(&unlisted) > MAX_REJECT_WALK_COST);
    let (err, asked) = validate_unmined(&unlisted);
    assert!(err.contains("not proven on chain"), "{err}");
    assert!(asked > 0, "rgb-lib ran: {err}");
}

/// The file costs its bytes at one rate and each cost its steps at another;
/// the sum saturates.
#[test]
fn the_rgb_lib_time_adds_the_file_to_each_cost() {
    let costs = [100, 1_000, 10, 1_000];
    assert_eq!(rgb_lib_ns(0, [0; 4]), 0);
    assert_eq!(rgb_lib_ns(1_000, [0; 4]), 1_300_000);
    assert_eq!(rgb_lib_ns(0, costs), 200 + 14_000 + 45_000 + 75_000);
    assert_eq!(
        rgb_lib_ns(1_000, costs),
        rgb_lib_ns(1_000, [0; 4]) + rgb_lib_ns(0, costs)
    );
    assert_eq!(rgb_lib_ns(usize::MAX, costs), u64::MAX);
}

/// A listed walk within its cap passes at the largest file the time budget
/// leaves it and is refused one byte larger; unlisted, that file passes.
#[test]
fn a_listed_walk_is_refused_when_its_file_leaves_too_little_time() {
    let transfer = load(&merged_chain(listed(), 16, 8));
    let walk = reject_walk_cost(&transfer, MAX_REJECT_WALK_COST);
    assert!(walk > 2 * 16 * 8, "{walk}");
    let costs = [
        opouts_dag_cost(&transfer),
        witness_check_cost(&transfer),
        bundle_id_cost(&transfer),
        walk,
    ];
    let left = MAX_RGB_LIB_NS - rgb_lib_ns(0, costs);
    let largest = usize::try_from(left / rgb_lib_ns(1, [0; 4])).unwrap();
    assert_bounded_for_rgb_lib(&transfer, largest, true).unwrap();
    let err = assert_bounded_for_rgb_lib(&transfer, largest + 1, true).unwrap_err();
    assert!(err.to_string().contains("rgb-lib time"), "{err}");
    assert_bounded_for_rgb_lib(&transfer, largest + 1, false).unwrap();
}

/// CI keeps every cap above the largest honest burn: 2810 mints, all
/// burned by one transition of a listed asset. Its costs leave the time
/// budget room for a file at the default size cap.
#[test]
fn the_burn_of_2810_mints_passes_every_cap() {
    let bytes = honest_burn(listed(), 2_810, 0);
    gate(&bytes, true).unwrap();
    let size_cap = crate::config::DEFAULT_MAX_CONSIGNMENT_BYTES;
    assert_bounded_for_rgb_lib(&load(&bytes), size_cap, true).unwrap();
}

/// A listed merge of 1400 lines after 23,900 transfers: 12.1 MB, its walk
/// at 66.98M, within the size cap and every other cap, took rgb-lib 20.1 s.
/// The time budget refuses it before rgb-lib; unlisted it passes.
#[test]
#[ignore = "builds a 12 MB history; run it in release on request"]
fn a_listed_merge_at_the_size_and_walk_caps_is_refused_before_rgb_lib() {
    let bytes = merged_chain(listed(), 1_400, 23_900);
    assert!(bytes.len() <= crate::config::DEFAULT_MAX_CONSIGNMENT_BYTES);
    let walk = reject_walk_cost(&load(&bytes), MAX_REJECT_WALK_COST);
    assert!(walk <= MAX_REJECT_WALK_COST, "{walk}");
    gate(&bytes, false).unwrap();
    assert_capped(&bytes, "rgb-lib time");
}

// ===== release-mode timings (ignored) =====

/// The sizes a timing runs, from `var` (comma separated) or `default`.
fn sizes(var: &str, default: &[u64]) -> Vec<u64> {
    std::env::var(var)
        .map(|v| v.split(',').map(|n| n.trim().parse().unwrap()).collect())
        .unwrap_or_else(|_| default.to_vec())
}

/// `a:b` pairs from `var` (comma separated) or `default`.
fn pairs(var: &str, default: &str) -> Vec<(u64, u64)> {
    let pairs = std::env::var(var).unwrap_or_else(|_| default.into());
    pairs
        .split(',')
        .map(|pair| {
            let (a, b) = pair.split_once(':').unwrap();
            (a.trim().parse().unwrap(), b.trim().parse().unwrap())
        })
        .collect()
}

fn reads_unrelated(_: &RejectListContract) -> Result<Decisions> {
    let unrelated = OpoutKey {
        op: [0x99; 32],
        ty: 4000,
        no: 0,
    };
    Ok(decisions(
        &[RejectListEntry {
            opout: unrelated,
            reject: true,
        }],
        1,
    ))
}

/// rgb-lib past our caps, with the witnesses of `chain` mined and an
/// unrelated list. Returns its error, if any, and its time.
fn time_rgb_lib(
    bytes: &[u8],
    chain: &BTreeMap<bitcoin::Txid, WitnessPos>,
) -> (Option<String>, Duration) {
    let transfer = load(bytes);
    let check = on_chain(chain);
    let witnesses = OnChainResolver::new(&transfer, ChainNet::BitcoinRegtest, &check);
    let anchors = BindingResolver::new(&transfer, &bind_all);
    let list = reject_list(&transfer.genesis)
        .unwrap()
        .map(|list| ListResolver::new(list, &reads_unrelated));
    let options = ValidationOptions {
        bitcoin_network: BitcoinNetwork::Regtest,
        offchain_txid: None,
    };
    let start = Instant::now();
    let result = with_scratch_file(bytes, |path| {
        validate_consignment_with_resolver(
            path.to_str().unwrap(),
            &witnesses,
            Some(&anchors),
            list.as_ref().map(|l| l as &dyn ResolveRejectList),
            None,
            &options,
        )
        .map_err(|e| crate::error::EnclaveError::CrossCheck(e.to_string()))
    });
    (result.err().map(|e| e.to_string()), start.elapsed())
}

/// A forged shape with nothing mined reached phase 2: phase 1 ran in full.
fn assert_reached_the_witnesses(err: Option<String>) {
    let err = err.expect("nothing is mined");
    assert!(err.contains("not confirmed on chain"), "{err}");
}

/// Our checks before rgb-lib, as production runs them: the parse and the
/// gate. Returns the costs (dag, witness, bundle ids, walk), whether the gate
/// passed, its time, then the walk's alone.
fn time_pre_checks(bytes: &[u8]) -> ([u64; 4], bool, Duration, Duration) {
    let start = Instant::now();
    let transfer = load(bytes);
    let listed = reject_list(&transfer.genesis).unwrap().is_some();
    let passed = assert_bounded_for_rgb_lib(&transfer, bytes.len(), listed).is_ok();
    let pre = start.elapsed();
    let walk_start = Instant::now();
    let walk = reject_walk_cost(&transfer, MAX_REJECT_WALK_COST);
    let walk_took = walk_start.elapsed();
    let costs = [
        opouts_dag_cost(&transfer),
        witness_check_cost(&transfer),
        bundle_id_cost(&transfer),
        if listed { walk } else { 0 },
    ];
    (costs, passed, pre, walk_took)
}

/// rgb-lib's own load of the file, before it validates anything.
fn time_file_load(bytes: &[u8]) -> Duration {
    let start = Instant::now();
    with_scratch_file(bytes, |path| {
        rgbstd::containers::UniversalFile::load_file(path)
            .map(drop)
            .map_err(|e| crate::error::EnclaveError::CrossCheck(e.to_string()))
    })
    .unwrap();
    start.elapsed()
}

/// One line of a timing: `name`, the file, our pre-checks and the modeled
/// rgb-lib time they hold to `MAX_RGB_LIB_NS`.
fn describe(name: &str, bytes: &[u8]) -> String {
    let (costs, passed, pre, walk_took) = time_pre_checks(bytes);
    let [dag, witness, ids, walk] = costs;
    format!(
        "{name}: {} bytes, dag {dag}, witness {witness}, ids {ids}, walk {walk}, model {} ms, \
         gate {}, pre-checks {} ms (walk {} ms), file load {} ms",
        bytes.len(),
        rgb_lib_ns(bytes.len(), costs) / 1_000_000,
        if passed { "passes" } else { "refuses" },
        pre.as_millis(),
        walk_took.as_millis(),
        time_file_load(bytes).as_millis()
    )
}

/// Forged burns of n rights (`DAG_N`, default 4096, 16384, 65535): rgb-lib
/// refuses each at its first witness, after phase 1 built the opouts DAG.
#[test]
#[ignore = "release-mode timing; run on request"]
fn measures_the_opouts_dag_of_forged_wide_burns() {
    for n in sizes("DAG_N", &[4_096, 16_384, 65_535]) {
        let bytes = rights_burn(issue(), u16::try_from(n).unwrap());
        time_forged(&format!("dag n={n}"), &bytes);
    }
}

/// Forged bundles of t one-right burns in a tx of d dummy inputs
/// (`WITNESS_TD`, `t:d`), or with a Tapret partner leaf of l bytes
/// (`TAPRET_TL`, `t:l`), and burns of n rights after d dummies (`SCAN_ND`).
#[test]
#[ignore = "release-mode timing; run on request"]
fn measures_the_witness_checks_of_forged_bundles() {
    let default = "64:49900,256:12480,1024:3110,256:0,512:0,1024:0,2048:0";
    for (t, d) in pairs("WITNESS_TD", default) {
        let bytes = many_burns(
            issue(),
            u16::try_from(t).unwrap(),
            u32::try_from(d).unwrap(),
        );
        time_forged(&format!("witness t={t} d={d}"), &bytes);
    }
    for (t, l) in pairs("TAPRET_TL", "64:2090000,256:523000,511:262000,511:0") {
        let (t, l) = (u16::try_from(t).unwrap(), usize::try_from(l).unwrap());
        time_forged(&format!("tapret t={t} leaf={l}"), &many_tapret_burns(t, l));
    }
    for (n, d) in pairs("SCAN_ND", "8192:16000") {
        let mut history = issue();
        let right = history.genesis_right(0, right_utxo());
        let (n, d) = (u16::try_from(n).unwrap(), u32::try_from(d).unwrap());
        burn_rights_of(&mut history, right, n, d);
        time_forged(&format!("scan n={n} d={d}"), &history.consignment());
    }
}

/// rgb-lib on a forged shape with nothing mined, which it refuses only in
/// phase 2.
fn time_forged(name: &str, bytes: &[u8]) {
    let (err, took) = time_rgb_lib(bytes, &BTreeMap::new());
    println!("{}, rgb-lib {} ms", describe(name, bytes), took.as_millis());
    assert_reached_the_witnesses(err);
}

/// A forged file near `MAX_CONSIGNMENT_BYTES` within the DAG cap: burns of
/// `FILL_K` rights each (default 700), as many as the cap allows.
#[test]
#[ignore = "release-mode timing; run on request"]
fn measures_a_forged_file_at_the_size_cap_within_the_dag_cap() {
    let k = sizes("FILL_K", &[700])[0];
    let pairs = MAX_OPOUTS_DAG_COST / rights_burn_cost(k);
    let outpoints: Vec<OutPoint> = (0..pairs).map(|i| gen::outpoint(0xA0, i as u32)).collect();
    let mut history = History::issue(Issue::new(EVM_CHAIN_ID, BRIDGE, outpoints.clone()));
    for (no, outpoint) in outpoints.iter().enumerate() {
        let right = history.genesis_right(u16::try_from(no).unwrap(), *outpoint);
        burn_rights_of(&mut history, right, u16::try_from(k).unwrap(), 0);
    }
    let bytes = history.consignment();
    assert!(opouts_dag_cost(&load(&bytes)) <= MAX_OPOUTS_DAG_COST);
    let size_cap = crate::config::DEFAULT_MAX_CONSIGNMENT_BYTES;
    time_forged(
        &format!("fill k={k} x {pairs} (size cap {size_cap})"),
        &bytes,
    );
}

/// Forged reject walks, every witness mined: fan-outs (`WALK_KL`), merges
/// of separate lines (`MERGE_KL`), both `k:l`, and wide transfers (`WIDE_K`).
#[test]
#[ignore = "release-mode timing; run on request"]
fn measures_the_reject_walk_of_forged_shapes() {
    for (k, l) in pairs("WALK_KL", "4096:1000,65535:500") {
        let (k, l) = (u16::try_from(k).unwrap(), usize::try_from(l).unwrap());
        report_walk(&format!("fan-out k={k} l={l}"), |h| fanned_chain(h, k, l));
    }
    for (k, l) in pairs("MERGE_KL", "4096:8180") {
        let (k, l) = (u16::try_from(k).unwrap(), usize::try_from(l).unwrap());
        report_walk(&format!("merge k={k} l={l}"), |h| merged_chain(h, k, l));
    }
    for k in sizes("WIDE_K", &[4_096, 5_790]) {
        let k = u16::try_from(k).unwrap();
        report_walk(&format!("wide k={k}"), |h| wide_transfer(h, k));
    }
}

/// Listed merges of k lines after l transfers near the size cap
/// (`BUDGET_KL`, `k:l`): the time budget refuses the first, which every other
/// cap lets through, and admits the second.
#[test]
#[ignore = "release-mode timing; run on request"]
fn measures_listed_merges_against_the_time_budget() {
    for (k, l) in pairs("BUDGET_KL", "1400:23900,600:23900") {
        let (k, l) = (u16::try_from(k).unwrap(), usize::try_from(l).unwrap());
        report_walk(&format!("budget merge k={k} l={l}"), |h| {
            merged_chain(h, k, l)
        });
    }
}

/// The same shape listed and unlisted: the difference is rgb-lib's walk.
fn report_walk(name: &str, shape: impl Fn(History) -> Vec<u8>) {
    let listed = shape(listed());
    let unlisted = shape(issue());
    let (err, with_list) = time_rgb_lib(&listed, &mined(&witness_ids(&listed)));
    assert_eq!(err, None, "{name}");
    let (err, without) = time_rgb_lib(&unlisted, &mined(&witness_ids(&unlisted)));
    assert_eq!(err, None, "{name}");
    println!(
        "{}, exact walk {}, rgb-lib listed {} ms, unlisted {} ms",
        describe(&format!("walk {name}"), &listed),
        walk_cost(&listed),
        with_list.as_millis(),
        without.as_millis()
    );
}

/// `n` mints, each from its own right of one propagate and moved on by
/// `transfers` transfers, then one burn of all their units in one transition.
fn honest_burn(mut history: History, n: u16, transfers: usize) -> Vec<u8> {
    let right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(right, n);
    let units: Vec<Utxo> = rights
        .into_iter()
        .map(|right| {
            let mut units = history.mint_owned(right, MINTED, 90);
            for _ in 0..transfers {
                units = history.transfer(units, MINTED);
            }
            units
        })
        .collect();
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
        .add_global_state("burnedAsset", rgbstd::Amount::from(MINTED * u64::from(n)))
        .unwrap()
        .add_global_state(
            "burnReason",
            rgbstd::stl::BurnReason::from(amplify::Bytes32::from_array(gen::burn_reason_for(
                PAYEE,
            ))),
        )
        .unwrap()
        .complete_transition()
        .unwrap();
    let inputs = units.iter().map(|unit| unit.outpoint).collect();
    history.commit_bundle(gen::bundle_of(vec![burn]), inputs, vec![gen::dust(4)]);
    history.consignment()
}

/// Honest burns over `MINTS` mints (default 1404, 2810), each line with
/// `HISTORY` transfers (default 0, 3), validate end to end, listed and not.
#[test]
#[ignore = "release-mode timing; run on request"]
fn times_honest_burns_over_many_mints() {
    for n in sizes("MINTS", &[1_404, 2_810]) {
        for h in sizes("HISTORY", &[0, 3]) {
            let n = u16::try_from(n).unwrap();
            for (kind, history) in [("unlisted", issue()), ("listed", listed())] {
                let bytes = honest_burn(history, n, usize::try_from(h).unwrap());
                let chain = mined(&witness_ids(&bytes));
                let (err, in_rgb_lib) = time_rgb_lib(&bytes, &chain);
                assert_eq!(err, None);
                let lists = ListAccess {
                    bind_asset: &any_asset,
                    read: Some(&reads_unrelated),
                };
                let start = Instant::now();
                let validated = validator()
                    .validate_consignment(&bytes, Some(&bind_all), &on_chain(&chain), &lists)
                    .unwrap();
                let end_to_end = start.elapsed();
                println!(
                    "{}, rgb-lib {} ms, validated in {} ms",
                    describe(&format!("honest {kind} mints={n} history={h}"), &bytes),
                    in_rgb_lib.as_millis(),
                    end_to_end.as_millis()
                );
                assert_eq!(validated.mint_locks.len(), usize::from(n));
            }
        }
    }
}
