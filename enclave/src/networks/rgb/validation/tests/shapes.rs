//! Large and forged consignment shapes, and what rgb-lib does with them.

use rgbstd::{Operation, Opout};

use super::*;
use crate::networks::rgb::bfa_schema;

#[cfg(all(rgb_to_evm, unix))]
fn load(bytes: &[u8]) -> rgbstd::containers::Transfer {
    rgbstd::containers::Transfer::load(std::io::Cursor::new(bytes)).unwrap()
}

/// A propagate of the genesis right to `n` rights, then a burn of all of
/// them in one transition: schema-valid, no mint.
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
        let right = Opout::new(rights, bfa_schema::OS_MINT, no);
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

/// An asset of `rights` genesis mint rights, right 0 on [`right_utxo`].
#[cfg(all(rgb_to_evm, unix))]
fn issue_of(rights: u32, listed: bool) -> History {
    let outpoints = (0..rights).map(|i| gen::outpoint(0xA0, i)).collect();
    History::issue(Issue {
        reject_list: listed.then(|| gen::evm_reject_list(EVM_CHAIN_ID, LIST)),
        ..Issue::new(EVM_CHAIN_ID, BRIDGE, outpoints)
    })
}

/// Validates `bytes` against a chain with no block. Returns the refusal and
/// how many headers rgb-lib asked for.
fn validate_unmined(bytes: &[u8]) -> (String, usize) {
    let chain = MinedBlocks::of(&[]);
    let source = Recording {
        chain: &chain,
        asked: RefCell::new(Vec::new()),
    };
    let result = validator().validate_consignment(bytes, Some(&bind_all), &source, &open_lists());
    (error_of(result), source.asked.into_inner().len())
}

/// rgb-consensus 0.11.2-rc.2 builds its DAG in linear time, so a burn of 8193
/// rights reaches the witness checks of rgb-lib.
#[test]
fn a_burn_of_8193_rights_reaches_the_witness_checks() {
    let (err, asked) = validate_unmined(&rights_burn(issue(), 8_193));
    assert!(err.contains("no header at height"), "{err}");
    assert!(asked > 0, "rgb-lib ran: {err}");
}

/// rgb-lib refuses the second copy of a transition in a bundle: the first
/// spent its inputs.
#[test]
fn a_bundle_that_repeats_a_transition_is_refused_by_rgb_lib() {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let (rights, at) = propagate_rights(&mut history, right, 1);
    let burn = history
        .transition("burn")
        .add_input(
            Opout::new(rights, bfa_schema::OS_MINT, 0),
            AllocatedState::Void,
        )
        .unwrap()
        .complete_transition()
        .unwrap();
    let bundle = gen::bundle_of(vec![burn.clone(), burn]);
    assert_eq!(bundle.known_transitions.len(), 2);
    history.commit_bundle(bundle, vec![at], vec![gen::dust(4)]);
    let err = error_of(validate(&history.consignment()));
    assert!(err.contains("references previous state"), "{err}");
}

/// The records of a verdict on the burn of 2810 mints take fewer bytes than
/// its file: a witness txid and a witness block for each bundle and a lock
/// for each mint. So the verdict fits the frame the enclave reads from its
/// validator child.
#[cfg(all(rgb_to_evm, unix))]
#[test]
fn the_verdict_records_of_the_burn_of_2810_mints_fit_in_its_file() {
    use super::super::ipc::{
        LOCK_RECORD_BYTES, WITNESS_BLOCK_RECORD_BYTES, WITNESS_TXID_RECORD_BYTES,
    };
    let bytes = honest_burn(issue_of(10, true), 2_810, 0);
    let bundles = load(&bytes).bundles.len();
    let witness = WITNESS_TXID_RECORD_BYTES + WITNESS_BLOCK_RECORD_BYTES;
    let records = bundles * witness + 2_810 * LOCK_RECORD_BYTES;
    println!(
        "{bundles} bundles: {records} record bytes, {} file bytes",
        bytes.len()
    );
    assert!(records <= bytes.len(), "{records}");
}

/// `n` mints, each from its own right of one propagate and moved on by
/// `transfers` transfers, then one burn of all their units in one transition.
#[cfg(all(rgb_to_evm, unix))]
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
