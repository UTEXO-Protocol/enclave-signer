//! CPU timings of the shapes in `docs/validation-cost-model.md`.
//! Fixture construction, the enclave's parse and its gate stay outside the
//! rgb-lib timers. Witness and reject-list resolvers use in-memory fixtures.

use super::*;
use rgb_lib::no_wallet::{inspect_consignment, BundleFilter};

/// Print one record per shape. A slow machine must still report every shape;
/// the maintainer compares the measured sum with the model after the run.
fn measure(name: &str, bytes: Vec<u8>, confirmed: bool, expected_gate: bool) {
    let transfer = load(&bytes);
    let listed = reject_list(&transfer.genesis).unwrap().is_some();
    let costs = [
        witness_check_cost(&transfer),
        bundle_id_cost(&transfer),
        if listed { walk_cost(&bytes) } else { 0 },
    ];
    let uncapped = uncapped_costs(&transfer);
    let model_validation = validation_ns(bytes.len(), uncapped, costs);
    let model_inspection = inspection_ns(bytes.len(), uncapped, costs);
    let gate_passes = gate(&bytes, listed).is_ok();
    assert_eq!(gate_passes, expected_gate, "{name}");
    let chain = if confirmed {
        mined(&witness_ids(&bytes))
    } else {
        BTreeMap::new()
    };
    let (err, validation) = time_rgb_lib(&bytes, &chain);
    if confirmed {
        assert_eq!(err, None, "{name}");
    } else {
        assert_reached_the_witnesses(err);
    }
    // Refused shapes are deliberately inspected too, to measure the work the
    // production gate prevents. Production inspects only after validation.
    let start = Instant::now();
    with_scratch_file(&bytes, |path| {
        inspect_consignment(path.to_str().unwrap().to_owned(), BundleFilter::All)
            .map(drop)
            .map_err(|e| crate::error::EnclaveError::CrossCheck(e.to_string()))
    })
    .unwrap();
    let inspection = start.elapsed();
    println!(
        "RGB_COST {}",
        serde_json::json!({
            "shape": name,
            "bytes": bytes.len(),
            "opouts": uncapped[0],
            "genesis_leaves": uncapped[1],
            "operations": uncapped[2],
            "witness_steps": costs[0],
            "bundle_id_steps": costs[1],
            "walk_steps": costs[2],
            "gate_passes": gate_passes,
            "model_validation_ns": model_validation,
            "model_inspection_ns": model_inspection,
            "model_total_ns": model_validation + model_inspection,
            "validation_ns": validation.as_nanos(),
            "inspection_ns": inspection.as_nanos(),
            "total_ns": (validation + inspection).as_nanos(),
        })
    );
}

#[test]
#[ignore = "release-mode timing of the documented shapes; run on the target CPU"]
fn measures_documented_consignment_shapes() {
    for (rights, history) in [(10, 0), (10, 3), (255, 0)] {
        measure(
            &format!("honest_2810_genesis_{rights}_history_{history}"),
            honest_burn(issue_of(rights, true), 2_810, history),
            true,
            true,
        );
    }
    for rights in [1, 255] {
        measure(
            &format!("chain_2000_genesis_{rights}"),
            propagate_chain(issue_of(rights, false), 1, 2_000),
            false,
            true,
        );
    }
    measure(
        "fanout_65535",
        fanned_chain(issue_of(1, false), u16::MAX, 0),
        true,
        true,
    );
    measure(
        "burn_65535_rights",
        rights_burn(issue_of(1, false), u16::MAX),
        false,
        true,
    );
    measure(
        "chain_13_propagates_65535_rights",
        propagate_chain(issue_of(1, false), u16::MAX, 13),
        false,
        false,
    );
    for (burns, dummies, accepted) in [(64, 49_900, true), (512, 0, false), (2048, 0, false)] {
        measure(
            &format!("bundle_{burns}_burns_{dummies}_dummy_inputs"),
            many_burns(issue_of(1, false), burns, dummies),
            false,
            accepted,
        );
    }
    measure(
        "listed_fanout_65535_after_500_transfers",
        fanned_chain(issue_of(1, true), u16::MAX, 500),
        true,
        true,
    );
}
