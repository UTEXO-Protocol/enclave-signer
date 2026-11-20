//! The memory of one validator child, against the reserve the memory model
//! counts for it. The file has one test, so the largest child this process
//! reaps is the validator child of its burn.
#![cfg(all(feature = "rgb-validation", rgb_to_evm, target_os = "linux"))]

// The test uses only the smallest burn of the shared fixture.
#[allow(dead_code)]
#[path = "support/bfa_burn.rs"]
mod burn_fixture;

use nix::sys::resource::{getrusage, UsageWho};
use utexo_bridge_enclave::memory::VALIDATOR_BASELINE_BYTES;

use burn_fixture::{Fixture, Route};

/// The validator child of the smallest burn peaks within its baseline.
#[test]
fn a_small_burn_keeps_its_validator_child_within_the_baseline() {
    Fixture::new(Route::Direct).control();
    // Linux reports `ru_maxrss` in KiB.
    let kib = getrusage(UsageWho::RUSAGE_CHILDREN).unwrap().max_rss();
    let peak = u64::try_from(kib).unwrap() * 1024;
    println!(
        "validator child of the smallest burn: peak resident {} KiB, baseline {} KiB",
        peak / 1024,
        VALIDATOR_BASELINE_BYTES / 1024
    );
    assert!(peak > 0, "no reaped child");
    assert!(
        peak <= VALIDATOR_BASELINE_BYTES as u64,
        "the validator child peaked at {peak} bytes, over its baseline of \
         {VALIDATOR_BASELINE_BYTES} bytes"
    );
}
