use super::*;
use crate::memory::{MIN_ENCLAVE_MEMORY_BYTES, RUN_ENCLAVE_MEMORY_MIB};

fn changes(edit: impl FnOnce(&mut Limits)) -> Limits {
    let mut limits = Limits::NONE;
    edit(&mut limits);
    limits
}

fn accept(_: &Limits) -> Result<(), String> {
    Ok(())
}

fn apply_to_defaults(edit: impl FnOnce(&mut Limits)) -> Result<Limits, String> {
    apply(&BridgeConfig::default(), &changes(edit), false, accept)
}

/// The image values must pass the rules that a change must pass, and they
/// must equal the constants that the memory model uses.
#[test]
fn the_image_values_pass_the_checks_and_match_the_memory_model() {
    Limits::DEFAULTS.check().unwrap();
    Limits::image(&BridgeConfig::default()).check().unwrap();
    assert_eq!(
        Limits::DEFAULTS.request_bound_bytes() as usize,
        crate::memory::request_bound(MAX_MESSAGE_SIZE as usize)
    );
    let needed = crate::memory::BASELINE_BYTES as u64
        + crate::conn::WORKER_THREADS as u64 * Limits::DEFAULTS.request_bound_bytes();
    assert_eq!(needed as usize, MIN_ENCLAVE_MEMORY_BYTES);
    assert!(needed <= RUN_ENCLAVE_MEMORY_MIB as u64 * MIB);
}

#[test]
fn a_change_holds_until_a_reset_and_keeps_the_other_values() {
    let cfg = BridgeConfig::default();
    let limits = apply_to_defaults(|l| l.evm_rpc_timeout_secs = 20).unwrap();
    assert_eq!(limits.evm_rpc_timeout_secs, 20);
    assert_eq!(get().evm_rpc_timeout_secs, 20);
    assert_eq!(get().max_psbt_bytes, Limits::DEFAULTS.max_psbt_bytes);

    apply_to_defaults(|l| l.max_psbt_bytes = 2 * MIB).unwrap();
    assert_eq!(
        get().evm_rpc_timeout_secs,
        20,
        "a second change keeps the first"
    );

    let limits = apply(&cfg, &Limits::NONE, true, accept).unwrap();
    assert_eq!(limits, Limits::image(&cfg));
    assert_eq!(get(), Limits::DEFAULTS);
}

#[test]
fn a_reset_with_values_keeps_only_those_values() {
    apply_to_defaults(|l| l.evm_rpc_timeout_secs = 20).unwrap();
    let limits = apply(
        &BridgeConfig::default(),
        &changes(|l| l.max_psbt_bytes = 2 * MIB),
        true,
        accept,
    )
    .unwrap();
    assert_eq!(
        limits.evm_rpc_timeout_secs,
        Limits::DEFAULTS.evm_rpc_timeout_secs
    );
    assert_eq!(limits.max_psbt_bytes, 2 * MIB);
}

/// The values in force of another process replace each value here, the
/// changes made here included. They hold as they are, also where the checks
/// of a change would refuse them: `MAX_CONSIGNMENT_BYTES` can set a value
/// below the range of a change.
#[test]
fn adopted_values_are_the_values_in_force() {
    apply_to_defaults(|l| l.max_psbt_bytes = 2 * MIB).unwrap();
    let theirs = Limits {
        evm_rpc_timeout_secs: 20,
        max_gas_tx_bytes: 2 * MIB,
        ..Limits::DEFAULTS
    };
    adopt(&theirs);
    assert_eq!(get(), theirs);
    let lowered = Limits {
        max_consignment_bytes: 512,
        ..theirs
    };
    assert!(lowered.check().is_err());
    adopt(&lowered);
    assert_eq!(get(), lowered);
    assert_eq!(in_force(&BridgeConfig::default()), lowered);
}

#[test]
fn a_refused_change_changes_nothing() {
    apply_to_defaults(|l| l.evm_rpc_timeout_secs = 20).unwrap();
    let err = apply_to_defaults(|l| {
        l.max_psbt_bytes = 2 * MIB;
        l.total_request_timeout_secs = 1;
    })
    .unwrap_err();
    assert!(err.contains("total_request_timeout_secs is 1"), "{err}");
    assert_eq!(get().evm_rpc_timeout_secs, 20);
    assert_eq!(get().max_psbt_bytes, Limits::DEFAULTS.max_psbt_bytes);
}

#[test]
fn the_memory_check_of_the_caller_can_refuse_a_change() {
    let err = apply(
        &BridgeConfig::default(),
        &changes(|l| l.max_message_bytes = 48 * MIB),
        false,
        |_| Err("no memory".into()),
    )
    .unwrap_err();
    assert_eq!(err, "no memory");
    assert_eq!(get(), Limits::DEFAULTS);
}

/// Sets the per-call timeout `name`. The test names each field itself, so
/// a timeout that `per_call_timeouts` leaves out fails the test.
fn set_timeout(limits: &mut Limits, name: &str, secs: u64) {
    let field = match name {
        "io_idle_timeout_secs" => &mut limits.io_idle_timeout_secs,
        "first_bytes_timeout_secs" => &mut limits.first_bytes_timeout_secs,
        "evm_rpc_timeout_secs" => &mut limits.evm_rpc_timeout_secs,
        _ => panic!("{name} is not a per-call timeout"),
    };
    *field = secs;
}

/// One stalled call must not outlast the request deadline: a timeout at
/// the deadline passes, and one second more is refused. A later deadline
/// lets it pass.
#[test]
fn each_per_call_timeout_must_fit_the_request_deadline() {
    let cfg = BridgeConfig::default();
    let deadline = Limits::DEFAULTS.total_request_timeout_secs;
    for name in [
        "io_idle_timeout_secs",
        "first_bytes_timeout_secs",
        "evm_rpc_timeout_secs",
    ] {
        apply_to_defaults(|l| set_timeout(l, name, deadline)).unwrap();
        let err = apply_to_defaults(|l| set_timeout(l, name, deadline + 1)).unwrap_err();
        assert!(
            err.contains(&format!(
                "{name} is {}; it must be at most total_request_timeout_secs, {deadline}",
                deadline + 1
            )),
            "{err}"
        );
        let kept = Limits::DEFAULTS.with(&changes(|l| set_timeout(l, name, deadline)));
        assert_eq!(get(), kept, "a refused change keeps the values");
        apply_to_defaults(|l| {
            set_timeout(l, name, deadline + 1);
            l.total_request_timeout_secs = deadline + 1;
        })
        .unwrap();
        apply(&cfg, &Limits::NONE, true, accept).unwrap();
    }
}

/// The image timeouts also hold the deadline up: below the image value of
/// `evm_rpc_timeout_secs`, a shorter deadline needs a shorter timeout.
#[test]
fn a_shorter_deadline_needs_shorter_per_call_timeouts() {
    let evm_rpc = Limits::DEFAULTS.evm_rpc_timeout_secs;
    apply_to_defaults(|l| l.total_request_timeout_secs = evm_rpc).unwrap();
    let err = apply_to_defaults(|l| l.total_request_timeout_secs = evm_rpc - 1).unwrap_err();
    assert!(
        err.contains(&format!("evm_rpc_timeout_secs is {evm_rpc}")),
        "{err}"
    );
    apply_to_defaults(|l| {
        l.total_request_timeout_secs = evm_rpc - 1;
        l.evm_rpc_timeout_secs = evm_rpc - 1;
    })
    .unwrap();
}

/// A larger consignment or PSBT needs a larger frame budget. The memory
/// model holds at each size that passes. A lower frame limit needs nothing.
#[test]
fn the_size_limits_must_fit_the_heap_of_a_frame() {
    let err = apply_to_defaults(|l| l.max_consignment_bytes = 11 * MIB).unwrap_err();
    assert!(err.contains("max_consignment_bytes"), "{err}");
    let err = apply_to_defaults(|l| l.max_psbt_bytes = 3 * MIB).unwrap_err();
    assert!(err.contains("max_psbt_bytes"), "{err}");
    apply_to_defaults(|l| {
        l.max_consignment_bytes = 11 * MIB;
        l.max_message_bytes = 32 * MIB;
    })
    .unwrap();
    apply_to_defaults(|l| {
        l.max_consignment_bytes = Limits::DEFAULTS.max_consignment_bytes;
        l.max_message_bytes = MIB;
    })
    .unwrap();
}

/// A burn holds the list beside the rest of the request. A longer list
/// takes a smaller consignment or a larger frame budget.
#[test]
fn a_long_reject_list_must_fit_the_heap_of_a_frame() {
    apply_to_defaults(|l| l.max_reject_list_entries = 30_000).unwrap();
    let err = apply_to_defaults(|l| l.max_reject_list_entries = 40_000).unwrap_err();
    assert!(err.contains("max_reject_list_entries is 40000"), "{err}");
    apply_to_defaults(|l| {
        l.max_reject_list_entries = 100_000;
        l.max_consignment_bytes = 10_000_000;
    })
    .unwrap();
}

/// An entry outlives the request that made it.
#[test]
fn the_mint_replay_window_must_outlive_a_request() {
    apply_to_defaults(|l| l.mint_replay_ttl_secs = 120).unwrap();
    apply_to_defaults(|l| l.total_request_timeout_secs = 119).unwrap();
    let err = apply_to_defaults(|l| l.total_request_timeout_secs = 120).unwrap_err();
    assert!(err.contains("mint_replay_ttl_secs is 120"), "{err}");
}

/// The highest values must reach the checks, and a check must refuse them
/// without an overflow.
#[test]
fn the_checks_refuse_the_highest_values_without_an_overflow() {
    let highest = Limits::HIGHEST;
    assert!(highest.check_ranges().is_ok());
    assert!(highest.request_bound_bytes() > 0);
    assert!(highest.check().is_err(), "the sizes are over the memory");
}

/// A `SetLimits` request is far below the lowest frame and element limits,
/// so the lowest values still let the operator reach the enclave and raise
/// them again. The lowest deadline takes per-call timeouts within it.
#[test]
fn the_lowest_values_keep_the_enclave_reachable() {
    let lowest = changes(|l| {
        l.max_message_bytes = MIB;
        l.max_wire_elements = 1_024;
        l.total_request_timeout_secs = 10;
        l.io_idle_timeout_secs = 2;
        l.first_bytes_timeout_secs = 1;
        l.evm_rpc_timeout_secs = 1;
        l.max_consignment_bytes = KIB;
        l.max_psbt_bytes = KIB;
    });
    apply(&BridgeConfig::default(), &lowest, false, accept).unwrap();
}

#[test]
fn the_config_values_are_the_start_values_of_the_request_limits() {
    let cfg = BridgeConfig {
        max_consignment_bytes: 1024,
        ..BridgeConfig::default()
    };
    assert_eq!(in_force(&cfg).max_consignment_bytes, 1024);
    apply(
        &cfg,
        &changes(|l| l.max_consignment_bytes = 2048),
        false,
        accept,
    )
    .unwrap();
    assert_eq!(in_force(&cfg).max_consignment_bytes, 2048);
}

#[test]
fn a_gas_transaction_bound_stops_at_its_image_ceiling() {
    // A caller on the parent can change a limit, so the ceiling is the bound that holds.
    let at_the_ceilings = apply_to_defaults(|l| {
        l.gas_tx_max_gas_limit = GAS_TX_GAS_LIMIT_CEILING;
        l.gas_tx_max_fee_per_gas = GAS_TX_FEE_PER_GAS_CEILING;
        l.gas_tx_max_value_wei = GAS_TX_VALUE_WEI_CEILING;
    })
    .expect("the ceilings themselves are accepted");
    assert_eq!(
        at_the_ceilings.gas_tx_max_gas_limit,
        GAS_TX_GAS_LIMIT_CEILING
    );

    let over_gas = apply_to_defaults(|l| l.gas_tx_max_gas_limit = GAS_TX_GAS_LIMIT_CEILING + 1);
    assert!(over_gas.unwrap_err().contains("gas_tx_max_gas_limit"));
    let over_fee = apply_to_defaults(|l| l.gas_tx_max_fee_per_gas = GAS_TX_FEE_PER_GAS_CEILING + 1);
    assert!(over_fee.unwrap_err().contains("gas_tx_max_fee_per_gas"));
    let over_value = apply_to_defaults(|l| l.gas_tx_max_value_wei = GAS_TX_VALUE_WEI_CEILING + 1);
    assert!(over_value.unwrap_err().contains("gas_tx_max_value_wei"));
}
