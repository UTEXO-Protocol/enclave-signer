//! The burn signer binary as a validator child: the mode switch, the probe,
//! and a burn whose validation the enclave ends before the request deadline.
#![cfg(all(feature = "rgb-validation", rgb_to_evm))]

// The tests here use only the long burn of the shared fixture.
#[allow(dead_code)]
#[path = "support/bfa_burn.rs"]
mod burn_fixture;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use utexo_bridge_enclave::conn::RESPONSE_MARGIN;
use utexo_bridge_enclave::networks::rgb::validation::{
    probe_validator_child, ChildProgram, CHILD_ARG,
};
use utexo_bridge_enclave::proto::enclave_response::Response;

use burn_fixture::{exchange_until, Fixture, Route};

const ENCLAVE: &str = env!("CARGO_BIN_EXE_utexo-bridge-enclave");

/// Runs the enclave binary with `args`, no stdin and a network that the boot
/// refuses. Returns the exit code and the whole output.
fn run_enclave(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(ENCLAVE)
        .args(args)
        .env("BITCOIN_NETWORK", "not-a-network")
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    (output.status.code(), format!("{stdout}{stderr}"))
}

/// With its one argument the binary is a validator child. It runs no boot
/// step, so the network does not stop it: it ends for want of a start frame.
#[test]
fn the_mode_switch_runs_before_any_boot_step() {
    let (code, output) = run_enclave(&[CHILD_ARG]);
    // The exit code of a child with no start frame.
    assert_eq!(code, Some(3), "{output}");
    assert!(output.contains("no start frame"), "{output}");
    assert!(
        !output.contains("starting utexo-bridge-enclave"),
        "{output}"
    );
}

/// Any other arguments boot the enclave, which refuses the network.
#[test]
fn the_mode_needs_exactly_its_one_argument() {
    let (code, output) = run_enclave(&[CHILD_ARG, CHILD_ARG]);
    // A panic exits with 101, and aborts a release build.
    let panicked = cfg!(debug_assertions).then_some(101);
    assert_eq!(code, panicked, "{output}");
    assert!(output.contains("starting utexo-bridge-enclave"), "{output}");
    assert!(output.contains("'not-a-network' is not valid"), "{output}");
}

/// The enclave binary answers a probe. It confines itself on Linux only.
#[test]
fn the_enclave_binary_answers_the_probe() {
    let report = probe_validator_child(&ChildProgram::binary(ENCLAVE), Duration::from_secs(30))
        .expect("the probe child answers");
    assert_eq!(report.confined, cfg!(target_os = "linux"), "{report:?}");
    #[cfg(target_os = "linux")]
    assert!(report.vm_rss_bytes > 0, "{report:?}");
}

/// The time the validator child of the long burn gets before the enclave
/// ends it. Its validation takes several times as long.
const BUDGET: Duration = Duration::from_millis(300);

/// A burn whose validation outlasts its deadline is refused before that
/// deadline: the enclave ends its validator child, or starts none when the
/// steps before it spent the time. The enclave then signs the same burn with
/// the default deadline.
#[test]
fn a_burn_past_its_deadline_is_refused_before_it_and_the_enclave_signs_after() {
    let fixture = Fixture::after_transfers(Route::Direct, 2_000);
    let request = fixture.request(fixture.params.clone());
    let deadline = Instant::now() + RESPONSE_MARGIN + BUDGET;
    let response = exchange_until(&fixture.ctx, request, deadline);
    assert!(
        Instant::now() < deadline,
        "the reply came after its deadline"
    );
    let Some(Response::Error(error)) = response.response else {
        panic!("expected the deadline refusal: {response:?}");
    };
    // An ended child has its own wire code. With no time left to start one,
    // the refusal is an internal error.
    let ended = error.code == 10 && error.message.contains("the enclave ended its validator");
    let not_started = error.code == 1
        && error
            .message
            .contains("request deadline passed before RGB validation");
    assert!(ended || not_started, "{error:?}");
    fixture.control();
}
