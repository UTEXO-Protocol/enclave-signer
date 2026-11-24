use std::io::Write;
use std::time::Duration;

use super::*;

/// The validator child of the lib tests: this test binary run with
/// [`TEST_ENTRY_ENV`], acting out the fault of [`FAULT_ENV`] if one is set. It
/// exits inside the test, so the binary prints no test result.
#[test]
fn validator_child_entry() {
    if std::env::var_os(TEST_ENTRY_ENV).is_none() {
        return;
    }
    let code = match std::env::var(FAULT_ENV).ok().as_deref() {
        None => serve(),
        Some(fault) => run_fault(fault),
    };
    std::process::exit(code);
}

/// Each allocation of the `grow` fault, written so that every page is used.
const GROW_STEP_BYTES: usize = 16 * 1024 * 1024;

/// Acts out `fault` in place of the child's job and returns the exit code.
fn run_fault(fault: &str) -> i32 {
    match fault {
        "panic" => {
            let _ = enter();
            panic!("the test validator panics");
        }
        "abort" => std::process::abort(),
        "exit" => 3,
        // Reports its pid as the contract id, then waits for its end.
        "hang" => {
            let mut io = start();
            ask(&mut io, bind_asset(&std::process::id().to_string()));
            hang()
        }
        // Reports its pid as the contract id, asks for its reject list, then
        // waits for its end.
        "list" => {
            let mut io = start();
            ask(&mut io, bind_asset(&std::process::id().to_string()));
            ask(
                &mut io,
                to_enclave::Body::RejectList(ipc::ListAddress {
                    chain_id: 42161,
                    address: Bytes::from_static(&[0x11; 20]),
                }),
            );
            hang()
        }
        "garbage" => {
            let mut io = channel().unwrap();
            io.write_all(&4u32.to_le_bytes()).unwrap();
            io.write_all(&[0xff; 4]).unwrap();
            hang()
        }
        "oversized" => {
            let mut io = channel().unwrap();
            io.write_all(&u32::MAX.to_le_bytes()).unwrap();
            hang()
        }
        "header-then-abort" => {
            let mut io = start();
            ask(&mut io, bind_asset("rgb:test-asset"));
            ask(&mut io, to_enclave::Body::Header(1));
            std::process::abort()
        }
        "env" => {
            let mut own = vec![TEST_ENTRY_ENV, FAULT_ENV, "RUST_LOG"];
            // CoreFoundation sets it in each macOS process that links it.
            if cfg!(target_os = "macos") {
                own.push("__CF_USER_TEXT_ENCODING");
            }
            let others: Vec<_> = std::env::vars_os()
                .map(|(key, _)| key)
                .filter(|key| !own.iter().any(|name| key == *name))
                .collect();
            if !others.is_empty() {
                eprintln!("the validator child has the variables {others:?}");
                return 3;
            }
            serve()
        }
        // Confines itself as `serve` does, then allocates until it is ended.
        "grow" => {
            let _ = enter();
            let _io = start();
            let mut held = Vec::new();
            loop {
                held.push(vec![1u8; GROW_STEP_BYTES]);
            }
        }
        // Beside 0, 1 and 2, only the descriptor of the listing itself.
        #[cfg(target_os = "linux")]
        "fds" => {
            let _ = enter();
            let open = std::fs::read_dir("/proc/self/fd").unwrap().count();
            if open > 4 {
                return 3;
            }
            serve()
        }
        // No core files, and the stack limit as soft and hard limit.
        #[cfg(target_os = "linux")]
        "limits" => {
            use nix::sys::resource::{getrlimit, Resource};
            let (_, hard) = getrlimit(Resource::RLIMIT_STACK).unwrap();
            let _ = enter();
            let stack = u64::try_from(crate::memory::VALIDATOR_STACK_BYTES)
                .unwrap()
                .min(hard);
            let core = getrlimit(Resource::RLIMIT_CORE).unwrap();
            if core != (0, 0) || getrlimit(Resource::RLIMIT_STACK).unwrap() != (stack, stack) {
                return 3;
            }
            serve()
        }
        other => panic!("no test fault {other}"),
    }
}

/// The child's socket, after the start frame.
fn start() -> UnixStream {
    let mut io = channel().unwrap();
    framing::read_message::<ipc::ToChild>(&mut io).unwrap();
    io
}

/// Sends `request` and reads the answer.
fn ask(io: &mut UnixStream, request: to_enclave::Body) {
    framing::write_message(
        io,
        &ipc::ToEnclave {
            body: Some(request),
        },
    )
    .unwrap();
    framing::read_message::<ipc::ToChild>(io).unwrap();
}

fn bind_asset(contract_id: &str) -> to_enclave::Body {
    to_enclave::Body::BindAsset(ipc::BindAsset {
        contract_id: Bytes::copy_from_slice(contract_id.as_bytes()),
    })
}

/// Waits until the enclave ends the child.
fn hang() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn build(debug_or_test: bool) -> BuildContext {
    BuildContext {
        debug_or_test,
        ..BuildContext::current()
    }
}

/// A start frame of a validation, with the limits in force.
fn validate_job() -> ipc::Start {
    ipc::Start {
        limits: Some((&crate::limits::get()).into()),
        job: Some(start::Job::Validate(ipc::Validate::default())),
    }
}

/// The kind and text of a refusal.
fn refusal_of(body: to_enclave::Body) -> (u32, String) {
    match body {
        to_enclave::Body::Verdict(ipc::Verdict {
            outcome: Some(ipc::verdict::Outcome::Refused(refusal)),
            ..
        }) => (
            refusal.kind,
            String::from_utf8(refusal.text.to_vec()).unwrap(),
        ),
        other => panic!("not a refusal: {other:?}"),
    }
}

/// A release child refuses a job when a confinement step failed. A debug
/// child goes on to the job, whose empty chain it refuses.
#[test]
fn a_release_child_refuses_a_job_it_could_not_confine() {
    let (io, _enclave) = UnixStream::pair().unwrap();
    let failed = || Err("no confinement".to_string());
    let refused = refusal_of(run_job(validate_job(), failed(), &build(false), &io));
    let confine = "the validator could not confine itself: no confinement";
    assert_eq!(refused, (ipc::REFUSAL_INTERNAL, confine.into()));
    for (confined, build) in [(failed(), build(true)), (Ok(()), build(false))] {
        let (kind, text) = refusal_of(run_job(validate_job(), confined, &build, &io));
        assert_eq!(kind, ipc::REFUSAL_INTERNAL);
        assert!(text.contains("unknown chain"), "{text}");
    }
}

/// A start frame needs its job and the limits in force: the child has no
/// default of its own for either.
#[test]
fn a_start_frame_without_its_job_or_limits_is_refused() {
    let (io, _enclave) = UnixStream::pair().unwrap();
    let no_job = ipc::Start {
        job: None,
        ..validate_job()
    };
    let refused = refusal_of(run_job(no_job, Ok(()), &build(false), &io));
    assert_eq!(
        refused,
        (ipc::REFUSAL_INTERNAL, "the start frame names no job".into())
    );
    let no_limits = ipc::Start {
        limits: None,
        ..validate_job()
    };
    let refused = refusal_of(run_job(no_limits, Ok(()), &build(false), &io));
    let text = "the start frame carries no limits";
    assert_eq!(refused, (ipc::REFUSAL_INTERNAL, text.into()));
}

/// The fields of `/proc/self/status` read in bytes.
#[cfg(target_os = "linux")]
#[test]
fn the_status_fields_of_this_process_read_in_bytes() {
    let rss = status_bytes("VmRSS").expect("a resident size");
    assert!(rss > 0 && rss.is_multiple_of(1024), "{rss}");
    assert!(status_bytes("VmHWM").unwrap() >= rss);
    assert_eq!(status_bytes("NoSuchField"), None);
}
