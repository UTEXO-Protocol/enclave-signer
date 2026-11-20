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

/// Acts out `fault` in place of the child's job and returns the exit code.
fn run_fault(fault: &str) -> i32 {
    match fault {
        "panic" => {
            abort_on_panic();
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
        // Beside 0, 1 and 2, only the descriptor of the listing itself.
        #[cfg(target_os = "linux")]
        "fds" => {
            let _ = confine();
            let open = std::fs::read_dir("/proc/self/fd").unwrap().count();
            if open > 4 {
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

/// A release child refuses a job when a confinement step failed. A debug
/// child goes on.
#[test]
fn a_release_child_refuses_a_job_it_could_not_confine() {
    let build = |debug_or_test| BuildContext {
        debug_or_test,
        ..BuildContext::current()
    };
    let failed = || Err("no confinement".to_string());
    let err = confinement_outcome(failed(), &build(false)).unwrap_err();
    assert_eq!(
        err,
        "the validator could not confine itself: no confinement"
    );
    assert_eq!(confinement_outcome(failed(), &build(true)), Ok(()));
    assert_eq!(confinement_outcome(Ok(()), &build(false)), Ok(()));
}

/// The fields of `/proc/self/status` read in bytes.
#[cfg(target_os = "linux")]
#[test]
fn the_status_fields_of_this_process_read_in_bytes() {
    let rss = status_bytes("VmRSS").expect("a resident size");
    assert!(rss > 0 && rss % 1024 == 0, "{rss}");
    assert!(status_bytes("VmHWM").unwrap() >= rss);
    assert_eq!(status_bytes("NoSuchField"), None);
}
