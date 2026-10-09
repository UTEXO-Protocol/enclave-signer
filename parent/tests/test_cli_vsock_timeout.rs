//! The CLI stops when the vsock peer accepts and never replies.
#![cfg(all(feature = "vsock", target_os = "linux"))]
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use vsock::{VsockListener, VMADDR_CID_LOCAL};

const GUARD: Duration = Duration::from_secs(45);

#[test]
fn cli_clone_returns_error_when_vsock_peer_is_silent() {
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_LOCAL, u32::MAX).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_utexo-bridge-parent-cli"))
        .env_clear()
        .env("UTEXO_CLONING_SECRET", "secret")
        .args([
            "--addr",
            &format!("vsock://{VMADDR_CID_LOCAL}:{port}"),
            "clone",
            "--donor-grpc",
            "http://127.0.0.1:1",
            "--donor-evm",
            "0x0000000000000000000000000000000000000000",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Hold the accepted stream. Never read or write it.
    let mut peer = None;
    let status = loop {
        if peer.is_none() {
            if let Ok((s, _)) = listener.accept() {
                peer = Some(s);
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if start.elapsed() > GUARD {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let elapsed = start.elapsed();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let status = status.expect("CLI still blocked after 45 s");
    assert_eq!(status.code(), Some(1), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("Error before SetClone: io error:"),
        "{stderr}"
    );
    assert!(elapsed < GUARD, "{elapsed:?}");
}
