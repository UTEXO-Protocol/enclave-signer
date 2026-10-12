#![cfg(not(feature = "vsock"))]

use std::{net::TcpListener, process::Command, time::Duration};

use utexo_bridge_enclave::proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, SetEndpointsResponse,
};
use utexo_bridge_parent::framing::{read_message, write_message};

#[test]
fn cli_sends_path_file_over_the_wire_without_printing_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let directory = std::env::temp_dir().join(format!("rpc-path-cli-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let file = directory.join("path");
    let secret = "/v3/wire-fixture-secret";
    std::fs::write(&file, format!("{secret}\n")).unwrap();

    let receiver = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "CLI did not connect");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request: EnclaveRequest = read_message(&mut stream).unwrap();
        let Some(enclave_request::Request::SetEndpoints(endpoints)) = request.request else {
            panic!("expected SetEndpoints");
        };
        assert_eq!(endpoints.evm_rpc_path, secret);
        write_message(
            &mut stream,
            &EnclaveResponse {
                response: Some(enclave_response::Response::SetEndpoints(
                    SetEndpointsResponse {},
                )),
            },
        )
        .unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_utexo-bridge-parent-cli"))
        .args(["--addr", &address, "set-endpoints"])
        .env("EVM_RPC_PATH_FILE", &file)
        .env("RUST_LOG", "trace")
        .output()
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    receiver.join().unwrap();
    assert!(output.status.success());
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains("wire-fixture-secret"));
    }
    assert!(String::from_utf8_lossy(&output.stdout).contains("Endpoints set"));
}
