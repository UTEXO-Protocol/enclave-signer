use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
use utexo_bridge_enclave::proto::*;
use utexo_bridge_enclave::server::{self, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;

/// Start a test server on a random TCP port. Returns the port number.
/// The server runs in a background thread and handles connections until
/// the test process exits.
#[allow(dead_code)]
pub fn start_test_server() -> u16 {
    start_test_server_with(|_| {})
}

/// Start a test server, running the provided configuration closure against
/// the fresh `EnclaveState` before the listener accepts connections. Used
/// by the cloning integration test to seed the donor with a known seed
/// and a cloning secret before the first client request arrives.
pub fn start_test_server_with(configure: impl FnOnce(&EnclaveState)) -> u16 {
    start_test_server_with_config(configure, BridgeConfig::from_env())
}

/// Start a test server with an explicit `BridgeConfig`. Use this from
/// tests that need to exercise the pinned cross-check path (mismatch
/// rejection, bundle commitment). `start_test_server` / `_with` read from
/// env, which is the empty default in CI — pass a constructed config here
/// to inject one without env mutation (env mutation across parallel tests
/// is a footgun).
#[allow(dead_code)]
pub fn start_test_server_with_config(
    configure: impl FnOnce(&EnclaveState),
    bridge_config: BridgeConfig,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    configure(&state);
    // Tests run with the placeholder Regtest checkpoint. The header chain
    // is initialised but empty; tests that don't push headers leave it
    // alone, tests that do start from `checkpoint.height` (= 0).
    let header_chain = std::sync::Mutex::new(HeaderChain::new(
        Network::Regtest,
        checkpoint_for(Network::Regtest),
    ));
    let ctx = Arc::new(ServerContext {
        state,
        bridge_config,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: None,
        header_chain,
        submit_rate_limiter: std::sync::Mutex::new(server::SubmitRateLimiter::default()),
    });

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => server::handle_connection(stream, &ctx),
                Err(e) => eprintln!("test server accept error: {}", e),
            }
        }
    });

    port
}

/// Send a request to a test server and return the response.
/// Opens a new TCP connection (one connection per request, matching
/// the real vsock protocol).
pub fn send_request(port: u16, req: &EnclaveRequest) -> EnclaveResponse {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    framing::write_message(&mut stream, req).unwrap();
    framing::read_message(&mut stream).unwrap()
}
