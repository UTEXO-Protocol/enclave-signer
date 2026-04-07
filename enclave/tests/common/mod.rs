use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::keys::EnclaveState;
use utexo_bridge_enclave::proto::*;
use utexo_bridge_enclave::server::{self, ServerContext};

/// Start a test server on a random TCP port. Returns the port number.
/// The server runs in a background thread and handles connections until
/// the test process exits.
pub fn start_test_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let ctx = Arc::new(ServerContext {
        state: EnclaveState::new(bitcoin::Network::Bitcoin),
        #[cfg(feature = "rgb-validation")]
        rgb_validator: None,
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
