//! Shared scaffolding for the parent integration tests: a scriptable mock
//! enclave speaking the length-prefixed wire protocol over TCP.

#![allow(dead_code)]

use std::io::Write;
use std::net::TcpListener;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

use utexo_bridge_parent::enclave_proto::{
    enclave_response, EnclaveRequest, EnclaveResponse, ErrorResponse,
};
use utexo_bridge_parent::framing;

/// What the mock enclave does with one request.
pub enum Reply {
    /// Answer with a well-formed response.
    Msg(Box<EnclaveResponse>),
    /// Write these raw bytes instead of a frame.
    Raw(Vec<u8>),
    /// Close the connection without answering.
    Hangup,
}

pub type Handler = Arc<dyn Fn(EnclaveRequest) -> Reply + Send + Sync>;

/// Start a mock enclave that answers every connection through `handler`.
/// Returns the TCP port and a receiver that yields every decoded request.
pub fn start_enclave(handler: Handler) -> (u16, Receiver<EnclaveRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let req: EnclaveRequest = match framing::read_message(&mut stream) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let _ = tx.send(req.clone());
            match handler(req) {
                Reply::Msg(resp) => {
                    let _ = framing::write_message(&mut stream, resp.as_ref());
                }
                Reply::Raw(bytes) => {
                    let _ = stream.write_all(&bytes);
                    let _ = stream.flush();
                }
                Reply::Hangup => drop(stream),
            }
        }
    });

    (port, rx)
}

/// Shorthand for a well-formed reply.
pub fn msg(resp: EnclaveResponse) -> Reply {
    Reply::Msg(Box::new(resp))
}

/// A mock enclave that always answers with the same response.
pub fn start_enclave_replying(resp: EnclaveResponse) -> (u16, Receiver<EnclaveRequest>) {
    start_enclave(Arc::new(move |_| Reply::Msg(Box::new(resp.clone()))))
}

pub fn error_response(code: u32, message: &str) -> EnclaveResponse {
    EnclaveResponse {
        response: Some(enclave_response::Response::Error(ErrorResponse {
            code,
            message: message.into(),
        })),
    }
}

pub fn response(r: enclave_response::Response) -> EnclaveResponse {
    EnclaveResponse { response: Some(r) }
}

/// A port with nothing listening on it (bound then released).
pub fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}
