//! Stub Electrum server for tests: newline-delimited JSON-RPC over plain TCP.
//!
//! It answers only the RGB resolver chain check: `blockchain.block.header`
//! at height 0 gives the genesis header of `network`, and
//! `blockchain.transaction.get` gives the "genesis block coinbase" error that
//! the check accepts. Other calls get an error. Fixtures carry their witness
//! txs, so validation needs nothing else.
//!
//! Std, `bitcoin` and `serde_json` only: integration tests include this file
//! with `#[path]`.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Starts the stub and returns its `tcp://` URL.
pub fn spawn(network: bitcoin::Network) -> String {
    spawn_counted(network).0
}

/// Starts the stub. Returns its `tcp://` URL and the count of connections.
/// The count goes up before the stub reads the connection.
pub fn spawn_counted(network: bitcoin::Network) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub electrum");
    let addr = listener.local_addr().unwrap();
    let header = bitcoin::consensus::encode::serialize_hex(
        &bitcoin::constants::genesis_block(network).header,
    );
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            counter.fetch_add(1, Ordering::SeqCst);
            let header = header.clone();
            std::thread::spawn(move || serve(stream, &header));
        }
    });
    (format!("tcp://{addr}"), hits)
}

fn serve(stream: TcpStream, header: &str) {
    let Ok(mut out) = stream.try_clone() else {
        return;
    };
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { return };
        let Ok(req) = serde_json::from_str::<serde_json::Value>(&line) else {
            return;
        };
        let id = req["id"].clone();
        let body = match (req["method"].as_str(), req["params"][0].as_u64()) {
            (Some("blockchain.block.header"), Some(0)) => serde_json::json!({ "result": header }),
            (Some("blockchain.transaction.get"), _) => serde_json::json!({ "error": {
                "code": 1,
                "message": "genesis block coinbase is not considered an ordinary transaction",
            }}),
            _ => serde_json::json!({ "error": { "code": -32601, "message": "not in the stub" } }),
        };
        let mut resp = serde_json::json!({ "jsonrpc": "2.0", "id": id });
        resp.as_object_mut()
            .unwrap()
            .extend(body.as_object().unwrap().clone());
        if writeln!(out, "{resp}").is_err() {
            return;
        }
    }
}
