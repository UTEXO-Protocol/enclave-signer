use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::framing;
#[cfg(feature = "spv")]
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
use utexo_bridge_enclave::policy::{BuildContext, EvmDataSource, SecurityPolicy};
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

/// Start a test server with an explicit `BridgeConfig`, for tests exercising
/// the pinned cross-check path. `start_test_server` / `_with` read env, which
/// is empty in CI, and mutating env across parallel tests is unsafe.
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
    // alone, tests that do start from `checkpoint.height` (= 0). SPV-only.
    #[cfg(feature = "spv")]
    let header_chain = std::sync::Mutex::new(HeaderChain::new(
        Network::Regtest,
        checkpoint_for(Network::Regtest),
    ));
    let policy = SecurityPolicy::resolve(
        &BuildContext::current(),
        &bridge_config,
        EvmDataSource::Disabled,
        None,
    );
    let ctx = Arc::new(ServerContext {
        state,
        bridge_config,
        policy,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: None,
        #[cfg(feature = "evm-rpc")]
        evm_rpc_client: None,
        #[cfg(feature = "evm-rpc")]
        evm_rpc_config: utexo_bridge_enclave::config::EvmRpcConfig::default(),
        #[cfg(feature = "spv")]
        header_chain,
        #[cfg(feature = "spv")]
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

/// Build `count` synthetic regtest headers chained from `prev_hash`, the first
/// carrying `prev_time + 1`. The test server runs `Network::Regtest`, where
/// header validation is chain-linkage only, so no real PoW has to be satisfied
/// and timestamps are free to choose.
#[cfg(feature = "spv")]
#[allow(dead_code)]
pub fn synth_chain_from(prev_hash: [u8; 32], prev_time: u32, count: u32) -> Vec<Vec<u8>> {
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;

    let mut prev = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(prev_hash),
    );
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: prev_time + 1 + i,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: i,
        };
        out.push(serialize(&header));
        prev = header.block_hash();
    }
    out
}

/// Push a header batch and return the raw response, so callers can assert on
/// either the success or the error shape.
#[cfg(feature = "spv")]
#[allow(dead_code)]
pub fn submit_headers(port: u16, start_height: u32, headers: Vec<Vec<u8>>) -> EnclaveResponse {
    send_request(
        port,
        &EnclaveRequest {
            request: Some(enclave_request::Request::SubmitHeaders(
                SubmitHeadersRequest {
                    headers,
                    start_height,
                },
            )),
        },
    )
}
