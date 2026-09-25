use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::framing;
#[cfg(feature = "rgb-validation")]
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
    let policy = SecurityPolicy::resolve(
        &BuildContext::current(),
        &bridge_config,
        EvmDataSource::Disabled,
        None,
        0,
    );
    start_test_server_with_policy(configure, bridge_config, policy)
}

/// Explicit policy for clone commitment tests. This only constructs a test
/// context; it does not bypass or test the production boot gate.
#[allow(dead_code)]
pub fn start_test_server_with_policy(
    configure: impl FnOnce(&EnclaveState),
    bridge_config: BridgeConfig,
    policy: SecurityPolicy,
) -> u16 {
    start_test_server_inner(
        configure,
        bridge_config,
        policy,
        #[cfg(feature = "evm-rpc")]
        None,
    )
}

/// Same, with an EVM receipt provider wired in. A bridge-mode PSBT is refused
/// up front unless the enclave can verify the FundsIn deposit itself, so any
/// test that wants to reach the RGB checks has to supply one.
#[cfg(feature = "evm-rpc")]
#[allow(dead_code)]
pub fn start_test_server_with_evm_rpc(
    client: Box<dyn utexo_bridge_enclave::networks::evm::events::EvmReceiptProvider + Send + Sync>,
) -> u16 {
    let bridge_config = BridgeConfig::from_env();
    let policy = SecurityPolicy::resolve(
        &BuildContext::current(),
        &bridge_config,
        EvmDataSource::Disabled,
        None,
        0,
    );
    start_test_server_inner(|_| {}, bridge_config, policy, Some(client))
}

fn start_test_server_inner(
    configure: impl FnOnce(&EnclaveState),
    bridge_config: BridgeConfig,
    policy: SecurityPolicy,
    #[cfg(feature = "evm-rpc")] evm_rpc_client: Option<
        Box<dyn utexo_bridge_enclave::networks::evm::events::EvmReceiptProvider + Send + Sync>,
    >,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    configure(&state);
    // Tests run with the placeholder Regtest checkpoint. The header chain
    // is initialised but empty; tests that don't push headers leave it
    // alone, tests that do start from `checkpoint.height` (= 0). SPV-only.
    #[cfg(feature = "rgb-validation")]
    let header_chain = std::sync::Mutex::new(HeaderChain::new(
        Network::Regtest,
        checkpoint_for(Network::Regtest),
    ));
    let ctx = Arc::new(ServerContext {
        state,
        bridge_config,
        policy,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: None,
        #[cfg(feature = "evm-rpc")]
        evm_rpc_client,
        #[cfg(feature = "evm-rpc")]
        evm_rpc_config: utexo_bridge_enclave::config::EvmRpcConfig::default(),
        #[cfg(feature = "rgb-validation")]
        header_chain,
        #[cfg(feature = "rgb-validation")]
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
#[cfg(feature = "rgb-validation")]
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
#[cfg(feature = "rgb-validation")]
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

/// A stand-in EVM RPC that reports one confirmed `BridgeFundsIn` deposit.
///
/// A bridge-mode PSBT is refused before any RGB work unless the enclave can
/// verify the deposit itself, so a test that wants to reach the RGB checks
/// needs this. The log carries the gross and commission the request declares,
/// so the deposit gate passes and the later checks are what reject.
#[cfg(feature = "evm-rpc")]
#[allow(dead_code)]
pub mod deposit_stub {
    use alloy_primitives::U256;
    use alloy_sol_types::{sol, SolEvent};
    use utexo_bridge_enclave::error::Result;
    use utexo_bridge_enclave::networks::evm::events::{EvmReceiptProvider, LogEntry, ReceiptData};

    sol! {
        event BridgeFundsIn(
            bytes32 indexed operationId, bytes32 indexed sourceSender, address indexed sender,
            uint256 senderNonce, uint256 amount, uint256 netAmount, uint256 tokenCommission,
            uint256 nativeCommission, uint256 sourceChainId, uint256 destinationChainId,
            string destinationAddress
        );
    }

    /// An invoice `parse_authorized_recipient` accepts, so the deposit gate
    /// gets past the recipient parse too.
    const INVOICE: &str = "rgb:fuhLYX9G-eC8gDvf-V0XpYFH-ceSafoc-lGutAYq-~SExGU4/\
                           XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                           UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP";

    /// Block 100 against head 112 is a depth of 12, the default minimum.
    const BLOCK: u64 = 100;
    const HEAD: u64 = 112;

    /// Answers for any tx hash: the tests that care about a malformed hash are
    /// rejected on length before the client is consulted.
    pub struct OneDeposit {
        pub operation_id: [u8; 32],
        pub gross: u64,
        pub commission: u64,
        /// Must equal `BridgeConfig::funds_in_contract`, else the log is not
        /// from the pinned emitter and the gate rejects it.
        pub emitter: [u8; 20],
    }

    impl EvmReceiptProvider for OneDeposit {
        fn get_transaction_receipt(&self, _tx_hash: &[u8; 32]) -> Result<Option<ReceiptData>> {
            let event = BridgeFundsIn {
                operationId: self.operation_id.into(),
                sourceSender: [0x5c; 32].into(),
                sender: [0xde; 20].into(),
                senderNonce: U256::ZERO,
                amount: U256::from(self.gross),
                netAmount: U256::from(self.gross - self.commission),
                tokenCommission: U256::from(self.commission),
                nativeCommission: U256::ZERO,
                sourceChainId: U256::ZERO,
                destinationChainId: U256::ZERO,
                destinationAddress: INVOICE.into(),
            };
            Ok(Some(ReceiptData {
                status_success: true,
                block_number: BLOCK,
                logs: vec![LogEntry {
                    address: self.emitter,
                    topics: event.encode_topics().into_iter().map(|t| t.0 .0).collect(),
                    data: event.encode_data(),
                }],
            }))
        }

        fn get_block_number(&self) -> Result<u64> {
            Ok(HEAD)
        }
    }
}
