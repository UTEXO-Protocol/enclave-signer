use super::*;
use crate::config::BridgeConfig;
use crate::networks::rgb::validation::{OpoutKey, RejectListEntry};
use crate::state::EnclaveState;
use crate::test_support::{far_deadline, CallLog, ListEvm};

const CHAIN: u64 = 42161;
const LIST: RejectListContract = RejectListContract {
    chain_id: CHAIN,
    address: [0x4e; 20],
};

fn opout(no: u16) -> OpoutKey {
    OpoutKey {
        op: [0xab; 32],
        ty: 4000,
        no,
    }
}

fn context(rpc: Option<ListEvm>) -> ServerContext {
    let cfg = BridgeConfig {
        chain_id: CHAIN,
        ..BridgeConfig::default()
    };
    let mut ctx = ServerContext::new(
        EnclaveState::default(),
        cfg,
        crate::test_support::regtest_header_chain(),
    );
    ctx.launch.get_mut().unwrap().evm_rpc_client = rpc.map(|rpc| {
        Box::new(rpc) as Box<dyn crate::networks::evm::events::EvmReceiptProvider + Send + Sync>
    });
    ctx
}

/// The entries cross as the contract holds them, with the finalized count:
/// rgb-lib decides from them.
#[test]
fn reads_the_entries_through_the_pinned_client() {
    let entries = vec![
        RejectListEntry {
            opout: opout(0),
            reject: true,
        },
        RejectListEntry {
            opout: opout(1),
            reject: false,
        },
    ];
    let mut rpc = ListEvm::new(CHAIN, entries.clone());
    rpc.finalized_len = Some(1);
    let got = read_entries(&context(Some(rpc)), &LIST, far_deadline()).unwrap();
    assert_eq!(got.entries, entries);
    assert_eq!(got.finalized, 1);
}

#[test]
fn list_on_another_chain_is_refused() {
    let rpc = ListEvm::new(CHAIN, vec![]);
    let calls: CallLog = rpc.calls.clone();
    let other = RejectListContract {
        chain_id: 1,
        ..LIST
    };
    let err = read_entries(&context(Some(rpc)), &other, far_deadline())
        .unwrap_err()
        .to_string();
    assert!(err.contains("reads only EVM_CHAIN_ID 42161"), "{err}");
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn a_missing_rpc_client_is_refused() {
    let err = read_entries(&context(None), &LIST, far_deadline())
        .unwrap_err()
        .to_string();
    assert!(err.contains("EVM RPC client is unavailable"), "{err}");
}

#[test]
fn a_node_on_another_chain_is_refused() {
    let rpc = ListEvm::new(1, vec![]);
    let calls: CallLog = rpc.calls.clone();
    let err = read_entries(&context(Some(rpc)), &LIST, far_deadline())
        .unwrap_err()
        .to_string();
    assert!(err.contains("reports chain id 1"), "{err}");
    assert!(calls.lock().unwrap().is_empty());
}
