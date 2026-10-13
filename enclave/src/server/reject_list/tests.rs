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

#[test]
fn reads_decisions_through_the_pinned_client() {
    let mut rpc = ListEvm::new(
        CHAIN,
        vec![
            RejectListEntry {
                opout: opout(0),
                reject: true,
            },
            RejectListEntry {
                opout: opout(1),
                reject: false,
            },
        ],
    );
    rpc.finalized_len = Some(1);
    let got = read_decisions(&context(Some(rpc)), &LIST, far_deadline()).unwrap();
    assert_eq!(got.reject.into_iter().collect::<Vec<_>>(), vec![opout(0)]);
    // The allow is not finalized yet.
    assert!(got.allow.is_empty());
}

#[test]
fn list_on_another_chain_is_refused() {
    let rpc = ListEvm::new(CHAIN, vec![]);
    let calls: CallLog = rpc.calls.clone();
    let other = RejectListContract {
        chain_id: 1,
        ..LIST
    };
    let err = read_decisions(&context(Some(rpc)), &other, far_deadline())
        .unwrap_err()
        .to_string();
    assert!(err.contains("reads only EVM_CHAIN_ID 42161"), "{err}");
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn a_missing_rpc_client_is_refused() {
    let err = read_decisions(&context(None), &LIST, far_deadline())
        .unwrap_err()
        .to_string();
    assert!(err.contains("EVM RPC client is unavailable"), "{err}");
}

#[test]
fn a_node_on_another_chain_is_refused() {
    let rpc = ListEvm::new(1, vec![]);
    let calls: CallLog = rpc.calls.clone();
    let err = read_decisions(&context(Some(rpc)), &LIST, far_deadline())
        .unwrap_err()
        .to_string();
    assert!(err.contains("reports chain id 1"), "{err}");
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn an_rpc_failure_is_refused() {
    let mut rpc = ListEvm::new(CHAIN, vec![]);
    rpc.deployed = false;
    let err = read_decisions(&context(Some(rpc)), &LIST, far_deadline())
        .unwrap_err()
        .to_string();
    assert!(err.contains("no contract code"), "{err}");
}
