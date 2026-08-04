//! Live-chain check of the #60 FundsIn binding, against a real `BridgeFundsIn`
//! log rather than a synthetic one. The unit tests build their own logs, so a
//! wrong event signature or topic index would pass both sides of the mistake.
//!
//! Skipped unless `UTEXO_LIVE_EVM_RPC` is set — no CI runner has a chain. Run it
//! against the localnet after `make evm-fundsin`:
//!
//! ```sh
//! UTEXO_LIVE_EVM_RPC=http://localhost:8545 \
//! UTEXO_LIVE_BRIDGE=0x… UTEXO_LIVE_TX=0x… UTEXO_LIVE_OP_ID=0x… \
//! UTEXO_LIVE_AMOUNT=1000000 UTEXO_LIVE_COMMISSION=0 UTEXO_LIVE_MIN_CONF=1 \
//!     cargo test -p utexo-bridge-enclave --features evm-rpc --test test_evm_event_live
//! ```
#![cfg(feature = "evm-rpc")]

use utexo_bridge_enclave::networks::evm::evm_event::{verify_funds_in_event, AlloyEvmClient};

struct Live {
    client: AlloyEvmClient,
    bridge: [u8; 20],
    tx: [u8; 32],
    op_id: Vec<u8>,
    amount: u64,
    commission: u64,
    min_conf: u64,
}

fn bytes(var: &str) -> Vec<u8> {
    let v = std::env::var(var).unwrap_or_else(|_| panic!("{var} is required"));
    hex::decode(v.strip_prefix("0x").unwrap_or(&v)).expect("hex")
}

fn num(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// `None` when the live chain is not configured, so the suite is a no-op in CI.
fn live() -> Option<Live> {
    let url = std::env::var("UTEXO_LIVE_EVM_RPC").ok()?;
    Some(Live {
        client: AlloyEvmClient::new(&url).expect("build RPC client"),
        bridge: bytes("UTEXO_LIVE_BRIDGE")
            .try_into()
            .expect("20-byte bridge"),
        tx: bytes("UTEXO_LIVE_TX").try_into().expect("32-byte tx hash"),
        op_id: bytes("UTEXO_LIVE_OP_ID"),
        amount: num("UTEXO_LIVE_AMOUNT", 0),
        commission: num("UTEXO_LIVE_COMMISSION", 0),
        min_conf: num("UTEXO_LIVE_MIN_CONF", 1),
    })
}

/// The real operationId from the chain's own topic1 must bind.
#[test]
fn live_deposit_binds_operation_id() {
    let Some(l) = live() else { return };
    verify_funds_in_event(
        &l.client,
        &l.bridge,
        l.min_conf,
        &l.tx,
        &l.op_id,
        l.amount,
        l.commission,
    )
    .expect("the real deposit must verify");
}

/// Flipping one byte of the id must refuse — proves the comparison runs.
#[test]
fn live_deposit_rejects_wrong_operation_id() {
    let Some(l) = live() else { return };
    let mut wrong = l.op_id.clone();
    wrong[0] ^= 0xFF;
    let e = verify_funds_in_event(
        &l.client,
        &l.bridge,
        l.min_conf,
        &l.tx,
        &wrong,
        l.amount,
        l.commission,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("operationId mismatch"), "got: {e}");
}

/// An absent id must refuse rather than skip the comparison.
#[test]
fn live_deposit_rejects_absent_operation_id() {
    let Some(l) = live() else { return };
    let e = verify_funds_in_event(
        &l.client,
        &l.bridge,
        l.min_conf,
        &l.tx,
        &[],
        l.amount,
        l.commission,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("must be exactly 32 bytes"), "got: {e}");
}
