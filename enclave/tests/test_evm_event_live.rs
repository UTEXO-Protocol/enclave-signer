//! Live-chain check of the #60 FundsIn binding, against a real `BridgeFundsIn`
//! log rather than a synthetic one. The unit tests build their own logs, so a
//! wrong event signature or topic index would pass both sides of the mistake.
//!
//! Skipped unless `UTEXO_LIVE_EVM_RPC` is set — no CI runner has a chain. Run it
//! against the localnet after `make evm-fundsin`:
//!
//! ```sh
//! UTEXO_LIVE_EVM_RPC=http://localhost:8545 \
//! UTEXO_LIVE_BRIDGE=0x… UTEXO_LIVE_TX=0x… UTEXO_LIVE_OP_ID=42 \
//! UTEXO_LIVE_AMOUNT=1000000 UTEXO_LIVE_COMMISSION=0 UTEXO_LIVE_MIN_CONF=1 \
//!     cargo test -p utexo-bridge-enclave --features evm-rpc --test test_evm_event_live
//! ```
#![cfg(feature = "evm-rpc")]

use utexo_bridge_enclave::networks::evm::evm_event::{verify_funds_in_event, AlloyEvmClient};

struct Live {
    client: AlloyEvmClient,
    bridge: [u8; 20],
    tx: [u8; 32],
    op_id: u64,
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

/// `operationId` is a `uint256` on chain that the enclave binds as a `u64`.
/// Accept either a decimal or a `0x` literal so the value can be pasted
/// straight from a tx receipt.
fn op_id(var: &str) -> u64 {
    let v = std::env::var(var).unwrap_or_else(|_| panic!("{var} is required"));
    match v.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).expect("operationId hex must fit u64"),
        None => v.parse().expect("operationId must be a u64"),
    }
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
        op_id: op_id("UTEXO_LIVE_OP_ID"),
        amount: num("UTEXO_LIVE_AMOUNT", 0),
        commission: num("UTEXO_LIVE_COMMISSION", 0),
        min_conf: num("UTEXO_LIVE_MIN_CONF", 1),
    })
}

/// The real operationId decoded from the chain's own log data must bind.
#[test]
fn live_deposit_binds_operation_id() {
    let Some(l) = live() else { return };
    verify_funds_in_event(
        &l.client,
        &l.bridge,
        l.min_conf,
        &l.tx,
        l.op_id,
        l.amount,
        l.commission,
    )
    .expect("the real deposit must verify");
}

/// A different id must refuse — proves the comparison runs rather than the
/// decode merely succeeding.
#[test]
fn live_deposit_rejects_wrong_operation_id() {
    let Some(l) = live() else { return };
    let e = verify_funds_in_event(
        &l.client,
        &l.bridge,
        l.min_conf,
        &l.tx,
        l.op_id.wrapping_add(1),
        l.amount,
        l.commission,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("operationId mismatch"), "got: {e}");
}

/// The amount is bound off the same log, at a different word offset — a swapped
/// or mis-numbered offset would still bind the id but not this.
#[test]
fn live_deposit_rejects_wrong_amount() {
    let Some(l) = live() else { return };
    let e = verify_funds_in_event(
        &l.client,
        &l.bridge,
        l.min_conf,
        &l.tx,
        l.op_id,
        l.amount.wrapping_add(1),
        l.commission,
    )
    .unwrap_err()
    .to_string();
    assert!(
        e.contains("amount mismatch") || e.contains("netAmount mismatch"),
        "got: {e}"
    );
}
