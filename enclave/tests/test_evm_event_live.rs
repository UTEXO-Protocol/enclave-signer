//! Live-chain check of the #60 FundsIn binding against a real `BridgeFundsIn`
//! log. The unit tests build their own logs, so a wrong event signature or
//! topic index would pass on both sides.
//!
//! Skipped unless `UTEXO_LIVE_EVM_RPC` is set. Run against the localnet after
//! `make evm-fundsin`:
//!
//! ```sh
//! UTEXO_LIVE_EVM_RPC=http://localhost:8545 \
//! UTEXO_LIVE_BRIDGE=0x... UTEXO_LIVE_TX=0x... UTEXO_LIVE_OP_ID=0x<64 hex> \
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

/// `operationId` is a `bytes32` on chain (a keccak hash). Accept a `0x` literal
/// (or bare hex) and left-pad to 32 bytes so a short value pasted from a receipt
/// still binds.
fn op_id(var: &str) -> Vec<u8> {
    let v = std::env::var(var).unwrap_or_else(|_| panic!("{var} is required"));
    let raw = hex::decode(v.strip_prefix("0x").unwrap_or(&v)).expect("operationId hex");
    assert!(raw.len() <= 32, "operationId must be at most 32 bytes");
    let mut id = vec![0u8; 32 - raw.len()];
    id.extend_from_slice(&raw);
    id
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
        &l.op_id,
        l.amount,
        l.commission,
    )
    .expect("the real deposit must verify");
}

/// A different id must refuse - proves the comparison runs rather than the
/// decode merely succeeding.
#[test]
fn live_deposit_rejects_wrong_operation_id() {
    let Some(l) = live() else { return };
    // Flip the last byte so the id is a valid 32-byte value that differs.
    let mut wrong = l.op_id.clone();
    wrong[31] ^= 1;
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

/// The amount is bound off the same log, at a different word offset - a swapped
/// or mis-numbered offset would still bind the id but not this.
#[test]
fn live_deposit_rejects_wrong_amount() {
    let Some(l) = live() else { return };
    let e = verify_funds_in_event(
        &l.client,
        &l.bridge,
        l.min_conf,
        &l.tx,
        &l.op_id,
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
