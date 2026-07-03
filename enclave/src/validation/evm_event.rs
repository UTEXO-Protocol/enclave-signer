//! Independent in-enclave verification of the EVM `FundsIn` deposit event for
//! bridge-mode `signPsbt` (audit M-06 / issues #60, #51).
//!
//! Bridge-mode `signPsbt` releases RGB against an EVM deposit. Previously the
//! enclave trusted two listener-supplied booleans (`evm_event_valid` /
//! `evm_event_finalized`) that anyone reaching the enclave could set to `true`.
//! This module replaces that trust: the enclave fetches the deposit's
//! transaction receipt over an in-enclave EVM RPC and checks, itself, that a
//! `FundsIn` / `BridgeFundsIn` log was emitted by the pinned bridge contract
//! with the claimed `operationId` and amount, and at sufficient confirmation
//! depth. Every predicate is **fail-closed**.
//!
//! TRUST BOUNDARY: the RPC is reached through the loopback -> vsock forwarder,
//! i.e. responses are relayed by the UNTRUSTED host. A malicious host can
//! withhold a receipt (-> we fail closed, safe) but could in principle forge
//! one; this predicate becomes trustless only once Helios (#77) verifies the
//! RPC inside the TEE. This is the predicate + plumbing layer.
//!
//! WHAT THIS DOES NOT BIND: `operationId` is a backend-assigned `uint256` with
//! no on-chain cryptographic link to the RGB mint being signed, so confirming
//! the deposit does not by itself prove it corresponds to *this* RGB transfer;
//! that association stays listener-supplied (related to #66). And because the
//! proto carries `operation_idx`/`evm_amount` as `u64` while the chain uses
//! `uint256`, an on-chain value exceeding `u64` is rejected fail-closed (see
//! [`super::evm_crosscheck::extract_uint256_as_u64`]); full-width support needs
//! a `bytes operation_id` proto field + a listener change.

use sha3::{Digest, Keccak256};

use super::evm_crosscheck::extract_uint256_as_u64;
use crate::error::{EnclaveError, Result};

/// Canonical `BridgeFundsIn` signature (the richer event: carries gross amount,
/// net, and commission, so the enclave can verify all three independently).
/// Verbatim from `bridge-smart-contracts` `IBridge.sol`. `sender` is indexed
/// (-> topic1), so the non-indexed args below are what lands in log `data`.
const BRIDGE_FUNDS_IN_SIG: &str =
    "BridgeFundsIn(address,uint256,uint256,uint256,uint256,uint256,uint256,uint256,string)";

/// Canonical plain `FundsIn` signature (`BridgeBase.sol`). Weaker fallback:
/// its `amount` is the post-commission net, so the commission stays
/// listener-trusted when only this shape is present.
const FUNDS_IN_SIG: &str = "FundsIn(address,uint256,uint256)";

/// Byte offsets of the non-indexed `BridgeFundsIn` data words (each 32 bytes).
/// Order: operationId, amount(gross), netAmount, tokenCommission,
/// nativeCommission, sourceChainId, destinationChainId, <string offset>.
const BFI_OPERATION_ID_OFF: usize = 0;
const BFI_AMOUNT_OFF: usize = 32;
const BFI_NET_AMOUNT_OFF: usize = 64;
const BFI_TOKEN_COMMISSION_OFF: usize = 96;
/// 7 static words + 1 dynamic-string offset word must be present.
const BFI_MIN_DATA_LEN: usize = 8 * 32;

/// Byte offsets of the plain `FundsIn` data words: operationId, amount(net).
const FI_OPERATION_ID_OFF: usize = 0;
const FI_NET_AMOUNT_OFF: usize = 32;
const FI_MIN_DATA_LEN: usize = 2 * 32;

/// One decoded EVM log, enclave-local so no RPC-client types leak past this
/// module boundary (keeps the predicate unit-testable without a live RPC).
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// The subset of a transaction receipt the predicate needs.
#[derive(Debug, Clone)]
pub struct ReceiptData {
    /// Post-Byzantium receipt status: `true` == success (`0x1`).
    pub status_success: bool,
    /// Block the tx was mined in (used for confirmation-depth).
    pub block_number: u64,
    pub logs: Vec<LogEntry>,
}

/// Read-only EVM RPC surface the predicate needs. Behind a trait so unit tests
/// inject synthetic receipts and CI never touches a real RPC; the alloy-backed
/// [`AlloyEvmClient`] is the production impl.
pub trait EvmReceiptProvider {
    /// `eth_getTransactionReceipt`. `Ok(None)` == tx not mined / not found.
    fn get_transaction_receipt(&self, tx_hash: &[u8; 32]) -> Result<Option<ReceiptData>>;
    /// `eth_blockNumber` (current head).
    fn get_block_number(&self) -> Result<u64>;
}

/// keccak256 of an event signature -> its `topic0`.
fn event_topic0(sig: &str) -> [u8; 32] {
    Keccak256::digest(sig.as_bytes()).into()
}

/// Independently verify the `FundsIn` deposit for a bridge-mode `signPsbt`.
///
/// Fail-closed: a missing/failed receipt, no matching log, an ambiguous match,
/// any field mismatch, an on-chain value exceeding `u64`, or insufficient
/// confirmation depth all return `Err` and the caller refuses to sign.
///
/// `bridge_contract` and `min_confirmations` come from PINNED config, never the
/// request. `expected_*` come from the request fields the listener supplied and
/// that this function is confirming against the chain.
#[allow(clippy::too_many_arguments)]
pub fn verify_funds_in_event(
    provider: &dyn EvmReceiptProvider,
    bridge_contract: &[u8; 20],
    min_confirmations: u64,
    evm_tx_hash: &[u8; 32],
    expected_operation_id: u64,
    expected_gross_amount: u64,
    expected_commission: u64,
) -> Result<()> {
    // 1. Receipt must exist. `None` == not mined or host withheld it.
    let receipt = provider
        .get_transaction_receipt(evm_tx_hash)?
        .ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
            "FundsIn receipt not found for tx 0x{} (not mined, or host withheld it) - refusing \
             to sign",
            hex::encode(evm_tx_hash)
        ))
        })?;

    // 2. The deposit tx must have succeeded; a reverted tx emits no real FundsIn.
    if !receipt.status_success {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn tx 0x{} reverted (receipt status != success)",
            hex::encode(evm_tx_hash)
        )));
    }

    // 3/4. Find the UNIQUE log emitted by the pinned bridge contract whose
    //      topic0 is FundsIn / BridgeFundsIn. Pinning the address means a
    //      compromised host cannot satisfy this with a look-alike contract.
    let bridge_topic0 = event_topic0(BRIDGE_FUNDS_IN_SIG);
    let funds_in_topic0 = event_topic0(FUNDS_IN_SIG);
    let mut matches = receipt.logs.iter().filter(|log| {
        log.address == *bridge_contract
            && log
                .topics
                .first()
                .is_some_and(|t| *t == bridge_topic0 || *t == funds_in_topic0)
    });
    let log = matches.next().ok_or_else(|| {
        EnclaveError::CrossCheck(format!(
            "no FundsIn/BridgeFundsIn log from bridge contract 0x{} in tx 0x{}",
            hex::encode(bridge_contract),
            hex::encode(evm_tx_hash)
        ))
    })?;
    if matches.next().is_some() {
        return Err(EnclaveError::CrossCheck(format!(
            "ambiguous: multiple FundsIn logs from bridge contract 0x{} in tx 0x{} - refusing to \
             guess which authorises this release",
            hex::encode(bridge_contract),
            hex::encode(evm_tx_hash)
        )));
    }

    // 5/6/7. Decode the log data and bind operationId + amounts. `sender` is
    //        indexed, so it is in topics, not data.
    let is_bridge_shape = log.topics.first() == Some(&bridge_topic0);
    if is_bridge_shape {
        if log.data.len() < BFI_MIN_DATA_LEN {
            return Err(EnclaveError::CrossCheck(format!(
                "BridgeFundsIn data too short: {} bytes (need {BFI_MIN_DATA_LEN})",
                log.data.len()
            )));
        }
        let operation_id = decode_u64_word(&log.data, BFI_OPERATION_ID_OFF, "operationId")?;
        let gross = decode_u64_word(&log.data, BFI_AMOUNT_OFF, "amount")?;
        let net = decode_u64_word(&log.data, BFI_NET_AMOUNT_OFF, "netAmount")?;
        let commission = decode_u64_word(&log.data, BFI_TOKEN_COMMISSION_OFF, "tokenCommission")?;

        check_eq("operationId", operation_id, expected_operation_id)?;
        check_eq("amount", gross, expected_gross_amount)?;
        check_eq("tokenCommission", commission, expected_commission)?;
        // Internal consistency: net == gross - commission (also pins net to the
        // request's derived net without trusting a separate wire field).
        let want_net = gross.checked_sub(commission).ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "BridgeFundsIn commission ({commission}) exceeds gross amount ({gross})"
            ))
        })?;
        check_eq("netAmount", net, want_net)?;
    } else {
        // Plain FundsIn: only net amount is available; commission stays
        // listener-supplied (weaker). Prefer BridgeFundsIn in production.
        if log.data.len() < FI_MIN_DATA_LEN {
            return Err(EnclaveError::CrossCheck(format!(
                "FundsIn data too short: {} bytes (need {FI_MIN_DATA_LEN})",
                log.data.len()
            )));
        }
        let operation_id = decode_u64_word(&log.data, FI_OPERATION_ID_OFF, "operationId")?;
        let net = decode_u64_word(&log.data, FI_NET_AMOUNT_OFF, "netAmount")?;
        let want_net = expected_gross_amount
            .checked_sub(expected_commission)
            .ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "expected commission ({expected_commission}) exceeds expected gross \
                     ({expected_gross_amount})"
                ))
            })?;
        check_eq("operationId", operation_id, expected_operation_id)?;
        check_eq("netAmount", net, want_net)?;
        tracing::warn!(
            "verified only plain FundsIn (net amount); tokenCommission stays listener-trusted - \
             emit BridgeFundsIn to bind the commission"
        );
    }

    // 8. Confirmation depth against the current head. `eth_blockNumber` and the
    //    receipt are two separate calls, so a reorg between them is possible;
    //    min_confirmations bounds it. head < block_number == the receipt's
    //    block was reorged out from under us -> reject.
    let head = provider.get_block_number()?;
    let depth = head.checked_sub(receipt.block_number).ok_or_else(|| {
        EnclaveError::CrossCheck(format!(
            "FundsIn receipt block {} is above RPC head {head} (reorg?) - refusing to sign",
            receipt.block_number
        ))
    })?;
    if depth < min_confirmations {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn not final: depth {depth} < required {min_confirmations} (receipt block {}, \
             head {head})",
            receipt.block_number
        )));
    }

    tracing::info!(
        tx = %hex::encode(evm_tx_hash),
        operation_id = expected_operation_id,
        depth,
        "FundsIn event independently verified in-enclave"
    );
    Ok(())
}

/// Read a 32-byte ABI word at `offset` in `data` as a `u64`, mapping the
/// generic overflow/short errors to a field-named, fail-closed message. The
/// `u64`-fit check (high 24 bytes zero) is the documented width guard: an
/// on-chain value exceeding `u64` is rejected, not truncated.
fn decode_u64_word(data: &[u8], offset: usize, field: &str) -> Result<u64> {
    extract_uint256_as_u64(data, offset).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "FundsIn {field}: {e} (a uint256 exceeding u64 needs the bytes operation_id proto \
             follow-up)"
        ))
    })
}

/// Equality assertion with a field-named fail-closed error.
fn check_eq(field: &str, got: u64, want: u64) -> Result<()> {
    if got != want {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn {field} mismatch: on-chain {got} != request {want}"
        )));
    }
    Ok(())
}

/// Production [`EvmReceiptProvider`]: an alloy JSON-RPC client over the
/// in-enclave loopback URL (which a vsock forwarder tunnels to the host EVM
/// RPC). alloy is async, so a single-worker tokio runtime is built once at boot
/// and each blocking call is driven via `block_on`. One worker is enough (the
/// receipt fetch is the only async work) and keeps `Send + Sync` so the shared
/// `ServerContext` can call it from any handler thread.
pub struct AlloyEvmClient {
    runtime: tokio::runtime::Runtime,
    provider: alloy::providers::RootProvider,
}

impl AlloyEvmClient {
    /// Build the client against `rpc_url` (must be the loopback forwarder URL).
    pub fn new(rpc_url: &str) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("evm-rpc: failed to build tokio runtime: {e}"))
            })?;
        let url = rpc_url.parse().map_err(|e| {
            EnclaveError::CrossCheck(format!("evm-rpc: invalid rpc_url {rpc_url:?}: {e}"))
        })?;
        let provider = alloy::providers::RootProvider::new_http(url);
        Ok(Self { runtime, provider })
    }
}

impl EvmReceiptProvider for AlloyEvmClient {
    fn get_transaction_receipt(&self, tx_hash: &[u8; 32]) -> Result<Option<ReceiptData>> {
        use alloy::providers::Provider;
        let hash = alloy::primitives::B256::from_slice(tx_hash);
        let receipt = self
            .runtime
            .block_on(self.provider.get_transaction_receipt(hash))
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("evm-rpc: eth_getTransactionReceipt failed: {e}"))
            })?;
        Ok(receipt.map(map_alloy_receipt))
    }

    fn get_block_number(&self) -> Result<u64> {
        use alloy::providers::Provider;
        self.runtime
            .block_on(self.provider.get_block_number())
            .map_err(|e| EnclaveError::CrossCheck(format!("evm-rpc: eth_blockNumber failed: {e}")))
    }
}

/// Translate an alloy receipt into the enclave-local [`ReceiptData`] so no
/// alloy types leak into the predicate.
fn map_alloy_receipt(r: alloy::rpc::types::TransactionReceipt) -> ReceiptData {
    let logs = r
        .inner
        .logs()
        .iter()
        .map(|log| LogEntry {
            address: log.address().into_array(),
            topics: log.topics().iter().map(|t| t.0).collect(),
            data: log.data().data.to_vec(),
        })
        .collect();
    ReceiptData {
        status_success: r.status(),
        block_number: r.block_number.unwrap_or(0),
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BRIDGE: [u8; 20] = [0xB1; 20];
    const OTHER: [u8; 20] = [0xC2; 20];
    const TX: [u8; 32] = [0x11; 32];

    /// In-memory provider for the predicate tests - no real RPC.
    struct FakeProvider {
        receipt: Option<ReceiptData>,
        head: u64,
    }
    impl EvmReceiptProvider for FakeProvider {
        fn get_transaction_receipt(&self, _tx_hash: &[u8; 32]) -> Result<Option<ReceiptData>> {
            Ok(self.receipt.clone())
        }
        fn get_block_number(&self) -> Result<u64> {
            Ok(self.head)
        }
    }

    fn word(v: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    }

    /// Build BridgeFundsIn data: operationId, gross, net, commission, then
    /// nativeCommission/srcChain/destChain/string-offset zero-filled.
    fn bridge_data(op: u64, gross: u64, net: u64, commission: u64) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&word(op));
        d.extend_from_slice(&word(gross));
        d.extend_from_slice(&word(net));
        d.extend_from_slice(&word(commission));
        d.extend_from_slice(&[0u8; 32 * 4]); // nativeCommission, src, dest, str offset
        d
    }

    fn bridge_log(op: u64, gross: u64, net: u64, commission: u64) -> LogEntry {
        LogEntry {
            address: BRIDGE,
            topics: vec![event_topic0(BRIDGE_FUNDS_IN_SIG), word(0xdead)], // topic1 = sender (unused)
            data: bridge_data(op, gross, net, commission),
        }
    }

    fn receipt_with(logs: Vec<LogEntry>, block_number: u64) -> ReceiptData {
        ReceiptData {
            status_success: true,
            block_number,
            logs,
        }
    }

    /// gross=1000, commission=50, net=950, op=7. head 112, block 100 -> depth 12.
    fn happy_provider() -> FakeProvider {
        FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(7, 1000, 950, 50)], 100)),
            head: 112,
        }
    }

    fn verify(p: &FakeProvider) -> Result<()> {
        verify_funds_in_event(p, &BRIDGE, 12, &TX, 7, 1000, 50)
    }

    // ---- topic0 drift guards (offline-pinned known-good vectors) ----

    #[test]
    fn topic0_vectors_are_pinned() {
        assert_eq!(
            hex::encode(event_topic0(FUNDS_IN_SIG)),
            "cf4f3270b7400c5ca42954767c516b7c595dcd8038cdd121945a474c616208f8",
            "FundsIn topic0 drifted"
        );
        assert_eq!(
            hex::encode(event_topic0(BRIDGE_FUNDS_IN_SIG)),
            "08f62fdb70e8436181cbb1e561f6059677b179778bb0e0b9789a277eca0767e5",
            "BridgeFundsIn topic0 drifted"
        );
    }

    // ---- happy path ----

    #[test]
    fn accepts_matching_bridge_funds_in() {
        assert!(verify(&happy_provider()).is_ok());
    }

    // ---- receipt-level rejections ----

    #[test]
    fn rejects_missing_receipt() {
        let p = FakeProvider {
            receipt: None,
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("receipt not found"), "got: {e}");
    }

    #[test]
    fn rejects_reverted_tx() {
        let mut r = receipt_with(vec![bridge_log(7, 1000, 950, 50)], 100);
        r.status_success = false;
        let p = FakeProvider {
            receipt: Some(r),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("reverted"), "got: {e}");
    }

    // ---- log-matching rejections ----

    #[test]
    fn rejects_log_from_wrong_contract() {
        let mut log = bridge_log(7, 1000, 950, 50);
        log.address = OTHER;
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![log], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("no FundsIn/BridgeFundsIn log"), "got: {e}");
    }

    #[test]
    fn rejects_wrong_topic0() {
        let mut log = bridge_log(7, 1000, 950, 50);
        log.topics[0] = word(0x1234); // not a FundsIn topic
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![log], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("no FundsIn/BridgeFundsIn log"), "got: {e}");
    }

    #[test]
    fn rejects_ambiguous_multiple_logs() {
        let p = FakeProvider {
            receipt: Some(receipt_with(
                vec![bridge_log(7, 1000, 950, 50), bridge_log(7, 1000, 950, 50)],
                100,
            )),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("ambiguous"), "got: {e}");
    }

    #[test]
    fn ignores_unrelated_logs_and_accepts() {
        let unrelated = LogEntry {
            address: OTHER,
            topics: vec![word(0x9999)],
            data: vec![],
        };
        let p = FakeProvider {
            receipt: Some(receipt_with(
                vec![unrelated, bridge_log(7, 1000, 950, 50)],
                100,
            )),
            head: 112,
        };
        assert!(verify(&p).is_ok());
    }

    // ---- field-mismatch rejections ----

    #[test]
    fn rejects_operation_id_mismatch() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(8, 1000, 950, 50)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("operationId mismatch"), "got: {e}");
    }

    #[test]
    fn rejects_amount_mismatch() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(7, 999, 949, 50)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("amount mismatch"), "got: {e}");
    }

    #[test]
    fn rejects_commission_mismatch() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(7, 1000, 950, 40)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("tokenCommission mismatch"), "got: {e}");
    }

    #[test]
    fn rejects_inconsistent_net_amount() {
        // gross-commission = 950 but log claims net = 900.
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(7, 1000, 900, 50)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("netAmount mismatch"), "got: {e}");
    }

    #[test]
    fn rejects_operation_id_exceeding_u64() {
        let mut log = bridge_log(7, 1000, 950, 50);
        // Set a high byte in the operationId word -> exceeds u64.
        log.data[BFI_OPERATION_ID_OFF] = 0x01;
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![log], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("operationId") && e.contains("u64"), "got: {e}");
    }

    // ---- confirmation-depth rejections ----

    #[test]
    fn rejects_insufficient_depth() {
        // head 111, block 100 -> depth 11 < 12.
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(7, 1000, 950, 50)], 100)),
            head: 111,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("not final"), "got: {e}");
    }

    #[test]
    fn accepts_exact_min_depth() {
        // head 112, block 100 -> depth 12 == 12.
        assert!(verify(&happy_provider()).is_ok());
    }

    #[test]
    fn rejects_head_below_receipt_block() {
        // head 99 < block 100 -> reorg.
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(7, 1000, 950, 50)], 100)),
            head: 99,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("reorg"), "got: {e}");
    }

    // ---- #51 regression: listener booleans can no longer authorize ----

    #[test]
    fn issue_51_no_receipt_means_no_authorization() {
        // Simulates a request whose listener set evm_event_valid/finalized=true
        // but for which no real deposit exists: verification must still reject,
        // proving the removed booleans no longer gate signing.
        let p = FakeProvider {
            receipt: None,
            head: 112,
        };
        assert!(verify(&p).is_err());
    }
}
