//! Independent in-enclave verification of the EVM `FundsIn` deposit event for
//! bridge-mode `signPsbt` (audit M-06 / issues #60, #51).
//!
//! Bridge-mode `signPsbt` releases RGB against an EVM deposit. Previously the
//! enclave trusted two listener-supplied booleans (`evm_event_valid` /
//! `evm_event_finalized`) that anyone reaching the enclave could set to `true`.
//! This module replaces that trust: the enclave fetches the deposit's
//! transaction receipt over an in-enclave EVM RPC and checks, itself, that a
//! `BridgeFundsIn` log was emitted by the pinned bridge contract with the
//! claimed amount, and at sufficient confirmation depth. Every predicate is
//! **fail-closed**.
//!
//! TRUST BOUNDARY: the RPC is reached through the loopback -> vsock forwarder,
//! i.e. responses are relayed by the UNTRUSTED host. A malicious host can
//! withhold a receipt (-> we fail closed, safe) but could in principle forge
//! one; this predicate becomes trustless only once Helios (#77) verifies the
//! RPC inside the TEE. This is the predicate + plumbing layer.
//!
//! #77 PREDICATE SHAPE (deliberate divergence): issue #77 sketches matching the
//! exact listener-forwarded log (`evm_contract`, `evm_log_index`,
//! `evm_event_topics`, `evm_event_data`). This module instead PINS the contract
//! from config and independently DECODES + binds the semantic fields
//! (`operationId`, gross/net/commission) from the log data. That is strictly
//! stronger — the enclave never trusts a listener-forwarded raw log — so
//! `evm_log_index` / `evm_event_topics` / `evm_event_data` are intentionally
//! unused rather than an oversight.
//!
//! WHAT THIS DOES NOT BIND: `operationId` has no on-chain cryptographic link to
//! the RGB mint being signed, so confirming the deposit does not by itself prove
//! it corresponds to *this* RGB transfer; that association stays
//! listener-supplied (related to #66). Amounts are still compared as `u64`
//! because the proto carries them that way, so an on-chain value exceeding `u64`
//! is rejected fail-closed (see [`extract_uint256_as_u64`]).
//!
//! `operationId` is a contract-derived `bytes32` on the route-agnostic Bridge,
//! and the binding is required: exactly 32 bytes, matching the on-chain topic,
//! or refuse. There is deliberately no "unavailable" sentinel to forget to fill.

use sha3::{Digest, Keccak256};

use crate::error::{EnclaveError, Result};

/// Read a uint256 from an ABI word at a byte offset, as u64. Fails if the data
/// is too short or the value exceeds u64.
fn extract_uint256_as_u64(data: &[u8], offset: usize) -> Result<u64> {
    let end = offset + 32;
    if data.len() < end {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need {} bytes, got {}",
            end,
            data.len()
        )));
    }
    let slot = &data[offset..end];
    if slot[..24].iter().any(|&b| b != 0) {
        return Err(EnclaveError::CrossCheck(
            "uint256 value exceeds u64 range".into(),
        ));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&slot[24..32]);
    Ok(u64::from_be_bytes(buf))
}

/// Canonical `BridgeFundsIn` signature, verbatim from `bridge-smart-contracts`
/// `IBridge.sol`. A stale signature here fails SILENTLY — the filter matches zero
/// logs and every deposit reports "no FundsIn log in tx".
const BRIDGE_FUNDS_IN_SIG: &str = "BridgeFundsIn(bytes32,bytes32,address,uint256,uint256,\
     uint256,uint256,uint256,uint256,uint256,string)";

/// `operationId` is `topic1` (topic0 is the event signature itself).
const BFI_OPERATION_ID_TOPIC: usize = 1;

/// Canonical lean RGB-correlation event, verbatim from `bridge-smart-contracts`
/// `BaseBridge.sol`. A deposit emits it ALONGSIDE `BridgeFundsIn`; a REBALANCE
/// credit leg emits ONLY this one, and its `rgbOpId` (topic2) carries exactly
/// the RGB operation id a rebalance-origin mint is verified against.
const LEAN_FUNDS_IN_SIG: &str = "FundsIn(address,uint256,uint256)";

/// `rgbOpId` is `topic2` of the lean event (topic1 is the indexed sender).
const LFI_RGB_OP_ID_TOPIC: usize = 2;

/// Byte offsets of the NON-INDEXED `BridgeFundsIn` data words (each 32 bytes).
/// Order: senderNonce, amount(gross), netAmount, tokenCommission,
/// nativeCommission, sourceChainId, destinationChainId, <string offset>.
///
/// The amount offsets are unchanged from the old event only by coincidence —
/// `senderNonce` took the slot `operationId` vacated — so a half-done migration
/// still decodes plausible amounts. Hence the pinned topic0 test.
const BFI_AMOUNT_OFF: usize = 32;
const BFI_NET_AMOUNT_OFF: usize = 64;
const BFI_TOKEN_COMMISSION_OFF: usize = 96;
/// 7 static words + 1 dynamic-string offset word must be present.
const BFI_MIN_DATA_LEN: usize = 8 * 32;

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
///
/// `expected_operation_id` is mandatory: exactly 32 bytes, or refuse. Empty is an
/// error, not a skipped comparison.
#[allow(clippy::too_many_arguments)]
pub fn verify_funds_in_event(
    provider: &dyn EvmReceiptProvider,
    bridge_contract: &[u8; 20],
    min_confirmations: u64,
    evm_tx_hash: &[u8; 32],
    expected_operation_id: &[u8],
    expected_gross_amount: u64,
    expected_commission: u64,
) -> Result<()> {
    if expected_operation_id.len() != 32 {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn expected operationId must be exactly 32 bytes (the contract-derived \
             BridgeFundsIn.operationId from indexed topic1), got {}",
            expected_operation_id.len()
        )));
    }
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

    // 3/4. Find the log emitted by the pinned bridge contract that authorises
    //      this release. Pinning the address means a compromised host cannot
    //      satisfy this with a look-alike contract.
    //
    //      The plain-`FundsIn` fallback is gone: on the new Bridge that event is
    //      RGB-only and carries the RGB OpId, so falling back would compare
    //      across id-spaces. Two deposits in one tx still refuse rather than
    //      guess.
    let bridge_topic0 = event_topic0(BRIDGE_FUNDS_IN_SIG);
    let candidates: Vec<&LogEntry> = receipt
        .logs
        .iter()
        .filter(|log| {
            &log.address == bridge_contract
                && log.topics.first().is_some_and(|t| *t == bridge_topic0)
        })
        .collect();
    if candidates.len() > 1 {
        return Err(EnclaveError::CrossCheck(format!(
            "ambiguous: multiple BridgeFundsIn logs from the pinned bridge contract {} in tx 0x{} - \
             refusing to guess which authorises this release",
            hex::encode(bridge_contract),
            hex::encode(evm_tx_hash)
        )));
    }
    let operation_id: [u8; 32] = if let Some(log) = candidates.first().copied() {
        // 5/6/7. Bind operationId + amounts. The three indexed fields are in
        //        topics; everything else comes from `data`.
        let operation_id = log
            .topics
            .get(BFI_OPERATION_ID_TOPIC)
            .ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "BridgeFundsIn log has {} topic(s); operationId is expected in topic{BFI_OPERATION_ID_TOPIC}",
                    log.topics.len()
                ))
            })?;

        if log.data.len() < BFI_MIN_DATA_LEN {
            return Err(EnclaveError::CrossCheck(format!(
                "BridgeFundsIn data too short: {} bytes (need {BFI_MIN_DATA_LEN})",
                log.data.len()
            )));
        }
        let gross = decode_u64_word(&log.data, BFI_AMOUNT_OFF, "amount")?;
        let net = decode_u64_word(&log.data, BFI_NET_AMOUNT_OFF, "netAmount")?;
        let commission = decode_u64_word(&log.data, BFI_TOKEN_COMMISSION_OFF, "tokenCommission")?;

        if expected_operation_id != operation_id.as_slice() {
            return Err(EnclaveError::CrossCheck(format!(
                "FundsIn operationId mismatch: on-chain 0x{} != request 0x{}",
                hex::encode(operation_id),
                hex::encode(expected_operation_id)
            )));
        }

        check_eq("amount", gross, expected_gross_amount)?;
        check_eq("tokenCommission", commission, expected_commission)?;

        // Bounded, not equal: the Bridge credits the MEASURED balance delta while
        // `amount` stays nominal, so a fee-on-transfer token legitimately nets less
        // (Bridge.sol:501-508). Only `net` too HIGH is unsafe — it would mint more
        // RGB than the deposit backs.
        let max_net = gross.checked_sub(commission).ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "BridgeFundsIn commission ({commission}) exceeds gross amount ({gross})"
            ))
        })?;
        if net > max_net {
            return Err(EnclaveError::CrossCheck(format!(
                "BridgeFundsIn netAmount ({net}) exceeds gross - commission ({max_net}) - refusing \
                 to sign a release for more than the deposit backs"
            )));
        }
        if net < max_net {
            tracing::warn!(
                net,
                max_net,
                "BridgeFundsIn netAmount is below gross - commission; expected only for a \
                 fee-on-transfer token, where the Bridge credits the measured balance delta"
            );
        }
        *operation_id
    } else {
        // No BridgeFundsIn at all: the REBALANCE credit leg emits only the lean
        // RGB-correlation event, whose `rgbOpId` IS the RGB operation id this
        // mint is verified against — the id-space concern that removed the old
        // plain-FundsIn fallback applies to deposits, and a deposit always
        // carries BridgeFundsIn, so this branch never fires for one. Same
        // pinned-address and fail-closed rules as above.
        let lean_topic0 = event_topic0(LEAN_FUNDS_IN_SIG);
        let lean: Vec<&LogEntry> = receipt
            .logs
            .iter()
            .filter(|log| {
                &log.address == bridge_contract
                    && log.topics.first().is_some_and(|t| *t == lean_topic0)
            })
            .collect();
        if lean.len() > 1 {
            return Err(EnclaveError::CrossCheck(format!(
                "ambiguous: multiple FundsIn logs from the pinned bridge contract {} in tx 0x{} - \
                 refusing to guess which authorises this release",
                hex::encode(bridge_contract),
                hex::encode(evm_tx_hash)
            )));
        }
        let log = lean.first().copied().ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "no BridgeFundsIn or FundsIn log from the pinned bridge contract {} in tx 0x{}",
                hex::encode(bridge_contract),
                hex::encode(evm_tx_hash)
            ))
        })?;

        let rgb_op_id = log.topics.get(LFI_RGB_OP_ID_TOPIC).ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "FundsIn log has {} topic(s); rgbOpId is expected in topic{LFI_RGB_OP_ID_TOPIC}",
                log.topics.len()
            ))
        })?;
        if expected_operation_id != rgb_op_id.as_slice() {
            return Err(EnclaveError::CrossCheck(format!(
                "FundsIn rgbOpId mismatch: on-chain 0x{} != request 0x{}",
                hex::encode(rgb_op_id),
                hex::encode(expected_operation_id)
            )));
        }

        let amount = decode_u64_word(&log.data, 0, "amount")?;
        check_eq("amount", amount, expected_gross_amount)?;
        // The rebalance credit leg carries no commission; a nonzero expectation
        // cannot be satisfied by this event — refuse rather than skip.
        check_eq("tokenCommission", 0, expected_commission)?;

        *rgb_op_id
    };

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
        operation_id = %hex::encode(operation_id),
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
            "FundsIn {field}: {e} (the proto carries this field as u64; a larger on-chain value \
             is rejected, never truncated)"
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
        receipt.map(map_alloy_receipt).transpose()
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
///
/// Fails closed on a missing `block_number`: the confirmation-depth check is
/// `head - block_number`, so a `None` defaulted to `0` would report the receipt
/// as infinitely deep and pass finality. A mined tx always carries a block
/// number (a pending tx yields no receipt at all), so this only guards against
/// a malformed response, but a finality check must never default to "deep".
fn map_alloy_receipt(r: alloy::rpc::types::TransactionReceipt) -> Result<ReceiptData> {
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
    let block_number = r.block_number.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "evm-rpc: FundsIn receipt has no block_number (pending/malformed) - refusing to \
             treat an unmined receipt as confirmed"
                .into(),
        )
    })?;
    Ok(ReceiptData {
        status_success: r.status(),
        block_number,
        logs,
    })
}

/// Boot-time bound on the Helios light-client initial sync. If the client is
/// not synced within this window, [`HeliosEvmClient::new`] fails and the
/// provider stays unset - bridge signing then fails closed rather than run
/// against an unverified/unsynced client.
#[cfg(feature = "helios")]
const HELIOS_BOOT_SYNC_TIMEOUT_SECS: u64 = 300;

/// TRUSTLESS [`EvmReceiptProvider`] (#77): the a16z Helios light client embedded
/// in-process. Helios treats the execution/consensus RPCs (reached via loopback
/// vsock forwarders) as UNTRUSTED and verifies them against a pinned
/// weak-subjectivity checkpoint before returning a receipt - so unlike
/// [`AlloyEvmClient`], a malicious host cannot forge the result.
///
/// Helios is async and runs a background sync task, so a long-lived tokio
/// runtime is built at boot and kept alive for the client's lifetime; each
/// query is driven via `block_on`. The returned receipt (alloy 1.x types) is
/// mapped to the enclave-local [`ReceiptData`] so no alloy-version types cross
/// the [`EvmReceiptProvider`] boundary.
#[cfg(feature = "helios")]
pub struct HeliosEvmClient {
    // Field order matters for drop: the client is dropped before the runtime.
    client: helios_ethereum::EthereumClient,
    runtime: tokio::runtime::Runtime,
}

#[cfg(feature = "helios")]
impl HeliosEvmClient {
    /// Build and SYNC the Helios client at boot. Blocks (bounded by
    /// [`HELIOS_BOOT_SYNC_TIMEOUT_SECS`]) until the light client is synced so
    /// the first query is already verified. Any error (bad config, no
    /// checkpoint, sync timeout) is returned so boot leaves the provider unset
    /// and bridge signing fails closed.
    pub fn new(cfg: &crate::config::HeliosConfig, expected_chain_id: u64) -> Result<Self> {
        use helios_ethereum::{config::networks::Network, EthereumClientBuilder};

        // Canonical chain id for each supported network. Kept here rather than
        // read from the network object so the consistency check below does not
        // depend on Helios internals.
        let (network, network_chain_id) = match cfg.network.to_ascii_lowercase().as_str() {
            "mainnet" => (Network::Mainnet, 1u64),
            "sepolia" => (Network::Sepolia, 11155111u64),
            "holesky" => (Network::Holesky, 17000u64),
            other => {
                return Err(EnclaveError::CrossCheck(format!(
                    "helios: unsupported HELIOS_NETWORK {other:?} (want mainnet|sepolia|holesky)"
                )))
            }
        };
        // #77 predicate 1: HELIOS_NETWORK must be consistent with the pinned
        // EVM_CHAIN_ID. Both are operator-set at boot, so a mismatch is a
        // misconfiguration (e.g. Helios on sepolia while the bridge is pinned to
        // mainnet) that would otherwise verify FundsIn on the wrong chain.
        // Skipped only when EVM_CHAIN_ID is unset (0), i.e. an unconfigured
        // dev/mock deploy that pins no identity.
        if expected_chain_id != 0 && expected_chain_id != network_chain_id {
            return Err(EnclaveError::CrossCheck(format!(
                "helios: HELIOS_NETWORK {:?} (chain id {network_chain_id}) is inconsistent with \
                 the pinned EVM_CHAIN_ID {expected_chain_id} - refusing to verify FundsIn on a \
                 different chain than the bridge is configured for",
                cfg.network
            )));
        }
        let checkpoint = parse_checkpoint(cfg.checkpoint.as_deref())?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| EnclaveError::CrossCheck(format!("helios: tokio runtime: {e}")))?;

        let exec = cfg.execution_rpc.clone();
        let cons = cfg.consensus_rpc.clone();
        let strict = cfg.strict_checkpoint_age;

        let client = runtime.block_on(async move {
            let builder = EthereumClientBuilder::new()
                .network(network)
                .execution_rpc(&exec)
                .map_err(|e| EnclaveError::CrossCheck(format!("helios: bad execution_rpc: {e}")))?
                .consensus_rpc(&cons)
                .map_err(|e| EnclaveError::CrossCheck(format!("helios: bad consensus_rpc: {e}")))?
                .checkpoint(checkpoint);
            // No `load_external_fallback`/`fallback`: the ONLY egress is the two
            // forwarded RPCs, and the checkpoint is operator-pinned.
            let builder = if strict {
                builder.strict_checkpoint_age()
            } else {
                builder
            };
            let client = builder
                .with_config_db() // in-memory, no disk in the enclave
                .build()
                .map_err(|e| EnclaveError::CrossCheck(format!("helios: build: {e}")))?;

            let timeout = std::time::Duration::from_secs(HELIOS_BOOT_SYNC_TIMEOUT_SECS);
            tokio::time::timeout(timeout, client.wait_synced())
                .await
                .map_err(|_| {
                    EnclaveError::CrossCheck(format!(
                        "helios: light client did not sync within {HELIOS_BOOT_SYNC_TIMEOUT_SECS}s \
                         - refusing to start (bridge signing fails closed until synced)"
                    ))
                })?
                .map_err(|e| EnclaveError::CrossCheck(format!("helios: sync failed: {e}")))?;
            Ok::<_, EnclaveError>(client)
        })?;

        tracing::info!(
            network = %cfg.network,
            execution_rpc = %cfg.execution_rpc,
            consensus_rpc = %cfg.consensus_rpc,
            "Helios light client synced (trustless FundsIn verification, #77)"
        );
        Ok(Self { client, runtime })
    }
}

#[cfg(feature = "helios")]
impl EvmReceiptProvider for HeliosEvmClient {
    fn get_transaction_receipt(&self, tx_hash: &[u8; 32]) -> Result<Option<ReceiptData>> {
        let hash = alloy_primitives::B256::from_slice(tx_hash);
        let receipt = self
            .runtime
            .block_on(self.client.get_transaction_receipt(hash))
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("helios: eth_getTransactionReceipt failed: {e}"))
            })?;
        // Map inline so the alloy-1.x receipt type is inferred, never named -
        // it must not cross the EvmReceiptProvider boundary (our alloy is 2.x).
        // Fails closed on a missing block_number, same as `map_alloy_receipt`.
        receipt
            .map(|r| {
                let block_number = r.block_number.ok_or_else(|| {
                    EnclaveError::CrossCheck(
                        "helios: FundsIn receipt has no block_number (pending/malformed) - \
                         refusing to treat an unmined receipt as confirmed"
                            .into(),
                    )
                })?;
                Ok(ReceiptData {
                    status_success: r.status(),
                    block_number,
                    logs: r
                        .inner
                        .logs()
                        .iter()
                        .map(|log| LogEntry {
                            address: log.address().into_array(),
                            topics: log.topics().iter().map(|t| t.0).collect(),
                            data: log.data().data.to_vec(),
                        })
                        .collect(),
                })
            })
            .transpose()
    }

    fn get_block_number(&self) -> Result<u64> {
        let n = self
            .runtime
            .block_on(self.client.get_block_number())
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("helios: eth_blockNumber failed: {e}"))
            })?;
        u64::try_from(n)
            .map_err(|_| EnclaveError::CrossCheck("helios: head block number exceeds u64".into()))
    }
}

/// Parse the operator-pinned `HELIOS_CHECKPOINT` (0x-prefixed 32-byte beacon
/// block root) into an alloy-1.x `B256`. A checkpoint is mandatory for a
/// trustless build; `None`/malformed fails closed.
#[cfg(feature = "helios")]
fn parse_checkpoint(checkpoint: Option<&str>) -> Result<alloy_primitives::B256> {
    let hex_str = checkpoint.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "helios: HELIOS_CHECKPOINT is required (a recent weak-subjectivity beacon block root) \
             - refusing to sync against an untrusted community checkpoint"
                .into(),
        )
    })?;
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)
        .map_err(|e| EnclaveError::CrossCheck(format!("helios: HELIOS_CHECKPOINT not hex: {e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        EnclaveError::CrossCheck(format!(
            "helios: HELIOS_CHECKPOINT must be 32 bytes, got {}",
            v.len()
        ))
    })?;
    Ok(alloy_primitives::B256::from(arr))
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

    /// A hash-shaped operationId — deliberately not a small left-padded integer.
    fn op_id(tag: u8) -> [u8; 32] {
        let mut id = [tag; 32];
        id[0] = 0xF0 | (tag & 0x0F); // high bytes set: cannot fit a u64
        id
    }

    /// BridgeFundsIn `data`: senderNonce, gross, net, commission, then
    /// nativeCommission/srcChain/destChain/string-offset zero-filled.
    /// `operationId` is NOT here any more — it is an indexed topic.
    fn bridge_data(gross: u64, net: u64, commission: u64) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&word(0)); // senderNonce
        d.extend_from_slice(&word(gross));
        d.extend_from_slice(&word(net));
        d.extend_from_slice(&word(commission));
        d.extend_from_slice(&[0u8; 32 * 4]); // nativeCommission, src, dest, str offset
        d
    }

    /// topics: [topic0, operationId, sourceSender, sender].
    fn bridge_log(op: [u8; 32], gross: u64, net: u64, commission: u64) -> LogEntry {
        LogEntry {
            address: BRIDGE,
            topics: vec![
                event_topic0(BRIDGE_FUNDS_IN_SIG),
                op,
                [0x5c; 32],   // sourceSender
                word(0xdead), // sender
            ],
            data: bridge_data(gross, net, commission),
        }
    }

    /// The RGB-only companion `FundsIn(address,uint256 rgbOpId,uint256)`. When a
    /// `BridgeFundsIn` is present it always wins; the companion is consulted
    /// ONLY when no `BridgeFundsIn` exists (the rebalance credit leg), and even
    /// then its rgbOpId must equal the expected operation id exactly.
    fn rgb_companion_log(rgb_op_id: u64, net: u64) -> LogEntry {
        LogEntry {
            address: BRIDGE,
            topics: vec![
                event_topic0("FundsIn(address,uint256,uint256)"),
                word(0xdead),
                word(rgb_op_id),
            ],
            data: word(net).to_vec(),
        }
    }

    /// A rebalance credit-leg log: lean `FundsIn` with a full 32-byte RGB op id.
    fn lean_log(rgb_op_id: [u8; 32], amount: u64) -> LogEntry {
        LogEntry {
            address: BRIDGE,
            topics: vec![
                event_topic0(LEAN_FUNDS_IN_SIG),
                word(0xdead), // sender
                rgb_op_id,
            ],
            data: word(amount).to_vec(),
        }
    }

    fn receipt_with(logs: Vec<LogEntry>, block_number: u64) -> ReceiptData {
        ReceiptData {
            status_success: true,
            block_number,
            logs,
        }
    }

    /// gross=1000, commission=50, net=950. head 112, block 100 -> depth 12.
    fn happy_provider() -> FakeProvider {
        FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 50)], 100)),
            head: 112,
        }
    }

    /// Verify with the operationId bound — the only supported call shape.
    fn verify(p: &FakeProvider) -> Result<()> {
        verify_funds_in_event(p, &BRIDGE, 12, &TX, &op_id(7), 1000, 50)
    }

    #[test]
    fn extract_uint256_works() {
        let mut data = vec![0u8; 40];
        // Put value 42 at offset 8 (bytes 8..40)
        data[39] = 42;
        assert_eq!(extract_uint256_as_u64(&data, 8).unwrap(), 42);
    }

    #[test]
    fn extract_uint256_rejects_short_data() {
        let data = vec![0u8; 10];
        assert!(extract_uint256_as_u64(&data, 0).is_err());
    }

    #[test]
    fn extract_uint256_rejects_overflow() {
        let mut data = vec![0u8; 32];
        data[0] = 1; // high byte set — exceeds u64
        assert!(extract_uint256_as_u64(&data, 0).is_err());
    }

    // ---- topic0 drift guards (offline-pinned known-good vectors) ----

    #[test]
    fn topic0_vectors_are_pinned() {
        assert_eq!(
            hex::encode(event_topic0(BRIDGE_FUNDS_IN_SIG)),
            "96266da276e870bb3d9c25740c9e24ec6448fc7bbed72ca384c3b8952574014c",
            "BridgeFundsIn topic0 drifted"
        );
    }

    /// Pins the pre-migration topic0 so a silent revert to the 9-field signature
    /// fails loudly here instead of looking like "no deposit found".
    #[test]
    fn legacy_topic0_is_not_in_use() {
        assert_ne!(
            hex::encode(event_topic0(BRIDGE_FUNDS_IN_SIG)),
            "08f62fdb70e8436181cbb1e561f6059677b179778bb0e0b9789a277eca0767e5",
            "still filtering on the pre-migration BridgeFundsIn signature"
        );
    }

    // ---- happy path ----

    #[test]
    fn accepts_matching_bridge_funds_in() {
        assert!(verify(&happy_provider()).is_ok());
    }

    #[test]
    fn accepts_real_contract_dual_emit() {
        // One deposit emits both events; the pair must not trip the ambiguity
        // guard, since only BridgeFundsIn is a candidate.
        let p = FakeProvider {
            receipt: Some(receipt_with(
                vec![
                    rgb_companion_log(7, 950),
                    bridge_log(op_id(7), 1000, 950, 50),
                ],
                100,
            )),
            head: 112,
        };
        assert!(verify(&p).is_ok());
    }

    #[test]
    fn dual_emit_binds_via_bridge_shape_not_the_companion() {
        // The pair must resolve to BridgeFundsIn, which binds tokenCommission.
        // Commission is invisible to the companion event: passing would mean
        // selection had fallen back to it.
        let p = FakeProvider {
            receipt: Some(receipt_with(
                vec![
                    rgb_companion_log(7, 950),
                    bridge_log(op_id(7), 1000, 950, 999),
                ],
                100,
            )),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("tokenCommission mismatch"), "got: {e}");
    }

    /// A companion-only tx is consulted as a rebalance credit leg, but its
    /// rgbOpId must match the expected operation id exactly - a foreign id is
    /// still refused (the id-space guard, now enforced by comparison instead
    /// of by ignoring the event).
    #[test]
    fn rejects_rgb_companion_event_alone_with_foreign_id() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![rgb_companion_log(7, 950)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("rgbOpId mismatch"), "got: {e}");
    }

    /// The rebalance credit leg: only the lean `FundsIn`, carrying exactly the
    /// expected RGB operation id and amount, no commission expectation.
    #[test]
    fn accepts_rebalance_lean_funds_in() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![lean_log(op_id(7), 1000)], 100)),
            head: 112,
        };
        assert!(verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 1000, 0).is_ok());
    }

    #[test]
    fn rejects_rebalance_lean_amount_mismatch() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![lean_log(op_id(7), 999)], 100)),
            head: 112,
        };
        let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 1000, 0)
            .unwrap_err()
            .to_string();
        assert!(e.contains("amount mismatch"), "got: {e}");
    }

    /// The lean event binds no commission, so a nonzero commission expectation
    /// cannot be satisfied by it - refuse rather than silently skip the check.
    #[test]
    fn rejects_rebalance_lean_with_commission_expectation() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![lean_log(op_id(7), 1000)], 100)),
            head: 112,
        };
        let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 1000, 50)
            .unwrap_err()
            .to_string();
        assert!(e.contains("tokenCommission mismatch"), "got: {e}");
    }

    #[test]
    fn rejects_two_lean_logs_ambiguous() {
        let p = FakeProvider {
            receipt: Some(receipt_with(
                vec![lean_log(op_id(7), 1000), lean_log(op_id(8), 1000)],
                100,
            )),
            head: 112,
        };
        let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 1000, 0)
            .unwrap_err()
            .to_string();
        assert!(e.contains("ambiguous"), "got: {e}");
    }

    /// A lean log from a foreign contract is invisible - the pinned-address
    /// rule holds on the fallback path too.
    #[test]
    fn rejects_lean_log_from_unpinned_contract() {
        let mut foreign = lean_log(op_id(7), 1000);
        foreign.address = OTHER;
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![foreign], 100)),
            head: 112,
        };
        let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 1000, 0)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no BridgeFundsIn or FundsIn log"), "got: {e}");
    }

    #[test]
    fn rejects_two_real_deposits_in_one_tx() {
        // Uniqueness still holds WITHIN a shape: two distinct BridgeFundsIn
        // logs are two deposits, and picking one is a guess.
        let p = FakeProvider {
            receipt: Some(receipt_with(
                vec![
                    bridge_log(op_id(7), 1000, 950, 50),
                    bridge_log(op_id(8), 1000, 950, 50),
                ],
                100,
            )),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("ambiguous"), "got: {e}");
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
        let mut r = receipt_with(vec![bridge_log(op_id(7), 1000, 950, 50)], 100);
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
        let mut log = bridge_log(op_id(7), 1000, 950, 50);
        log.address = OTHER;
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![log], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("no BridgeFundsIn or FundsIn log"), "got: {e}");
    }

    #[test]
    fn rejects_wrong_topic0() {
        let mut log = bridge_log(op_id(7), 1000, 950, 50);
        log.topics[0] = word(0x1234); // not a FundsIn topic
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![log], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("no BridgeFundsIn or FundsIn log"), "got: {e}");
    }

    #[test]
    fn rejects_ambiguous_multiple_logs() {
        let p = FakeProvider {
            receipt: Some(receipt_with(
                vec![
                    bridge_log(op_id(7), 1000, 950, 50),
                    bridge_log(op_id(7), 1000, 950, 50),
                ],
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
                vec![unrelated, bridge_log(op_id(7), 1000, 950, 50)],
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
            receipt: Some(receipt_with(vec![bridge_log(op_id(8), 1000, 950, 50)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("operationId mismatch"), "got: {e}");
    }

    #[test]
    fn rejects_amount_mismatch() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(op_id(7), 999, 949, 50)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("amount mismatch"), "got: {e}");
    }

    #[test]
    fn rejects_commission_mismatch() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 40)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("tokenCommission mismatch"), "got: {e}");
    }

    #[test]
    fn rejects_net_amount_above_gross_minus_commission() {
        // gross-commission = 950 but the log claims 960.
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 960, 50)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("exceeds gross - commission"), "got: {e}");
    }

    /// Under-crediting is legitimate for a fee-on-transfer token and safe, so it
    /// is accepted and logged rather than refused.
    #[test]
    fn accepts_net_amount_below_gross_minus_commission() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 900, 50)], 100)),
            head: 112,
        };
        assert!(verify(&p).is_ok());
    }

    #[test]
    fn rejects_commission_exceeding_gross() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(op_id(7), 100, 0, 150)], 100)),
            head: 112,
        };
        let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 100, 150)
            .unwrap_err()
            .to_string();
        assert!(e.contains("exceeds gross amount"), "got: {e}");
    }

    /// A log without the indexed topics cannot be bound: fail closed rather than
    /// reading a data word.
    #[test]
    fn rejects_log_without_operation_id_topic() {
        let mut log = bridge_log(op_id(7), 1000, 950, 50);
        log.topics.truncate(1); // topic0 only
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![log], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("operationId is expected in topic1"), "got: {e}");
    }

    /// A full-width id must round-trip — the old u64 decode rejected every
    /// realistic one as "exceeds u64 range".
    #[test]
    fn binds_full_width_operation_id() {
        let p = happy_provider();
        assert!(verify(&p).is_ok(), "a 32-byte operationId must bind");
        // ...and a different one must not.
        let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(9), 1000, 50)
            .unwrap_err()
            .to_string();
        assert!(e.contains("operationId mismatch"), "got: {e}");
    }

    /// Regression guard: an absent id must refuse, not degrade to an unbound
    /// check as it once did.
    #[test]
    fn rejects_when_operation_id_not_supplied() {
        let e = verify_funds_in_event(&happy_provider(), &BRIDGE, 12, &TX, &[], 1000, 50)
            .unwrap_err()
            .to_string();
        assert!(e.contains("must be exactly 32 bytes"), "got: {e}");
    }

    #[test]
    fn still_rejects_amount_mismatch_with_matching_operation_id() {
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(op_id(7), 999, 949, 50)], 100)),
            head: 112,
        };
        let e = verify(&p).unwrap_err().to_string();
        assert!(e.contains("amount mismatch"), "got: {e}");
    }

    /// A wrong-length id is a mis-encoding, not an absent one: refuse.
    #[test]
    fn rejects_malformed_expected_operation_id() {
        let e = verify_funds_in_event(&happy_provider(), &BRIDGE, 12, &TX, &[0xAA; 8], 1000, 50)
            .unwrap_err()
            .to_string();
        assert!(e.contains("must be exactly 32 bytes"), "got: {e}");
    }

    // ---- confirmation-depth rejections ----

    #[test]
    fn rejects_insufficient_depth() {
        // head 111, block 100 -> depth 11 < 12.
        let p = FakeProvider {
            receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 50)], 100)),
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
            receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 50)], 100)),
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

    /// Two matching logs from the pinned contract in one receipt are still
    /// two candidates - refuse rather than guess which authorises the release.
    #[test]
    fn two_logs_from_the_pinned_contract_are_ambiguous() {
        let a = bridge_log(op_id(7), 1000, 950, 50);
        let b = bridge_log(op_id(7), 1000, 950, 50);
        let p = FakeProvider {
            receipt: Some(ReceiptData {
                status_success: true,
                block_number: 100,
                logs: vec![a, b],
            }),
            head: 112,
        };
        let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 1000, 50)
            .unwrap_err()
            .to_string();
        assert!(e.contains("ambiguous"), "unexpected: {e}");
    }

    /// A log from any contract other than the pinned one is ignored - a
    /// look-alike emitter cannot satisfy the deposit check.
    #[test]
    fn unpinned_emitter_is_ignored() {
        let mut log = bridge_log(op_id(7), 1000, 950, 50);
        log.address = OTHER;
        let p = FakeProvider {
            receipt: Some(ReceiptData {
                status_success: true,
                block_number: 100,
                logs: vec![log],
            }),
            head: 112,
        };
        let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 1000, 50)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("no BridgeFundsIn or FundsIn log"),
            "unexpected: {e}"
        );
    }
}
