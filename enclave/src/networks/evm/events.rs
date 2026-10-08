//! In-enclave verification of the EVM `FundsIn` deposit event for an
//! EVM -> RGB `Sign`.
//!
//! An EVM -> RGB `Sign` releases RGB against an EVM deposit. The enclave does
//! not trust the listener `event_valid` / `event_finalized` flags. It
//! gets the deposit receipt over an in-enclave EVM RPC. It checks that the
//! pinned bridge contract emitted a `BridgeFundsIn` log with the claimed
//! amount, at sufficient depth. Each predicate fails closed.
//!
//! Trust boundary: the untrusted host relays the RPC over vsock, but TLS ends
//! inside the enclave with a pinned CA and host. The host can withhold a
//! receipt (fail closed) but cannot forge one. The RPC operator stays trusted.
//!
//! The module does not match the raw log from the listener. It pins the
//! contract from config and decodes the fields (`operationId`,
//! gross/net/commission) itself.
//!
//! `BridgeFundsIn.operationId` and the RGB OpId are different identifiers.
//! For BFA mints, the caller also verifies the receipt's `FundsIn` RGB OpId
//! against the mint transition. Amounts must fit the proto's `u64` fields.
//! Larger values fail (see [`extract_uint256_as_u64`]).

use sha3::{Digest, Keccak256};

use crate::error::{EnclaveError, Result};

/// Reads a uint256 ABI word at a byte offset as u64. Fails if the data is too
/// short or the value is more than u64.
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
/// `IBridge.sol`. A stale signature matches zero logs, and each deposit then
/// reports "no FundsIn log in tx".
///
/// The enclave does not decode `bytes settlementData` (bridge PR #152), but it
/// is part of the signature and thus of `topic0`.
pub(crate) const BRIDGE_FUNDS_IN_SIG: &str =
    "BridgeFundsIn(bytes32,bytes32,address,uint256,uint256,\
     uint256,uint256,uint256,uint256,uint256,string,bytes)";

/// `operationId` is `topic1` (topic0 is the event signature itself).
const BFI_OPERATION_ID_TOPIC: usize = 1;

/// Byte offsets of the NON-INDEXED `BridgeFundsIn` data words (each 32 bytes).
/// Order: senderNonce, amount(gross), netAmount, tokenCommission,
/// nativeCommission, sourceChainId, destinationChainId, <string offset>,
/// <settlementData offset>.
///
/// An older event layout also decodes plausible amounts at these offsets. A
/// test pins topic0 for this reason.
const BFI_AMOUNT_OFF: usize = 32;
const BFI_NET_AMOUNT_OFF: usize = 64;
const BFI_TOKEN_COMMISSION_OFF: usize = 96;
const BFI_DEST_CHAIN_ID_OFF: usize = 192;
/// Word 7: the byte offset of the `string destinationAddress` tail, not the
/// string itself.
const BFI_DEST_ADDRESS_HEAD_OFF: usize = 224;
/// Maximum decoded `destinationAddress` length. `Bridge.sol` caps it at 512
/// on chain. This cap bounds the parse of a relayed receipt. The invoice parser
/// uses the same cap, so the two cannot drift.
pub(crate) const BFI_MAX_DEST_ADDRESS_LEN: usize = 2048;
/// 7 static words + 2 dynamic-tail offset words (`destinationAddress`,
/// `settlementData`) must be present. The `settlementData` tail is not read.
const BFI_MIN_DATA_LEN: usize = 9 * 32;

/// Bridge `FundsIn` signature. The sender and the RGB OpId are indexed; the
/// uint64 amount is the one data word.
pub const FUNDS_IN_SIG: &str = "FundsIn(address,uint256,uint64)";

/// An RGB invoice in the shape the pinned `rgb-invoicing` accepts:
/// `rgb:<contract>/<schema>/<state>/bc:utxob:<seal>`.
///
/// It is outside the test module, so the [`crate::networks::rgb::invoice`]
/// tests parse the same string that this module's tests ABI-encode. Thus the
/// two cannot drift.
#[cfg(test)]
pub(crate) const SAMPLE_INVOICE: &str = "rgb:fuhLYX9G-eC8gDvf-V0XpYFH-ceSafoc-lGutAYq-~SExGU4/\
                                         XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                                         UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP";

/// The beneficiary [`SAMPLE_INVOICE`] names, in the form a confidential
/// recipient leg carries.
#[cfg(all(test, evm_to_rgb))]
pub(crate) const SAMPLE_INVOICE_SEAL: &str =
    "utxob:UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP";

/// One decoded EVM log. It is enclave-local, so no RPC-client types leave this
/// module, and unit tests need no live RPC.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// The transaction receipt fields that the predicate needs.
#[derive(Debug, Clone)]
pub struct ReceiptData {
    /// Post-Byzantium receipt status: `true` == success (`0x1`).
    pub status_success: bool,
    /// Block that contains the tx (for confirmation depth).
    pub block_number: u64,
    pub logs: Vec<LogEntry>,
}

/// Read-only EVM RPC calls that the predicate needs. A trait, so unit tests
/// inject synthetic receipts. [`AlloyEvmClient`] is the production impl.
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

/// `topic0` of the two events that select logs. Hashed once, because each log
/// uses them and the BFA path loops over a full mint ancestry.
static BRIDGE_FUNDS_IN_TOPIC0: std::sync::LazyLock<[u8; 32]> =
    std::sync::LazyLock::new(|| event_topic0(BRIDGE_FUNDS_IN_SIG));
#[cfg(feature = "bfa-validation")]
static FUNDS_IN_TOPIC0: std::sync::LazyLock<[u8; 32]> =
    std::sync::LazyLock::new(|| event_topic0(FUNDS_IN_SIG));

/// What a verified `BridgeFundsIn` deposit authorises. Only the fields that
/// later stages bind. [`verify_funds_in_event`] checks the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(evm_to_rgb)]
pub struct VerifiedFundsIn {
    /// Verbatim from the log. For an RGB destination this is the user's
    /// invoice, which the send-RGB recipient bind parses.
    pub destination_address: String,
}

/// Verifies the `FundsIn` deposit for an EVM -> RGB `Sign`.
///
/// Fails closed on: a missing or failed receipt, no matching log, an ambiguous
/// match, a field mismatch, an on-chain value above `u64`, or low confirmation
/// depth. The caller then refuses to sign.
///
/// `bridge_contract` and `min_confirmations` come from PINNED config, never the
/// request. `expected_*` are the listener request fields that this function
/// checks against the chain.
///
/// `expected_operation_id` is mandatory: exactly 32 bytes, or refuse. Empty is an
/// error, not a skipped comparison.
#[allow(clippy::too_many_arguments)]
#[cfg(evm_to_rgb)]
pub fn verify_funds_in_event(
    provider: &dyn EvmReceiptProvider,
    bridge_contract: &[u8; 20],
    min_confirmations: u64,
    evm_tx_hash: &[u8; 32],
    expected_operation_id: &[u8],
    expected_gross_amount: u64,
    expected_commission: u64,
) -> Result<VerifiedFundsIn> {
    if expected_operation_id.len() != 32 {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn expected operationId must be exactly 32 bytes (the contract-derived \
             BridgeFundsIn.operationId from indexed topic1), got {}",
            expected_operation_id.len()
        )));
    }
    // 1/2. The receipt must exist and the deposit tx must have succeeded.
    let receipt = fetch_successful_receipt(provider, evm_tx_hash)?;

    // 3/4. Find the one log from the pinned bridge contract. No fallback to
    //      plain `FundsIn`: it carries an RGB OpId, a different id-space.
    //      Two deposits in one tx refuse.
    let log = select_unique_log(
        &receipt,
        bridge_contract,
        &BRIDGE_FUNDS_IN_TOPIC0,
        "BridgeFundsIn",
        evm_tx_hash,
    )?;

    // 5/6/7. Bind operationId and amounts. The log comes from the pinned
    //        bridge contract, so later stages bind authenticated evidence.
    let BridgeFundsInRecord {
        operation_id,
        gross,
        net,
        commission,
        destination_address,
        ..
    } = decode_bridge_funds_in(log)?;

    if expected_operation_id != operation_id.as_slice() {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn operationId mismatch: on-chain 0x{} != request 0x{}",
            hex::encode(operation_id),
            hex::encode(expected_operation_id)
        )));
    }

    check_eq("amount", gross, expected_gross_amount)?;
    check_eq("tokenCommission", commission, expected_commission)?;

    // Bounded, not equal. The Bridge credits the measured balance delta and
    // `amount` stays nominal, so a fee-on-transfer token nets less
    // (`Bridge` fee-on-transfer balance delta). Only a `net` that is too high is unsafe.
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

    // 8. Confirmation depth against the current head.
    let depth = check_confirmation_depth(provider, receipt.block_number, min_confirmations)?;

    tracing::info!(
        tx = %hex::encode(evm_tx_hash),
        operation_id = %hex::encode(operation_id),
        depth,
        "FundsIn event independently verified in-enclave"
    );
    Ok(VerifiedFundsIn {
        destination_address,
    })
}

/// The fields of one `BridgeFundsIn` log from the pinned emitter. The burn
/// direction reads only the id and net amount. It decodes the full log, so
/// both images refuse a malformed one.
#[cfg_attr(not(evm_to_rgb), allow(dead_code))]
struct BridgeFundsInRecord {
    operation_id: [u8; 32],
    gross: u64,
    net: u64,
    commission: u64,
    dest_chain_id: u64,
    destination_address: String,
}

/// Decodes a `BridgeFundsIn` log. The indexed `operationId` is in topic1. All
/// other fields are in `data`. Callers must first select `log` by pinned
/// emitter and topic0.
fn decode_bridge_funds_in(log: &LogEntry) -> Result<BridgeFundsInRecord> {
    let operation_id = *log
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
    Ok(BridgeFundsInRecord {
        operation_id,
        gross: decode_u64_word(&log.data, BFI_AMOUNT_OFF, "amount")?,
        net: decode_u64_word(&log.data, BFI_NET_AMOUNT_OFF, "netAmount")?,
        commission: decode_u64_word(&log.data, BFI_TOKEN_COMMISSION_OFF, "tokenCommission")?,
        dest_chain_id: decode_u64_word(&log.data, BFI_DEST_CHAIN_ID_OFF, "destinationChainId")?,
        destination_address: decode_abi_string(
            &log.data,
            BFI_DEST_ADDRESS_HEAD_OFF,
            "destinationAddress",
        )?,
    })
}

/// Reads a 32-byte ABI word at `offset` in `data` as a `u64`, with a field
/// name in the error. A value above `u64` is rejected, not truncated.
fn decode_u64_word(data: &[u8], offset: usize, field: &str) -> Result<u64> {
    extract_uint256_as_u64(data, offset).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "FundsIn {field}: {e} (the proto carries this field as u64; a larger on-chain value \
             is rejected, never truncated)"
        ))
    })
}

/// Decodes the ABI dynamic `string` whose head word is at `head_off`: an
/// offset into `data`, then a length word and the bytes, padded to 32.
///
/// Each bound is checked. A forged offset or length must fail, not read
/// adjacent memory or panic.
fn decode_abi_string(data: &[u8], head_off: usize, field: &str) -> Result<String> {
    let err = |m: String| EnclaveError::CrossCheck(format!("BridgeFundsIn {field}: {m}"));

    let word_at = |off: usize, what: &str| -> Result<usize> {
        let raw = extract_uint256_as_u64(data, off).map_err(|e| err(e.to_string()))?;
        usize::try_from(raw).map_err(|_| err(format!("{what} exceeds usize")))
    };

    let offset = word_at(head_off, "tail offset")?;
    let len_off = offset
        .checked_add(32)
        .ok_or_else(|| err("tail offset overflow".into()))?;
    // This check keeps `offset + 32` in range for the read below.
    if len_off > data.len() {
        return Err(err(format!(
            "tail offset {offset} is past the {} bytes of log data",
            data.len()
        )));
    }
    let len = word_at(offset, "tail length")?;
    if len > BFI_MAX_DEST_ADDRESS_LEN {
        return Err(err(format!(
            "tail length {len} exceeds the {BFI_MAX_DEST_ADDRESS_LEN}-byte cap"
        )));
    }
    let end = len_off
        .checked_add(len)
        .ok_or_else(|| err("tail length overflow".into()))?;
    if end > data.len() {
        return Err(err(format!(
            "tail claims {len} bytes at {len_off} but the log data is {} bytes",
            data.len()
        )));
    }
    String::from_utf8(data[len_off..end].to_vec())
        .map_err(|_| err("tail is not valid UTF-8".into()))
}

#[cfg(evm_to_rgb)]
fn check_eq(field: &str, got: u64, want: u64) -> Result<()> {
    if got != want {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn {field} mismatch: on-chain {got} != request {want}"
        )));
    }
    Ok(())
}

/// Gets the receipt for `evm_tx_hash` and requires a successful tx. Both event
/// predicates use it: a withheld or reverted tx authorises nothing.
fn fetch_successful_receipt(
    provider: &dyn EvmReceiptProvider,
    evm_tx_hash: &[u8; 32],
) -> Result<ReceiptData> {
    let receipt = provider
        .get_transaction_receipt(evm_tx_hash)?
        .ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
            "FundsIn receipt not found for tx 0x{} (not mined, or host withheld it) - refusing \
             to sign",
            hex::encode(evm_tx_hash)
        ))
        })?;
    if !receipt.status_success {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn tx 0x{} reverted (receipt status != success)",
            hex::encode(evm_tx_hash)
        )));
    }
    Ok(receipt)
}

/// The one log in `receipt` from `emitter` with `topic0`. A look-alike
/// contract cannot match. Two matches are two deposits, so zero or many refuse.
fn select_unique_log<'a>(
    receipt: &'a ReceiptData,
    emitter: &[u8; 20],
    topic0: &[u8; 32],
    event: &str,
    evm_tx_hash: &[u8; 32],
) -> Result<&'a LogEntry> {
    let candidates: Vec<&LogEntry> = receipt
        .logs
        .iter()
        .filter(|log| log.address == *emitter && log.topics.first().is_some_and(|t| t == topic0))
        .collect();
    if candidates.len() > 1 {
        return Err(EnclaveError::CrossCheck(format!(
            "ambiguous: multiple {event} logs from bridge contract 0x{} in tx 0x{} - \
             refusing to guess which authorises this release",
            hex::encode(emitter),
            hex::encode(evm_tx_hash)
        )));
    }
    candidates.first().copied().ok_or_else(|| {
        EnclaveError::CrossCheck(format!(
            "no {event} log from bridge contract 0x{} in tx 0x{}",
            hex::encode(emitter),
            hex::encode(evm_tx_hash)
        ))
    })
}

/// Depth is `head - receipt_block`; the receipt block itself is not counted.
/// Receipt and head come from separate RPC calls. A head below the receipt
/// height is rejected. This does not detect a reorg at the same or greater
/// height, because no block hash is compared. The RPC provider remains trusted.
fn check_confirmation_depth(
    provider: &dyn EvmReceiptProvider,
    receipt_block: u64,
    min_confirmations: u64,
) -> Result<u64> {
    let head = provider.get_block_number()?;
    let depth = head.checked_sub(receipt_block).ok_or_else(|| {
        EnclaveError::CrossCheck(format!(
            "FundsIn receipt block {receipt_block} is above RPC head {head} (reorg?) - refusing \
             to sign"
        ))
    })?;
    if depth < min_confirmations {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn not final: depth {depth} < required {min_confirmations} (receipt block \
             {receipt_block}, head {head})"
        )));
    }
    Ok(depth)
}

/// Decodes a `FundsIn` log, binds it to `expected_rgb_opid`, and returns the amount.
///
/// Only one layout is accepted: topic0, the indexed sender and the indexed
/// `rgbOpId` (the OpId bytes as a big-endian uint256), then the amount word.
#[cfg(feature = "bfa-validation")]
fn decode_funds_in(log: &LogEntry, expected_rgb_opid: &[u8; 32]) -> Result<u64> {
    if log.topics.first() != Some(&*FUNDS_IN_TOPIC0) {
        return Err(EnclaveError::CrossCheck(
            "log is not a FundsIn event".into(),
        ));
    }
    if log.topics.len() != 3 || log.data.len() != 32 {
        return Err(EnclaveError::CrossCheck(
            "unexpected FundsIn event layout".into(),
        ));
    }
    let rgb_op_id = log.topics[2];
    let amount = extract_uint256_as_u64(&log.data, 0)?;
    if &rgb_op_id != expected_rgb_opid {
        return Err(EnclaveError::CrossCheck(format!(
            "FundsIn rgbOpId mismatch: on-chain 0x{} != consignment 0x{}",
            hex::encode(rgb_op_id),
            hex::encode(expected_rgb_opid)
        )));
    }
    Ok(amount)
}

/// One verified EVM deposit behind a BFA mint.
///
/// `minted` is the maximum RGB issue: consensus checks the mint against this
/// `FundsIn` amount. `operation_id` / `net_amount` are the `BridgeFundsIn`
/// record that the settlement module stored. Thus they are the only pair that
/// a `fundsOut.settlementData` can cite for this deposit.
#[cfg(feature = "bfa-validation")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLock {
    /// The mint that this lock backs, named by the caller and confirmed by the
    /// `FundsIn` log.
    pub mint_opid: [u8; 32],
    pub minted: u64,
    pub operation_id: [u8; 32],
    pub net_amount: u64,
}

/// `Bridge.RGB_MINT_DEPOSIT_TYPEHASH` preimage; bridge-utexo derives the same id.
#[cfg(feature = "bfa-validation")]
const RGB_MINT_DEPOSIT_TYPEHASH_STR: &str = "UtexoRgbMintDeposit(address bridge,uint256 chainId,\
     address token,uint256 rgbNetwork,uint256 rgbOpId,uint256 netAmount)";

/// The `operationId` of the one deposit that can back a mint. Every input is
/// pinned or in the consignment, so no caller or RPC chooses it (finding 47).
#[cfg(feature = "bfa-validation")]
pub fn rgb_mint_deposit_id(
    cfg: &crate::config::BridgeConfig,
    mint_opid: &[u8; 32],
    minted: u64,
) -> Result<[u8; 32]> {
    if cfg.token_contract == [0u8; 20] || cfg.chain_id == 0 {
        return Err(EnclaveError::CrossCheck(
            "TOKEN_CONTRACT and EVM_CHAIN_ID must be pinned to derive a mint's deposit id - \
             refusing to sign"
                .into(),
        ));
    }
    if minted == 0 {
        return Err(EnclaveError::CrossCheck(format!(
            "BFA mint 0x{} mints nothing, so no deposit can back it",
            hex::encode(mint_opid)
        )));
    }

    let word = |value: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&value.to_be_bytes());
        w
    };
    let address = |a: &[u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a);
        w
    };
    let mut hasher = Keccak256::new();
    hasher.update(Keccak256::digest(RGB_MINT_DEPOSIT_TYPEHASH_STR.as_bytes()));
    hasher.update(address(&cfg.funds_in_contract));
    hasher.update(word(cfg.chain_id));
    hasher.update(address(&cfg.token_contract));
    hasher.update(word(crate::networks::evm::RGB_CHAIN_ID));
    hasher.update(mint_opid);
    hasher.update(word(minted));
    Ok(hasher.finalize().into())
}

/// The lock of a mint: its deposit id, with the minted units as net amount.
#[cfg(feature = "bfa-validation")]
pub fn derived_lock(
    cfg: &crate::config::BridgeConfig,
    mint_opid: [u8; 32],
    minted: u64,
) -> Result<VerifiedLock> {
    Ok(VerifiedLock {
        mint_opid,
        minted,
        operation_id: rgb_mint_deposit_id(cfg, &mint_opid, minted)?,
        net_amount: minted,
    })
}

/// Verifies the `FundsIn` lock that a BFA mint commits to. Returns the deposit.
///
/// Same fail-closed checks as [`verify_funds_in_event`] (receipt, success,
/// pinned emitter, depth), but bound to the RGB OpId, not to the bridge
/// `operationId` (a different id-space). `funds_in_contract` and
/// `min_confirmations` come from PINNED config, never the request. `rgb_opid`
/// comes from the consignment and only selects the log that must exist.
///
/// The receipt must also have exactly one `BridgeFundsIn` from the pinned
/// contract. A later `fundsOut` must cite its `(operationId, netAmount)` in
/// `settlementData` (see `crosscheck::validate_funds_out_settlement`).
#[cfg(feature = "bfa-validation")]
pub fn verify_rgb_funds_in(
    provider: &dyn EvmReceiptProvider,
    funds_in_contract: &[u8; 20],
    min_confirmations: u64,
    evm_tx_hash: &[u8; 32],
    rgb_opid: &[u8; 32],
) -> Result<VerifiedLock> {
    let receipt = fetch_successful_receipt(provider, evm_tx_hash)?;
    let log = select_unique_log(
        &receipt,
        funds_in_contract,
        &FUNDS_IN_TOPIC0,
        "FundsIn",
        evm_tx_hash,
    )?;
    let minted = decode_funds_in(log, rgb_opid)?;

    let bridge_log = select_unique_log(
        &receipt,
        funds_in_contract,
        &BRIDGE_FUNDS_IN_TOPIC0,
        "BridgeFundsIn",
        evm_tx_hash,
    )?;
    let BridgeFundsInRecord {
        operation_id,
        net: net_amount,
        dest_chain_id,
        ..
    } = decode_bridge_funds_in(bridge_log)?;
    // FundsIn has no chain field, so the deposit's chain comes from BridgeFundsIn.
    if dest_chain_id != crate::networks::evm::RGB_CHAIN_ID {
        return Err(EnclaveError::CrossCheck(format!(
            "BridgeFundsIn destinationChainId {dest_chain_id} != RGB network id {}",
            crate::networks::evm::RGB_CHAIN_ID
        )));
    }

    let depth = check_confirmation_depth(provider, receipt.block_number, min_confirmations)?;

    tracing::info!(
        tx = %hex::encode(evm_tx_hash),
        rgb_opid = %hex::encode(rgb_opid),
        operation_id = %hex::encode(operation_id),
        minted,
        net_amount,
        depth,
        "FundsIn lock for a BFA mint independently verified in-enclave"
    );
    Ok(VerifiedLock {
        mint_opid: *rgb_opid,
        minted,
        operation_id,
        net_amount,
    })
}

/// A BFA asset names its bridge contract in genesis. Only the pinned contract
/// can authorise a mint that this federation signs.
#[cfg(feature = "bfa-validation")]
pub fn check_bridge_location(location: &str, pinned: &[u8; 20]) -> Result<()> {
    let hex_addr = location.strip_prefix("0x").unwrap_or(location);
    let mut addr = [0u8; 20];
    hex::decode_to_slice(hex_addr, &mut addr).map_err(|e| {
        EnclaveError::CrossCheck(format!("invalid bridge location {location:?}: {e}"))
    })?;
    if &addr != pinned {
        return Err(EnclaveError::CrossCheck(format!(
            "asset bridge location 0x{} is not the pinned funds-in contract 0x{}",
            hex::encode(addr),
            hex::encode(pinned)
        )));
    }
    Ok(())
}

/// Hard per-call limit for one EVM JSON-RPC round-trip. Without it, a hung RPC
/// blocks the worker thread forever: `block_on` has no deadline, and
/// alloy/reqwest set no default timeout. A client-side timeout does not cancel
/// an in-flight `block_on`, so a few stalls can block all workers. 15s covers a
/// healthy fetch through loopback -> vsock -> the RPC.
const EVM_RPC_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Production [`EvmReceiptProvider`]: an alloy JSON-RPC client over the
/// in-enclave loopback that a vsock forwarder tunnels to the EVM RPC. alloy is
/// async, so the launch builds a single-worker tokio runtime, and each call uses
/// `block_on`. One worker is sufficient and keeps the type `Send + Sync` for
/// the shared `ServerContext`.
pub struct AlloyEvmClient {
    runtime: tokio::runtime::Runtime,
    provider: alloy::providers::RootProvider,
}

impl AlloyEvmClient {
    /// Builds a client that ends TLS inside the enclave. It trusts only the
    /// pinned CA, checks the certificate against the pinned host, and sends
    /// the connection to the loopback forwarder. The host relays ciphertext.
    pub fn with_pinned_tls(tls: &crate::config::EvmRpcTls) -> Result<Self> {
        use alloy::transports::http::reqwest;
        let err = |e: reqwest::Error| {
            EnclaveError::CrossCheck(format!("evm-rpc: failed to build the TLS client: {e}"))
        };
        let client = reqwest::Client::builder()
            .https_only(true)
            .tls_certs_only([reqwest::Certificate::from_der(&tls.ca_der).map_err(err)?])
            // The URL port wins over this port. The forwarder listens on the
            // TLS port, so the Host header carries the real port.
            .resolve(&tls.host, ([127, 0, 0, 1], 0).into())
            .no_proxy()
            // Only the pinned host can redirect. It could still point at a
            // peer the CA never certified.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(EVM_RPC_CALL_TIMEOUT)
            .build()
            .map_err(err)?;
        let url = format!("https://{}:{}/", tls.host, tls.tls_port)
            .parse()
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("evm-rpc: invalid host {:?}: {e}", tls.host))
            })?;
        Ok(Self {
            runtime: Self::runtime()?,
            provider: alloy::providers::ProviderBuilder::default().connect_reqwest(client, url),
        })
    }

    fn runtime() -> Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("evm-rpc: failed to build tokio runtime: {e}"))
            })
    }
}

impl EvmReceiptProvider for AlloyEvmClient {
    fn get_transaction_receipt(&self, tx_hash: &[u8; 32]) -> Result<Option<ReceiptData>> {
        use alloy::providers::Provider;
        let hash = alloy::primitives::B256::from_slice(tx_hash);
        // Outer `?`: the deadline passed (fail closed, free the worker). Inner
        // `?`: the RPC failed. Build the `timeout` future INSIDE the async
        // block. As a `block_on` argument it panics with "there is no reactor
        // running", and `panic = "abort"` stops the enclave.
        let receipt = self
            .runtime
            .block_on(async {
                tokio::time::timeout(
                    EVM_RPC_CALL_TIMEOUT,
                    self.provider.get_transaction_receipt(hash),
                )
                .await
            })
            .map_err(|_elapsed| {
                EnclaveError::CrossCheck(format!(
                    "evm-rpc: eth_getTransactionReceipt timed out after {}s (host RPC path stalled) \
                     - refusing to sign",
                    EVM_RPC_CALL_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("evm-rpc: eth_getTransactionReceipt failed: {e}"))
            })?;
        receipt.map(map_alloy_receipt).transpose()
    }

    fn get_block_number(&self) -> Result<u64> {
        use alloy::providers::Provider;
        // Build the `timeout` future inside the async block. See
        // `get_transaction_receipt`.
        self.runtime
            .block_on(async {
                tokio::time::timeout(EVM_RPC_CALL_TIMEOUT, self.provider.get_block_number()).await
            })
            .map_err(|_elapsed| {
                EnclaveError::CrossCheck(format!(
                    "evm-rpc: eth_blockNumber timed out after {}s (host RPC path stalled) - \
                     refusing to sign",
                    EVM_RPC_CALL_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| EnclaveError::CrossCheck(format!("evm-rpc: eth_blockNumber failed: {e}")))
    }
}

/// Maps an alloy receipt into the enclave-local [`ReceiptData`], so no alloy
/// types reach the predicate.
///
/// Fails closed on a missing `block_number`. A default of `0` makes
/// `head - block_number` very deep, so finality passes. A finality check must
/// never default to "deep".
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

#[cfg(test)]
mod tests;
