//! Gas-key transaction shape allowlist.
//!
//! The gas key (`m/44'/60'/0'/0/1`) pays L1 gas for the bridge's Ethereum
//! transactions. The enclave gets the unsigned transaction preimage, not a
//! digest. It:
//!   1. decodes it as EIP-1559 (type `0x02`) or legacy EIP-155 with a strict
//!      canonical RLP decoder;
//!   2. computes the signing hash itself (`keccak256(preimage)`);
//!   3. enforces the operator's attested allowlist: chain id == `EVM_CHAIN_ID`,
//!      `to` == `GAS_TX_ALLOWED_TO`, `value == 0`, `gasLimit` <=
//!      `GAS_TX_MAX_GAS_LIMIT`, per-gas fees <= `GAS_TX_MAX_FEE_PER_GAS`, and a
//!      leading 4-byte selector in `GAS_TX_ALLOWED_SELECTORS`.
//!
//! Carve-out to `value == 0`: the payable `lzFundsOutCall` forwards the
//! LayerZero messaging fee. Allowed only when the selector is `lzFundsOutCall`,
//! `to` == pinned `EVM_PROXY_CONTRACT_ADDRESS`, and `value` <= `GAS_TX_MAX_VALUE_WEI`. The
//! selector must also be in `GAS_TX_ALLOWED_SELECTORS`.
//!
//! Any unset pin fails the path closed. The attestation `user_data`
//! commitment includes the whole rule, via [`crate::policy::SecurityPolicy`].
//!
//! Not bounded here: total fee spend across many txs (validation is
//! stateless). The LayerZero fee is not bound to its release.
//! EIP-712 typed data is refused: the gas key signs RLP L1 transactions.

use sha3::{Digest, Keccak256};

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::proto::SignRawDigestRequest;

/// EIP-2718 type byte for an EIP-1559 (dynamic-fee) transaction.
const TX_TYPE_EIP1559: u8 = 0x02;

/// Selector of the **on-chain** `MultisigProxy.lzFundsOutCall` (params as one
/// struct). It is the only proxy method that can carry native value.
///
/// NOT [`super::validation::LZ_FUNDS_OUT_SELECTOR`], the enclave wire format.
/// It is a literal because keccak is not const here.
/// `onchain_lz_selector_matches_its_signature` pins it.
const ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR: [u8; 4] = [0x8f, 0x6b, 0x30, 0x31];

/// Maximum RLP nesting depth. A real transaction reaches depth ~4 (tx list ->
/// accessList -> entry -> storage-key list). The cap stops deep input from
/// exhausting the stack.
const MAX_RLP_DEPTH: usize = 8;

fn reject(msg: impl Into<String>) -> EnclaveError {
    EnclaveError::CrossCheck(msg.into())
}

/// A decoded RLP item: a byte string or a list of items. It borrows from the
/// input buffer.
enum Rlp<'a> {
    Str(&'a [u8]),
    List(Vec<Rlp<'a>>),
}

/// The fields of an unsigned gas transaction that the allowlist inspects.
struct GasTx<'a> {
    chain_id: u64,
    to: [u8; 20],
    /// Wei. A number, not a zero flag, because the LayerZero carve-out
    /// compares it to a pinned ceiling.
    value: u128,
    /// `gasLimit`, bounded by `GAS_TX_MAX_GAS_LIMIT`.
    gas_limit: u64,
    /// `maxFeePerGas` (EIP-1559) or `gasPrice` (legacy), bounded by
    /// `GAS_TX_MAX_FEE_PER_GAS`.
    max_fee_per_gas: u128,
    /// `maxPriorityFeePerGas` (EIP-1559), or `gasPrice` for legacy. Bounded by
    /// `GAS_TX_MAX_FEE_PER_GAS`.
    max_priority_fee_per_gas: u128,
    /// Leading 4-byte function selector, or `None` for empty calldata (which
    /// `validate_gas_tx_request` refuses).
    selector: Option<[u8; 4]>,
    /// The full calldata, prefix-matched by the LayerZero carve-out.
    data: &'a [u8],
}

/// Validates a gas-key `SignRawDigest` request against the operator pins.
/// Returns the digest to sign: `keccak256` of the preimage, computed here and
/// not taken from the wire.
///
/// Fails closed (`CrossCheck`) on: no preimage, bad or non-canonical RLP,
/// unsupported envelope, unpinned chain id / destination / gas cap / fee cap,
/// chain id or destination mismatch, contract creation, a non-zero value that
/// fails the LayerZero carve-out, `gasLimit` or fee above the cap, or a
/// selector not in the operator allowlist.
pub fn validate_gas_tx_request(req: &SignRawDigestRequest, cfg: &BridgeConfig) -> Result<[u8; 32]> {
    if req.unsigned_tx.is_empty() {
        return Err(reject(
            "gas tx signing requires the unsigned transaction preimage (unsigned_tx); \
             refusing to sign an opaque digest",
        ));
    }

    let tx = parse_gas_tx(&req.unsigned_tx)?;

    // Chain-id pin: blocks cross-chain replay of a gas tx.
    if cfg.chain_id == 0 {
        return Err(reject(
            "gas tx: chain_id not pinned (EVM_CHAIN_ID unset) - refusing to sign",
        ));
    }
    if tx.chain_id != cfg.chain_id {
        return Err(reject(format!(
            "gas tx: chain_id {} != pinned {}",
            tx.chain_id, cfg.chain_id
        )));
    }

    // Destination pin: stops a redirect-to-attacker drain.
    let allowed = cfg.gas_tx_allowed_to.ok_or_else(|| {
        reject(
            "gas tx: destination not pinned (GAS_TX_ALLOWED_TO unset) - refusing to sign \
             (this enclave will not sign gas transactions until the allowed destination is pinned)",
        )
    })?;
    if tx.to != allowed {
        return Err(reject(format!(
            "gas tx: destination {} != pinned {}",
            hex::encode(tx.to),
            hex::encode(allowed)
        )));
    }

    // A non-zero value is a drain vector. Refused by default; the LayerZero
    // fee carve-out needs all three legs below.
    if tx.value != 0 {
        // (a) Payable entrypoint only.
        if !tx.data.starts_with(&ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR) {
            return Err(reject(
                "gas tx: value must be 0 unless calldata is the payable lzFundsOutCall",
            ));
        }

        // (b) The proxy itself, not just GAS_TX_ALLOWED_TO, which may be an
        // EOA that ignores calldata.
        if cfg.bridge_contract == [0u8; 20] {
            return Err(reject(
                "gas tx: non-zero value requires a pinned EVM_PROXY_CONTRACT_ADDRESS to check the \
                 destination against (unset) - refusing to sign",
            ));
        }
        if tx.to != cfg.bridge_contract {
            return Err(reject(format!(
                "gas tx: non-zero value is only allowed to the pinned MultisigProxy {}, not {}",
                hex::encode(cfg.bridge_contract),
                hex::encode(tx.to)
            )));
        }

        // (c) Bounded: nothing on-chain constrains the fee.
        let max = cfg.gas_tx_max_value_wei.ok_or_else(|| {
            reject(
                "gas tx: non-zero value requires a pinned ceiling (GAS_TX_MAX_VALUE_WEI unset) \
                 - refusing to sign",
            )
        })?;
        if tx.value > max {
            return Err(reject(format!(
                "gas tx: value {} exceeds pinned GAS_TX_MAX_VALUE_WEI {}",
                tx.value, max
            )));
        }
    }

    // Fee/gas ceilings: a signed gas tx can burn at most
    // `gasLimit * maxFeePerGas`. Unset caps fail closed.
    if cfg.gas_tx_max_gas_limit == 0 {
        return Err(reject(
            "gas tx: gas-limit cap not pinned (GAS_TX_MAX_GAS_LIMIT unset) - refusing to sign",
        ));
    }
    if cfg.gas_tx_max_fee_per_gas == 0 {
        return Err(reject(
            "gas tx: fee cap not pinned (GAS_TX_MAX_FEE_PER_GAS unset) - refusing to sign",
        ));
    }
    if tx.gas_limit > cfg.gas_tx_max_gas_limit {
        return Err(reject(format!(
            "gas tx: gasLimit {} exceeds pinned cap {}",
            tx.gas_limit, cfg.gas_tx_max_gas_limit
        )));
    }
    if tx.max_fee_per_gas > cfg.gas_tx_max_fee_per_gas {
        return Err(reject(format!(
            "gas tx: maxFeePerGas {} exceeds pinned cap {}",
            tx.max_fee_per_gas, cfg.gas_tx_max_fee_per_gas
        )));
    }
    if tx.max_priority_fee_per_gas > cfg.gas_tx_max_fee_per_gas {
        return Err(reject(format!(
            "gas tx: maxPriorityFeePerGas {} exceeds pinned cap {}",
            tx.max_priority_fee_per_gas, cfg.gas_tx_max_fee_per_gas
        )));
    }

    // Each gas tx must call an allowlisted selector on the pinned destination.
    // Empty calldata is refused because it calls `fallback()` / `receive()`.
    // An empty allowlist refuses all gas-tx signing.
    match tx.selector {
        Some(selector) => {
            if !cfg.gas_tx_allowed_selectors.contains(&selector) {
                return Err(reject(format!(
                    "gas tx: calldata selector 0x{} is not in the operator allowlist \
                     (GAS_TX_ALLOWED_SELECTORS)",
                    hex::encode(selector)
                )));
            }
        }
        None => {
            return Err(reject(
                "gas tx: empty calldata is not permitted - a gas tx must invoke an \
                 allowlisted function selector on the pinned destination; a bare call \
                 would still invoke the destination contract's fallback/receive, which \
                 is outside the allowlist",
            ));
        }
    }

    // The signed digest comes from the validated preimage. A wire digest, if
    // present, must agree.
    let digest: [u8; 32] = Keccak256::digest(&req.unsigned_tx).into();
    if !req.digest.is_empty() && req.digest.as_slice() != digest {
        return Err(reject(
            "gas tx: supplied digest does not match keccak256(unsigned_tx)",
        ));
    }
    Ok(digest)
}

/// Decodes an unsigned gas transaction preimage into the allowlist fields.
/// Accepts only EIP-1559 (`0x02 || rlp([...9])`) and legacy EIP-155
/// (`rlp([...9])`) unsigned bodies.
fn parse_gas_tx(raw: &[u8]) -> Result<GasTx<'_>> {
    let first = *raw
        .first()
        .ok_or_else(|| reject("gas tx: empty unsigned_tx"))?;

    if first == TX_TYPE_EIP1559 {
        // 0x02 prefix, then a 9-field RLP list:
        // [chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList]
        let body = decode_canonical(&raw[1..])?;
        let items = as_list(&body)?;
        if items.len() != 9 {
            return Err(reject(format!(
                "gas tx: EIP-1559 unsigned tx must have 9 fields, got {}",
                items.len()
            )));
        }
        Ok(GasTx {
            chain_id: scalar_u64(&items[0])?,
            max_priority_fee_per_gas: scalar_u128(&items[2])?,
            max_fee_per_gas: scalar_u128(&items[3])?,
            gas_limit: scalar_u64(&items[4])?,
            to: as_address(&items[5])?,
            value: scalar_u128(&items[6])?,
            selector: as_calldata_selector(&items[7])?,
            data: as_bytes(&items[7])?,
        })
    } else if first >= 0xc0 {
        // Legacy EIP-155 unsigned signing body, a 9-field RLP list:
        // [nonce, gasPrice, gas, to, value, data, chainId, 0, 0]
        let body = decode_canonical(raw)?;
        let items = as_list(&body)?;
        if items.len() != 9 {
            return Err(reject(format!(
                "gas tx: legacy EIP-155 unsigned tx must have 9 fields, got {}",
                items.len()
            )));
        }
        // The trailer must be (chainId, 0, 0). Non-zero r/s means a signed
        // tx, not an unsigned signing body.
        if !scalar_is_zero(&items[7])? || !scalar_is_zero(&items[8])? {
            return Err(reject(
                "gas tx: legacy EIP-155 trailer must be (chainId, 0, 0) - \
                 refusing a signed or pre-EIP-155 transaction",
            ));
        }
        // Legacy has one `gasPrice`. The cap check uses it as both the max fee
        // and the priority fee.
        let gas_price = scalar_u128(&items[1])?;
        Ok(GasTx {
            chain_id: scalar_u64(&items[6])?,
            max_priority_fee_per_gas: gas_price,
            max_fee_per_gas: gas_price,
            gas_limit: scalar_u64(&items[2])?,
            to: as_address(&items[3])?,
            value: scalar_u128(&items[4])?,
            selector: as_calldata_selector(&items[5])?,
            data: as_bytes(&items[5])?,
        })
    } else {
        Err(reject(format!(
            "gas tx: unsupported envelope (first byte 0x{:02x}); only EIP-1559 (0x02) \
             and legacy EIP-155 transactions are accepted",
            first
        )))
    }
}

// Minimal, defensive RLP decoder
//
// Strict, because it decodes attacker bytes inside the TEE. It bounds-checks
// every read and rejects non-canonical encodings. Exactly one top-level item
// must use the whole input.

/// Decodes exactly one top-level RLP item. It must use the whole buffer.
fn decode_canonical(buf: &[u8]) -> Result<Rlp<'_>> {
    let (item, used) = decode_one(buf, 0)?;
    if used != buf.len() {
        return Err(reject("rlp: trailing bytes after top-level item"));
    }
    Ok(item)
}

/// Decodes one RLP item from the front of `buf`. Returns the item and the
/// number of bytes used.
fn decode_one(buf: &[u8], depth: usize) -> Result<(Rlp<'_>, usize)> {
    if depth > MAX_RLP_DEPTH {
        return Err(reject("rlp: nesting too deep"));
    }
    let b0 = *buf
        .first()
        .ok_or_else(|| reject("rlp: unexpected end of input"))?;
    match b0 {
        // Single byte in [0x00, 0x7f]: the byte is its own value.
        0x00..=0x7f => Ok((Rlp::Str(&buf[..1]), 1)),

        // Short string: length 0..=55 in the header byte.
        0x80..=0xb7 => {
            let len = (b0 - 0x80) as usize;
            let end = 1 + len;
            if buf.len() < end {
                return Err(reject("rlp: short string truncated"));
            }
            let payload = &buf[1..end];
            // A single byte < 0x80 must be encoded as itself, not as 0x81 xx.
            if len == 1 && payload[0] < 0x80 {
                return Err(reject("rlp: non-canonical single-byte string"));
            }
            Ok((Rlp::Str(payload), end))
        }

        // Long string: header carries the length-of-length.
        0xb8..=0xbf => {
            let (len, header) = read_long_len(buf, b0 - 0xb7)?;
            let end = header
                .checked_add(len)
                .ok_or_else(|| reject("rlp: length overflow"))?;
            if buf.len() < end {
                return Err(reject("rlp: long string truncated"));
            }
            Ok((Rlp::Str(&buf[header..end]), end))
        }

        // Short list: payload 0..=55 bytes of concatenated items.
        0xc0..=0xf7 => {
            let len = (b0 - 0xc0) as usize;
            let end = 1 + len;
            if buf.len() < end {
                return Err(reject("rlp: short list truncated"));
            }
            let items = decode_list(&buf[1..end], depth)?;
            Ok((Rlp::List(items), end))
        }

        // Long list: header carries the length-of-length.
        0xf8..=0xff => {
            let (len, header) = read_long_len(buf, b0 - 0xf7)?;
            let end = header
                .checked_add(len)
                .ok_or_else(|| reject("rlp: length overflow"))?;
            if buf.len() < end {
                return Err(reject("rlp: long list truncated"));
            }
            let items = decode_list(&buf[header..end], depth)?;
            Ok((Rlp::List(items), end))
        }
    }
}

/// Reads the big-endian length after a long-string/long-list header byte.
/// `len_of_len` is in 1..=8. Returns `(length, 1 + len_of_len)`. Canonical
/// form: no leading-zero length bytes, and the length must be > 55 (else the
/// short form applies).
fn read_long_len(buf: &[u8], len_of_len: u8) -> Result<(usize, usize)> {
    let lol = len_of_len as usize; // 1..=8 by construction
    let header = 1 + lol;
    if buf.len() < header {
        return Err(reject("rlp: length header truncated"));
    }
    let len_bytes = &buf[1..header];
    if len_bytes[0] == 0 {
        return Err(reject("rlp: non-canonical length (leading zero)"));
    }
    let mut len: usize = 0;
    for &b in len_bytes {
        // Big-endian accumulate. Checked ops reject overflow.
        len = len
            .checked_shl(8)
            .and_then(|v| v.checked_add(b as usize))
            .ok_or_else(|| reject("rlp: length exceeds usize"))?;
    }
    if len <= 55 {
        return Err(reject("rlp: non-canonical long form for short payload"));
    }
    Ok((len, header))
}

/// Decodes a list payload (zero or more concatenated RLP items) completely.
fn decode_list(mut buf: &[u8], depth: usize) -> Result<Vec<Rlp<'_>>> {
    let mut items = Vec::new();
    while !buf.is_empty() {
        let (item, used) = decode_one(buf, depth + 1)?;
        // `used` is always >= 1, so this terminates.
        items.push(item);
        buf = &buf[used..];
    }
    Ok(items)
}

/// Borrows an item's list contents. Rejects a string.
fn as_list<'a, 'b>(item: &'b Rlp<'a>) -> Result<&'b [Rlp<'a>]> {
    match item {
        Rlp::List(v) => Ok(v),
        Rlp::Str(_) => Err(reject("rlp: expected a list, found a string")),
    }
}

/// Borrows a byte-string field, such as transaction calldata.
fn as_bytes<'a>(item: &Rlp<'a>) -> Result<&'a [u8]> {
    match item {
        Rlp::Str(bytes) => Ok(bytes),
        Rlp::List(_) => Err(reject("rlp: expected a byte string, found a list")),
    }
}

/// Borrows an item's scalar bytes (canonical big-endian integer). Rejects a
/// list or a leading zero.
fn as_scalar<'a>(item: &Rlp<'a>) -> Result<&'a [u8]> {
    match item {
        Rlp::Str(s) => {
            if s.first() == Some(&0) {
                return Err(reject("rlp: non-canonical scalar (leading zero)"));
            }
            Ok(s)
        }
        Rlp::List(_) => Err(reject("rlp: expected a scalar, found a list")),
    }
}

/// Reads a scalar item as a `u64`. Rejects more than 8 bytes.
fn scalar_u64(item: &Rlp) -> Result<u64> {
    let s = as_scalar(item)?;
    if s.len() > 8 {
        return Err(reject("rlp: integer exceeds u64"));
    }
    let mut v = 0u64;
    for &b in s {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

/// Reads a scalar item as a `u128`, for the wei fee fields and `value`
/// (`uint256` on the wire). More than 16 bytes is rejected, not truncated:
/// `u128::MAX` wei is above any pinnable ceiling.
fn scalar_u128(item: &Rlp) -> Result<u128> {
    let s = as_scalar(item)?;
    if s.len() > 16 {
        return Err(reject(
            "gas tx: integer exceeds u128 (far above any pinnable ceiling)",
        ));
    }
    let mut v = 0u128;
    for &b in s {
        v = (v << 8) | b as u128;
    }
    Ok(v)
}

/// True if a scalar item encodes zero (the canonical empty string).
fn scalar_is_zero(item: &Rlp) -> Result<bool> {
    Ok(as_scalar(item)?.is_empty())
}

/// Reads an item as a 20-byte address. Rejects the empty string (contract
/// creation), a wrong length, or a list.
fn as_address(item: &Rlp) -> Result<[u8; 20]> {
    match item {
        Rlp::Str(s) if s.len() == 20 => {
            let mut a = [0u8; 20];
            a.copy_from_slice(s);
            Ok(a)
        }
        Rlp::Str([]) => Err(reject(
            "gas tx: contract creation (empty `to`) is not allowed for the gas key",
        )),
        Rlp::Str(_) => Err(reject("gas tx: `to` must be a 20-byte address")),
        Rlp::List(_) => Err(reject("rlp: expected an address string, found a list")),
    }
}

/// Gets the 4-byte selector from the `data` item. Empty calldata gives `None`
/// (the caller refuses it). Rejects 1-3 bytes of calldata, or a list.
fn as_calldata_selector(item: &Rlp) -> Result<Option<[u8; 4]>> {
    match item {
        Rlp::Str([]) => Ok(None),
        Rlp::Str(s) if s.len() >= 4 => {
            let mut sel = [0u8; 4];
            sel.copy_from_slice(&s[..4]);
            Ok(Some(sel))
        }
        Rlp::Str(_) => Err(reject(
            "gas tx: calldata is shorter than a 4-byte function selector",
        )),
        Rlp::List(_) => Err(reject("rlp: expected calldata string, found a list")),
    }
}

#[cfg(test)]
mod tests;
