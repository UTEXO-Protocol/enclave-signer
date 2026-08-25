//! Gas-key transaction shape allowlist (audit TEE-XC-09).
//!
//! The gas key (`m/44'/60'/0'/0/1`) pays L1 gas for the bridge's Ethereum
//! transactions. The enclave is given the unsigned transaction preimage, not a
//! pre-hashed digest, and:
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
//! `to` == pinned `BRIDGE_CONTRACT`, and `value` <= `GAS_TX_MAX_VALUE_WEI`. The
//! selector must also be in `GAS_TX_ALLOWED_SELECTORS`.
//!
//! Any unset pin fails the path closed. The whole rule is folded into the
//! attestation `user_data` commitment via [`crate::policy::SecurityPolicy`].
//!
//! Not bounded here: aggregate fee spend across many txs (validation is
//! stateless), and the LayerZero fee is not bound to its release (#68).
//! EIP-712 typed data is not accepted: the gas key signs L1 transactions,
//! whose envelope is RLP.

use sha3::{Digest, Keccak256};

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::proto::SignRawDigestRequest;

/// EIP-2718 type byte for an EIP-1559 (dynamic-fee) transaction.
const TX_TYPE_EIP1559: u8 = 0x02;

/// Selector of the **on-chain** `MultisigProxy.lzFundsOutCall` (params as one
/// struct) - the only proxy method that legitimately carries native value.
///
/// NOT [`super::validation::LZ_FUNDS_OUT_SELECTOR`], which is the enclave's
/// wire format for the same operation. A literal because keccak is not
/// const-evaluable here; `onchain_lz_selector_matches_its_signature` pins it.
const ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR: [u8; 4] = [0x7a, 0xe8, 0xf7, 0x36];

/// Maximum RLP nesting depth we will decode. A real transaction reaches
/// depth ~4 (tx list -> accessList -> entry -> storage-key list); the cap is
/// a defensive backstop against a deeply-nested input exhausting the stack.
const MAX_RLP_DEPTH: usize = 8;

/// Shorthand for the cross-check rejection used throughout this module.
fn reject(msg: impl Into<String>) -> EnclaveError {
    EnclaveError::CrossCheck(msg.into())
}

/// A decoded RLP item: either a byte string or a list of items. Borrows
/// from the input buffer - no allocation of payload bytes.
enum Rlp<'a> {
    Str(&'a [u8]),
    List(Vec<Rlp<'a>>),
}

/// The fields of an unsigned gas transaction that the allowlist inspects.
struct GasTx<'a> {
    chain_id: u64,
    to: [u8; 20],
    /// Wei. A number rather than a zero flag: the LayerZero carve-out
    /// compares it against a pinned ceiling.
    value: u128,
    /// `gasLimit` - bounded by `GAS_TX_MAX_GAS_LIMIT`.
    gas_limit: u64,
    /// `maxFeePerGas` (EIP-1559) or `gasPrice` (legacy) - bounded by
    /// `GAS_TX_MAX_FEE_PER_GAS`.
    max_fee_per_gas: u128,
    /// `maxPriorityFeePerGas` (EIP-1559); equal to `gasPrice` for legacy. Also
    /// bounded by `GAS_TX_MAX_FEE_PER_GAS`.
    max_priority_fee_per_gas: u128,
    /// Leading 4-byte function selector, or `None` for empty calldata (which
    /// `validate_gas_tx_request` refuses).
    selector: Option<[u8; 4]>,
    /// The full calldata, prefix-matched by the LayerZero carve-out.
    data: &'a [u8],
}

/// Validate a gas-key `SignRawDigest` request against the operator pins and
/// return the 32-byte digest the enclave should sign - `keccak256` of the
/// supplied preimage, computed here rather than trusted from the wire.
///
/// Fails closed (`CrossCheck`) on: missing preimage, unparseable / malformed
/// / non-canonical RLP, unsupported envelope, unpinned chain id / destination /
/// gas cap / fee cap, chain-id / destination mismatch, contract-creation, a
/// non-zero value failing any leg of the LayerZero fee carve-out, a `gasLimit`
/// or per-gas fee above the pinned ceiling, or calldata whose selector is not
/// in the operator allowlist.
pub fn validate_gas_tx_request(req: &SignRawDigestRequest, cfg: &BridgeConfig) -> Result<[u8; 32]> {
    if req.unsigned_tx.is_empty() {
        return Err(reject(
            "gas tx signing requires the unsigned transaction preimage (unsigned_tx); \
             refusing to sign an opaque digest",
        ));
    }

    // Decode + structural allowlist.
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
                "gas tx: non-zero value requires a pinned BRIDGE_CONTRACT to check the \
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

    // Fee/gas ceilings (audit C-02): a signed gas tx can burn at most
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

    // Calldata allowlist (audit C-02). Every signed gas tx must invoke an
    // allowlisted 4-byte selector on the pinned destination. Empty calldata is
    // refused (it would invoke `fallback()` / `receive()`), and an empty
    // allowlist refuses all gas-tx signing.
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

    // Compute the digest from the validated preimage. Any wire-supplied
    // digest must agree, but the signed bytes come from our own hash.
    let digest: [u8; 32] = Keccak256::digest(&req.unsigned_tx).into();
    if !req.digest.is_empty() && req.digest.as_slice() != digest {
        return Err(reject(
            "gas tx: supplied digest does not match keccak256(unsigned_tx)",
        ));
    }
    Ok(digest)
}

/// Decode an unsigned gas transaction preimage and extract the fields the
/// allowlist needs. Accepts EIP-1559 (`0x02 || rlp([...9])`) and legacy
/// EIP-155 (`rlp([...9])`) unsigned bodies; rejects everything else.
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
        // Legacy has a single `gasPrice`; it plays the role of both the max fee
        // and the priority fee for the cap check.
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
// Hand-rolled and strict: it decodes attacker-controlled bytes inside the TEE,
// so it bounds-checks every read, rejects non-canonical encodings, and requires
// the whole input to be consumed by exactly one top-level item.

/// Decode exactly one top-level RLP item and require it to consume the
/// entire buffer (no trailing bytes).
fn decode_canonical(buf: &[u8]) -> Result<Rlp<'_>> {
    let (item, used) = decode_one(buf, 0)?;
    if used != buf.len() {
        return Err(reject("rlp: trailing bytes after top-level item"));
    }
    Ok(item)
}

/// Decode a single RLP item from the front of `buf`, returning it and the
/// number of bytes consumed.
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

/// Read the big-endian length that follows a long-string/long-list header
/// byte. `len_of_len` is in 1..=8. Returns `(length, header_size)` where
/// `header_size = 1 + len_of_len`. Enforces canonical form: no leading-zero
/// length bytes and the length must be > 55 (otherwise the short form was
/// required).
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
        // lol <= 8 and we cap at usize below; shift-accumulate big-endian.
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

/// Decode a buffer that is the concatenation of zero or more RLP items
/// (a list payload), consuming all of it.
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

/// Borrow an item's list contents, or reject if it's a string.
fn as_list<'a, 'b>(item: &'b Rlp<'a>) -> Result<&'b [Rlp<'a>]> {
    match item {
        Rlp::List(v) => Ok(v),
        Rlp::Str(_) => Err(reject("rlp: expected a list, found a string")),
    }
}

/// Borrow a byte-string field such as transaction calldata.
fn as_bytes<'a>(item: &Rlp<'a>) -> Result<&'a [u8]> {
    match item {
        Rlp::Str(bytes) => Ok(bytes),
        Rlp::List(_) => Err(reject("rlp: expected a byte string, found a list")),
    }
}

/// Borrow an item's scalar bytes (a canonical big-endian integer string),
/// rejecting a list or a non-minimal leading-zero encoding.
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

/// Interpret a scalar item as a `u64`, rejecting anything wider than 8 bytes.
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

/// Interpret a scalar item as a `u128`, used for the wei-denominated fee
/// fields and `value` (all `uint256` on the wire). Wider than 16 bytes is
/// rejected rather than truncated: `u128::MAX` wei already exceeds any
/// pinnable ceiling.
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

/// Interpret an item as a 20-byte address. Rejects the empty string
/// (contract creation), a wrong-length string, or a list.
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

/// Interpret the `data` item as calldata and extract its leading 4-byte
/// function selector. Empty calldata yields `None` (the caller refuses it).
/// Non-empty calldata shorter than 4 bytes, or a list, is rejected.
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
mod tests {
    use super::*;

    const CHAIN_ID: u64 = 1;
    const ALLOWED_TO: [u8; 20] = [0xAA; 20];
    const MAX_GAS_LIMIT: u64 = 30_000;
    const MAX_FEE_PER_GAS: u128 = 1_000;
    const ALLOWED_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    fn cfg() -> BridgeConfig {
        BridgeConfig {
            chain_id: CHAIN_ID,
            bridge_contract: [0xBB; 20],
            rgb_asset_id: "rgb:test".into(),
            gas_tx_allowed_to: Some(ALLOWED_TO),
            gas_tx_max_gas_limit: MAX_GAS_LIMIT,
            gas_tx_max_fee_per_gas: MAX_FEE_PER_GAS,
            gas_tx_allowed_selectors: vec![ALLOWED_SELECTOR],
            ..Default::default()
        }
    }

    // ---- tiny RLP encoder, for building test fixtures only ----

    fn rlp_str(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            return vec![bytes[0]];
        }
        let mut out = Vec::new();
        if bytes.len() <= 55 {
            out.push(0x80 + bytes.len() as u8);
        } else {
            let len = bytes.len();
            let len_be = len.to_be_bytes();
            let lb: Vec<u8> = len_be.iter().copied().skip_while(|&b| b == 0).collect();
            out.push(0xb7 + lb.len() as u8);
            out.extend_from_slice(&lb);
        }
        out.extend_from_slice(bytes);
        out
    }

    /// Encode a scalar (minimal big-endian, zero = empty string).
    fn rlp_scalar(v: u64) -> Vec<u8> {
        let be = v.to_be_bytes();
        let trimmed: Vec<u8> = be.iter().copied().skip_while(|&b| b == 0).collect();
        rlp_str(&trimmed)
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for it in items {
            payload.extend_from_slice(it);
        }
        let mut out = Vec::new();
        if payload.len() <= 55 {
            out.push(0xc0 + payload.len() as u8);
        } else {
            let len = payload.len();
            let len_be = len.to_be_bytes();
            let lb: Vec<u8> = len_be.iter().copied().skip_while(|&b| b == 0).collect();
            out.push(0xf7 + lb.len() as u8);
            out.extend_from_slice(&lb);
        }
        out.extend_from_slice(&payload);
        out
    }

    /// Build a well-formed unsigned EIP-1559 preimage with default fee/gas
    /// fields and caller-chosen calldata.
    fn eip1559_with_data(chain_id: u64, to: &[u8], value: u64, data: &[u8]) -> Vec<u8> {
        eip1559_full(chain_id, to, value, 1, 100, 21_000, data)
    }

    /// Build a well-formed unsigned EIP-1559 preimage. Carries the allowlisted
    /// selector as calldata so the happy path passes the calldata check; the
    /// rejection tests that use this fail earlier (chain/destination/value/caps).
    fn eip1559(chain_id: u64, to: &[u8], value: u64) -> Vec<u8> {
        eip1559_with_data(chain_id, to, value, &ALLOWED_SELECTOR)
    }

    /// Build a well-formed unsigned EIP-1559 preimage with explicit fee/gas/data
    /// fields, for exercising the cap and calldata-allowlist checks.
    #[allow(clippy::too_many_arguments)]
    fn eip1559_full(
        chain_id: u64,
        to: &[u8],
        value: u64,
        max_prio: u64,
        max_fee: u64,
        gas: u64,
        data: &[u8],
    ) -> Vec<u8> {
        let body = rlp_list(&[
            rlp_scalar(chain_id),
            rlp_scalar(7),
            rlp_scalar(max_prio),
            rlp_scalar(max_fee),
            rlp_scalar(gas),
            rlp_str(to),
            rlp_scalar(value),
            rlp_str(data),
            rlp_list(&[]),
        ]);
        let mut out = vec![TX_TYPE_EIP1559];
        out.extend_from_slice(&body);
        out
    }

    /// Build a well-formed unsigned legacy EIP-155 preimage (allowlisted-selector
    /// calldata, so the happy path passes the calldata check).
    fn legacy(chain_id: u64, to: &[u8], value: u64) -> Vec<u8> {
        legacy_full(chain_id, to, value, 100, 21_000, &ALLOWED_SELECTOR)
    }

    /// Build a well-formed unsigned legacy EIP-155 preimage with explicit
    /// gasPrice/gas/data fields.
    fn legacy_full(
        chain_id: u64,
        to: &[u8],
        value: u64,
        gas_price: u64,
        gas: u64,
        data: &[u8],
    ) -> Vec<u8> {
        rlp_list(&[
            rlp_scalar(7),         // nonce
            rlp_scalar(gas_price), // gasPrice
            rlp_scalar(gas),       // gasLimit
            rlp_str(to),           // to
            rlp_scalar(value),     // value
            rlp_str(data),         // data
            rlp_scalar(chain_id),  // chainId
            rlp_scalar(0),         // 0
            rlp_scalar(0),         // 0
        ])
    }

    /// Build a well-formed unsigned legacy EIP-155 preimage with default
    /// gasPrice/gas and caller-chosen calldata.
    fn legacy_with_data(chain_id: u64, to: &[u8], value: u64, data: &[u8]) -> Vec<u8> {
        legacy_full(chain_id, to, value, 100, 21_000, data)
    }

    fn req(unsigned_tx: Vec<u8>) -> SignRawDigestRequest {
        SignRawDigestRequest {
            digest: Vec::new(),
            unsigned_tx,
        }
    }

    #[test]
    fn accepts_eip1559_to_pinned_destination() {
        let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
        let expected: [u8; 32] = Keccak256::digest(&tx).into();
        let got = validate_gas_tx_request(&req(tx), &cfg()).unwrap();
        assert_eq!(got, expected, "must sign keccak256(unsigned_tx)");
    }

    #[test]
    fn accepts_legacy_eip155_to_pinned_destination() {
        let tx = legacy(CHAIN_ID, &ALLOWED_TO, 0);
        assert!(validate_gas_tx_request(&req(tx), &cfg()).is_ok());
    }

    #[test]
    fn rejects_empty_preimage() {
        let err = validate_gas_tx_request(&req(vec![]), &cfg()).unwrap_err();
        assert!(err
            .to_string()
            .contains("requires the unsigned transaction preimage"));
    }

    #[test]
    fn rejects_wrong_destination_the_drain() {
        // The core drain: a well-formed tx sending to an attacker address.
        let attacker = [0xEE; 20];
        let tx = eip1559(CHAIN_ID, &attacker, 0);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("destination") && err.to_string().contains("pinned"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_nonzero_value_the_other_drain() {
        let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 1_000_000);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("value must be 0"), "got: {err}");
    }

    // LayerZero native-fee carve-out: payable selector + destination ==
    // pinned proxy + value <= ceiling. Each test breaks exactly one leg.

    /// Verbatim from `MultisigProxy.sol`. Kept in the test module so the
    /// release build carries no unused constant.
    const ONCHAIN_LZ_FUNDS_OUT_CALL_SIG: &str =
        "lzFundsOutCall((uint256,uint256,uint256,uint256,string,bytes,bytes,uint32,bytes32,\
         uint256,bytes),uint256,uint256,uint256,bytes[])";

    /// Drift fails closed, so this catches a silently disabled carve-out.
    #[test]
    fn onchain_lz_selector_matches_its_signature() {
        let digest = Keccak256::digest(ONCHAIN_LZ_FUNDS_OUT_CALL_SIG.as_bytes());
        assert_eq!(
            digest[..4],
            ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR,
            "selector drifted from {ONCHAIN_LZ_FUNDS_OUT_CALL_SIG}"
        );
    }

    /// LZ posture: `GAS_TX_ALLOWED_TO` pinned at the proxy, plus a ceiling.
    fn lz_cfg() -> BridgeConfig {
        BridgeConfig {
            chain_id: CHAIN_ID,
            bridge_contract: ALLOWED_TO,
            rgb_asset_id: "rgb:test".into(),
            gas_tx_allowed_to: Some(ALLOWED_TO),
            gas_tx_max_value_wei: Some(1_000_000),
            gas_tx_max_gas_limit: MAX_GAS_LIMIT,
            gas_tx_max_fee_per_gas: MAX_FEE_PER_GAS,
            // The carve-out widens the value rule only; the selector must
            // still be allowlisted.
            gas_tx_allowed_selectors: vec![ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR, ALLOWED_SELECTOR],
            ..Default::default()
        }
    }

    fn lz_calldata() -> Vec<u8> {
        let mut calldata = ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR.to_vec();
        calldata.extend_from_slice(&[0x11; 64]);
        calldata
    }

    #[test]
    fn accepts_nonzero_value_for_lz_funds_out_call() {
        let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 999_999, &lz_calldata());
        assert!(validate_gas_tx_request(&req(tx), &lz_cfg()).is_ok());
    }

    /// value/data indices differ per envelope; both must decide the same.
    #[test]
    fn accepts_nonzero_value_for_lz_funds_out_call_legacy_envelope() {
        let tx = legacy_with_data(CHAIN_ID, &ALLOWED_TO, 999_999, &lz_calldata());
        assert!(validate_gas_tx_request(&req(tx), &lz_cfg()).is_ok());
    }

    #[test]
    fn accepts_value_exactly_at_the_ceiling() {
        let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000_000, &lz_calldata());
        assert!(validate_gas_tx_request(&req(tx), &lz_cfg()).is_ok());
    }

    #[test]
    fn rejects_nonzero_value_for_other_selector() {
        let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000, &[0xde, 0xad, 0xbe, 0xef]);
        let err = validate_gas_tx_request(&req(tx), &lz_cfg()).unwrap_err();
        assert!(err.to_string().contains("value must be 0"), "got: {err}");
    }

    /// `GAS_TX_ALLOWED_TO` may be an EOA, which ignores calldata, so value
    /// also requires `to` == the pinned proxy.
    #[test]
    fn rejects_nonzero_value_when_destination_is_not_the_pinned_proxy() {
        let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000, &lz_calldata());
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string()
                .contains("only allowed to the pinned MultisigProxy"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_nonzero_value_when_bridge_contract_unpinned() {
        let unpinned = BridgeConfig {
            bridge_contract: [0u8; 20],
            ..lz_cfg()
        };
        let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000, &lz_calldata());
        let err = validate_gas_tx_request(&req(tx), &unpinned).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires a pinned BRIDGE_CONTRACT"),
            "got: {err}"
        );
    }

    /// Fail-closed default: an unset pin keeps the `value == 0` posture.
    #[test]
    fn rejects_nonzero_value_when_ceiling_unset() {
        let uncapped = BridgeConfig {
            gas_tx_max_value_wei: None,
            ..lz_cfg()
        };
        let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1, &lz_calldata());
        let err = validate_gas_tx_request(&req(tx), &uncapped).unwrap_err();
        assert!(
            err.to_string().contains("GAS_TX_MAX_VALUE_WEI unset"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_value_above_the_ceiling() {
        let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000_001, &lz_calldata());
        let err = validate_gas_tx_request(&req(tx), &lz_cfg()).unwrap_err();
        assert!(
            err.to_string()
                .contains("exceeds pinned GAS_TX_MAX_VALUE_WEI"),
            "got: {err}"
        );
    }

    /// A bare selector passes leg (a); the ceiling is what stops it.
    #[test]
    fn rejects_bare_selector_above_the_ceiling() {
        let tx = eip1559_with_data(
            CHAIN_ID,
            &ALLOWED_TO,
            u64::MAX,
            &ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR,
        );
        let err = validate_gas_tx_request(&req(tx), &lz_cfg()).unwrap_err();
        assert!(
            err.to_string()
                .contains("exceeds pinned GAS_TX_MAX_VALUE_WEI"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_wrong_chain_id() {
        let tx = eip1559(999, &ALLOWED_TO, 0);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("chain_id"), "got: {err}");
    }

    #[test]
    fn rejects_when_chain_id_unpinned() {
        let mut c = cfg();
        c.chain_id = 0;
        let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
        let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
        assert!(
            err.to_string().contains("chain_id not pinned"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_when_destination_unpinned() {
        let mut c = cfg();
        c.gas_tx_allowed_to = None;
        let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
        let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
        assert!(
            err.to_string().contains("destination not pinned"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_contract_creation_empty_to() {
        let tx = eip1559(CHAIN_ID, &[], 0);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("contract creation"), "got: {err}");
    }

    #[test]
    fn rejects_unsupported_envelope() {
        // 0x01 = EIP-2930 access-list tx, not accepted.
        let mut tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
        tx[0] = 0x01;
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("unsupported envelope"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
        tx.push(0xff); // extra byte after the top-level item
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("trailing bytes"), "got: {err}");
    }

    #[test]
    fn rejects_wrong_field_count() {
        // A 9-field list with the 0x02 prefix is valid; drop a field -> 8.
        let body = rlp_list(&[
            rlp_scalar(CHAIN_ID),
            rlp_scalar(7),
            rlp_scalar(1),
            rlp_scalar(100),
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            rlp_scalar(0),
            rlp_str(&[]),
            // accessList omitted -> 8 fields
        ]);
        let mut tx = vec![TX_TYPE_EIP1559];
        tx.extend_from_slice(&body);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("9 fields"), "got: {err}");
    }

    #[test]
    fn rejects_signed_legacy_tx() {
        // Legacy *signed* form has (v, r, s) where the unsigned body has
        // (chainId, 0, 0); a non-zero r/s trailer must be refused.
        let signed = rlp_list(&[
            rlp_scalar(7),
            rlp_scalar(100),
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            rlp_scalar(0),
            rlp_str(&[]),
            rlp_scalar(37),       // v
            rlp_str(&[0x11; 32]), // r
            rlp_str(&[0x22; 32]), // s
        ]);
        let err = validate_gas_tx_request(&req(signed), &cfg()).unwrap_err();
        assert!(err.to_string().contains("trailer must be"), "got: {err}");
    }

    #[test]
    fn rejects_digest_mismatch_when_supplied() {
        let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
        let mut r = req(tx);
        r.digest = vec![0xAB; 32]; // wrong digest
        let err = validate_gas_tx_request(&r, &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("does not match keccak256"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_truncated_rlp() {
        let mut tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
        tx.truncate(tx.len() - 5); // chop the tail
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("rlp:"), "got: {err}");
    }

    #[test]
    fn rejects_non_canonical_leading_zero_chain_id() {
        // Hand-build a body where chainId is encoded as 0x8201 -> [0x01] is
        // fine, but 0x820001 (leading zero) must be rejected. Build chainId
        // as a 2-byte string with a leading zero.
        let bad_chain = vec![0x82, 0x00, 0x01];
        let body = rlp_list(&[
            bad_chain,
            rlp_scalar(7),
            rlp_scalar(1),
            rlp_scalar(100),
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            rlp_scalar(0),
            rlp_str(&[]),
            rlp_list(&[]),
        ]);
        let mut tx = vec![TX_TYPE_EIP1559];
        tx.extend_from_slice(&body);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("non-canonical scalar"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_value_field_that_is_a_list() {
        // `value` (item 6) encoded as a list rather than a scalar must be
        // rejected by the type check, not silently treated as zero.
        let body = rlp_list(&[
            rlp_scalar(CHAIN_ID),
            rlp_scalar(7),
            rlp_scalar(1),
            rlp_scalar(100),
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            rlp_list(&[rlp_scalar(1)]), // value as a list
            rlp_str(&[]),
            rlp_list(&[]),
        ]);
        let mut tx = vec![TX_TYPE_EIP1559];
        tx.extend_from_slice(&body);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("expected a scalar, found a list"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_wide_nonzero_value() {
        // A non-zero value encoded as a wide (9-byte) scalar must be
        // rejected by the value==0 check, not accepted.
        let wide_value = rlp_str(&[0x01; 9]);
        let body = rlp_list(&[
            rlp_scalar(CHAIN_ID),
            rlp_scalar(7),
            rlp_scalar(1),
            rlp_scalar(100),
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            wide_value,
            rlp_str(&[]),
            rlp_list(&[]),
        ]);
        let mut tx = vec![TX_TYPE_EIP1559];
        tx.extend_from_slice(&body);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("value must be 0"), "got: {err}");
    }

    /// Refused at the decode, not wrapped into a small number that would
    /// slip under the ceiling.
    #[test]
    fn rejects_value_wider_than_u128() {
        let body = rlp_list(&[
            rlp_scalar(CHAIN_ID),
            rlp_scalar(7),
            rlp_scalar(1),
            rlp_scalar(100),
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            rlp_str(&[0x01; 17]), // 17-byte value
            rlp_str(&lz_calldata()),
            rlp_list(&[]),
        ]);
        let mut tx = vec![TX_TYPE_EIP1559];
        tx.extend_from_slice(&body);
        let err = validate_gas_tx_request(&req(tx), &lz_cfg()).unwrap_err();
        assert!(err.to_string().contains("exceeds u128"), "got: {err}");
    }

    #[test]
    fn rejects_nesting_beyond_depth_limit() {
        // An accessList nested past MAX_RLP_DEPTH must be rejected by the
        // depth guard rather than recursing without bound.
        let mut deep = rlp_list(&[]);
        for _ in 0..(MAX_RLP_DEPTH + 4) {
            deep = rlp_list(&[deep]);
        }
        let body = rlp_list(&[
            rlp_scalar(CHAIN_ID),
            rlp_scalar(7),
            rlp_scalar(1),
            rlp_scalar(100),
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            rlp_scalar(0),
            rlp_str(&[]),
            deep, // accessList nested beyond the limit
        ]);
        let mut tx = vec![TX_TYPE_EIP1559];
        tx.extend_from_slice(&body);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("nesting too deep"), "got: {err}");
    }

    // ---- fee/gas caps (audit C-02) ----

    #[test]
    fn rejects_gas_limit_over_cap() {
        // gasLimit above GAS_TX_MAX_GAS_LIMIT is the fee-griefing vector.
        let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, MAX_GAS_LIMIT + 1, &[]);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("gasLimit") && err.to_string().contains("exceeds pinned cap"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_max_fee_over_cap() {
        let tx = eip1559_full(
            CHAIN_ID,
            &ALLOWED_TO,
            0,
            1,
            (MAX_FEE_PER_GAS + 1) as u64,
            21_000,
            &[],
        );
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("maxFeePerGas")
                && err.to_string().contains("exceeds pinned cap"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_priority_fee_over_cap() {
        // maxFee within cap, but the priority fee alone exceeds it.
        let tx = eip1559_full(
            CHAIN_ID,
            &ALLOWED_TO,
            0,
            (MAX_FEE_PER_GAS + 1) as u64,
            500,
            21_000,
            &[],
        );
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("maxPriorityFeePerGas")
                && err.to_string().contains("exceeds pinned cap"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_legacy_gas_price_over_cap() {
        // Legacy gasPrice maps to the maxFeePerGas cap.
        let tx = legacy_full(
            CHAIN_ID,
            &ALLOWED_TO,
            0,
            (MAX_FEE_PER_GAS + 1) as u64,
            21_000,
            &[],
        );
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("maxFeePerGas")
                && err.to_string().contains("exceeds pinned cap"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_when_gas_cap_unpinned() {
        let mut c = cfg();
        c.gas_tx_max_gas_limit = 0;
        let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
        let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
        assert!(
            err.to_string().contains("gas-limit cap not pinned"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_when_fee_cap_unpinned() {
        let mut c = cfg();
        c.gas_tx_max_fee_per_gas = 0;
        let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
        let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
        assert!(err.to_string().contains("fee cap not pinned"), "got: {err}");
    }

    #[test]
    fn rejects_fee_wider_than_u128() {
        // A 17-byte maxFeePerGas is far above any pinnable cap; reject at decode.
        let wide_fee = rlp_str(&[0x01; 17]);
        let body = rlp_list(&[
            rlp_scalar(CHAIN_ID),
            rlp_scalar(7),
            rlp_scalar(1),
            wide_fee, // maxFeePerGas > u128
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            rlp_scalar(0),
            rlp_str(&[]),
            rlp_list(&[]),
        ]);
        let mut tx = vec![TX_TYPE_EIP1559];
        tx.extend_from_slice(&body);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("exceeds u128"), "got: {err}");
    }

    // ---- calldata selector allowlist (audit C-02) ----

    #[test]
    fn accepts_allowlisted_selector_with_args() {
        // Selector in the allowlist, followed by ABI args, is accepted.
        let mut data = ALLOWED_SELECTOR.to_vec();
        data.extend_from_slice(&[0x00; 32]); // one 32-byte arg
        let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &data);
        let expected: [u8; 32] = Keccak256::digest(&tx).into();
        let got = validate_gas_tx_request(&req(tx), &cfg()).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn accepts_allowlisted_selector_legacy() {
        let data = ALLOWED_SELECTOR.to_vec();
        let tx = legacy_full(CHAIN_ID, &ALLOWED_TO, 0, 100, 21_000, &data);
        assert!(validate_gas_tx_request(&req(tx), &cfg()).is_ok());
    }

    #[test]
    fn rejects_disallowed_selector() {
        let data = [0x11, 0x22, 0x33, 0x44]; // not in the allowlist
        let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &data);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("selector")
                && err.to_string().contains("not in the operator allowlist"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_non_empty_calldata_when_allowlist_empty() {
        // With no selectors pinned, only empty calldata may be signed.
        let mut c = cfg();
        c.gas_tx_allowed_selectors = Vec::new();
        let data = ALLOWED_SELECTOR.to_vec();
        let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &data);
        let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
        assert!(
            err.to_string().contains("not in the operator allowlist"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_empty_calldata() {
        // A bare / empty-calldata call is refused: it would still invoke the
        // pinned contract's fallback/receive, outside the selector allowlist.
        let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &[]);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string().contains("empty calldata is not permitted"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_calldata_shorter_than_selector() {
        // 1..=3 bytes of calldata cannot carry a 4-byte selector.
        let data = [0x11, 0x22];
        let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &data);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string()
                .contains("shorter than a 4-byte function selector"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_data_field_that_is_a_list() {
        // `data` (item 7) encoded as a list rather than a byte string.
        let body = rlp_list(&[
            rlp_scalar(CHAIN_ID),
            rlp_scalar(7),
            rlp_scalar(1),
            rlp_scalar(100),
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            rlp_scalar(0),
            rlp_list(&[rlp_scalar(1)]), // data as a list
            rlp_list(&[]),
        ]);
        let mut tx = vec![TX_TYPE_EIP1559];
        tx.extend_from_slice(&body);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(
            err.to_string()
                .contains("expected calldata string, found a list"),
            "got: {err}"
        );
    }
}
