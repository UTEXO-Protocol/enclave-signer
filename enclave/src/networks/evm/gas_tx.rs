//! Gas-key transaction shape allowlist (audit TEE-XC-09).
//!
//! The gas key (`m/44'/60'/0'/0/1`) exists to pay L1 gas for the bridge's
//! Ethereum transactions. Its RPC, `SignRawDigest`, originally signed an
//! opaque 32-byte digest with no constraint — so a compromised listener
//! could have the enclave sign *any* transaction from the gas address,
//! including one transferring its whole ETH balance to an attacker (a
//! gas-account drain).
//!
//! This module closes that path. Instead of trusting a pre-hashed digest,
//! the enclave is given the **unsigned transaction preimage** and:
//!   1. decodes it as a recognised envelope — EIP-1559 (type `0x02`) or
//!      legacy EIP-155 — with a strict, canonical RLP decoder that rejects
//!      malformed / non-canonical / trailing-byte input;
//!   2. computes the signing hash itself (`keccak256(preimage)`) rather
//!      than trusting any supplied digest;
//!   3. enforces an operator allowlist: the chain id must equal the pinned
//!      `EVM_CHAIN_ID`, the destination must equal the pinned
//!      `GAS_TX_ALLOWED_TO`, the value must be zero unless the transaction is
//!      the payable `lzFundsOutCall`, and contract-creation (empty `to`) is
//!      refused.
//!
//! Anything that doesn't decode to an allowed shape, or that targets an
//! address / carries value the operator didn't pin, is rejected before a
//! signature is produced. With the destination pinned, the two *theft*
//! vectors are closed: an attacker can neither redirect funds (`to` is
//! pinned) nor move ETH through arbitrary calldata. A non-zero value is only
//! accepted for the pinned proxy's payable LayerZero release entrypoint. When
//! the pin is unset the enclave fails closed in production rather than signing
//! blindly.
//!
//! Residual risks deliberately NOT covered here (tracked as #68 follow-ups):
//!   * **Fee griefing.** `gasLimit` and the fee-per-gas fields are not
//!     capped, so a compromised listener could still burn the gas account's
//!     ETH as transaction fees. This is griefing, not theft — the ETH is
//!     burned as base fee / tipped to the block builder, never redirected
//!     to an attacker — and capping it well is brittle as gas prices move.
//!     An operator-pinned fee/gas ceiling would close it.
//!   * **Calldata.** The transaction `data` sent to the pinned `to` is not
//!     inspected. `GAS_TX_ALLOWED_TO` must therefore be an EOA, or a
//!     contract with no function the gas key could be coerced into calling
//!     to the operator's detriment. A calldata/selector allowlist would
//!     close it.
//!   * **Attestation observability.** The destination pin is not folded
//!     into the attestation `user_data` bundle, so an external verifier
//!     cannot confirm it (see `BridgeConfig::gas_tx_allowed_to`). It is a
//!     self-protection pin over the operator's own gas funds, so this is an
//!     observability gap, not a signing-path bypass.
//!
//! Note: EIP-712 typed-data is intentionally *not* accepted here — the gas
//! key signs outer L1 transactions, whose canonical envelope is RLP, not
//! EIP-712. A separate signing surface would be needed if that ever
//! changes.

use sha3::{Digest, Keccak256};

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::proto::SignRawDigestRequest;

/// EIP-2718 type byte for an EIP-1559 (dynamic-fee) transaction.
const TX_TYPE_EIP1559: u8 = 0x02;

/// `keccak256("lzFundsOutCall((uint256,uint256,uint256,uint256,string,bytes,bytes,uint32,bytes32,uint256,bytes),uint256,uint256,uint256,bytes[])")[0..4]`.
///
/// This is the only proxy method that legitimately carries native value: the
/// value is forwarded as the LayerZero messaging fee.
const LZ_FUNDS_OUT_CALL_SELECTOR: [u8; 4] = [0x7a, 0xe8, 0xf7, 0x36];

/// Maximum RLP nesting depth we will decode. A real transaction reaches
/// depth ~4 (tx list → accessList → entry → storage-key list); the cap is
/// a defensive backstop against a deeply-nested input exhausting the stack.
const MAX_RLP_DEPTH: usize = 8;

/// Shorthand for the cross-check rejection used throughout this module.
/// Maps to the same `CrossCheck` error code (3) as the other signing
/// cross-checks.
fn reject(msg: impl Into<String>) -> EnclaveError {
    EnclaveError::CrossCheck(msg.into())
}

/// A decoded RLP item: either a byte string or a list of items. Borrows
/// from the input buffer — no allocation of payload bytes.
enum Rlp<'a> {
    Str(&'a [u8]),
    List(Vec<Rlp<'a>>),
}

/// The fields of an unsigned gas transaction that the allowlist inspects.
struct GasTx<'a> {
    chain_id: u64,
    to: [u8; 20],
    value_is_zero: bool,
    data: &'a [u8],
}

/// Validate a gas-key `SignRawDigest` request against the operator pins and
/// return the 32-byte digest the enclave should sign — `keccak256` of the
/// supplied preimage, computed here rather than trusted from the wire.
///
/// Fails closed (`CrossCheck`) on: missing preimage, unparseable / malformed
/// / non-canonical RLP, unsupported envelope, unpinned chain id or
/// destination, chain-id / destination mismatch, non-zero value, or
/// contract-creation.
pub fn validate_gas_tx_request(req: &SignRawDigestRequest, cfg: &BridgeConfig) -> Result<[u8; 32]> {
    if req.unsigned_tx.is_empty() {
        return Err(reject(
            "gas tx signing requires the unsigned transaction preimage (unsigned_tx); \
             refusing to sign an opaque digest",
        ));
    }

    // Decode + structural allowlist. Reject anything that isn't a clean,
    // recognised, canonical transaction envelope.
    let tx = parse_gas_tx(&req.unsigned_tx)?;

    // Chain-id pin. EVM_CHAIN_ID must be configured, and the tx must target
    // exactly it — blocks cross-chain replay of a gas tx.
    if cfg.chain_id == 0 {
        return Err(reject(
            "gas tx: chain_id not pinned (EVM_CHAIN_ID unset) — refusing to sign",
        ));
    }
    if tx.chain_id != cfg.chain_id {
        return Err(reject(format!(
            "gas tx: chain_id {} != pinned {}",
            tx.chain_id, cfg.chain_id
        )));
    }

    // Destination pin. GAS_TX_ALLOWED_TO must be configured, and the tx must
    // go to exactly it — this is what stops a redirect-to-attacker drain.
    let allowed = cfg.gas_tx_allowed_to.ok_or_else(|| {
        reject(
            "gas tx: destination not pinned (GAS_TX_ALLOWED_TO unset) — refusing to sign \
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

    // Native value is required only by the payable LayerZero release method,
    // where the pinned MultisigProxy forwards it as the messaging fee. Keep
    // the original fail-closed rule for every other selector so the gas key
    // cannot be used for an arbitrary value transfer to the proxy.
    if !tx.value_is_zero && !tx.data.starts_with(&LZ_FUNDS_OUT_CALL_SELECTOR) {
        return Err(reject(
            "gas tx: value must be 0 unless calldata is lzFundsOutCall",
        ));
    }

    // Compute the digest ourselves from the validated preimage. If the
    // request also carried a digest (legacy/defence-in-depth), it must
    // agree — but the signed bytes come from our own hash, never the wire.
    let digest: [u8; 32] = Keccak256::digest(&req.unsigned_tx).into();
    if !req.digest.is_empty() && req.digest.as_slice() != digest {
        return Err(reject(
            "gas tx: supplied digest does not match keccak256(unsigned_tx)",
        ));
    }
    Ok(digest)
}

/// Decode an unsigned gas transaction preimage and extract the fields the
/// allowlist needs. Accepts EIP-1559 (`0x02 ‖ rlp([...9])`) and legacy
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
            to: as_address(&items[5])?,
            value_is_zero: scalar_is_zero(&items[6])?,
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
        // The EIP-155 trailer must be (chainId, 0, 0). The two zero scalars
        // distinguish an *unsigned* signing body from a *signed* tx (whose
        // trailer is (v, r, s) with non-zero r/s) — we only sign the former.
        if !scalar_is_zero(&items[7])? || !scalar_is_zero(&items[8])? {
            return Err(reject(
                "gas tx: legacy EIP-155 trailer must be (chainId, 0, 0) — \
                 refusing a signed or pre-EIP-155 transaction",
            ));
        }
        Ok(GasTx {
            chain_id: scalar_u64(&items[6])?,
            to: as_address(&items[3])?,
            value_is_zero: scalar_is_zero(&items[4])?,
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

// ============================================================================
// Minimal, defensive RLP decoder
// ============================================================================
//
// Hand-rolled (no external crate) and strict: it decodes attacker-controlled
// bytes inside the TEE, so it bounds-checks every read, rejects non-canonical
// encodings, and requires the whole input to be consumed by exactly one
// top-level item. Correctness here is not load-bearing for the *signed bytes*
// — those are `keccak256` of the raw preimage — but it must extract fields
// truthfully and never panic.

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

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN_ID: u64 = 1;
    const ALLOWED_TO: [u8; 20] = [0xAA; 20];

    fn cfg() -> BridgeConfig {
        BridgeConfig {
            chain_id: CHAIN_ID,
            bridge_contract: [0xBB; 20],
            rgb_asset_id: "rgb:test".into(),
            gas_tx_allowed_to: Some(ALLOWED_TO),
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

    /// Build a well-formed unsigned EIP-1559 preimage.
    fn eip1559_with_data(chain_id: u64, to: &[u8], value: u64, data: &[u8]) -> Vec<u8> {
        let body = rlp_list(&[
            rlp_scalar(chain_id), // chainId
            rlp_scalar(7),        // nonce
            rlp_scalar(1),        // maxPriorityFeePerGas
            rlp_scalar(100),      // maxFeePerGas
            rlp_scalar(21_000),   // gasLimit
            rlp_str(to),          // to
            rlp_scalar(value),    // value
            rlp_str(data),        // data
            rlp_list(&[]),        // accessList (empty)
        ]);
        let mut out = vec![TX_TYPE_EIP1559];
        out.extend_from_slice(&body);
        out
    }

    fn eip1559(chain_id: u64, to: &[u8], value: u64) -> Vec<u8> {
        eip1559_with_data(chain_id, to, value, &[])
    }

    /// Build a well-formed unsigned legacy EIP-155 preimage.
    fn legacy(chain_id: u64, to: &[u8], value: u64) -> Vec<u8> {
        rlp_list(&[
            rlp_scalar(7),        // nonce
            rlp_scalar(100),      // gasPrice
            rlp_scalar(21_000),   // gasLimit
            rlp_str(to),          // to
            rlp_scalar(value),    // value
            rlp_str(&[]),         // data
            rlp_scalar(chain_id), // chainId
            rlp_scalar(0),        // 0
            rlp_scalar(0),        // 0
        ])
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

    #[test]
    fn accepts_nonzero_value_for_lz_funds_out_call() {
        let mut calldata = LZ_FUNDS_OUT_CALL_SELECTOR.to_vec();
        calldata.extend_from_slice(&[0x11; 64]);
        let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000_000, &calldata);
        assert!(validate_gas_tx_request(&req(tx), &cfg()).is_ok());
    }

    #[test]
    fn rejects_nonzero_value_for_other_proxy_selector() {
        let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000_000, &[0xde, 0xad, 0xbe, 0xef]);
        let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
        assert!(err.to_string().contains("value must be 0"), "got: {err}");
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
        // A 9-field list with the 0x02 prefix is valid; drop a field → 8.
        let body = rlp_list(&[
            rlp_scalar(CHAIN_ID),
            rlp_scalar(7),
            rlp_scalar(1),
            rlp_scalar(100),
            rlp_scalar(21_000),
            rlp_str(&ALLOWED_TO),
            rlp_scalar(0),
            rlp_str(&[]),
            // accessList omitted → 8 fields
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
}
