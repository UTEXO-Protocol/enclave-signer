//! RGB→EVM `fundsOut` cross-checks: bind the calldata the enclave signs to the
//! consignment it validated. All logic here is `rgb-validation`-gated (the
//! module is only compiled then) because every check reads a
//! [`ValidatedConsignment`]; SPV builds additionally run the BtcRelay agreement
//! check ([`verify_btc_relay_agreement`]).
//!
//! Ported from the pre-refactor `validation/evm_crosscheck.rs` (audit M-02/#93,
//! #63/#97, #57/#122, 4th I-03/#95) and re-homed onto the `networks/evm` layout;
//! the helpers now operate on `EvmDestination.call_data` bytes rather than the
//! old flat `SignEvmRequest`.

use sha3::{Digest, Keccak256};

use crate::error::{EnclaveError, Result};
use crate::networks::evm::validation::FUNDS_OUT_SELECTOR_POOLS;
use crate::networks::rgb::spv::HeaderChain;
use crate::networks::rgb::validation::ValidatedConsignment;

/// Byte offset of `amount` in the `fundsOut` calldata. After the 4-byte
/// selector and the 32-byte `recipient` head slot, `amount` (uint256) sits at
/// byte 36..68.
const FUNDS_OUT_AMOUNT_OFFSET: usize = 36;

/// Byte offset of `burnId` (uint256) in the `fundsOut` calldata: after the
/// selector, `recipient` (4..36) and `amount` (36..68), `burnId` sits at
/// 68..100. Confirmed against `Bridge.sol` on `dev`.
const FUNDS_OUT_BURN_ID_OFFSET: usize = 68;

/// Byte offset of the `settlementData` head slot (its ABI tail offset word).
/// `settlementData` is the 8th arg, so after the selector its head word sits at
/// 4 + 7*32 = 228..260. The `abi.encode(uint256[] fundsInIds)` payload is in the
/// tail.
const FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET: usize = 4 + 7 * 32;

/// Byte offset of the `proof` head slot (its ABI tail offset word). `proof` is
/// the 7th arg, so its head word sits at 4 + 6*32 = 196. The tail decodes to
/// `abi.encode(uint256 blockHeight, bytes32 commitmentHash)`.
const FUNDS_OUT_PROOF_HEAD_OFFSET: usize = 4 + 6 * 32;

/// Defense-in-depth for the RGB→EVM `fundsOut` direction (audit 4th I-03 / #95):
/// every consignment witness tx must be mined. rgbstd's per-witness ordinal map
/// (otherwise discarded) is surfaced as `non_mined_witness_txids`; reject here
/// so confirmation does not rest on the SPV header chain alone.
pub fn assert_witnesses_confirmed(validated: &ValidatedConsignment) -> Result<()> {
    if !validated.non_mined_witness_txids.is_empty() {
        let list: Vec<String> = validated
            .non_mined_witness_txids
            .iter()
            .map(hex::encode)
            .collect();
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut requires every consignment witness tx to be mined, but rgbstd classified \
             {} witness(es) as not-yet-confirmed (tentative/ignored): {} - refusing to sign",
            list.len(),
            list.join(", ")
        )));
    }
    Ok(())
}

/// Fail-closed selector guard for the selector-specific `fundsOut` validator
/// [`validate_funds_out_transfer`].
///
/// It is only meaningful for the `fundsOut` selector
/// ([`FUNDS_OUT_SELECTOR_POOLS`]), which the caller
/// (`server::apply_funds_out_binding`) has already whitelisted before invoking
/// it. It previously returned `Ok(())` for any other selector, so a future
/// refactor that called it directly - skipping that whitelist - would get a
/// *silent success* for an unsupported selector (audit I-03 / Oxorio I-10:
/// caller-ordering instead of failing closed). Reject instead: a
/// selector-specific validator handed the wrong selector is a programming
/// error, so fail closed rather than pass.
fn ensure_funds_out_selector(call_data: &[u8], validator: &str) -> Result<()> {
    if call_data.len() < 4 || call_data[..4] != FUNDS_OUT_SELECTOR_POOLS {
        return Err(EnclaveError::CrossCheck(format!(
            "{validator} called with a non-fundsOut selector - selector-specific validators must \
             only run after the fundsOut whitelist in apply_funds_out_binding"
        )));
    }
    Ok(())
}

/// Pools-side amount cross-check for the `fundsOut` transfer flow. Binds the
/// calldata `amount` to the consignment's actual asset value:
///
///   1. The consignment's most recent transition must be an IFA `Transfer`
///      (`transition_type == ifa::TS_TRANSFER`).
///   2. The transition's `total_output_amount` must cover the EVM-side release
///      `amount`.
///
/// Fails closed (does not no-op) if handed anything but the `fundsOut`
/// selector - see [`ensure_funds_out_selector`] (audit I-03).
pub fn validate_funds_out_transfer(
    call_data: &[u8],
    validated: &ValidatedConsignment,
) -> Result<()> {
    use crate::networks::rgb::validation::ifa;

    ensure_funds_out_selector(call_data, "validate_funds_out_transfer")?;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "pools fundsOut requires a consignment with at least one transition".into(),
        )
    })?;
    if last.transition_type != ifa::TS_TRANSFER {
        return Err(EnclaveError::CrossCheck(format!(
            "pools fundsOut requires a Transfer transition (last transition_type = {}, want {})",
            last.transition_type,
            ifa::TS_TRANSFER
        )));
    }

    // Read `amount` straight from the calldata bytes rather than trusting the
    // listener-supplied `calldata_amount`, then bind it to the consignment's
    // output value — the consignment is the authority on how much RGB moved.
    let calldata_amount = extract_uint256_as_u64(call_data, FUNDS_OUT_AMOUNT_OFFSET)?;
    if last.total_output_amount < calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "transfer amount mismatch: consignment total_output_amount ({}) < calldata amount ({})",
            last.total_output_amount, calldata_amount
        )));
    }
    Ok(())
}

/// The OpId → on-chain-id transform: `keccak256(op_id_bytes)`. This MUST match
/// the derivation the backend uses when it builds the `fundsOut` calldata; the
/// whole OpId binding hinges on this single function.
fn op_id_to_calldata_id(op_id: &str) -> Result<[u8; 32]> {
    let bytes = decode_op_id_to_bytes32(op_id)?;
    Ok(Keccak256::digest(bytes).into())
}

/// OpId binding applied to a `fundsOut` calldata before signing (audit
/// TEE-SE-02 / M-02 / #93, spec §6/§7). The enclave does NOT trust the
/// listener's `burnId`/`fundsInIds`; it derives them from the consignment it
/// validated and **overwrites** the calldata it signs:
///   - `burnId` (offset 68) := `keccak256(last_transfer_op_id)`; and
///   - `settlementData` := `abi.encode(uint256[] fundsInIds)` over
///     `op_id_to_calldata_id(opid)` for every IFA `TS_INFLATION` transition.
///
/// Returns the rewritten calldata. Because the signature commits to
/// `keccak256(callData)`, these bytes are authoritative — **the caller MUST
/// submit exactly the returned bytes**.
pub fn apply_op_id_binding(call_data: &[u8], validated: &ValidatedConsignment) -> Result<Vec<u8>> {
    // burnId is derived from the rgbstd-VALIDATED OpId of the release
    // (TS_TRANSFER) transition (`last_transfer_op_id`), not the flat parser
    // (audit M-02 / #93). Fail closed if it wasn't extracted.
    let op_id = validated.last_transfer_op_id.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "OpId binding requires the validated OpId of the release transition, but none was \
             extracted (the last transition is not a validated Transfer) - refusing to sign"
                .into(),
        )
    })?;
    let burn_id: [u8; 32] = Keccak256::digest(op_id).into();
    let funds_in_ids: Vec<[u8; 32]> = validated
        .mint_op_ids
        .iter()
        .map(|o| op_id_to_calldata_id(o))
        .collect::<Result<_>>()?;

    // The 8-word head (after the 4-byte selector) must be present to locate the
    // burnId slot and the settlementData offset.
    let head_end = FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET + 32; // 260
    if call_data.len() < head_end {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut calldata too short: need {head_end} head bytes, got {}",
            call_data.len()
        )));
    }

    let mut out = call_data.to_vec();

    // (1) Overwrite burnId in place (a static head slot).
    out[FUNDS_OUT_BURN_ID_OFFSET..FUNDS_OUT_BURN_ID_OFFSET + 32].copy_from_slice(&burn_id);

    // (2) Replace settlementData (the last dynamic arg). Read its tail offset
    //     (relative to the args start, byte 4), drop the old tail, and append a
    //     fresh `abi.encode(uint256[] fundsInIds)`. The head offset word still
    //     points at the same start, so it needs no update.
    let sd_rel = bytes32_to_usize(&extract_bytes32(
        &out,
        FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET,
    )?)?;
    let sd_start = 4usize
        .checked_add(sd_rel)
        .ok_or_else(|| EnclaveError::CrossCheck("settlementData offset overflow".into()))?;
    if sd_start < head_end || sd_start > out.len() {
        return Err(EnclaveError::CrossCheck(format!(
            "settlementData offset out of range: {sd_start} (head_end {head_end}, len {})",
            out.len()
        )));
    }
    out.truncate(sd_start);

    // settlementData is a dynamic `bytes`: [length][payload], where payload is
    // `abi.encode(uint256[])` = [0x20 offset][N][ids...].
    let payload_len = 64 + funds_in_ids.len() * 32;
    out.extend_from_slice(&u256_word(payload_len)); // bytes length
    out.extend_from_slice(&u256_word(32)); // inner array offset (0x20)
    out.extend_from_slice(&u256_word(funds_in_ids.len())); // N
    for id in &funds_in_ids {
        out.extend_from_slice(id);
    }

    Ok(out)
}

/// Encode a `usize` as a big-endian 32-byte ABI word.
fn u256_word(n: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(n as u64).to_be_bytes());
    w
}

/// BtcRelay-agreement cross-check (bridge spec §13, #57/#122). Binds the
/// calldata's claimed `proof = abi.encode(uint256 blockHeight, bytes32
/// commitmentHash)` to the header the enclave holds at that height, so a
/// listener can't split the contract's on-chain BtcRelay check away from the
/// enclave's own SPV evidence. A no-op for non-`fundsOut` selectors and inert
/// when the `proof` slot is empty (pre-migration).
///
/// Byte order: the calldata `commitmentHash` is display (big-endian) order; the
/// in-enclave `header.block_hash()` is internal order, so we reverse it before
/// comparing.
pub fn verify_btc_relay_agreement(call_data: &[u8], chain: &HeaderChain) -> Result<()> {
    use bitcoin::hashes::Hash as _;

    if call_data.len() < 4 || call_data[..4] != FUNDS_OUT_SELECTOR_POOLS {
        return Ok(());
    }
    let Some((block_height, commitment_hash)) = decode_funds_out_proof(call_data)? else {
        // proof slot empty → no calldata commitment to bind (pre-migration).
        return Ok(());
    };

    let header = chain.header_at(block_height).ok_or_else(|| {
        EnclaveError::Spv(format!(
            "fundsOut BtcRelay check: no header at block height {block_height} \
             (chain tip = {}) — cannot confirm the calldata commitment against \
             the enclave header chain",
            chain.tip_height()
        ))
    })?;

    let mut stored_display: [u8; 32] = header.block_hash().to_byte_array();
    stored_display.reverse();
    if stored_display != commitment_hash {
        return Err(EnclaveError::Spv(format!(
            "fundsOut BtcRelay check: calldata commitmentHash {} != enclave header \
             hash {} at block height {block_height}",
            hex::encode(commitment_hash),
            hex::encode(stored_display)
        )));
    }
    Ok(())
}

/// Decode the `fundsOut` `proof` slot into `(block_height, commitment_hash)`.
/// Returns `Ok(None)` when the `proof` bytes are empty (pre-migration shape).
fn decode_funds_out_proof(call_data: &[u8]) -> Result<Option<(u32, [u8; 32])>> {
    // (1) proof tail offset, measured from the args start (byte 4).
    let proof_offset = read_u256_as_usize(call_data, FUNDS_OUT_PROOF_HEAD_OFFSET)?;
    let tail_start = 4usize
        .checked_add(proof_offset)
        .ok_or_else(|| EnclaveError::CrossCheck("fundsOut proof offset overflow".into()))?;

    // (2) length word of the `bytes`.
    let payload_start = tail_start
        .checked_add(32)
        .ok_or_else(|| EnclaveError::CrossCheck("fundsOut proof length overflow".into()))?;
    if call_data.len() < payload_start {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short for fundsOut proof length: need {payload_start}, got {}",
            call_data.len()
        )));
    }
    let proof_len = read_u256_as_usize(call_data, tail_start)?;
    if proof_len == 0 {
        return Ok(None);
    }
    if proof_len != 64 {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut proof must be abi.encode(uint256 blockHeight, bytes32 commitmentHash) \
             = 64 bytes, got {proof_len}"
        )));
    }

    // (3) payload: [blockHeight: uint256][commitmentHash: bytes32].
    let payload_end = payload_start
        .checked_add(64)
        .ok_or_else(|| EnclaveError::CrossCheck("fundsOut proof payload overflow".into()))?;
    if call_data.len() < payload_end {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short for fundsOut proof payload: need {payload_end}, got {}",
            call_data.len()
        )));
    }
    let payload = &call_data[payload_start..payload_end];

    // blockHeight is a uint256 that must fit in u32 (Bitcoin heights do).
    if payload[..28].iter().any(|&b| b != 0) {
        return Err(EnclaveError::CrossCheck(
            "fundsOut proof blockHeight exceeds u32 range".into(),
        ));
    }
    let mut bh = [0u8; 4];
    bh.copy_from_slice(&payload[28..32]);
    let block_height = u32::from_be_bytes(bh);

    let mut commitment_hash = [0u8; 32];
    commitment_hash.copy_from_slice(&payload[32..64]);

    Ok(Some((block_height, commitment_hash)))
}

/// Read a 32-byte ABI word at `offset` and interpret it as a `usize`, range
/// checked (the high bytes must be zero) rather than silently truncated.
fn read_u256_as_usize(call_data: &[u8], offset: usize) -> Result<usize> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| EnclaveError::CrossCheck("fundsOut word offset overflow".into()))?;
    if call_data.len() < end {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need {end} bytes, got {}",
            call_data.len()
        )));
    }
    let word = &call_data[offset..end];
    if word[..24].iter().any(|&b| b != 0) {
        return Err(EnclaveError::CrossCheck(
            "fundsOut ABI word exceeds usize range".into(),
        ));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    Ok(u64::from_be_bytes(buf) as usize)
}

/// Read a uint256 from call_data at a byte offset, as u64. Fails if too short or
/// the value exceeds u64.
pub(crate) fn extract_uint256_as_u64(call_data: &[u8], offset: usize) -> Result<u64> {
    let end = offset + 32;
    if call_data.len() < end {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need {} bytes, got {}",
            end,
            call_data.len()
        )));
    }
    let slot = &call_data[offset..end];
    if slot[..24].iter().any(|&b| b != 0) {
        return Err(EnclaveError::CrossCheck(
            "uint256 value exceeds u64 range".into(),
        ));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&slot[24..32]);
    Ok(u64::from_be_bytes(buf))
}

/// Read a full 32-byte word (a `bytes32`/`uint256` head slot) at a fixed offset.
/// Safe only for the static `fundsOut` head slots.
fn extract_bytes32(call_data: &[u8], offset: usize) -> Result<[u8; 32]> {
    let end = offset + 32;
    if call_data.len() < end {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need {} bytes, got {}",
            end,
            call_data.len()
        )));
    }
    call_data[offset..end]
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("bytes32 slice conversion failed".into()))
}

/// Decode an RGB OpId string (64-char hex of the 32-byte OpId) into raw bytes.
/// Fails closed if not exactly 32 bytes of hex.
fn decode_op_id_to_bytes32(op_id: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(op_id).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "op_id is not hex-decodable (got {op_id:?}): {e} — burnId binding needs the \
             32-byte OpId form"
        ))
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "op_id decodes to {} bytes, expected 32 (op_id {op_id:?})",
            bytes.len()
        ))
    })
}

/// Interpret a 32-byte ABI word as a `usize`, failing closed if the high 24
/// bytes are non-zero.
fn bytes32_to_usize(word: &[u8; 32]) -> Result<usize> {
    if word[..24].iter().any(|&b| b != 0) {
        return Err(EnclaveError::CrossCheck(
            "ABI offset/length word exceeds usize range".into(),
        ));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    Ok(u64::from_be_bytes(buf) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a mock `fundsOut` calldata in the 8-arg shape
    /// (`fundsOut(address,uint256,uint256,uint256,uint256,string,bytes,bytes)`
    /// = [`FUNDS_OUT_SELECTOR_POOLS`]) with `amount` at
    /// [`FUNDS_OUT_AMOUNT_OFFSET`] (byte 36). Remaining head slots are
    /// zero-filled — none of the cross-checks here read them.
    fn mock_funds_out_calldata(amount: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 8 * 32);
        data.extend_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
        // recipient (32, address)
        data.extend_from_slice(&[0u8; 32]);
        // amount (uint256) @ offset 36
        let mut amt = [0u8; 32];
        amt[24..].copy_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&amt);
        // 6 more head slots zero-filled (burnId, sourceChainId,
        // destinationChainId, srcAddrOffset, proofOffset, settlementDataOffset).
        data.extend_from_slice(&[0u8; 32 * 6]);
        data
    }

    /// Parse the `fundsOut` `settlementData` (`abi.encode(uint256[] fundsInIds)`)
    /// and return each `fundsInId` as a raw 32-byte word.
    ///
    /// Two levels of ABI indirection: (1) the `settlementData` head slot at
    /// [`FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET`] holds a tail offset measured from
    /// the start of the argument block (byte 4); (2) at that tail the `bytes` has
    /// a length word followed by its payload, which is itself
    /// `abi.encode(uint256[])` = `[0x20 offset][len N][N words]`. Every read is
    /// bounds-checked (via [`extract_bytes32`]) and every offset/length is range
    /// checked (via [`bytes32_to_usize`]); a malformed or truncated blob is a hard
    /// error. Returns an empty vec when `settlementData` is empty.
    ///
    /// The enclave OVERWRITES `settlementData` ([`apply_op_id_binding`]) rather
    /// than reading it, so this reader exists only to verify, in tests, that the
    /// writer's encoding round-trips — hence it lives in the test module.
    fn extract_funds_in_ids(call_data: &[u8]) -> Result<Vec<[u8; 32]>> {
        // (1) settlementData tail offset (relative to the args start = byte 4).
        let rel = bytes32_to_usize(&extract_bytes32(
            call_data,
            FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET,
        )?)?;
        let sd_start = 4usize
            .checked_add(rel)
            .ok_or_else(|| EnclaveError::CrossCheck("settlementData offset overflow".into()))?;

        // settlementData `bytes`: [length word][payload].
        let sd_len = bytes32_to_usize(&extract_bytes32(call_data, sd_start)?)?;
        if sd_len == 0 {
            return Ok(vec![]); // no fundsInIds claimed
        }
        let sd_body = sd_start
            .checked_add(32)
            .ok_or_else(|| EnclaveError::CrossCheck("settlementData body overflow".into()))?;
        let sd_end = sd_body
            .checked_add(sd_len)
            .ok_or_else(|| EnclaveError::CrossCheck("settlementData length overflow".into()))?;
        if call_data.len() < sd_end {
            return Err(EnclaveError::CrossCheck(format!(
                "call_data too short for settlementData: need {sd_end}, got {}",
                call_data.len()
            )));
        }
        let sd = &call_data[sd_body..sd_end];

        // (2) sd = abi.encode(uint256[]) = [offset (0x20)][len N][N words].
        let arr_off = bytes32_to_usize(&extract_bytes32(sd, 0)?)?;
        let n = bytes32_to_usize(&extract_bytes32(sd, arr_off)?)?;
        let elems_start = arr_off.checked_add(32).ok_or_else(|| {
            EnclaveError::CrossCheck("fundsInIds elements offset overflow".into())
        })?;
        let span = n
            .checked_mul(32)
            .and_then(|x| elems_start.checked_add(x))
            .ok_or_else(|| EnclaveError::CrossCheck("fundsInIds array size overflow".into()))?;
        if sd.len() < span {
            return Err(EnclaveError::CrossCheck(format!(
                "settlementData too short for {n} fundsInIds: need {span}, got {}",
                sd.len()
            )));
        }

        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            ids.push(extract_bytes32(sd, elems_start + i * 32)?);
        }
        Ok(ids)
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

    #[test]
    fn extract_bytes32_works() {
        let mut data = vec![0u8; 4 + 32 + 32 + 32];
        let mut word = [0u8; 32];
        word[0] = 0xab;
        word[31] = 0xcd;
        data[68..100].copy_from_slice(&word); // burnId head slot
        assert_eq!(extract_bytes32(&data, 68).unwrap(), word);
    }

    #[test]
    fn extract_bytes32_rejects_short_data() {
        let data = vec![0u8; 90]; // burnId slot ends at 100
        assert!(extract_bytes32(&data, 68).is_err());
    }

    #[test]
    fn bytes32_to_usize_works() {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&320u64.to_be_bytes());
        assert_eq!(bytes32_to_usize(&w).unwrap(), 320);
    }

    #[test]
    fn bytes32_to_usize_rejects_out_of_range() {
        let mut w = [0u8; 32];
        w[0] = 1; // high byte set — exceeds usize/u64
        assert!(bytes32_to_usize(&w).is_err());
    }

    // =========================================================================
    // Pools fundsOut tests — `validate_funds_out_transfer` (+ the #95 witness
    // recency guard `assert_witnesses_confirmed`).
    // =========================================================================

    mod transfer {
        use super::*;
        use crate::networks::rgb::validation::{ifa, TransitionSummary, ValidatedConsignment};

        fn validated_with_last(transition: TransitionSummary) -> ValidatedConsignment {
            ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: vec![transition.op_id.clone()],
                mint_op_ids: vec![],
                last_transition: Some(transition),
                last_transfer_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
            }
        }

        fn transfer_transition(total_output_amount: u64) -> TransitionSummary {
            TransitionSummary {
                op_id: "transfer-op".into(),
                transition_type: ifa::TS_TRANSFER,
                total_output_amount,
                asset_output_amount: total_output_amount,
                outputs: Vec::new(),
                burned_asset_amount: None,
            }
        }

        #[test]
        fn passes_when_total_output_covers_calldata_amount() {
            let cd = mock_funds_out_calldata(1000);
            let validated = validated_with_last(transfer_transition(1000));
            assert!(validate_funds_out_transfer(&cd, &validated).is_ok());
        }

        #[test]
        fn witnesses_confirmed_passes_when_all_mined() {
            // No non-mined witnesses surfaced -> the recency guard is a no-op
            // (audit 4th I-03 / #95).
            let validated = validated_with_last(transfer_transition(1000));
            assert!(super::super::assert_witnesses_confirmed(&validated).is_ok());
        }

        #[test]
        fn witnesses_confirmed_rejects_non_mined() {
            // A tentative/ignored witness in the RGB->EVM direction is an
            // anomaly: the unlock settles an already-confirmed transfer.
            let mut validated = validated_with_last(transfer_transition(1000));
            validated.non_mined_witness_txids = vec![[0xABu8; 32]];
            let err = super::super::assert_witnesses_confirmed(&validated).unwrap_err();
            assert!(
                err.to_string().contains("mined"),
                "expected not-mined rejection, got: {err}"
            );
        }

        #[test]
        fn passes_when_total_output_exceeds_calldata_amount() {
            let cd = mock_funds_out_calldata(1000);
            let validated = validated_with_last(transfer_transition(2000));
            assert!(validate_funds_out_transfer(&cd, &validated).is_ok());
        }

        /// P0 regression: even with a valid consignment that deserializes
        /// and validates, the EVM-side release cannot exceed the RGB-side
        /// transfer total. A consignment for 1 unit must not authorise a
        /// withdrawal for 10^9.
        #[test]
        fn rejects_when_total_output_less_than_calldata_amount() {
            let cd = mock_funds_out_calldata(1_000_000_000);
            let validated = validated_with_last(transfer_transition(1));
            let err = validate_funds_out_transfer(&cd, &validated).unwrap_err();
            assert!(
                err.to_string().contains("transfer amount mismatch"),
                "expected transfer amount mismatch, got: {err}"
            );
        }

        /// A burn consignment arriving on the (single) `fundsOut`
        /// selector must be rejected by the transfer check — this is how
        /// mint/burn stays off until it's wired by contract address.
        #[test]
        fn rejects_when_last_transition_is_not_transfer() {
            let cd = mock_funds_out_calldata(500);
            let mut t = transfer_transition(500);
            t.transition_type = ifa::TS_BURN;
            let validated = validated_with_last(t);
            let err = validate_funds_out_transfer(&cd, &validated).unwrap_err();
            assert!(
                err.to_string().contains("requires a Transfer transition"),
                "expected Transfer-required rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_when_consignment_has_no_transition() {
            let cd = mock_funds_out_calldata(500);
            let validated = ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: vec![],
                mint_op_ids: vec![],
                last_transition: None,
                last_transfer_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
            };
            let err = validate_funds_out_transfer(&cd, &validated).unwrap_err();
            assert!(
                err.to_string().contains("at least one transition"),
                "expected no-transition rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_non_funds_out_selector() {
            // Calldata with a selector that isn't `fundsOut` — the
            // selector-specific validator fails closed instead of silently
            // passing (audit I-03: the pre-#127 contract was a no-op; a caller
            // skipping the `apply_funds_out_binding` whitelist must not get an
            // `Ok`).
            let mut cd = vec![0u8; 4 + 8 * 32];
            cd[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            let validated = validated_with_last(transfer_transition(0));
            let err = validate_funds_out_transfer(&cd, &validated).unwrap_err();
            assert!(
                err.to_string().contains("non-fundsOut selector"),
                "expected the fail-closed selector guard, got: {err}"
            );
        }
    }

    // =========================================================================
    // OpId binding — `apply_op_id_binding` (audit TEE-SE-02, spec §6/§7). The
    // enclave derives burnId / fundsInIds from the consignment it validated and
    // OVERWRITES them in the calldata it signs. No listener-supplied OpId is
    // trusted or even read. `extract_funds_in_ids` confirms the writer's
    // settlementData round-trips through the reader.
    // =========================================================================

    mod op_id_binding {
        use super::*;
        use crate::networks::rgb::validation::{ifa, TransitionSummary, ValidatedConsignment};
        use sha3::{Digest, Keccak256};

        const OP_ID: &str = "74c1d59264894a1bd44887fe84b36739c024bd50188e69baeeda845569313543";
        const MINT_A: &str = "f5106c6ddb8b8fd3d1de3bda0106ae13ef0705dc36bfc543566362e5e8dd4bd5";
        const MINT_B: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        /// The binding transform: keccak256 of the raw 32-byte OpId.
        fn id(op_id: &str) -> [u8; 32] {
            Keccak256::digest(hex::decode(op_id).unwrap()).into()
        }

        fn u256(n: usize) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&(n as u64).to_be_bytes());
            w
        }

        /// Build `fundsOut` calldata with the given `burnId` (offset 68) and
        /// `fundsInIds` (encoded in `settlementData = abi.encode(uint256[])`).
        /// `sourceAddress` and `proof` are present but empty. The ABI tail
        /// layout mirrors what `extract_funds_in_ids` traverses.
        fn mock_funds_out(burn_id: [u8; 32], funds_in_ids: &[[u8; 32]]) -> Vec<u8> {
            let mut d = Vec::new();
            d.extend_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
            d.extend_from_slice(&[0u8; 32]); // recipient
            d.extend_from_slice(&[0u8; 32]); // amount
            d.extend_from_slice(&burn_id); // burnId @68
            d.extend_from_slice(&[0u8; 32]); // sourceChainId
            d.extend_from_slice(&[0u8; 32]); // destinationChainId
            d.extend_from_slice(&u256(256)); // sourceAddress tail offset (rel byte 4)
            d.extend_from_slice(&u256(288)); // proof tail offset
            d.extend_from_slice(&u256(320)); // settlementData tail offset
            d.extend_from_slice(&u256(0)); // sourceAddress length = 0
            d.extend_from_slice(&u256(0)); // proof length = 0
                                           // settlementData bytes = abi.encode(uint256[]) = [0x20][N][ids...]
            let payload_len = 64 + funds_in_ids.len() * 32;
            d.extend_from_slice(&u256(payload_len)); // settlementData length
            d.extend_from_slice(&u256(32)); // inner array offset (0x20)
            d.extend_from_slice(&u256(funds_in_ids.len())); // N
            for fid in funds_in_ids {
                d.extend_from_slice(fid);
            }
            d
        }

        fn transition(op_id: &str, transition_type: u16) -> TransitionSummary {
            TransitionSummary {
                op_id: op_id.into(),
                transition_type,
                total_output_amount: 0,
                asset_output_amount: 0,
                outputs: Vec::new(),
                burned_asset_amount: None,
            }
        }

        /// The validated last-transfer OpId bytes for a given hex OpId - the
        /// authoritative burnId source (`ValidatedConsignment::last_transfer_op_id`).
        fn op_id_bytes(op_id: &str) -> [u8; 32] {
            hex::decode(op_id).unwrap().try_into().unwrap()
        }

        fn validated(
            last: Option<TransitionSummary>,
            mint_op_ids: Vec<String>,
        ) -> ValidatedConsignment {
            // The burnId is derived from the rgbstd-VALIDATED OpId, so mirror
            // production: `last_transfer_op_id` carries the same OpId as the
            // last transition (set by `read_last_transfer_witness` for a
            // TS_TRANSFER last transition).
            let last_transfer_op_id = last.as_ref().map(|t| op_id_bytes(&t.op_id));
            ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: last
                    .as_ref()
                    .map(|t| vec![t.op_id.clone()])
                    .unwrap_or_default(),
                mint_op_ids,
                last_transition: last,
                last_transfer_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id,
                non_mined_witness_txids: vec![],
            }
        }

        // ---- apply_op_id_binding (override, not verify) ----

        /// Writes burnId@68 = keccak256(validated OpId), overriding whatever the
        /// bridge put there. The OpId is sourced from the rgbstd-validated
        /// transfer (`last_transfer_op_id`), not the flat parser (audit M-02 / #93).
        #[test]
        fn writes_burn_id_from_validated_op_id() {
            let cd = mock_funds_out([0xEE; 32], &[]); // bogus burnId in input
            let v = validated(Some(transition(OP_ID, ifa::TS_TRANSFER)), vec![]);
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert_eq!(
                extract_bytes32(&out, FUNDS_OUT_BURN_ID_OFFSET).unwrap(),
                id(OP_ID)
            );
        }

        /// Fail closed when no validated OpId was extracted (e.g. a non-Transfer
        /// last transition): the enclave must refuse rather than fall back to a
        /// listener- or flat-parser-supplied burnId.
        #[test]
        fn rejects_when_validated_op_id_missing() {
            let cd = mock_funds_out([0xEE; 32], &[]);
            let mut v = validated(Some(transition(OP_ID, ifa::TS_TRANSFER)), vec![]);
            v.last_transfer_op_id = None;
            let err = apply_op_id_binding(&cd, &v).unwrap_err();
            assert!(
                err.to_string()
                    .contains("validated OpId of the release transition"),
                "got: {err}"
            );
        }

        /// Writes ALL mint OpIds into settlementData, overriding the bridge's set.
        #[test]
        fn writes_all_mint_funds_in_ids() {
            let cd = mock_funds_out([0xEE; 32], &[[0x11; 32], [0x22; 32]]);
            let v = validated(
                Some(transition(OP_ID, ifa::TS_BURN)),
                vec![MINT_A.into(), MINT_B.into()],
            );
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert_eq!(
                extract_funds_in_ids(&out).unwrap(),
                vec![id(MINT_A), id(MINT_B)]
            );
        }

        /// No mints in the consignment → empty fundsInIds (not an error).
        #[test]
        fn writes_empty_funds_in_ids_when_no_mints() {
            let cd = mock_funds_out([0xEE; 32], &[[0x11; 32]]);
            let v = validated(Some(transition(OP_ID, ifa::TS_BURN)), vec![]);
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert!(extract_funds_in_ids(&out).unwrap().is_empty());
        }

        /// Override, not verify: a fully bogus input (wrong burnId AND wrong
        /// fundsInIds) is rewritten to the consignment's values.
        #[test]
        fn overrides_whatever_the_bridge_sent() {
            let cd = mock_funds_out([0xEE; 32], &[[0xAB; 32]]);
            let v = validated(Some(transition(OP_ID, ifa::TS_BURN)), vec![MINT_A.into()]);
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert_eq!(
                extract_bytes32(&out, FUNDS_OUT_BURN_ID_OFFSET).unwrap(),
                id(OP_ID)
            );
            assert_eq!(extract_funds_in_ids(&out).unwrap(), vec![id(MINT_A)]);
        }

        /// The non-OpId fields (recipient, amount) are left exactly as sent.
        #[test]
        fn preserves_non_op_id_fields() {
            let mut cd = mock_funds_out([0xEE; 32], &[[0x11; 32]]);
            cd[4..36].copy_from_slice(&u256(0xBEEF)); // recipient marker
            cd[36..68].copy_from_slice(&u256(123_456)); // amount marker
            let v = validated(Some(transition(OP_ID, ifa::TS_BURN)), vec![MINT_A.into()]);
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert_eq!(&out[4..36], &u256(0xBEEF));
            assert_eq!(&out[36..68], &u256(123_456));
        }

        /// A mint OpId that isn't 32-byte hex can not be transformed - fail
        /// closed. (The burnId now comes from the pre-validated
        /// `last_transfer_op_id` bytes, so the only string-decoded OpIds left
        /// are the `fundsInIds` mint set.)
        #[test]
        fn rejects_non_hex_op_id() {
            let cd = mock_funds_out([0xEE; 32], &[]);
            let v = validated(
                Some(transition(OP_ID, ifa::TS_TRANSFER)),
                vec!["not-hex".into()],
            );
            let err = apply_op_id_binding(&cd, &v).unwrap_err();
            assert!(
                err.to_string().contains("hex-decodable")
                    || err.to_string().contains("expected 32"),
                "expected op_id decode rejection, got: {err}"
            );
        }

        /// Calldata too short to hold the fundsOut head is rejected.
        #[test]
        fn rejects_calldata_too_short() {
            let v = validated(Some(transition(OP_ID, ifa::TS_BURN)), vec![]);
            let err = apply_op_id_binding(&[0u8; 100], &v).unwrap_err();
            assert!(err.to_string().contains("too short"), "got: {err}");
        }

        /// No validated release OpId to bind against -> hard error.
        #[test]
        fn rejects_no_transition() {
            let cd = mock_funds_out([0xEE; 32], &[]);
            let v = validated(None, vec![]);
            let err = apply_op_id_binding(&cd, &v).unwrap_err();
            assert!(
                err.to_string()
                    .contains("validated OpId of the release transition"),
                "got: {err}"
            );
        }

        // ---- settlementData ABI round-trip (writer vs reader agree) ----

        #[test]
        fn settlement_parser_round_trips() {
            let ids = [id(MINT_A), id(MINT_B)];
            let cd = mock_funds_out(id(OP_ID), &ids);
            assert_eq!(extract_funds_in_ids(&cd).unwrap(), ids.to_vec());
        }

        #[test]
        fn settlement_parser_empty() {
            let cd = mock_funds_out(id(OP_ID), &[]);
            assert!(extract_funds_in_ids(&cd).unwrap().is_empty());
        }
    }

    // =========================================================================
    // BtcRelay-agreement cross-check (#57 / #122) — `verify_btc_relay_agreement`.
    // These exercise `proof` decoding and header comparison directly against a
    // synthetic regtest header chain.
    // =========================================================================

    mod btc_relay {
        use super::*;
        use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
        use bitcoin::block::{Header, Version};
        use bitcoin::consensus::serialize;
        use bitcoin::hashes::Hash as _;

        /// Encode `n` as a big-endian 32-byte ABI word.
        fn u256_be(n: u64) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&n.to_be_bytes());
            w
        }

        /// A regtest chain with a single synthetic header at height 1 (PoW is
        /// skipped on regtest — same pattern as the `spv::chain` tests).
        /// Returns the chain and the header's DISPLAY-order block hash — the
        /// byte order the calldata `commitmentHash` carries.
        fn chain_with_one_header() -> (HeaderChain, [u8; 32]) {
            let mut chain = HeaderChain::new(
                Network::Regtest,
                Checkpoint {
                    height: 0,
                    hash: [0u8; 32],
                    bits: 0x207fffff,
                    time: 1_700_000_000,
                    is_real: false,
                },
            );
            let header = Header {
                version: Version::ONE,
                prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xAB; 32]),
                time: 1_700_000_001,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            };
            chain.submit_headers(1, &[serialize(&header)]).unwrap();
            let mut display: [u8; 32] = header.block_hash().to_byte_array();
            display.reverse();
            (chain, display)
        }

        /// `fundsOut` calldata carrying a well-formed `proof` tail. The 8 head
        /// slots are zero except `proofOffset` (slot 6), which points at the
        /// tail laid out right after the head (= 256 bytes from the args
        /// start). Tail: `[length=64][blockHeight uint256][commitmentHash]`.
        fn calldata_with_proof(block_height: u32, commitment_display: [u8; 32]) -> Vec<u8> {
            let mut data = Vec::new();
            data.extend_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
            let mut head = [0u8; 8 * 32];
            head[6 * 32..7 * 32].copy_from_slice(&u256_be(256)); // proofOffset
            data.extend_from_slice(&head);
            data.extend_from_slice(&u256_be(64)); // proof bytes length
            data.extend_from_slice(&u256_be(block_height as u64)); // blockHeight
            data.extend_from_slice(&commitment_display); // commitmentHash
            data
        }

        #[test]
        fn passes_on_matching_commitment() {
            let (chain, display_hash) = chain_with_one_header();
            let cd = calldata_with_proof(1, display_hash);
            assert!(verify_btc_relay_agreement(&cd, &chain).is_ok());
        }

        #[test]
        fn rejects_mismatched_commitment() {
            let (chain, _display_hash) = chain_with_one_header();
            let cd = calldata_with_proof(1, [0x11; 32]);
            let err = verify_btc_relay_agreement(&cd, &chain).unwrap_err();
            assert!(err.to_string().contains("commitmentHash"), "got: {err}");
        }

        #[test]
        fn rejects_internal_order_commitment() {
            // Defends the byte-order contract: feeding the INTERNAL-order hash
            // (the un-reversed `block_hash()` bytes) must be rejected — the
            // calldata convention is display order.
            let (chain, mut display_hash) = chain_with_one_header();
            display_hash.reverse(); // back to internal order
            let cd = calldata_with_proof(1, display_hash);
            assert!(verify_btc_relay_agreement(&cd, &chain).is_err());
        }

        #[test]
        fn rejects_height_beyond_tip() {
            let (chain, display_hash) = chain_with_one_header();
            let cd = calldata_with_proof(99, display_hash);
            let err = verify_btc_relay_agreement(&cd, &chain).unwrap_err();
            assert!(
                err.to_string().contains("no header at block height 99"),
                "got: {err}"
            );
        }

        #[test]
        fn inert_when_proof_empty() {
            // The current live calldata shape zero-fills the proof offset, so
            // the decoder reads an empty `proof` and the check is a no-op.
            let (chain, _) = chain_with_one_header();
            let cd = mock_funds_out_calldata(1_000);
            assert!(verify_btc_relay_agreement(&cd, &chain).is_ok());
        }

        #[test]
        fn noop_on_non_fundsout_selector() {
            let (chain, _) = chain_with_one_header();
            let cd = vec![0xde, 0xad, 0xbe, 0xef]; // not the fundsOut selector
            assert!(verify_btc_relay_agreement(&cd, &chain).is_ok());
        }

        #[test]
        fn rejects_malformed_proof_length() {
            let (chain, display_hash) = chain_with_one_header();
            let mut cd = calldata_with_proof(1, display_hash);
            // Corrupt the proof `bytes` length word (at byte 260) to a
            // non-zero, non-64 value: a calldata that claims a proof must
            // carry a 64-byte one.
            cd[260..292].copy_from_slice(&u256_be(33));
            let err = verify_btc_relay_agreement(&cd, &chain).unwrap_err();
            assert!(err.to_string().contains("64 bytes"), "got: {err}");
        }

        #[test]
        fn rejects_blockheight_over_u32() {
            let (chain, display_hash) = chain_with_one_header();
            let mut cd = calldata_with_proof(1, display_hash);
            // Set a blockHeight word (at byte 292) that overflows u32.
            let mut huge = [0u8; 32];
            huge[20] = 0x01; // a bit set above the low 4 bytes
            cd[292..324].copy_from_slice(&huge);
            let err = verify_btc_relay_agreement(&cd, &chain).unwrap_err();
            assert!(err.to_string().contains("u32 range"), "got: {err}");
        }
    }
}
