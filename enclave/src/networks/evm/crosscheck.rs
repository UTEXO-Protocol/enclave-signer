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

/// Pools-side amount cross-check for the `fundsOut` transfer flow. Binds the
/// calldata `amount` to the consignment's actual asset value:
///
///   1. The consignment's most recent transition must be an IFA `Transfer`
///      (`transition_type == ifa::TS_TRANSFER`).
///   2. The transition's `total_output_amount` must cover the EVM-side release
///      `amount`.
///
/// A no-op for any non-`fundsOut` selector.
pub fn validate_funds_out_transfer(
    call_data: &[u8],
    validated: &ValidatedConsignment,
) -> Result<()> {
    use crate::networks::rgb::validation::ifa;

    if call_data.len() < 4 || call_data[..4] != FUNDS_OUT_SELECTOR_POOLS {
        return Ok(());
    }

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
fn extract_uint256_as_u64(call_data: &[u8], offset: usize) -> Result<u64> {
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
