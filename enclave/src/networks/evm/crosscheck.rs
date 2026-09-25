//! RGB->EVM `fundsOut` cross-checks: bind the calldata the enclave signs to the
//! consignment it validated. All logic here is `rgb-validation`-gated (the
//! module is only compiled then) because every check reads a
//! [`ValidatedConsignment`]; SPV builds additionally run the BtcRelay agreement
//! check ([`verify_btc_relay_agreement`]).
//!
//! The helpers operate on `EvmDestination.call_data` bytes.

use crate::error::{EnclaveError, Result};
use crate::networks::evm::validation::FundsOutParams;
use crate::networks::rgb::spv::HeaderChain;
use crate::networks::rgb::spv_crosscheck;
use crate::networks::rgb::spv_crosscheck::ChainPins;
use crate::networks::rgb::validation::ValidatedConsignment;
use crate::proto::MerkleProofEntry;

// Calldata is decoded via `sol!` ([`decode_funds_out_params`]), not at
// hard-coded byte offsets: the `FundsOutParams` tuple shifts every field by one
// head pointer word, so the old constants would be 32 bytes off.

/// Defense-in-depth for the RGB->EVM `fundsOut` direction:
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

/// Amount cross-check for the `fundsOut` direction. Binds the release `amount`
/// to the consignment's actual asset value:
///
///   1. The consignment's most recent transition must be the type this build's
///      RGB flow accepts on a withdrawal - a BFA `Transfer` under `rgb-swap`,
///      a BFA `Burn` under `rgb-mint-burn`.
///   2. The amount that transition proves left the source must cover the
///      EVM-side release `amount`.
///
/// Both legs come from [`crate::networks::rgb::flow::funds_out_source_amount`],
/// the same function the route proof is built from, so the two cannot disagree
/// about which transition authorized the release.
///
/// Takes the decoded intent, which also replaces the old selector
/// guard: `FundsOutParams` only exists after a successful `fundsOut` decode.
pub fn validate_funds_out_amount(
    params: &FundsOutParams,
    validated: &ValidatedConsignment,
) -> Result<()> {
    use crate::networks::rgb::flow;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "fundsOut requires a consignment with at least one transition".into(),
        )
    })?;
    // The consignment, not the listener-supplied `calldata_amount`, is the
    // authority on how much RGB moved.
    let source_amount = flow::funds_out_source_amount(last)?;

    let calldata_amount: u64 = params
        .amount
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("fundsOut amount exceeds u64 range".into()))?;
    // Coverage under rgb-swap, exact equality under rgb-mint-burn.
    flow::assert_funds_out_amount(source_amount, calldata_amount)
}

/// Redemption-side payout bind for the `fundsOut` burn flow: the target the
/// burner committed to (`MS_BURN_RECIPIENT`) must equal the calldata
/// `recipient`.
///
/// This is what makes a redemption unforgeable. Those 32 bytes sit inside the
/// burn operation, so they are covered by its OpId and signed by whoever spent
/// the burned units; binding them here means a release cannot be redirected by
/// anyone who merely holds a copy of the consignment.
///
/// The shape and amount halves of the burn rule are NOT repeated here.
/// [`validate_funds_out_amount`] runs first and, under `rgb-mint-burn`, its
/// [`crate::networks::rgb::flow::funds_out_source_amount`] already rejects
/// anything that is not a `Burn` covering the released amount. So a caller must
/// run that first - this function assumes it did.
#[cfg(feature = "rgb-mint-burn")]
pub fn validate_funds_out_burn_recipient(
    params: &FundsOutParams,
    validated: &ValidatedConsignment,
) -> Result<()> {
    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "burn fundsOut requires a consignment with at least one transition".into(),
        )
    })?;

    let recipient = last.burn_recipient.as_deref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "burn transition carries no MS_BURN_RECIPIENT metadata - this burn cannot authorise \
             a bridged redemption"
                .into(),
        )
    })?;
    // 32 bytes holding a 20-byte EVM address in the low half, ABI-style. The
    // high 12 must be zero: a non-zero prefix means the burner committed to
    // something that is not this address, and silently truncating it would pay
    // out to a target nobody signed.
    if recipient.len() != 32 || recipient[..12] != [0u8; 12] {
        return Err(EnclaveError::CrossCheck(format!(
            "MS_BURN_RECIPIENT is not a left-padded EVM address: 0x{}",
            hex::encode(recipient)
        )));
    }
    if recipient[12..] != params.recipient.as_slice()[..] {
        return Err(EnclaveError::CrossCheck(format!(
            "recipient mismatch: burn commits to 0x{}, calldata releases to {}",
            hex::encode(&recipient[12..]),
            params.recipient
        )));
    }

    Ok(())
}

/// Settlement bind for the BFA burn flow: `settlementData` must cite exactly
/// the deposits behind the burn's mint ancestry.
///
/// `RgbSettlementModule.beforeFundsOut` decodes `settlementData` as
/// `abi.encode(bytes32[] operationIds, uint256[] amounts)` and checks each
/// pair against the `(operationId, netAmount)` it recorded at `FundsIn`. It
/// does not know which deposits a given burn descends from; the enclave does,
/// because it verified every ancestry lock's receipt itself
/// ([`crate::networks::evm::events::verify_rgb_funds_in`]). Requiring the
/// cited set to equal that ancestry, pair for pair, ties the release to the
/// burn: a second release of the same burn cannot cite other deposits to earn
/// a fresh `burnId`.
///
/// Set equality, order-insensitive, no duplicates, canonical encoding. An
/// empty lock set refuses: in this build every signable asset is bridged, so a
/// burn with no verified deposit behind it settles nothing.
#[cfg(feature = "bfa-mint")]
pub fn validate_funds_out_settlement(
    params: &FundsOutParams,
    locks: &[crate::networks::evm::events::VerifiedLock],
) -> Result<()> {
    use alloy_primitives::{B256, U256};
    use alloy_sol_types::SolValue;

    type Settlement = (Vec<B256>, Vec<U256>);

    if locks.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "fundsOut settles no verified deposit: the burn's mint ancestry carries no EVM lock \
             this enclave verified - refusing to sign"
                .into(),
        ));
    }

    let decoded: Settlement = Settlement::abi_decode_params_validate(&params.settlementData)
        .map_err(|e| {
            EnclaveError::CrossCheck(format!("fundsOut settlementData does not decode: {e}"))
        })?;
    let (ids, amounts) = &decoded;
    if ids.len() != amounts.len() {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut settlementData cites {} ids but {} amounts",
            ids.len(),
            amounts.len()
        )));
    }
    if decoded.abi_encode_params() != params.settlementData.as_ref() {
        return Err(EnclaveError::CrossCheck(
            "fundsOut settlementData is not canonically encoded".into(),
        ));
    }

    let mut cited: Vec<([u8; 32], U256)> = ids
        .iter()
        .zip(amounts.iter())
        .map(|(id, amount)| (id.0, *amount))
        .collect();
    cited.sort();
    if cited.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(EnclaveError::CrossCheck(
            "fundsOut settlementData cites the same deposit twice".into(),
        ));
    }

    let mut expected: Vec<([u8; 32], U256)> = locks
        .iter()
        .map(|lock| (lock.operation_id, U256::from(lock.net_amount)))
        .collect();
    expected.sort();
    expected.dedup();

    if cited != expected {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut settlementData mismatch: calldata cites {} deposit(s), the burn's verified \
             mint ancestry has {} - every (operationId, netAmount) pair must match",
            cited.len(),
            expected.len()
        )));
    }
    Ok(())
}

/// One `(height, commitmentHash)` pair of the finality proof.
#[derive(Debug, Clone, Copy)]
struct ProofBlock {
    height: u32,
    /// Display (big-endian) byte order, as it appears in the calldata.
    commitment: [u8; 32],
}

/// BtcRelay agreement + consignment source-block bind (spec section 13,
/// #57/#122). Before signing a `fundsOut`:
///
/// 1. find the block anchoring the consignment's last witness tx from its SPV
///    Merkle proof, not from the calldata;
/// 2. require a header there, proving the TEE is in sync;
/// 3. require the calldata `proof` to name that same height.
///
/// The `proof` slot is `abi.encode(uint256 sourceHeight, bytes32 sourceCommit,
/// uint256 latestHeight, bytes32 latestCommit)` (`RGBVerifier.sol:115-117`):
/// `source` packaged the burn/transfer, `latest` is the relay tip. `latest` must
/// also sit within `MAX_RELAY_TIP_LAG_BLOCKS` of the enclave tip, so freshness
/// is not delegated to a relay the host also feeds. Empty `proof` = reject.
///
/// **The commitment words are not checked, by design.** They are BtcRelay's
/// `keccak256(StoredBlockHeader)` over relay-internal state (chainWork,
/// lastDiffAdjustment, the last ten timestamps), which the enclave cannot
/// compute - comparing them to `header.block_hash()` made every release
/// unsatisfiable. `RGBVerifier` checks each against the relay itself, so a
/// manipulated commitment reverts on-chain. The enclave enforces what only it
/// knows: which block the consignment is anchored in, by height.
///
/// Ordered cheapest-first: the pure calldata decode and the `latest` checks run
/// before the anchor resolution, which reads the chain and redoes a Merkle
/// verification.
pub fn verify_btc_relay_agreement(
    params: &FundsOutParams,
    validated: &ValidatedConsignment,
    merkle_proofs: &[MerkleProofEntry],
    chain: &HeaderChain,
    pins: &ChainPins,
) -> Result<()> {
    let (source, latest) = decode_funds_out_proof(params)?;

    // The tip cannot precede the block it buries. Caught here so the error names
    // the problem instead of surfacing as a header-lookup failure.
    if latest.height < source.height {
        return Err(EnclaveError::Spv(format!(
            "fundsOut BtcRelay check: proof latest height {} is below source height {} - \
             the relay tip cannot precede the block that packaged the burn",
            latest.height, source.height
        )));
    }

    assert_header_present(chain, &latest, "latest")?;
    // Pin the relay's `latest` header too. A reorg that replaces it removes
    // the freshness this check proved.
    pins.pin(chain, latest.height)?;

    // `latest` must actually be near the tip, else it proves only that some
    // block existed and the relay could be arbitrarily far behind.
    let lag = chain.tip_height().saturating_sub(latest.height);
    if lag > MAX_RELAY_TIP_LAG_BLOCKS {
        return Err(EnclaveError::Spv(format!(
            "fundsOut BtcRelay check: proof latest height {} is {lag} blocks below the \
             enclave tip {} (max {MAX_RELAY_TIP_LAG_BLOCKS}) - the relay's view is too \
             stale to prove freshness",
            latest.height,
            chain.tip_height()
        )));
    }

    // Recorded, not checked: an on-chain revert is otherwise opaque about which
    // commitments were signed.
    tracing::debug!(
        source_height = source.height,
        source_commit = %hex::encode(source.commitment),
        latest_height = latest.height,
        latest_commit = %hex::encode(latest.commitment),
        "fundsOut relay proof accepted (commitments verified on-chain, not here)"
    );

    // The calldata's source block must be the consignment's own anchor. Height
    // only - see the commitment note on this function.
    let anchor = resolve_consignment_anchor(validated, merkle_proofs, chain)?;
    pins.pin(chain, anchor.height)?;
    if source.height != anchor.height {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut source block mismatch: calldata proof cites height {}, but the \
             consignment's last witness tx {} is anchored at height {} (enclave header hash {}) \
             - refusing to sign",
            source.height,
            hex::encode(anchor.txid),
            anchor.height,
            hex::encode(anchor.commitment),
        )));
    }

    Ok(())
}

/// The Bitcoin block anchoring a consignment's last witness tx.
#[derive(Debug, Clone, Copy)]
struct ConsignmentAnchor {
    height: u32,
    /// Block hash in display (big-endian) order, as the calldata carries it.
    commitment: [u8; 32],
    /// Witness txid, display order. Error messages only.
    txid: [u8; 32],
}

/// Locate that block from evidence the enclave already trusts: the txid from
/// the rgbstd-validated `Transfer`, the height from the tx's SPV proof, the hash
/// from the enclave's own header chain. Nothing is read from the calldata. No
/// header at that height means the enclave is behind the anchoring block, so it
/// refuses.
///
/// The proof is re-verified here rather than relying on the earlier
/// `validate_source_chain` pass: that ran under a different acquisition of the
/// header-chain lock, and a concurrent `SubmitHeaders` reorg (up to
/// `MAX_REORG_DEPTH = 100`, well past `SPV_MIN_CONFIRMATIONS = 6`) could have
/// replaced the header in between. Inclusion and header hash must come from one
/// consistent view.
fn resolve_consignment_anchor(
    validated: &ValidatedConsignment,
    merkle_proofs: &[MerkleProofEntry],
    chain: &HeaderChain,
) -> Result<ConsignmentAnchor> {
    use bitcoin::hashes::Hash as _;

    let witness_txid = validated.last_witness_txid.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "fundsOut requires a consignment with at least one witness bundle, but the validated \
             consignment has no last witness txid - refusing to sign"
                .into(),
        )
    })?;
    // `MerkleProofEntry.txid` is display order; `Txid::to_byte_array` is internal.
    let mut txid: [u8; 32] = witness_txid.to_byte_array();
    txid.reverse();

    // `validate_spv_proofs` enforced set equality against `witness_txids`, so a
    // miss means the two views disagree. Fail closed.
    let proof = merkle_proofs
        .iter()
        .find(|p| p.txid.as_slice() == txid)
        .ok_or_else(|| {
            EnclaveError::Spv(format!(
                "fundsOut source block: no merkle proof for the consignment's last witness tx {} \
                 - cannot determine the block that anchors it",
                hex::encode(txid)
            ))
        })?;

    let commitment = display_hash_at(chain, proof.block_height).ok_or_else(|| {
        EnclaveError::Spv(format!(
            "fundsOut source block: enclave holds no header at height {} (chain tip = {}) for the \
             consignment's last witness tx {} - the TEE header chain is not in sync with \
             the block that anchors this consignment",
            proof.block_height,
            chain.tip_height(),
            hex::encode(txid)
        ))
    })?;

    // Re-verify inclusion and depth against the chain just read, under this
    // same lock guard (see the doc note on reorgs). The full set validator is
    // reused on a one-element slice so the path-depth and txid-correspondence
    // bounds it enforces apply here too.
    spv_crosscheck::validate_spv_proofs(
        chain,
        &[txid],
        std::slice::from_ref(proof),
        spv_crosscheck::SPV_MIN_CONFIRMATIONS,
    )?;

    Ok(ConsignmentAnchor {
        height: proof.block_height,
        commitment,
        txid,
    })
}

/// Hash of the enclave's own header at `height`, in display (big-endian) order:
/// the order calldata `commitmentHash` words carry. `None` when the enclave
/// holds no header there (at or below the checkpoint, or beyond the tip).
fn display_hash_at(chain: &HeaderChain, height: u32) -> Option<[u8; 32]> {
    use bitcoin::hashes::Hash as _;

    let mut display: [u8; 32] = chain.header_at(height)?.block_hash().to_byte_array();
    display.reverse();
    Some(display)
}

/// Confirm one proof pair against the in-enclave header chain.
fn assert_header_present(chain: &HeaderChain, block: &ProofBlock, label: &str) -> Result<()> {
    display_hash_at(chain, block.height)
        .map(|_| ())
        .ok_or_else(|| {
            EnclaveError::Spv(format!(
                "fundsOut BtcRelay check: no header at {label} block height {} \
                 (chain tip = {}) - the enclave is behind the chain and cannot confirm the \
                 block the calldata names",
                block.height,
                chain.tip_height()
            ))
        })
}

/// Number of bytes in the finality proof: four ABI words.
const FUNDS_OUT_PROOF_LEN: usize = 4 * 32;

/// How far the calldata's `latest` block may sit below the enclave's own tip.
/// Without a bound the `latest` pair proves only that a block existed, so a
/// listener could pass an ancient known block and the freshness half of the
/// BtcRelay check would be vacuous.
///
/// Set to `MAX_REORG_DEPTH` (100 blocks, ~16 h on mainnet): generous next to
/// the relay's own posting cadence, and the depth beyond which the enclave
/// already refuses to rewrite history. Aliased rather than re-typed so the two
/// cannot drift. Compile-time, not host-tunable.
const MAX_RELAY_TIP_LAG_BLOCKS: u32 = crate::networks::rgb::spv::chain::MAX_REORG_DEPTH;

/// Decode the `fundsOut` `proof` slot into its `(source, latest)` block pair.
/// An empty slot is rejected: it leaves nothing to bind the anchor to.
fn decode_funds_out_proof(params: &FundsOutParams) -> Result<(ProofBlock, ProofBlock)> {
    let proof = &params.proof;
    if proof.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "fundsOut proof is empty: the calldata must carry the finality proof - \
             abi.encode(uint256 sourceHeight, bytes32 sourceCommit, uint256 latestHeight, \
             bytes32 latestCommit) - so the enclave can bind it to the consignment's \
             anchoring block"
                .into(),
        ));
    }
    if proof.len() != FUNDS_OUT_PROOF_LEN {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut proof must be abi.encode(uint256 sourceHeight, bytes32 sourceCommit, \
             uint256 latestHeight, bytes32 latestCommit) = {FUNDS_OUT_PROOF_LEN} bytes, got {}",
            proof.len()
        )));
    }

    let source = ProofBlock {
        height: proof_height(&proof[0..32], "sourceHeight")?,
        commitment: proof[32..64]
            .try_into()
            .expect("32-byte slice always converts"),
    };
    let latest = ProofBlock {
        height: proof_height(&proof[64..96], "latestHeight")?,
        commitment: proof[96..128]
            .try_into()
            .expect("32-byte slice always converts"),
    };

    Ok((source, latest))
}

/// Read one proof height word as a `u32`. Bitcoin heights fit comfortably; a
/// larger value is rejected rather than truncated.
fn proof_height(word: &[u8], field: &str) -> Result<u32> {
    if word[..28].iter().any(|&b| b != 0) {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut proof {field} exceeds u32 range"
        )));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&word[28..32]);
    Ok(u32::from_be_bytes(buf))
}

// `extract_uint256_as_u64` moved to `events`, its only remaining consumer.
// `extract_bytes32`, `decode_op_id_to_bytes32` and `bytes32_to_usize` went with
// the removed calldata rewrite.

#[cfg(test)]
mod tests;
