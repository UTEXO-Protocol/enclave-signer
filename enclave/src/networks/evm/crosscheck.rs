//! RGB -> EVM `fundsOut` cross-checks: they bind the signed calldata to the
//! validated consignment. The module compiles only with `rgb-validation`,
//! because each check reads a [`ValidatedConsignment`]. SPV builds also run
//! the BtcRelay agreement check ([`verify_btc_relay_agreement`]).

use crate::config::BtcRelayMode;
use crate::error::{EnclaveError, Result};
use crate::networks::evm::validation::FundsOutParams;
use crate::networks::rgb::spv::HeaderChain;
use crate::networks::rgb::spv_crosscheck;
use crate::networks::rgb::spv_crosscheck::ChainPins;
use crate::networks::rgb::validation::ValidatedConsignment;
use crate::proto::MerkleProofEntry;

/// Defense-in-depth for RGB -> EVM `fundsOut`: each consignment witness tx must
/// be mined. `non_mined_witness_txids` comes from the rgbstd per-witness
/// ordinal map. Thus confirmation does not rest on the SPV header chain alone.
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

/// Amount cross-check for `fundsOut`. Binds the release `amount` to the
/// consignment asset value:
///
///   1. The last transition must be the type that this build's RGB flow
///      accepts on a withdrawal: a BFA `Transfer` under `rgb-swap`, a BFA
///      `Burn` under `rgb-mint-burn`.
///   2. The amount that transition moves out of the source must cover the
///      EVM release `amount`.
///
/// Both come from [`crate::networks::rgb::flow::funds_out_source_amount`],
/// which also builds the route proof. Thus the two agree on the transition.
///
/// `FundsOutParams` exists only after a successful `fundsOut` decode, so no
/// selector check is necessary.
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
    // The consignment, not the listener `calldata_amount`, is the authority
    // on the RGB amount.
    let source_amount = flow::funds_out_source_amount(last)?;

    let calldata_amount: u64 = params
        .amount
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("fundsOut amount exceeds u64 range".into()))?;
    // Coverage under rgb-swap, exact equality under rgb-mint-burn.
    flow::assert_funds_out_amount(source_amount, calldata_amount)
}

/// Payout bind for the `fundsOut` burn flow: the burner's target
/// (`MS_BURN_RECIPIENT`) must equal the calldata `recipient`.
///
/// This makes a redemption unforgeable. The 32 bytes are in the burn
/// operation, so its OpId covers them and the spender of the burned units signs
/// them. A holder of a consignment copy cannot redirect the release.
///
/// This does not check the burn shape or amount. The caller must run
/// [`validate_funds_out_amount`] first. Under `rgb-mint-burn`, it rejects
/// anything that is not a `Burn` that covers the released amount.
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
    // 32 bytes with a 20-byte EVM address in the low bytes, ABI-style. The
    // high 12 bytes must be zero. Truncation would pay a target that nobody
    // signed.
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

/// Source-burn bind (bridge PR #152): `sourceBurnTxId` must be the RGB OpId of
/// the settled transition. That is the last transition, which
/// [`validate_funds_out_amount`] reads.
///
/// On chain, `sourceBurnTxId` is the only `burnId` input that identifies the
/// burn. `Bridge.fundsOut` and `rebalanceLiquidity` hash it into the
/// `BURN_TYPEHASH` key and reject zero, but cannot verify it. The enclave
/// attests it. A new id would give a paid burn a new `burnId`. This bind maps
/// one validated burn to one id.
///
/// `op_id` is the 64-char hex form of the 32-byte OpId. The calldata word must
/// equal those bytes.
pub fn validate_funds_out_source_burn_tx_id(
    params: &FundsOutParams,
    validated: &ValidatedConsignment,
) -> Result<()> {
    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "fundsOut requires a consignment with at least one transition".into(),
        )
    })?;

    let expected = decode_op_id_to_bytes32(&last.op_id)?;
    let cited: [u8; 32] = params.sourceBurnTxId.0;

    // The Bridge also rejects zero (`ZeroSourceBurnTxId`). Refuse here, so the
    // enclave does not attest an intent that cannot settle.
    if cited == [0u8; 32] {
        return Err(EnclaveError::CrossCheck(
            "fundsOut sourceBurnTxId is zero: the calldata must carry the RGB OpId of the \
             transition being settled"
                .into(),
        ));
    }
    if cited != expected {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut sourceBurnTxId mismatch: calldata cites 0x{}, but the validated \
             consignment's settling transition is OpId 0x{} - refusing to sign",
            hex::encode(cited),
            hex::encode(expected)
        )));
    }
    Ok(())
}

/// Decodes a `TransitionSummary::op_id` (64 hex chars, optional `0x`) to the
/// 32-byte calldata word. A malformed id is an internal error, so refuse.
fn decode_op_id_to_bytes32(op_id: &str) -> Result<[u8; 32]> {
    let normalized = op_id.strip_prefix("0x").unwrap_or(op_id);
    let bytes = hex::decode(normalized).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "validated consignment op_id {op_id:?} is not hex-decodable: {e}"
        ))
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "validated consignment op_id {op_id:?} is not a 32-byte OpId ({} bytes)",
            bytes.len()
        ))
    })
}

/// Settlement bind for the BFA burn flow: `settlementData` must cite exactly
/// the deposits behind the burn's mint ancestry.
///
/// `RgbSettlementModule.beforeFundsOut` decodes `settlementData` as
/// `abi.encode(bytes32[] operationIds, uint256[] amounts)`. It checks each
/// pair against the `(operationId, netAmount)` it recorded at `FundsIn`. It
/// does not know the deposits behind a burn. The enclave knows, because it
/// verified each ancestry lock receipt
/// ([`crate::networks::evm::events::verify_rgb_funds_in`]). The cited set must
/// equal that ancestry, pair for pair. Thus a second release of the same burn
/// cannot cite other deposits to get a new `burnId`.
///
/// Set equality, any order, no duplicates, canonical encoding. An empty lock
/// set refuses: each signable asset is bridged, so such a burn settles nothing.
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
    /// BtcRelay's `keccak256` of its 160-byte record at `height`, as the
    /// calldata carries it.
    commitment: [u8; 32],
}

/// BtcRelay agreement and consignment source-block bind (spec section 13,
/// #57/#122). Before a `fundsOut` is signed:
///
/// 1. Find the block of the last witness tx from its SPV Merkle proof, not
///    from the calldata.
/// 2. Require a header there. This proves the TEE is in sync.
/// 3. Require the calldata `proof` to name that height.
/// 4. Require both commitment words to equal the relay record that the
///    enclave builds from its own chain ([`relay_record`]).
///
/// The `proof` slot is `abi.encode(uint256 sourceHeight, bytes32 sourceCommit,
/// uint256 latestHeight, bytes32 latestCommit)` (`RGBVerifier.sol:115-117`).
/// `source` holds the burn/transfer. `latest` is the relay tip. `latest` must
/// be within `MAX_RELAY_TIP_LAG_BLOCKS` of the enclave tip, so freshness does
/// not depend on a relay that the host also feeds. An empty `proof` is refused.
///
/// `RGBVerifier` checks each commitment by height only. Step 4 proves that the
/// relay holds the enclave's block at that height.
///
/// Step 4 depends on the operator [`BtcRelayMode`] (`BTC_RELAY_MODE`):
///
/// - [`Required`](BtcRelayMode::Required): the default, and the only mode a
///   production policy boots with. Both words must match. A zero word is
///   refused, because the bridge sends zeros only when it has no relay.
/// - [`None`](BtcRelayMode::None): a local stand with no BtcRelay. Both words
///   must be zero, and no compare occurs. A non-zero word means the bridge
///   and the enclave disagree about the relay, so it is refused.
///
/// Steps 1-3 run in both modes. No build flag affects the choice.
///
/// Order is cheapest first. The calldata decode and `latest` checks run
/// before the anchor resolution, which reads the chain and verifies a Merkle
/// proof again. The commitment checks run last, because they sum the work of
/// each header above the checkpoint.
pub fn verify_btc_relay_agreement(
    params: &FundsOutParams,
    validated: &ValidatedConsignment,
    merkle_proofs: &[MerkleProofEntry],
    chain: &HeaderChain,
    pins: &ChainPins,
    mode: BtcRelayMode,
) -> Result<()> {
    let (source, latest) = decode_funds_out_proof(params)?;

    // The tip cannot be below the block it buries. Check it here for a clear
    // error, not a header-lookup failure.
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

    // `latest` must be near the tip. Else it proves only that a block existed,
    // and the relay can be far behind.
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

    let zero = |b: &ProofBlock| b.commitment == [0u8; 32];
    match mode {
        BtcRelayMode::Required => {
            for (block, label) in [(&source, "source"), (&latest, "latest")] {
                if zero(block) {
                    return Err(EnclaveError::CrossCheck(format!(
                        "fundsOut relay proof carries a zero {label} commitment at height {}: the \
                         bridge has no BtcRelay configured, but this enclave runs with \
                         {}=required - refusing to sign",
                        block.height,
                        crate::config::BTC_RELAY_MODE_ENV
                    )));
                }
            }
            assert_relay_commitment(chain, &source, "source")?;
            assert_relay_commitment(chain, &latest, "latest")
        }
        BtcRelayMode::None => {
            for (block, label) in [(&source, "source"), (&latest, "latest")] {
                if !zero(block) {
                    return Err(EnclaveError::CrossCheck(format!(
                        "fundsOut relay proof carries a {label} commitment 0x{} at height {}, but \
                         this enclave runs with {}=none (no BtcRelay on this stand): the bridge \
                         and the enclave disagree about the relay - refusing to sign",
                        hex::encode(block.commitment),
                        block.height,
                        crate::config::BTC_RELAY_MODE_ENV
                    )));
                }
            }
            tracing::warn!(
                source_height = source.height,
                latest_height = latest.height,
                "fundsOut relay commitment compare skipped ({}=none): heights, anchor and \
                 freshness bound only",
                crate::config::BTC_RELAY_MODE_ENV
            );
            Ok(())
        }
    }
}

/// Refuses unless the calldata commitment is `keccak256` of the relay record
/// that the enclave builds at that height.
///
/// The relay deploy does not check the timestamps and `lastDiffAdjustment` of
/// its checkpoint record. If they are wrong, its records are wrong for ten
/// blocks or up to the next epoch start. The enclave refuses there (fail
/// closed).
fn assert_relay_commitment(chain: &HeaderChain, block: &ProofBlock, label: &str) -> Result<()> {
    let expected = alloy_primitives::keccak256(relay_record(chain, block.height)?).0;
    if block.commitment != expected {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut relay commitment mismatch at {label} height {}: calldata 0x{}, enclave \
             record 0x{}: the relay does not hold the enclave's block there, refusing to sign",
            block.height,
            hex::encode(block.commitment),
            hex::encode(expected),
        )));
    }
    Ok(())
}

/// Builds the BtcRelay 160-byte `StoredBlockHeader` record from the enclave chain.
///
/// Refuses heights that need a block below the checkpoint. The relay sets those
/// values at deploy and does not check them, so the enclave cannot know them.
fn relay_record(chain: &HeaderChain, height: u32) -> Result<[u8; 160]> {
    let cp = chain.checkpoint();
    let header = chain.header_at(height).ok_or_else(|| {
        EnclaveError::Spv(format!(
            "fundsOut relay record: no header at height {height} (checkpoint {}, tip {})",
            cp.height,
            chain.tip_height()
        ))
    })?;
    let cp_work = cp.chain_work.ok_or_else(|| {
        EnclaveError::Spv(format!(
            "fundsOut relay record: the checkpoint at height {} has no chainwork, so the enclave \
             cannot rebuild relay records. Set the fifth field of {}. Refusing to sign",
            cp.height,
            crate::networks::rgb::spv::checkpoint::CHECKPOINT_ENV
        ))
    })?;

    let epoch_start = height - height % crate::networks::rgb::spv::validation::RETARGET_INTERVAL;
    if height < cp.height + 10 || epoch_start < cp.height {
        return Err(EnclaveError::Spv(format!(
            "fundsOut relay record at height {height} needs the times of blocks {}..{height} \
             and of epoch start {epoch_start}, but the enclave holds no block below its \
             checkpoint at height {} - refusing to sign",
            height.saturating_sub(10),
            cp.height
        )));
    }
    // The chain holds every height above the checkpoint. The checkpoint gives
    // only its time.
    let time_at = |h: u32| chain.header_at(h).map_or(cp.time, |header| header.time);

    let work = (cp.height + 1..=height)
        .filter_map(|h| chain.header_at(h))
        .fold(bitcoin::Work::from_be_bytes(cp_work), |w, h| w + h.work());

    let mut record = [0u8; 160];
    record[..80].copy_from_slice(&bitcoin::consensus::serialize(header));
    record[80..112].copy_from_slice(&work.to_be_bytes());
    record[112..116].copy_from_slice(&height.to_be_bytes());
    record[116..120].copy_from_slice(&time_at(epoch_start).to_be_bytes());
    for (i, h) in (height - 10..height).enumerate() {
        record[120 + 4 * i..124 + 4 * i].copy_from_slice(&time_at(h).to_be_bytes());
    }
    Ok(record)
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

/// Finds that block from trusted evidence only: the txid from the
/// rgbstd-validated consignment, the height from the tx SPV proof, and the hash
/// from the enclave header chain. Nothing comes from the calldata. If no header
/// is at that height, the enclave is behind, so it refuses.
///
/// The proof is verified again here. The earlier `validate_source_chain` pass
/// held a different header-chain lock. A concurrent `SubmitHeaders` reorg (up
/// to `MAX_REORG_DEPTH = 100`, more than `SPV_MIN_CONFIRMATIONS = 6`) can
/// replace the header between the two. Inclusion and header hash must come
/// from one view.
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

    // `validate_spv_proofs` enforced set equality with `witness_txids`, so a
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

    // Verify inclusion and depth again under this lock guard (see the reorg
    // note above). Use the full set validator on one element, so its path-depth
    // and txid bounds also apply.
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

/// Hash of the enclave header at `height`, in display (big-endian) order, as
/// calldata `commitmentHash` words carry it. `None` if the enclave has no
/// header there (at or below the checkpoint, or above the tip).
fn display_hash_at(chain: &HeaderChain, height: u32) -> Option<[u8; 32]> {
    use bitcoin::hashes::Hash as _;

    let mut display: [u8; 32] = chain.header_at(height)?.block_hash().to_byte_array();
    display.reverse();
    Some(display)
}

/// Confirms that the enclave header chain has a header at the proof height.
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

/// Maximum distance of the calldata `latest` block below the enclave tip.
/// Without a bound, a listener can send a very old block, and the freshness
/// check proves nothing.
///
/// Equal to `MAX_REORG_DEPTH` (100 blocks, ~16 h on mainnet). This is more
/// than the relay posting interval, and the enclave does not reorg deeper.
/// It is an alias, so the two values cannot drift. The host cannot change it.
const MAX_RELAY_TIP_LAG_BLOCKS: u32 = crate::networks::rgb::spv::chain::MAX_REORG_DEPTH;

/// Decodes the `fundsOut` `proof` slot into its `(source, latest)` block pair.
/// An empty slot is refused, because the anchor then has nothing to bind to.
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

/// Reads one proof height word as a `u32`. A larger value is rejected, not
/// truncated.
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

#[cfg(test)]
mod tests;
