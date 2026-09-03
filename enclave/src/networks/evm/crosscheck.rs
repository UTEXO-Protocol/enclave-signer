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
use crate::networks::rgb::spv_validation;
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
///      RGB flow accepts on a withdrawal - an IFA `Transfer` under `rgb-swap`,
///      an IFA `Burn` under `rgb-mint-burn`.
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
    if source_amount < calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut amount mismatch: consignment proves {source_amount} asset units left the \
             source, below the calldata amount ({calldata_amount})"
        )));
    }
    Ok(())
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
            "burn transition carries no MS_BURN_RECIPIENT metadata - an IFA burn cannot authorise \
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

// `apply_op_id_binding` / `op_id_to_calldata_id` were removed: they
// rewrote `burnId` and `settlementData` in the signed
// calldata, and both fields are now keyed on bridge-derived ids no RGB OpId
// yields. They are backend-supplied and enforced on-chain (`InvalidBurnId`,
// `FundsInNotFound` / `AmountMismatch`). An enclave-side check would need the
// deposit receipts via `evm_event::EvmReceiptProvider` - follow-up.

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
    spv_validation::validate_spv_proofs(
        chain,
        &[txid],
        std::slice::from_ref(proof),
        spv_validation::SPV_MIN_CONFIRMATIONS,
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

// `extract_uint256_as_u64` moved to `evm_event`, its only remaining consumer.
// `extract_bytes32`, `decode_op_id_to_bytes32` and `bytes32_to_usize` went with
// the removed calldata rewrite.

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::SolCall;

    use crate::networks::evm::validation::{
        decode_funds_out_params, fundsOutCall, FundsOutParams, FUNDS_OUT_SELECTOR_POOLS,
    };

    /// Decode a fixture blob into the intent the cross-checks now take.
    fn params_of(call_data: &[u8]) -> FundsOutParams {
        decode_funds_out_params(call_data).expect("fixture calldata must decode")
    }

    /// Build a `fundsOut(FundsOutParams)` calldata through the real ABI encoder.
    ///
    /// Encoded through `sol!` rather than hand-assembled head words, which
    /// would have to reproduce the dynamic-tail arithmetic.
    fn mock_funds_out_calldata(amount: u64) -> Vec<u8> {
        mock_funds_out_calldata_with_proof(amount, Bytes::new())
    }

    fn mock_funds_out_calldata_with_proof(amount: u64, proof: Bytes) -> Vec<u8> {
        mock_funds_out_calldata_to(Address::ZERO, amount, proof)
    }

    fn mock_funds_out_calldata_to(recipient: Address, amount: u64, proof: Bytes) -> Vec<u8> {
        fundsOutCall {
            params: FundsOutParams {
                recipient,
                amount: U256::from(amount),
                burnId: U256::ZERO,
                sourceChainId: U256::ZERO,
                destinationChainId: U256::ZERO,
                sourceAddress: String::new(),
                proof,
                settlementData: Bytes::new(),
            },
        }
        .abi_encode()
    }

    /// A `ValidatedConsignment` carrying nothing but `transition` as its last.
    /// The `fundsOut` cross-checks read `last_transition` only; the per-witness
    /// grouping is the send-RGB PSBT bind's input.
    #[cfg(feature = "rgb-validation")]
    fn validated_with_last(
        transition: crate::networks::rgb::validation::TransitionSummary,
    ) -> crate::networks::rgb::validation::ValidatedConsignment {
        crate::networks::rgb::validation::ValidatedConsignment {
            contract_id: "rgb:test".into(),
            chain_net: "bc".into(),
            witness_txids: vec![],
            all_op_ids: vec![transition.op_id.clone()],
            mint_op_ids: vec![],
            last_transition: Some(transition),
            last_witness_txid: None,
            last_transfer_witness_prevouts: None,
            last_transfer_op_id: None,
            non_mined_witness_txids: vec![],
            transitions_by_witness: vec![],
        }
    }

    /// The tuple encoding must round-trip through the decoder the cross-checks
    /// rely on. Replaces the old `abi_layout` module's hard-coded head offsets.
    #[test]
    fn mock_calldata_decodes_back_to_its_fields() {
        let cd = mock_funds_out_calldata_with_proof(1_234, Bytes::from(vec![0xAB; 128]));
        let params = decode_funds_out_params(&cd).expect("tuple calldata must decode");
        assert_eq!(params.amount, U256::from(1_234u64));
        assert_eq!(params.proof.len(), 128);
        assert_eq!(&cd[..4], &FUNDS_OUT_SELECTOR_POOLS);
    }

    /// Guard against a half-finished migration: a flat 8-argument body must not
    /// decode as the tuple shape.
    ///
    /// With a zero `recipient`, as here, the ABI decoder accepts the legacy
    /// body: the leading zero word reads as a tuple head pointer of 0, aliasing
    /// the tuple onto those words so every field lines up. Only the canonical
    /// re-encode check inside [`decode_funds_out_params`] rejects it. A
    /// non-zero recipient fails the decode by itself, so this pins the harder
    /// case.
    fn legacy_flat_calldata(recipient: [u8; 32]) -> Vec<u8> {
        let mut legacy = Vec::with_capacity(4 + 8 * 32);
        legacy.extend_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
        legacy.extend_from_slice(&recipient);
        let mut amt = [0u8; 32];
        amt[24..].copy_from_slice(&1_000u64.to_be_bytes());
        legacy.extend_from_slice(&amt); // amount, at the old flat offset 36
        legacy.extend_from_slice(&[0u8; 32 * 6]); // remaining flat head slots
        legacy
    }

    #[test]
    fn rejects_legacy_flat_encoding_zero_recipient() {
        assert!(
            decode_funds_out_params(&legacy_flat_calldata([0u8; 32])).is_err(),
            "a flat-encoded body must fail closed, not alias onto the tuple layout"
        );
    }

    #[test]
    fn rejects_legacy_flat_encoding_real_recipient() {
        let mut recipient = [0u8; 32];
        recipient[12..].copy_from_slice(&[0x22; 20]);
        assert!(decode_funds_out_params(&legacy_flat_calldata(recipient)).is_err());
    }

    // fundsOut amount tests - `validate_funds_out_amount` (+ the witness
    // recency guard `assert_witnesses_confirmed`).

    // Redemption fundsOut tests - `validate_funds_out_burn_recipient`. The shape
    // and amount halves belong to `validate_funds_out_amount` / the mint-burn
    // flow, and are tested there.
    #[cfg(feature = "rgb-mint-burn")]
    mod burn {
        use super::*;
        use crate::networks::rgb::validation::{ifa, TransitionSummary};

        const RECIPIENT: [u8; 20] = [0x42; 20];

        fn burn_transition(burned: Option<u64>, recipient: Option<Vec<u8>>) -> TransitionSummary {
            TransitionSummary {
                op_id: "burn-op".into(),
                transition_type: ifa::TS_BURN,
                // A burn has no output assignments; the destroyed value lives
                // in the metadata, which is exactly why this must not be the
                // quantity the release is bound to.
                total_output_amount: 0,
                asset_output_amount: 0,
                outputs: Vec::new(),
                burned_asset_amount: burned,
                burn_recipient: recipient,
            }
        }

        fn padded(addr: [u8; 20]) -> Vec<u8> {
            let mut v = vec![0u8; 32];
            v[12..].copy_from_slice(&addr);
            v
        }

        #[test]
        fn passes_when_the_burn_names_the_calldata_recipient() {
            let cd = mock_funds_out_calldata_to(Address::from(RECIPIENT), 1000, Bytes::new());
            let validated =
                validated_with_last(burn_transition(Some(1000), Some(padded(RECIPIENT))));
            assert!(validate_funds_out_burn_recipient(&params_of(&cd), &validated).is_ok());
        }

        #[test]
        fn rejects_an_ifa_burn_that_names_no_recipient() {
            let cd = mock_funds_out_calldata_to(Address::from(RECIPIENT), 1000, Bytes::new());
            let validated = validated_with_last(burn_transition(Some(1000), None));
            assert!(validate_funds_out_burn_recipient(&params_of(&cd), &validated).is_err());
        }

        /// The whole point of the field: a release must not go anywhere the
        /// burner did not commit to.
        #[test]
        fn rejects_a_recipient_the_burn_did_not_commit_to() {
            let cd = mock_funds_out_calldata_to(Address::from([0x99; 20]), 1000, Bytes::new());
            let validated =
                validated_with_last(burn_transition(Some(1000), Some(padded(RECIPIENT))));
            assert!(validate_funds_out_burn_recipient(&params_of(&cd), &validated).is_err());
        }

        /// A non-zero high half means the burner committed to something that is
        /// not this address; truncating to the low 20 bytes would pay out to a
        /// target nobody signed.
        #[test]
        fn rejects_a_recipient_with_a_dirty_high_half() {
            let cd = mock_funds_out_calldata_to(Address::from(RECIPIENT), 1000, Bytes::new());
            let mut dirty = padded(RECIPIENT);
            dirty[0] = 1;
            let validated = validated_with_last(burn_transition(Some(1000), Some(dirty)));
            assert!(validate_funds_out_burn_recipient(&params_of(&cd), &validated).is_err());
        }
    }

    mod transfer {
        use super::*;
        use crate::networks::rgb::validation::{ifa, TransitionSummary};

        /// The last transition this build's RGB flow accepts on a `fundsOut`,
        /// carrying `amount` where that flow reads it: a Transfer's output
        /// assignments under `rgb-swap`, a Burn's `MS_BURNED_ASSET` metadata
        /// under `rgb-mint-burn`. Keeps the shared cases below flow-agnostic.
        #[cfg(feature = "rgb-swap")]
        fn source_transition(amount: u64) -> TransitionSummary {
            TransitionSummary {
                op_id: "transfer-op".into(),
                transition_type: ifa::TS_TRANSFER,
                total_output_amount: amount,
                asset_output_amount: amount,
                outputs: Vec::new(),
                burned_asset_amount: None,
                burn_recipient: None,
            }
        }

        #[cfg(feature = "rgb-mint-burn")]
        fn source_transition(amount: u64) -> TransitionSummary {
            TransitionSummary {
                op_id: "burn-op".into(),
                // A burn destroys units; it has no output assignments carrying
                // them, so the amount lives in the metadata field only.
                transition_type: ifa::TS_BURN,
                total_output_amount: 0,
                asset_output_amount: 0,
                outputs: Vec::new(),
                burned_asset_amount: Some(amount),
                // The payout target is a separate bind
                // (`validate_funds_out_burn_recipient`, tested in `mod burn`),
                // so the amount cases here leave it unset.
                burn_recipient: None,
            }
        }

        #[test]
        fn passes_when_source_amount_covers_calldata_amount() {
            let cd = mock_funds_out_calldata(1000);
            let validated = validated_with_last(source_transition(1000));
            assert!(validate_funds_out_amount(&params_of(&cd), &validated).is_ok());
        }

        #[test]
        fn witnesses_confirmed_passes_when_all_mined() {
            // No non-mined witnesses surfaced -> the recency guard is a no-op.
            let validated = validated_with_last(source_transition(1000));
            assert!(super::super::assert_witnesses_confirmed(&validated).is_ok());
        }

        #[test]
        fn witnesses_confirmed_rejects_non_mined() {
            // A tentative/ignored witness in the RGB->EVM direction is an
            // anomaly: the unlock settles an already-confirmed transfer.
            let mut validated = validated_with_last(source_transition(1000));
            validated.non_mined_witness_txids = vec![[0xABu8; 32]];
            let err = super::super::assert_witnesses_confirmed(&validated).unwrap_err();
            assert!(
                err.to_string().contains("mined"),
                "expected not-mined rejection, got: {err}"
            );
        }

        #[test]
        fn passes_when_source_amount_exceeds_calldata_amount() {
            let cd = mock_funds_out_calldata(1000);
            let validated = validated_with_last(source_transition(2000));
            assert!(validate_funds_out_amount(&params_of(&cd), &validated).is_ok());
        }

        /// P0 regression: even with a valid consignment that deserializes
        /// and validates, the EVM-side release cannot exceed what the RGB side
        /// proves left the source. A consignment for 1 unit must not authorise
        /// a withdrawal for 10^9.
        #[test]
        fn rejects_when_source_amount_less_than_calldata_amount() {
            let cd = mock_funds_out_calldata(1_000_000_000);
            let validated = validated_with_last(source_transition(1));
            let err = validate_funds_out_amount(&params_of(&cd), &validated).unwrap_err();
            assert!(
                err.to_string().contains("fundsOut amount mismatch"),
                "expected fundsOut amount mismatch, got: {err}"
            );
        }

        /// A consignment whose last transition is not the one this build's
        /// flow withdraws with must be refused. `TS_INFLATION` is a deposit
        /// shape in both flows, so it is wrong for either build - which is
        /// also how a mint-shaped consignment stays out of a swap enclave.
        #[test]
        fn rejects_when_last_transition_is_not_the_flow_shape() {
            let cd = mock_funds_out_calldata(500);
            let mut t = source_transition(500);
            t.transition_type = ifa::TS_INFLATION;
            let validated = validated_with_last(t);
            let err = validate_funds_out_amount(&params_of(&cd), &validated).unwrap_err();
            assert!(
                err.to_string().contains("this enclave is built for the"),
                "expected flow-shape rejection, got: {err}"
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
                last_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
                transitions_by_witness: vec![],
            };
            let err = validate_funds_out_amount(&params_of(&cd), &validated).unwrap_err();
            assert!(
                err.to_string().contains("at least one transition"),
                "expected no-transition rejection, got: {err}"
            );
        }
    }

    // BtcRelay-agreement cross-check - `verify_btc_relay_agreement`.
    // These exercise `proof` decoding and header comparison directly against a
    // synthetic regtest header chain.

    mod btc_relay {
        use super::*;
        use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
        use bitcoin::block::{Header, Version};
        use bitcoin::consensus::serialize;
        use bitcoin::hashes::Hash as _;

        /// Display-order txid of the consignment's single witness tx.
        /// Deliberately NOT a palindrome: a byte-order slip in
        /// `resolve_consignment_anchor` must fail the tests, not pass them.
        const WITNESS_TXID: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        /// Block holding [`WITNESS_TXID`].
        const ANCHOR_HEIGHT: u32 = 2;
        /// Default tip: leaves the anchor 7 deep, past `SPV_MIN_CONFIRMATIONS`.
        const TIP_HEIGHT: u32 = 8;

        /// Encode `n` as a big-endian 32-byte ABI word.
        fn u256_be(n: u64) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&n.to_be_bytes());
            w
        }

        /// A regtest chain of `tip` synthetic headers (PoW is skipped on
        /// regtest - same pattern as the `spv::chain` tests). The header at
        /// [`ANCHOR_HEIGHT`] commits exactly one transaction, [`WITNESS_TXID`],
        /// so a proof with an empty path reconstructs its Merkle root.
        ///
        /// Returns the chain and every header's DISPLAY-order hash, indexed by
        /// height (slot 0 is the checkpoint placeholder).
        fn chain_to(tip: u32) -> (HeaderChain, Vec<[u8; 32]>) {
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
            let mut hashes = vec![[0u8; 32]];
            let mut prev = bitcoin::BlockHash::from_byte_array([0u8; 32]);
            for height in 1..=tip {
                let merkle_root = if height == ANCHOR_HEIGHT {
                    let mut internal = WITNESS_TXID;
                    internal.reverse(); // Merkle math works in internal order
                    bitcoin::TxMerkleNode::from_byte_array(internal)
                } else {
                    bitcoin::TxMerkleNode::from_byte_array([0xAB; 32])
                };
                let header = Header {
                    version: Version::ONE,
                    prev_blockhash: prev,
                    merkle_root,
                    time: 1_700_000_000 + height,
                    bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                    nonce: 0,
                };
                chain.submit_headers(height, &[serialize(&header)]).unwrap();
                prev = header.block_hash();
                let mut display: [u8; 32] = header.block_hash().to_byte_array();
                display.reverse();
                hashes.push(display);
            }
            (chain, hashes)
        }

        fn chain() -> (HeaderChain, Vec<[u8; 32]>) {
            chain_to(TIP_HEIGHT)
        }

        /// The 4-field finality proof payload:
        /// `abi.encode(sourceHeight, sourceCommit, latestHeight, latestCommit)`.
        fn proof_bytes(
            source_height: u32,
            source_commit: [u8; 32],
            latest_height: u32,
            latest_commit: [u8; 32],
        ) -> Bytes {
            let mut p = Vec::with_capacity(FUNDS_OUT_PROOF_LEN);
            p.extend_from_slice(&u256_be(source_height as u64));
            p.extend_from_slice(&source_commit);
            p.extend_from_slice(&u256_be(latest_height as u64));
            p.extend_from_slice(&latest_commit);
            Bytes::from(p)
        }

        /// `fundsOut` calldata carrying the four-field finality proof.
        fn calldata(sh: u32, sc: [u8; 32], lh: u32, lc: [u8; 32]) -> Vec<u8> {
            mock_funds_out_calldata_with_proof(1_000, proof_bytes(sh, sc, lh, lc))
        }

        /// The well-formed case: `source` is the anchor block, `latest` the tip.
        fn good_calldata(hashes: &[[u8; 32]]) -> Vec<u8> {
            calldata(
                ANCHOR_HEIGHT,
                hashes[ANCHOR_HEIGHT as usize],
                TIP_HEIGHT,
                hashes[TIP_HEIGHT as usize],
            )
        }

        /// A consignment anchored by [`WITNESS_TXID`], plus the SPV proof
        /// placing it at `height`. The block at [`ANCHOR_HEIGHT`] holds only
        /// that tx, so the path is empty and the position is 0.
        fn anchored_at(height: u32) -> (ValidatedConsignment, Vec<MerkleProofEntry>) {
            let mut internal = WITNESS_TXID;
            internal.reverse();
            let validated = ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![WITNESS_TXID],
                all_op_ids: vec![],
                mint_op_ids: vec![],
                last_transition: None,
                last_witness_txid: Some(bitcoin::Txid::from_byte_array(internal)),
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
                transitions_by_witness: vec![],
            };
            let proofs = vec![MerkleProofEntry {
                txid: WITNESS_TXID.to_vec(),
                block_height: height,
                tx_position: 0,
                merkle_path: vec![],
            }];
            (validated, proofs)
        }

        /// Run the check against a consignment anchored at [`ANCHOR_HEIGHT`].
        fn check(cd: &[u8], chain: &HeaderChain) -> Result<()> {
            check_at(cd, chain, ANCHOR_HEIGHT)
        }

        /// Run the check against a consignment anchored at `anchor_height`.
        fn check_at(cd: &[u8], chain: &HeaderChain, anchor_height: u32) -> Result<()> {
            let (validated, proofs) = anchored_at(anchor_height);
            verify_btc_relay_agreement(&params_of(cd), &validated, &proofs, chain)
        }

        // -- Calldata proof vs the enclave's own headers.

        #[test]
        fn passes_on_matching_commitment() {
            let (chain, hashes) = chain();
            assert!(check(&good_calldata(&hashes), &chain).is_ok());
        }

        /// Right height, wrong hash: the anchor bind owns the `source` half, so
        /// this surfaces as a mismatch against the consignment's anchor.
        #[test]
        fn accepts_any_source_commitment_at_the_anchor_height() {
            let (chain, hashes) = chain();
            // BtcRelay's commitment is keccak256 over its own 160-byte record,
            // which the enclave cannot compute. It is verified on-chain against
            // the relay instead; the enclave binds the height.
            let cd = calldata(
                ANCHOR_HEIGHT,
                [0x11; 32],
                TIP_HEIGHT,
                hashes[TIP_HEIGHT as usize],
            );
            assert!(check(&cd, &chain).is_ok());
        }

        /// The bind that remains: a source height other than the consignment's
        /// anchor is refused, whatever commitment accompanies it.
        #[test]
        fn rejects_a_source_height_that_is_not_the_anchor() {
            let (chain, hashes) = chain();
            let cd = calldata(
                ANCHOR_HEIGHT + 1,
                hashes[(ANCHOR_HEIGHT + 1) as usize],
                TIP_HEIGHT,
                hashes[TIP_HEIGHT as usize],
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string().contains("source block mismatch"),
                "got: {err}"
            );
        }

        /// A `source` height the enclave holds no header for - here at the
        /// checkpoint, below every stored header - cannot equal the anchor, so
        /// the bind rejects it without a separate header lookup. (A height
        /// ABOVE the tip trips the ordering guard first; see
        /// `rejects_latest_below_source`.)
        #[test]
        fn rejects_source_height_with_no_header() {
            let (chain, hashes) = chain();
            let cd = calldata(0, hashes[0], TIP_HEIGHT, hashes[TIP_HEIGHT as usize]);
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string().contains("source block mismatch"),
                "got: {err}"
            );
        }

        /// The relay-tip half of the proof is checked too, else freshness would
        /// be delegated to a relay the untrusted host also feeds.
        #[test]
        fn rejects_unknown_latest_block() {
            let (chain, hashes) = chain();
            let cd = calldata(
                ANCHOR_HEIGHT,
                hashes[ANCHOR_HEIGHT as usize],
                99,
                hashes[TIP_HEIGHT as usize],
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string()
                    .contains("no header at latest block height 99"),
                "got: {err}"
            );
        }

        #[test]
        fn accepts_any_latest_commitment_at_a_known_height() {
            let (chain, hashes) = chain();
            let cd = calldata(
                ANCHOR_HEIGHT,
                hashes[ANCHOR_HEIGHT as usize],
                TIP_HEIGHT,
                [0x11; 32],
            );
            assert!(check(&cd, &chain).is_ok());
        }

        /// What `latest` still proves: the enclave holds a header there, so it
        /// is in sync with the chain the relay claims to be following.
        #[test]
        fn rejects_a_latest_height_the_enclave_has_no_header_for() {
            let (chain, hashes) = chain();
            let cd = calldata(
                ANCHOR_HEIGHT,
                hashes[ANCHOR_HEIGHT as usize],
                TIP_HEIGHT + 1,
                [0x11; 32],
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string().contains("no header at latest block height"),
                "got: {err}"
            );
        }

        #[test]
        fn rejects_latest_below_source() {
            let (chain, hashes) = chain();
            let cd = calldata(
                TIP_HEIGHT,
                hashes[TIP_HEIGHT as usize],
                ANCHOR_HEIGHT,
                hashes[ANCHOR_HEIGHT as usize],
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string().contains("cannot precede"),
                "expected the tip-ordering guard, got: {err}"
            );
        }

        /// A `latest` far below the enclave tip proves only that a block
        /// existed, so the freshness half would be vacuous.
        #[test]
        fn rejects_stale_relay_tip() {
            let (chain, hashes) = chain_to(MAX_RELAY_TIP_LAG_BLOCKS + 20);
            let cd = calldata(
                ANCHOR_HEIGHT,
                hashes[ANCHOR_HEIGHT as usize],
                ANCHOR_HEIGHT,
                hashes[ANCHOR_HEIGHT as usize],
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string().contains("too stale to prove freshness"),
                "got: {err}"
            );
        }

        /// A relay lagging inside the bound is still accepted.
        #[test]
        fn accepts_relay_tip_within_lag_bound() {
            let (chain, hashes) = chain_to(MAX_RELAY_TIP_LAG_BLOCKS);
            let latest = MAX_RELAY_TIP_LAG_BLOCKS / 2;
            let cd = calldata(
                ANCHOR_HEIGHT,
                hashes[ANCHOR_HEIGHT as usize],
                latest,
                hashes[latest as usize],
            );
            assert!(check(&cd, &chain).is_ok());
        }

        /// Fail-closed: a zero-filled `proof` leaves nothing to bind the
        /// anchoring block to.
        #[test]
        fn rejects_empty_proof() {
            let (chain, _) = chain();
            let cd = mock_funds_out_calldata(1_000);
            let err = check(&cd, &chain).unwrap_err();
            assert!(err.to_string().contains("proof is empty"), "got: {err}");
        }

        #[test]
        fn rejects_malformed_proof_length() {
            let (chain, _) = chain();
            let cd = mock_funds_out_calldata_with_proof(1_000, Bytes::from(vec![0u8; 33]));
            let err = check(&cd, &chain).unwrap_err();
            assert!(err.to_string().contains("128 bytes"), "got: {err}");
        }

        /// The pre-migration proof was a single 64-byte
        /// `(blockHeight, commitmentHash)` pair. Accepting it would verify the
        /// source block and leave the relay-freshness half unchecked.
        #[test]
        fn rejects_legacy_two_field_proof() {
            let (chain, hashes) = chain();
            let mut legacy = Vec::with_capacity(64);
            legacy.extend_from_slice(&u256_be(ANCHOR_HEIGHT as u64));
            legacy.extend_from_slice(&hashes[ANCHOR_HEIGHT as usize]);
            let cd = mock_funds_out_calldata_with_proof(1_000, Bytes::from(legacy));
            let err = check(&cd, &chain).unwrap_err();
            assert!(err.to_string().contains("128 bytes"), "got: {err}");
        }

        #[test]
        fn rejects_blockheight_over_u32() {
            let (chain, hashes) = chain();
            let mut huge = [0u8; 32];
            huge[20] = 0x01; // a bit set above the low 4 bytes
            let mut payload = Vec::with_capacity(FUNDS_OUT_PROOF_LEN);
            payload.extend_from_slice(&huge); // sourceHeight
            payload.extend_from_slice(&hashes[ANCHOR_HEIGHT as usize]);
            payload.extend_from_slice(&u256_be(TIP_HEIGHT as u64));
            payload.extend_from_slice(&hashes[TIP_HEIGHT as usize]);
            let cd = mock_funds_out_calldata_with_proof(1_000, Bytes::from(payload));
            let err = check(&cd, &chain).unwrap_err();
            assert!(err.to_string().contains("u32 range"), "got: {err}");
        }

        // -- Source-block bind: the calldata `source` pair must be the block
        // -- anchoring the consignment's last witness tx.

        /// A different but real block - one the enclave knows, so the BtcRelay
        /// half passes - must still be refused.
        #[test]
        fn rejects_source_block_that_is_not_the_consignment_anchor() {
            let (chain, hashes) = chain();
            let other = ANCHOR_HEIGHT + 1;
            let cd = calldata(
                other,
                hashes[other as usize],
                TIP_HEIGHT,
                hashes[TIP_HEIGHT as usize],
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string().contains("source block mismatch"),
                "got: {err}"
            );
        }

        /// No header at the anchoring height: refuse rather than trust the
        /// calldata.
        #[test]
        fn rejects_when_tee_has_no_header_at_anchor_height() {
            let (chain, hashes) = chain();
            let err = check_at(&good_calldata(&hashes), &chain, 99).unwrap_err();
            assert!(err.to_string().contains("not in sync"), "got: {err}");
        }

        /// The anchor's own SPV proof is re-verified here, under the same lock
        /// guard the header is read with, so a reorg between the source-chain
        /// pass and this one cannot slip a substituted header through.
        #[test]
        fn rejects_when_anchor_proof_does_not_reconstruct_the_root() {
            let (chain, hashes) = chain();
            // Block ANCHOR_HEIGHT + 1 commits a different Merkle root.
            let err = check_at(&good_calldata(&hashes), &chain, ANCHOR_HEIGHT + 1).unwrap_err();
            assert!(err.to_string().contains("failed"), "got: {err}");
        }

        /// Depth is re-checked too: an anchor at the tip is only 1 confirmation
        /// deep, short of `SPV_MIN_CONFIRMATIONS`.
        #[test]
        fn rejects_when_anchor_is_too_shallow() {
            let (chain, hashes) = chain();
            let err = check_at(&good_calldata(&hashes), &chain, TIP_HEIGHT).unwrap_err();
            assert!(
                err.to_string().contains("insufficient confirmations"),
                "got: {err}"
            );
        }

        #[test]
        fn rejects_when_no_merkle_proof_covers_the_last_witness_tx() {
            let (chain, hashes) = chain();
            let (validated, mut proofs) = anchored_at(ANCHOR_HEIGHT);
            proofs[0].txid = vec![0x01; 32];
            let err = verify_btc_relay_agreement(
                &params_of(&good_calldata(&hashes)),
                &validated,
                &proofs,
                &chain,
            )
            .unwrap_err();
            assert!(err.to_string().contains("no merkle proof"), "got: {err}");
        }

        #[test]
        fn rejects_when_consignment_has_no_witness_bundle() {
            let (chain, hashes) = chain();
            let (mut validated, proofs) = anchored_at(ANCHOR_HEIGHT);
            validated.last_witness_txid = None;
            let err = verify_btc_relay_agreement(
                &params_of(&good_calldata(&hashes)),
                &validated,
                &proofs,
                &chain,
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("no last witness txid"),
                "got: {err}"
            );
        }
    }
}
