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

/// Pools-side amount cross-check for the `fundsOut` transfer flow. Binds the
/// release `amount` to the consignment's actual asset value:
///
///   1. The consignment's most recent transition must be an IFA `Transfer`
///      (`transition_type == ifa::TS_TRANSFER`).
///   2. The transition's `total_output_amount` must cover the EVM-side release
///      `amount`.
///
/// Takes the decoded intent, which also replaces the old selector
/// guard: `FundsOutParams` only exists after a successful `fundsOut` decode.
pub fn validate_funds_out_transfer(
    params: &FundsOutParams,
    validated: &ValidatedConsignment,
) -> Result<()> {
    use crate::networks::rgb::validation::ifa;

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

    // The consignment, not the listener-supplied `calldata_amount`, is the
    // authority on how much RGB moved.
    let calldata_amount: u64 = params
        .amount
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("fundsOut amount exceeds u64 range".into()))?;
    if last.total_output_amount < calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "transfer amount mismatch: consignment total_output_amount ({}) < calldata amount ({})",
            last.total_output_amount, calldata_amount
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
/// 1. find the block anchoring the consignment's last witness tx (received
///    transfer or burn) from its SPV Merkle proof, not from the calldata;
/// 2. require a header there, which proves the TEE is in sync;
/// 3. require the calldata `proof` to name that same block.
///
/// The `proof` slot is `abi.encode(uint256 sourceHeight, bytes32 sourceCommit,
/// uint256 latestHeight, bytes32 latestCommit)` (`RGBVerifier.sol:115-117`):
/// `source` packaged the burn/transfer, `latest` is the relay tip. Both must
/// match the enclave's own headers; `latest` must additionally sit within
/// `MAX_RELAY_TIP_LAG_BLOCKS` of the enclave tip, so freshness is not delegated
/// to a relay the host also feeds. Pinning `source` to the anchor stops a
/// listener citing any other block the enclave knows. Empty `proof` = reject.
///
/// Byte order: calldata is display order, `header.block_hash()` internal.
pub fn verify_btc_relay_agreement(
    params: &FundsOutParams,
    validated: &ValidatedConsignment,
    merkle_proofs: &[MerkleProofEntry],
    chain: &HeaderChain,
) -> Result<()> {
    let anchor = resolve_consignment_anchor(validated, merkle_proofs, chain)?;
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

    verify_proof_block(chain, &source, "source")?;
    verify_proof_block(chain, &latest, "latest")?;

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

    // The calldata's source block must be the consignment's own anchor.
    if source.height != anchor.height || source.commitment != anchor.commitment {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut source block mismatch: calldata proof cites height {} / hash {}, but the \
             consignment's last witness tx {} is anchored at height {} / hash {} - refusing \
             to sign",
            source.height,
            hex::encode(source.commitment),
            hex::encode(anchor.txid),
            anchor.height,
            hex::encode(anchor.commitment),
        )));
    }

    Ok(())
}

/// The Bitcoin block anchoring a consignment's last witness tx.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ConsignmentAnchor {
    pub height: u32,
    /// Block hash in display (big-endian) order, as the calldata carries it.
    pub commitment: [u8; 32],
    /// Witness txid, display order. Error messages only.
    pub txid: [u8; 32],
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
pub(crate) fn resolve_consignment_anchor(
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

    let header = chain.header_at(proof.block_height).ok_or_else(|| {
        EnclaveError::Spv(format!(
            "fundsOut source block: enclave holds no header at height {} (chain tip = {}) for the \
             consignment's last witness tx {} - the TEE header chain is not in sync with \
             the block that anchors this consignment",
            proof.block_height,
            chain.tip_height(),
            hex::encode(txid)
        ))
    })?;

    // Re-verify inclusion and depth against the header just read, under this
    // same lock guard (see the doc note on reorgs).
    spv_validation::verify_proof_against_chain(
        chain,
        spv_validation::SPV_MIN_CONFIRMATIONS,
        proof,
    )?;

    let mut commitment: [u8; 32] = header.block_hash().to_byte_array();
    commitment.reverse();

    Ok(ConsignmentAnchor {
        height: proof.block_height,
        commitment,
        txid,
    })
}

/// Confirm one proof pair against the in-enclave header chain.
fn verify_proof_block(chain: &HeaderChain, block: &ProofBlock, label: &str) -> Result<()> {
    use bitcoin::hashes::Hash as _;

    let header = chain.header_at(block.height).ok_or_else(|| {
        EnclaveError::Spv(format!(
            "fundsOut BtcRelay check: no header at {label} block height {} \
             (chain tip = {}) - cannot confirm the calldata commitment against \
             the enclave header chain",
            block.height,
            chain.tip_height()
        ))
    })?;

    let mut stored_display: [u8; 32] = header.block_hash().to_byte_array();
    stored_display.reverse();
    if stored_display != block.commitment {
        return Err(EnclaveError::Spv(format!(
            "fundsOut BtcRelay check: calldata {label} commitmentHash {} != enclave header \
             hash {} at block height {}",
            hex::encode(block.commitment),
            hex::encode(stored_display),
            block.height
        )));
    }
    Ok(())
}

/// Number of bytes in the finality proof: four ABI words.
const FUNDS_OUT_PROOF_LEN: usize = 4 * 32;

/// How far the calldata's `latest` block may sit below the enclave's own tip.
/// Without a bound the `latest` pair proves only that a block existed, so a
/// listener could pass an ancient known block and the freshness half of the
/// BtcRelay check would be vacuous.
///
/// 100 blocks is ~16 h on mainnet - generous next to the relay's own posting
/// cadence, and it matches `MAX_REORG_DEPTH`, the depth beyond which the
/// enclave already refuses to rewrite history. Compile-time, not host-tunable.
const MAX_RELAY_TIP_LAG_BLOCKS: u32 = 100;

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
        fundsOutCall {
            params: FundsOutParams {
                recipient: Address::ZERO,
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

    // Pools fundsOut tests - `validate_funds_out_transfer` (+ the witness
    // recency guard `assert_witnesses_confirmed`).

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
                last_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
                // The fundsOut cross-check reads `last_transition` only; the
                // per-witness grouping is the send-RGB PSBT bind's input.
                transitions_by_witness: vec![],
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
            assert!(validate_funds_out_transfer(&params_of(&cd), &validated).is_ok());
        }

        #[test]
        fn witnesses_confirmed_passes_when_all_mined() {
            // No non-mined witnesses surfaced -> the recency guard is a no-op.
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
            assert!(validate_funds_out_transfer(&params_of(&cd), &validated).is_ok());
        }

        /// P0 regression: even with a valid consignment that deserializes
        /// and validates, the EVM-side release cannot exceed the RGB-side
        /// transfer total. A consignment for 1 unit must not authorise a
        /// withdrawal for 10^9.
        #[test]
        fn rejects_when_total_output_less_than_calldata_amount() {
            let cd = mock_funds_out_calldata(1_000_000_000);
            let validated = validated_with_last(transfer_transition(1));
            let err = validate_funds_out_transfer(&params_of(&cd), &validated).unwrap_err();
            assert!(
                err.to_string().contains("transfer amount mismatch"),
                "expected transfer amount mismatch, got: {err}"
            );
        }

        /// A burn consignment arriving on the (single) `fundsOut`
        /// selector must be rejected by the transfer check - this is how
        /// mint/burn stays off until it's wired by contract address.
        #[test]
        fn rejects_when_last_transition_is_not_transfer() {
            let cd = mock_funds_out_calldata(500);
            let mut t = transfer_transition(500);
            t.transition_type = ifa::TS_BURN;
            let validated = validated_with_last(t);
            let err = validate_funds_out_transfer(&params_of(&cd), &validated).unwrap_err();
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
                last_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
                transitions_by_witness: vec![],
            };
            let err = validate_funds_out_transfer(&params_of(&cd), &validated).unwrap_err();
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

        /// `fundsOut` calldata whose `source` pair is the anchor block and whose
        /// `latest` pair is the chain tip - the well-formed case.
        fn good_calldata(hashes: &[[u8; 32]]) -> Vec<u8> {
            mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    ANCHOR_HEIGHT,
                    hashes[ANCHOR_HEIGHT as usize],
                    TIP_HEIGHT,
                    hashes[TIP_HEIGHT as usize],
                ),
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
                last_transfer_witness_txid: None,
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

        #[test]
        fn rejects_mismatched_commitment() {
            let (chain, hashes) = chain();
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    ANCHOR_HEIGHT,
                    [0x11; 32],
                    TIP_HEIGHT,
                    hashes[TIP_HEIGHT as usize],
                ),
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(err.to_string().contains("commitmentHash"), "got: {err}");
        }

        /// Byte-order contract: the internal-order (un-reversed) hash must be
        /// rejected, since calldata carries display order.
        #[test]
        fn rejects_internal_order_commitment() {
            let (chain, hashes) = chain();
            let mut internal = hashes[ANCHOR_HEIGHT as usize];
            internal.reverse();
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    ANCHOR_HEIGHT,
                    internal,
                    TIP_HEIGHT,
                    hashes[TIP_HEIGHT as usize],
                ),
            );
            assert!(check(&cd, &chain).is_err());
        }

        #[test]
        fn rejects_height_beyond_tip() {
            let (chain, hashes) = chain();
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(99, hashes[ANCHOR_HEIGHT as usize], 99, hashes[1]),
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string()
                    .contains("no header at source block height 99"),
                "got: {err}"
            );
        }

        /// The relay-tip half of the proof is checked too, else freshness would
        /// be delegated to a relay the untrusted host also feeds.
        #[test]
        fn rejects_unknown_latest_block() {
            let (chain, hashes) = chain();
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    ANCHOR_HEIGHT,
                    hashes[ANCHOR_HEIGHT as usize],
                    99,
                    hashes[TIP_HEIGHT as usize],
                ),
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string()
                    .contains("no header at latest block height 99"),
                "got: {err}"
            );
        }

        #[test]
        fn rejects_mismatched_latest_commitment() {
            let (chain, hashes) = chain();
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    ANCHOR_HEIGHT,
                    hashes[ANCHOR_HEIGHT as usize],
                    TIP_HEIGHT,
                    [0x11; 32],
                ),
            );
            let err = check(&cd, &chain).unwrap_err();
            assert!(
                err.to_string().contains("latest commitmentHash"),
                "got: {err}"
            );
        }

        #[test]
        fn rejects_latest_below_source() {
            let (chain, hashes) = chain();
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    TIP_HEIGHT,
                    hashes[TIP_HEIGHT as usize],
                    ANCHOR_HEIGHT,
                    hashes[ANCHOR_HEIGHT as usize],
                ),
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
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    ANCHOR_HEIGHT,
                    hashes[ANCHOR_HEIGHT as usize],
                    ANCHOR_HEIGHT,
                    hashes[ANCHOR_HEIGHT as usize],
                ),
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
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    ANCHOR_HEIGHT,
                    hashes[ANCHOR_HEIGHT as usize],
                    latest,
                    hashes[latest as usize],
                ),
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
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    other,
                    hashes[other as usize],
                    TIP_HEIGHT,
                    hashes[TIP_HEIGHT as usize],
                ),
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
