//! RGB->EVM `fundsOut` cross-checks: bind the calldata the enclave signs to the
//! consignment it validated. All logic here is `rgb-validation`-gated (the
//! module is only compiled then) because every check reads a
//! [`ValidatedConsignment`]; SPV builds additionally run the BtcRelay agreement
//! check ([`verify_btc_relay_agreement`]).
//!
//! Audit refs: M-02/#93, #63/#97, #57/#122, 4th I-03/#95. The helpers operate
//! on `EvmDestination.call_data` bytes.

use crate::error::{EnclaveError, Result};
use crate::networks::evm::validation::FundsOutParams;
use crate::networks::rgb::spv::HeaderChain;
use crate::networks::rgb::validation::ValidatedConsignment;

// Calldata is decoded via `sol!` ([`decode_funds_out_params`]), not at
// hard-coded byte offsets: the `FundsOutParams` tuple shifts every field by one
// head pointer word, so the old constants would be 32 bytes off (#168).

/// Defense-in-depth for the RGB->EVM `fundsOut` direction (audit 4th I-03 / #95):
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
/// Takes the decoded intent (I-12 / #165), which also replaces the old selector
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

// `apply_op_id_binding` / `op_id_to_calldata_id` were removed (audit TEE-SE-02
// / M-02 / #93): they rewrote `burnId` and `settlementData` in the signed
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

/// BtcRelay-agreement cross-check (bridge spec section 13, #57/#122). Binds the
/// calldata's claimed finality proof to the headers the enclave holds, so a
/// listener can't split the contract's on-chain BtcRelay check away from the
/// enclave's own SPV evidence. A no-op for non-`fundsOut` selectors and inert
/// when the `proof` slot is empty.
///
/// The proof is now two block pairs (`RGBVerifier.sol:115-117`):
///
/// ```text
/// abi.encode(uint256 sourceHeight, bytes32 sourceCommit,
///            uint256 latestHeight, bytes32 latestCommit)
/// ```
///
/// `source` packaged the RGB burn; `latest` is the relay tip proving the
/// relay's view is current. Both are checked against the enclave's own headers,
/// so freshness is not delegated to a relay the host also feeds.
///
/// Byte order: calldata commitments are display (big-endian) order; the
/// in-enclave `header.block_hash()` is internal order, so it is reversed before
/// comparing.
pub fn verify_btc_relay_agreement(params: &FundsOutParams, chain: &HeaderChain) -> Result<()> {
    let Some((source, latest)) = decode_funds_out_proof(params)? else {
        // proof slot empty -> no calldata commitment to bind.
        return Ok(());
    };

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
    verify_proof_block(chain, &latest, "latest")
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

/// Decode the `fundsOut` `proof` slot into its `(source, latest)` block pair.
/// Returns `Ok(None)` when the `proof` bytes are empty.
///
fn decode_funds_out_proof(params: &FundsOutParams) -> Result<Option<(ProofBlock, ProofBlock)>> {
    let proof = &params.proof;
    if proof.is_empty() {
        return Ok(None);
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

    Ok(Some((source, latest)))
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

    // Pools fundsOut tests - `validate_funds_out_transfer` (+ the #95 witness
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

    // BtcRelay-agreement cross-check (#57 / #122) - `verify_btc_relay_agreement`.
    // These exercise `proof` decoding and header comparison directly against a
    // synthetic regtest header chain.

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
        /// skipped on regtest - same pattern as the `spv::chain` tests).
        /// Returns the chain and the header's DISPLAY-order block hash - the
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

        /// `fundsOut` calldata carrying a well-formed proof. The synthetic chain
        /// has a single header, so source and latest point at the same block -
        /// the degenerate but valid case where the burn sits at the relay tip.
        fn calldata_with_proof(block_height: u32, commitment_display: [u8; 32]) -> Vec<u8> {
            mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(
                    block_height,
                    commitment_display,
                    block_height,
                    commitment_display,
                ),
            )
        }

        #[test]
        fn passes_on_matching_commitment() {
            let (chain, display_hash) = chain_with_one_header();
            let cd = calldata_with_proof(1, display_hash);
            assert!(verify_btc_relay_agreement(&params_of(&cd), &chain).is_ok());
        }

        #[test]
        fn rejects_mismatched_commitment() {
            let (chain, _display_hash) = chain_with_one_header();
            let cd = calldata_with_proof(1, [0x11; 32]);
            let err = verify_btc_relay_agreement(&params_of(&cd), &chain).unwrap_err();
            assert!(err.to_string().contains("commitmentHash"), "got: {err}");
        }

        #[test]
        fn rejects_internal_order_commitment() {
            // Byte-order contract: the internal-order (un-reversed) hash must
            // be rejected, since calldata carries display order.
            let (chain, mut display_hash) = chain_with_one_header();
            display_hash.reverse(); // back to internal order
            let cd = calldata_with_proof(1, display_hash);
            assert!(verify_btc_relay_agreement(&params_of(&cd), &chain).is_err());
        }

        #[test]
        fn rejects_height_beyond_tip() {
            let (chain, display_hash) = chain_with_one_header();
            let cd = calldata_with_proof(99, display_hash);
            let err = verify_btc_relay_agreement(&params_of(&cd), &chain).unwrap_err();
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
            let (chain, display_hash) = chain_with_one_header();
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(1, display_hash, 99, display_hash),
            );
            let err = verify_btc_relay_agreement(&params_of(&cd), &chain).unwrap_err();
            assert!(
                err.to_string()
                    .contains("no header at latest block height 99"),
                "got: {err}"
            );
        }

        #[test]
        fn rejects_mismatched_latest_commitment() {
            let (chain, display_hash) = chain_with_one_header();
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(1, display_hash, 1, [0x11; 32]),
            );
            let err = verify_btc_relay_agreement(&params_of(&cd), &chain).unwrap_err();
            assert!(
                err.to_string().contains("latest commitmentHash"),
                "got: {err}"
            );
        }

        #[test]
        fn rejects_latest_below_source() {
            let (chain, display_hash) = chain_with_one_header();
            let cd = mock_funds_out_calldata_with_proof(
                1_000,
                proof_bytes(5, display_hash, 1, display_hash),
            );
            let err = verify_btc_relay_agreement(&params_of(&cd), &chain).unwrap_err();
            assert!(
                err.to_string().contains("cannot precede"),
                "expected the tip-ordering guard, got: {err}"
            );
        }

        #[test]
        fn inert_when_proof_empty() {
            // The current live calldata shape zero-fills the proof offset, so
            // the decoder reads an empty `proof` and the check is a no-op.
            let (chain, _) = chain_with_one_header();
            let cd = mock_funds_out_calldata(1_000);
            assert!(verify_btc_relay_agreement(&params_of(&cd), &chain).is_ok());
        }

        #[test]
        fn rejects_malformed_proof_length() {
            let (chain, _) = chain_with_one_header();
            let cd = mock_funds_out_calldata_with_proof(1_000, Bytes::from(vec![0u8; 33]));
            let err = verify_btc_relay_agreement(&params_of(&cd), &chain).unwrap_err();
            assert!(err.to_string().contains("128 bytes"), "got: {err}");
        }

        /// The pre-migration proof was a single 64-byte
        /// `(blockHeight, commitmentHash)` pair. Accepting it would verify the
        /// source block and leave the relay-freshness half unchecked.
        #[test]
        fn rejects_legacy_two_field_proof() {
            let (chain, display_hash) = chain_with_one_header();
            let mut legacy = Vec::with_capacity(64);
            legacy.extend_from_slice(&u256_be(1));
            legacy.extend_from_slice(&display_hash);
            let cd = mock_funds_out_calldata_with_proof(1_000, Bytes::from(legacy));
            let err = verify_btc_relay_agreement(&params_of(&cd), &chain).unwrap_err();
            assert!(err.to_string().contains("128 bytes"), "got: {err}");
        }

        #[test]
        fn rejects_blockheight_over_u32() {
            let (chain, display_hash) = chain_with_one_header();
            let mut huge = [0u8; 32];
            huge[20] = 0x01; // a bit set above the low 4 bytes
            let mut payload = Vec::with_capacity(FUNDS_OUT_PROOF_LEN);
            payload.extend_from_slice(&huge); // sourceHeight
            payload.extend_from_slice(&display_hash);
            payload.extend_from_slice(&u256_be(1));
            payload.extend_from_slice(&display_hash);
            let cd = mock_funds_out_calldata_with_proof(1_000, Bytes::from(payload));
            let err = verify_btc_relay_agreement(&params_of(&cd), &chain).unwrap_err();
            assert!(err.to_string().contains("u32 range"), "got: {err}");
        }
    }
}
