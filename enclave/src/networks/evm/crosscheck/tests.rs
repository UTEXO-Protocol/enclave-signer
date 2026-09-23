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
    mock_funds_out_calldata_full(recipient, amount, proof, Bytes::new())
}

fn mock_funds_out_calldata_full(
    recipient: Address,
    amount: u64,
    proof: Bytes,
    settlement_data: Bytes,
) -> Vec<u8> {
    fundsOutCall {
        params: FundsOutParams {
            recipient,
            amount: U256::from(amount),
            burnId: U256::ZERO,
            sourceChainId: U256::ZERO,
            destinationChainId: U256::ZERO,
            sourceAddress: String::new(),
            proof,
            settlementData: settlement_data,
        },
    }
    .abi_encode()
}

/// A `ValidatedConsignment` carrying nothing but `transition` as its last.
/// The `fundsOut` cross-checks read `last_transition` only; the per-witness
/// grouping is the send-RGB PSBT bind's input.
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
    use crate::networks::rgb::validation::{bfa, TransitionSummary};

    const RECIPIENT: [u8; 20] = [0x42; 20];

    fn burn_transition(burned: Option<u64>, recipient: Option<Vec<u8>>) -> TransitionSummary {
        TransitionSummary {
            op_id: "burn-op".into(),
            transition_type: bfa::TS_BURN,
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
        let validated = validated_with_last(burn_transition(Some(1000), Some(padded(RECIPIENT))));
        assert!(validate_funds_out_burn_recipient(&params_of(&cd), &validated).is_ok());
    }

    #[test]
    fn rejects_a_burn_that_names_no_recipient() {
        let cd = mock_funds_out_calldata_to(Address::from(RECIPIENT), 1000, Bytes::new());
        let validated = validated_with_last(burn_transition(Some(1000), None));
        assert!(validate_funds_out_burn_recipient(&params_of(&cd), &validated).is_err());
    }

    /// The whole point of the field: a release must not go anywhere the
    /// burner did not commit to.
    #[test]
    fn rejects_a_recipient_the_burn_did_not_commit_to() {
        let cd = mock_funds_out_calldata_to(Address::from([0x99; 20]), 1000, Bytes::new());
        let validated = validated_with_last(burn_transition(Some(1000), Some(padded(RECIPIENT))));
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
    use crate::networks::rgb::validation::{bfa, TransitionSummary};

    /// The last transition this build's RGB flow accepts on a `fundsOut`,
    /// carrying `amount` where that flow reads it: a Transfer's output
    /// assignments under `rgb-swap`, a Burn's `MS_BURNED_ASSET` metadata
    /// under `rgb-mint-burn`. Keeps the shared cases below flow-agnostic.
    #[cfg(feature = "rgb-swap")]
    fn source_transition(amount: u64) -> TransitionSummary {
        TransitionSummary {
            op_id: "transfer-op".into(),
            transition_type: bfa::TS_TRANSFER,
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
            transition_type: bfa::TS_BURN,
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

    /// A Transfer's total includes the sender's change, so surplus is
    /// legitimate on the swap flow.
    #[cfg(feature = "rgb-swap")]
    #[test]
    fn passes_when_source_amount_exceeds_calldata_amount() {
        let cd = mock_funds_out_calldata(1000);
        let validated = validated_with_last(source_transition(2000));
        assert!(validate_funds_out_amount(&params_of(&cd), &validated).is_ok());
    }

    /// I-06: a burn has no change leg and `fundsOut.amount` is gross, so
    /// the release must equal the burned figure exactly. A release below
    /// the burn would strand the difference.
    #[cfg(feature = "rgb-mint-burn")]
    #[test]
    fn rejects_when_source_amount_exceeds_calldata_amount() {
        let cd = mock_funds_out_calldata(1000);
        let validated = validated_with_last(source_transition(2000));
        let err = validate_funds_out_amount(&params_of(&cd), &validated).unwrap_err();
        assert!(
            err.to_string().contains("exact equality"),
            "expected exact-equality rejection, got: {err}"
        );
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
    /// flow withdraws with must be refused. `TS_BRIDGE` is a deposit
    /// shape in both flows, so it is wrong for either build - which is
    /// also how a mint-shaped consignment stays out of a swap enclave.
    #[test]
    fn rejects_when_last_transition_is_not_the_flow_shape() {
        let cd = mock_funds_out_calldata(500);
        let mut t = source_transition(500);
        t.transition_type = bfa::TS_BRIDGE;
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

// Settlement bind - `validate_funds_out_settlement`.
#[cfg(feature = "bfa-mint")]
mod settlement {
    use super::*;
    use crate::networks::evm::events::VerifiedLock;
    use alloy_primitives::B256;
    use alloy_sol_types::SolValue;

    const LOCK_A: VerifiedLock = VerifiedLock {
        mint_opid: [0x51; 32],
        minted: 100,
        operation_id: [0xA1; 32],
        net_amount: 950,
    };

    const LOCK_B: VerifiedLock = VerifiedLock {
        mint_opid: [0x62; 32],
        minted: 30,
        operation_id: [0xB2; 32],
        net_amount: 20,
    };

    fn settlement(pairs: &[(u8, u64)]) -> Bytes {
        let ids: Vec<B256> = pairs.iter().map(|(t, _)| B256::from([*t; 32])).collect();
        let amounts: Vec<U256> = pairs.iter().map(|(_, a)| U256::from(*a)).collect();
        Bytes::from((ids, amounts).abi_encode_params())
    }

    fn check(pairs: &[(u8, u64)], locks: &[VerifiedLock]) -> Result<()> {
        let cd = mock_funds_out_calldata_full(Address::ZERO, 1000, Bytes::new(), settlement(pairs));
        validate_funds_out_settlement(&params_of(&cd), locks)
    }

    #[test]
    fn passes_when_the_cited_pairs_are_the_verified_locks() {
        assert!(check(&[(0xA1, 950), (0xB2, 20)], &[LOCK_A, LOCK_B]).is_ok());
    }

    // Characterizes the replay candidate, not a paid contract replay.
    // burnid_test.go uses the same pairs to exercise payout ID derivation.
    #[test]
    fn reordered_settlement_passes_with_different_committed_bytes() {
        let locks = [LOCK_A, LOCK_B];
        let original = [(0xA1, 950), (0xB2, 20)];
        let reordered = [(0xB2, 20), (0xA1, 950)];
        assert!(check(&original, &locks).is_ok());
        assert!(check(&reordered, &locks).is_ok());

        // The settlement validator accepts both encodings, but burnId
        // commits to their bytes rather than the normalized pair set.
        let original_hash = alloy_primitives::keccak256(settlement(&original));
        let reordered_hash = alloy_primitives::keccak256(settlement(&reordered));
        assert_ne!(original_hash, reordered_hash);
    }

    /// The P6 attack: a valid burn re-presented with other deposits cited,
    /// which would earn a fresh `burnId` on-chain.
    #[test]
    fn rejects_a_deposit_the_burn_does_not_descend_from() {
        let err = check(&[(0xC3, 950)], &[LOCK_A]).unwrap_err();
        assert!(err.to_string().contains("settlementData mismatch"), "{err}");
    }

    #[test]
    fn rejects_a_citation_of_the_mint_pair_instead_of_the_bridge_record() {
        let err = check(&[(LOCK_A.mint_opid[0], LOCK_A.minted)], &[LOCK_A]).unwrap_err();
        assert!(err.to_string().contains("settlementData mismatch"), "{err}");
    }

    #[test]
    fn rejects_a_missing_ancestry_deposit() {
        let err = check(&[(0xA1, 950)], &[LOCK_A, LOCK_B]).unwrap_err();
        assert!(err.to_string().contains("settlementData mismatch"), "{err}");
    }

    #[test]
    fn rejects_an_extra_cited_deposit() {
        let err = check(&[(0xA1, 950), (0xB2, 20)], &[LOCK_A]).unwrap_err();
        assert!(err.to_string().contains("settlementData mismatch"), "{err}");
    }

    /// The module checks the full recorded netAmount per pair, so a wrong
    /// amount is a wrong citation, not a rounding issue.
    #[test]
    fn rejects_a_wrong_net_amount() {
        let err = check(&[(0xA1, 949)], &[LOCK_A]).unwrap_err();
        assert!(err.to_string().contains("settlementData mismatch"), "{err}");
    }

    #[test]
    fn rejects_a_duplicated_citation() {
        let err = check(&[(0xA1, 950), (0xA1, 950)], &[LOCK_A]).unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
    }

    #[test]
    fn rejects_when_no_lock_was_verified() {
        let err = check(&[(0xA1, 950)], &[]).unwrap_err();
        assert!(err.to_string().contains("no verified deposit"), "{err}");
    }

    #[test]
    fn rejects_empty_settlement_data() {
        let cd = mock_funds_out_calldata_full(Address::ZERO, 1000, Bytes::new(), Bytes::new());
        let err = validate_funds_out_settlement(&params_of(&cd), &[LOCK_A]).unwrap_err();
        assert!(err.to_string().contains("does not decode"), "{err}");
    }

    #[test]
    fn rejects_non_canonical_settlement_data() {
        let mut padded = settlement(&[(0xA1, 950)]).to_vec();
        padded.extend_from_slice(&[0u8; 32]);
        let cd =
            mock_funds_out_calldata_full(Address::ZERO, 1000, Bytes::new(), Bytes::from(padded));
        let err = validate_funds_out_settlement(&params_of(&cd), &[LOCK_A]).unwrap_err();
        assert!(
            err.to_string().contains("canonically") || err.to_string().contains("decode"),
            "{err}"
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
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
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
        verify_btc_relay_agreement(
            &params_of(cd),
            &validated,
            &proofs,
            chain,
            &ChainPins::new(),
        )
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
            &ChainPins::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no merkle proof"), "got: {err}");
    }

    // -- F05-NEW-AF-08: the chain can move after the last check.
    //
    // `verify_btc_relay_agreement` is the last chain read on the direct
    // route. Its lock ends at return. A real reorg must close the gate.
    // A real extension must not.

    /// Build a longer chain from `from_height` and submit it the normal
    /// way. No test state is written directly, so the accept rule is real.
    fn submit_reorg(chain: &mut HeaderChain, from_height: u32, extra: u32) {
        let pred = chain
            .hash_at(from_height - 1)
            .expect("reorg fixture needs a predecessor header");
        let mut prev = <bitcoin::BlockHash as bitcoin::hashes::Hash>::from_byte_array(pred);
        let mut raw = Vec::new();
        for height in from_height..=(TIP_HEIGHT + extra) {
            let header = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xCD; 32]),
                time: 1_700_000_000 + height,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                // Different from `chain_to`, so each new block gets a new
                // hash.
                nonce: 7,
            };
            prev = header.block_hash();
            raw.push(serialize(&header));
        }
        let outcome = chain.submit_headers(from_height, &raw).unwrap();
        assert!(
            outcome.reorg_depth > 0,
            "fixture must be a real reorg, got depth 0"
        );
    }

    /// Extend the tip and rewrite nothing. The harmless control.
    fn submit_extension(chain: &mut HeaderChain, count: u32) {
        let mut prev = <bitcoin::BlockHash as bitcoin::hashes::Hash>::from_byte_array(
            chain.hash_at(chain.tip_height()).expect("tip present"),
        );
        let start = chain.tip_height() + 1;
        let mut raw = Vec::new();
        for height in start..start + count {
            let header = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xEF; 32]),
                time: 1_700_000_000 + height,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            };
            prev = header.block_hash();
            raw.push(serialize(&header));
        }
        let outcome = chain.submit_headers(start, &raw).unwrap();
        assert_eq!(outcome.reorg_depth, 0, "control must not be a reorg");
    }

    /// Run the last check and return what it pinned.
    fn check_pinning(chain: &HeaderChain, hashes: &[[u8; 32]]) -> ChainPins {
        let pins = ChainPins::new();
        let (validated, proofs) = anchored_at(ANCHOR_HEIGHT);
        verify_btc_relay_agreement(
            &params_of(&good_calldata(hashes)),
            &validated,
            &proofs,
            chain,
            &pins,
        )
        .expect("terminal check passes on the fixture chain");
        pins
    }

    #[test]
    fn pins_the_anchor_and_the_relay_latest_header() {
        let (chain, hashes) = chain();
        let pins = check_pinning(&chain, &hashes);
        // The anchor block, and the relay's `latest` header.
        assert_eq!(pins.len(), 2);
    }

    #[test]
    fn accepted_extension_after_the_final_check_still_signs() {
        let (mut chain, hashes) = chain();
        let pins = check_pinning(&chain, &hashes);

        submit_extension(&mut chain, 3);

        pins.assert_unchanged(&chain)
            .expect("an extension touches no pinned block");
    }

    #[test]
    fn accepted_reorg_removing_the_anchor_after_the_final_check_refuses() {
        let (mut chain, hashes) = chain();
        let pins = check_pinning(&chain, &hashes);

        submit_reorg(&mut chain, ANCHOR_HEIGHT, 2);

        let err = pins.assert_unchanged(&chain).unwrap_err();
        assert!(
            matches!(err, EnclaveError::Spv(_)),
            "reorg must surface as an Spv refusal, got: {err}"
        );
        assert!(
            err.to_string().contains("chain reorg after validation"),
            "got: {err}"
        );
    }

    /// A reorg above the anchor still rewrites the relay's `latest`
    /// header. The freshness the check proved no longer holds.
    #[test]
    fn accepted_reorg_replacing_the_relay_latest_header_refuses() {
        let (mut chain, hashes) = chain();
        let pins = check_pinning(&chain, &hashes);

        submit_reorg(&mut chain, ANCHOR_HEIGHT + 3, 2);

        let err = pins.assert_unchanged(&chain).unwrap_err();
        assert!(
            err.to_string().contains("chain reorg after validation"),
            "got: {err}"
        );
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
            &ChainPins::new(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no last witness txid"),
            "got: {err}"
        );
    }
}
