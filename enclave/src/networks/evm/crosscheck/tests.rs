use super::*;

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::SolCall;

use crate::networks::evm::validation::{
    decode_funds_out_params, fundsOutCall, FundsOutParams, ReleaseIdentity,
    FUNDS_OUT_SELECTOR_POOLS,
};

/// Decodes a fixture blob into the release that the cross-checks take.
fn params_of(call_data: &[u8]) -> ReleaseIdentity {
    ReleaseIdentity::from_funds_out(
        &decode_funds_out_params(call_data).expect("fixture calldata must decode"),
    )
}

/// Builds a `fundsOut(FundsOutParams)` calldata with the real `sol!` ABI
/// encoder, so the tests do not repeat the dynamic-tail arithmetic.
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
    mock_funds_out_calldata_identity(
        recipient,
        amount,
        proof,
        settlement_data,
        String::new(),
        SOURCE_BURN_TX_ID,
    )
}

/// A non-zero `sourceBurnTxId` for fixtures that do not test this field.
/// [`source_burn`] tests the real bind.
const SOURCE_BURN_TX_ID: [u8; 32] = [0x5b; 32];

fn mock_funds_out_calldata_identity(
    recipient: Address,
    amount: u64,
    proof: Bytes,
    settlement_data: Bytes,
    source_address: String,
    source_burn_tx_id: [u8; 32],
) -> Vec<u8> {
    fundsOutCall {
        params: FundsOutParams {
            recipient,
            amount: U256::from(amount),
            burnId: U256::ZERO,
            sourceChainId: U256::ZERO,
            destinationChainId: U256::ZERO,
            sourceAddress: source_address,
            proof,
            settlementData: settlement_data,
            sourceBurnTxId: FixedBytes(source_burn_tx_id),
        },
    }
    .abi_encode()
}

/// A `ValidatedConsignment` with only `transition` as its last transition.
/// The `fundsOut` cross-checks read only `last_transition`.
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

/// The tuple encoding must round-trip through the cross-check decoder.
#[test]
fn mock_calldata_decodes_back_to_its_fields() {
    let cd = mock_funds_out_calldata_with_proof(1_234, Bytes::from(vec![0xAB; 128]));
    let params = decode_funds_out_params(&cd).expect("tuple calldata must decode");
    assert_eq!(params.amount, U256::from(1_234u64));
    assert_eq!(params.proof.len(), 128);
    assert_eq!(&cd[..4], &FUNDS_OUT_SELECTOR_POOLS);
}

/// A flat 9-argument body must not decode as the tuple shape.
///
/// With a zero `recipient`, the ABI decoder accepts the legacy body: the
/// leading zero word is a tuple head pointer of 0, so all fields align. Only
/// the canonical re-encode check in [`decode_funds_out_params`] rejects it. A
/// non-zero recipient fails the decode alone, so this tests the harder case.
fn legacy_flat_calldata(recipient: [u8; 32]) -> Vec<u8> {
    let mut legacy = Vec::with_capacity(4 + 9 * 32);
    legacy.extend_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
    legacy.extend_from_slice(&recipient);
    let mut amt = [0u8; 32];
    amt[24..].copy_from_slice(&1_000u64.to_be_bytes());
    legacy.extend_from_slice(&amt); // amount, at the old flat offset 36
    legacy.extend_from_slice(&[0u8; 32 * 7]); // remaining flat head slots
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

/// A calldata in the pre-PR #152 shape (no `sourceBurnTxId`, selector
/// `0xdc771390`) must fail closed. `MultisigProxy` cannot verify that intent.
#[test]
fn rejects_pre_source_burn_tx_id_calldata() {
    let current = mock_funds_out_calldata(1_000);
    // Remove the last static word. The tuple then has eight fields, so each
    // dynamic tail offset is one word too large.
    let mut legacy = current.clone();
    legacy[..4].copy_from_slice(&[0xdc, 0x77, 0x13, 0x90]);
    assert!(
        decode_funds_out_params(&legacy).is_err(),
        "old selector must not decode"
    );
    assert!(
        decode_funds_out_params(&current).is_ok(),
        "the current shape is what the fixture builder emits"
    );
}

// Source-burn identity: `validate_funds_out_source_burn_tx_id`. The bind reads
// only the last transition OpId, of any type. `validate_rgb_source_identity`
// in `validation.rs` binds `sourceChainId` / `sourceAddress`.
mod source_burn {
    use super::*;
    use crate::networks::rgb::validation::{bfa, TransitionSummary};

    /// OpId as the consignment parser yields it: 64 lowercase hex chars.
    const OP_ID_HEX: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    fn op_id_bytes() -> [u8; 32] {
        hex::decode(OP_ID_HEX).unwrap().try_into().unwrap()
    }

    fn settling_transition(op_id: &str) -> TransitionSummary {
        TransitionSummary {
            op_id: op_id.into(),
            transition_type: bfa::TS_TRANSFER,
            total_output_amount: 1000,
            asset_output_amount: 1000,
            outputs: Vec::new(),
            burned_asset_amount: None,
            burn_recipient: None,
        }
    }

    fn calldata_with(source_address: &str, source_burn_tx_id: [u8; 32]) -> Vec<u8> {
        mock_funds_out_calldata_identity(
            Address::ZERO,
            1000,
            Bytes::new(),
            Bytes::new(),
            source_address.to_string(),
            source_burn_tx_id,
        )
    }

    #[test]
    fn passes_when_the_calldata_cites_the_settling_op_id() {
        let cd = calldata_with("", op_id_bytes());
        let validated = validated_with_last(settling_transition(OP_ID_HEX));
        assert!(validate_funds_out_source_burn_tx_id(&params_of(&cd), &validated).is_ok());
    }

    #[test]
    fn accepts_a_0x_prefixed_op_id() {
        let cd = calldata_with("", op_id_bytes());
        let validated = validated_with_last(settling_transition(&format!("0x{OP_ID_HEX}")));
        assert!(validate_funds_out_source_burn_tx_id(&params_of(&cd), &validated).is_ok());
    }

    /// The purpose of the bind: a new id gives a settled burn a new `burnId`.
    #[test]
    fn rejects_an_id_that_is_not_the_settling_op_id() {
        let mut other = op_id_bytes();
        other[31] ^= 0x01;
        let cd = calldata_with("", other);
        let validated = validated_with_last(settling_transition(OP_ID_HEX));
        let err = validate_funds_out_source_burn_tx_id(&params_of(&cd), &validated).unwrap_err();
        assert!(err.to_string().contains("sourceBurnTxId mismatch"), "{err}");
    }

    #[test]
    fn rejects_a_zero_id() {
        let cd = calldata_with("", [0u8; 32]);
        let validated = validated_with_last(settling_transition(OP_ID_HEX));
        let err = validate_funds_out_source_burn_tx_id(&params_of(&cd), &validated).unwrap_err();
        assert!(err.to_string().contains("is zero"), "{err}");
    }

    #[test]
    fn rejects_a_consignment_with_no_transition() {
        let cd = calldata_with("", op_id_bytes());
        let mut validated = validated_with_last(settling_transition(OP_ID_HEX));
        validated.last_transition = None;
        assert!(validate_funds_out_source_burn_tx_id(&params_of(&cd), &validated).is_err());
    }

    /// A malformed op_id is an internal error. Do not use a partial compare.
    #[test]
    fn rejects_a_non_hex_or_short_op_id() {
        let cd = calldata_with("", op_id_bytes());
        for bad in ["burn-op", "abcd", &OP_ID_HEX[..62]] {
            let validated = validated_with_last(settling_transition(bad));
            assert!(
                validate_funds_out_source_burn_tx_id(&params_of(&cd), &validated).is_err(),
                "op_id {bad:?} must refuse"
            );
        }
    }
}

// fundsOut amount tests: `validate_funds_out_amount` and the witness recency
// guard `assert_witnesses_confirmed`.

// Redemption fundsOut tests: `validate_funds_out_burn_recipient`. The shape
// and amount checks are tested with `validate_funds_out_amount` and the
// mint-burn flow.
#[cfg(feature = "rgb-mint-burn")]
mod burn {
    use super::*;
    use crate::networks::rgb::validation::{bfa, TransitionSummary};

    const RECIPIENT: [u8; 20] = [0x42; 20];

    fn burn_transition(burned: Option<u64>, recipient: Option<Vec<u8>>) -> TransitionSummary {
        TransitionSummary {
            op_id: "burn-op".into(),
            transition_type: bfa::TS_BURN,
            // A burn has no output assignments. The destroyed value is in
            // the metadata.
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

    /// The purpose of the field: a release must go only to the burner's
    /// committed target.
    #[test]
    fn rejects_a_recipient_the_burn_did_not_commit_to() {
        let cd = mock_funds_out_calldata_to(Address::from([0x99; 20]), 1000, Bytes::new());
        let validated = validated_with_last(burn_transition(Some(1000), Some(padded(RECIPIENT))));
        assert!(validate_funds_out_burn_recipient(&params_of(&cd), &validated).is_err());
    }

    /// A non-zero high part is not this address. Truncation to the low 20
    /// bytes would pay a target that nobody signed.
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

    /// The last transition that this build's RGB flow accepts on a
    /// `fundsOut`, with `amount` where that flow reads it: Transfer output
    /// assignments under `rgb-swap`, Burn `MS_BURNED_ASSET` metadata under
    /// `rgb-mint-burn`. The shared cases below then work for both flows.
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
            // A burn destroys units and has no output assignments, so the
            // amount is only in the metadata field.
            transition_type: bfa::TS_BURN,
            total_output_amount: 0,
            asset_output_amount: 0,
            outputs: Vec::new(),
            burned_asset_amount: Some(amount),
            // The payout target is a separate bind
            // (`validate_funds_out_burn_recipient`, tested in `mod burn`).
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
        // No non-mined witnesses, so the recency guard passes.
        let validated = validated_with_last(source_transition(1000));
        assert!(super::super::assert_witnesses_confirmed(&validated).is_ok());
    }

    #[test]
    fn witnesses_confirmed_rejects_non_mined() {
        // A tentative/ignored witness in the RGB -> EVM direction is an
        // anomaly: the unlock settles a confirmed transfer.
        let mut validated = validated_with_last(source_transition(1000));
        validated.non_mined_witness_txids = vec![[0xABu8; 32]];
        let err = super::super::assert_witnesses_confirmed(&validated).unwrap_err();
        assert!(
            err.to_string().contains("mined"),
            "expected not-mined rejection, got: {err}"
        );
    }

    /// A Transfer total includes the sender change, so a surplus is correct
    /// on the swap flow.
    #[cfg(feature = "rgb-swap")]
    #[test]
    fn passes_when_source_amount_exceeds_calldata_amount() {
        let cd = mock_funds_out_calldata(1000);
        let validated = validated_with_last(source_transition(2000));
        assert!(validate_funds_out_amount(&params_of(&cd), &validated).is_ok());
    }

    /// I-06: a burn has no change leg and `fundsOut.amount` is gross, so the
    /// release must equal the burned amount. A lower release strands the
    /// difference.
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

    /// P0 regression: with a valid consignment, the EVM release cannot be
    /// more than the RGB amount that left the source. A consignment for 1
    /// unit must not authorise a withdrawal of 10^9.
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

    /// A last transition that is not this build's withdrawal type must be
    /// refused. `TS_BRIDGE` is a deposit shape in both flows, so both builds
    /// refuse it. This also keeps a mint-shaped consignment out of a swap
    /// enclave.
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
        // commits to their bytes, not to the normalized pair set.
        let original_hash = alloy_primitives::keccak256(settlement(&original));
        let reordered_hash = alloy_primitives::keccak256(settlement(&reordered));
        assert_ne!(original_hash, reordered_hash);
    }

    /// The P6 attack: a valid burn sent again with other deposits cited, to
    /// get a new `burnId` on chain.
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

    /// The module checks the full recorded netAmount per pair. A wrong amount
    /// is a wrong citation, not a rounding issue.
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

// LayerZero route (#264): `lzFundsOut` runs the same burn binds as `fundsOut`.
// Each case decodes real `lzFundsOut` calldata through the LZ path.
#[cfg(feature = "bfa-mint")]
mod lz_route {
    use super::*;
    use crate::networks::evm::events::VerifiedLock;
    use crate::networks::evm::validation::{decode_lz_funds_out_params, lzFundsOutCall};
    use crate::networks::rgb::validation::{bfa, TransitionSummary};
    use alloy_primitives::B256;
    use alloy_sol_types::SolValue;

    const OP_ID_HEX: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const BURNED: u64 = 1000;

    const LOCK: VerifiedLock = VerifiedLock {
        mint_opid: [0x51; 32],
        minted: 100,
        operation_id: [0xA1; 32],
        net_amount: 950,
    };

    fn padded_recipient() -> [u8; 32] {
        let mut r = [0u8; 32];
        r[12..].copy_from_slice(&[0x42; 20]);
        r
    }

    fn burn() -> ValidatedConsignment {
        validated_with_last(TransitionSummary {
            op_id: OP_ID_HEX.into(),
            transition_type: bfa::TS_BURN,
            total_output_amount: 0,
            asset_output_amount: 0,
            outputs: Vec::new(),
            burned_asset_amount: Some(BURNED),
            burn_recipient: Some(padded_recipient().to_vec()),
        })
    }

    /// An LZ release that matches [`burn`] and [`LOCK`] in every bound field.
    fn honest() -> lzFundsOutCall {
        let settlement = (
            vec![B256::from(LOCK.operation_id)],
            vec![U256::from(LOCK.net_amount)],
        );
        lzFundsOutCall {
            amount: U256::from(BURNED),
            burnId: U256::ZERO,
            sourceChainId: U256::ZERO,
            destinationChainId: U256::from(137u64),
            sourceAddress: String::new(),
            proof: Bytes::new(),
            settlementData: Bytes::from(settlement.abi_encode_params()),
            dstEid: 30109,
            recipient: FixedBytes(padded_recipient()),
            minAmountLD: U256::from(BURNED),
            extraOptions: Bytes::new(),
            sourceBurnTxId: FixedBytes(hex::decode(OP_ID_HEX).unwrap().try_into().unwrap()),
        }
    }

    /// Encode, then decode through the LZ path, as `validate_destination` does.
    fn release(call: lzFundsOutCall) -> ReleaseIdentity {
        let decoded = decode_lz_funds_out_params(&call.abi_encode()).expect("LZ fixture decodes");
        ReleaseIdentity::from_lz_funds_out(&decoded)
    }

    fn check(call: lzFundsOutCall) -> Result<()> {
        let r = release(call);
        let validated = burn();
        validate_funds_out_amount(&r, &validated)?;
        validate_funds_out_source_burn_tx_id(&r, &validated)?;
        validate_funds_out_burn_recipient(&r, &validated)?;
        validate_funds_out_settlement(&r, &[LOCK])
    }

    #[test]
    fn passes_an_lz_release_that_matches_the_burn() {
        check(honest()).expect("honest LZ release must pass");
    }

    #[test]
    fn rejects_an_lz_recipient_the_burn_did_not_commit_to() {
        let err = check(lzFundsOutCall {
            recipient: FixedBytes([0x99; 32]),
            ..honest()
        })
        .unwrap_err();
        assert!(err.to_string().contains("recipient mismatch"), "{err}");
    }

    #[test]
    fn rejects_an_lz_source_burn_tx_id_that_is_not_the_burn() {
        let err = check(lzFundsOutCall {
            sourceBurnTxId: FixedBytes([0x6c; 32]),
            ..honest()
        })
        .unwrap_err();
        assert!(err.to_string().contains("sourceBurnTxId mismatch"), "{err}");
    }

    #[test]
    fn rejects_lz_settlement_data_that_is_not_the_ancestry() {
        let other = (vec![B256::from([0xC3; 32])], vec![U256::from(950u64)]);
        let err = check(lzFundsOutCall {
            settlementData: Bytes::from(other.abi_encode_params()),
            ..honest()
        })
        .unwrap_err();
        assert!(err.to_string().contains("settlementData mismatch"), "{err}");
    }

    #[test]
    fn rejects_an_lz_amount_below_the_burned_amount() {
        let err = check(lzFundsOutCall {
            amount: U256::from(BURNED - 100),
            ..honest()
        })
        .unwrap_err();
        assert!(err.to_string().contains("exact equality"), "{err}");
    }

    /// The BtcRelay bind reads the LZ `proof` too. An empty one fails closed.
    #[test]
    fn rejects_an_lz_release_with_no_finality_proof() {
        let err = super::super::decode_funds_out_proof(&release(honest())).unwrap_err();
        assert!(err.to_string().contains("proof is empty"), "{err}");
    }
}

// BtcRelay-agreement cross-check: `verify_btc_relay_agreement`. These test
// `proof` decoding and header comparison against a synthetic regtest chain.

mod btc_relay {
    use super::*;
    use crate::networks::rgb::spv::checkpoint::{parse_checkpoint_spec, REGTEST_CHECKPOINT};
    use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash as _;

    /// Display-order txid of the consignment's single witness tx. NOT a
    /// palindrome, so a byte-order error in `resolve_consignment_anchor`
    /// fails the tests.
    const WITNESS_TXID: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    /// Block holding [`WITNESS_TXID`]. Its ten prior timestamps are above
    /// the checkpoint.
    const ANCHOR_HEIGHT: u32 = 11;
    /// Default tip: leaves the anchor 7 deep, past `SPV_MIN_CONFIRMATIONS`.
    const TIP_HEIGHT: u32 = 17;

    /// Encode `n` as a big-endian 32-byte ABI word.
    fn u256_be(n: u64) -> [u8; 32] {
        U256::from(n).to_be_bytes()
    }

    /// Increases the nonce until the header meets its target, so the relay
    /// also accepts it.
    fn mined(mut header: Header) -> Header {
        while header.validate_pow(header.target()).is_err() {
            header.nonce += 1;
        }
        header
    }

    /// The checkpoint block every fixture chain starts from.
    fn h0() -> Header {
        mined(Header {
            version: Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_700_000_000,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        })
    }

    /// BtcRelay's 160-byte `StoredBlockHeader` at `height`, as
    /// `updateChain` derives it from the record seeded at [`h0`].
    fn relay_model(chain: &HeaderChain, height: u32) -> Vec<u8> {
        let mut header = h0();
        let mut times = [header.time; 10];
        let mut last_diff = header.time;
        let mut work = bitcoin::Work::from_be_bytes(chain.checkpoint().chain_work.unwrap());
        for h in 1..=height {
            times.rotate_left(1);
            times[9] = header.time;
            header = *chain.header_at(h).expect("model needs every header");
            work = work + header.work();
            if h % 2016 == 0 {
                last_diff = header.time;
            }
        }
        let mut record = serialize(&header);
        record.extend_from_slice(&work.to_be_bytes());
        record.extend_from_slice(&height.to_be_bytes());
        record.extend_from_slice(&last_diff.to_be_bytes());
        for t in times {
            record.extend_from_slice(&t.to_be_bytes());
        }
        record
    }

    /// BtcRelay's commitment at `height`: `keccak256` of [`relay_model`].
    fn relay_commit(chain: &HeaderChain, height: u32) -> [u8; 32] {
        alloy_primitives::keccak256(relay_model(chain, height)).0
    }

    /// A regtest chain of `tip` mined headers above [`h0`]. The header at
    /// [`ANCHOR_HEIGHT`] commits exactly one transaction, [`WITNESS_TXID`],
    /// so a proof with an empty path reconstructs its Merkle root.
    ///
    /// Returns the chain and the relay commitment at every height.
    fn chain_to(tip: u32) -> (HeaderChain, Vec<[u8; 32]>) {
        chain_to_with_work(tip, REGTEST_CHECKPOINT.chain_work)
    }

    /// [`chain_to`] over a checkpoint with the given `chain_work`. With
    /// `None` no relay record can be rebuilt, so the returned commitment
    /// list is empty.
    fn chain_to_with_work(tip: u32, chain_work: Option<[u8; 32]>) -> (HeaderChain, Vec<[u8; 32]>) {
        let h0 = h0();
        let mut chain = HeaderChain::new(
            Network::Regtest,
            Checkpoint {
                height: 0,
                hash: h0.block_hash().to_byte_array(),
                bits: 0x207fffff,
                time: h0.time,
                is_real: false,
                chain_work,
            },
        );
        let mut prev = h0.block_hash();
        for height in 1..=tip {
            let merkle_root = if height == ANCHOR_HEIGHT {
                let mut internal = WITNESS_TXID;
                internal.reverse(); // Merkle math works in internal order
                bitcoin::TxMerkleNode::from_byte_array(internal)
            } else {
                bitcoin::TxMerkleNode::from_byte_array([0xAB; 32])
            };
            let header = mined(Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root,
                time: 1_700_000_000 + height,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            });
            chain.submit_headers(height, &[serialize(&header)]).unwrap();
            prev = header.block_hash();
        }
        let commits = if chain_work.is_some() {
            (0..=tip).map(|h| relay_commit(&chain, h)).collect()
        } else {
            Vec::new()
        };
        (chain, commits)
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

    /// Run the check against a consignment anchored at [`ANCHOR_HEIGHT`],
    /// in the default `BTC_RELAY_MODE=required`.
    fn check(cd: &[u8], chain: &HeaderChain) -> Result<()> {
        check_at(cd, chain, ANCHOR_HEIGHT)
    }

    /// Run the check against a consignment anchored at `anchor_height`, in
    /// the default `BTC_RELAY_MODE=required`.
    fn check_at(cd: &[u8], chain: &HeaderChain, anchor_height: u32) -> Result<()> {
        check_in(cd, chain, anchor_height, BtcRelayMode::Required)
    }

    /// [`check`] on a stand without a BtcRelay (`BTC_RELAY_MODE=none`).
    fn check_no_relay(cd: &[u8], chain: &HeaderChain) -> Result<()> {
        check_in(cd, chain, ANCHOR_HEIGHT, BtcRelayMode::None)
    }

    fn check_in(
        cd: &[u8],
        chain: &HeaderChain,
        anchor_height: u32,
        mode: BtcRelayMode,
    ) -> Result<()> {
        let (validated, proofs) = anchored_at(anchor_height);
        verify_btc_relay_agreement(
            &params_of(cd),
            &validated,
            &proofs,
            chain,
            &ChainPins::new(),
            mode,
        )
    }

    /// The proof the bridge sends when it has no BtcRelay configured: real
    /// heights, both commitment words zero.
    fn zero_commit_calldata() -> Vec<u8> {
        calldata(ANCHOR_HEIGHT, [0u8; 32], TIP_HEIGHT, [0u8; 32])
    }

    // -- Calldata proof vs the enclave's own headers.

    #[test]
    fn passes_on_matching_commitment() {
        let (chain, hashes) = chain();
        assert!(check(&good_calldata(&hashes), &chain).is_ok());
    }

    // -- BTC_RELAY_MODE. The bridge zeroes both commitment words when it has
    // no BtcRelay. Only an enclave in `none` mode accepts that.

    /// `required` (the default) refuses a zero word before it reads the
    /// chain. The message names the setting.
    #[test]
    fn required_mode_rejects_zero_commitments() {
        let (chain, hashes) = chain();
        let err = check(&zero_commit_calldata(), &chain).unwrap_err();
        assert!(
            err.to_string().contains("zero source commitment")
                && err.to_string().contains("BTC_RELAY_MODE=required"),
            "got: {err}"
        );

        // One zero word is also refused.
        let cd = calldata(
            ANCHOR_HEIGHT,
            hashes[ANCHOR_HEIGHT as usize],
            TIP_HEIGHT,
            [0u8; 32],
        );
        let err = check(&cd, &chain).unwrap_err();
        assert!(
            err.to_string().contains("zero latest commitment"),
            "got: {err}"
        );
    }

    /// `none`: both words zero, heights bound, compare skipped.
    #[test]
    fn none_mode_accepts_zero_commitments() {
        let (chain, _) = chain();
        assert!(check_no_relay(&zero_commit_calldata(), &chain).is_ok());
    }

    /// `none` needs no relay record, so no checkpoint chainwork either (the
    /// shape of the built-in signet checkpoint).
    #[test]
    fn none_mode_needs_no_checkpoint_chainwork() {
        let (chain, _) = chain_to_with_work(TIP_HEIGHT, None);
        assert!(check_no_relay(&zero_commit_calldata(), &chain).is_ok());
    }

    /// `none` refuses a real commitment: the bridge has a relay, but the
    /// enclave config has none.
    #[test]
    fn none_mode_rejects_a_non_zero_commitment() {
        let (chain, hashes) = chain();
        let err = check_no_relay(&good_calldata(&hashes), &chain).unwrap_err();
        assert!(
            err.to_string().contains("BTC_RELAY_MODE=none")
                && err.to_string().contains("disagree about the relay"),
            "got: {err}"
        );

        let cd = calldata(
            ANCHOR_HEIGHT,
            [0u8; 32],
            TIP_HEIGHT,
            hashes[TIP_HEIGHT as usize],
        );
        let err = check_no_relay(&cd, &chain).unwrap_err();
        assert!(err.to_string().contains("latest commitment"), "got: {err}");
    }

    /// `none` skips only step 4. The source height must be the consignment
    /// anchor.
    #[test]
    fn none_mode_still_binds_the_source_height() {
        let (chain, _) = chain();
        let cd = calldata(ANCHOR_HEIGHT + 1, [0u8; 32], TIP_HEIGHT, [0u8; 32]);
        let err = check_no_relay(&cd, &chain).unwrap_err();
        assert!(
            err.to_string().contains("fundsOut source block mismatch"),
            "got: {err}"
        );
    }

    /// ... and the relay tip must be fresh.
    #[test]
    fn none_mode_still_binds_relay_freshness() {
        let (chain, _) = chain_to(TIP_HEIGHT + MAX_RELAY_TIP_LAG_BLOCKS + 1);
        let err = check_no_relay(&zero_commit_calldata(), &chain).unwrap_err();
        assert!(
            err.to_string().contains("too stale to prove freshness"),
            "got: {err}"
        );
    }

    /// ... and an empty proof is refused.
    #[test]
    fn none_mode_still_rejects_an_empty_proof() {
        let (chain, _) = chain();
        let cd = mock_funds_out_calldata_with_proof(1_000, Bytes::new());
        assert!(check_no_relay(&cd, &chain).is_err());
    }

    /// Right height, wrong commitment.
    #[test]
    fn rejects_a_source_commitment_that_is_not_the_relay_record() {
        let (chain, hashes) = chain();
        let cd = calldata(
            ANCHOR_HEIGHT,
            [0x11; 32],
            TIP_HEIGHT,
            hashes[TIP_HEIGHT as usize],
        );
        let err = check(&cd, &chain).unwrap_err();
        assert!(
            err.to_string()
                .contains("relay commitment mismatch at source height 11"),
            "got: {err}"
        );
    }

    /// A source height that is not the consignment anchor is refused, with
    /// any commitment.
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

    /// A `source` height with no enclave header (here the checkpoint, below
    /// all stored headers) cannot equal the anchor. The bind rejects it with
    /// no header lookup. A height ABOVE the tip fails the ordering guard
    /// first (see `rejects_latest_below_source`).
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

    /// The relay-tip part of the proof is also checked. Else freshness
    /// depends on a relay that the untrusted host also feeds.
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

    /// The relay's tip is on another branch above the anchor.
    #[test]
    fn rejects_a_latest_commitment_from_another_branch() {
        let (mut chain_a, hashes) = chain();
        submit_extension(&mut chain_a, 3);
        let (mut chain_b, _) = chain();
        submit_reorg(&mut chain_b, ANCHOR_HEIGHT + 3, 1);
        let cd = calldata(
            ANCHOR_HEIGHT,
            hashes[ANCHOR_HEIGHT as usize],
            TIP_HEIGHT,
            relay_commit(&chain_b, TIP_HEIGHT),
        );
        let err = check(&cd, &chain_a).unwrap_err();
        assert!(
            err.to_string()
                .contains("relay commitment mismatch at latest height 17"),
            "got: {err}"
        );
    }

    /// `latest` proves that the enclave has a header there, so it is in sync
    /// with the chain that the relay follows.
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

    /// A `latest` far below the enclave tip proves only that a block existed.
    /// The freshness check then proves nothing.
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

    /// A relay lag within the bound is accepted.
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

    /// Fail closed: a zero-filled `proof` gives the anchor block nothing to
    /// bind to.
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

    /// The legacy proof is one 64-byte `(blockHeight, commitmentHash)` pair.
    /// It verifies the source block, but not relay freshness, so refuse it.
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

    /// A different real block must be refused. The enclave knows it, so the
    /// BtcRelay check passes.
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

    /// No header at the anchor height: refuse, and do not trust the calldata.
    #[test]
    fn rejects_when_tee_has_no_header_at_anchor_height() {
        let (chain, hashes) = chain();
        let err = check_at(&good_calldata(&hashes), &chain, 99).unwrap_err();
        assert!(err.to_string().contains("not in sync"), "got: {err}");
    }

    /// The anchor SPV proof is verified again under the header lock guard.
    /// Thus a reorg after the source-chain pass cannot replace the header.
    #[test]
    fn rejects_when_anchor_proof_does_not_reconstruct_the_root() {
        let (chain, hashes) = chain();
        // Block ANCHOR_HEIGHT + 1 commits a different Merkle root.
        let err = check_at(&good_calldata(&hashes), &chain, ANCHOR_HEIGHT + 1).unwrap_err();
        assert!(err.to_string().contains("failed"), "got: {err}");
    }

    /// Depth is also checked again: an anchor at the tip has 1 confirmation,
    /// less than `SPV_MIN_CONFIRMATIONS`.
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
            BtcRelayMode::Required,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no merkle proof"), "got: {err}");
    }

    // -- F05-NEW-AF-08: the chain can move after the last check.
    //
    // `verify_btc_relay_agreement` is the last chain read on the direct
    // route. Its lock ends at return. A real reorg must close the gate.
    // A real extension must not.

    /// Builds a longer chain from `from_height` and submits it normally. No
    /// test state is written directly, so the real accept rule applies.
    fn submit_reorg(chain: &mut HeaderChain, from_height: u32, extra: u32) {
        let pred = chain
            .hash_at(from_height - 1)
            .expect("reorg fixture needs a predecessor header");
        let mut prev = <bitcoin::BlockHash as bitcoin::hashes::Hash>::from_byte_array(pred);
        let mut raw = Vec::new();
        for height in from_height..=(TIP_HEIGHT + extra) {
            let header = mined(Header {
                version: Version::ONE,
                prev_blockhash: prev,
                // Different from `chain_to`, so each new block gets a new
                // hash.
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xCD; 32]),
                time: 1_700_000_000 + height,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            });
            prev = header.block_hash();
            raw.push(serialize(&header));
        }
        let outcome = chain.submit_headers(from_height, &raw).unwrap();
        assert!(
            outcome.reorg_depth > 0,
            "fixture must be a real reorg, got depth 0"
        );
    }

    /// Extends the tip and rewrites nothing. The harmless control.
    fn submit_extension(chain: &mut HeaderChain, count: u32) {
        let mut prev = <bitcoin::BlockHash as bitcoin::hashes::Hash>::from_byte_array(
            chain.hash_at(chain.tip_height()).expect("tip present"),
        );
        let start = chain.tip_height() + 1;
        let mut raw = Vec::new();
        for height in start..start + count {
            let header = mined(Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xEF; 32]),
                time: 1_700_000_000 + height,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            });
            prev = header.block_hash();
            raw.push(serialize(&header));
        }
        let outcome = chain.submit_headers(start, &raw).unwrap();
        assert_eq!(outcome.reorg_depth, 0, "control must not be a reorg");
    }

    /// Runs the last check and returns what it pinned.
    fn check_pinning(chain: &HeaderChain, hashes: &[[u8; 32]]) -> ChainPins {
        let pins = ChainPins::new();
        let (validated, proofs) = anchored_at(ANCHOR_HEIGHT);
        verify_btc_relay_agreement(
            &params_of(&good_calldata(hashes)),
            &validated,
            &proofs,
            chain,
            &pins,
            BtcRelayMode::Required,
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

    /// A reorg above the anchor rewrites the relay `latest` header. The
    /// proven freshness is then not valid.
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

    /// The enclave holds branch A, with the burn in `A[11]`. The relay
    /// follows branch B. The proof cites B's relay records at the anchor
    /// height and at B's tip. The heights agree, the blocks do not.
    #[test]
    fn rejects_a_source_commitment_from_another_branch() {
        let (mut chain_a, _) = chain();
        submit_extension(&mut chain_a, 3);
        let (mut chain_b, _) = chain();
        submit_reorg(&mut chain_b, ANCHOR_HEIGHT, 2);

        let h = ANCHOR_HEIGHT;
        assert_eq!(chain_a.hash_at(h - 1), chain_b.hash_at(h - 1));
        assert_ne!(chain_a.hash_at(h), chain_b.hash_at(h));
        for chain in [&chain_a, &chain_b] {
            for j in 1..=chain.tip_height() {
                let header = chain.header_at(j).unwrap();
                assert!(header.validate_pow(header.target()).is_ok());
            }
        }

        let latest = chain_b.tip_height();
        let source_b = relay_commit(&chain_b, h);
        let cd = calldata(h, source_b, latest, relay_commit(&chain_b, latest));
        let err = check(&cd, &chain_a).expect_err("a branch-B source commitment must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("relay commitment mismatch at source height {h}")),
            "got: {msg}"
        );
        assert!(msg.contains(&hex::encode(source_b)), "got: {msg}");
        assert!(
            msg.contains(&hex::encode(relay_commit(&chain_a, h))),
            "got: {msg}"
        );
    }

    /// Honest commitments across a retarget boundary.
    #[test]
    fn accepts_relay_commitments_across_a_retarget_boundary() {
        let (chain, hashes) = chain_to(2030);
        let cd = calldata(ANCHOR_HEIGHT, hashes[11], 2016, hashes[2016]);
        check(&cd, &chain).expect("honest commitments pass");
    }

    #[test]
    fn relay_record_refuses_a_height_below_the_checkpoint_window() {
        let (chain, _) = chain();
        let err = relay_record(&chain, 9).unwrap_err();
        assert!(
            err.to_string().contains("below its checkpoint"),
            "got: {err}"
        );
    }

    /// A chain of 30 mined headers above a checkpoint at height 2000, from
    /// a `SPV_CHECKPOINT` spec. `chain_work` is appended to the spec.
    fn chain_above_2000(chain_work: &str) -> HeaderChain {
        let base = h0();
        let spec = format!(
            "2000:{}:0x207fffff:{}{chain_work}",
            base.block_hash(),
            base.time
        );
        let cp = parse_checkpoint_spec(&spec, Network::Regtest, &REGTEST_CHECKPOINT).unwrap();
        let mut chain = HeaderChain::new(Network::Regtest, cp);
        let mut prev = base.block_hash();
        for height in 2001..=2030 {
            let header = mined(Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xAB; 32]),
                time: 1_700_000_000 + height,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            });
            chain.submit_headers(height, &[serialize(&header)]).unwrap();
            prev = header.block_hash();
        }
        chain
    }

    #[test]
    fn relay_record_refuses_a_missing_epoch_start() {
        // Work of 2001 regtest blocks: 2001 * 2.
        let chain = chain_above_2000(&format!(":{:064x}", 2001 * 2));
        // Epoch start 0 is below the checkpoint.
        let err = relay_record(&chain, 2015).unwrap_err();
        assert!(err.to_string().contains("epoch start 0"), "got: {err}");

        // Epoch start 2016 is held.
        let record = relay_record(&chain, 2020).unwrap();
        assert_eq!(&record[..80], serialize(chain.header_at(2020).unwrap()));
        assert_eq!(record[80..112], u256_be(2021 * 2));
        assert_eq!(record[112..116], 2020u32.to_be_bytes());
        assert_eq!(record[116..120], (1_700_000_000u32 + 2016).to_be_bytes());
        for (i, h) in (2010..2020u32).enumerate() {
            assert_eq!(
                record[120 + 4 * i..124 + 4 * i],
                (1_700_000_000 + h).to_be_bytes()
            );
        }
    }

    #[test]
    fn relay_record_refuses_a_checkpoint_without_chainwork() {
        let chain = chain_above_2000("");
        let err = relay_record(&chain, 2020).unwrap_err();
        assert!(err.to_string().contains("has no chainwork"), "got: {err}");
    }

    /// Records produced by `StoredBlockHeaderTestnet.updateChain` for the
    /// headers of `chain_to(2030)`, seeded at [`h0`] with chainwork 2.
    #[test]
    fn relay_record_matches_the_relay_contract() {
        let (chain, _) = chain_to(2030);
        let fixture = include_str!("../../../../tests/fixtures/btc_relay_records.txt");
        let mut lines = 0;
        for line in fixture.lines() {
            let (height, record) = line.split_once(' ').unwrap();
            let height: u32 = height.parse().unwrap();
            let record = hex::decode(record).unwrap();
            assert_eq!(
                relay_record(&chain, height).unwrap().to_vec(),
                record,
                "height {height}"
            );
            assert_eq!(
                relay_model(&chain, height),
                record,
                "model at height {height}"
            );
            lines += 1;
        }
        assert_eq!(lines, 5);
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
            BtcRelayMode::Required,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no last witness txid"),
            "got: {err}"
        );
    }
}
