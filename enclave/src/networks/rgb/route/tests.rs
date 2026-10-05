use super::*;
#[cfg(rgb_to_evm)]
use validation::{bfa, TransitionSummary, ValidatedConsignment};

#[cfg(rgb_to_evm)]
fn validated_consignment(
    transition_type: u16,
    total_output_amount: u64,
    burned_asset_amount: Option<u64>,
    op_id: &str,
) -> ValidatedConsignment {
    ValidatedConsignment {
        contract_id: "rgb:test-asset".into(),
        chain_net: "bc:regtest".into(),
        witness_txids: vec![],
        all_op_ids: vec![op_id.into()],
        mint_op_ids: vec![],
        last_transition: Some(TransitionSummary {
            op_id: op_id.into(),
            transition_type,
            total_output_amount,
            asset_output_amount: total_output_amount,
            outputs: vec![],
            burned_asset_amount,
            burn_recipient: None,
        }),
        last_witness_txid: None,
        last_transfer_witness_prevouts: None,
        last_transfer_op_id: None,
        non_mined_witness_txids: vec![],
        // These cases do not reach the PSBT bind.
        transitions_by_witness: vec![],
    }
}

/// A withdrawal consignment in the shape of this build's flow, with `amount`
/// in the field that the flow reads.
#[cfg(all(feature = "rgb-swap", rgb_to_evm))]
fn funds_out_consignment(amount: u64, op_id: &str) -> ValidatedConsignment {
    validated_consignment(bfa::TS_TRANSFER, amount, None, op_id)
}

#[cfg(all(feature = "rgb-mint-burn", rgb_to_evm))]
fn funds_out_consignment(amount: u64, op_id: &str) -> ValidatedConsignment {
    validated_consignment(bfa::TS_BURN, 0, Some(amount), op_id)
}

#[cfg(all(feature = "rgb-swap", rgb_to_evm))]
#[test]
fn route_proof_uses_transfer_output_amount() {
    let op_id = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let proof = route_proof_from_validated_consignment(&validated_consignment(
        bfa::TS_TRANSFER,
        1_500,
        None,
        op_id,
    ))
    .unwrap();

    assert_eq!(proof.amount, 1_500);
    assert_eq!(
        proof.operation_id.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[cfg(all(feature = "rgb-mint-burn", rgb_to_evm))]
#[test]
fn route_proof_uses_burn_metadata_amount() {
    let op_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let proof = route_proof_from_validated_consignment(&validated_consignment(
        bfa::TS_BURN,
        0,
        Some(700),
        op_id,
    ))
    .unwrap();

    assert_eq!(proof.amount, 700);
    assert_eq!(proof.operation_id.as_deref(), Some(op_id));
}

#[cfg(all(feature = "rgb-mint-burn", rgb_to_evm))]
#[test]
fn route_proof_rejects_burn_without_burned_amount() {
    let err = route_proof_from_validated_consignment(&validated_consignment(
        bfa::TS_BURN,
        0,
        None,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ))
    .unwrap_err();

    assert!(err.to_string().contains("burn transition is missing"));
}

#[cfg(rgb_to_evm)]
#[test]
fn route_proof_rejects_non_hex_operation_id() {
    let err = route_proof_from_validated_consignment(&funds_out_consignment(
        100,
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ))
    .unwrap_err();

    assert!(err.to_string().contains("not hex-decodable"));
}

/// The other flow's withdrawal shape must not authorize a release here.
#[cfg(rgb_to_evm)]
#[test]
fn route_proof_rejects_the_other_flows_shape() {
    let op_id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    #[cfg(feature = "rgb-swap")]
    let wrong = validated_consignment(bfa::TS_BURN, 0, Some(700), op_id);
    #[cfg(feature = "rgb-mint-burn")]
    let wrong = validated_consignment(bfa::TS_TRANSFER, 700, None, op_id);

    let err = route_proof_from_validated_consignment(&wrong).unwrap_err();
    assert!(
        err.to_string().contains("this enclave is built for the"),
        "expected flow-shape rejection, got: {err}"
    );
}

// Asset-identity binding, destination path. The checks are inline in
// `validate_destination_anchor`, so that function is the smallest testable
// unit. The tests use the mainnet transfer fixture and a stub Electrum.
//
// Intentional asymmetry: this path always enforces the RGB_ASSET_ID pin.
// The source path enforces it only if `BridgeConfig::is_configured()`.

/// End-to-end asset binding. These tests run the full validator, so they
/// prove that the bind is in the request path. The rule tests in
/// `validation::tests::asset_binding_rule` cannot show this.
///
/// They run on a real BFA consignment (see `BFA_FIXTURE`). The consignment
/// history has a mint, and only a `bfa-validation` build can run a mint
/// script. Without that feature, the cases that must pass RGB consensus are
/// ignored.
#[cfg(evm_to_rgb)]
mod asset_bind {
    use super::*;
    use crate::config::BridgeConfig;
    use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
    use crate::networks::rgb::validation::RgbValidator;
    use rgbstd::containers::{ConsignmentExt, FileContent, Transfer};
    use std::io::Cursor;
    use std::sync::Mutex;

    /// A real BFA consignment from a bridge run on signet: one `Bridge` mint
    /// of 100_000 units, then two `Burn`s. The last transition is a burn, not
    /// the mint that a deposit PSBT finalizes. That is sufficient here: each
    /// case below stops at or before the PSBT parse, which is before the
    /// transition-type gate.
    const BFA_FIXTURE: &[u8] =
        include_bytes!("../../../../tests/fixtures/bfa_burn_consignment.rgbc");

    /// Contract id of `BFA_FIXTURE`. [`fixture_asset_id`] derives it again
    /// and asserts it, so a fixture change fails loudly.
    const FIXTURE_ASSET_ID: &str = "rgb:psO2jKZI-i4fudyA-ORTT8a~-SMaLO6u-69ELk2p-yPRGPJY";

    /// The validated asset identity: the genesis contract id of the fixture.
    fn fixture_asset_id() -> String {
        let t = Transfer::load(Cursor::new(BFA_FIXTURE)).expect("load BFA fixture");
        let id = t.contract_id().to_string();
        assert_eq!(
            id, FIXTURE_ASSET_ID,
            "BFA fixture contract id drifted - update FIXTURE_ASSET_ID"
        );
        id
    }

    /// The EVM lock for the one mint in the fixture, as the `FundsIn` read of
    /// the enclave reports it: the mint OpId and 100_000 units. RGB consensus
    /// (`cea`) refuses the mint without an event that agrees.
    fn fixture_mint_events() -> Vec<rgbstd::vm::ether_extension::Event> {
        let mint_opid: [u8; 32] =
            hex::decode("6d72ee6970a5cd28ef6f00a67b95242e088941bd79980739c29a40fb4050e593")
                .unwrap()
                .try_into()
                .unwrap();
        vec![rgbstd::vm::ether_extension::Event::new(
            rgbstd::OpId::from(mint_opid),
            rgbstd::RevealedValue::new(100_000u64),
        )]
    }

    /// Stub Electrum that answers only the signet chain check.
    fn spawn_stub_electrum() -> String {
        crate::test_support::electrum_stub::spawn(bitcoin::Network::Signet)
    }

    /// Fully pinned operator config (`is_configured() == true`) with the
    /// given RGB_ASSET_ID.
    fn pinned_config(rgb_asset_id: &str) -> BridgeConfig {
        BridgeConfig {
            chain_id: 1,
            bridge_contract: [0x11; 20],
            rgb_asset_id: rgb_asset_id.into(),
            gas_tx_allowed_to: None,
            ..Default::default()
        }
    }

    /// Empty operator config with no RGB_ASSET_ID pin.
    fn unconfigured_config() -> BridgeConfig {
        BridgeConfig {
            chain_id: 0,
            bridge_contract: [0u8; 20],
            rgb_asset_id: String::new(),
            gas_tx_allowed_to: None,
            ..Default::default()
        }
    }

    /// A hash-bound destination with the fixture consignment and invalid
    /// `psbt_bytes`. PSBT parsing runs after all asset-binding checks, so its
    /// error proves that the binding passed.
    fn fixture_destination(asset_id: &str) -> RgbDestination {
        RgbDestination {
            operation_idx: 0,
            psbt_bytes: b"not-a-psbt".to_vec(),
            psbt_output_amount: 0,
            asset_id: asset_id.into(),
            consignment: BFA_FIXTURE.to_vec(),
            mint_ancestors: Vec::new(),
            consignment_hash: Keccak256::digest(BFA_FIXTURE).to_vec(),
        }
    }

    /// Runs `validate_destination_anchor` with a stub-Electrum validator.
    fn run_validate_destination_anchor(
        destination: &RgbDestination,
        config: &BridgeConfig,
    ) -> Result<u64> {
        let url = spawn_stub_electrum();
        let validator = RgbValidator::new(url, "signet").expect("validator");
        let events = fixture_mint_events();
        let chain = Mutex::new(HeaderChain::new(
            Network::Signet,
            Checkpoint {
                height: 0,
                hash: [0u8; 32],
                bits: 0x1d00_ffff,
                time: 1_700_000_000,
                is_real: false,
                chain_work: None,
            },
        ));
        // All cases fail before the PSBT stage, so the resolver is not called.
        // It must be present, or the fail-closed guard hides the expected error.
        let self_owned = |_: &bitcoin::psbt::Psbt, _: bitcoin::OutPoint| Ok(false);
        let ctx = ValidationContext {
            bridge_config: config,
            rgb_validator: Some(&validator),
            header_chain: &chain,
            chain_pins: &crate::networks::rgb::spv_crosscheck::ChainPins::new(),
            self_owned_psbt_outputs: Some(&self_owned),
            psbt_fee_key_paths: None,
            bridge_events: &events,
        };
        validate_destination_anchor(destination, 0, 0, &ctx).map(|(amount, _)| amount)
    }

    /// Happy path: validated contract_id == declared asset_id == pinned
    /// RGB_ASSET_ID. All binding checks pass and validation reaches the PSBT stage.
    #[test]
    #[cfg_attr(
        not(feature = "bfa-validation"),
        ignore = "needs bfa-validation to run the mint script of the fixture"
    )]
    fn binds_when_contract_id_matches_pin() {
        let id = fixture_asset_id();
        let err = run_validate_destination_anchor(&fixture_destination(&id), &pinned_config(&id))
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("psbt_bytes is not a valid PSBT"),
            "expected to reach the PSBT stage past asset binding, got: {msg}"
        );
        assert!(
            !msg.contains("contract_id mismatch") && !msg.contains("RGB_ASSET_ID"),
            "asset binding must have passed, got: {msg}"
        );
    }

    /// The destination must declare its asset. An empty `asset_id` fails
    /// closed before the validator runs. The pin alone does not bind.
    #[test]
    fn rejects_when_declared_is_empty() {
        let err = run_validate_destination_anchor(
            &fixture_destination(""),
            &pinned_config(FIXTURE_ASSET_ID),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("RGB destination asset_id is empty"),
            "expected empty-declared rejection, got: {err}"
        );
    }

    /// Empty declarations fail first. Thus the reachable theft path is a
    /// listener that declares the foreign asset of the consignment. The
    /// RGB_ASSET_ID pin must still reject it.
    #[test]
    #[cfg_attr(
        not(feature = "bfa-validation"),
        ignore = "needs bfa-validation to run the mint script of the fixture"
    )]
    fn rejects_foreign_asset_even_when_declared_agrees() {
        let id = fixture_asset_id();
        let err = run_validate_destination_anchor(
            &fixture_destination(&id),
            &pinned_config("rgb:some-other-pinned-asset"),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("contract_id mismatch") && msg.contains("pinned RGB_ASSET_ID"),
            "expected pin mismatch, got: {msg}"
        );
    }

    /// This path always fails closed on a missing RGB_ASSET_ID pin, with no
    /// `is_configured()` gate. An enclave with no pin must not trust the
    /// listener to sign a send-RGB PSBT.
    #[test]
    #[cfg_attr(
        not(feature = "bfa-validation"),
        ignore = "needs bfa-validation to run the mint script of the fixture"
    )]
    fn rejects_when_pin_absent() {
        let id = fixture_asset_id();
        let err =
            run_validate_destination_anchor(&fixture_destination(&id), &unconfigured_config())
                .unwrap_err();
        assert!(
            err.to_string().contains("asset-identity pin missing"),
            "expected pin-missing rejection, got: {err}"
        );
    }

    /// The listener declares an asset that is not the validated identity.
    /// The declared-vs-validated check fails before the pin check.
    #[test]
    #[cfg_attr(
        not(feature = "bfa-validation"),
        ignore = "needs bfa-validation to run the mint script of the fixture"
    )]
    fn rejects_when_declared_disagrees_with_validated() {
        let err = run_validate_destination_anchor(
            &fixture_destination("rgb:listener-lied"),
            &pinned_config(FIXTURE_ASSET_ID),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("contract_id mismatch") && msg.contains("RGB destination declares"),
            "expected declared-mismatch rejection, got: {msg}"
        );
    }

    // No end-to-end test for an empty validated contract_id.
    // `validate_consignment` derives it from the genesis, so it is never
    // empty. `assert_asset_binding` rejects it, and
    // `validation::tests::asset_binding_rule` covers the rule.
}
