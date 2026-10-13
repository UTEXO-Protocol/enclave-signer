use super::*;
#[cfg(rgb_to_evm)]
use crate::test_support::bfa_ids;
#[cfg(rgb_to_evm)]
use validation::{TransitionSummary, ValidatedConsignment};

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
        last_transition: Some(TransitionSummary {
            op_id: op_id.into(),
            transition_type,
            total_output_amount,
            asset_output_amount: total_output_amount,
            outputs: vec![],
            burned_asset_amount,
            burn_reason: None,
        }),
        last_witness_txid: None,
        last_transfer_witness_prevouts: vec![],
        last_transfer_op_id: None,
        non_mined_witness_txids: vec![],
        // These cases do not reach the PSBT bind.
        transitions_by_witness: vec![],
        ..Default::default()
    }
}

/// A withdrawal consignment in the shape of this build's flow, with `amount`
/// in the field that the flow reads.
#[cfg(all(feature = "rgb-swap", rgb_to_evm))]
fn funds_out_consignment(amount: u64, op_id: &str) -> ValidatedConsignment {
    validated_consignment(bfa_ids::TS_TRANSFER, amount, None, op_id)
}

#[cfg(all(feature = "rgb-mint-burn", rgb_to_evm))]
fn funds_out_consignment(amount: u64, op_id: &str) -> ValidatedConsignment {
    validated_consignment(bfa_ids::TS_BURN, 0, Some(amount), op_id)
}

#[cfg(all(feature = "rgb-swap", rgb_to_evm))]
#[test]
fn route_proof_uses_transfer_output_amount() {
    let op_id = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let proof = route_proof_from_validated_consignment(&validated_consignment(
        bfa_ids::TS_TRANSFER,
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
        bfa_ids::TS_BURN,
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
        bfa_ids::TS_BURN,
        0,
        None,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ))
    .unwrap_err();

    assert!(err.to_string().contains("no burnedAsset"), "{err}");
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
    let wrong = validated_consignment(bfa_ids::TS_BURN, 0, Some(700), op_id);
    #[cfg(feature = "rgb-mint-burn")]
    let wrong = validated_consignment(bfa_ids::TS_TRANSFER, 700, None, op_id);

    let err = route_proof_from_validated_consignment(&wrong).unwrap_err();
    assert!(
        err.to_string().contains("this enclave is built for the"),
        "expected flow-shape rejection, got: {err}"
    );
}

// Asset-identity binding, destination path. The checks are inline in
// `validate_destination_anchor`, so that function is the smallest testable
// unit. The tests use a generated BFA mint.
//
// Intentional asymmetry: this path always enforces the RGB_ASSET_ID pin.
// The source path enforces it only if `BridgeConfig::is_configured()`.

/// End-to-end asset binding. These tests run the full validator, so they
/// prove that the bind is in the request path. The rule tests in
/// `validation::tests::asset_binding_rule` cannot show this.
#[cfg(evm_to_rgb)]
mod asset_bind {
    use super::*;
    use crate::config::BridgeConfig;
    use crate::error::Result;
    use crate::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
    use crate::networks::rgb::validation::{
        BfaBridge, BoundAnchors, MintAnchor, RgbValidator, VerifiedLock,
    };
    use crate::test_support::bfa_consignment::{self as gen, History, Issue};
    use std::sync::Mutex;

    /// A generated BFA mint of 100_000 units to a blinded seal.
    fn mint() -> History {
        mint_of(Issue::new(42161, [0xB1; 20], vec![gen::outpoint(0xA0, 0)]))
    }

    fn mint_of(issue: Issue) -> History {
        let mut history = History::issue(issue);
        let right = history.genesis_right(0, gen::outpoint(0xA0, 0));
        let to = rgbstd::GraphSeal::with_blinding(gen::outpoint(0xC0, 0).txid, 0u32, 7);
        history.mint(
            right,
            100_000,
            90,
            rgbstd::BuilderSeal::Concealed(to.to_secret_seal()),
            vec![],
            vec![gen::dust(1)],
        );
        history
    }

    fn asset_id() -> String {
        mint().contract_id.to_string()
    }

    fn bind_all(bridge: &BfaBridge, anchors: &[MintAnchor]) -> Result<BoundAnchors> {
        Ok(BoundAnchors {
            evm_chain_id: bridge.chain_id,
            locks: anchors
                .iter()
                .map(|a| VerifiedLock {
                    mint_opid: a.opid,
                    minted: a.amount,
                    operation_id: [0xd0; 32],
                    net_amount: a.amount,
                })
                .collect(),
        })
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

    /// A hash-bound destination with the mint consignment and invalid
    /// `psbt_bytes`. PSBT parsing runs after all asset-binding checks, so its
    /// error proves that the binding passed.
    fn destination(asset_id: &str) -> RgbDestination {
        let consignment = mint().consignment(vec![]);
        RgbDestination {
            operation_idx: 0,
            psbt_bytes: b"not-a-psbt".to_vec(),
            psbt_output_amount: 0,
            asset_id: asset_id.into(),
            consignment_hash: Keccak256::digest(&consignment).to_vec(),
            consignment,
        }
    }

    fn run(destination: &RgbDestination, config: &BridgeConfig) -> Result<u64> {
        run_reading(destination, config, None)
    }

    fn run_reading(
        destination: &RgbDestination,
        config: &BridgeConfig,
        reader: Option<validation::RejectListReader<'_>>,
    ) -> Result<u64> {
        let validator = RgbValidator::new("tcp://indexer.invalid:1".into(), "regtest").unwrap();
        let chain = Mutex::new(HeaderChain::new(
            Network::Regtest,
            checkpoint_for(Network::Regtest),
        ));
        // All cases fail before the PSBT stage, so the resolvers are not
        // called. They must be present, or the fail-closed guards hide the
        // expected error.
        let self_owned = |_: &bitcoin::psbt::Psbt, _: bitcoin::OutPoint| Ok(false);
        let key_paths = |_: &bitcoin::psbt::Psbt| Ok(Vec::new());
        let ctx = ValidationContext {
            bridge_config: config,
            rgb_validator: Some(&validator),
            header_chain: &chain,
            chain_pins: &crate::networks::rgb::spv_crosscheck::ChainPins::new(),
            self_owned_psbt_outputs: Some(&self_owned),
            psbt_fee_key_paths: Some(&key_paths),
            anchor_binder: Some(&bind_all),
            reject_list_reader: reader,
        };
        validate_destination_anchor(destination, 0, 0, &ctx).map(|(amount, _)| amount)
    }

    /// Happy path: validated contract_id == declared asset_id == pinned
    /// RGB_ASSET_ID. All binding checks pass and validation reaches the PSBT stage.
    #[test]
    fn binds_when_contract_id_matches_pin() {
        let id = asset_id();
        let msg = run(&destination(&id), &pinned_config(&id))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("psbt_bytes is not a valid PSBT"), "{msg}");
    }

    /// The destination must declare its asset. An empty `asset_id` fails
    /// closed before the validator runs. The pin alone does not bind.
    #[test]
    fn rejects_when_declared_is_empty() {
        let err = run(&destination(""), &pinned_config(&asset_id())).unwrap_err();
        assert!(
            err.to_string()
                .contains("RGB destination asset_id is empty"),
            "{err}"
        );
    }

    /// The reachable theft path is a listener that declares the foreign asset
    /// of the consignment. The RGB_ASSET_ID pin must still reject it.
    #[test]
    fn rejects_foreign_asset_even_when_declared_agrees() {
        let id = asset_id();
        let msg = run(
            &destination(&id),
            &pinned_config("rgb:some-other-pinned-asset"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            msg.contains("contract_id mismatch") && msg.contains("pinned RGB_ASSET_ID"),
            "{msg}"
        );
    }

    /// This path always fails closed on a missing RGB_ASSET_ID pin.
    #[test]
    fn rejects_when_pin_absent() {
        let err = run(&destination(&asset_id()), &BridgeConfig::default()).unwrap_err();
        assert!(
            err.to_string().contains("asset-identity pin missing"),
            "{err}"
        );
    }

    /// The declared-vs-validated check fails before the pin check.
    #[test]
    fn rejects_when_declared_disagrees_with_validated() {
        let msg = run(
            &destination("rgb:listener-lied"),
            &pinned_config(&asset_id()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            msg.contains("contract_id mismatch") && msg.contains("RGB destination declares"),
            "{msg}"
        );
    }

    /// The PSBT-bind tests use a mint consignment, which only the mint-burn
    /// flow accepts.
    #[cfg(feature = "rgb-mint-burn")]
    mod unbroadcast_mint {
        use super::*;

        /// A pinned destination whose PSBT is `tx`, with no input data.
        fn with_psbt(tx: bitcoin::Transaction) -> (RgbDestination, BridgeConfig) {
            let id = asset_id();
            let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
                .unwrap()
                .serialize();
            let destination = RgbDestination {
                psbt_bytes: psbt,
                ..destination(&id)
            };
            (destination, pinned_config(&id))
        }

        fn mint_tx() -> bitcoin::Transaction {
            mint().bundles.last().unwrap().tx.clone()
        }

        /// The mint tx is unbroadcast, so no indexer knows it. It passes
        /// consensus and the PSBT bind, and stops at the next PSBT check.
        #[test]
        fn the_unbroadcast_mint_tx_passes_when_it_is_the_psbt() {
            let (destination, config) = with_psbt(mint_tx());
            let msg = run(&destination, &config).unwrap_err().to_string();
            assert!(msg.contains("carries no witness_utxo"), "{msg}");
        }

        #[test]
        fn an_unbroadcast_mint_tx_that_is_not_the_psbt_is_refused() {
            let mut other = mint_tx();
            other.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
            let (destination, config) = with_psbt(other);
            let msg = run(&destination, &config).unwrap_err().to_string();
            assert!(
                msg.contains("does not finalize the consignment's transition"),
                "{msg}"
            );
        }
    }

    /// A mint of an asset with a reject list, as a pinned destination.
    fn listed_mint() -> (History, RgbDestination, BridgeConfig) {
        let history = mint_of(Issue {
            reject_list: Some(gen::evm_reject_list(42161, [0x4e; 20])),
            ..Issue::new(42161, [0xB1; 20], vec![gen::outpoint(0xA0, 0)])
        });
        let consignment = history.consignment(vec![]);
        let id = history.contract_id.to_string();
        let destination = RgbDestination {
            consignment_hash: Keccak256::digest(&consignment).to_vec(),
            consignment,
            ..destination(&id)
        };
        (history, destination, pinned_config(&id))
    }

    /// Runs the listed mint with `rejected` on the list.
    fn run_rejecting(rejected: rgbstd::Opout) -> String {
        let (_, destination, config) = listed_mint();
        let entries = [validation::RejectListEntry {
            opout: rejected.into(),
            reject: true,
        }];
        let reader = |_: &validation::RejectListContract| Ok(validation::decisions(&entries, 1));
        run_reading(&destination, &config, Some(&reader))
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn mint_from_a_rejected_right_is_refused() {
        let (history, ..) = listed_mint();
        let right = history.genesis_right(0, gen::outpoint(0xA0, 0)).opout;
        let msg = run_rejecting(right);
        assert!(msg.contains("reject list: opout"), "{msg}");
    }

    /// The recipient would refuse it, which strands the deposit.
    #[test]
    fn mint_whose_output_is_rejected_is_refused() {
        let (history, ..) = listed_mint();
        let minted = rgbstd::Opout::new(history.mints[0].opid, schemata::OS_ASSET, 0);
        let msg = run_rejecting(minted);
        assert!(msg.contains("reject list: opout"), "{msg}");
    }

    #[test]
    fn mint_with_unrelated_entries_reaches_the_psbt_check() {
        let unrelated = rgbstd::Opout::new(
            rgbstd::OpId::copy_from_slice([0x99; 32]).unwrap(),
            schemata::OS_ASSET,
            0,
        );
        let msg = run_rejecting(unrelated);
        assert!(msg.contains("psbt_bytes is not a valid PSBT"), "{msg}");
    }

    // No end-to-end test for an empty validated contract_id.
    // `validate_consignment` derives it from the genesis, so it is never
    // empty. `assert_asset_binding` rejects it, and
    // `validation::tests::asset_binding_rule` covers the rule.
}
