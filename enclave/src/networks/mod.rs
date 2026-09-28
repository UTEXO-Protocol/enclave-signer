#[cfg(feature = "spv")]
use std::sync::Mutex;

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
#[cfg(feature = "rgb-validation")]
use crate::networks::rgb::validation::RgbValidator;
use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};

// `ccd` is self-contained, so its module is feature-gated. `rgb` and `evm` stay
// always-compiled: they are woven into shared code (keys.rs PSBT signing,
// error.rs SpvError), and their heavy deps sit behind `rgb-validation`.
#[cfg(feature = "ccd")]
pub mod ccd;
pub mod evm;
pub mod rgb;

/// Normalized bridge-side proof emitted by source and destination validators.
///
/// Each network module validates only its own payload and maps the trusted
/// amount/operation identity into this route-neutral shape
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProof {
    pub amount: u64,
    pub operation_id: Option<String>,
}

pub struct ValidationContext<'a> {
    pub bridge_config: &'a BridgeConfig,
    #[cfg(feature = "rgb-validation")]
    pub rgb_validator: Option<&'a RgbValidator>,
    #[cfg(feature = "spv")]
    pub header_chain: &'a Mutex<crate::networks::rgb::spv::HeaderChain>,
    /// Resolves whether a Bitcoin outpoint pays back to this enclave.
    /// Required by the send-RGB per-output recipient bind to tell
    /// bridge change from a payout to a third party. The outpoint may sit on
    /// the PSBT being signed or on an earlier transaction - see
    /// [`crate::networks::rgb::psbt_validation::SelfOwnedOutpoint`].
    ///
    /// A callback, so the key lock is taken only for that resolution and never
    /// across consignment validation's network round-trips. `None` fails the
    /// bind closed.
    #[cfg(feature = "rgb-validation")]
    pub self_owned_psbt_outputs:
        Option<crate::networks::rgb::psbt_validation::SelfOwnedOutpoint<'a>>,
    /// EVM lock events the enclave verified itself, handed to RGB consensus so
    /// the ether extension can re-check a BFA mint's amount. Empty on every
    /// other path (including every build without `bfa-mint`); a BFA consignment
    /// with an empty set is refused.
    #[cfg(feature = "rgb-validation")]
    pub bridge_events: &'a [rgbstd::vm::ether_extension::Event],
}

/// Outcome of validating a source network: the route proof, plus the validated
/// consignment for an RGB source on an `rgb-validation` build. The EVM
/// destination signer binds the `fundsOut` calldata to that consignment, so it
/// must outlive source validation. `None` for EVM sources and dev-mode.
pub struct SourceProof {
    pub proof: RouteProof,
    #[cfg(feature = "rgb-validation")]
    pub rgb_consignment: Option<crate::networks::rgb::validation::ValidatedConsignment>,
}

/// Dispatch source-network validation to the owning network module.
pub fn validate_source(
    amount: u64,
    source: &SourceNetwork,
    ctx: &ValidationContext<'_>,
) -> Result<SourceProof> {
    match source {
        SourceNetwork::EvmSource(source) => Ok(SourceProof {
            proof: evm::validation::validate_source(amount, source)?,
            #[cfg(feature = "rgb-validation")]
            rgb_consignment: None,
        }),
        // RGB is always compiled; `rgb::validate_source` fails closed (with a
        // "requires --features rgb-validation" message) on a build that lacks
        // the validator, so a `ccd`-only enclave refuses RGB sources there.
        SourceNetwork::RgbSource(source) => rgb::validate_source(amount, source, ctx),
        // Concordium source handling is gated with the `ccd` feature.
        #[cfg(feature = "ccd")]
        SourceNetwork::CcdSource(source) => Ok(SourceProof {
            proof: ccd::validate_source(amount, source)?,
            #[cfg(feature = "rgb-validation")]
            rgb_consignment: None,
        }),
        #[allow(unreachable_patterns)]
        _ => Err(EnclaveError::InvalidRequest(
            "source network not supported by this build (rebuild with `--features ccd`)".into(),
        )),
    }
}

/// Route proof plus, for an EVM `fundsOut`, the calldata decoded once into one
/// typed intent that the later stages consume. `None` for RGB
/// destinations and the dev-mode bypass.
pub struct DestinationProof {
    pub proof: RouteProof,
    pub evm_funds_out: Option<crate::networks::evm::validation::FundsOutParams>,
    /// `utxob:...` seals of the send-RGB confidential recipient legs. Bound
    /// against the deposit's invoice once that receipt is verified. Empty for
    /// EVM destinations and builds without the bind.
    pub rgb_recipient_seals: Vec<String>,
}

/// Dispatch destination-network validation to the owning network module.
pub fn validate_destination(
    amount: u64,
    source_commission: u64,
    destination: &DestinationNetwork,
    ctx: &ValidationContext<'_>,
) -> Result<DestinationProof> {
    #[cfg(not(all(feature = "rgb-validation", not(feature = "dev-mode"))))]
    {
        let _ = amount;
        let _ = source_commission;
    }

    match destination {
        DestinationNetwork::EvmDestination(destination) => {
            let (proof, evm_funds_out) = evm::validation::validate_destination(destination, ctx)?;
            Ok(DestinationProof {
                proof,
                evm_funds_out,
                rgb_recipient_seals: Vec::new(),
            })
        }
        DestinationNetwork::RgbDestination(destination) => {
            rgb::validate_destination(destination, ctx)?;

            // The destination amount is the consignment's recipient leg,
            // proven inside the enclave, not the unchecked
            // host-supplied `psbt_output_amount`. Only builds without that
            // binding fall back to the wire field, and they run no destination
            // cross-checks at all.
            #[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
            let (destination_amount, rgb_recipient_seals) =
                rgb::validate_destination_anchor(destination, amount, source_commission, ctx)?;
            #[cfg(not(all(feature = "rgb-validation", not(feature = "dev-mode"))))]
            let (destination_amount, rgb_recipient_seals) =
                (destination.psbt_output_amount, Vec::new());

            Ok(DestinationProof {
                proof: RouteProof {
                    amount: destination_amount
                        .checked_add(source_commission)
                        .ok_or_else(|| {
                            EnclaveError::CrossCheck(
                                "destination amount + source_commission overflow".into(),
                            )
                        })?,
                    operation_id: None,
                },
                evm_funds_out: None,
                rgb_recipient_seals,
            })
        }
    }
}

/// Validate that source and destination proofs describe the same route action.
pub fn validate_route_proofs(
    source: &SourceNetwork,
    destination: &DestinationNetwork,
    source_proof: &RouteProof,
    destination_proof: &RouteProof,
) -> Result<()> {
    if cfg!(all(feature = "dev-mode", not(test))) {
        let _ = source;
        let _ = destination;
        let _ = source_proof;
        let _ = destination_proof;
        return Ok(());
    }

    match (source, destination) {
        (SourceNetwork::EvmSource(_), DestinationNetwork::RgbDestination(_)) => {
            validate_amount_covers_destination(source_proof.amount, destination_proof.amount)
        }
        (SourceNetwork::RgbSource(_), DestinationNetwork::EvmDestination(_)) => {
            validate_amount_covers_destination(source_proof.amount, destination_proof.amount)
            // TODO: re-enable operation_id binding once EVM destination proofs
            // derive the operation id from fundsOut.settlementData. The current
            // contract burnId is unrelated to the RGB consignment opId.
            // validate_operation_ids_match(source_proof, destination_proof)
        }
        // Concordium fundsIn -> EVM release. Source finality/structure was
        // validated by the listener; bind the release amount to the destination.
        #[cfg(feature = "ccd")]
        (SourceNetwork::CcdSource(_), DestinationNetwork::EvmDestination(_)) => {
            validate_amount_covers_destination(source_proof.amount, destination_proof.amount)
        }
        _ => Err(EnclaveError::InvalidRequest(
            "unsupported source/destination network pair".into(),
        )),
    }
}

/// Both sides are bridge asset units, not sats. `source_amount` is the EVM
/// `FundsIn` token amount verified by `evm::evm_event::verify_funds_in_event`;
/// an RGB `destination_amount` is the consignment's recipient leg in RGB asset
/// units, issued 1:1 against the EVM token. The sats-denominated PSBT checks
/// live in [`crate::networks::rgb::btc_crosscheck`].
fn validate_amount_covers_destination(source_amount: u64, destination_amount: u64) -> Result<()> {
    if source_amount < destination_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "amount mismatch: source amount ({source_amount}) < destination amount ({destination_amount})"
        )));
    }

    Ok(())
}

#[allow(dead_code)]
fn validate_operation_ids_match(source: &RouteProof, destination: &RouteProof) -> Result<()> {
    let source_id = source.operation_id.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck("source route proof is missing operation_id".into())
    })?;
    let destination_id = destination.operation_id.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck("destination route proof is missing operation_id".into())
    })?;

    if source_id != destination_id {
        return Err(EnclaveError::CrossCheck(format!(
            "operation mismatch: source operation_id {source_id} != destination operation_id {destination_id}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "ccd")]
    use crate::proto::CcdSource;
    use crate::proto::{EvmDestination, EvmSource, RgbDestination, RgbSource};

    fn evm_source(commission: u64) -> SourceNetwork {
        SourceNetwork::EvmSource(EvmSource {
            tx_hash: vec![0xAA; 32],
            event_valid: true,
            event_finalized: true,
            token: vec![0x11; 20],
            recipient: vec![0x22; 20],
            commission,
            funds_in_operation_id: vec![0x33; 32],
        })
    }

    fn rgb_destination(destination_amount: u64) -> DestinationNetwork {
        DestinationNetwork::RgbDestination(RgbDestination {
            operation_idx: 1,
            psbt_bytes: vec![0x70, 0x73, 0x62, 0x74, 0xff],
            psbt_output_amount: destination_amount,
            asset_id: "rgb:test-asset".into(),
            consignment: vec![],
            mint_ancestors: Vec::new(),
            consignment_hash: vec![],
        })
    }

    fn rgb_source() -> SourceNetwork {
        SourceNetwork::RgbSource(RgbSource {
            consignment_valid: true,
            asset_id: "rgb:test-asset".into(),
            consignment: vec![0x01],
            consignment_hash: vec![0x02; 32],
            merkle_proofs: vec![],
            commission: 20,
            mint_ancestors: vec![],
        })
    }

    #[cfg(feature = "ccd")]
    fn ccd_source(commission: u64) -> SourceNetwork {
        SourceNetwork::CcdSource(CcdSource {
            tx_hash: vec![0xCC; 32],
            commission,
        })
    }

    fn evm_destination(destination_amount: u64, commission: u64) -> DestinationNetwork {
        DestinationNetwork::EvmDestination(EvmDestination {
            call_data: vec![0x00; 4],
            nonce: 1,
            deadline: 1,
            chain_id: 1,
            proxy_contract: vec![0x33; 20],
            calldata_amount: destination_amount,
            calldata_commission: commission,
            lz_release: None,
        })
    }

    fn proof(amount: u64, operation_id: Option<&str>) -> RouteProof {
        RouteProof {
            amount,
            operation_id: operation_id.map(str::to_string),
        }
    }

    #[test]
    fn route_proofs_accept_exact_match_to_rgb_destination() {
        assert!(validate_route_proofs(
            &evm_source(20),
            &rgb_destination(90),
            &proof(90, None),
            &proof(90, None),
        )
        .is_ok());
    }

    #[cfg(feature = "ccd")]
    #[test]
    fn route_proofs_accept_ccd_source_to_evm_destination() {
        assert!(validate_route_proofs(
            &ccd_source(10),
            &evm_destination(990, 10),
            &proof(990, None),
            &proof(990, None),
        )
        .is_ok());
    }

    #[cfg(feature = "ccd")]
    #[test]
    fn route_proofs_reject_underfunded_ccd_to_evm_destination() {
        let err = validate_route_proofs(
            &ccd_source(10),
            &evm_destination(990, 10),
            &proof(980, None), // source amount < destination amount
            &proof(990, None),
        );
        assert!(err.is_err());
    }

    #[cfg(feature = "ccd")]
    #[test]
    fn ccd_validate_source_trusts_and_binds_amount() {
        let proof = ccd::validate_source(
            990,
            &CcdSource {
                tx_hash: vec![0xCC; 32],
                commission: 10,
            },
        )
        .expect("trusted CCD source");
        assert_eq!(proof.amount, 990);
    }

    #[cfg(feature = "ccd")]
    #[test]
    fn ccd_validate_source_rejects_bad_tx_hash() {
        let err = ccd::validate_source(
            990,
            &CcdSource {
                tx_hash: vec![0xCC; 31],
                commission: 10,
            },
        );
        assert!(err.is_err());
    }

    #[test]
    fn route_proofs_reject_underfunded_rgb_destination() {
        let err = validate_route_proofs(
            &evm_source(20),
            &rgb_destination(90),
            &proof(89, None),
            &proof(90, None),
        )
        .unwrap_err();
        assert!(err.to_string().contains("amount mismatch"));
    }

    #[test]
    fn route_proofs_accept_rgb_to_evm_match() {
        assert!(validate_route_proofs(
            &rgb_source(),
            &evm_destination(90, 20),
            &proof(90, Some("op")),
            &proof(90, Some("op")),
        )
        .is_ok());
    }

    #[test]
    fn route_proofs_reject_underfunded_evm_destination() {
        let err = validate_route_proofs(
            &rgb_source(),
            &evm_destination(90, 20),
            &proof(89, Some("op")),
            &proof(90, Some("op")),
        )
        .unwrap_err();
        assert!(err.to_string().contains("amount mismatch"));
    }

    #[test]
    fn route_proofs_do_not_compare_rgb_to_evm_operation_id_yet() {
        assert!(validate_route_proofs(
            &rgb_source(),
            &evm_destination(90, 20),
            &proof(90, Some("source-op")),
            &proof(90, Some("destination-op")),
        )
        .is_ok());
    }

    #[test]
    fn route_proofs_accept_rgb_to_evm_missing_operation_id_for_now() {
        assert!(validate_route_proofs(
            &rgb_source(),
            &evm_destination(90, 20),
            &proof(90, None),
            &proof(90, Some("destination-op")),
        )
        .is_ok());
    }

    #[test]
    fn route_proofs_reject_unsupported_pair() {
        let err = validate_route_proofs(
            &rgb_source(),
            &rgb_destination(90),
            &proof(90, None),
            &proof(90, None),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    #[cfg(feature = "ccd")]
    use crate::proto::CcdSource;
    #[cfg(not(feature = "rgb-validation"))]
    use crate::proto::RgbSource;
    use crate::proto::{EvmDestination, EvmSource, RgbDestination};
    #[cfg(feature = "spv")]
    use std::sync::Mutex;

    /// Same shape as the EVM validator's own test helper, so it compiles under
    /// every feature combination CI builds.
    fn with_ctx<T>(config: &BridgeConfig, f: impl FnOnce(&ValidationContext<'_>) -> T) -> T {
        #[cfg(feature = "spv")]
        let header_chain = Mutex::new(crate::networks::rgb::spv::HeaderChain::new(
            crate::networks::rgb::spv::Network::Regtest,
            crate::networks::rgb::spv::checkpoint_for(crate::networks::rgb::spv::Network::Regtest),
        ));
        let ctx = ValidationContext {
            bridge_config: config,
            #[cfg(feature = "rgb-validation")]
            rgb_validator: None,
            #[cfg(feature = "spv")]
            header_chain: &header_chain,
            #[cfg(feature = "rgb-validation")]
            self_owned_psbt_outputs: None,
            #[cfg(feature = "rgb-validation")]
            bridge_events: &[],
        };
        f(&ctx)
    }

    fn pinned() -> BridgeConfig {
        BridgeConfig {
            chain_id: 1,
            bridge_contract: [0xAA; 20],
            rgb_asset_id: "rgb:test".into(),
            ..Default::default()
        }
    }

    fn evm_source(tx_hash_len: usize) -> SourceNetwork {
        SourceNetwork::EvmSource(EvmSource {
            tx_hash: vec![0xAA; tx_hash_len],
            event_valid: false,
            event_finalized: false,
            token: vec![],
            recipient: vec![],
            commission: 3,
            funds_in_operation_id: vec![],
        })
    }

    fn funds_out_calldata(amount: u64) -> Vec<u8> {
        use crate::networks::evm::validation::{fundsOutCall, FundsOutParams};
        use alloy_primitives::{Address, Bytes, U256};
        use alloy_sol_types::SolCall;
        fundsOutCall {
            params: FundsOutParams {
                recipient: Address::from([0x22; 20]),
                amount: U256::from(amount),
                burnId: U256::from(7u64),
                sourceChainId: U256::from(1u64),
                destinationChainId: U256::from(1u64),
                sourceAddress: String::new(),
                proof: Bytes::new(),
                settlementData: Bytes::new(),
            },
        }
        .abi_encode()
    }

    fn evm_destination(amount: u64) -> DestinationNetwork {
        DestinationNetwork::EvmDestination(EvmDestination {
            call_data: funds_out_calldata(amount),
            nonce: 1,
            deadline: u64::MAX,
            chain_id: 1,
            proxy_contract: vec![0xAA; 20],
            calldata_amount: amount,
            calldata_commission: 0,
            lz_release: None,
        })
    }

    /// A BIP-174-valid PSBT with one input and one output, enough to pass
    /// the RGB destination's shape check without any signing material.
    #[allow(dead_code)]
    fn minimal_psbt() -> Vec<u8> {
        use bitcoin::hashes::Hash;
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        bitcoin::psbt::Psbt::from_unsigned_tx(tx)
            .unwrap()
            .serialize()
    }

    #[allow(dead_code)]
    fn rgb_destination(psbt_bytes: Vec<u8>, amount: u64) -> DestinationNetwork {
        DestinationNetwork::RgbDestination(RgbDestination {
            operation_idx: 1,
            psbt_bytes,
            psbt_output_amount: amount,
            asset_id: "rgb:test".into(),
            consignment: vec![],
            mint_ancestors: Vec::new(),
            consignment_hash: vec![],
        })
    }

    // ---- amount comparison --------------------------------------------------

    #[test]
    fn amount_check_accepts_equal_and_surplus_source() {
        assert!(validate_amount_covers_destination(10, 10).is_ok());
        assert!(validate_amount_covers_destination(11, 10).is_ok());
        assert!(validate_amount_covers_destination(u64::MAX, 0).is_ok());
        assert!(validate_amount_covers_destination(0, 0).is_ok());
    }

    #[test]
    fn amount_check_rejects_any_shortfall_with_both_numbers() {
        match validate_amount_covers_destination(9, 10) {
            Err(EnclaveError::CrossCheck(msg)) => {
                assert!(msg.contains("(9)") && msg.contains("(10)"), "{msg}");
            }
            other => panic!("expected CrossCheck, got {other:?}"),
        }
        assert!(validate_amount_covers_destination(0, 1).is_err());
        assert!(validate_amount_covers_destination(u64::MAX - 1, u64::MAX).is_err());
    }

    // ---- operation-id binding (kept for when the binding returns) ----------

    #[test]
    fn operation_ids_match_when_both_present_and_equal() {
        let a = RouteProof {
            amount: 1,
            operation_id: Some("op".into()),
        };
        assert!(validate_operation_ids_match(&a, &a.clone()).is_ok());
    }

    #[test]
    fn operation_ids_reject_mismatch_and_each_missing_side() {
        let with = |id: Option<&str>| RouteProof {
            amount: 1,
            operation_id: id.map(str::to_string),
        };
        let err = validate_operation_ids_match(&with(Some("a")), &with(Some("b"))).unwrap_err();
        assert!(err.to_string().contains("operation mismatch"), "{err}");
        let err = validate_operation_ids_match(&with(None), &with(Some("b"))).unwrap_err();
        assert!(err.to_string().contains("source route proof"), "{err}");
        let err = validate_operation_ids_match(&with(Some("a")), &with(None)).unwrap_err();
        assert!(err.to_string().contains("destination route proof"), "{err}");
        assert!(validate_operation_ids_match(&with(None), &with(None)).is_err());
    }

    // ---- validate_source dispatch --------------------------------------------

    #[test]
    fn evm_source_dispatches_and_binds_the_request_amount() {
        with_ctx(&pinned(), |ctx| {
            let out = validate_source(500, &evm_source(32), ctx).unwrap();
            assert_eq!(
                out.proof,
                RouteProof {
                    amount: 500,
                    operation_id: None
                }
            );
            #[cfg(feature = "rgb-validation")]
            assert!(out.rgb_consignment.is_none());
        });
    }

    #[test]
    fn evm_source_with_a_bad_tx_hash_is_rejected_at_dispatch() {
        with_ctx(&pinned(), |ctx| {
            let err = validate_source(500, &evm_source(31), ctx)
                .err()
                .expect("short tx hash must fail");
            assert!(matches!(err, EnclaveError::CrossCheck(_)), "{err}");
            assert!(err.to_string().contains("evm_tx_hash"), "{err}");
        });
    }

    #[cfg(not(feature = "rgb-validation"))]
    #[test]
    fn rgb_source_fails_closed_on_a_build_without_the_validator() {
        let source = SourceNetwork::RgbSource(RgbSource {
            consignment_valid: true,
            asset_id: "rgb:test".into(),
            consignment: vec![1, 2, 3],
            consignment_hash: vec![0; 32],
            merkle_proofs: vec![],
            commission: 0,
            mint_ancestors: vec![],
        });
        with_ctx(&pinned(), |ctx| match validate_source(1, &source, ctx) {
            Err(EnclaveError::CrossCheck(msg)) => {
                assert!(msg.contains("rgb-validation"), "{msg}")
            }
            other => panic!("expected CrossCheck, got {:?}", other.map(|p| p.proof)),
        });
    }

    #[cfg(feature = "ccd")]
    #[test]
    fn ccd_source_dispatches_on_a_ccd_build() {
        let source = SourceNetwork::CcdSource(CcdSource {
            tx_hash: vec![0xCC; 32],
            commission: 1,
        });
        with_ctx(&pinned(), |ctx| {
            let out = validate_source(77, &source, ctx).unwrap();
            assert_eq!(out.proof.amount, 77);
            assert!(out.proof.operation_id.is_none());
        });
        let bad = SourceNetwork::CcdSource(CcdSource {
            tx_hash: vec![0xCC; 16],
            commission: 1,
        });
        with_ctx(&pinned(), |ctx| {
            assert!(matches!(
                validate_source(77, &bad, ctx),
                Err(EnclaveError::CrossCheck(_))
            ));
        });
    }

    #[cfg(not(feature = "ccd"))]
    #[test]
    fn ccd_source_is_refused_on_a_build_without_ccd() {
        let source = SourceNetwork::CcdSource(crate::proto::CcdSource {
            tx_hash: vec![0xCC; 32],
            commission: 1,
        });
        with_ctx(&pinned(), |ctx| match validate_source(77, &source, ctx) {
            Err(EnclaveError::InvalidRequest(msg)) => {
                assert!(msg.contains("not supported"), "{msg}")
            }
            other => panic!("expected InvalidRequest, got {:?}", other.map(|p| p.proof)),
        });
    }

    // ---- validate_destination dispatch ---------------------------------------

    #[test]
    fn evm_destination_dispatches_with_decoded_calldata_and_no_rgb_seals() {
        with_ctx(&pinned(), |ctx| {
            let out = validate_destination(1_000, 0, &evm_destination(1_000), ctx).unwrap();
            assert_eq!(out.proof.amount, 1_000);
            assert!(out.proof.operation_id.is_none());
            assert!(out.rgb_recipient_seals.is_empty());
            let params = out.evm_funds_out.expect("pools route decodes its params");
            assert_eq!(params.amount, alloy_primitives::U256::from(1_000u64));
            assert_eq!(params.recipient.into_array(), [0x22; 20]);
        });
    }

    #[test]
    fn evm_destination_rejects_an_unknown_selector_at_dispatch() {
        let mut bad = evm_destination(1_000);
        if let DestinationNetwork::EvmDestination(d) = &mut bad {
            d.call_data[0] ^= 0xff;
        }
        with_ctx(&pinned(), |ctx| {
            let err = validate_destination(1_000, 0, &bad, ctx)
                .err()
                .expect("unknown selector must fail");
            assert!(matches!(err, EnclaveError::CrossCheck(_)), "{err}");
            assert!(err.to_string().contains("selector"), "{err}");
        });
    }

    #[test]
    fn evm_destination_ignores_source_commission_in_its_proof() {
        // The commission argument only feeds the RGB destination sum.
        with_ctx(&pinned(), |ctx| {
            let a = validate_destination(1_000, 0, &evm_destination(1_000), ctx).unwrap();
            let b = validate_destination(1_000, 999, &evm_destination(1_000), ctx).unwrap();
            assert_eq!(a.proof, b.proof);
        });
    }

    #[cfg(all(not(feature = "rgb-validation"), not(feature = "dev-mode")))]
    #[test]
    fn rgb_destination_without_the_validator_sums_wire_amount_and_commission() {
        with_ctx(&pinned(), |ctx| {
            let out =
                validate_destination(0, 25, &rgb_destination(minimal_psbt(), 100), ctx).unwrap();
            assert_eq!(out.proof.amount, 125);
            assert!(out.proof.operation_id.is_none());
            assert!(out.evm_funds_out.is_none());
            assert!(out.rgb_recipient_seals.is_empty());
        });
    }

    #[cfg(all(not(feature = "rgb-validation"), not(feature = "dev-mode")))]
    #[test]
    fn rgb_destination_amount_plus_commission_overflow_is_rejected() {
        with_ctx(&pinned(), |ctx| {
            match validate_destination(0, 1, &rgb_destination(minimal_psbt(), u64::MAX), ctx) {
                Err(EnclaveError::CrossCheck(msg)) => assert!(msg.contains("overflow"), "{msg}"),
                other => panic!("expected CrossCheck, got {:?}", other.map(|p| p.proof)),
            }
            // Exactly at the ceiling is fine.
            let out = validate_destination(0, 0, &rgb_destination(minimal_psbt(), u64::MAX), ctx)
                .unwrap();
            assert_eq!(out.proof.amount, u64::MAX);
        });
    }

    #[cfg(not(feature = "dev-mode"))]
    #[test]
    fn rgb_destination_with_malformed_psbt_bytes_is_rejected_before_any_sum() {
        with_ctx(&pinned(), |ctx| {
            for bytes in [Vec::new(), b"psbt".to_vec(), vec![0xff; 40]] {
                let r = validate_destination(0, 0, &rgb_destination(bytes.clone(), 1), ctx);
                assert!(r.is_err(), "{} bytes must be rejected", bytes.len());
            }
        });
    }

    // ---- route pairing ---------------------------------------------------------

    #[test]
    fn route_proofs_evm_to_evm_is_unsupported() {
        let p = RouteProof {
            amount: 1,
            operation_id: None,
        };
        let err = validate_route_proofs(&evm_source(32), &evm_destination(1), &p, &p).unwrap_err();
        assert!(matches!(err, EnclaveError::InvalidRequest(_)), "{err}");
    }

    #[cfg(feature = "ccd")]
    #[test]
    fn route_proofs_ccd_to_rgb_is_unsupported() {
        let p = RouteProof {
            amount: 1,
            operation_id: None,
        };
        let ccd = SourceNetwork::CcdSource(CcdSource {
            tx_hash: vec![0xCC; 32],
            commission: 0,
        });
        let err =
            validate_route_proofs(&ccd, &rgb_destination(minimal_psbt(), 1), &p, &p).unwrap_err();
        assert!(matches!(err, EnclaveError::InvalidRequest(_)), "{err}");
    }

    #[test]
    fn route_proof_equality_covers_both_fields() {
        let a = RouteProof {
            amount: 1,
            operation_id: Some("x".into()),
        };
        assert_eq!(a, a.clone());
        assert_ne!(
            a,
            RouteProof {
                amount: 2,
                operation_id: Some("x".into())
            }
        );
        assert_ne!(
            a,
            RouteProof {
                amount: 1,
                operation_id: None
            }
        );
    }
}
