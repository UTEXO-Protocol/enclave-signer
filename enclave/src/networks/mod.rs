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
    #[cfg(feature = "rgb-validation")]
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
                #[cfg(feature = "rgb-validation")]
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
            let destination_amount = destination.psbt_output_amount;
            #[cfg(all(feature = "rgb-validation", feature = "dev-mode"))]
            let rgb_recipient_seals: Vec<String> = Vec::new();

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
                #[cfg(feature = "rgb-validation")]
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
