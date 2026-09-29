//! Route-level validation: match a source network against a destination
//! network and prove the two describe the same bridge action.
//!
//! Dispatch only. Each arm hands the payload to the owning network module,
//! which is the one place that knows how to check it.

#[cfg(feature = "rgb-validation")]
use std::sync::Mutex;

#[cfg(feature = "ccd")]
use super::ccd;
use super::{evm, rgb};
use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
#[cfg(feature = "rgb-validation")]
use crate::networks::rgb::validation::RgbValidator;
use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};

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
    #[cfg(feature = "rgb-validation")]
    pub header_chain: &'a Mutex<crate::networks::rgb::spv::HeaderChain>,
    /// The blocks the SPV checks used. Each check records them under its own
    /// lock guard. Checked again just before the key is used, so a reorg in
    /// the gap refuses instead of signing old chain state (F05-NEW-AF-08).
    #[cfg(feature = "rgb-validation")]
    pub chain_pins: &'a crate::networks::rgb::spv_crosscheck::ChainPins,
    /// Resolves whether a Bitcoin outpoint pays back to this enclave.
    /// Required by the send-RGB per-output recipient bind to tell
    /// bridge change from a payout to a third party. The outpoint may sit on
    /// the PSBT being signed or on an earlier transaction - see
    /// [`crate::networks::rgb::psbt_validation::SelfOwnedOutpoint`].
    ///
    /// A callback, so the key lock is taken only for that resolution and never
    /// across consignment validation's network round-trips. `None` fails the
    /// bind closed.
    #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
    pub self_owned_psbt_outputs:
        Option<crate::networks::rgb::psbt_validation::SelfOwnedOutpoint<'a>>,
    /// Selects owned key-path inputs for fee sizing without holding keys across I/O.
    /// Without a resolver, disclosed scripts retain conservative script-path sizing.
    #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
    pub psbt_fee_key_paths: Option<crate::networks::rgb::psbt_validation::FeeKeyPathResolver<'a>>,
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
/// must outlive source validation. `None` for EVM sources.
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
    // Each direction reads only one of these.
    #[cfg(not(evm_to_rgb))]
    let _ = amount;
    #[cfg(not(rgb_to_evm))]
    let _ = ctx;

    match source {
        #[cfg(evm_to_rgb)]
        SourceNetwork::EvmSource(source) => Ok(SourceProof {
            proof: evm::validation::validate_source(amount, source)?,
            #[cfg(feature = "rgb-validation")]
            rgb_consignment: None,
        }),
        // RGB is always compiled; `rgb::validate_source` fails closed (with a
        // "requires --features rgb-validation" message) on a build that lacks
        // the validator, so a `ccd`-only enclave refuses RGB sources there.
        #[cfg(rgb_to_evm)]
        SourceNetwork::RgbSource(source) => rgb::validate_source(source, ctx),
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
/// destinations.
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
    // Only the RGB (mint) destination binds the amounts.
    #[cfg(not(evm_to_rgb))]
    let _ = (amount, source_commission);
    #[cfg(all(evm_to_rgb, not(feature = "rgb-validation")))]
    let _ = amount;

    match destination {
        #[cfg(rgb_to_evm)]
        DestinationNetwork::EvmDestination(destination) => {
            let (proof, evm_funds_out) = evm::validation::validate_destination(destination, ctx)?;
            Ok(DestinationProof {
                proof,
                evm_funds_out,
                rgb_recipient_seals: Vec::new(),
            })
        }
        #[cfg(evm_to_rgb)]
        DestinationNetwork::RgbDestination(destination) => {
            rgb::validate_destination(destination, ctx)?;

            // The destination amount is the consignment's recipient leg,
            // proven inside the enclave, not the unchecked
            // host-supplied `psbt_output_amount`. Only builds without that
            // binding fall back to the wire field, and they run no destination
            // cross-checks at all.
            #[cfg(feature = "rgb-validation")]
            let (destination_amount, rgb_recipient_seals) =
                rgb::validate_destination_anchor(destination, amount, source_commission, ctx)?;
            #[cfg(not(feature = "rgb-validation"))]
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
        #[allow(unreachable_patterns)]
        _ => Err(EnclaveError::InvalidRequest(
            "destination network not signed by this signer role".into(),
        )),
    }
}

/// Validate that source and destination proofs describe the same route action.
pub fn validate_route_proofs(
    source: &SourceNetwork,
    destination: &DestinationNetwork,
    source_proof: &RouteProof,
    destination_proof: &RouteProof,
) -> Result<()> {
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
/// `FundsIn` token amount verified by `evm::events::verify_funds_in_event`;
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
mod tests;
