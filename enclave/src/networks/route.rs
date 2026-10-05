//! Route-level validation: match a source network against a destination
//! network and prove the two describe the same bridge action.
//!
//! Dispatch only. Each arm sends the payload to the network module that owns
//! its checks.

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

/// Route-neutral proof that the source and destination validators return.
///
/// Each network module validates only its own payload. It maps the trusted
/// amount and operation identity into this shape.
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
    /// The blocks that the SPV checks used, recorded under each check's lock.
    /// They are checked again before key use, so a reorg in the gap refuses
    /// instead of signing old chain state (F05-NEW-AF-08).
    #[cfg(feature = "rgb-validation")]
    pub chain_pins: &'a crate::networks::rgb::spv_crosscheck::ChainPins,
    /// Tells if a Bitcoin outpoint pays back to this enclave. The send-RGB
    /// recipient bind uses it to tell bridge change from a third-party payout.
    /// The outpoint can be on the PSBT or on an earlier transaction. See
    /// [`crate::networks::rgb::psbt_validation::SelfOwnedOutpoint`].
    ///
    /// It is a callback, so the key lock is not held across the network
    /// round-trips of consignment validation. `None` fails the bind closed.
    #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
    pub self_owned_psbt_outputs:
        Option<crate::networks::rgb::psbt_validation::SelfOwnedOutpoint<'a>>,
    /// Selects owned key-path inputs for fee sizing without holding keys across I/O.
    /// Without a resolver, disclosed scripts keep conservative script-path sizing.
    #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
    pub psbt_fee_key_paths: Option<crate::networks::rgb::psbt_validation::FeeKeyPathResolver<'a>>,
    /// EVM lock events that the enclave verified. RGB consensus gets them so
    /// the ether extension can check BFA mint amounts again. Empty when no
    /// side has a BFA consignment, and on builds without `bfa-validation`. A
    /// BFA consignment with an empty set is refused.
    #[cfg(feature = "rgb-validation")]
    pub bridge_events: &'a [rgbstd::vm::ether_extension::Event],
}

/// Result of source validation: the route proof and, for an RGB source on an
/// `rgb-validation` build, the validated consignment. The EVM destination
/// signer binds the `fundsOut` calldata to that consignment, so it must
/// outlive source validation. `None` for EVM sources.
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
        // On a build without the validator, `rgb::validate_source` fails
        // closed. Thus a `ccd`-only enclave refuses RGB sources.
        #[cfg(rgb_to_evm)]
        SourceNetwork::RgbSource(source) => rgb::validate_source(source, ctx),
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

/// Route proof and, for an EVM `fundsOut`, the calldata decoded once into a
/// typed intent for the later stages. `None` for RGB destinations.
pub struct DestinationProof {
    pub proof: RouteProof,
    pub evm_funds_out: Option<crate::networks::evm::validation::FundsOutParams>,
    /// The burn-identity fields of an EVM release calldata (both routes). The
    /// handler binds the source fields to the request's source network and
    /// recomputes `burnId`. `None` for RGB destinations.
    pub evm_release_identity: Option<crate::networks::evm::validation::ReleaseIdentity>,
    /// `utxob:...` seals of the send-RGB confidential recipient legs. They are
    /// bound to the deposit invoice after that receipt is verified. Empty for
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
            let (proof, evm_funds_out, release) =
                evm::validation::validate_destination(destination, ctx)?;
            Ok(DestinationProof {
                proof,
                evm_funds_out,
                evm_release_identity: Some(release),
                rgb_recipient_seals: Vec::new(),
            })
        }
        #[cfg(evm_to_rgb)]
        DestinationNetwork::RgbDestination(destination) => {
            rgb::validate_destination(destination, ctx)?;

            // The destination amount is the consignment recipient leg that the
            // enclave proves, not the unchecked host `psbt_output_amount`. Only
            // builds without that bind use the wire field. They run no
            // destination cross-checks.
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
                evm_release_identity: None,
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
            // The handler binds burn identity on both routes: `validate_burn_id`
            // and the `sourceBurnTxId` OpId bind.
        }
        // Concordium fundsIn -> EVM release. The listener validates the source.
        #[cfg(feature = "ccd")]
        (SourceNetwork::CcdSource(_), DestinationNetwork::EvmDestination(_)) => {
            validate_amount_covers_destination(source_proof.amount, destination_proof.amount)
        }
        _ => Err(EnclaveError::InvalidRequest(
            "unsupported source/destination network pair".into(),
        )),
    }
}

/// Both sides are bridge asset units, not sats. For EVM -> RGB,
/// `source_amount` is the `FundsIn` amount from
/// `evm::events::verify_funds_in_event`. For RGB -> EVM, it is the consignment
/// amount. An RGB
/// `destination_amount` is the consignment recipient leg in RGB units, issued
/// 1:1 against the EVM token. The PSBT checks in sats are in
/// [`crate::networks::rgb::btc_crosscheck`].
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
