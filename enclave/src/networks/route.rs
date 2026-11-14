//! Route-level validation: match a source network against a destination
//! network and prove the two describe the same bridge action.
//!
//! Dispatch only. Each arm sends the payload to the network module that owns
//! its checks.

#[cfg(feature = "rgb-validation")]
use std::sync::Mutex;

use super::{evm, rgb};
use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
use crate::networks::rgb::validation::RgbValidator;
use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};

/// Route-neutral proof that the source and destination validators return.
///
/// Each network module validates only its own payload. It maps the trusted
/// amount into this shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProof {
    pub amount: u64,
}

pub struct ValidationContext<'a> {
    pub bridge_config: &'a BridgeConfig,
    /// Consignment validation. The mint signer validates no consignment.
    #[cfg(all(feature = "rgb-validation", rgb_to_evm))]
    pub rgb_validator: Option<&'a RgbValidator>,
    #[cfg(feature = "rgb-validation")]
    pub header_chain: &'a Mutex<crate::networks::rgb::spv::HeaderChain>,
    /// The blocks that the SPV checks used, recorded under each check's lock.
    /// They are checked again before key use, so a reorg in the gap refuses
    /// instead of signing old chain state.
    #[cfg(feature = "rgb-validation")]
    pub chain_pins: &'a crate::networks::rgb::spv_crosscheck::ChainPins,
    /// Selects the colored key-path inputs the enclave signs, without holding
    /// keys across I/O. Fee sizing and the input binds use them. `None`
    /// fails the destination bind closed.
    #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
    pub psbt_fee_key_paths: Option<crate::networks::rgb::psbt_validation::FeeKeyPathResolver<'a>>,
    /// Binds the mint a PSBT commits to the request's EVM deposit (M6).
    /// `None` fails the mint closed.
    #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
    pub mint_binder: Option<crate::networks::rgb::psbt_validation::MintBinder<'a>>,
    /// M8 on the mint PSBT. A callback, as `psbt_fee_key_paths` is, so the
    /// keys are not held across I/O. `None` fails the mint closed.
    #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
    pub mint_sats: Option<crate::networks::rgb::psbt_validation::MintSatsCheck<'a>>,
    /// Binds each BFA mint anchor of a consignment to an EVM lock. With
    /// `None`, a consignment with a mint anchor is refused.
    #[cfg(all(feature = "rgb-validation", rgb_to_evm))]
    pub anchor_binder: Option<crate::networks::rgb::validation::AnchorBinder<'a>>,
    /// Reads the asset's reject list.
    #[cfg(all(feature = "rgb-validation", rgb_to_evm))]
    pub reject_list_reader: Option<crate::networks::rgb::validation::RejectListReader<'a>>,
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
    // An RGB source drops `amount`. The payout is the decoded calldata amount.
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
        // closed.
        #[cfg(rgb_to_evm)]
        SourceNetwork::RgbSource(source) => rgb::validate_source(source, ctx),
        #[cfg(not(evm_to_rgb))]
        SourceNetwork::EvmSource(_) => Err(EnclaveError::InvalidRequest(
            "source network not supported by this enclave".into(),
        )),
        #[cfg(not(rgb_to_evm))]
        SourceNetwork::RgbSource(_) => Err(EnclaveError::InvalidRequest(
            "source network not supported by this enclave".into(),
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
}

/// Dispatch destination-network validation to the owning network module.
pub fn validate_destination(
    amount: u64,
    source_commission: u64,
    destination: &DestinationNetwork,
    ctx: &ValidationContext<'_>,
) -> Result<DestinationProof> {
    // An EVM destination drops these. It checks only `calldata_amount`, against the calldata.
    #[cfg(not(evm_to_rgb))]
    let _ = (amount, source_commission);

    match destination {
        #[cfg(rgb_to_evm)]
        DestinationNetwork::EvmDestination(destination) => {
            let (proof, evm_funds_out, release) =
                evm::validation::validate_destination(destination, ctx)?;
            Ok(DestinationProof {
                proof,
                evm_funds_out,
                evm_release_identity: Some(release),
            })
        }
        #[cfg(evm_to_rgb)]
        DestinationNetwork::RgbDestination(destination) => {
            rgb::validate_destination(destination)?;

            // The destination amount is `mint.issued` from the fascia that the enclave proves.
            let destination_amount =
                rgb::validate_destination_anchor(destination, amount, source_commission, ctx)?;

            Ok(DestinationProof {
                proof: RouteProof {
                    amount: destination_amount
                        .checked_add(source_commission)
                        .ok_or_else(|| {
                            EnclaveError::CrossCheck(
                                "destination amount + source_commission overflow".into(),
                            )
                        })?,
                },
                evm_funds_out: None,
                evm_release_identity: None,
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
        _ => Err(EnclaveError::InvalidRequest(
            "unsupported source/destination network pair".into(),
        )),
    }
}

/// Both sides are bridge asset units, not sats. For EVM -> RGB,
/// `source_amount` is the request amount, which
/// `evm::events::verify_funds_in_event` binds to the `BridgeFundsIn` gross
/// `amount`. For RGB -> EVM, it is the consignment amount. An RGB
/// `destination_amount` is the fascia's `mint.issued` plus the source
/// commission, in RGB units issued 1:1 against the EVM token. The PSBT checks
/// in sats are in [`crate::networks::rgb::btc_crosscheck`].
fn validate_amount_covers_destination(source_amount: u64, destination_amount: u64) -> Result<()> {
    if source_amount < destination_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "amount mismatch: source amount ({source_amount}) < destination amount ({destination_amount})"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
