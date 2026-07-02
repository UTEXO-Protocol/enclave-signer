use std::sync::Mutex;

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
#[cfg(feature = "rgb-validation")]
use crate::networks::rgb::validation::RgbValidator;
use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};

pub mod evm;
pub mod rgb;

pub struct ValidationContext<'a> {
    pub bridge_config: &'a BridgeConfig,
    #[cfg(feature = "rgb-validation")]
    pub rgb_validator: Option<&'a RgbValidator>,
    pub header_chain: &'a Mutex<crate::networks::rgb::spv::HeaderChain>,
}

/// Dispatch source-network validation to the owning network module.
pub fn validate_source(source: &SourceNetwork, ctx: &ValidationContext<'_>) -> Result<()> {
    match source {
        SourceNetwork::EvmSource(source) => evm::validation::validate_source(source),
        SourceNetwork::RgbSource(source) => rgb::validate_source(source, ctx),
    }
}

/// Dispatch destination-network validation to the owning network module.
pub fn validate_destination(
    amount: u64,
    source_commission: u64,
    destination: &DestinationNetwork,
    ctx: &ValidationContext<'_>,
) -> Result<()> {
    #[cfg(not(all(feature = "rgb-validation", not(feature = "dev-mode"))))]
    {
        let _ = amount;
        let _ = source_commission;
    }

    match destination {
        DestinationNetwork::EvmDestination(destination) => {
            evm::validation::validate_destination(destination, ctx)
        }
        DestinationNetwork::RgbDestination(destination) => {
            rgb::validate_destination(destination, ctx)?;

            #[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
            rgb::validate_destination_anchor(destination, amount, source_commission, ctx)?;

            Ok(())
        }
    }
}

/// Validate invariants that require both source and destination fields.
pub fn validate_route(
    amount: u64,
    source: &SourceNetwork,
    destination: &DestinationNetwork,
) -> Result<()> {
    match (source, destination) {
        (SourceNetwork::EvmSource(source), DestinationNetwork::RgbDestination(destination)) => {
            validate_amount_covers_destination(
                amount,
                destination.psbt_output_amount,
                source.commission,
            )
        }
        (SourceNetwork::RgbSource(_), DestinationNetwork::EvmDestination(destination)) => {
            validate_amount_covers_destination(
                amount,
                destination.calldata_amount,
                destination.calldata_commission,
            )
        }
        _ => Err(EnclaveError::InvalidRequest(
            "unsupported source/destination network pair".into(),
        )),
    }
}

fn validate_amount_covers_destination(
    source_amount: u64,
    destination_amount: u64,
    commission: u64,
) -> Result<()> {
    let required = destination_amount.checked_add(commission).ok_or_else(|| {
        EnclaveError::CrossCheck("destination_amount + commission overflow".into())
    })?;

    if source_amount < required {
        return Err(EnclaveError::CrossCheck(format!(
            "amount mismatch: source_amount ({source_amount}) < destination_amount ({destination_amount}) + commission ({commission})"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{EvmDestination, RgbSource};
    #[cfg(not(feature = "rgb-validation"))]
    use crate::proto::{EvmSource, RgbDestination};

    #[cfg(not(feature = "rgb-validation"))]
    fn evm_source(commission: u64) -> SourceNetwork {
        SourceNetwork::EvmSource(EvmSource {
            tx_hash: vec![0xAA; 32],
            event_valid: true,
            event_finalized: true,
            token: vec![0x11; 20],
            recipient: vec![0x22; 20],
            commission,
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

    fn evm_destination(destination_amount: u64, commission: u64) -> DestinationNetwork {
        DestinationNetwork::EvmDestination(EvmDestination {
            call_data: vec![0x00; 4],
            nonce: 1,
            deadline: 1,
            chain_id: 1,
            proxy_contract: vec![0x33; 20],
            calldata_amount: destination_amount,
            calldata_commission: commission,
        })
    }

    #[cfg(not(feature = "rgb-validation"))]
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

    #[test]
    #[cfg(not(feature = "rgb-validation"))]
    fn route_amount_accepts_exact_match_to_rgb_destination() {
        assert!(validate_route(110, &evm_source(20), &rgb_destination(90)).is_ok());
    }

    #[test]
    #[cfg(not(feature = "rgb-validation"))]
    fn route_amount_rejects_underfunded_rgb_destination() {
        let err = validate_route(100, &evm_source(20), &rgb_destination(90)).unwrap_err();
        assert!(err.to_string().contains("amount mismatch"));
    }

    #[test]
    fn route_amount_accepts_exact_match_to_evm_destination() {
        assert!(validate_route(110, &rgb_source(), &evm_destination(90, 20)).is_ok());
    }

    #[test]
    fn route_amount_rejects_underfunded_evm_destination() {
        let err = validate_route(100, &rgb_source(), &evm_destination(90, 20)).unwrap_err();
        assert!(err.to_string().contains("amount mismatch"));
    }
}
