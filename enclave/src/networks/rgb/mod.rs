pub mod psbt_validation;
pub mod signing;
pub mod spv;
#[cfg(feature = "spv")]
pub mod spv_validation;
#[cfg(feature = "rgb-validation")]
pub mod validation;

#[cfg(not(feature = "rgb-validation"))]
use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::ValidationContext;
use crate::proto::{RgbDestination, RgbSource};
#[cfg(feature = "rgb-validation")]
use sha3::{Digest, Keccak256};

fn dev_mode_bypass() -> bool {
    cfg!(all(feature = "dev-mode", not(test)))
}

/// Dispatch RGB source validation to the implementation enabled for this build.
///
/// `mod.rs` owns module wiring only. Field-level checks, consignment
/// validation, asset binding, and SPV verification live in `validation.rs`
/// when `rgb-validation` is enabled.
pub fn validate_source(source: &RgbSource, ctx: &ValidationContext<'_>) -> Result<()> {
    if dev_mode_bypass() {
        let _ = source;
        let _ = ctx;
        return Ok(());
    }

    #[cfg(feature = "rgb-validation")]
    {
        validation::validate_source(source, ctx)
    }

    #[cfg(not(feature = "rgb-validation"))]
    {
        let _ = source;
        let _ = ctx;
        Err(EnclaveError::CrossCheck(
            "RGB source validation requires the enclave to be built with --features rgb-validation"
                .into(),
        ))
    }
}

/// Validate fields owned by an RGB destination before route-level validation.
pub fn validate_destination(
    destination: &RgbDestination,
    _ctx: &ValidationContext<'_>,
) -> Result<()> {
    #[cfg(not(feature = "dev-mode"))]
    {
        psbt_validation::validate_psbt_bytes(&destination.psbt_bytes)?;
    }
    #[cfg(feature = "dev-mode")]
    let _ = destination;

    Ok(())
}

#[cfg(feature = "rgb-validation")]
pub fn validate_destination_anchor(
    destination: &RgbDestination,
    source_amount: u64,
    source_commission: u64,
    ctx: &ValidationContext<'_>,
) -> Result<()> {
    use crate::error::EnclaveError;

    if destination.consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "send-RGB PSBT signing requires a consignment to bind the PSBT to the RGB transition"
                .into(),
        ));
    }
    if destination.consignment_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "consignment present but consignment_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(&destination.consignment);
    if computed[..] != destination.consignment_hash {
        return Err(EnclaveError::CrossCheck(
            "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
        ));
    }
    if destination.asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB destination asset_id is empty".into(),
        ));
    }

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT carries a consignment but the RGB validator is not configured".into(),
        )
    })?;
    let validated = validator.validate_consignment(&destination.consignment)?;

    if validated.contract_id != destination.asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: consignment has {} but RGB destination declares {}",
            validated.contract_id, destination.asset_id
        )));
    }
    if ctx.bridge_config.is_configured() {
        if ctx.bridge_config.rgb_asset_id.is_empty() {
            return Err(EnclaveError::CrossCheck(
                "bridge config pinned chain/contract but RGB_ASSET_ID is empty — \
                 set all three env vars or none"
                    .into(),
            ));
        }
        if validated.contract_id != ctx.bridge_config.rgb_asset_id {
            return Err(EnclaveError::CrossCheck(format!(
                "contract_id mismatch: consignment asset {} != pinned RGB_ASSET_ID {}",
                validated.contract_id, ctx.bridge_config.rgb_asset_id
            )));
        }
    }

    let psbt = bitcoin::psbt::Psbt::deserialize(&destination.psbt_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("psbt_bytes is not a valid PSBT: {e}")))?;
    psbt_validation::validate_psbt_anchors_transition(
        &psbt,
        &validated,
        source_amount,
        source_commission,
    )
}
