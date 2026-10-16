//! Asset-identity binding: binds the validated contract id to the asset that
//! the listener declares and to the operator-pinned `RGB_ASSET_ID`.

use crate::config::BridgeConfig;
use crate::error::EnclaveError;
use crate::error::Result;

/// The bridge side of an asset binding. The sides differ only in how they
/// treat a missing `RGB_ASSET_ID` pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetBindMode {
    /// RGB -> EVM. The pin applies only when the bridge config is configured.
    /// The fail-closed check for this direction is in the EVM destination
    /// (`networks/evm/validation.rs`).
    Source,
    /// EVM -> RGB. An unpinned asset is always refused. An unconfigured enclave
    /// with `rgb-validation` must not trust the listener.
    Destination,
}

impl AssetBindMode {
    /// The direction name in a declared-vs-validated rejection.
    fn declarer(self) -> &'static str {
        match self {
            Self::Source => "RGB source",
            Self::Destination => "RGB destination",
        }
    }
}

/// Binds the validated asset identity to the declared asset and to the
/// operator-pinned `RGB_ASSET_ID`.
///
/// Three checks, all fail closed: the validated id must be non-empty, equal
/// the declared `asset_id`, and equal the pin. `mode` holds the only
/// difference between the directions (see [`AssetBindMode`]).
///
/// A pure function by design. It stops a colluding listener from using a
/// foreign asset, so tests need no consignment, resolver or header chain.
pub fn assert_asset_binding(
    validated_contract_id: &str,
    declared_asset_id: &str,
    cfg: &BridgeConfig,
    mode: AssetBindMode,
) -> Result<()> {
    if validated_contract_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "validated consignment has empty contract_id - cannot bind asset identity".into(),
        ));
    }
    if validated_contract_id != declared_asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: consignment has {} but {} declares {}",
            validated_contract_id,
            mode.declarer(),
            declared_asset_id
        )));
    }

    match mode {
        AssetBindMode::Source => {
            if !cfg.is_configured() {
                return Ok(());
            }
            if cfg.rgb_asset_id.is_empty() {
                return Err(EnclaveError::CrossCheck(
                    "bridge config pinned chain/contract but RGB_ASSET_ID is empty - \
                     set all three env vars or none"
                        .into(),
                ));
            }
        }
        AssetBindMode::Destination => {
            if cfg.rgb_asset_id.is_empty() {
                return Err(EnclaveError::CrossCheck(
                    "asset-identity pin missing: RGB_ASSET_ID is not configured - refusing to \
                     bind a send-RGB PSBT to an unpinned asset"
                        .into(),
                ));
            }
        }
    }

    if validated_contract_id != cfg.rgb_asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: consignment asset {} != pinned RGB_ASSET_ID {}",
            validated_contract_id, cfg.rgb_asset_id
        )));
    }
    Ok(())
}
