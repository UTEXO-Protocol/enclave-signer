//! Asset-identity binding: tie a validated consignment's contract id to what
//! the listener declared and to the operator-pinned `RGB_ASSET_ID`.

use crate::config::BridgeConfig;
use crate::error::EnclaveError;
use crate::error::Result;

/// Which side of the bridge an asset binding is being made for. The two sides
/// differ only in how they treat a missing `RGB_ASSET_ID` pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetBindMode {
    /// RGB -> EVM. The pin is enforced only once the bridge config is otherwise
    /// configured; the fail-closed half for this direction lives in the EVM
    /// destination (`networks/evm/validation.rs`).
    Source,
    /// EVM -> RGB. An unpinned asset is refused outright: an unconfigured yet
    /// `rgb-validation`-enabled enclave must not sign in listener-trusting mode.
    Destination,
}

impl AssetBindMode {
    /// How the direction names itself in a declared-vs-validated rejection.
    fn declarer(self) -> &'static str {
        match self {
            Self::Source => "RGB source",
            Self::Destination => "RGB destination",
        }
    }
}

/// Bind a validated consignment's asset identity to what the listener declared
/// and to the operator-pinned `RGB_ASSET_ID`.
///
/// Three legs, all fail-closed: the validated id must be non-empty, must equal
/// the declared `asset_id`, and must equal the pin. `mode` carries the only
/// difference between the two directions - see [`AssetBindMode`].
///
/// Pure on purpose: this is the check standing between a colluding listener and
/// a foreign asset, so it is testable without a consignment, a resolver or a
/// header chain.
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
