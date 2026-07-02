use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{EnclaveError, Result};
use crate::networks::evm::{ADDRESS_LEN, HASH_LEN as TX_HASH_LEN};
use crate::networks::ValidationContext;
use crate::proto::{EvmDestination, EvmSource};

/// `keccak256("fundsOut(address,uint256,uint256,uint256,uint256,string,bytes,bytes)")[0..4]`.
pub const FUNDS_OUT_SELECTOR_POOLS: [u8; 4] = [0xcc, 0xdd, 0xb7, 0x68];

const ALLOWED_SELECTORS: &[[u8; 4]] = &[FUNDS_OUT_SELECTOR_POOLS];

fn dev_mode_bypass() -> bool {
    cfg!(all(feature = "dev-mode", not(test)))
}

/// Validate only source-EVM concerns reported by the listener.
///
/// Destination-network payload shape and cross-network amount consistency
/// belong to the destination or route-level validator.
pub fn validate_source(source: &EvmSource) -> Result<()> {
    if dev_mode_bypass() {
        let _ = source;
        return Ok(());
    }

    if source.tx_hash.len() != TX_HASH_LEN {
        return Err(EnclaveError::CrossCheck(format!(
            "evm_tx_hash must be {TX_HASH_LEN} bytes, got {}",
            source.tx_hash.len()
        )));
    }
    if !source.event_valid {
        return Err(EnclaveError::CrossCheck(
            "EVM event not validated by Listener".into(),
        ));
    }
    if !source.event_finalized {
        return Err(EnclaveError::CrossCheck(
            "EVM event not yet finalized".into(),
        ));
    }

    Ok(())
}

/// Validate only destination-EVM concerns.
///
/// Source-network proof validation, including RGB consignments, assets,
/// amounts, and SPV proofs, belongs to the source network validator.
pub fn validate_destination(
    destination: &EvmDestination,
    ctx: &ValidationContext<'_>,
) -> Result<()> {
    if dev_mode_bypass() {
        let _ = destination;
        let _ = ctx;
        return Ok(());
    }

    let bridge_config = ctx.bridge_config;

    if destination.call_data.len() < 4 {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need at least 4 bytes for selector, got {}",
            destination.call_data.len()
        )));
    }

    let selector: [u8; 4] = destination.call_data[..4]
        .try_into()
        .expect("4-byte slice always converts");
    if !ALLOWED_SELECTORS.contains(&selector) {
        return Err(EnclaveError::CrossCheck(format!(
            "unexpected calldata selector 0x{}: not in fundsOut whitelist",
            hex::encode(selector)
        )));
    }

    if destination.chain_id == 0 {
        return Err(EnclaveError::CrossCheck("chain_id must be > 0".into()));
    }
    if destination.proxy_contract.len() != ADDRESS_LEN {
        return Err(EnclaveError::CrossCheck(format!(
            "proxy_contract must be {ADDRESS_LEN} bytes, got {}",
            destination.proxy_contract.len()
        )));
    }

    #[cfg(all(feature = "rgb-validation", not(test)))]
    if !bridge_config.is_configured() {
        return Err(EnclaveError::CrossCheck(
            "bridge config unconfigured: set EVM_CHAIN_ID / BRIDGE_CONTRACT / RGB_ASSET_ID \
             — refusing to sign in listener-trusting mode"
                .into(),
        ));
    }

    if bridge_config.chain_id != 0 && destination.chain_id != bridge_config.chain_id {
        return Err(EnclaveError::CrossCheck(format!(
            "chain_id mismatch: request {} != pinned {}",
            destination.chain_id, bridge_config.chain_id
        )));
    }
    if bridge_config.bridge_contract != [0u8; ADDRESS_LEN]
        && destination.proxy_contract.as_slice() != bridge_config.bridge_contract
    {
        return Err(EnclaveError::CrossCheck(format!(
            "proxy_contract mismatch: request {} != pinned {}",
            hex::encode(&destination.proxy_contract),
            hex::encode(bridge_config.bridge_contract)
        )));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::Internal(format!("system time error: {e}")))?
        .as_secs();
    if destination.deadline <= now {
        return Err(EnclaveError::CrossCheck("request deadline expired".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BridgeConfig;
    use std::sync::Mutex;

    fn source() -> EvmSource {
        EvmSource {
            tx_hash: vec![0xAA; TX_HASH_LEN],
            event_valid: true,
            event_finalized: true,
            token: vec![0x11; ADDRESS_LEN],
            recipient: vec![0x22; ADDRESS_LEN],
            commission: 50,
        }
    }

    fn destination() -> EvmDestination {
        let mut call_data = vec![0u8; 68];
        call_data[..4].copy_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
        EvmDestination {
            call_data,
            nonce: 1,
            deadline: u64::MAX,
            chain_id: 1,
            proxy_contract: vec![0xAA; ADDRESS_LEN],
            calldata_amount: 1000,
            calldata_commission: 0,
        }
    }

    fn config() -> BridgeConfig {
        BridgeConfig {
            chain_id: 1,
            bridge_contract: [0xAA; ADDRESS_LEN],
            rgb_asset_id: "ignored-by-evm-validation".into(),
        }
    }

    fn with_ctx<T>(config: &BridgeConfig, f: impl FnOnce(&ValidationContext<'_>) -> T) -> T {
        let header_chain = Mutex::new(crate::networks::rgb::spv::HeaderChain::new(
            crate::networks::rgb::spv::Network::Regtest,
            crate::networks::rgb::spv::checkpoint_for(crate::networks::rgb::spv::Network::Regtest),
        ));
        let ctx = ValidationContext {
            bridge_config: config,
            #[cfg(feature = "rgb-validation")]
            rgb_validator: None,
            header_chain: &header_chain,
        };
        f(&ctx)
    }

    #[test]
    fn valid_destination_passes() {
        with_ctx(&config(), |ctx| {
            assert!(validate_destination(&destination(), ctx).is_ok());
        });
    }

    #[test]
    fn valid_source_passes() {
        assert!(validate_source(&source()).is_ok());
    }

    #[test]
    fn source_rejects_invalid_tx_hash_length() {
        let mut source = source();
        source.tx_hash.truncate(16);
        assert!(validate_source(&source)
            .unwrap_err()
            .to_string()
            .contains(&format!("evm_tx_hash must be {TX_HASH_LEN} bytes")));
    }

    #[test]
    fn source_rejects_invalid_event() {
        let mut source = source();
        source.event_valid = false;
        assert!(validate_source(&source)
            .unwrap_err()
            .to_string()
            .contains("EVM event not validated"));
    }

    #[test]
    fn source_rejects_unfinalized_event() {
        let mut source = source();
        source.event_finalized = false;
        assert!(validate_source(&source)
            .unwrap_err()
            .to_string()
            .contains("not yet finalized"));
    }

    #[test]
    fn rejects_unknown_selector() {
        let mut destination = destination();
        destination.call_data[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        with_ctx(&config(), |ctx| {
            assert!(validate_destination(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("unexpected calldata selector"));
        });
    }

    #[test]
    fn rejects_chain_mismatch() {
        let mut destination = destination();
        destination.chain_id = 42;
        with_ctx(&config(), |ctx| {
            assert!(validate_destination(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("chain_id mismatch"));
        });
    }

    #[test]
    fn ignores_rgb_config() {
        let mut config = config();
        config.rgb_asset_id.clear();
        with_ctx(&config, |ctx| {
            assert!(validate_destination(&destination(), ctx).is_ok());
        });
    }
}
