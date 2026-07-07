use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};

use crate::error::{EnclaveError, Result};
use crate::networks::evm::{ADDRESS_LEN, HASH_LEN as TX_HASH_LEN};
use crate::networks::{RouteProof, ValidationContext};
use crate::proto::{EvmDestination, EvmSource};

/// `keccak256("fundsOut(address,uint256,uint256,uint256,uint256,string,bytes,bytes)")[0..4]`.
pub const FUNDS_OUT_SELECTOR_POOLS: [u8; 4] = [0xcc, 0xdd, 0xb7, 0x68];

const ALLOWED_SELECTORS: &[[u8; 4]] = &[FUNDS_OUT_SELECTOR_POOLS];

sol! {
    function fundsOut(
        address recipient,
        uint256 amount,
        uint256 burnId,
        uint256 sourceChainId,
        uint256 destinationChainId,
        string sourceAddress,
        bytes proof,
        bytes settlementData
    );
}

fn dev_mode_bypass() -> bool {
    cfg!(all(feature = "dev-mode", not(test)))
}

/// Validate only source-EVM concerns reported by the listener.
///
/// Destination-network payload shape and cross-network amount consistency
/// belong to the destination or route-level validator.
pub fn validate_source(amount: u64, source: &EvmSource) -> Result<RouteProof> {
    if dev_mode_bypass() {
        let _ = source;
        return Ok(RouteProof {
            amount,
            operation_id: None,
        });
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

    Ok(RouteProof {
        amount,
        operation_id: None,
    })
}

/// Validate only destination-EVM concerns.
///
/// Source-network proof validation, including RGB consignments, assets,
/// amounts, and SPV proofs, belongs to the source network validator.
pub fn validate_destination(
    destination: &EvmDestination,
    ctx: &ValidationContext<'_>,
) -> Result<RouteProof> {
    if dev_mode_bypass() {
        let _ = ctx;
        return Ok(RouteProof {
            amount: destination.calldata_amount,
            operation_id: None,
        });
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
    let proof = parse_proof_from_calldata(&destination.call_data)?;
    if proof.amount != destination.calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "calldata amount mismatch: decoded {} != declared {}",
            proof.amount, destination.calldata_amount
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

    Ok(proof)
}

fn parse_proof_from_calldata(call_data: &[u8]) -> Result<RouteProof> {
    let decoded = fundsOutCall::abi_decode(call_data)
        .map_err(|e| EnclaveError::CrossCheck(format!("invalid fundsOut calldata: {e}")))?;
    let amount: u64 = decoded
        .amount
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("fundsOut amount exceeds u64 range".into()))?;

    Ok(RouteProof {
        amount,
        operation_id: Some(u256_to_32_byte_hex(decoded.burnId)),
    })
}

fn u256_to_32_byte_hex(value: U256) -> String {
    hex::encode(value.to_be_bytes::<32>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BridgeConfig;
    use alloy_primitives::{Address, Bytes};
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

    fn funds_out_calldata(amount: u64, burn_id: u64) -> Vec<u8> {
        fundsOutCall {
            recipient: Address::from([0x22; ADDRESS_LEN]),
            amount: U256::from(amount),
            burnId: U256::from(burn_id),
            sourceChainId: U256::from(1u64),
            destinationChainId: U256::from(1u64),
            sourceAddress: String::new(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
        }
        .abi_encode()
    }

    fn destination() -> EvmDestination {
        EvmDestination {
            call_data: funds_out_calldata(1000, 7),
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
            let proof = validate_destination(&destination(), ctx).expect("valid destination");
            assert_eq!(proof.amount, 1000);
            assert_eq!(
                proof.operation_id.as_deref(),
                Some("0000000000000000000000000000000000000000000000000000000000000007")
            );
        });
    }

    #[test]
    fn valid_source_passes() {
        let proof = validate_source(1_000, &source()).expect("valid source");
        assert_eq!(proof.amount, 1_000);
        assert_eq!(proof.operation_id, None);
    }

    #[test]
    fn source_rejects_invalid_tx_hash_length() {
        let mut source = source();
        source.tx_hash.truncate(16);
        assert!(validate_source(1_000, &source)
            .unwrap_err()
            .to_string()
            .contains(&format!("evm_tx_hash must be {TX_HASH_LEN} bytes")));
    }

    #[test]
    fn source_rejects_invalid_event() {
        let mut source = source();
        source.event_valid = false;
        assert!(validate_source(1_000, &source)
            .unwrap_err()
            .to_string()
            .contains("EVM event not validated"));
    }

    #[test]
    fn source_rejects_unfinalized_event() {
        let mut source = source();
        source.event_finalized = false;
        assert!(validate_source(1_000, &source)
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

    #[test]
    fn rejects_calldata_amount_mismatch() {
        let mut destination = destination();
        destination.calldata_amount = 999;
        with_ctx(&config(), |ctx| {
            assert!(validate_destination(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("calldata amount mismatch"));
        });
    }

    #[test]
    fn rejects_uint256_amount_overflow() {
        let mut call = fundsOutCall {
            recipient: Address::from([0x22; ADDRESS_LEN]),
            amount: U256::from(u64::MAX) + U256::from(1u64),
            burnId: U256::from(7u64),
            sourceChainId: U256::from(1u64),
            destinationChainId: U256::from(1u64),
            sourceAddress: String::new(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
        }
        .abi_encode();
        call[..4].copy_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
        let mut destination = destination();
        destination.call_data = call;
        with_ctx(&config(), |ctx| {
            assert!(validate_destination(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("exceeds u64 range"));
        });
    }
}
