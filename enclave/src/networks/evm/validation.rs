#[cfg(rgb_to_evm)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(rgb_to_evm)]
use alloy_primitives::U256;
use alloy_sol_types::sol;
#[cfg(rgb_to_evm)]
use alloy_sol_types::SolCall;

use crate::error::{EnclaveError, Result};
#[cfg(rgb_to_evm)]
use crate::networks::evm::ADDRESS_LEN;
#[cfg(evm_to_rgb)]
use crate::networks::evm::HASH_LEN as TX_HASH_LEN;
use crate::networks::RouteProof;
#[cfg(rgb_to_evm)]
use crate::networks::ValidationContext;
#[cfg(rgb_to_evm)]
use crate::proto::EvmDestination;
#[cfg(evm_to_rgb)]
use crate::proto::EvmSource;

/// `keccak256("fundsOut((address,uint256,uint256,uint256,uint256,string,bytes,bytes))")[0..4]`.
///
/// Bundling the release fields into `FundsOutParams` moved the selector
/// `0xccddb768` -> `0xdc771390`. A flat body read as a tuple lands one word off
/// on every field, so the mismatch fails closed at the whitelist.
#[cfg(rgb_to_evm)]
pub const FUNDS_OUT_SELECTOR_POOLS: [u8; 4] = [0xdc, 0x77, 0x13, 0x90];

/// `keccak256("lzFundsOut(uint256,uint256,uint256,uint256,string,bytes,bytes,uint32,bytes32,uint256,bytes)")[0..4]`.
///
/// Enclave wire format for `MultisigProxy.lzFundsOutCall`: individual params,
/// no struct wrapper - analogous to `fundsOut` above. The selector distinguishes
/// the two release paths in the allowlist and routes to `TeeLzFundsOut` digest.
#[cfg(rgb_to_evm)]
pub const LZ_FUNDS_OUT_SELECTOR: [u8; 4] = lzFundsOutCall::SELECTOR;

/// Upper bound on `call_data` length. A legitimate `fundsOut` call is a few
/// hundred bytes, so anything past 64 KiB is malformed or a work-amplification
/// attempt. Compile-time and PCR-attested.
#[cfg(rgb_to_evm)]
pub const MAX_FUNDS_OUT_CALL_DATA_LEN: usize = 64 * 1024;

#[cfg(rgb_to_evm)]
const ALLOWED_SELECTORS: &[[u8; 4]] = &[FUNDS_OUT_SELECTOR_POOLS, LZ_FUNDS_OUT_SELECTOR];

sol! {
    /// Mirrors `IBridge.FundsOutParams` (IBridge.sol:193-202). Field order fixes
    /// both the ABI decode here and the `TeeFundsOut` struct hash in
    /// [`super::signing::funds_out_digest`].
    struct FundsOutParams {
        address recipient;
        uint256 amount;
        uint256 burnId;
        uint256 sourceChainId;
        uint256 destinationChainId;
        string sourceAddress;
        bytes proof;
        bytes settlementData;
    }

    /// Never reaches the chain - the proxy takes the struct directly. This is
    /// only the enclave's wire format, which is why the protos still carry an
    /// opaque `call_data` blob.
    function fundsOut(FundsOutParams params);

    /// Mirrors `IMultisigProxy.LzFundsOutParams` enclave wire format.
    /// Individual params (no struct wrapper) analogous to `fundsOut` above.
    /// Selector routes to `TeeLzFundsOut` digest in [`super::signing::lz_funds_out_digest`].
    function lzFundsOut(
        uint256 amount,
        uint256 burnId,
        uint256 sourceChainId,
        uint256 destinationChainId,
        string sourceAddress,
        bytes proof,
        bytes settlementData,
        uint32 dstEid,
        bytes32 recipient,
        uint256 minAmountLD,
        bytes extraOptions
    );
}

/// Validate only source-EVM concerns reported by the listener.
///
/// Destination-network payload shape and cross-network amount consistency
/// belong to the destination or route-level validator.
#[cfg(evm_to_rgb)]
pub fn validate_source(amount: u64, source: &EvmSource) -> Result<RouteProof> {
    if source.tx_hash.len() != TX_HASH_LEN {
        return Err(EnclaveError::CrossCheck(format!(
            "evm_tx_hash must be {TX_HASH_LEN} bytes, got {}",
            source.tx_hash.len()
        )));
    }

    // The listener-supplied `event_valid` / `event_finalized`
    // booleans are not trusted here - anyone reaching the enclave could set
    // both. Validity and finality come from
    // `networks::evm::events::verify_funds_in_event` in `handle_sign`. The
    // proto fields remain, ignored, until the listener stops sending them.

    Ok(RouteProof {
        amount,
        operation_id: None,
    })
}

/// Validate only destination-EVM concerns.
///
/// Source-network proof validation, including RGB consignments, assets,
/// amounts, and SPV proofs, belongs to the source network validator.
#[cfg(rgb_to_evm)]
pub fn validate_destination(
    destination: &EvmDestination,
    ctx: &ValidationContext<'_>,
) -> Result<(RouteProof, Option<FundsOutParams>)> {
    let bridge_config = ctx.bridge_config;

    if destination.call_data.len() < 4 {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need at least 4 bytes for selector, got {}",
            destination.call_data.len()
        )));
    }
    // Reject an oversize calldata before any offset extraction or signing.
    if destination.call_data.len() > MAX_FUNDS_OUT_CALL_DATA_LEN {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too large: {} bytes (max {})",
            destination.call_data.len(),
            MAX_FUNDS_OUT_CALL_DATA_LEN
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
    // Decoded once here; later stages take the typed result. The
    // LayerZero route has its own param shape and yields no `FundsOutParams`, so
    // `signing::lz_funds_out_digest` re-decodes it. Both routes surface
    // `destinationChainId` but mean different things by it, so
    // `is_entrypoint_route` picks the matching check below.
    let is_entrypoint_route = selector == LZ_FUNDS_OUT_SELECTOR;
    let (proof, params, calldata_destination_chain_id) = if is_entrypoint_route {
        let decoded = decode_lz_funds_out_params(&destination.call_data)?;
        let chain_id = decoded.destinationChainId;
        (lz_route_proof_from_params(&decoded)?, None, chain_id)
    } else {
        let params = decode_funds_out_params(&destination.call_data)?;
        let chain_id = params.destinationChainId;
        (route_proof_from_params(&params)?, Some(params), chain_id)
    };
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
            "bridge config unconfigured: set EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID \
             - refusing to sign in listener-trusting mode"
                .into(),
        ));
    }

    if bridge_config.chain_id != 0 && destination.chain_id != bridge_config.chain_id {
        return Err(EnclaveError::CrossCheck(format!(
            "chain_id mismatch: request {} != pinned {}",
            destination.chain_id, bridge_config.chain_id
        )));
    }
    // Distinct from the request-level `chain_id` above, which only drives the
    // EIP-712 domain.
    //
    // A direct pools payout settles on the very chain the tx runs on, so its
    // calldata destinationChainId must equal the attested pin. An entrypoint
    // (LayerZero) payout settles on a remote chain by design - Ethereum,
    // Polygon, Plasma, Tron - so pinning it the same way made every
    // cross-chain payout unsignable. The execution chain stays pinned
    // for both routes by the `destination.chain_id` and `proxy_contract`
    // checks above; the entrypoint route only has to name a real, remote
    // destination. Beyond that the field is bound on-chain: `Bridge.fundsOut`
    // folds it into the canonical `burnId` preimage and rejects a mismatch,
    // so it cannot be varied on its own.
    if is_entrypoint_route {
        if calldata_destination_chain_id.is_zero() {
            return Err(EnclaveError::CrossCheck(
                "calldata destinationChainId must be > 0".into(),
            ));
        }
        if bridge_config.chain_id != 0
            && calldata_destination_chain_id == U256::from(bridge_config.chain_id)
        {
            return Err(EnclaveError::CrossCheck(format!(
                "calldata destinationChainId {} equals the pinned execution chain - \
                 a local payout must use the direct fundsOut route",
                calldata_destination_chain_id
            )));
        }
    } else if bridge_config.chain_id != 0
        && calldata_destination_chain_id != U256::from(bridge_config.chain_id)
    {
        return Err(EnclaveError::CrossCheck(format!(
            "calldata destinationChainId mismatch: {} != pinned {}",
            calldata_destination_chain_id, bridge_config.chain_id
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

    Ok((proof, params))
}

/// Narrow a decoded release into the route-neutral proof.
#[cfg(rgb_to_evm)]
fn route_proof_from_params(params: &FundsOutParams) -> Result<RouteProof> {
    let amount: u64 = params
        .amount
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("fundsOut amount exceeds u64 range".into()))?;

    Ok(RouteProof {
        amount,
        // Still `None`. `settlementData` cites bridge-derived deposit ids, not
        // an RGB OpId, and `burnId` is not one either - so cross-network binding
        // cannot be recovered from the calldata alone.
        operation_id: None,
    })
}

/// Decode a `fundsOut` calldata blob into the release fields, enforcing the
/// canonical encoding. Shared with the signing path, which needs the fields to
/// rebuild the `TeeFundsOut` struct hash.
///
/// The canonicity check lives here rather than only in the validator: a legacy
/// flat body with a zero `recipient` decodes cleanly as a tuple, and only the
/// re-encode catches it. Deferring to `validate_destination` would make the
/// property depend on caller ordering.
#[cfg(rgb_to_evm)]
pub fn decode_funds_out_params(call_data: &[u8]) -> Result<FundsOutParams> {
    let decoded = fundsOutCall::abi_decode_validate(call_data)
        .map_err(|e| EnclaveError::CrossCheck(format!("invalid fundsOut calldata: {e}")))?;
    if decoded.abi_encode() != call_data {
        return Err(EnclaveError::CrossCheck(
            "non-canonical fundsOut calldata encoding: re-encoding the decoded call does not \
             reproduce the input bytes"
                .into(),
        ));
    }
    Ok(decoded.params)
}

/// Decode an `lzFundsOut` calldata blob, enforcing canonical encoding.
/// Shared with [`super::signing::lz_funds_out_digest`] which needs every
/// field to build the `TeeLzFundsOut` struct hash.
#[cfg(rgb_to_evm)]
pub fn decode_lz_funds_out_params(call_data: &[u8]) -> Result<lzFundsOutCall> {
    let decoded = lzFundsOutCall::abi_decode_validate(call_data)
        .map_err(|e| EnclaveError::CrossCheck(format!("invalid lzFundsOut calldata: {e}")))?;
    if decoded.abi_encode() != call_data {
        return Err(EnclaveError::CrossCheck(
            "non-canonical lzFundsOut calldata encoding: re-encoding does not reproduce input"
                .into(),
        ));
    }
    Ok(decoded)
}

/// Narrow a decoded LayerZero release into the route-neutral proof, mirroring
/// [`route_proof_from_params`] on the pools route.
#[cfg(rgb_to_evm)]
fn lz_route_proof_from_params(decoded: &lzFundsOutCall) -> Result<RouteProof> {
    let amount: u64 = decoded
        .amount
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("lzFundsOut amount exceeds u64 range".into()))?;
    Ok(RouteProof {
        amount,
        operation_id: None,
    })
}

// Destination (`fundsOut`) checks: the RGB -> EVM direction.
#[cfg(all(test, evm_to_rgb))]
mod source_tests;
#[cfg(all(test, rgb_to_evm))]
mod tests;
