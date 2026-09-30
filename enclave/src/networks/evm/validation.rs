#[cfg(rgb_to_evm)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(rgb_to_evm)]
use alloy_primitives::U256;
use alloy_sol_types::sol;
#[cfg(rgb_to_evm)]
use alloy_sol_types::SolCall;

#[cfg(rgb_to_evm)]
use crate::config::BridgeConfig;
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

/// `keccak256("fundsOut((address,uint256,uint256,uint256,uint256,string,bytes,bytes,bytes32))")[0..4]`.
///
/// Bundling the release fields into `FundsOutParams` moved the selector
/// `0xccddb768` -> `0xdc771390`; appending `sourceBurnTxId` (bridge PR #152)
/// moved it again to `0x340276aa`. A body in either older shape fails closed
/// at the whitelist, so a half-migrated backend cannot get a signature.
#[cfg(rgb_to_evm)]
pub const FUNDS_OUT_SELECTOR_POOLS: [u8; 4] = [0x34, 0x02, 0x76, 0xaa];

/// `keccak256("lzFundsOut(uint256,uint256,uint256,uint256,string,bytes,bytes,uint32,bytes32,uint256,bytes,bytes32)")[0..4]`.
///
/// Enclave wire format for `MultisigProxy.lzFundsOutCall`: individual params,
/// no struct wrapper - analogous to `fundsOut` above. The selector distinguishes
/// the two release paths in the allowlist and routes to `TeeLzFundsOut` digest.
#[cfg(rgb_to_evm)]
pub const LZ_FUNDS_OUT_SELECTOR: [u8; 4] = lzFundsOutCall::SELECTOR;

/// Chain id the bridge assigns to the RGB network: `networks.IDUtexo` in
/// bridge-utexo and the `96 -> <evm>` routes the contracts' `DeployAll`
/// registers. A protocol constant, not a deployment knob, so it is pinned in
/// code and measured into PCR0 with the rest of the image.
///
/// `sourceChainId` is not a label: the Router and CommissionManager key the
/// verifier, the settlement module and the commission rate on the
/// `(sourceChainId, destinationChainId)` pair, so a forged value steers an
/// RGB release through a foreign verifier or rate. Enforced by
/// [`validate_rgb_source_identity`] on both release routes.
#[cfg(rgb_to_evm)]
pub const RGB_SOURCE_CHAIN_ID: u64 = 96;

/// Upper bound on `call_data` length. A legitimate `fundsOut` call is a few
/// hundred bytes, so anything past 64 KiB is malformed or a work-amplification
/// attempt. Compile-time and PCR-attested.
#[cfg(rgb_to_evm)]
pub const MAX_FUNDS_OUT_CALL_DATA_LEN: usize = 64 * 1024;

#[cfg(rgb_to_evm)]
const ALLOWED_SELECTORS: &[[u8; 4]] = &[FUNDS_OUT_SELECTOR_POOLS, LZ_FUNDS_OUT_SELECTOR];

sol! {
    /// Mirrors `IBridge.FundsOutParams` (IBridge.sol:294-304). Field order fixes
    /// both the ABI decode here and the `TeeFundsOut` struct hash in
    /// [`super::signing::funds_out_digest`].
    ///
    /// `sourceBurnTxId` (bridge PR #152) is the RGB OpId of the burn transition:
    /// the only field that says WHICH burn is settled. The Bridge folds it into
    /// `burnId` but cannot verify it; the enclave binds it to the validated
    /// consignment in [`super::crosscheck::validate_funds_out_source_burn_tx_id`].
    struct FundsOutParams {
        address recipient;
        uint256 amount;
        uint256 burnId;
        uint256 sourceChainId;
        uint256 destinationChainId;
        string sourceAddress;
        bytes proof;
        bytes settlementData;
        bytes32 sourceBurnTxId;
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
        bytes extraOptions,
        bytes32 sourceBurnTxId
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

/// The fields of a release calldata that identify WHICH burn it settles,
/// decoded route-neutrally: both the direct `fundsOut` and the LayerZero
/// `lzFundsOut` shapes carry them. They are exactly the `burnId` preimage
/// inputs plus the `burnId` the backend derived, so the handler can bind the
/// source fields to the request's source network and recompute `burnId`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseIdentity {
    /// Calldata `burnId`, as the backend derived it.
    pub burn_id: alloy_primitives::U256,
    /// Calldata `amount`, full width.
    pub amount: alloy_primitives::U256,
    /// Calldata `sourceChainId`.
    pub source_chain_id: alloy_primitives::U256,
    /// Calldata `sourceAddress`.
    pub source_address: String,
    /// Calldata `settlementData`.
    pub settlement_data: Vec<u8>,
    /// Calldata `sourceBurnTxId`.
    pub source_burn_tx_id: [u8; 32],
}

/// `Bridge.BURN_TYPEHASH` preimage, verbatim from `Bridge.sol` (bridge PRs
/// #152 and #155). `recipient`, `proof` and `destinationChainId` are absent
/// by design: the key is shared with `rebalanceLiquidity`.
#[cfg(rgb_to_evm)]
const BURN_TYPEHASH_STR: &str = "UtexoBurnId(address bridge,uint256 chainId,address token,\
     uint256 amount,uint256 sourceChainId,bytes32 sourceAddressHash,\
     bytes32 settlementDataHash,bytes32 sourceBurnTxId)";

/// Recompute `burnId` exactly as `Bridge._deriveBurnIdFromFields` does:
///
/// ```text
/// keccak256(abi.encode(BURN_TYPEHASH, bridge, chainId, token, amount,
///     sourceChainId, keccak256(sourceAddress), keccak256(settlementData),
///     sourceBurnTxId))
/// ```
///
/// `bridge` is `address(this)` inside the Bridge, i.e. the pinned
/// `FUNDS_IN_CONTRACT` (the contract that emits `BridgeFundsIn`); `chainId`
/// the pinned `EVM_CHAIN_ID`; `token` the pinned `TOKEN_CONTRACT`. Nine static
/// words, so `abi.encode` is plain concatenation.
#[cfg(rgb_to_evm)]
pub fn expected_burn_id(cfg: &BridgeConfig, release: &ReleaseIdentity) -> U256 {
    use sha3::{Digest, Keccak256};

    let mut buf = Vec::with_capacity(32 * 9);
    buf.extend_from_slice(&Keccak256::digest(BURN_TYPEHASH_STR.as_bytes()));
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(&cfg.funds_in_contract);
    buf.extend_from_slice(&U256::from(cfg.chain_id).to_be_bytes::<32>());
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(&cfg.token_contract);
    buf.extend_from_slice(&release.amount.to_be_bytes::<32>());
    buf.extend_from_slice(&release.source_chain_id.to_be_bytes::<32>());
    buf.extend_from_slice(&Keccak256::digest(release.source_address.as_bytes()));
    buf.extend_from_slice(&Keccak256::digest(&release.settlement_data));
    buf.extend_from_slice(&release.source_burn_tx_id);
    U256::from_be_bytes::<32>(Keccak256::digest(&buf).into())
}

/// Refuse a release whose `burnId` is not the one the Bridge will derive.
///
/// The contract performs the same check and reverts (`InvalidBurnId`), so
/// this adds no authority; it fails at sign time, with the expected value in
/// the error, instead of on chain. Both routes. Skipped while
/// `TOKEN_CONTRACT` is unpinned (dev builds): a production policy cannot boot
/// without it ([`crate::policy::ProductionPolicy::check_invariants`]).
#[cfg(rgb_to_evm)]
pub fn validate_burn_id(cfg: &BridgeConfig, release: &ReleaseIdentity) -> Result<()> {
    if cfg.token_contract == [0u8; ADDRESS_LEN] {
        return Ok(());
    }
    let expected = expected_burn_id(cfg, release);
    if release.burn_id != expected {
        return Err(EnclaveError::CrossCheck(format!(
            "calldata burnId {:#x} != {:#x}, the burnId the Bridge derives from the bound fields \
             (FUNDS_IN_CONTRACT, EVM_CHAIN_ID, TOKEN_CONTRACT, amount, sourceChainId, \
             sourceAddress, settlementData, sourceBurnTxId) - refusing to sign a release the \
             contract would revert with InvalidBurnId",
            release.burn_id, expected
        )));
    }
    Ok(())
}

/// Bind a release's source fields to an RGB source, on either route.
///
/// - `sourceChainId` MUST be [`RGB_SOURCE_CHAIN_ID`]: it selects which
///   verifier, settlement module and commission rate judge the release.
/// - `sourceAddress` MUST be empty: RGB has no source-address concept
///   (`RGBVerifier.UnexpectedSourceAddress`, bridge PR #152) and the field is
///   hashed into `burnId`, so any other value would let one burn derive a
///   second replay key. Refused here so the enclave never attests such an
///   intent in the first place.
///
/// Called by the sign handler only when the request's source is an RGB
/// source; a CCD-sourced release names its own chain.
#[cfg(rgb_to_evm)]
pub fn validate_rgb_source_identity(source: &ReleaseIdentity) -> Result<()> {
    if source.source_chain_id != U256::from(RGB_SOURCE_CHAIN_ID) {
        return Err(EnclaveError::CrossCheck(format!(
            "calldata sourceChainId {} != RGB network id {RGB_SOURCE_CHAIN_ID}: the source chain \
             selects the verifier, settlement module and commission rate - refusing to sign an \
             RGB release under a foreign source chain",
            source.source_chain_id
        )));
    }
    if !source.source_address.is_empty() {
        return Err(EnclaveError::CrossCheck(format!(
            "calldata sourceAddress must be empty on an RGB route (RGB has no source-address \
             concept and it is hashed into burnId), got {:?}",
            source.source_address
        )));
    }
    Ok(())
}

/// Validate only destination-EVM concerns.
///
/// Source-network proof validation, including RGB consignments, assets,
/// amounts, and SPV proofs, belongs to the source network validator. The
/// returned [`ReleaseIdentity`] is decoded here but judged by the handler:
/// the source fields against the request's source network, the `burnId`
/// against the pinned Bridge, chain id and token.
#[cfg(rgb_to_evm)]
pub fn validate_destination(
    destination: &EvmDestination,
    ctx: &ValidationContext<'_>,
) -> Result<(RouteProof, Option<FundsOutParams>, ReleaseIdentity)> {
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
    let (proof, params, calldata_destination_chain_id, release) = if is_entrypoint_route {
        let decoded = decode_lz_funds_out_params(&destination.call_data)?;
        let proof = lz_route_proof_from_params(&decoded)?;
        let chain_id = decoded.destinationChainId;
        let release = ReleaseIdentity {
            burn_id: decoded.burnId,
            amount: decoded.amount,
            source_chain_id: decoded.sourceChainId,
            source_address: decoded.sourceAddress,
            settlement_data: decoded.settlementData.to_vec(),
            source_burn_tx_id: decoded.sourceBurnTxId.0,
        };
        (proof, None, chain_id, release)
    } else {
        let params = decode_funds_out_params(&destination.call_data)?;
        let proof = route_proof_from_params(&params)?;
        let chain_id = params.destinationChainId;
        let release = ReleaseIdentity {
            burn_id: params.burnId,
            amount: params.amount,
            source_chain_id: params.sourceChainId,
            source_address: params.sourceAddress.clone(),
            settlement_data: params.settlementData.to_vec(),
            source_burn_tx_id: params.sourceBurnTxId.0,
        };
        (proof, Some(params), chain_id, release)
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

    Ok((proof, params, release))
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
