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
/// The older shapes `0xccddb768` and `0xdc771390` (before `sourceBurnTxId`,
/// bridge PR #152) fail closed at the whitelist. Thus a half-migrated backend
/// cannot get a signature.
#[cfg(rgb_to_evm)]
pub const FUNDS_OUT_SELECTOR_POOLS: [u8; 4] = [0x34, 0x02, 0x76, 0xaa];

/// `keccak256("lzFundsOut(uint256,uint256,uint256,uint256,string,bytes,bytes,uint32,bytes32,uint256,bytes,bytes32)")[0..4]`.
///
/// Enclave wire format for `MultisigProxy.lzFundsOutCall`, with individual
/// params and no struct. The selector identifies this release path in the
/// allowlist and selects the `TeeLzFundsOut` digest.
#[cfg(rgb_to_evm)]
pub const LZ_FUNDS_OUT_SELECTOR: [u8; 4] = lzFundsOutCall::SELECTOR;

/// Chain id of the RGB network: `networks.IDUtexo` in bridge-utexo and the
/// `96 -> <evm>` routes that `DeployAll` registers. It is a protocol constant,
/// so code pins it and PCR0 measures it.
///
/// The Router and CommissionManager select the verifier, settlement module and
/// commission rate by `(sourceChainId, destinationChainId)`. A forged value
/// sends an RGB release through a foreign verifier or rate.
/// [`validate_rgb_source_identity`] enforces it on both release routes.
#[cfg(rgb_to_evm)]
pub const RGB_SOURCE_CHAIN_ID: u64 = 96;

/// Maximum `call_data` length. A valid `fundsOut` call is a few hundred bytes.
/// More than 64 KiB is malformed or a work-amplification attempt. PCR-attested.
#[cfg(rgb_to_evm)]
pub const MAX_FUNDS_OUT_CALL_DATA_LEN: usize = 64 * 1024;

#[cfg(rgb_to_evm)]
const ALLOWED_SELECTORS: &[[u8; 4]] = &[FUNDS_OUT_SELECTOR_POOLS, LZ_FUNDS_OUT_SELECTOR];

sol! {
    /// Mirrors `IBridge.FundsOutParams` (in IBridge.sol). Field order fixes
    /// both the ABI decode here and the `TeeFundsOut` struct hash in
    /// [`super::signing::funds_out_digest`].
    ///
    /// `sourceBurnTxId` (bridge PR #152) is the RGB OpId of the burn transition.
    /// It is the only field that identifies the settled burn. The Bridge hashes
    /// it into `burnId` but cannot verify it. The enclave binds it to the
    /// validated consignment in
    /// [`super::crosscheck::validate_funds_out_source_burn_tx_id`].
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

    /// Enclave wire format only. It never goes on chain because the proxy takes
    /// the struct directly. Thus the protos carry an opaque `call_data` blob.
    function fundsOut(FundsOutParams params);

    /// Enclave wire format of `IMultisigProxy.LzFundsOutParams`, as individual
    /// params. The selector selects the `TeeLzFundsOut` digest in
    /// [`super::signing::lz_funds_out_digest`].
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

/// Validates only the source-EVM fields that the listener reports.
///
/// The destination and route validators own the destination payload and the
/// cross-network amount check.
#[cfg(evm_to_rgb)]
pub fn validate_source(amount: u64, source: &EvmSource) -> Result<RouteProof> {
    if source.tx_hash.len() != TX_HASH_LEN {
        return Err(EnclaveError::CrossCheck(format!(
            "evm_tx_hash must be {TX_HASH_LEN} bytes, got {}",
            source.tx_hash.len()
        )));
    }

    // Do not trust the listener `event_valid` / `event_finalized` flags. Any
    // caller can set them. Validity and finality come from
    // `networks::evm::events::verify_funds_in_event` in `handle_sign`.

    Ok(RouteProof {
        amount,
        operation_id: None,
    })
}

/// The release calldata fields that identify the settled burn and its payout.
/// Both `fundsOut` and `lzFundsOut` carry them, so every burn bind runs on both
/// routes (#264). The handler binds the source fields to the request's source
/// network and recomputes `burnId`.
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
    /// Final payee as 32 bytes. `fundsOut`: `recipient`, left-padded.
    /// `lzFundsOut`: the LayerZero `recipient`.
    pub recipient: [u8; 32],
    /// Calldata `proof`.
    pub proof: Vec<u8>,
}

impl ReleaseIdentity {
    /// The identity of a pools-route `fundsOut`.
    pub fn from_funds_out(params: &FundsOutParams) -> Self {
        let mut recipient = [0u8; 32];
        recipient[12..].copy_from_slice(params.recipient.as_slice());
        Self {
            burn_id: params.burnId,
            amount: params.amount,
            source_chain_id: params.sourceChainId,
            source_address: params.sourceAddress.clone(),
            settlement_data: params.settlementData.to_vec(),
            source_burn_tx_id: params.sourceBurnTxId.0,
            recipient,
            proof: params.proof.to_vec(),
        }
    }

    /// The identity of a LayerZero-route `lzFundsOut`.
    pub fn from_lz_funds_out(call: &lzFundsOutCall) -> Self {
        Self {
            burn_id: call.burnId,
            amount: call.amount,
            source_chain_id: call.sourceChainId,
            source_address: call.sourceAddress.clone(),
            settlement_data: call.settlementData.to_vec(),
            source_burn_tx_id: call.sourceBurnTxId.0,
            recipient: call.recipient.0,
            proof: call.proof.to_vec(),
        }
    }
}

/// `Bridge.BURN_TYPEHASH` preimage, verbatim from `Bridge.sol` (bridge PRs
/// #152 and #155). `recipient`, `proof` and `destinationChainId` are absent
/// by design: the key is shared with `rebalanceLiquidity`.
#[cfg(rgb_to_evm)]
const BURN_TYPEHASH_STR: &str = "UtexoBurnId(address bridge,uint256 chainId,address token,\
     uint256 amount,uint256 sourceChainId,bytes32 sourceAddressHash,\
     bytes32 settlementDataHash,bytes32 sourceBurnTxId)";

/// Recomputes `burnId` exactly as `Bridge._deriveBurnIdFromFields` does:
///
/// ```text
/// keccak256(abi.encode(BURN_TYPEHASH, bridge, chainId, token, amount,
///     sourceChainId, keccak256(sourceAddress), keccak256(settlementData),
///     sourceBurnTxId))
/// ```
///
/// `bridge` is `address(this)` in the Bridge: the pinned `FUNDS_IN_CONTRACT`
/// that emits `BridgeFundsIn`. `chainId` is the pinned `EVM_CHAIN_ID`. `token`
/// is the pinned `TOKEN_CONTRACT`. All nine words are static, so `abi.encode`
/// is concatenation.
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

/// Refuses a release whose `burnId` is not the one the Bridge derives.
///
/// The contract does the same check (`InvalidBurnId`), so this adds no
/// authority. It fails at sign time with the expected value, not on chain.
/// Both routes. Skipped while `TOKEN_CONTRACT` is not pinned (dev builds). A
/// production policy cannot boot without it
/// ([`crate::policy::ProductionPolicy::check_invariants`]).
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

/// Binds the source fields of a release to an RGB source, on both routes.
///
/// - `sourceChainId` MUST be [`RGB_SOURCE_CHAIN_ID`]. It selects the
///   verifier, settlement module and commission rate.
/// - `sourceAddress` MUST be empty. RGB has no source address
///   (`RGBVerifier.UnexpectedSourceAddress`, bridge PR #152). The field is
///   hashed into `burnId`, so another value gives one burn a second replay key.
///
/// The sign handler calls it only for an RGB source. A CCD-sourced release
/// names its own chain.
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

/// Validates only the destination-EVM fields.
///
/// The source validator owns the source proofs (RGB consignments, assets,
/// amounts, SPV). The handler checks the returned [`ReleaseIdentity`]: the
/// source fields against the source network, and `burnId` against the pinned
/// Bridge, chain id and token.
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
    // Reject oversize calldata before any decode or signing.
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
    // Decode once. Later stages use the typed result. The LayerZero route gives
    // no `FundsOutParams`, so `signing::lz_funds_out_digest` decodes it again.
    // `destinationChainId` means different things on the two routes, so
    // `is_entrypoint_route` selects the check below.
    let is_entrypoint_route = selector == LZ_FUNDS_OUT_SELECTOR;
    // `lz_release` is required on the LayerZero route and refused on the
    // direct route (F05-NEW-AF-12). The signer then routes on `params` only.
    match (is_entrypoint_route, destination.lz_release.is_some()) {
        (true, false) => {
            return Err(EnclaveError::CrossCheck(
                "lzFundsOut calldata requires lz_release".into(),
            ))
        }
        (false, true) => {
            return Err(EnclaveError::CrossCheck(
                "lz_release is only valid with lzFundsOut calldata".into(),
            ))
        }
        _ => {}
    }
    let (proof, params, calldata_destination_chain_id, release) = if is_entrypoint_route {
        let decoded = decode_lz_funds_out_params(&destination.call_data)?;
        let proof = lz_route_proof_from_params(&decoded)?;
        let chain_id = decoded.destinationChainId;
        let release = ReleaseIdentity::from_lz_funds_out(&decoded);
        (proof, None, chain_id, release)
    } else {
        let params = decode_funds_out_params(&destination.call_data)?;
        let proof = route_proof_from_params(&params)?;
        let chain_id = params.destinationChainId;
        let release = ReleaseIdentity::from_funds_out(&params);
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
    // Calldata `destinationChainId` is not the request `chain_id` above, which
    // sets only the EIP-712 domain.
    //
    // A direct pools payout settles on the execution chain, so it must equal
    // the pin. An entrypoint (LayerZero) payout settles on a remote chain, so
    // it must be non-zero and not the pin. The `destination.chain_id` and
    // `proxy_contract` checks pin the execution chain on both routes.
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

/// Maps a decoded release into the route-neutral proof.
#[cfg(rgb_to_evm)]
fn route_proof_from_params(params: &FundsOutParams) -> Result<RouteProof> {
    let amount: u64 = params
        .amount
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("fundsOut amount exceeds u64 range".into()))?;

    Ok(RouteProof {
        amount,
        // `None`: the handler binds burn identity with `validate_burn_id` and
        // the `sourceBurnTxId` OpId bind.
        operation_id: None,
    })
}

/// Decodes a `fundsOut` calldata blob and enforces canonical encoding. The
/// signing path also uses it to rebuild the `TeeFundsOut` struct hash.
///
/// The canonical check is here, not in the validator. A legacy flat body with
/// a zero `recipient` decodes as a tuple, and only the re-encode catches it.
/// In the validator, the check would depend on caller order.
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

/// Decodes an `lzFundsOut` calldata blob and enforces canonical encoding.
/// [`super::signing::lz_funds_out_digest`] also uses it for the
/// `TeeLzFundsOut` struct hash.
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

/// Maps a decoded LayerZero release into the route-neutral proof, as
/// [`route_proof_from_params`] does on the pools route.
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

#[cfg(all(test, evm_to_rgb))]
mod source_tests;
// Destination (`fundsOut`) checks: the RGB -> EVM direction.
#[cfg(all(test, rgb_to_evm))]
mod tests;
