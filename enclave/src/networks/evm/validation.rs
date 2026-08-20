use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};

use crate::error::{EnclaveError, Result};
use crate::networks::evm::{ADDRESS_LEN, HASH_LEN as TX_HASH_LEN};
use crate::networks::{RouteProof, ValidationContext};
use crate::proto::{EvmDestination, EvmSource};

/// `keccak256("fundsOut((address,uint256,uint256,uint256,uint256,string,bytes,bytes))")[0..4]`.
///
/// Bundling the release fields into `FundsOutParams` moved the selector
/// `0xccddb768` -> `0xdc771390`. A flat-encoded body read as a tuple lands one
/// word off on every field, so the mismatch fails closed at the whitelist.
pub const FUNDS_OUT_SELECTOR_POOLS: [u8; 4] = [0xdc, 0x77, 0x13, 0x90];

/// `keccak256("lzFundsOut(uint256,uint256,uint256,uint256,string,bytes,bytes,uint32,bytes32,uint256,bytes)")[0..4]`.
///
/// Enclave wire format for `MultisigProxy.lzFundsOutCall`: individual params,
/// no struct wrapper — analogous to `fundsOut` above. The selector distinguishes
/// the two release paths in the allowlist and routes to `TeeLzFundsOut` digest.
pub const LZ_FUNDS_OUT_SELECTOR: [u8; 4] = lzFundsOutCall::SELECTOR;

/// Upper bound on `call_data` length. A legitimate `fundsOut` call is a few
/// hundred bytes; anything past 64 KiB is either malformed or an attempt to
/// blow up per-request work before any byte-level extraction or signing runs
/// (audit I-06 / #90). Compile-time so the posture is PCR-attested, not
/// host-tunable.
pub const MAX_FUNDS_OUT_CALL_DATA_LEN: usize = 64 * 1024;

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

    /// Never reaches the chain — the proxy takes the struct directly. This is
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

    // NOTE (audit M-06 / #51): the listener-supplied `event_valid` /
    // `event_finalized` booleans are NO LONGER trusted here - anyone reaching
    // the enclave could set both `true`. EVM-event validity and finality are
    // now established independently by the enclave itself in `handle_sign` via
    // `networks::evm::evm_event::verify_funds_in_event` (the `evm-rpc` feature:
    // fetches the FundsIn receipt and checks the operationId/amount/depth
    // against the pinned bridge contract). The proto fields remain (ignored)
    // until the listener stops sending them.

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
) -> Result<(RouteProof, Option<FundsOutParams>)> {
    if dev_mode_bypass() {
        let _ = ctx;
        return Ok((
            RouteProof {
                amount: destination.calldata_amount,
                operation_id: None,
            },
            None,
        ));
    }

    let bridge_config = ctx.bridge_config;

    if destination.call_data.len() < 4 {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need at least 4 bytes for selector, got {}",
            destination.call_data.len()
        )));
    }
    // Reject an oversize calldata before any offset extraction or signing
    // (audit I-06 / #90).
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
    // Decoded once here; every later stage takes the typed result (I-12 / #165).
    // The LayerZero route has its own param shape, so it yields no
    // `FundsOutParams` — `signing::lz_funds_out_digest` re-decodes the calldata
    // itself. Both routes surface `destinationChainId`, but they mean different
    // things by it, so `is_entrypoint_route` picks the matching check below.
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
    // Distinct from the request-level `chain_id` above, which only drives the
    // EIP-712 domain (I-12 / #165).
    //
    // A direct pools payout settles on the very chain the tx runs on, so its
    // calldata destinationChainId must equal the attested pin. An entrypoint
    // (LayerZero) payout settles on a remote chain by design - Ethereum,
    // Polygon, Plasma, Tron - so pinning it the same way made every
    // cross-chain payout unsignable (#200). The execution chain stays pinned
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
fn route_proof_from_params(params: &FundsOutParams) -> Result<RouteProof> {
    let amount: u64 = params
        .amount
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("fundsOut amount exceeds u64 range".into()))?;

    Ok(RouteProof {
        amount,
        // Still `None`. `settlementData` cites bridge-derived deposit ids, not
        // an RGB OpId, and `burnId` is not one either — so cross-network binding
        // cannot be recovered from the calldata alone.
        operation_id: None,
    })
}

/// Decode a `fundsOut` calldata blob into the release fields, enforcing the
/// canonical encoding. Shared with the signing path, which needs the fields to
/// rebuild the `TeeFundsOut` struct hash.
///
/// The canonicity check lives HERE, not only in the validator: a legacy flat
/// body with a zero `recipient` decodes cleanly as a tuple (the zero reads as a
/// head pointer aliasing the tuple onto the same words), and only the re-encode
/// catches it. Deferring to `validate_destination` would make this
/// caller-ordering — audit I-03 / Oxorio I-10.
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

#[cfg(test)]
mod tests {
    /// Drop the typed intent; these assertions cover the route proof.
    fn validate_dest(
        destination: &EvmDestination,
        ctx: &ValidationContext<'_>,
    ) -> Result<RouteProof> {
        super::validate_destination(destination, ctx).map(|(proof, _)| proof)
    }

    /// Keeps the canonical-encoding regressions expressed against raw bytes.
    fn parse_proof_from_calldata(call_data: &[u8]) -> Result<RouteProof> {
        route_proof_from_params(&decode_funds_out_params(call_data)?)
    }

    use super::*;
    use crate::config::BridgeConfig;
    use alloy_primitives::{Address, Bytes};
    #[cfg(feature = "spv")]
    use std::sync::Mutex;

    fn source() -> EvmSource {
        EvmSource {
            tx_hash: vec![0xAA; TX_HASH_LEN],
            event_valid: true,
            event_finalized: true,
            token: vec![0x11; ADDRESS_LEN],
            recipient: vec![0x22; ADDRESS_LEN],
            commission: 50,
            funds_in_operation_id: vec![0x33; 32],
        }
    }

    fn funds_out_calldata(amount: u64, burn_id: u64) -> Vec<u8> {
        fundsOutCall {
            params: FundsOutParams {
                recipient: Address::from([0x22; ADDRESS_LEN]),
                amount: U256::from(amount),
                burnId: U256::from(burn_id),
                sourceChainId: U256::from(1u64),
                destinationChainId: U256::from(1u64),
                sourceAddress: String::new(),
                proof: Bytes::new(),
                settlementData: Bytes::new(),
            },
        }
        .abi_encode()
    }

    /// `funds_out_calldata` with `destinationChainId` overridden.
    fn funds_out_calldata_for_chain(amount: u64, destination_chain_id: u64) -> Vec<u8> {
        fundsOutCall {
            params: FundsOutParams {
                recipient: Address::from([0x22; ADDRESS_LEN]),
                amount: U256::from(amount),
                burnId: U256::from(7u64),
                sourceChainId: U256::from(1u64),
                destinationChainId: U256::from(destination_chain_id),
                sourceAddress: String::new(),
                proof: Bytes::new(),
                settlementData: Bytes::new(),
            },
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
            lz_release: None,
        }
    }

    fn config() -> BridgeConfig {
        BridgeConfig {
            chain_id: 1,
            bridge_contract: [0xAA; ADDRESS_LEN],
            rgb_asset_id: "ignored-by-evm-validation".into(),
            gas_tx_allowed_to: None,
            ..Default::default()
        }
    }

    fn with_ctx<T>(config: &BridgeConfig, f: impl FnOnce(&ValidationContext<'_>) -> T) -> T {
        #[cfg(feature = "spv")]
        let header_chain = Mutex::new(crate::networks::rgb::spv::HeaderChain::new(
            crate::networks::rgb::spv::Network::Regtest,
            crate::networks::rgb::spv::checkpoint_for(crate::networks::rgb::spv::Network::Regtest),
        ));
        let ctx = ValidationContext {
            bridge_config: config,
            #[cfg(feature = "rgb-validation")]
            rgb_validator: None,
            #[cfg(feature = "spv")]
            header_chain: &header_chain,
            // EVM destinations never reach the send-RGB PSBT bind.
            #[cfg(feature = "rgb-validation")]
            self_owned_psbt_outputs: None,
        };
        f(&ctx)
    }

    #[test]
    fn valid_destination_passes() {
        with_ctx(&config(), |ctx| {
            let proof = validate_dest(&destination(), ctx).expect("valid destination");
            assert_eq!(proof.amount, 1000);
            assert_eq!(proof.operation_id, None);
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

    /// Audit M-06 / #51: the listener-supplied `event_valid` / `event_finalized`
    /// booleans are no longer read by `validate_source`, so flipping them to
    /// `false` does NOT change the outcome. EVM-event validity/finality is now
    /// established independently by `evm_event::verify_funds_in_event` in the
    /// handler (see that module's `issue_51_no_receipt_means_no_authorization`).
    #[test]
    fn source_ignores_listener_evm_booleans() {
        let mut source = source();
        source.event_valid = false;
        source.event_finalized = false;
        // Shape is still valid and the booleans are ignored now.
        assert!(validate_source(1_000, &source).is_ok());
    }

    #[test]
    fn rejects_unknown_selector() {
        let mut destination = destination();
        destination.call_data[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        with_ctx(&config(), |ctx| {
            let msg = validate_dest(&destination, ctx).unwrap_err().to_string();
            // The error must both name the failing predicate and echo the
            // offending selector so an operator can see WHAT was rejected.
            assert!(
                msg.contains("unexpected calldata selector") && msg.contains("deadbeef"),
                "expected selector rejection echoing the selector hex, got: {msg}"
            );
        });
    }

    #[test]
    fn rejects_calldata_shorter_than_selector() {
        let mut destination = destination();
        // 3 bytes can't carry a 4-byte selector.
        destination.call_data = vec![0x1a, 0xd8, 0x80];
        with_ctx(&config(), |ctx| {
            let err = validate_dest(&destination, ctx).unwrap_err();
            assert!(
                err.to_string().contains("call_data too short"),
                "expected too-short rejection, got: {err}"
            );
        });
    }

    #[test]
    fn rejects_calldata_over_size_cap() {
        // A maximally packed calldata must be rejected up-front (audit I-06 /
        // #90), before selector dispatch or any offset extraction. Start from
        // a valid fundsOut destination and pad the tail past the cap.
        let mut destination = destination();
        destination
            .call_data
            .resize(MAX_FUNDS_OUT_CALL_DATA_LEN + 1, 0u8);
        with_ctx(&config(), |ctx| {
            let err = validate_dest(&destination, ctx).unwrap_err();
            assert!(
                err.to_string().contains("call_data too large"),
                "expected too-large rejection, got: {err}"
            );
        });
    }

    #[test]
    fn accepts_calldata_at_size_cap() {
        // Exactly at the cap is allowed; the selector head is preserved so
        // dispatch still recognizes the fundsOut shape.
        let mut destination = destination();
        destination
            .call_data
            .resize(MAX_FUNDS_OUT_CALL_DATA_LEN, 0u8);
        destination.call_data[..4].copy_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
        // The zero-padded tail may still fail the later ABI decode; assert
        // only that it is NOT the size error.
        with_ctx(&config(), |ctx| {
            if let Err(e) = validate_dest(&destination, ctx) {
                assert!(
                    !e.to_string().contains("call_data too large"),
                    "calldata exactly at the cap must not trip the size check, got: {e}"
                );
            }
        });
    }

    #[test]
    fn rejects_chain_mismatch() {
        let mut destination = destination();
        destination.chain_id = 42;
        with_ctx(&config(), |ctx| {
            assert!(validate_dest(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("chain_id mismatch"));
        });
    }

    /// I-12 / #165: a release naming an unpinned chain is refused even when the
    /// request-level `chain_id` matches.
    #[test]
    fn rejects_calldata_destination_chain_id_mismatch() {
        let mut destination = destination();
        destination.call_data = funds_out_calldata_for_chain(1000, 999);
        with_ctx(&config(), |ctx| {
            let err = destination_or_err(&destination, ctx);
            assert!(
                err.contains("destinationChainId mismatch"),
                "expected destinationChainId rejection, got: {err}"
            );
        });
    }

    /// `lzFundsOut` calldata for an entrypoint-routed payout to a remote chain.
    fn lz_funds_out_calldata(amount: u64, destination_chain_id: u64) -> Vec<u8> {
        use alloy_primitives::FixedBytes;

        let mut recipient = [0u8; 32];
        recipient[31] = 0x05;

        lzFundsOutCall {
            amount: U256::from(amount),
            burnId: U256::from(7u64),
            sourceChainId: U256::from(1u64),
            destinationChainId: U256::from(destination_chain_id),
            sourceAddress: String::new(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
            dstEid: 30101u32,
            recipient: FixedBytes(recipient),
            minAmountLD: U256::from(amount),
            extraOptions: Bytes::new(),
        }
        .abi_encode()
    }

    fn lz_destination(destination_chain_id: u64) -> EvmDestination {
        EvmDestination {
            call_data: lz_funds_out_calldata(1000, destination_chain_id),
            ..destination()
        }
    }

    /// The entrypoint route settles on a remote chain, so its calldata
    /// destinationChainId must NOT be pinned to the execution chain: pinning it
    /// blocked every LayerZero payout (Ethereum, Polygon, Plasma, Tron).
    #[test]
    fn accepts_entrypoint_route_to_remote_chain() {
        with_ctx(&config(), |ctx| {
            let proof = validate_dest(&lz_destination(137), ctx)
                .expect("entrypoint payout to a remote chain must validate");
            assert_eq!(proof.amount, 1000);
        });
    }

    /// The entrypoint route still has to name a real destination.
    #[test]
    fn rejects_entrypoint_route_with_zero_destination_chain_id() {
        with_ctx(&config(), |ctx| {
            let err = destination_or_err(&lz_destination(0), ctx);
            assert!(
                err.contains("destinationChainId must be > 0"),
                "expected zero destinationChainId rejection, got: {err}"
            );
        });
    }

    /// A payout that lands back on the pinned execution chain is a direct
    /// payout; routing it through the entrypoint digest is refused.
    #[test]
    fn rejects_entrypoint_route_to_pinned_chain() {
        let config = config(); // pinned chain_id = 1
        with_ctx(&config, |ctx| {
            let err = destination_or_err(&lz_destination(1), ctx);
            assert!(
                err.contains("equals the pinned execution chain"),
                "expected local-payout rejection, got: {err}"
            );
        });
    }

    fn destination_or_err(destination: &EvmDestination, ctx: &ValidationContext<'_>) -> String {
        validate_dest(destination, ctx)
            .expect_err("must reject")
            .to_string()
    }

    #[test]
    fn rejects_zero_chain_id() {
        let mut destination = destination();
        destination.chain_id = 0;
        with_ctx(&config(), |ctx| {
            assert!(validate_dest(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("chain_id must be > 0"));
        });
    }

    #[test]
    fn rejects_proxy_contract_mismatch() {
        let mut destination = destination();
        destination.proxy_contract = vec![0xBB; ADDRESS_LEN]; // pinned is 0xAA
        with_ctx(&config(), |ctx| {
            let err = validate_dest(&destination, ctx).unwrap_err();
            assert!(
                err.to_string().contains("proxy_contract mismatch"),
                "got: {err}"
            );
        });
    }

    #[test]
    fn rejects_missing_proxy_contract() {
        let mut destination = destination();
        destination.proxy_contract = vec![];
        with_ctx(&config(), |ctx| {
            assert!(validate_dest(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains(&format!("proxy_contract must be {ADDRESS_LEN} bytes")));
        });
    }

    #[test]
    fn rejects_expired_deadline() {
        let mut destination = destination();
        destination.deadline = 1; // Unix timestamp 1 is long expired
        with_ctx(&config(), |ctx| {
            assert!(validate_dest(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("deadline expired"));
        });
    }

    #[test]
    fn ignores_rgb_config() {
        let mut config = config();
        config.rgb_asset_id.clear();
        with_ctx(&config, |ctx| {
            assert!(validate_dest(&destination(), ctx).is_ok());
        });
    }

    #[test]
    fn rejects_calldata_amount_mismatch() {
        let mut destination = destination();
        destination.calldata_amount = 999;
        with_ctx(&config(), |ctx| {
            assert!(validate_dest(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("calldata amount mismatch"));
        });
    }

    #[test]
    fn rejects_uint256_amount_overflow() {
        let mut call = fundsOutCall {
            params: FundsOutParams {
                recipient: Address::from([0x22; ADDRESS_LEN]),
                amount: U256::from(u64::MAX) + U256::from(1u64),
                burnId: U256::from(7u64),
                sourceChainId: U256::from(1u64),
                destinationChainId: U256::from(1u64),
                sourceAddress: String::new(),
                proof: Bytes::new(),
                settlementData: Bytes::new(),
            },
        }
        .abi_encode();
        call[..4].copy_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
        let mut destination = destination();
        destination.call_data = call;
        with_ctx(&config(), |ctx| {
            assert!(validate_dest(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("exceeds u64 range"));
        });
    }

    /// The hand-pinned selector constant and the alloy-derived ABI selector
    /// must never drift apart (#65): the whitelist gates on the constant while
    /// decode/encode use the `sol!` type.
    #[test]
    fn funds_out_selector_matches_abi_derived_selector() {
        assert_eq!(FUNDS_OUT_SELECTOR_POOLS, fundsOutCall::SELECTOR);
    }

    /// Canonical calldata with non-empty dynamic tails — the baseline the two
    /// non-canonical rejection tests below tamper with.
    fn funds_out_calldata_with_tails(amount: u64) -> Vec<u8> {
        fundsOutCall {
            params: FundsOutParams {
                recipient: Address::from([0x22; ADDRESS_LEN]),
                amount: U256::from(amount),
                burnId: U256::from(7u64),
                sourceChainId: U256::from(1u64),
                destinationChainId: U256::from(1u64),
                sourceAddress: "rgb-src".to_string(),
                proof: Bytes::from(vec![0xCC; 64]),
                settlementData: Bytes::from(vec![0xDD; 32]),
            },
        }
        .abi_encode()
    }

    #[test]
    fn accepts_canonical_calldata_with_dynamic_tails() {
        let cd = funds_out_calldata_with_tails(1_234);
        let proof = parse_proof_from_calldata(&cd).expect("canonical encoding must parse");
        assert_eq!(proof.amount, 1_234);
    }

    /// audit W-01 residual (#123): the ABI decoder accepts trailing junk
    /// after the last dynamic tail; the canonical re-encode check must not, so
    /// no unread bytes can ride along inside a signing request.
    #[test]
    fn rejects_calldata_with_trailing_junk() {
        let mut cd = funds_out_calldata_with_tails(1_234);
        cd.extend_from_slice(&[0u8; 32]);
        let err = parse_proof_from_calldata(&cd).unwrap_err();
        assert!(
            err.to_string().contains("non-canonical fundsOut calldata"),
            "expected canonical-encoding rejection, got: {err}"
        );
    }

    /// audit W-01 residual (#123): two dynamic-arg head words pointing at the
    /// same tail decode fine but are not a canonical encoding.
    #[test]
    fn rejects_calldata_with_overlapping_dynamic_tails() {
        let mut cd = funds_out_calldata_with_tails(1_234);
        // Offset words for `proof` (228..260) and `settlementData` (260..292),
        // counting the selector and the tuple head pointer. Both are measured
        // from the same tuple start, so copying one aliases the two tails.
        let proof_offset_word: [u8; 32] = cd[228..260].try_into().unwrap();
        cd[260..292].copy_from_slice(&proof_offset_word);
        let err = parse_proof_from_calldata(&cd).unwrap_err();
        assert!(
            err.to_string().contains("non-canonical fundsOut calldata"),
            "expected canonical-encoding rejection of overlapping tails, got: {err}"
        );
    }
}
