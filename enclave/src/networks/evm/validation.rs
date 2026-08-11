use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
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

/// Upper bound on `call_data` length. A legitimate `fundsOut` call is a few
/// hundred bytes; anything past 64 KiB is either malformed or an attempt to
/// blow up per-request work before any byte-level extraction or signing runs
/// (audit I-06 / #90). Compile-time so the posture is PCR-attested, not
/// host-tunable.
pub const MAX_FUNDS_OUT_CALL_DATA_LEN: usize = 64 * 1024;

/// `keccak256("rebalanceLiquidity((uint256,uint256,uint256,uint256,string,string,bytes,bytes,bytes))")[0..4]`.
///
/// The credit leg of a scenario-A pool refill, submitted through
/// `MultisigProxy.rebalanceCall`. Distinct from `fundsOut` in both shape and
/// authorisation: a rebalance is **self-originated**, so there is no source
/// consignment to bind it to (see `server.rs::run_evm_destination_crosschecks`).
///
/// Derived from the `sol!` definition so it cannot drift from the decoder;
/// `rebalance_selector_matches_contract` pins it to the independently computed
/// value so the definition itself cannot drift unnoticed.
pub const REBALANCE_SELECTOR: [u8; 4] = rebalanceLiquidityCall::SELECTOR;

const ALLOWED_SELECTORS: &[[u8; 4]] = &[FUNDS_OUT_SELECTOR_POOLS, REBALANCE_SELECTOR];

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

    /// Mirrors `IBridge.RebalanceParams`. Field order fixes both the ABI decode
    /// here and the `TeeRebalance` struct hash in
    /// [`super::signing::rebalance_digest`].
    ///
    /// Two settlement blobs, not one: a rebalance debits one chain's bucket and
    /// credits another's, so it cites deposits on both sides.
    struct RebalanceParams {
        uint256 amount;
        uint256 burnId;
        uint256 sourceChainId;
        uint256 destinationChainId;
        string sourceAddress;
        string destinationAddress;
        bytes proof;
        bytes settlementDataOut;
        bytes settlementDataIn;
    }

    /// Never reaches the chain — the proxy takes the struct directly. This is
    /// only the enclave's wire format, which is why the protos still carry an
    /// opaque `call_data` blob.
    function fundsOut(FundsOutParams params);

    /// Same: the enclave's wire format for the rebalance calldata blob.
    function rebalanceLiquidity(RebalanceParams params);
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
    // Membership, not equality: one federation serves several Bridge
    // deployments on a chain (pools and mint/burn are separate pairs). Widening
    // the pin does not widen what a compromised host can reach - the request
    // still has to name an address the operator pinned, and the matched address
    // is what the rest of the request is bound to.
    if !bridge_config.bridge_contracts.is_empty()
        && !bridge_config.allows_proxy_contract(&destination.proxy_contract)
    {
        return Err(EnclaveError::CrossCheck(format!(
            "proxy_contract mismatch: request {} is not one of the pinned [{}]",
            hex::encode(&destination.proxy_contract),
            bridge_config
                .bridge_contracts
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>()
                .join(", ")
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
    // Canonical-encoding enforcement (audit W-01 residual, #123): the ABI
    // decoder is deliberately layout-permissive — overlapping or out-of-order
    // dynamic tails and trailing junk all decode fine (`abi_decode_validate`
    // only validates the decoded *values*). Re-encoding the decoded call and
    // requiring byte equality pins the input to the one canonical layout.
    //
    // The byte-level reason is gone (#168 removed the offset rewrite, and the
    // digest now commits to decoded fields). Kept anyway: it keeps the wire
    // format unambiguous and stops unread trailing data riding along.
    //
    // Selector-dispatched: the caller already rejected anything outside
    // ALLOWED_SELECTORS, so this matches the same set. A new selector added to
    // the whitelist without a decode arm here fails closed rather than being
    // read with the wrong struct.
    let amount = match call_data.get(..4) {
        Some(s) if s == FUNDS_OUT_SELECTOR_POOLS => decode_funds_out_params(call_data)?.amount,
        Some(s) if s == REBALANCE_SELECTOR => decode_rebalance_params(call_data)?.amount,
        _ => {
            return Err(EnclaveError::CrossCheck(
                "no decoder for this calldata selector".into(),
            ))
        }
    };
    let amount: u64 = amount
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("calldata amount exceeds u64 range".into()))?;

    Ok(RouteProof {
        amount,
        // Still `None`. `settlementData` cites bridge-derived deposit ids, not
        // an RGB OpId, and `burnId` is not one either — so cross-network binding
        // cannot be recovered from the calldata alone.
        operation_id: None,
    })
}

/// Decode a `rebalanceLiquidity` calldata blob, enforcing the canonical
/// encoding for the same reason [`decode_funds_out_params`] does.
pub fn decode_rebalance_params(call_data: &[u8]) -> Result<RebalanceParams> {
    let decoded = rebalanceLiquidityCall::abi_decode_validate(call_data).map_err(|e| {
        EnclaveError::CrossCheck(format!("invalid rebalanceLiquidity calldata: {e}"))
    })?;
    if decoded.abi_encode() != call_data {
        return Err(EnclaveError::CrossCheck(
            "non-canonical rebalanceLiquidity calldata encoding: re-encoding the decoded call \
             does not reproduce the input bytes"
                .into(),
        ));
    }
    Ok(decoded.params)
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
            bridge_contracts: vec![[0xAA; ADDRESS_LEN]],
            rgb_asset_id: "ignored-by-evm-validation".into(),
            gas_tx_allowed_to: None,
            ..Default::default()
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
            let msg = validate_destination(&destination, ctx)
                .unwrap_err()
                .to_string();
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
            let err = validate_destination(&destination, ctx).unwrap_err();
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
            let err = validate_destination(&destination, ctx).unwrap_err();
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
            if let Err(e) = validate_destination(&destination, ctx) {
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
            assert!(validate_destination(&destination, ctx)
                .unwrap_err()
                .to_string()
                .contains("chain_id mismatch"));
        });
    }

    #[test]
    fn rejects_zero_chain_id() {
        let mut destination = destination();
        destination.chain_id = 0;
        with_ctx(&config(), |ctx| {
            assert!(validate_destination(&destination, ctx)
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
            let err = validate_destination(&destination, ctx).unwrap_err();
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
            assert!(validate_destination(&destination, ctx)
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
            assert!(validate_destination(&destination, ctx)
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
            assert!(validate_destination(&destination, ctx)
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

    fn rebalance_calldata(amount: u64) -> Vec<u8> {
        rebalanceLiquidityCall {
            params: RebalanceParams {
                amount: U256::from(amount),
                burnId: U256::from(7u64),
                sourceChainId: U256::from(1u64),
                destinationChainId: U256::from(96u64),
                sourceAddress: "src".into(),
                destinationAddress: "dst".into(),
                proof: Bytes::new(),
                settlementDataOut: Bytes::new(),
                settlementDataIn: Bytes::new(),
            },
        }
        .abi_encode()
    }

    /// The mint/burn deployment is a second `Bridge` + `MultisigProxy` pair on
    /// the same chain, so a request naming it must be accepted by the same
    /// federation that serves pools.
    #[test]
    fn second_pinned_proxy_is_accepted() {
        let cfg = BridgeConfig {
            bridge_contracts: vec![[0xAA; ADDRESS_LEN], [0xBB; ADDRESS_LEN]],
            ..config()
        };
        let mut dst = destination();
        dst.proxy_contract = vec![0xBB; ADDRESS_LEN];
        with_ctx(&cfg, |ctx| {
            validate_destination(&dst, ctx).expect("second pinned proxy accepted");
        });
    }

    #[test]
    fn unpinned_proxy_is_rejected_even_with_several_pins() {
        let cfg = BridgeConfig {
            bridge_contracts: vec![[0xAA; ADDRESS_LEN], [0xBB; ADDRESS_LEN]],
            ..config()
        };
        let mut dst = destination();
        dst.proxy_contract = vec![0xCC; ADDRESS_LEN];
        with_ctx(&cfg, |ctx| {
            let err = validate_destination(&dst, ctx).unwrap_err().to_string();
            assert!(err.contains("not one of the pinned"), "unexpected: {err}");
        });
    }

    /// Widening the pin must not become "allow anything": the zero address is
    /// not a member, so a request for it is still refused.
    #[test]
    fn zero_address_is_not_a_member() {
        let cfg = config();
        assert!(!cfg.allows_proxy_contract(&[0u8; ADDRESS_LEN]));
    }

    #[test]
    fn rebalance_selector_is_accepted_and_amount_decoded() {
        let cfg = config();
        let mut dst = destination();
        dst.call_data = rebalance_calldata(4242);
        dst.calldata_amount = 4242;
        with_ctx(&cfg, |ctx| {
            let proof = validate_destination(&dst, ctx).expect("rebalance accepted");
            assert_eq!(proof.amount, 4242);
        });
    }

    /// The declared amount is cross-checked against the decoded one for
    /// rebalance exactly as it is for fundsOut.
    #[test]
    fn rebalance_amount_mismatch_is_rejected() {
        let cfg = config();
        let mut dst = destination();
        dst.call_data = rebalance_calldata(4242);
        dst.calldata_amount = 1;
        with_ctx(&cfg, |ctx| {
            let err = validate_destination(&dst, ctx).unwrap_err().to_string();
            assert!(err.contains("amount mismatch"), "unexpected: {err}");
        });
    }

    /// `REBALANCE_SELECTOR` is derived from the `sol!` definition, so it tracks
    /// the decoder automatically - but that means a wrong definition would go
    /// unnoticed. Pin it to the value computed independently (go-ethereum) from
    /// the contract's own signature.
    #[test]
    fn rebalance_selector_matches_contract() {
        assert_eq!(hex::encode(REBALANCE_SELECTOR), "a021ba4e");
    }
}
