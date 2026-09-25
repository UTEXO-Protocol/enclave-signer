/// Drop the typed intent; these assertions cover the route proof.
fn validate_dest(destination: &EvmDestination, ctx: &ValidationContext<'_>) -> Result<RouteProof> {
    super::validate_destination(destination, ctx).map(|(proof, _)| proof)
}

/// Keeps the canonical-encoding regressions expressed against raw bytes.
fn parse_proof_from_calldata(call_data: &[u8]) -> Result<RouteProof> {
    route_proof_from_params(&decode_funds_out_params(call_data)?)
}

use super::*;
use crate::config::BridgeConfig;
use alloy_primitives::{Address, Bytes};
#[cfg(feature = "rgb-validation")]
use std::sync::Mutex;

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
    #[cfg(feature = "rgb-validation")]
    let header_chain = Mutex::new(crate::networks::rgb::spv::HeaderChain::new(
        crate::networks::rgb::spv::Network::Regtest,
        crate::networks::rgb::spv::checkpoint_for(crate::networks::rgb::spv::Network::Regtest),
    ));
    let ctx = ValidationContext {
        bridge_config: config,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: None,
        #[cfg(feature = "rgb-validation")]
        header_chain: &header_chain,
        #[cfg(feature = "rgb-validation")]
        chain_pins: &crate::networks::rgb::spv_crosscheck::ChainPins::new(),
        // EVM destinations never reach the send-RGB PSBT bind.
        #[cfg(feature = "rgb-validation")]
        #[cfg(evm_to_rgb)]
        self_owned_psbt_outputs: None,
        #[cfg(feature = "rgb-validation")]
        bridge_events: &[],
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
    // A maximally packed calldata must be rejected up-front,
    // before selector dispatch or any offset extraction. Start from
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

/// A release naming an unpinned chain is refused even when the
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
/// must never drift apart: the whitelist gates on the constant while
/// decode/encode use the `sol!` type.
#[test]
fn funds_out_selector_matches_abi_derived_selector() {
    assert_eq!(FUNDS_OUT_SELECTOR_POOLS, fundsOutCall::SELECTOR);
}

/// Canonical calldata with non-empty dynamic tails - the baseline the two
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

/// ABI residual: the ABI decoder accepts trailing junk
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

/// ABI residual: two dynamic-arg head words pointing at the
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
