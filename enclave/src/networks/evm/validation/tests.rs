/// Drops the typed intent. These assertions cover the route proof.
fn validate_dest(destination: &EvmDestination, ctx: &ValidationContext<'_>) -> Result<RouteProof> {
    super::validate_destination(destination, ctx).map(|(proof, _, _)| proof)
}

/// Keeps only the decoded burn fields. These assertions cover the identity.
fn release_of(destination: &EvmDestination, ctx: &ValidationContext<'_>) -> ReleaseIdentity {
    super::validate_destination(destination, ctx)
        .expect("valid destination")
        .2
}

/// Decodes raw bytes for the canonical-encoding regressions.
fn parse_proof_from_calldata(call_data: &[u8]) -> Result<RouteProof> {
    route_proof_from_params(&decode_funds_out_params(call_data)?)
}

use super::*;
use crate::config::BridgeConfig;
use alloy_primitives::{Address, Bytes, FixedBytes};
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
            sourceBurnTxId: FixedBytes([0x5b; 32]),
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
            sourceBurnTxId: FixedBytes([0x5b; 32]),
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
        #[cfg(all(feature = "rgb-validation", evm_to_rgb))]
        psbt_fee_key_paths: None,
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
        // The error must name the failed predicate and the selector, so an
        // operator can see WHAT was rejected.
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
    // Oversize calldata must be rejected before selector dispatch or decode.
    // Pad a valid fundsOut tail past the cap.
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
    // Exactly at the cap is allowed. The selector stays, so dispatch still
    // recognizes the fundsOut shape.
    let mut destination = destination();
    destination
        .call_data
        .resize(MAX_FUNDS_OUT_CALL_DATA_LEN, 0u8);
    destination.call_data[..4].copy_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
    // The zero-padded tail can fail the ABI decode. Assert only that it is
    // NOT the size error.
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

/// A release that names an unpinned chain is refused, also when the request
/// `chain_id` matches.
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
        sourceBurnTxId: FixedBytes([0x5b; 32]),
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
/// destinationChainId must NOT be pinned to the execution chain. A pin blocks
/// each LayerZero payout (Ethereum, Polygon, Plasma, Tron).
#[test]
fn accepts_entrypoint_route_to_remote_chain() {
    with_ctx(&config(), |ctx| {
        let proof = validate_dest(&lz_destination(137), ctx)
            .expect("entrypoint payout to a remote chain must validate");
        assert_eq!(proof.amount, 1000);
    });
}

/// The entrypoint route must name a real destination.
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

/// A payout to the pinned execution chain is a direct payout. The entrypoint
/// route refuses it.
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
            sourceBurnTxId: FixedBytes([0x5b; 32]),
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

/// The pinned selector constant and the alloy ABI selector must agree. The
/// whitelist uses the constant, and decode/encode use the `sol!` type.
#[test]
fn funds_out_selector_matches_abi_derived_selector() {
    assert_eq!(FUNDS_OUT_SELECTOR_POOLS, fundsOutCall::SELECTOR);
}

/// Canonical calldata with non-empty dynamic tails. The two non-canonical
/// tests below change it.
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
            sourceBurnTxId: FixedBytes([0x5b; 32]),
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

/// ABI residual: the ABI decoder accepts trailing junk after the last dynamic
/// tail. The canonical re-encode check must refuse it, so a signing request
/// carries no unread bytes.
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

/// ABI residual: two dynamic-arg head words that point at the same tail
/// decode, but are not a canonical encoding.
#[test]
fn rejects_calldata_with_overlapping_dynamic_tails() {
    let mut cd = funds_out_calldata_with_tails(1_234);
    // Offset words for `proof` (228..260) and `settlementData` (260..292),
    // with the selector and the tuple head pointer. Both start at the same
    // tuple start, so a copy of one aliases the two tails.
    let proof_offset_word: [u8; 32] = cd[228..260].try_into().unwrap();
    cd[260..292].copy_from_slice(&proof_offset_word);
    let err = parse_proof_from_calldata(&cd).unwrap_err();
    assert!(
        err.to_string().contains("non-canonical fundsOut calldata"),
        "expected canonical-encoding rejection of overlapping tails, got: {err}"
    );
}

// ---- release identity: source fields and burnId on both routes ----

fn rgb_release() -> ReleaseIdentity {
    ReleaseIdentity {
        burn_id: U256::ZERO,
        amount: U256::from(1000u64),
        source_chain_id: U256::from(RGB_SOURCE_CHAIN_ID),
        source_address: String::new(),
        settlement_data: Vec::new(),
        source_burn_tx_id: [0x5b; 32],
    }
}

#[test]
fn rgb_source_identity_accepts_the_rgb_network_id_and_empty_address() {
    validate_rgb_source_identity(&rgb_release()).expect("canonical RGB source");
}

#[test]
fn rgb_source_identity_rejects_a_foreign_source_chain() {
    // On chain, (sourceChainId, destinationChainId) selects the verifier and
    // commission rate. Each id but the RGB one must refuse, also the
    // execution chain id and zero.
    for foreign in [0u64, 1, 42161, RGB_SOURCE_CHAIN_ID + 1] {
        let release = ReleaseIdentity {
            source_chain_id: U256::from(foreign),
            ..rgb_release()
        };
        let err = validate_rgb_source_identity(&release)
            .expect_err("foreign source chain must refuse")
            .to_string();
        assert!(
            err.contains("sourceChainId") && err.contains(&RGB_SOURCE_CHAIN_ID.to_string()),
            "{foreign}: {err}"
        );
    }
}

#[test]
fn rgb_source_identity_rejects_a_non_empty_source_address() {
    let release = ReleaseIdentity {
        source_address: "rgb:some-sender".into(),
        ..rgb_release()
    };
    let err = validate_rgb_source_identity(&release)
        .expect_err("non-empty sourceAddress must refuse")
        .to_string();
    assert!(err.contains("sourceAddress must be empty"), "{err}");
}

/// The direct route returns each burn-identity field from its calldata, so the
/// handler binds the signed values.
#[test]
fn direct_route_surfaces_its_release_identity() {
    let mut destination = destination();
    destination.call_data = fundsOutCall {
        params: FundsOutParams {
            recipient: Address::from([0x22; ADDRESS_LEN]),
            amount: U256::from(1000u64),
            burnId: U256::from(7u64),
            sourceChainId: U256::from(RGB_SOURCE_CHAIN_ID),
            destinationChainId: U256::from(1u64),
            sourceAddress: "who".into(),
            proof: Bytes::new(),
            settlementData: Bytes::from(vec![0xd0, 0x0d]),
            sourceBurnTxId: FixedBytes([0x5b; 32]),
        },
    }
    .abi_encode();
    with_ctx(&config(), |ctx| {
        assert_eq!(
            release_of(&destination, ctx),
            ReleaseIdentity {
                burn_id: U256::from(7u64),
                amount: U256::from(1000u64),
                source_chain_id: U256::from(RGB_SOURCE_CHAIN_ID),
                source_address: "who".into(),
                settlement_data: vec![0xd0, 0x0d],
                source_burn_tx_id: [0x5b; 32],
            }
        );
    });
}

/// Same for the LayerZero route. It gives no `FundsOutParams`, so the identity
/// is the handler's only typed view of its burn fields.
#[test]
fn entrypoint_route_surfaces_its_release_identity() {
    let mut destination = destination();
    destination.call_data = lzFundsOutCall {
        amount: U256::from(1000u64),
        burnId: U256::from(9u64),
        sourceChainId: U256::from(5u64),
        destinationChainId: U256::from(137u64),
        sourceAddress: "lz-who".into(),
        proof: Bytes::new(),
        settlementData: Bytes::from(vec![0xe1]),
        dstEid: 30101u32,
        recipient: FixedBytes([0x05; 32]),
        minAmountLD: U256::from(1000u64),
        extraOptions: Bytes::new(),
        sourceBurnTxId: FixedBytes([0x6c; 32]),
    }
    .abi_encode();
    with_ctx(&config(), |ctx| {
        assert_eq!(
            release_of(&destination, ctx),
            ReleaseIdentity {
                burn_id: U256::from(9u64),
                amount: U256::from(1000u64),
                source_chain_id: U256::from(5u64),
                source_address: "lz-who".into(),
                settlement_data: vec![0xe1],
                source_burn_tx_id: [0x6c; 32],
            }
        );
    });
}

// ---- burnId recompute ----

/// Pins the enclave recompute to the contract formula. The test uses the
/// alloy `abi.encode` of the nine-word tuple, not the manual concatenation.
fn contract_burn_id(cfg: &BridgeConfig, release: &ReleaseIdentity) -> U256 {
    use alloy_primitives::{keccak256, B256};
    use alloy_sol_types::SolValue;

    let typehash: B256 = keccak256(
        "UtexoBurnId(address bridge,uint256 chainId,address token,uint256 amount,\
         uint256 sourceChainId,bytes32 sourceAddressHash,bytes32 settlementDataHash,\
         bytes32 sourceBurnTxId)",
    );
    let encoded = (
        typehash,
        Address::from(cfg.funds_in_contract),
        U256::from(cfg.chain_id),
        Address::from(cfg.token_contract),
        release.amount,
        release.source_chain_id,
        keccak256(release.source_address.as_bytes()),
        keccak256(&release.settlement_data),
        B256::from(release.source_burn_tx_id),
    )
        .abi_encode();
    assert_eq!(encoded.len(), 9 * 32, "nine static words");
    U256::from_be_bytes(keccak256(encoded).0)
}

fn token_pinned_config() -> BridgeConfig {
    BridgeConfig {
        chain_id: 42161,
        funds_in_contract: [0xb1; ADDRESS_LEN],
        token_contract: [0x70; ADDRESS_LEN],
        ..config()
    }
}

#[test]
fn burn_id_recompute_matches_the_contract_formula() {
    let cfg = token_pinned_config();
    let release = ReleaseIdentity {
        amount: U256::from(123_456u64),
        settlement_data: vec![0xaa, 0xbb, 0xcc],
        ..rgb_release()
    };
    assert_eq!(
        expected_burn_id(&cfg, &release),
        contract_burn_id(&cfg, &release)
    );
}

#[test]
fn burn_id_recompute_binds_every_input() {
    // Each preimage input alone must change the id, so the contract derives a
    // different key for each change.
    let cfg = token_pinned_config();
    let base = rgb_release();
    let base_id = expected_burn_id(&cfg, &base);

    let variants = [
        ReleaseIdentity {
            amount: U256::from(1001u64),
            ..base.clone()
        },
        ReleaseIdentity {
            source_chain_id: U256::from(97u64),
            ..base.clone()
        },
        ReleaseIdentity {
            source_address: "x".into(),
            ..base.clone()
        },
        ReleaseIdentity {
            settlement_data: vec![0x01],
            ..base.clone()
        },
        ReleaseIdentity {
            source_burn_tx_id: [0x5c; 32],
            ..base.clone()
        },
    ];
    for v in &variants {
        assert_ne!(expected_burn_id(&cfg, v), base_id, "{v:?}");
    }
    for other_cfg in [
        BridgeConfig {
            chain_id: 1,
            ..token_pinned_config()
        },
        BridgeConfig {
            funds_in_contract: [0xb2; ADDRESS_LEN],
            ..token_pinned_config()
        },
        BridgeConfig {
            token_contract: [0x71; ADDRESS_LEN],
            ..token_pinned_config()
        },
    ] {
        assert_ne!(expected_burn_id(&other_cfg, &base), base_id);
    }
}

#[test]
fn burn_id_check_accepts_the_derived_id_and_refuses_any_other() {
    let cfg = token_pinned_config();
    let mut release = rgb_release();
    release.burn_id = expected_burn_id(&cfg, &release);
    validate_burn_id(&cfg, &release).expect("the derived id must pass");

    release.burn_id += U256::from(1u64);
    let err = validate_burn_id(&cfg, &release)
        .expect_err("a foreign burnId must refuse")
        .to_string();
    assert!(
        err.contains("burnId") && err.contains("InvalidBurnId"),
        "{err}"
    );
}

#[test]
fn burn_id_check_is_skipped_while_the_token_is_unpinned() {
    // Dev builds have no token pin. Production cannot boot without one, so a
    // release image never skips.
    let cfg = BridgeConfig {
        token_contract: [0u8; ADDRESS_LEN],
        ..token_pinned_config()
    };
    validate_burn_id(&cfg, &rgb_release()).expect("unpinned token skips the recompute");
}
