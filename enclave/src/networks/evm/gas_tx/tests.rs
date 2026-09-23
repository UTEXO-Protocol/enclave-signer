use super::*;

const CHAIN_ID: u64 = 1;
const ALLOWED_TO: [u8; 20] = [0xAA; 20];
const MAX_GAS_LIMIT: u64 = 30_000;
const MAX_FEE_PER_GAS: u128 = 1_000;
const ALLOWED_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

fn cfg() -> BridgeConfig {
    BridgeConfig {
        chain_id: CHAIN_ID,
        bridge_contract: [0xBB; 20],
        rgb_asset_id: "rgb:test".into(),
        gas_tx_allowed_to: Some(ALLOWED_TO),
        gas_tx_max_gas_limit: MAX_GAS_LIMIT,
        gas_tx_max_fee_per_gas: MAX_FEE_PER_GAS,
        gas_tx_allowed_selectors: vec![ALLOWED_SELECTOR],
        ..Default::default()
    }
}

// ---- tiny RLP encoder, for building test fixtures only ----

fn rlp_str(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut out = Vec::new();
    if bytes.len() <= 55 {
        out.push(0x80 + bytes.len() as u8);
    } else {
        let len = bytes.len();
        let len_be = len.to_be_bytes();
        let lb: Vec<u8> = len_be.iter().copied().skip_while(|&b| b == 0).collect();
        out.push(0xb7 + lb.len() as u8);
        out.extend_from_slice(&lb);
    }
    out.extend_from_slice(bytes);
    out
}

/// Encode a scalar (minimal big-endian, zero = empty string).
fn rlp_scalar(v: u64) -> Vec<u8> {
    let be = v.to_be_bytes();
    let trimmed: Vec<u8> = be.iter().copied().skip_while(|&b| b == 0).collect();
    rlp_str(&trimmed)
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for it in items {
        payload.extend_from_slice(it);
    }
    let mut out = Vec::new();
    if payload.len() <= 55 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let len = payload.len();
        let len_be = len.to_be_bytes();
        let lb: Vec<u8> = len_be.iter().copied().skip_while(|&b| b == 0).collect();
        out.push(0xf7 + lb.len() as u8);
        out.extend_from_slice(&lb);
    }
    out.extend_from_slice(&payload);
    out
}

/// Build a well-formed unsigned EIP-1559 preimage with default fee/gas
/// fields and caller-chosen calldata.
fn eip1559_with_data(chain_id: u64, to: &[u8], value: u64, data: &[u8]) -> Vec<u8> {
    eip1559_full(chain_id, to, value, 1, 100, 21_000, data)
}

/// Build a well-formed unsigned EIP-1559 preimage. Carries the allowlisted
/// selector as calldata so the happy path passes the calldata check; the
/// rejection tests that use this fail earlier (chain/destination/value/caps).
fn eip1559(chain_id: u64, to: &[u8], value: u64) -> Vec<u8> {
    eip1559_with_data(chain_id, to, value, &ALLOWED_SELECTOR)
}

/// Build a well-formed unsigned EIP-1559 preimage with explicit fee/gas/data
/// fields, for exercising the cap and calldata-allowlist checks.
#[allow(clippy::too_many_arguments)]
fn eip1559_full(
    chain_id: u64,
    to: &[u8],
    value: u64,
    max_prio: u64,
    max_fee: u64,
    gas: u64,
    data: &[u8],
) -> Vec<u8> {
    let body = rlp_list(&[
        rlp_scalar(chain_id),
        rlp_scalar(7),
        rlp_scalar(max_prio),
        rlp_scalar(max_fee),
        rlp_scalar(gas),
        rlp_str(to),
        rlp_scalar(value),
        rlp_str(data),
        rlp_list(&[]),
    ]);
    let mut out = vec![TX_TYPE_EIP1559];
    out.extend_from_slice(&body);
    out
}

/// Build a well-formed unsigned legacy EIP-155 preimage (allowlisted-selector
/// calldata, so the happy path passes the calldata check).
fn legacy(chain_id: u64, to: &[u8], value: u64) -> Vec<u8> {
    legacy_full(chain_id, to, value, 100, 21_000, &ALLOWED_SELECTOR)
}

/// Build a well-formed unsigned legacy EIP-155 preimage with explicit
/// gasPrice/gas/data fields.
fn legacy_full(
    chain_id: u64,
    to: &[u8],
    value: u64,
    gas_price: u64,
    gas: u64,
    data: &[u8],
) -> Vec<u8> {
    rlp_list(&[
        rlp_scalar(7),         // nonce
        rlp_scalar(gas_price), // gasPrice
        rlp_scalar(gas),       // gasLimit
        rlp_str(to),           // to
        rlp_scalar(value),     // value
        rlp_str(data),         // data
        rlp_scalar(chain_id),  // chainId
        rlp_scalar(0),         // 0
        rlp_scalar(0),         // 0
    ])
}

/// Build a well-formed unsigned legacy EIP-155 preimage with default
/// gasPrice/gas and caller-chosen calldata.
fn legacy_with_data(chain_id: u64, to: &[u8], value: u64, data: &[u8]) -> Vec<u8> {
    legacy_full(chain_id, to, value, 100, 21_000, data)
}

fn req(unsigned_tx: Vec<u8>) -> SignRawDigestRequest {
    SignRawDigestRequest {
        digest: Vec::new(),
        unsigned_tx,
    }
}

#[test]
fn accepts_eip1559_to_pinned_destination() {
    let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
    let expected: [u8; 32] = Keccak256::digest(&tx).into();
    let got = validate_gas_tx_request(&req(tx), &cfg()).unwrap();
    assert_eq!(got, expected, "must sign keccak256(unsigned_tx)");
}

#[test]
fn accepts_legacy_eip155_to_pinned_destination() {
    let tx = legacy(CHAIN_ID, &ALLOWED_TO, 0);
    assert!(validate_gas_tx_request(&req(tx), &cfg()).is_ok());
}

#[test]
fn rejects_empty_preimage() {
    let err = validate_gas_tx_request(&req(vec![]), &cfg()).unwrap_err();
    assert!(err
        .to_string()
        .contains("requires the unsigned transaction preimage"));
}

#[test]
fn rejects_wrong_destination_the_drain() {
    // The core drain: a well-formed tx sending to an attacker address.
    let attacker = [0xEE; 20];
    let tx = eip1559(CHAIN_ID, &attacker, 0);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("destination") && err.to_string().contains("pinned"),
        "got: {err}"
    );
}

#[test]
fn rejects_nonzero_value_the_other_drain() {
    let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 1_000_000);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(err.to_string().contains("value must be 0"), "got: {err}");
}

// LayerZero native-fee carve-out: payable selector + destination ==
// pinned proxy + value <= ceiling. Each test breaks exactly one leg.

/// Verbatim from `MultisigProxy.sol`. Kept in the test module so the
/// release build carries no unused constant.
const ONCHAIN_LZ_FUNDS_OUT_CALL_SIG: &str =
    "lzFundsOutCall((uint256,uint256,uint256,uint256,string,bytes,bytes,uint32,bytes32,\
     uint256,bytes),uint256,uint256,uint256,bytes[])";

/// Drift fails closed, so this catches a silently disabled carve-out.
#[test]
fn onchain_lz_selector_matches_its_signature() {
    let digest = Keccak256::digest(ONCHAIN_LZ_FUNDS_OUT_CALL_SIG.as_bytes());
    assert_eq!(
        digest[..4],
        ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR,
        "selector drifted from {ONCHAIN_LZ_FUNDS_OUT_CALL_SIG}"
    );
}

/// LZ posture: `GAS_TX_ALLOWED_TO` pinned at the proxy, plus a ceiling.
fn lz_cfg() -> BridgeConfig {
    BridgeConfig {
        chain_id: CHAIN_ID,
        bridge_contract: ALLOWED_TO,
        rgb_asset_id: "rgb:test".into(),
        gas_tx_allowed_to: Some(ALLOWED_TO),
        gas_tx_max_value_wei: Some(1_000_000),
        gas_tx_max_gas_limit: MAX_GAS_LIMIT,
        gas_tx_max_fee_per_gas: MAX_FEE_PER_GAS,
        // The carve-out widens the value rule only; the selector must
        // still be allowlisted.
        gas_tx_allowed_selectors: vec![ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR, ALLOWED_SELECTOR],
        ..Default::default()
    }
}

fn lz_calldata() -> Vec<u8> {
    let mut calldata = ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR.to_vec();
    calldata.extend_from_slice(&[0x11; 64]);
    calldata
}

#[test]
fn accepts_nonzero_value_for_lz_funds_out_call() {
    let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 999_999, &lz_calldata());
    assert!(validate_gas_tx_request(&req(tx), &lz_cfg()).is_ok());
}

/// value/data indices differ per envelope; both must decide the same.
#[test]
fn accepts_nonzero_value_for_lz_funds_out_call_legacy_envelope() {
    let tx = legacy_with_data(CHAIN_ID, &ALLOWED_TO, 999_999, &lz_calldata());
    assert!(validate_gas_tx_request(&req(tx), &lz_cfg()).is_ok());
}

#[test]
fn accepts_value_exactly_at_the_ceiling() {
    let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000_000, &lz_calldata());
    assert!(validate_gas_tx_request(&req(tx), &lz_cfg()).is_ok());
}

#[test]
fn rejects_nonzero_value_for_other_selector() {
    let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000, &[0xde, 0xad, 0xbe, 0xef]);
    let err = validate_gas_tx_request(&req(tx), &lz_cfg()).unwrap_err();
    assert!(err.to_string().contains("value must be 0"), "got: {err}");
}

/// `GAS_TX_ALLOWED_TO` may be an EOA, which ignores calldata, so value
/// also requires `to` == the pinned proxy.
#[test]
fn rejects_nonzero_value_when_destination_is_not_the_pinned_proxy() {
    let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000, &lz_calldata());
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string()
            .contains("only allowed to the pinned MultisigProxy"),
        "got: {err}"
    );
}

#[test]
fn rejects_nonzero_value_when_bridge_contract_unpinned() {
    let unpinned = BridgeConfig {
        bridge_contract: [0u8; 20],
        ..lz_cfg()
    };
    let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000, &lz_calldata());
    let err = validate_gas_tx_request(&req(tx), &unpinned).unwrap_err();
    assert!(
        err.to_string()
            .contains("requires a pinned BRIDGE_CONTRACT"),
        "got: {err}"
    );
}

/// Fail-closed default: an unset pin keeps the `value == 0` posture.
#[test]
fn rejects_nonzero_value_when_ceiling_unset() {
    let uncapped = BridgeConfig {
        gas_tx_max_value_wei: None,
        ..lz_cfg()
    };
    let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1, &lz_calldata());
    let err = validate_gas_tx_request(&req(tx), &uncapped).unwrap_err();
    assert!(
        err.to_string().contains("GAS_TX_MAX_VALUE_WEI unset"),
        "got: {err}"
    );
}

#[test]
fn rejects_value_above_the_ceiling() {
    let tx = eip1559_with_data(CHAIN_ID, &ALLOWED_TO, 1_000_001, &lz_calldata());
    let err = validate_gas_tx_request(&req(tx), &lz_cfg()).unwrap_err();
    assert!(
        err.to_string()
            .contains("exceeds pinned GAS_TX_MAX_VALUE_WEI"),
        "got: {err}"
    );
}

/// A bare selector passes leg (a); the ceiling is what stops it.
#[test]
fn rejects_bare_selector_above_the_ceiling() {
    let tx = eip1559_with_data(
        CHAIN_ID,
        &ALLOWED_TO,
        u64::MAX,
        &ONCHAIN_LZ_FUNDS_OUT_CALL_SELECTOR,
    );
    let err = validate_gas_tx_request(&req(tx), &lz_cfg()).unwrap_err();
    assert!(
        err.to_string()
            .contains("exceeds pinned GAS_TX_MAX_VALUE_WEI"),
        "got: {err}"
    );
}

#[test]
fn rejects_wrong_chain_id() {
    let tx = eip1559(999, &ALLOWED_TO, 0);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(err.to_string().contains("chain_id"), "got: {err}");
}

#[test]
fn rejects_when_chain_id_unpinned() {
    let mut c = cfg();
    c.chain_id = 0;
    let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
    let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
    assert!(
        err.to_string().contains("chain_id not pinned"),
        "got: {err}"
    );
}

#[test]
fn rejects_when_destination_unpinned() {
    let mut c = cfg();
    c.gas_tx_allowed_to = None;
    let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
    let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
    assert!(
        err.to_string().contains("destination not pinned"),
        "got: {err}"
    );
}

#[test]
fn rejects_contract_creation_empty_to() {
    let tx = eip1559(CHAIN_ID, &[], 0);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(err.to_string().contains("contract creation"), "got: {err}");
}

#[test]
fn rejects_unsupported_envelope() {
    // 0x01 = EIP-2930 access-list tx, not accepted.
    let mut tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
    tx[0] = 0x01;
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("unsupported envelope"),
        "got: {err}"
    );
}

#[test]
fn rejects_trailing_garbage() {
    let mut tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
    tx.push(0xff); // extra byte after the top-level item
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(err.to_string().contains("trailing bytes"), "got: {err}");
}

#[test]
fn rejects_wrong_field_count() {
    // A 9-field list with the 0x02 prefix is valid; drop a field -> 8.
    let body = rlp_list(&[
        rlp_scalar(CHAIN_ID),
        rlp_scalar(7),
        rlp_scalar(1),
        rlp_scalar(100),
        rlp_scalar(21_000),
        rlp_str(&ALLOWED_TO),
        rlp_scalar(0),
        rlp_str(&[]),
        // accessList omitted -> 8 fields
    ]);
    let mut tx = vec![TX_TYPE_EIP1559];
    tx.extend_from_slice(&body);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(err.to_string().contains("9 fields"), "got: {err}");
}

#[test]
fn rejects_signed_legacy_tx() {
    // Legacy *signed* form has (v, r, s) where the unsigned body has
    // (chainId, 0, 0); a non-zero r/s trailer must be refused.
    let signed = rlp_list(&[
        rlp_scalar(7),
        rlp_scalar(100),
        rlp_scalar(21_000),
        rlp_str(&ALLOWED_TO),
        rlp_scalar(0),
        rlp_str(&[]),
        rlp_scalar(37),       // v
        rlp_str(&[0x11; 32]), // r
        rlp_str(&[0x22; 32]), // s
    ]);
    let err = validate_gas_tx_request(&req(signed), &cfg()).unwrap_err();
    assert!(err.to_string().contains("trailer must be"), "got: {err}");
}

#[test]
fn rejects_digest_mismatch_when_supplied() {
    let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
    let mut r = req(tx);
    r.digest = vec![0xAB; 32]; // wrong digest
    let err = validate_gas_tx_request(&r, &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("does not match keccak256"),
        "got: {err}"
    );
}

#[test]
fn rejects_truncated_rlp() {
    let mut tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
    tx.truncate(tx.len() - 5); // chop the tail
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(err.to_string().contains("rlp:"), "got: {err}");
}

#[test]
fn rejects_non_canonical_leading_zero_chain_id() {
    // Hand-build a body where chainId is encoded as 0x8201 -> [0x01] is
    // fine, but 0x820001 (leading zero) must be rejected. Build chainId
    // as a 2-byte string with a leading zero.
    let bad_chain = vec![0x82, 0x00, 0x01];
    let body = rlp_list(&[
        bad_chain,
        rlp_scalar(7),
        rlp_scalar(1),
        rlp_scalar(100),
        rlp_scalar(21_000),
        rlp_str(&ALLOWED_TO),
        rlp_scalar(0),
        rlp_str(&[]),
        rlp_list(&[]),
    ]);
    let mut tx = vec![TX_TYPE_EIP1559];
    tx.extend_from_slice(&body);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("non-canonical scalar"),
        "got: {err}"
    );
}

#[test]
fn rejects_value_field_that_is_a_list() {
    // `value` (item 6) encoded as a list rather than a scalar must be
    // rejected by the type check, not silently treated as zero.
    let body = rlp_list(&[
        rlp_scalar(CHAIN_ID),
        rlp_scalar(7),
        rlp_scalar(1),
        rlp_scalar(100),
        rlp_scalar(21_000),
        rlp_str(&ALLOWED_TO),
        rlp_list(&[rlp_scalar(1)]), // value as a list
        rlp_str(&[]),
        rlp_list(&[]),
    ]);
    let mut tx = vec![TX_TYPE_EIP1559];
    tx.extend_from_slice(&body);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("expected a scalar, found a list"),
        "got: {err}"
    );
}

#[test]
fn rejects_wide_nonzero_value() {
    // A non-zero value encoded as a wide (9-byte) scalar must be
    // rejected by the value==0 check, not accepted.
    let wide_value = rlp_str(&[0x01; 9]);
    let body = rlp_list(&[
        rlp_scalar(CHAIN_ID),
        rlp_scalar(7),
        rlp_scalar(1),
        rlp_scalar(100),
        rlp_scalar(21_000),
        rlp_str(&ALLOWED_TO),
        wide_value,
        rlp_str(&[]),
        rlp_list(&[]),
    ]);
    let mut tx = vec![TX_TYPE_EIP1559];
    tx.extend_from_slice(&body);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(err.to_string().contains("value must be 0"), "got: {err}");
}

/// Refused at the decode, not wrapped into a small number that would
/// slip under the ceiling.
#[test]
fn rejects_value_wider_than_u128() {
    let body = rlp_list(&[
        rlp_scalar(CHAIN_ID),
        rlp_scalar(7),
        rlp_scalar(1),
        rlp_scalar(100),
        rlp_scalar(21_000),
        rlp_str(&ALLOWED_TO),
        rlp_str(&[0x01; 17]), // 17-byte value
        rlp_str(&lz_calldata()),
        rlp_list(&[]),
    ]);
    let mut tx = vec![TX_TYPE_EIP1559];
    tx.extend_from_slice(&body);
    let err = validate_gas_tx_request(&req(tx), &lz_cfg()).unwrap_err();
    assert!(err.to_string().contains("exceeds u128"), "got: {err}");
}

#[test]
fn rejects_nesting_beyond_depth_limit() {
    // An accessList nested past MAX_RLP_DEPTH must be rejected by the
    // depth guard rather than recursing without bound.
    let mut deep = rlp_list(&[]);
    for _ in 0..(MAX_RLP_DEPTH + 4) {
        deep = rlp_list(&[deep]);
    }
    let body = rlp_list(&[
        rlp_scalar(CHAIN_ID),
        rlp_scalar(7),
        rlp_scalar(1),
        rlp_scalar(100),
        rlp_scalar(21_000),
        rlp_str(&ALLOWED_TO),
        rlp_scalar(0),
        rlp_str(&[]),
        deep, // accessList nested beyond the limit
    ]);
    let mut tx = vec![TX_TYPE_EIP1559];
    tx.extend_from_slice(&body);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(err.to_string().contains("nesting too deep"), "got: {err}");
}

// ---- fee/gas caps ----

#[test]
fn rejects_gas_limit_over_cap() {
    // gasLimit above GAS_TX_MAX_GAS_LIMIT is the fee-griefing vector.
    let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, MAX_GAS_LIMIT + 1, &[]);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("gasLimit") && err.to_string().contains("exceeds pinned cap"),
        "got: {err}"
    );
}

#[test]
fn rejects_max_fee_over_cap() {
    let tx = eip1559_full(
        CHAIN_ID,
        &ALLOWED_TO,
        0,
        1,
        (MAX_FEE_PER_GAS + 1) as u64,
        21_000,
        &[],
    );
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("maxFeePerGas") && err.to_string().contains("exceeds pinned cap"),
        "got: {err}"
    );
}

#[test]
fn rejects_priority_fee_over_cap() {
    // maxFee within cap, but the priority fee alone exceeds it.
    let tx = eip1559_full(
        CHAIN_ID,
        &ALLOWED_TO,
        0,
        (MAX_FEE_PER_GAS + 1) as u64,
        500,
        21_000,
        &[],
    );
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("maxPriorityFeePerGas")
            && err.to_string().contains("exceeds pinned cap"),
        "got: {err}"
    );
}

#[test]
fn rejects_legacy_gas_price_over_cap() {
    // Legacy gasPrice maps to the maxFeePerGas cap.
    let tx = legacy_full(
        CHAIN_ID,
        &ALLOWED_TO,
        0,
        (MAX_FEE_PER_GAS + 1) as u64,
        21_000,
        &[],
    );
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("maxFeePerGas") && err.to_string().contains("exceeds pinned cap"),
        "got: {err}"
    );
}

#[test]
fn rejects_when_gas_cap_unpinned() {
    let mut c = cfg();
    c.gas_tx_max_gas_limit = 0;
    let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
    let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
    assert!(
        err.to_string().contains("gas-limit cap not pinned"),
        "got: {err}"
    );
}

#[test]
fn rejects_when_fee_cap_unpinned() {
    let mut c = cfg();
    c.gas_tx_max_fee_per_gas = 0;
    let tx = eip1559(CHAIN_ID, &ALLOWED_TO, 0);
    let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
    assert!(err.to_string().contains("fee cap not pinned"), "got: {err}");
}

#[test]
fn rejects_fee_wider_than_u128() {
    // A 17-byte maxFeePerGas is far above any pinnable cap; reject at decode.
    let wide_fee = rlp_str(&[0x01; 17]);
    let body = rlp_list(&[
        rlp_scalar(CHAIN_ID),
        rlp_scalar(7),
        rlp_scalar(1),
        wide_fee, // maxFeePerGas > u128
        rlp_scalar(21_000),
        rlp_str(&ALLOWED_TO),
        rlp_scalar(0),
        rlp_str(&[]),
        rlp_list(&[]),
    ]);
    let mut tx = vec![TX_TYPE_EIP1559];
    tx.extend_from_slice(&body);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(err.to_string().contains("exceeds u128"), "got: {err}");
}

// ---- calldata selector allowlist ----

#[test]
fn accepts_allowlisted_selector_with_args() {
    // Selector in the allowlist, followed by ABI args, is accepted.
    let mut data = ALLOWED_SELECTOR.to_vec();
    data.extend_from_slice(&[0x00; 32]); // one 32-byte arg
    let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &data);
    let expected: [u8; 32] = Keccak256::digest(&tx).into();
    let got = validate_gas_tx_request(&req(tx), &cfg()).unwrap();
    assert_eq!(got, expected);
}

#[test]
fn accepts_allowlisted_selector_legacy() {
    let data = ALLOWED_SELECTOR.to_vec();
    let tx = legacy_full(CHAIN_ID, &ALLOWED_TO, 0, 100, 21_000, &data);
    assert!(validate_gas_tx_request(&req(tx), &cfg()).is_ok());
}

#[test]
fn rejects_disallowed_selector() {
    let data = [0x11, 0x22, 0x33, 0x44]; // not in the allowlist
    let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &data);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("selector")
            && err.to_string().contains("not in the operator allowlist"),
        "got: {err}"
    );
}

#[test]
fn rejects_non_empty_calldata_when_allowlist_empty() {
    // With no selectors pinned, only empty calldata may be signed.
    let mut c = cfg();
    c.gas_tx_allowed_selectors = Vec::new();
    let data = ALLOWED_SELECTOR.to_vec();
    let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &data);
    let err = validate_gas_tx_request(&req(tx), &c).unwrap_err();
    assert!(
        err.to_string().contains("not in the operator allowlist"),
        "got: {err}"
    );
}

#[test]
fn rejects_empty_calldata() {
    // A bare / empty-calldata call is refused: it would still invoke the
    // pinned contract's fallback/receive, outside the selector allowlist.
    let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &[]);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string().contains("empty calldata is not permitted"),
        "got: {err}"
    );
}

#[test]
fn rejects_calldata_shorter_than_selector() {
    // 1..=3 bytes of calldata cannot carry a 4-byte selector.
    let data = [0x11, 0x22];
    let tx = eip1559_full(CHAIN_ID, &ALLOWED_TO, 0, 1, 100, 21_000, &data);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string()
            .contains("shorter than a 4-byte function selector"),
        "got: {err}"
    );
}

#[test]
fn rejects_data_field_that_is_a_list() {
    // `data` (item 7) encoded as a list rather than a byte string.
    let body = rlp_list(&[
        rlp_scalar(CHAIN_ID),
        rlp_scalar(7),
        rlp_scalar(1),
        rlp_scalar(100),
        rlp_scalar(21_000),
        rlp_str(&ALLOWED_TO),
        rlp_scalar(0),
        rlp_list(&[rlp_scalar(1)]), // data as a list
        rlp_list(&[]),
    ]);
    let mut tx = vec![TX_TYPE_EIP1559];
    tx.extend_from_slice(&body);
    let err = validate_gas_tx_request(&req(tx), &cfg()).unwrap_err();
    assert!(
        err.to_string()
            .contains("expected calldata string, found a list"),
        "got: {err}"
    );
}
