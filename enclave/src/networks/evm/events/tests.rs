use super::*;
use crate::test_support::{abi_word as word, bridge_funds_in_data, FakeEvm};

const BRIDGE: [u8; 20] = [0xB1; 20];
const OTHER: [u8; 20] = [0xC2; 20];
const TX: [u8; 32] = [0x11; 32];

/// A hash-shaped operationId, not a small left-padded integer.
fn op_id(tag: u8) -> [u8; 32] {
    let mut id = [tag; 32];
    id[0] = 0xF0 | (tag & 0x0F); // high bytes set: cannot fit a u64
    id
}

/// BridgeFundsIn `data` paying [`SAMPLE_INVOICE`].
fn bridge_data(gross: u64, net: u64, commission: u64) -> Vec<u8> {
    bridge_funds_in_data(gross, net, commission, SAMPLE_INVOICE)
}

// --- destinationAddress tail decoding ---
//
// A relayed receipt can carry attacker data, so each bound is asserted.

#[test]
fn decodes_the_destination_address_tail() {
    let d = bridge_funds_in_data(1000, 950, 50, SAMPLE_INVOICE);
    let got = decode_abi_string(&d, BFI_DEST_ADDRESS_HEAD_OFF, "destinationAddress").unwrap();
    assert_eq!(got, SAMPLE_INVOICE);
}

#[test]
fn decodes_an_empty_destination_address() {
    let d = bridge_funds_in_data(1000, 950, 50, "");
    let got = decode_abi_string(&d, BFI_DEST_ADDRESS_HEAD_OFF, "destinationAddress").unwrap();
    assert!(got.is_empty());
}

#[test]
fn rejects_a_tail_offset_past_the_data() {
    let mut d = bridge_funds_in_data(1000, 950, 50, SAMPLE_INVOICE);
    d[BFI_DEST_ADDRESS_HEAD_OFF..BFI_DEST_ADDRESS_HEAD_OFF + 32].copy_from_slice(&word(1_000_000));
    let err = decode_abi_string(&d, BFI_DEST_ADDRESS_HEAD_OFF, "destinationAddress").unwrap_err();
    assert!(err.to_string().contains("past the"), "{err}");
}

#[test]
fn rejects_a_tail_length_past_the_data() {
    let mut d = bridge_funds_in_data(1000, 950, 50, SAMPLE_INVOICE);
    let len_at = 9 * 32;
    // Under the size cap, so the bounds check must catch it.
    d[len_at..len_at + 32].copy_from_slice(&word(1_000));
    let err = decode_abi_string(&d, BFI_DEST_ADDRESS_HEAD_OFF, "destinationAddress").unwrap_err();
    assert!(err.to_string().contains("log data is"), "{err}");
}

#[test]
fn rejects_a_tail_over_the_size_cap() {
    let huge = "x".repeat(BFI_MAX_DEST_ADDRESS_LEN + 1);
    let d = bridge_funds_in_data(1000, 950, 50, &huge);
    let err = decode_abi_string(&d, BFI_DEST_ADDRESS_HEAD_OFF, "destinationAddress").unwrap_err();
    assert!(err.to_string().contains("cap"), "{err}");
}

#[test]
fn rejects_a_non_utf8_tail() {
    let mut d = bridge_funds_in_data(1000, 950, 50, "abcd");
    let at = 10 * 32; // first byte of the string body
    d[at] = 0xFF;
    let err = decode_abi_string(&d, BFI_DEST_ADDRESS_HEAD_OFF, "destinationAddress").unwrap_err();
    assert!(err.to_string().contains("not valid UTF-8"), "{err}");
}

/// Without this, the recipient bind has no value to compare.
#[cfg(evm_to_rgb)]
#[test]
fn verified_funds_in_carries_the_destination_address() {
    let p = happy_provider();
    let v = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 1000, 50).unwrap();
    assert_eq!(v.destination_address, SAMPLE_INVOICE);
}

/// topics: [topic0, operationId, sourceSender, sender].
fn bridge_log(op: [u8; 32], gross: u64, net: u64, commission: u64) -> LogEntry {
    LogEntry {
        address: BRIDGE,
        topics: vec![
            event_topic0(BRIDGE_FUNDS_IN_SIG),
            op,
            [0x5c; 32],   // sourceSender
            word(0xdead), // sender
        ],
        data: bridge_data(gross, net, commission),
    }
}

/// The RGB-only companion `FundsIn(address,uint256 rgbOpId,uint64)`. Its id
/// is an RGB id, so the predicate must never use this shape as a fallback.
fn rgb_companion_log(rgb_op_id: u64, net: u64) -> LogEntry {
    let mut data = word(rgb_op_id).to_vec();
    data.extend_from_slice(&word(net));
    LogEntry {
        address: BRIDGE,
        topics: vec![event_topic0(FUNDS_IN_SIG), word(0xdead)],
        data,
    }
}

fn receipt_with(logs: Vec<LogEntry>, block_number: u64) -> ReceiptData {
    ReceiptData {
        status_success: true,
        block_number,
        logs,
    }
}

/// gross=1000, commission=50, net=950. head 112, block 100 -> depth 12.
#[cfg(evm_to_rgb)]
fn happy_provider() -> FakeEvm {
    FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 50)], 100)),
        head: 112,
    }
}

/// Verifies with the operationId bound, the only supported call shape.
#[cfg(evm_to_rgb)]
fn verify(p: &FakeEvm) -> Result<()> {
    verify_funds_in_event(p, &BRIDGE, 12, &TX, &op_id(7), 1000, 50).map(|_| ())
}

#[test]
fn extract_uint256_works() {
    let mut data = vec![0u8; 40];
    data[39] = 42;
    assert_eq!(extract_uint256_as_u64(&data, 8).unwrap(), 42);
}

#[test]
fn extract_uint256_rejects_short_data() {
    let data = vec![0u8; 10];
    assert!(extract_uint256_as_u64(&data, 0).is_err());
}

#[test]
fn extract_uint256_rejects_overflow() {
    let mut data = vec![0u8; 32];
    data[0] = 1; // high byte set - exceeds u64
    assert!(extract_uint256_as_u64(&data, 0).is_err());
}

// ---- topic0 drift guards (offline-pinned known-good vectors) ----

#[test]
fn topic0_vectors_are_pinned() {
    assert_eq!(
        hex::encode(event_topic0(BRIDGE_FUNDS_IN_SIG)),
        "f15e44b33fca27f251e63583a6666ef06fc5993fbabb58356f27d07cee2811ab",
        "BridgeFundsIn topic0 drifted"
    );
    assert_eq!(
        hex::encode(event_topic0(FUNDS_IN_SIG)),
        "f1a18caea297591892fc07ea412a5e617d8e51e1155912d8871793e1d4e70f87",
        "FundsIn topic0 drifted"
    );
}

/// Pins the older topic0s. A revert to the 9-field or 11-field
/// (pre-`settlementData`, bridge PR #152) signature then fails here, not as
/// "no deposit found".
#[test]
fn legacy_topic0_is_not_in_use() {
    let current = hex::encode(event_topic0(BRIDGE_FUNDS_IN_SIG));
    assert_ne!(
        current, "08f62fdb70e8436181cbb1e561f6059677b179778bb0e0b9789a277eca0767e5",
        "still filtering on the 9-field BridgeFundsIn signature"
    );
    assert_ne!(
        current, "96266da276e870bb3d9c25740c9e24ec6448fc7bbed72ca384c3b8952574014c",
        "still filtering on the pre-#152 BridgeFundsIn signature (no settlementData)"
    );
}

// ---- happy path ----

#[cfg(evm_to_rgb)]
#[test]
fn accepts_matching_bridge_funds_in() {
    assert!(verify(&happy_provider()).is_ok());
}

#[cfg(evm_to_rgb)]
#[test]
fn accepts_real_contract_dual_emit() {
    // One deposit emits both events. The pair must not trip the ambiguity
    // guard, because only BridgeFundsIn is a candidate.
    let p = FakeEvm {
        receipt: Some(receipt_with(
            vec![
                rgb_companion_log(7, 100),
                bridge_log(op_id(7), 1000, 950, 50),
            ],
            100,
        )),
        head: 112,
    };
    assert!(verify(&p).is_ok());
}

#[cfg(evm_to_rgb)]
#[test]
fn dual_emit_binds_via_bridge_shape_not_the_companion() {
    // The pair must resolve to BridgeFundsIn, which binds tokenCommission.
    // The companion event has no commission, so a pass means a fallback to it.
    let p = FakeEvm {
        receipt: Some(receipt_with(
            vec![
                rgb_companion_log(7, 100),
                bridge_log(op_id(7), 1000, 950, 999),
            ],
            100,
        )),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("tokenCommission mismatch"), "got: {e}");
}

/// A tx with only the companion `FundsIn` is not an authorised deposit: its
/// id is an RGB id and it binds no commission.
#[cfg(evm_to_rgb)]
#[test]
fn rejects_rgb_companion_event_alone() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![rgb_companion_log(7, 100)], 100)),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("no BridgeFundsIn log"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_two_real_deposits_in_one_tx() {
    // Uniqueness also applies WITHIN a shape: two BridgeFundsIn logs are two
    // deposits, and a selection is a guess.
    let p = FakeEvm {
        receipt: Some(receipt_with(
            vec![
                bridge_log(op_id(7), 1000, 950, 50),
                bridge_log(op_id(8), 1000, 950, 50),
            ],
            100,
        )),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("ambiguous"), "got: {e}");
}

// ---- receipt-level rejections ----

#[cfg(evm_to_rgb)]
#[test]
fn rejects_missing_receipt() {
    let p = FakeEvm {
        receipt: None,
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("receipt not found"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_reverted_tx() {
    let mut r = receipt_with(vec![bridge_log(op_id(7), 1000, 950, 50)], 100);
    r.status_success = false;
    let p = FakeEvm {
        receipt: Some(r),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("reverted"), "got: {e}");
}

// ---- log-matching rejections ----

#[cfg(evm_to_rgb)]
#[test]
fn rejects_log_from_wrong_contract() {
    let mut log = bridge_log(op_id(7), 1000, 950, 50);
    log.address = OTHER;
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![log], 100)),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("no BridgeFundsIn log"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_wrong_topic0() {
    let mut log = bridge_log(op_id(7), 1000, 950, 50);
    log.topics[0] = word(0x1234); // not a FundsIn topic
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![log], 100)),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("no BridgeFundsIn log"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_ambiguous_multiple_logs() {
    let p = FakeEvm {
        receipt: Some(receipt_with(
            vec![
                bridge_log(op_id(7), 1000, 950, 50),
                bridge_log(op_id(7), 1000, 950, 50),
            ],
            100,
        )),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("ambiguous"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn ignores_unrelated_logs_and_accepts() {
    let unrelated = LogEntry {
        address: OTHER,
        topics: vec![word(0x9999)],
        data: vec![],
    };
    let p = FakeEvm {
        receipt: Some(receipt_with(
            vec![unrelated, bridge_log(op_id(7), 1000, 950, 50)],
            100,
        )),
        head: 112,
    };
    assert!(verify(&p).is_ok());
}

// ---- field-mismatch rejections ----

#[cfg(evm_to_rgb)]
#[test]
fn rejects_operation_id_mismatch() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(8), 1000, 950, 50)], 100)),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("operationId mismatch"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_amount_mismatch() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 999, 949, 50)], 100)),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("amount mismatch"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_commission_mismatch() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 40)], 100)),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("tokenCommission mismatch"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_net_amount_above_gross_minus_commission() {
    // gross-commission = 950 but the log claims 960.
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 960, 50)], 100)),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("exceeds gross - commission"), "got: {e}");
}

/// A lower net is correct for a fee-on-transfer token and is safe. It is
/// accepted and logged, not refused.
#[cfg(evm_to_rgb)]
#[test]
fn accepts_net_amount_below_gross_minus_commission() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 900, 50)], 100)),
        head: 112,
    };
    assert!(verify(&p).is_ok());
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_commission_exceeding_gross() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 100, 0, 150)], 100)),
        head: 112,
    };
    let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(7), 100, 150)
        .unwrap_err()
        .to_string();
    assert!(e.contains("exceeds gross amount"), "got: {e}");
}

/// A log without the indexed topics cannot be bound. Fail closed, and do not
/// read a data word.
#[cfg(evm_to_rgb)]
#[test]
fn rejects_log_without_operation_id_topic() {
    let mut log = bridge_log(op_id(7), 1000, 950, 50);
    log.topics.truncate(1); // topic0 only
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![log], 100)),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("operationId is expected in topic1"), "got: {e}");
}

/// A full-width 32-byte id must bind.
#[cfg(evm_to_rgb)]
#[test]
fn binds_full_width_operation_id() {
    let p = happy_provider();
    assert!(verify(&p).is_ok(), "a 32-byte operationId must bind");
    // ...and a different one must not.
    let e = verify_funds_in_event(&p, &BRIDGE, 12, &TX, &op_id(9), 1000, 50)
        .unwrap_err()
        .to_string();
    assert!(e.contains("operationId mismatch"), "got: {e}");
}

/// Regression guard: an absent id must refuse, not skip the bind.
#[cfg(evm_to_rgb)]
#[test]
fn rejects_when_operation_id_not_supplied() {
    let e = verify_funds_in_event(&happy_provider(), &BRIDGE, 12, &TX, &[], 1000, 50)
        .unwrap_err()
        .to_string();
    assert!(e.contains("must be exactly 32 bytes"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn still_rejects_amount_mismatch_with_matching_operation_id() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 999, 949, 50)], 100)),
        head: 112,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("amount mismatch"), "got: {e}");
}

/// A wrong-length id is a mis-encoding, not an absent one: refuse.
#[cfg(evm_to_rgb)]
#[test]
fn rejects_malformed_expected_operation_id() {
    let e = verify_funds_in_event(&happy_provider(), &BRIDGE, 12, &TX, &[0xAA; 8], 1000, 50)
        .unwrap_err()
        .to_string();
    assert!(e.contains("must be exactly 32 bytes"), "got: {e}");
}

// ---- confirmation-depth rejections ----

#[cfg(evm_to_rgb)]
#[test]
fn rejects_insufficient_depth() {
    // head 111, block 100 -> depth 11 < 12.
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 50)], 100)),
        head: 111,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("not final"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn accepts_exact_min_depth() {
    // head 112, block 100 -> depth 12 == 12.
    assert!(verify(&happy_provider()).is_ok());
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_head_below_receipt_block() {
    // head 99 < block 100 -> reorg.
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 50)], 100)),
        head: 99,
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("reorg"), "got: {e}");
}

// ---- regression: listener flags cannot authorize ----

#[cfg(evm_to_rgb)]
#[test]
fn issue_51_no_receipt_means_no_authorization() {
    // The listener sets event_valid/event_finalized=true, but no deposit
    // exists. Verification must reject, so the flags do not gate signing.
    let p = FakeEvm {
        receipt: None,
        head: 112,
    };
    assert!(verify(&p).is_err());
}

// ---- BFA: the `FundsIn` log whose id is the RGB OpId ----

#[cfg(feature = "bfa-validation")]
#[test]
fn rejects_old_funds_in_signature() {
    let mut log = rgb_companion_log(0xab, 100);
    log.topics[0] = event_topic0("FundsIn(address,uint256,uint256)");
    assert!(decode_funds_in(&log, &word(0xab)).is_err());
}

#[cfg(feature = "bfa-validation")]
#[test]
fn decodes_funds_in_with_the_operation_id_in_data() {
    let log = rgb_companion_log(0xab, 100);
    assert_eq!(decode_funds_in(&log, &word(0xab)).unwrap(), 100);
}

#[cfg(feature = "bfa-validation")]
#[test]
fn rejects_funds_in_for_a_different_operation_id() {
    let log = rgb_companion_log(0xab, 100);
    assert!(decode_funds_in(&log, &word(0xcd)).is_err());
}

#[cfg(feature = "bfa-validation")]
#[test]
fn rejects_funds_in_amount_above_u64() {
    let mut data = word(0xab).to_vec();
    data.extend_from_slice(&[0x01; 32]);
    let log = LogEntry {
        address: BRIDGE,
        topics: vec![event_topic0(FUNDS_IN_SIG), word(0xdead)],
        data,
    };
    assert!(decode_funds_in(&log, &word(0xab)).is_err());
}

#[cfg(feature = "bfa-validation")]
#[test]
fn rejects_funds_in_with_unexpected_layout() {
    let mut log = rgb_companion_log(0xab, 100);
    log.topics.push(word(0xab));
    assert!(decode_funds_in(&log, &word(0xab)).is_err());
}

#[cfg(feature = "bfa-mint")]
#[test]
fn verify_rgb_funds_in_accepts_a_verified_lock() {
    // A real deposit tx emits both: the RGB companion (minted amount) and the
    // BridgeFundsIn record (operationId, netAmount).
    let p = FakeEvm {
        receipt: Some(receipt_with(
            vec![
                rgb_companion_log(0xab, 100),
                bridge_log(op_id(7), 1000, 950, 50),
            ],
            100,
        )),
        head: 112,
    };
    assert_eq!(
        verify_rgb_funds_in(&p, &BRIDGE, 12, &TX, &word(0xab)).unwrap(),
        VerifiedLock {
            mint_opid: word(0xab),
            minted: 100,
            operation_id: op_id(7),
            net_amount: 950,
        }
    );
}

/// Without the record, a `fundsOut` has nothing to cite, so the lock is not
/// settlement evidence.
#[cfg(feature = "bfa-validation")]
#[test]
fn verify_rgb_funds_in_requires_the_bridge_funds_in_record() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![rgb_companion_log(0xab, 100)], 100)),
        head: 112,
    };
    let e = verify_rgb_funds_in(&p, &BRIDGE, 12, &TX, &word(0xab))
        .unwrap_err()
        .to_string();
    assert!(e.contains("no BridgeFundsIn log"), "got: {e}");
}

/// The extension does not check the emitter. This filter is the only guard
/// against a mint from a log of an attacker contract.
#[cfg(feature = "bfa-validation")]
#[test]
fn verify_rgb_funds_in_rejects_a_log_from_an_unpinned_contract() {
    let mut log = rgb_companion_log(0xab, 100);
    log.address = OTHER;
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![log], 100)),
        head: 112,
    };
    let e = verify_rgb_funds_in(&p, &BRIDGE, 12, &TX, &word(0xab))
        .unwrap_err()
        .to_string();
    assert!(e.contains("no FundsIn log"), "got: {e}");
}

#[cfg(feature = "bfa-validation")]
#[test]
fn refuses_a_bridge_location_that_is_not_the_pinned_contract() {
    let pinned = [0x11u8; 20];
    assert!(check_bridge_location("0x1111111111111111111111111111111111111111", &pinned).is_ok());
    assert!(check_bridge_location("0x2222222222222222222222222222222222222222", &pinned).is_err());
    assert!(check_bridge_location("not-an-address", &pinned).is_err());
}

/// The vector bridge-utexo and the Bridge tests pin too.
#[cfg(feature = "bfa-validation")]
#[test]
fn rgb_mint_deposit_id_matches_the_shared_vector() {
    let mut cfg = crate::config::BridgeConfig::default();
    hex::decode_to_slice(
        "50d244bca9273fd5faadbee2d653b80a23e89ee5",
        &mut cfg.funds_in_contract,
    )
    .unwrap();
    hex::decode_to_slice(
        "fd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
        &mut cfg.token_contract,
    )
    .unwrap();
    cfg.chain_id = 42161;
    let mut opid = [0u8; 32];
    opid[0] = 0xab;
    opid[1] = 0x01;
    opid[31] = 0x02;

    assert_eq!(
        hex::encode(rgb_mint_deposit_id(&cfg, &opid, 100_000).unwrap()),
        "e0ff3d136bfe0a4de03da1aab87b954b20895d976e1a1753b2d553b451420766"
    );
}

/// The vector BridgeProxy.t.sol pins (bridge-smart-contracts #173).
#[cfg(feature = "bfa-validation")]
#[test]
fn rgb_mint_deposit_id_matches_the_contract_vector() {
    let cfg = crate::config::BridgeConfig {
        funds_in_contract: [0x11; 20],
        token_contract: [0x22; 20],
        chain_id: 42161,
        ..Default::default()
    };
    let mut opid = [0u8; 32];
    opid[29..].copy_from_slice(&[0xab, 0xcd, 0xef]);

    assert_eq!(
        hex::encode(rgb_mint_deposit_id(&cfg, &opid, 1_000_000).unwrap()),
        "6f0c19c7e7e8764fbd2afa1fc8211144acc9b45766be22d6b9bba1b20ed6cbd9"
    );
}

#[cfg(feature = "bfa-validation")]
#[test]
fn rgb_mint_deposit_id_binds_the_mint_and_its_amount() {
    let cfg = crate::config::BridgeConfig {
        funds_in_contract: [0x50; 20],
        token_contract: [0xfd; 20],
        chain_id: 42161,
        ..crate::config::BridgeConfig::default()
    };
    let id = rgb_mint_deposit_id(&cfg, &[1; 32], 100).unwrap();
    assert_ne!(id, rgb_mint_deposit_id(&cfg, &[1; 32], 101).unwrap());
    assert_ne!(id, rgb_mint_deposit_id(&cfg, &[2; 32], 100).unwrap());
    assert!(rgb_mint_deposit_id(&cfg, &[1; 32], 0).is_err());
}
