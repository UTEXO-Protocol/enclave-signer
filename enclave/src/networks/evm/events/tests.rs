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

/// A destination address that is longer than one ABI word.
const DESTINATION: &str = "a destination address that is longer than one ABI word";

/// BridgeFundsIn `data` of an RGB deposit: it names no destination address.
fn bridge_data(gross: u64, net: u64, commission: u64) -> Vec<u8> {
    bridge_funds_in_data(gross, net, commission, "")
}

// --- destinationAddress tail decoding ---
//
// A relayed receipt can carry attacker data, so each bound is asserted.

#[test]
fn decodes_the_destination_address_tail() {
    let d = bridge_funds_in_data(1000, 950, 50, DESTINATION);
    let got = decode_abi_string(&d, BFI_DEST_ADDRESS_HEAD_OFF, "destinationAddress").unwrap();
    assert_eq!(got, DESTINATION);
}

#[test]
fn decodes_an_empty_destination_address() {
    let d = bridge_funds_in_data(1000, 950, 50, "");
    let got = decode_abi_string(&d, BFI_DEST_ADDRESS_HEAD_OFF, "destinationAddress").unwrap();
    assert!(got.is_empty());
}

#[test]
fn rejects_a_tail_offset_past_the_data() {
    let mut d = bridge_funds_in_data(1000, 950, 50, DESTINATION);
    d[BFI_DEST_ADDRESS_HEAD_OFF..BFI_DEST_ADDRESS_HEAD_OFF + 32].copy_from_slice(&word(1_000_000));
    let err = decode_abi_string(&d, BFI_DEST_ADDRESS_HEAD_OFF, "destinationAddress").unwrap_err();
    assert!(err.to_string().contains("past the"), "{err}");
}

#[test]
fn rejects_a_tail_length_past_the_data() {
    let mut d = bridge_funds_in_data(1000, 950, 50, DESTINATION);
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

/// The RGB-only companion `FundsIn(address,uint256 lockId,uint64)`. Its id
/// is an RGB id, so the predicate must never use this shape as a fallback.
fn rgb_companion_log(lock_id: u64, net: u64) -> LogEntry {
    LogEntry {
        address: BRIDGE,
        topics: vec![event_topic0(FUNDS_IN_SIG), word(0xdead), word(lock_id)],
        data: word(net).to_vec(),
    }
}

fn receipt_with(logs: Vec<LogEntry>, block_number: u64) -> ReceiptData {
    ReceiptData {
        status_success: true,
        block_number,
        block_hash: [0x42; 32],
        logs,
    }
}

/// gross=1000, commission=50, net=950, in the safe block 100.
#[cfg(evm_to_rgb)]
fn happy_provider() -> FakeEvm {
    FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 50)], 100)),
        ..FakeEvm::default()
    }
}

/// Verifies with the operationId bound, the only supported call shape.
#[cfg(evm_to_rgb)]
fn verify(p: &FakeEvm) -> Result<()> {
    verify_funds_in_event(p, &BRIDGE, EvmFinalityTag::Safe, &TX, &op_id(7), 1000, 50)
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
        ..FakeEvm::default()
    };
    assert!(verify(&p).is_ok());
}

/// A tx with only the companion `FundsIn` is not an authorised deposit: its
/// id is an RGB id and it binds no commission.
#[cfg(evm_to_rgb)]
#[test]
fn rejects_rgb_companion_event_alone() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![rgb_companion_log(7, 100)], 100)),
        ..FakeEvm::default()
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("no BridgeFundsIn log"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn binds_the_requested_deposit_of_two_in_one_tx() {
    // The operationId selects the log. The other deposit comes first and has
    // other amounts.
    let p = FakeEvm {
        receipt: Some(receipt_with(
            vec![
                bridge_log(op_id(8), 500, 475, 25),
                bridge_log(op_id(7), 1000, 950, 50),
            ],
            100,
        )),
        ..FakeEvm::default()
    };
    verify(&p).unwrap();
    verify_funds_in_event(&p, &BRIDGE, EvmFinalityTag::Safe, &TX, &op_id(8), 500, 25).unwrap();
}

// ---- receipt-level rejections ----

#[cfg(evm_to_rgb)]
#[test]
fn rejects_missing_receipt() {
    let p = FakeEvm {
        receipt: None,
        ..FakeEvm::default()
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
        ..FakeEvm::default()
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
        ..FakeEvm::default()
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
        ..FakeEvm::default()
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
        ..FakeEvm::default()
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
        ..FakeEvm::default()
    };
    assert!(verify(&p).is_ok());
}

// ---- field-mismatch rejections ----

#[cfg(evm_to_rgb)]
#[test]
fn rejects_operation_id_mismatch() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(8), 1000, 950, 50)], 100)),
        ..FakeEvm::default()
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("no BridgeFundsIn log"), "got: {e}");
    assert!(e.contains(&hex::encode(op_id(7))), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_amount_mismatch() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 999, 949, 50)], 100)),
        ..FakeEvm::default()
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("amount mismatch"), "got: {e}");
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_commission_mismatch() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 1000, 950, 40)], 100)),
        ..FakeEvm::default()
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
        ..FakeEvm::default()
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
        ..FakeEvm::default()
    };
    assert!(verify(&p).is_ok());
}

#[cfg(evm_to_rgb)]
#[test]
fn rejects_commission_exceeding_gross() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![bridge_log(op_id(7), 100, 0, 150)], 100)),
        ..FakeEvm::default()
    };
    let e = verify_funds_in_event(&p, &BRIDGE, EvmFinalityTag::Safe, &TX, &op_id(7), 100, 150)
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
        ..FakeEvm::default()
    };
    let e = verify(&p).unwrap_err().to_string();
    assert!(e.contains("no BridgeFundsIn log"), "got: {e}");
}

/// An absent id must refuse, not skip the bind.
#[cfg(evm_to_rgb)]
#[test]
fn rejects_when_operation_id_not_supplied() {
    let e = verify_funds_in_event(
        &happy_provider(),
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &[],
        1000,
        50,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("must be exactly 32 bytes"), "got: {e}");
}

// The attested tag selects the head in both deposit verification paths.
mod finality {
    use super::*;
    use std::cell::RefCell;

    struct Provider {
        expected_tag: EvmFinalityTag,
        head: Option<BlockData>,
        head_after: Option<Option<BlockData>>,
        canonical: Option<BlockData>,
        snapshot_canonical: Option<Option<BlockData>>,
        receipt_number: u64,
        fail_tag: bool,
        fail_canonical: bool,
        calls: RefCell<Vec<&'static str>>,
    }

    impl Default for Provider {
        fn default() -> Self {
            let block = BlockData {
                number: 100,
                hash: [0x42; 32],
            };
            Self {
                expected_tag: EvmFinalityTag::Safe,
                head: Some(block),
                head_after: None,
                canonical: Some(block),
                snapshot_canonical: None,
                receipt_number: 100,
                fail_tag: false,
                fail_canonical: false,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl EvmReceiptProvider for Provider {
        fn get_transaction_receipt(&self, _: &[u8; 32]) -> Result<Option<ReceiptData>> {
            self.calls.borrow_mut().push("receipt");
            Ok(Some(receipt_with(
                vec![
                    rgb_companion_log(0xab, 950),
                    bridge_log(op_id(7), 1000, 950, 50),
                ],
                self.receipt_number,
            )))
        }

        fn get_block_by_tag(&self, tag: EvmFinalityTag) -> Result<Option<BlockData>> {
            assert_eq!(
                tag, self.expected_tag,
                "both head snapshots must use the configured tag"
            );
            let recheck = self.calls.borrow().contains(&"tag");
            self.calls
                .borrow_mut()
                .push(if recheck { "tag_recheck" } else { "tag" });
            if self.fail_tag {
                return Err(EnclaveError::CrossCheck("tag RPC failed".into()));
            }
            Ok(if recheck {
                self.head_after.unwrap_or(self.head)
            } else {
                self.head
            })
        }

        fn get_block_by_number(&self, number: u64) -> Result<Option<BlockData>> {
            let recheck = self.calls.borrow().contains(&"canonical");
            self.calls.borrow_mut().push(if recheck {
                "head_ancestor"
            } else {
                "canonical"
            });
            assert_eq!(
                number,
                if recheck {
                    self.head.unwrap().number
                } else {
                    self.receipt_number
                }
            );
            if self.fail_canonical {
                return Err(EnclaveError::CrossCheck("canonical RPC failed".into()));
            }
            Ok(if recheck {
                self.snapshot_canonical.unwrap_or(self.canonical)
            } else {
                self.canonical
            })
        }

        fn get_chain_id(&self) -> Result<u64> {
            panic!("deposit verification does not read the chain id")
        }
    }

    type Verifier = fn(&dyn EvmReceiptProvider, EvmFinalityTag) -> Result<()>;

    fn verifiers() -> Vec<Verifier> {
        vec![
            #[cfg(evm_to_rgb)]
            |provider, tag| verify_funds_in_event(provider, &BRIDGE, tag, &TX, &op_id(7), 1000, 50),
            |provider, tag| {
                verify_rgb_funds_in(
                    provider,
                    &BRIDGE,
                    tag,
                    &TX,
                    &word(0xab),
                    &op_id(7),
                    950,
                    BEFORE_BLOCK,
                )
                .map(|_| ())
            },
        ]
    }

    fn cases() -> Vec<(EvmFinalityTag, Verifier)> {
        [
            EvmFinalityTag::Latest,
            EvmFinalityTag::Safe,
            EvmFinalityTag::Finalized,
        ]
        .into_iter()
        .flat_map(|tag| verifiers().into_iter().map(move |verify| (tag, verify)))
        .collect()
    }

    fn rejects(configure: impl Fn(&mut Provider), message: &str) {
        for (tag, verify) in cases() {
            let mut provider = Provider {
                expected_tag: tag,
                ..Provider::default()
            };
            configure(&mut provider);
            let err = verify(&provider, tag).unwrap_err().to_string();
            assert!(
                err.contains(&message.replace("{tag}", tag.as_str())),
                "{err}"
            );
        }
    }

    #[test]
    fn receipt_above_selected_head_is_rejected() {
        rejects(
            |p| {
                p.head.as_mut().unwrap().number = 99;
            },
            "above RPC {tag}",
        );
    }

    #[test]
    fn only_safe_and_finalized_waits_have_the_retryable_wire_code() {
        for (tag, verify) in cases() {
            let mut provider = Provider {
                expected_tag: tag,
                ..Provider::default()
            };
            provider.head.as_mut().unwrap().number = 99;
            let err = verify(&provider, tag).unwrap_err();
            let expected = if tag == EvmFinalityTag::Latest { 3 } else { 8 };
            assert_eq!(err.error_code(), expected, "{tag}: {err}");
        }
    }

    #[test]
    fn receipt_at_selected_head_uses_same_tag_for_both_snapshots() {
        for (tag, verify) in cases() {
            let provider = Provider {
                expected_tag: tag,
                ..Provider::default()
            };
            verify(&provider, tag).unwrap();
            assert_eq!(
                *provider.calls.borrow(),
                ["tag", "receipt", "canonical", "tag_recheck"]
            );
        }
    }

    #[test]
    fn receipt_below_selected_head_is_accepted_with_its_own_canonical_hash() {
        for (tag, verify) in cases() {
            let provider = Provider {
                expected_tag: tag,
                head: Some(BlockData {
                    number: 105,
                    hash: [0x55; 32],
                }),
                ..Provider::default()
            };
            verify(&provider, tag).unwrap();
        }
    }

    #[test]
    fn missing_selected_tag_fails_before_receipt_is_read() {
        for (tag, verify) in cases() {
            let provider = Provider {
                expected_tag: tag,
                head: None,
                ..Provider::default()
            };
            let err = verify(&provider, tag).unwrap_err().to_string();
            assert!(err.contains("block unavailable"), "{err}");
            assert_eq!(*provider.calls.borrow(), ["tag"]);
        }
    }

    #[test]
    fn selected_tag_rpc_error_fails_closed() {
        for (tag, verify) in cases() {
            let provider = Provider {
                expected_tag: tag,
                fail_tag: true,
                ..Provider::default()
            };
            let err = verify(&provider, tag).unwrap_err().to_string();
            assert!(err.contains("tag RPC failed"), "{err}");
            assert_eq!(*provider.calls.borrow(), ["tag"]);
        }
    }

    #[test]
    fn orphaned_receipt_hash_is_rejected() {
        rejects(
            |p| p.canonical.as_mut().unwrap().hash = [0x99; 32],
            "does not match canonical block",
        );
    }

    #[test]
    fn canonical_block_must_exist() {
        rejects(|p| p.canonical = None, "canonical block 100 unavailable");
    }

    #[test]
    fn canonical_rpc_error_fails_closed() {
        rejects(|p| p.fail_canonical = true, "canonical RPC failed");
    }

    #[test]
    fn canonical_response_must_be_for_requested_height() {
        rejects(
            |p| p.canonical.as_mut().unwrap().number = 101,
            "canonical block number mismatch",
        );
    }

    #[test]
    fn head_height_receipt_must_match_original_head_hash() {
        rejects(
            |p| p.head.as_mut().unwrap().hash = [0x99; 32],
            "does not match {tag} block snapshot",
        );
    }

    #[test]
    fn head_regression_cannot_authorize_a_new_fork_receipt() {
        rejects(
            |p| {
                // Snapshot A100, then receipt B95, while a reorg moves the
                // selected head to B90. The old height cannot authorize B95.
                p.head.as_mut().unwrap().hash = [0xaa; 32];
                p.receipt_number = 95;
                p.canonical.as_mut().unwrap().number = 95;
                p.head_after = Some(Some(BlockData {
                    number: 90,
                    hash: [0xbb; 32],
                }));
            },
            "{tag} block regressed",
        );
    }

    #[test]
    fn changing_head_hash_at_same_height_is_rejected() {
        rejects(
            |p| {
                p.head_after = Some(Some(BlockData {
                    number: 100,
                    hash: [0xbb; 32],
                }));
            },
            "{tag} block snapshot changed",
        );
    }

    #[test]
    fn advancing_head_on_a_different_fork_is_rejected() {
        rejects(
            |p| {
                p.head_after = Some(Some(BlockData {
                    number: 101,
                    hash: [0xbb; 32],
                }));
                p.snapshot_canonical = Some(Some(BlockData {
                    number: 100,
                    hash: [0xcc; 32],
                }));
            },
            "{tag} block snapshot changed",
        );
    }

    #[test]
    fn advancing_head_preserving_original_block_is_accepted() {
        for (tag, verify) in cases() {
            let provider = Provider {
                expected_tag: tag,
                head_after: Some(Some(BlockData {
                    number: 101,
                    hash: [0xbb; 32],
                })),
                ..Provider::default()
            };
            verify(&provider, tag).unwrap();
            assert_eq!(
                *provider.calls.borrow(),
                [
                    "tag",
                    "receipt",
                    "canonical",
                    "tag_recheck",
                    "head_ancestor"
                ]
            );
        }
    }

    #[test]
    fn tag_recheck_must_be_available() {
        rejects(|p| p.head_after = Some(None), "block unavailable");
    }

    #[test]
    fn advancing_head_requires_original_block_to_exist() {
        rejects(
            |p| {
                p.head_after = Some(Some(BlockData {
                    number: 101,
                    hash: [0xbb; 32],
                }));
                p.snapshot_canonical = Some(None);
            },
            "original {tag} block 100 unavailable",
        );
    }

    #[test]
    fn advancing_head_requires_original_block_number_to_match() {
        rejects(
            |p| {
                p.head_after = Some(Some(BlockData {
                    number: 101,
                    hash: [0xbb; 32],
                }));
                p.snapshot_canonical = Some(Some(BlockData {
                    number: 99,
                    hash: [0x42; 32],
                }));
            },
            "{tag} block snapshot changed",
        );
    }
}

fn rpc_receipt_json() -> serde_json::Value {
    serde_json::json!({
        "type": "0x2",
        "status": "0x1",
        "cumulativeGasUsed": "0x5208",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x1",
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "transactionHash": format!("0x{}", hex::encode(TX)),
        "transactionIndex": "0x0",
        "blockHash": format!("0x{}", "42".repeat(32)),
        "blockNumber": "0x64",
        "from": format!("0x{}", hex::encode(BRIDGE)),
        "to": format!("0x{}", hex::encode(BRIDGE)),
        "contractAddress": null,
        "logs": []
    })
}

#[test]
fn receipt_mapping_preserves_block_hash() {
    let rpc = serde_json::from_value(rpc_receipt_json()).unwrap();
    let receipt = map_alloy_receipt(rpc).unwrap();
    assert_eq!(receipt.block_number, 100);
    assert_eq!(receipt.block_hash, [0x42; 32]);
}

#[test]
fn receipt_mapping_rejects_missing_or_null_block_hash() {
    let mut missing = rpc_receipt_json();
    missing.as_object_mut().unwrap().remove("blockHash");
    let mut null = rpc_receipt_json();
    null["blockHash"] = serde_json::Value::Null;
    for json in [missing, null] {
        let rpc = serde_json::from_value(json).unwrap();
        let err = map_alloy_receipt(rpc).unwrap_err().to_string();
        assert!(err.contains("no block_hash"), "{err}");
    }
}

// ---- BFA: the `FundsIn` log whose id is the RGB lockId ----

/// A lock keyed by the bare OpId, or by the OpId in another tx, is not the
/// lock of the mint in this tx.
#[test]
fn rejects_funds_in_keyed_by_the_bare_opid_or_another_tx() {
    use crate::networks::rgb::validation::lock_id;
    use bitcoin::hashes::Hash;

    let opid = rgbstd::OpId::from([0xab; 32]);
    let ours = lock_id(opid, bitcoin::Txid::from_byte_array([0x11; 32]));
    let other_tx = lock_id(opid, bitcoin::Txid::from_byte_array([0x22; 32]));
    let mut log = rgb_companion_log(0, 100);
    log.topics[2] = ours;
    assert_eq!(decode_funds_in(&log, &ours).unwrap(), 100);
    for topic in [[0xab; 32], other_tx] {
        log.topics[2] = topic;
        let err = decode_funds_in(&log, &ours).unwrap_err().to_string();
        assert!(err.contains("lockId mismatch"), "{err}");
    }
}

#[test]
fn rejects_funds_in_with_unexpected_layout() {
    // A layout with the id in data, not indexed.
    let mut data = word(0xab).to_vec();
    data.extend_from_slice(&word(100));
    let id_in_data = LogEntry {
        address: BRIDGE,
        topics: vec![event_topic0(FUNDS_IN_SIG), word(0xdead)],
        data,
    };
    assert!(decode_funds_in(&id_in_data, &word(0xab)).is_err());

    let mut extra = rgb_companion_log(0xab, 100);
    extra.topics.push(word(0xab));
    assert!(decode_funds_in(&extra, &word(0xab)).is_err());
}

/// The mint's `beforeBlock` in the lock tests: the lock is at block 100.
const BEFORE_BLOCK: u64 = 110;

/// A real deposit tx emits both: the RGB companion (minted amount) and the
/// BridgeFundsIn record (operationId, netAmount). Block 100.
fn lock_provider() -> FakeEvm {
    FakeEvm {
        receipt: Some(receipt_with(
            vec![
                rgb_companion_log(0xab, 100),
                bridge_log(op_id(7), 1000, 950, 50),
            ],
            100,
        )),
        chain_id: 42161,
    }
}

#[test]
fn verify_rgb_funds_in_accepts_a_verified_lock() {
    let p = lock_provider();
    assert_eq!(
        verify_rgb_funds_in(
            &p,
            &BRIDGE,
            EvmFinalityTag::Safe,
            &TX,
            &word(0xab),
            &op_id(7),
            100,
            BEFORE_BLOCK
        )
        .unwrap(),
        VerifiedLock {
            lock_id: word(0xab),
            minted: 100,
            operation_id: op_id(7),
            net_amount: 950,
        }
    );
}

/// An RGB receiver accepts only a lock in a block before `beforeBlock`.
#[test]
fn verify_rgb_funds_in_refuses_a_lock_at_or_after_before_block() {
    let p = lock_provider();
    for before_block in [100, 99] {
        let e = verify_rgb_funds_in(
            &p,
            &BRIDGE,
            EvmFinalityTag::Safe,
            &TX,
            &word(0xab),
            &op_id(7),
            100,
            before_block,
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("is not before the mint's beforeBlock"),
            "got: {e}"
        );
    }
    assert!(verify_rgb_funds_in(
        &p,
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &word(0xab),
        &op_id(7),
        100,
        101
    )
    .is_ok());
}

/// rgb-lib has no scan window: a lock far below `beforeBlock` still counts.
#[test]
fn verify_rgb_funds_in_accepts_a_lock_far_before_before_block() {
    let p = lock_provider();
    for before_block in [100 + 500_001, u64::MAX] {
        assert!(
            verify_rgb_funds_in(
                &p,
                &BRIDGE,
                EvmFinalityTag::Safe,
                &TX,
                &word(0xab),
                &op_id(7),
                100,
                before_block
            )
            .is_ok(),
            "{before_block}"
        );
    }
}

#[test]
fn node_chain_id_must_be_the_pinned_one() {
    let p = lock_provider();
    assert_eq!(check_node_chain_id(&p, 42161).unwrap(), 42161);
    let e = check_node_chain_id(&p, 1).unwrap_err().to_string();
    assert!(e.contains("reports chain id 42161"), "got: {e}");
}

/// A deposit routed to another chain must not back an RGB mint.
#[test]
fn verify_rgb_funds_in_rejects_a_foreign_destination_chain() {
    let mut bridge = bridge_log(op_id(7), 1000, 950, 50);
    bridge.data[BFI_DEST_CHAIN_ID_OFF..BFI_DEST_CHAIN_ID_OFF + 32].copy_from_slice(&word(42161));
    let p = FakeEvm {
        receipt: Some(receipt_with(
            vec![rgb_companion_log(0xab, 100), bridge],
            100,
        )),
        ..FakeEvm::default()
    };
    let e = verify_rgb_funds_in(
        &p,
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &word(0xab),
        &op_id(7),
        100,
        BEFORE_BLOCK,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("destinationChainId 42161"), "got: {e}");
}

/// The Bridge refuses an RGB deposit that names an address, and no check
/// binds a mint to one. One byte is an address, and so is white space.
#[test]
fn verify_rgb_funds_in_refuses_a_deposit_that_names_a_destination_address() {
    let longest = "x".repeat(BFI_MAX_DEST_ADDRESS_LEN);
    for address in [" ", "\n", "a", DESTINATION, &longest] {
        let mut bridge = bridge_log(op_id(7), 1000, 950, 50);
        bridge.data = bridge_funds_in_data(1000, 950, 50, address);
        let p = FakeEvm {
            receipt: Some(receipt_with(
                vec![rgb_companion_log(0xab, 100), bridge],
                100,
            )),
            ..FakeEvm::default()
        };
        let e = verify_rgb_funds_in(
            &p,
            &BRIDGE,
            EvmFinalityTag::Safe,
            &TX,
            &word(0xab),
            &op_id(7),
            100,
            BEFORE_BLOCK,
        )
        .unwrap_err()
        .to_string();
        let refusal = format!("destinationAddress has {} bytes", address.len());
        assert!(e.contains(&refusal), "{address:?}: {e}");
    }
}

/// Without the record, a `fundsOut` has nothing to cite, so the lock is not
/// settlement evidence.
#[test]
fn verify_rgb_funds_in_requires_the_bridge_funds_in_record() {
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![rgb_companion_log(0xab, 100)], 100)),
        ..FakeEvm::default()
    };
    let e = verify_rgb_funds_in(
        &p,
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &word(0xab),
        &op_id(7),
        100,
        BEFORE_BLOCK,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("no BridgeFundsIn log"), "got: {e}");
}

/// Only the pinned emitter's log can back a mint: an attacker contract can
/// emit the same event.
#[test]
fn verify_rgb_funds_in_rejects_a_log_from_an_unpinned_contract() {
    let mut log = rgb_companion_log(0xab, 100);
    log.address = OTHER;
    let p = FakeEvm {
        receipt: Some(receipt_with(vec![log], 100)),
        ..FakeEvm::default()
    };
    let e = verify_rgb_funds_in(
        &p,
        &BRIDGE,
        EvmFinalityTag::Safe,
        &TX,
        &word(0xab),
        &op_id(7),
        100,
        BEFORE_BLOCK,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("no FundsIn log"), "got: {e}");
}

/// The shared vector, with `rgbNetwork` = `RGB_CHAIN_ID`. The id is a pure
/// function of the 32-byte word, so it holds for a lockId word too.
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
    let mut lock_id = [0u8; 32];
    lock_id[0] = 0xab;
    lock_id[1] = 0x01;
    lock_id[31] = 0x02;

    assert_eq!(
        hex::encode(rgb_mint_deposit_id(&cfg, &lock_id, 100_000).unwrap()),
        "37a9c9b5fe6b36b6ac70e27858cd0408becfe3ee3b10161e27d3faf7fc200d25"
    );
}

/// The BridgeProxy.t.sol vector inputs (bridge-smart-contracts), with
/// `rgbNetwork` = `RGB_CHAIN_ID`. The contract test pins the 96 form.
#[test]
fn rgb_mint_deposit_id_matches_the_contract_vector() {
    let cfg = crate::config::BridgeConfig {
        funds_in_contract: [0x11; 20],
        token_contract: [0x22; 20],
        chain_id: 42161,
        ..Default::default()
    };
    let mut lock_id = [0u8; 32];
    lock_id[29..].copy_from_slice(&[0xab, 0xcd, 0xef]);

    assert_eq!(
        hex::encode(rgb_mint_deposit_id(&cfg, &lock_id, 1_000_000).unwrap()),
        "f275b61cb80792e5a40bf8de0b0d66b3ed9c29b774ea9df36d3ae567eb17c3c4"
    );
}

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

/// The client lives as long as the enclave, so a change of the timeout must
/// reach the next call of a client built before the change.
#[test]
fn a_stalled_call_ends_at_the_timeout_in_force() {
    let stalled = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ca_hex = include_str!("../../../../tests/fixtures/evm_rpc_tls/ca_a.der.hex");
    let client = AlloyEvmClient::with_pinned_tls(&crate::config::EvmRpcTls {
        host: "rpc.test".into(),
        ca_der: hex::decode(ca_hex.trim()).unwrap(),
        tls_port: stalled.local_addr().unwrap().port(),
        path: "/".into(),
    })
    .unwrap();

    crate::limits::change_for_test(|l| l.evm_rpc_timeout_secs = 1);
    let started = std::time::Instant::now();
    let err = client.get_chain_id().unwrap_err().to_string();
    assert!(err.contains("timed out after 1s"), "{err}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
}
