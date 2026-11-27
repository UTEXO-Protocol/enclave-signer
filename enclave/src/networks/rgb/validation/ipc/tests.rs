use std::collections::BTreeSet;
use std::fmt::Debug;
use std::io::Cursor;

use amplify::ByteArray;
use bitcoin::hashes::Hash;
use prost::Message;

use super::super::types::TransitionSummary;
use super::*;
use crate::error::EnclaveError::*;
use crate::framing::{read_frame_within, write_message};

fn block(n: u8) -> WitnessBlock {
    WitnessBlock {
        txid: [n; 32],
        height: 900_000 + u32::from(n),
        hash: [n ^ 0xaa; 32],
    }
}

fn lock(n: u8) -> VerifiedLock {
    VerifiedLock {
        lock_id: [n; 32],
        minted: 1_000 * u64::from(n),
        operation_id: [n ^ 0xff; 32],
        net_amount: 999 * u64::from(n),
    }
}

fn anchor(n: u8) -> MintAnchor {
    MintAnchor {
        opid: [n; 32],
        lock_id: [n ^ 0x0f; 32],
        amount: 7 * u64::from(n),
        before_block: u64::MAX - u64::from(n),
    }
}

fn opout(n: u8) -> OpoutKey {
    OpoutKey {
        op: [n; 32],
        ty: 4_000 + u16::from(n),
        no: u16::from(n),
    }
}

fn entry(n: u8, reject: bool) -> RejectListEntry {
    RejectListEntry {
        opout: opout(n),
        reject,
    }
}

/// A validated burn with blocks, locks and a settling burn.
fn burn() -> ValidatedConsignment {
    ValidatedConsignment {
        contract_id: "rgb:asset".into(),
        chain_net: "bcrt".into(),
        witness_txids: vec![[1; 32], [2; 32]],
        settling_transition: Some(TransitionSummary {
            op_id: hex::encode([0x0b; 32]),
            transition_type: TypeOfTransition::Burn,
            asset_output_amount: 0,
            outputs: vec![],
            burned_asset_amount: Some(1_000),
            burn_reason: Some([0x2e; 32]),
        }),
        settling_witness_txid: Some(bitcoin::Txid::from_byte_array([2; 32])),
        settling_op_id: Some([0x0b; 32]),
        witness_blocks: vec![block(1), block(2)],
        transitions_by_witness: vec![],
        mint_locks: vec![lock(1), lock(2)],
    }
}

/// A settling transition comes with its witness txid and OpId, or the child
/// refuses its own verdict.
#[test]
fn a_settling_transition_without_its_txid_or_opid_is_refused() {
    let halves = [
        ValidatedConsignment {
            settling_witness_txid: None,
            ..burn()
        },
        ValidatedConsignment {
            settling_op_id: None,
            ..burn()
        },
        ValidatedConsignment {
            settling_transition: None,
            ..burn()
        },
    ];
    for half in halves {
        let err = validated(&half).unwrap_err();
        assert!(
            matches!(&err, Internal(text) if text.contains("settling")),
            "{err}"
        );
    }
    let none = ValidatedConsignment {
        settling_transition: None,
        settling_witness_txid: None,
        settling_op_id: None,
        ..burn()
    };
    assert!(validated(&none).unwrap().settling.is_none());
}

/// `message` in a frame, as one end writes it.
fn frame_of(message: &impl Message) -> Vec<u8> {
    let mut wire = Vec::new();
    write_message(&mut wire, message).unwrap();
    wire
}

/// Writes `message` to a frame and decodes it from a `Bytes` of the frame, as
/// the enclave reads a frame of its child.
fn round_trip<M: Message + Default + PartialEq + Debug>(message: &M) {
    let wire = frame_of(message);
    let frame = read_frame_within(&mut Cursor::new(wire), u64::MAX).unwrap();
    assert_eq!(&M::decode(Bytes::from(frame)).unwrap(), message);
}

/// Each message comes back from its frame as it was.
#[test]
fn every_message_round_trips() {
    let limits = crate::proto::Limits::from(&crate::limits::Limits::DEFAULTS);
    let job = Validate {
        consignment_path: "/tmp/utexo-enclave-consignment-7-0.rgb".into(),
        chain_net: "bcrt".into(),
        safe_height: 900_100,
        bind_anchors: true,
        read_reject_list: true,
    };
    let to_child = [
        to_child::Body::Start(Start {
            limits: Some(limits),
            job: Some(start::Job::Validate(job)),
        }),
        to_child::Body::Start(Start {
            limits: Some(limits),
            job: Some(start::Job::Probe(Empty {})),
        }),
        to_child::Body::AssetBound(Empty {}),
        to_child::Body::Bound(Bound {
            evm_chain_id: 421_614,
            locks: pack_locks(&[lock(1), lock(2)]),
        }),
        to_child::Body::Header(vec![0x5a; 80]),
        to_child::Body::Entries(pack_entries(RejectListLog {
            entries: vec![entry(1, true), entry(2, false), entry(1, false)],
            finalized: 2,
        })),
        to_child::Body::Refused(Empty {}),
    ];
    for body in to_child {
        round_trip(&ToChild { body: Some(body) });
    }
    let refused = refusal(&CrossCheck("refused".into()));
    let to_enclave = [
        to_enclave::Body::BindAsset(BindAsset {
            contract_id: Bytes::from_static(b"rgb:asset"),
        }),
        to_enclave::Body::Anchors(Anchors {
            records: Bytes::new(),
        }),
        to_enclave::Body::Anchors(Anchors {
            records: pack_anchors(&[anchor(1)]).into(),
        }),
        to_enclave::Body::Header(1),
        to_enclave::Body::RejectList(ListAddress {
            chain_id: 421_614,
            address: Bytes::from_static(&[0x4e; 20]),
        }),
        to_enclave::Body::Verdict(Verdict {
            outcome: Some(verdict::Outcome::Validated(Box::new(
                validated(&burn()).unwrap(),
            ))),
            peak_rss_bytes: 1 << 30,
        }),
        to_enclave::Body::Verdict(Verdict {
            outcome: Some(verdict::Outcome::Refused(refused)),
            peak_rss_bytes: 0,
        }),
        to_enclave::Body::Verdict(Verdict {
            outcome: Some(held()),
            peak_rss_bytes: 0,
        }),
        to_enclave::Body::Ready(Ready {
            confined: true,
            oom_score_adj: 1_000,
            vm_data_bytes: 1 << 20,
            vm_rss_bytes: 1 << 21,
        }),
    ];
    for body in to_enclave {
        round_trip(&ToEnclave { body: Some(body) });
    }
}

/// Checks one record type: the layout of one record, a list that comes back
/// as it was, and lists one byte longer or shorter, which are refused.
fn check_records<T: PartialEq + Debug>(
    what: &str,
    one: (Vec<u8>, Vec<u8>),
    list: (Vec<u8>, T),
    unpack: fn(&[u8]) -> Result<T, String>,
) {
    let (packed, layout) = one;
    assert_eq!(packed, layout, "{what}");
    let (packed, items) = list;
    assert_eq!(unpack(&packed).unwrap(), items, "{what}");
    let mut longer = packed.clone();
    longer.push(0);
    for bytes in [&longer[..], &packed[..packed.len() - 1]] {
        let err = unpack(bytes).unwrap_err();
        assert!(err.contains(&format!("of {what} records")), "{err}");
    }
}

/// A list of records whose length is not a whole number of records is
/// refused, for each record type. The layouts are written out byte by byte.
#[test]
fn a_record_list_of_another_length_is_refused() {
    let concat = |parts: &[&[u8]]| parts.concat();
    let b = block(1);
    check_records(
        "witness block",
        (
            pack_witness_blocks(&[b]),
            concat(&[&b.txid, &b.height.to_le_bytes(), &b.hash]),
        ),
        (
            pack_witness_blocks(&[block(1), block(2), block(3)]),
            vec![block(1), block(2), block(3)],
        ),
        unpack_witness_blocks,
    );
    let l = lock(1);
    check_records(
        "lock",
        (
            pack_locks(std::slice::from_ref(&l)),
            concat(&[
                &l.lock_id,
                &l.minted.to_le_bytes(),
                &l.operation_id,
                &l.net_amount.to_le_bytes(),
            ]),
        ),
        (pack_locks(&[lock(1), lock(2)]), vec![lock(1), lock(2)]),
        unpack_locks,
    );
    let a = anchor(1);
    check_records(
        "mint anchor",
        (
            pack_anchors(&[a]),
            concat(&[
                &a.opid,
                &a.lock_id,
                &a.amount.to_le_bytes(),
                &a.before_block.to_le_bytes(),
            ]),
        ),
        (
            pack_anchors(&[anchor(1), anchor(2)]),
            vec![anchor(1), anchor(2)],
        ),
        unpack_anchors,
    );
    let e = entry(1, true);
    let entries = vec![entry(3, false), entry(1, true), entry(3, true)];
    check_records(
        "reject-list entry",
        (
            entry_records(vec![e]),
            concat(&[
                &e.opout.op,
                &e.opout.ty.to_le_bytes(),
                &e.opout.no.to_le_bytes(),
                &[1],
            ]),
        ),
        (entry_records(entries.clone()), entries),
        unpack_entry_records,
    );
}

/// The packed entries of `entries`.
fn entry_records(entries: Vec<RejectListEntry>) -> Vec<u8> {
    pack_entries(RejectListLog {
        entries,
        finalized: 0,
    })
    .entries
}

fn unpack_entry_records(bytes: &[u8]) -> Result<Vec<RejectListEntry>, String> {
    let answer = Entries {
        entries: bytes.to_vec(),
        finalized: 0,
    };
    unpack_entries(answer).map(|log| log.entries)
}

/// The entries and the finalized count cross as read, in append order and
/// with repeats. A flag other than 0 or 1 is refused.
#[test]
fn a_reject_list_crosses_as_read() {
    let log = RejectListLog {
        entries: vec![entry(2, false), entry(1, true), entry(2, true)],
        finalized: 1,
    };
    assert_eq!(unpack_entries(pack_entries(log.clone())).unwrap(), log);
    let mut answer = pack_entries(RejectListLog {
        entries: vec![entry(1, true)],
        finalized: 1,
    });
    *answer.entries.last_mut().unwrap() = 2;
    let err = unpack_entries(answer).unwrap_err();
    assert!(err.contains("the flag 2"), "{err}");
}

/// Each of the eight transition types crosses as itself, and a code of no
/// type is refused.
#[test]
fn every_transition_type_crosses_and_an_unknown_one_is_refused() {
    use TypeOfTransition::*;
    let types = [
        Inflate,
        Transfer,
        Burn,
        Link,
        TransferInflation,
        TransferLink,
        Mint,
        Propagate,
    ];
    let codes: BTreeSet<u32> = types.iter().map(|t| transition_code(*t)).collect();
    assert_eq!(codes, (1..=8).collect());
    for transition in types {
        assert_eq!(
            transition_type(transition_code(transition)),
            Some(transition)
        );
    }
    for code in [0, 9, u32::MAX] {
        assert_eq!(transition_type(code), None, "{code}");
    }
}

/// A cross-check, SPV or internal error of the child comes back with its
/// variant and text. An I/O error comes back as an internal error with its
/// display text, with the same code.
#[test]
fn a_child_refusal_keeps_the_variant_and_text_of_its_error() {
    for e in [
        CrossCheck("consignment deserialization failed".into()),
        Spv("witness tx is not proven on chain".into()),
        Internal("scratch path is not UTF-8".into()),
    ] {
        let back = refusal_error(&refusal(&e)).unwrap();
        assert_eq!(
            std::mem::discriminant(&back),
            std::mem::discriminant(&e),
            "{e}"
        );
        assert_eq!(back.to_string(), e.to_string());
        assert_eq!(back.error_code(), e.error_code());
    }
    let io = Io(std::io::Error::other("the file is gone"));
    let back = refusal_error(&refusal(&io)).unwrap();
    assert!(
        matches!(&back, Internal(text) if *text == io.to_string()),
        "{back}"
    );
    assert_eq!(back.error_code(), io.error_code());
}

/// An error with a code of its own, such as a retryable one, comes back from
/// the child as an internal error: only the enclave's own errors keep codes.
#[test]
fn a_child_never_chooses_a_retryable_code() {
    for e in [
        HeadersPending {
            required_tip: 106,
            tip: 104,
            detail: "header 105 is not buried".into(),
        },
        NotReady {
            state: "Ready".into(),
        },
        EvmFinalityPending {
            receipt_block: 100,
            tag: attestation_verify::EvmFinalityTag::Safe,
            finality_block: 99,
        },
    ] {
        assert_ne!(e.error_code(), 1);
        let back = refusal_error(&refusal(&e)).unwrap();
        assert!(matches!(&back, Internal(text) if *text == e.to_string()));
        assert_eq!(back.error_code(), 1, "{e}");
    }
}

/// A refusal of the child gives the reply that the same error gives in the
/// enclave process: the same text, cut at the same place, with its full
/// length. Dispatch returns it unchanged, and a cut never splits a character.
#[test]
fn a_refusal_gives_the_reply_of_the_same_error_in_process() {
    for filler in ["a", "\u{00e9}", "\u{1f600}"] {
        let long = format!("x{}", filler.repeat(4 * MAX_ERROR_TEXT_BYTES));
        for e in [
            CrossCheck(long.clone()),
            Spv(long.clone()),
            Internal(long.clone()),
            CrossCheck("consignment deserialization failed".into()),
            Io(std::io::Error::other(long.clone())),
        ] {
            // The enclave rebuilds any other error as an internal one.
            let shown = match &e {
                Io(_) => Internal(e.to_string()).to_string(),
                _ => e.to_string(),
            };
            let sent = refusal(&e);
            assert!(sent.text.len() <= MAX_ERROR_TEXT_BYTES);
            let back = refusal_error(&sent).unwrap().to_string();
            assert_eq!(back, fit_error_text(shown.clone()));
            assert_eq!(fit_error_text(back.clone()), back);
            if shown.len() > MAX_ERROR_TEXT_BYTES {
                assert!(back.ends_with(&format!("... ({} bytes)", shown.len())));
            }
        }
    }
}

/// A refusal the enclave cannot read breaks the protocol: an unknown kind, a
/// held refusal with no refusal of the enclave behind it, or a bad text.
#[test]
fn a_refusal_the_enclave_cannot_read_breaks_the_protocol() {
    let bytes = |text: &[u8]| Bytes::copy_from_slice(text);
    let cases = [
        (0, bytes(b"refused"), "unknown kind 0"),
        (REFUSAL_HELD + 1, bytes(b"refused"), "unknown kind 5"),
        (REFUSAL_HELD, Bytes::new(), "held refusal"),
        (REFUSAL_CROSS_CHECK, bytes(&[0xff, 0xfe]), "not UTF-8"),
        (
            REFUSAL_CROSS_CHECK,
            bytes(&[b'a'; MAX_ERROR_TEXT_BYTES + 1]),
            "over",
        ),
    ];
    for (kind, text, needle) in cases {
        let err = refusal_error(&Refusal { kind, text }).unwrap_err();
        assert!(err.contains(needle), "{err}");
    }
    let verdict::Outcome::Refused(held_refusal) = held() else {
        panic!("a held outcome is a refusal");
    };
    assert_eq!(held_refusal.kind, REFUSAL_HELD);
    assert!(held_refusal.text.is_empty());
}

/// The enclave decodes a verdict from a `Bytes` of its frame: the records
/// stay in the frame, and the decode adds only a fixed amount of heap.
#[test]
fn a_verdict_decodes_without_copying_its_records() {
    use crate::memory::peak;

    let (frame, decoded, peak) = peak::measure(
        || {
            let consignment = ValidatedConsignment {
                witness_txids: (0..30_000u32).map(|n| [n as u8; 32]).collect(),
                witness_blocks: (0..30_000u32).map(|n| block(n as u8)).collect(),
                mint_locks: (0..10_000u32).map(|n| lock(n as u8)).collect(),
                ..burn()
            };
            let verdict = ToEnclave {
                body: Some(to_enclave::Body::Verdict(Verdict {
                    outcome: Some(verdict::Outcome::Validated(Box::new(
                        validated(&consignment).unwrap(),
                    ))),
                    peak_rss_bytes: 0,
                })),
            };
            Bytes::from(verdict.encode_to_vec())
        },
        |frame| ToEnclave::decode(frame.clone()).unwrap(),
    );
    let Some(to_enclave::Body::Verdict(Verdict {
        outcome: Some(verdict::Outcome::Validated(v)),
        ..
    })) = decoded.body
    else {
        panic!("not a validated verdict");
    };
    let records = v.witness_txids.len() + v.witness_blocks.len() + v.mint_locks.len();
    assert_eq!(
        records,
        30_000 * (WITNESS_TXID_RECORD_BYTES + WITNESS_BLOCK_RECORD_BYTES)
            + 10_000 * LOCK_RECORD_BYTES
    );
    let within = |field: &Bytes| frame.as_ptr_range().contains(&field.as_ptr());
    assert!(within(&v.witness_txids) && within(&v.witness_blocks) && within(&v.mint_locks));
    assert!(
        peak <= 1024,
        "a decode of {records} bytes of records took {peak} bytes"
    );
}

/// The frames that do not grow with the consignment fit
/// `VALIDATOR_FRAME_FIXED_BYTES`: a refusal at the longest text, a verdict
/// with no records and the longest contract id, and each request.
#[test]
fn the_largest_fixed_part_fits_its_frame_bytes() {
    let longest_id = Bytes::from(vec![b'x'; MAX_CONTRACT_ID_BYTES]);
    let longest_refusal = refusal(&CrossCheck("\u{1f600}".repeat(MAX_ERROR_TEXT_BYTES)));
    assert!(longest_refusal.text.len() > MAX_ERROR_TEXT_BYTES - 64);
    let settling = Settling {
        witness_txid: Bytes::from_static(&[0xff; 32]),
        op_id: Bytes::from_static(&[0xff; 32]),
        transition_type: u32::MAX,
        asset_output_amount: u64::MAX,
        burned_asset_amount: Some(u64::MAX),
        burn_reason: Bytes::from_static(&[0xff; 32]),
    };
    let no_records = Validated {
        contract_id: longest_id.clone(),
        chain_net: Bytes::from_static(b"bcrt"),
        witness_blocks: Bytes::new(),
        settling: Some(settling),
        mint_locks: Bytes::new(),
        witness_txids: Bytes::new(),
    };
    let bodies = [
        to_enclave::Body::Verdict(Verdict {
            outcome: Some(verdict::Outcome::Refused(longest_refusal)),
            peak_rss_bytes: u64::MAX,
        }),
        to_enclave::Body::Verdict(Verdict {
            outcome: Some(verdict::Outcome::Validated(Box::new(no_records))),
            peak_rss_bytes: u64::MAX,
        }),
        to_enclave::Body::BindAsset(BindAsset {
            contract_id: longest_id,
        }),
        to_enclave::Body::Anchors(Anchors {
            records: pack_anchors(&[anchor(0xff)]).into(),
        }),
        to_enclave::Body::Header(u32::MAX),
        to_enclave::Body::RejectList(ListAddress {
            chain_id: u64::MAX,
            address: Bytes::from_static(&[0xff; 20]),
        }),
        to_enclave::Body::Ready(Ready {
            confined: true,
            oom_score_adj: i32::MIN,
            vm_data_bytes: u64::MAX,
            vm_rss_bytes: u64::MAX,
        }),
    ];
    for body in bodies {
        let wire = frame_of(&ToEnclave { body: Some(body) });
        assert!(wire.len() <= VALIDATOR_FRAME_FIXED_BYTES, "{}", wire.len());
    }
    // The display form of a contract id is far shorter than the cap.
    let id = rgb_lib::ContractId::from_byte_array([0xff; 32]).to_string();
    assert!(4 * id.len() <= MAX_CONTRACT_ID_BYTES, "{id}");
}

/// A child reads each frame of the enclave under the cap of the list limit:
/// the longest list, also when it is longer than a request frame, and each
/// other frame at the lowest list limit.
#[test]
fn every_frame_of_the_enclave_fits_the_cap_of_its_child() {
    const MIB: u64 = 1024 * 1024;
    let limits = Limits {
        max_message_bytes: MIB,
        max_reject_list_entries: 40_000,
        ..Limits::DEFAULTS
    };
    let entries = |range: std::ops::Range<u32>| -> Vec<RejectListEntry> {
        range
            .map(|n| RejectListEntry {
                opout: OpoutKey {
                    op: [n.to_le_bytes(), [0xab; 4], [0xcd; 4], [0xef; 4]]
                        .concat()
                        .repeat(2)
                        .try_into()
                        .unwrap(),
                    ty: 4_000,
                    no: 0,
                },
                reject: n < 30_000,
            })
            .collect()
    };
    let longest = RejectListLog {
        entries: entries(0..40_000),
        finalized: usize::MAX,
    };
    let wire = frame_of(&ToChild {
        body: Some(to_child::Body::Entries(pack_entries(longest))),
    });
    let cap = enclave_frame_bytes(&limits);
    assert!(wire.len() as u64 > limits.max_message_bytes);
    read_frame_within(&mut Cursor::new(&wire), cap).unwrap();
    assert!(read_frame_within(&mut Cursor::new(&wire), limits.max_message_bytes).is_err());

    let lowest = enclave_frame_bytes(&Limits {
        max_reject_list_entries: 1,
        ..Limits::DEFAULTS
    });
    let start = Start {
        limits: Some((&Limits::DEFAULTS).into()),
        job: Some(start::Job::Validate(Validate {
            consignment_path: "/".repeat(4096),
            chain_net: "bcrt".into(),
            safe_height: u32::MAX,
            bind_anchors: true,
            read_reject_list: true,
        })),
    };
    let bodies = [
        to_child::Body::Start(start),
        to_child::Body::AssetBound(Empty {}),
        to_child::Body::Bound(Bound {
            evm_chain_id: u64::MAX,
            locks: pack_locks(&[lock(0xff)]),
        }),
        to_child::Body::Header(vec![0xff; 80]),
        to_child::Body::Entries(pack_entries(RejectListLog {
            entries: entries(0..1),
            finalized: usize::MAX,
        })),
        to_child::Body::Refused(Empty {}),
    ];
    for body in bodies {
        let wire = frame_of(&ToChild { body: Some(body) });
        read_frame_within(&mut Cursor::new(&wire), lowest).unwrap();
    }
}

/// One list, from the enclave's read to the sets rgb-lib decides from its
/// entries in the child, stays within the rate that `Limits::check` counts.
/// The child runs in process here, through `ListResolver` and rgb-lib's own
/// decision code. The frame of the enclave stays in the count until the
/// child has its sets, as the two processes free their copies in no fixed
/// order. Each size is just past a hash table growth, the worst point of the
/// rate. The validation of the consignment without its list is not counted:
/// the request bound counts it (`limits::DENSE_CONSIGNMENT_RATE_TENTHS`).
#[test]
fn a_list_fits_the_heap_that_the_limits_count() {
    use super::super::reject_list::{ListAccess, RejectListContract};
    use super::super::tests::{bind_all, listed_burn, mined, validator, witness_ids};
    use crate::limits::{change_for_test, REJECT_LIST_ENTRY_BYTES};
    use crate::memory::peak;
    use crate::networks::evm::reject_list::read_reject_list;
    use crate::test_support::{far_deadline, ListEvm};

    const LIST: [u8; 20] = [0x4e; 20];
    change_for_test(|l| {
        l.max_reject_list_entries = 1 << 20;
        l.max_consignment_bytes = 1 << 20;
    });
    let bytes = listed_burn().0.consignment();
    let chain = mined(&witness_ids(&bytes));
    let any_asset = |_: &str| Ok(());
    let measure = |len: u32, reject: bool| {
        let entries: Vec<_> = (0..len)
            .map(|i| {
                let mut op = [0xab; 32];
                op[..4].copy_from_slice(&i.to_be_bytes());
                RejectListEntry {
                    opout: OpoutKey {
                        op,
                        ty: 4000,
                        no: 0,
                    },
                    reject,
                }
            })
            .collect();
        let (_, _, used) = peak::measure(
            || ListEvm::new(1, entries),
            |rpc| {
                // The enclave: `server::reject_list::read_entries`, then the
                // answer of the runner.
                let frame = {
                    let log = read_reject_list(rpc, &LIST, far_deadline()).unwrap();
                    let answer = to_child::Body::Entries(pack_entries(log));
                    ToChild { body: Some(answer) }.encode_to_vec()
                };
                // The child: its read of the frame, then `ListResolver` and
                // rgb-lib.
                let read = |_: &RejectListContract| {
                    let answer = ToChild::decode(&frame.clone()[..]).unwrap();
                    let Some(to_child::Body::Entries(answer)) = answer.body else {
                        panic!("not an answer to a list read");
                    };
                    Ok(unpack_entries(answer).unwrap())
                };
                let lists = ListAccess {
                    bind_asset: &any_asset,
                    read: Some(&read),
                };
                validator().validate_consignment(&bytes, Some(&bind_all), &chain, &lists)
            },
        );
        used
    };
    let without = measure(0, true);
    let mut over = Vec::new();
    for reject in [true, false] {
        for len in [28_673u32, 229_377] {
            let used = measure(len, reject).saturating_sub(without);
            let budget = u64::from(len) * REJECT_LIST_ENTRY_BYTES;
            println!(
                "a list of {len} entries (reject: {reject}): {used} bytes, {:.1} for each \
                 entry, budget {budget}",
                used as f64 / f64::from(len)
            );
            if used as u64 > budget {
                over.push(format!(
                    "{len} entries (reject: {reject}): {used} > {budget}"
                ));
            }
        }
    }
    assert!(over.is_empty(), "lists over the budget: {over:?}");
}
