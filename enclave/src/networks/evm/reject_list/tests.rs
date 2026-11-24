use super::*;
use crate::limits::{change_for_test, Limits};
use crate::test_support::{far_deadline, ListEvm};

const LIST: [u8; 20] = [0x4e; 20];

fn entry_no(no: u16, reject: bool) -> RejectListEntry {
    RejectListEntry {
        opout: OpoutKey {
            op: [0xab; 32],
            ty: 4000,
            no,
        },
        reject,
    }
}

fn list_of(len: u16) -> Vec<RejectListEntry> {
    (0..len).map(|no| entry_no(no, no % 2 == 0)).collect()
}

fn err_of(rpc: &ListEvm) -> String {
    read_reject_list(rpc, &LIST, far_deadline())
        .unwrap_err()
        .to_string()
}

/// rgb-lib calls the same functions.
#[test]
fn selectors_match_rgb_lib() {
    assert_eq!(hex::encode(lengthCall::SELECTOR), "1f7b6d32");
    assert_eq!(hex::encode(entriesCall::SELECTOR), "17b937e6");
}

#[test]
fn reads_pages_of_1000_at_latest() {
    let mut rpc = ListEvm::new(1, list_of(2500));
    rpc.finalized_len = Some(1200);
    let log = read_reject_list(&rpc, &LIST, far_deadline()).unwrap();
    assert_eq!(log.entries, list_of(2500));
    assert_eq!(log.finalized, 1200);
    let pages: Vec<u64> = rpc
        .calls()
        .into_iter()
        .filter(|(selector, _)| *selector == entriesCall::SELECTOR)
        .map(|(_, block)| block)
        .collect();
    assert_eq!(pages, vec![rpc.latest; 3]);
}

#[test]
fn reads_length_at_finalized_then_latest() {
    let rpc = ListEvm::new(1, list_of(3));
    read_reject_list(&rpc, &LIST, far_deadline()).unwrap();
    let lengths: Vec<u64> = rpc
        .calls()
        .into_iter()
        .filter(|(selector, _)| *selector == lengthCall::SELECTOR)
        .map(|(_, block)| block)
        .collect();
    assert_eq!(lengths, vec![100, 200]);
}

/// No code returns no data: refused, not read as an empty list.
#[test]
fn missing_contract_fails_closed() {
    let mut rpc = ListEvm::new(1, vec![]);
    rpc.deployed = false;
    rpc.finalized_len = None;
    assert!(err_of(&rpc).contains("has no contract code"));
}

#[test]
fn contract_absent_at_finalized_has_no_finalized_entries() {
    let mut rpc = ListEvm::new(1, list_of(2));
    rpc.finalized_len = None;
    let log = read_reject_list(&rpc, &LIST, far_deadline()).unwrap();
    assert_eq!(log.finalized, 0);
    assert_eq!(log.entries.len(), 2);
}

#[test]
fn list_shorter_at_latest_fails_closed() {
    let mut rpc = ListEvm::new(1, list_of(1));
    rpc.finalized_len = Some(2);
    assert!(err_of(&rpc).contains("is shorter at the latest block"));
}

#[test]
fn short_page_fails_closed() {
    let mut rpc = ListEvm::new(1, list_of(2));
    rpc.entries_reply = Some(entriesCall::abi_encode_returns(&vec![Entry {
        opId: [1; 32].into(),
        assignmentType: 4000,
        no: 0,
        reject: true,
    }]));
    assert!(err_of(&rpc).contains("returned 1 entries for [0, 2)"));
}

#[test]
fn malformed_abi_fails_closed() {
    let mut rpc = ListEvm::new(1, list_of(1));
    rpc.entries_reply = Some(vec![0x01; 33]);
    assert!(err_of(&rpc).contains("bad entries page"));
}

/// A bool word other than 0 or 1 is not an entry.
#[test]
fn a_non_boolean_reject_flag_fails_closed() {
    let mut reply = entriesCall::abi_encode_returns(&vec![Entry {
        opId: [1; 32].into(),
        assignmentType: 4000,
        no: 0,
        reject: true,
    }]);
    let last = reply.len() - 1;
    reply[last] = 2;
    let mut rpc = ListEvm::new(1, list_of(1));
    rpc.entries_reply = Some(reply);
    assert!(err_of(&rpc).contains("bad entries page"));
}

#[test]
fn finalized_head_is_capped_at_latest() {
    let mut rpc = ListEvm::new(1, list_of(1));
    rpc.finalized = Some(rpc.latest + 5);
    read_reject_list(&rpc, &LIST, far_deadline()).unwrap();
    assert!(rpc.calls().iter().all(|(_, block)| *block == rpc.latest));
}

#[test]
fn no_finalized_block_fails_closed() {
    let mut rpc = ListEvm::new(1, list_of(1));
    rpc.finalized = None;
    assert!(err_of(&rpc).contains("no Finalized block"));
}

#[test]
fn list_over_cap_fails_closed() {
    let mut rpc = ListEvm::new(1, vec![]);
    let max = Limits::DEFAULTS.max_reject_list_entries;
    rpc.entries = vec![entry_no(0, true); max as usize + 1];
    rpc.finalized_len = Some(0);
    assert!(err_of(&rpc).contains("over the 20000"));
    assert!(rpc
        .calls()
        .iter()
        .all(|(selector, _)| *selector == lengthCall::SELECTOR));
}

/// A provider without `eth_call` refuses rather than reading an empty list.
#[test]
fn a_provider_without_eth_call_fails_closed() {
    let rpc = crate::test_support::FakeEvm {
        chain_id: 1,
        ..Default::default()
    };
    let err = read_reject_list(&rpc, &LIST, far_deadline())
        .unwrap_err()
        .to_string();
    assert!(err.contains("makes no eth_call"), "{err}");
}

/// A read that cannot end before the request deadline makes no call, rather
/// than losing the response. It is the validation that ran out of time, not a
/// fault of the list or of the provider, so the backend rechecks it later.
#[test]
fn a_read_past_the_request_deadline_is_a_validation_out_of_time() {
    let rpc = ListEvm::new(1, list_of(10));
    for deadline in [
        std::time::Instant::now(),
        std::time::Instant::now() + crate::conn::RESPONSE_MARGIN / 2,
    ] {
        let err = read_reject_list(&rpc, &LIST, deadline).unwrap_err();
        assert!(matches!(err, EnclaveError::RgbValidationTimedOut), "{err}");
        assert_eq!(err.error_code(), 10);
    }
    assert!(rpc.calls().is_empty());
}

/// A change reaches the next read. The limit decides which list is refused.
/// The page decides how many calls a read takes, and not what it reads.
#[test]
fn the_limit_and_the_page_are_the_values_in_force() {
    let rpc = ListEvm::new(1, list_of(2500));
    change_for_test(|l| l.max_reject_list_entries = 2499);
    assert!(err_of(&rpc).contains("over the 2499"));

    change_for_test(|l| {
        l.max_reject_list_entries = 2500;
        l.reject_list_page_entries = 300;
    });
    let log = read_reject_list(&rpc, &LIST, far_deadline()).unwrap();
    assert_eq!(log.entries, list_of(2500));
    let pages = rpc
        .calls()
        .into_iter()
        .filter(|(selector, _)| *selector == entriesCall::SELECTOR)
        .count();
    assert_eq!(pages, 9, "2500 entries at 300 for each page");
}
