use std::cell::{Cell, RefCell};
use std::os::unix::process::ExitStatusExt;
use std::thread;

use super::super::bfa::MintAnchor;
#[cfg(target_os = "linux")]
use super::super::child::OOM_SCORE_ADJ_MAX;
use super::super::child::{lib_test_entry, FAULT_ENV};
use super::super::reject_list::{RejectListLog, RejectListReader};
use super::super::tests::{
    assert_same, bind_all, burn_bytes, burn_history, listed_burn, mined, open_lists, validator,
    witness_ids, PAYEE,
};
use super::super::types::WitnessBlock;
use super::*;
use crate::memory::peak;
use crate::test_support::bfa_consignment::burn_reason_for;
use crate::test_support::{far_deadline, MinedBlocks};

/// The contract id of the scripted asset binds.
const CONTRACT: &str = "rgb:scripted-asset";
/// The safe height of the scripted header source.
const SAFE: u32 = 10;

/// A kill time no scripted exchange reaches.
fn later() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

/// The values in force of the calling test.
fn in_force() -> Limits {
    crate::limits::get()
}

fn exited(code: i32) -> ExitStatus {
    ExitStatus::from_raw(code << 8)
}

fn signaled(signal: i32) -> ExitStatus {
    ExitStatus::from_raw(signal)
}

/// A wait for headers, with the tips the caller retries on.
fn header_wait() -> EnclaveError {
    EnclaveError::HeadersPending {
        required_tip: 120,
        tip: 100,
        detail: "witness proof: block_height 110 is not buried yet".into(),
    }
}

fn not_ready() -> EnclaveError {
    EnclaveError::NotReady {
        state: "evm-rpc down".into(),
    }
}

fn bump(calls: &Cell<u32>) {
    calls.set(calls.get() + 1);
}

/// A service of the enclave side and the error it fails with.
type Failure = (&'static str, fn() -> EnclaveError);

/// The enclave side of a scripted exchange: it counts each call, serves each
/// request, and fails the service that `fail` names with its error.
#[derive(Default)]
struct Side {
    binds: Cell<u32>,
    anchor_binds: Cell<u32>,
    headers: Cell<u32>,
    reads: Cell<u32>,
    fail: Option<Failure>,
}

impl Side {
    fn failing(service: &'static str, error: fn() -> EnclaveError) -> Self {
        Self {
            fail: Some((service, error)),
            ..Self::default()
        }
    }

    fn error(&self, service: &str) -> Option<EnclaveError> {
        self.fail
            .filter(|(failing, _)| *failing == service)
            .map(|(_, error)| error())
    }

    fn calls(&self) -> u32 {
        self.binds.get() + self.anchor_binds.get() + self.headers.get() + self.reads.get()
    }
}

impl BuriedHeaders for Side {
    fn buried_header(&self, _: u32) -> Result<bitcoin::block::Header> {
        bump(&self.headers);
        match self.error("headers") {
            Some(e) => Err(e),
            None => Ok(bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header),
        }
    }

    fn safe_height(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(SAFE)
    }
}

/// The child's end of a scripted exchange, after its start frame.
struct Peer(UnixStream);

impl Peer {
    /// The enclave may have ended the exchange already, so a send can fail.
    fn send(&mut self, body: to_enclave::Body) {
        let _ = framing::write_message(&mut self.0, &ipc::ToEnclave { body: Some(body) });
    }

    fn recv(&mut self) -> Option<to_child::Body> {
        framing::read_message::<ipc::ToChild>(&mut self.0)
            .ok()?
            .body
    }

    fn ask(&mut self, body: to_enclave::Body) -> Option<to_child::Body> {
        self.send(body);
        self.recv()
    }

    fn bind(&mut self) {
        let answer = self.ask(bind_asset(CONTRACT));
        assert!(
            matches!(answer, Some(to_child::Body::AssetBound(_))),
            "{answer:?}"
        );
    }

    fn verdict(&mut self, outcome: verdict::Outcome) {
        self.send(to_enclave::Body::Verdict(ipc::Verdict {
            outcome: Some(outcome),
            peak_rss_bytes: 0,
        }));
    }
}

fn bind_asset(contract_id: &str) -> to_enclave::Body {
    to_enclave::Body::BindAsset(ipc::BindAsset {
        contract_id: Bytes::copy_from_slice(contract_id.as_bytes()),
    })
}

/// A request to bind `n` anchors.
fn anchors(n: u8) -> to_enclave::Body {
    let anchors: Vec<MintAnchor> = (0..n)
        .map(|i| MintAnchor {
            opid: [i; 32],
            lock_id: [i ^ 0x0f; 32],
            amount: 1_000,
            before_block: 90,
        })
        .collect();
    to_enclave::Body::Anchors(ipc::Anchors {
        records: ipc::pack_anchors(&anchors).into(),
    })
}

fn list_request() -> to_enclave::Body {
    to_enclave::Body::RejectList(ipc::ListAddress {
        chain_id: 42161,
        address: Bytes::from_static(&[0x11; 20]),
    })
}

/// Runs `exchange` against `script`, which plays the child on the other end
/// of a socket pair until `kill_at`. `side` answers, without a binder or a
/// list reader when `without` names them.
fn scripted(
    side: &Side,
    without: &[&str],
    kill_at: Instant,
    script: impl FnOnce(Peer) + Send + 'static,
) -> Exchange {
    let bind_asset = |_: &str| {
        bump(&side.binds);
        side.error("asset").map_or(Ok(()), Err)
    };
    let bind = |anchors: &[MintAnchor]| {
        bump(&side.anchor_binds);
        match side.error("anchors") {
            Some(e) => Err(e),
            None => bind_all(anchors),
        }
    };
    let read = |_: &RejectListContract| {
        bump(&side.reads);
        match side.error("list") {
            Some(e) => Err(e),
            None => Ok(RejectListLog::default()),
        }
    };
    let lists = ListAccess {
        bind_asset: &bind_asset,
        read: (!without.contains(&"list")).then_some(&read as RejectListReader<'_>),
    };
    let services = Services {
        headers: side,
        bind: (!without.contains(&"anchors")).then_some(&bind as AnchorBinder<'_>),
        lists: &lists,
        list_entries: in_force().max_reject_list_entries,
    };
    let (ours, theirs) = UnixStream::pair().unwrap();
    let child = thread::spawn(move || {
        let mut peer = Peer(theirs);
        let first = peer.recv();
        assert!(matches!(first, Some(to_child::Body::Start(_))), "{first:?}");
        script(peer);
    });
    let mut io = DeadlineStream::with_deadline(ours, kill_at, Duration::MAX);
    let start = ipc::Start {
        limits: None,
        job: Some(start::Job::Validate(ipc::Validate::default())),
    };
    let ex = exchange(
        &mut io,
        start,
        VALIDATOR_FRAME_FIXED_BYTES as u64,
        kill_at,
        &services,
    );
    drop(io);
    child.join().unwrap();
    ex
}

fn assert_protocol(ex: &Exchange, what: &str) {
    assert!(
        matches!(&ex.ended, Ended::Protocol(text) if text.contains(what)),
        "{:?}",
        ex.ended
    );
}

/// The result of an exchange that ended so, after an asset bind.
fn bound(ended: Ended) -> Exchange {
    Exchange {
        ended,
        kept: None,
        bound: Some(CONTRACT.into()),
        locks: Sha256::new(),
        requests: 0,
    }
}

fn verdict_of(outcome: verdict::Outcome) -> Ended {
    Ended::Verdict(ipc::Verdict {
        outcome: Some(outcome),
        peak_rss_bytes: 0,
    })
}

/// A verdict on `CONTRACT` that passes every check.
fn valid() -> ipc::Validated {
    let block = WitnessBlock {
        txid: [0x01; 32],
        height: SAFE,
        hash: [0x02; 32],
    };
    ipc::Validated {
        contract_id: Bytes::from_static(CONTRACT.as_bytes()),
        chain_net: Bytes::from_static(b"bcrt"),
        witness_blocks: ipc::pack_witness_blocks(&[block]).into(),
        settling: None,
        mint_locks: Bytes::new(),
        witness_txids: Bytes::from_static(&[0x01; 32]),
    }
}

fn outcome_of(ex: Exchange, status: ExitStatus) -> Result<ValidatedConsignment> {
    outcome(
        ex,
        Ok(status),
        ChainNet::BitcoinRegtest,
        NonZeroU32::new(SAFE),
    )
}

/// A request before the asset bind breaks the protocol, and the enclave
/// serves nothing for it.
#[test]
fn the_enclave_refuses_a_request_before_the_asset_bind() {
    let side = Side::default();
    for request in [to_enclave::Body::Header(1), anchors(1), list_request()] {
        let ex = scripted(&side, &[], later(), move |mut peer| peer.send(request));
        assert_protocol(&ex, "a request before the asset bind");
        assert!(ex.kept.is_none());
    }
    assert_eq!(side.calls(), 0);
}

/// The enclave reads the list once, only after the asset bind, and only when
/// it has a reader.
#[test]
fn the_reject_list_is_read_once_and_only_after_the_bind() {
    let side = Side::default();
    let ex = scripted(&side, &[], later(), |mut peer| peer.send(list_request()));
    assert_protocol(&ex, "a request before the asset bind");
    assert_eq!(side.reads.get(), 0);

    let ex = scripted(&side, &[], later(), |mut peer| {
        peer.bind();
        let answer = peer.ask(list_request());
        assert!(
            matches!(answer, Some(to_child::Body::Entries(_))),
            "{answer:?}"
        );
        peer.send(list_request());
    });
    assert_protocol(&ex, "a second reject-list read");
    assert_eq!(side.reads.get(), 1);

    let ex = scripted(&side, &["list"], later(), |mut peer| {
        peer.bind();
        peer.send(list_request());
    });
    assert_protocol(&ex, "the enclave reads no list");
    assert_eq!(side.reads.get(), 1);
}

/// A request that the enclave cannot take as it is breaks the protocol, and
/// the enclave serves nothing for it. The longest contract id binds.
#[test]
fn a_malformed_request_breaks_the_protocol() {
    let list = |len: usize| {
        to_enclave::Body::RejectList(ipc::ListAddress {
            chain_id: 42161,
            address: Bytes::from(vec![0x11; len]),
        })
    };
    let long = "a".repeat(ipc::MAX_CONTRACT_ID_BYTES + 1);
    let not_utf8 = to_enclave::Body::BindAsset(ipc::BindAsset {
        contract_id: Bytes::from_static(&[0xff, 0xfe]),
    });
    let ready = to_enclave::Body::Ready(ipc::Ready::default());
    let cases = [
        (
            false,
            bind_asset(&long),
            format!("a contract id of {} bytes", long.len()),
        ),
        (false, not_utf8, "a contract id that is not UTF-8".into()),
        (true, bind_asset(CONTRACT), "a second asset bind".into()),
        (
            true,
            to_enclave::Body::Header(0),
            "a header at height 0".into(),
        ),
        (true, list(19), "a list address of 19 bytes".into()),
        (true, list(21), "a list address of 21 bytes".into()),
        (true, ready, "a frame that is not a request".into()),
    ];
    for (after_bind, request, what) in cases {
        let side = Side::default();
        let ex = scripted(&side, &[], later(), move |mut peer| {
            if after_bind {
                peer.bind();
            }
            peer.send(request);
        });
        assert_protocol(&ex, &what);
        assert_eq!(side.calls(), u32::from(after_bind), "{what}");
    }

    let side = Side::default();
    let ex = scripted(&side, &[], later(), |mut peer| {
        let longest = "a".repeat(ipc::MAX_CONTRACT_ID_BYTES);
        let answer = peer.ask(bind_asset(&longest));
        assert!(
            matches!(answer, Some(to_child::Body::AssetBound(_))),
            "{answer:?}"
        );
    });
    assert!(matches!(ex.ended, Ended::Closed), "{:?}", ex.ended);
}

/// After the enclave refused a request, it serves no other: the next one
/// breaks the protocol, and the kept error stays the result.
#[test]
fn a_request_after_a_refusal_breaks_the_protocol() {
    let side = Side::failing("headers", header_wait);
    let ex = scripted(&side, &[], later(), |mut peer| {
        peer.bind();
        let answer = peer.ask(to_enclave::Body::Header(1));
        assert!(
            matches!(answer, Some(to_child::Body::Refused(_))),
            "{answer:?}"
        );
        peer.send(anchors(1));
    });
    assert_protocol(&ex, "a request after the enclave refused one");
    assert_eq!(side.anchor_binds.get(), 0);
    let err = outcome_of(ex, exited(0)).unwrap_err();
    assert_eq!(err.error_code(), 9, "{err}");
}

/// Mint anchors need a binder, and come one at a time in whole records.
#[test]
fn anchors_without_a_binder_or_with_two_records_are_refused() {
    let side = Side::default();
    let ex = scripted(&side, &["anchors"], later(), |mut peer| {
        peer.bind();
        peer.send(anchors(1));
    });
    assert_protocol(&ex, "the enclave binds no anchor");
    let ex = scripted(&side, &[], later(), |mut peer| {
        peer.bind();
        peer.send(anchors(2));
    });
    assert_protocol(&ex, "bytes of mint anchors in one request, over one record");
    let ex = scripted(&side, &[], later(), |mut peer| {
        peer.bind();
        peer.send(to_enclave::Body::Anchors(ipc::Anchors {
            records: Bytes::from(vec![0; ipc::ANCHOR_RECORD_BYTES - 1]),
        }));
    });
    assert_protocol(&ex, "not a whole number");
    assert_eq!(side.anchor_binds.get(), 0);

    // No record asks for the chain id. One record gets its lock.
    let ex = scripted(&side, &[], later(), |mut peer| {
        peer.bind();
        for n in [0, 1] {
            let answer = peer.ask(anchors(n));
            let Some(to_child::Body::Bound(bound)) = answer else {
                panic!("{answer:?}");
            };
            assert_eq!(bound.evm_chain_id, 42161);
            let locks = ipc::unpack_locks(&bound.locks).unwrap();
            assert_eq!(locks.len(), usize::from(n));
        }
    });
    assert!(matches!(ex.ended, Ended::Closed), "{:?}", ex.ended);
    assert_eq!((side.anchor_binds.get(), ex.requests), (2, 3));
    // The enclave keeps the digest of the one lock it bound.
    let to_child::Body::Bound(one) = answer_of(anchors(1)) else {
        unreachable!()
    };
    assert_eq!(ex.locks.finalize(), Sha256::digest(&one.locks));
}

/// The enclave's answer to an `Anchors` request, from the test binder.
fn answer_of(request: to_enclave::Body) -> to_child::Body {
    let to_enclave::Body::Anchors(ask) = request else {
        unreachable!()
    };
    let anchors = ipc::unpack_anchors(&ask.records).unwrap();
    let bound = bind_all(&anchors).unwrap();
    to_child::Body::Bound(ipc::Bound {
        evm_chain_id: bound.evm_chain_id,
        locks: ipc::pack_locks(&bound.locks),
    })
}

/// A kept refusal is the result, with its own code and tips, whatever the
/// child does after it.
#[test]
fn the_enclave_error_wins_whatever_the_child_ends_with() {
    let side = Side::failing("headers", header_wait);
    type End = (&'static str, fn(&mut Peer));
    let ends: [End; 5] = [
        ("held", |peer| peer.verdict(ipc::held())),
        ("validated", |peer| {
            peer.verdict(verdict::Outcome::Validated(Box::new(valid())))
        }),
        ("eof", |_| {}),
        ("stall", |peer| {
            peer.recv();
        }),
        ("another request", |peer| {
            peer.send(to_enclave::Body::Header(2))
        }),
    ];
    for (end, act) in ends {
        let kill_at = Instant::now() + Duration::from_secs(2);
        let ex = scripted(&side, &[], kill_at, move |mut peer| {
            peer.bind();
            let answer = peer.ask(to_enclave::Body::Header(1));
            assert!(
                matches!(answer, Some(to_child::Body::Refused(_))),
                "{answer:?}"
            );
            act(&mut peer);
        });
        let err = outcome_of(ex, signaled(9)).unwrap_err();
        assert!(
            matches!(
                err,
                EnclaveError::HeadersPending {
                    required_tip: 120,
                    tip: 100,
                    ..
                }
            ),
            "{end}: {err}"
        );
        assert_eq!(err.error_code(), 9, "{end}");
    }
}

/// A failing asset bind, binder, header source or list reader refuses with
/// its own error, not with a text of the child.
#[test]
fn a_failing_callback_refuses_with_its_own_error_through_the_child() {
    let cases = [
        ("asset", None),
        ("anchors", Some(anchors(1))),
        ("headers", Some(to_enclave::Body::Header(1))),
        ("list", Some(list_request())),
    ];
    for (service, request) in cases {
        let side = Side::failing(service, not_ready);
        let ex = scripted(&side, &[], later(), move |mut peer| {
            let answer = match request {
                None => peer.ask(bind_asset(CONTRACT)),
                Some(request) => {
                    peer.bind();
                    peer.ask(request)
                }
            };
            assert!(
                matches!(answer, Some(to_child::Body::Refused(_))),
                "{answer:?}"
            );
            peer.verdict(ipc::held());
        });
        let err = outcome_of(ex, exited(0)).unwrap_err();
        assert!(
            matches!(&err, EnclaveError::NotReady { state } if state == "evm-rpc down"),
            "{service}: {err}"
        );
    }
}

/// A real verdict passes, also with no witness and no settling transition; a
/// change of one property fails its own check with code 1. A witness with no
/// block passes them, and the enclave's own B3.2 check refuses it.
#[test]
fn a_verdict_the_enclave_cannot_accept_is_refused() {
    let bytes = burn_bytes();
    let chain = mined(&witness_ids(&bytes));
    let validated = validator()
        .validate_consignment(&bytes, Some(&bind_all), &chain, &open_lists())
        .unwrap();
    let safe = chain.safe_height();
    let good = ipc::validated(&validated).unwrap();
    // The enclave bound the locks of the good verdict.
    let mut answered = Sha256::new();
    answered.update(&good.mint_locks);
    let accept = |v: ipc::Validated| {
        let ex = Exchange {
            ended: verdict_of(verdict::Outcome::Validated(Box::new(v))),
            kept: None,
            bound: Some(validated.contract_id.clone()),
            locks: answered.clone(),
            requests: 0,
        };
        outcome(ex, Ok(exited(0)), ChainNet::BitcoinRegtest, safe)
    };
    assert_same(&accept(good.clone()).unwrap(), &validated);
    let genesis_alone = ipc::Validated {
        witness_txids: Bytes::new(),
        witness_blocks: Bytes::new(),
        settling: None,
        ..good.clone()
    };
    let alone = accept(genesis_alone).unwrap();
    assert!(alone.witness_blocks.is_empty(), "{alone:?}");
    assert!(alone.settling_transition.is_none(), "{alone:?}");

    let reorder = |v: &mut ipc::Validated, change: &dyn Fn(&mut Vec<WitnessBlock>)| {
        let mut blocks = ipc::unpack_witness_blocks(&v.witness_blocks).unwrap();
        change(&mut blocks);
        v.witness_blocks = ipc::pack_witness_blocks(&blocks).into();
    };
    let retxid = |v: &mut ipc::Validated, change: &dyn Fn(&mut Vec<[u8; 32]>)| {
        let mut txids = ipc::unpack_witness_txids(&v.witness_txids).unwrap();
        change(&mut txids);
        v.witness_txids = ipc::pack_witness_txids(&txids).into();
    };
    let safe_height = safe.map_or(0, NonZeroU32::get);
    let above = format!(
        "a witness block at height {}, not from 1 to {safe_height}",
        safe_height + 1
    );
    let not_a_witness = "a settling witness that is not a witness of the consignment";
    type Change<'a> = (&'a str, &'a dyn Fn(&mut ipc::Validated), &'a str);
    let cases: [Change<'_>; 13] = [
        (
            "another contract",
            &|v| v.contract_id = Bytes::from_static(b"rgb:another-asset"),
            "a verdict on another contract than the bound one",
        ),
        (
            "another chain",
            &|v| v.chain_net = Bytes::from_static(b"bc"),
            "a verdict on another chain than bcrt",
        ),
        (
            "witness txids out of order",
            &|v| retxid(v, &|t| t.swap(0, 1)),
            "witness txids out of order",
        ),
        (
            "a witness txid twice",
            &|v| retxid(v, &|t| t.insert(0, t[0])),
            "witness txids out of order",
        ),
        (
            "a witness txid record of another length",
            &|v| v.witness_txids.truncate(v.witness_txids.len() - 1),
            "witness txid records, not a whole number",
        ),
        (
            "txids out of order",
            &|v| reorder(v, &|b| b.swap(0, 1)),
            "witness blocks out of txid order",
        ),
        (
            "a txid twice",
            &|v| reorder(v, &|b| b.insert(0, b[0])),
            "witness blocks out of txid order",
        ),
        (
            "a height above the safe one",
            &|v| reorder(v, &|b| b[0].height = safe_height + 1),
            &above,
        ),
        (
            "a height of 0",
            &|v| reorder(v, &|b| b[0].height = 0),
            "a witness block at height 0, not from 1 to",
        ),
        (
            "a settling txid of no witness",
            &|v| v.settling.as_mut().unwrap().witness_txid = Bytes::from_static(&[0x77; 32]),
            not_a_witness,
        ),
        (
            "an unknown type",
            &|v| v.settling.as_mut().unwrap().transition_type = 9,
            "the unknown transition type 9",
        ),
        (
            "a record of another length",
            &|v| v.witness_blocks.truncate(v.witness_blocks.len() - 1),
            "witness block records, not a whole number",
        ),
        (
            "a lock the enclave did not bind",
            &|v| {
                let extra = [0x5c; ipc::LOCK_RECORD_BYTES];
                v.mint_locks = [v.mint_locks.as_ref(), &extra[..]].concat().into();
            },
            "mint locks other than the ones the enclave bound",
        ),
    ];
    for (case, change, refusal) in cases {
        let mut v = good.clone();
        change(&mut v);
        let err = accept(v).unwrap_err();
        assert_eq!(err.error_code(), 1, "{case}: {err}");
        let text = err.to_string();
        assert!(text.contains("broke its protocol"), "{case}: {text}");
        assert!(text.contains(refusal), "{case}: {text}");
    }

    use crate::networks::evm::crosscheck::assert_witnesses_confirmed;
    assert_witnesses_confirmed(&accept(good.clone()).unwrap()).unwrap();
    let unplaced = ipc::Validated {
        witness_blocks: Bytes::new(),
        ..good
    };
    let err = assert_witnesses_confirmed(&accept(unplaced).unwrap()).unwrap_err();
    assert_eq!(err.error_code(), 3, "{err}");
    assert!(err.to_string().contains("placed 0 of"), "{err}");
}

/// Each way a validation ends maps to its error and wire code, in the order
/// the enclave decides them.
#[test]
fn each_outcome_maps_to_its_wire_code() {
    let code = |ex: Exchange, status: ExitStatus| {
        outcome_of(ex, status).map_or_else(|e| e.error_code(), |_| 0)
    };
    let text = |ex: Exchange, status: ExitStatus| outcome_of(ex, status).unwrap_err().to_string();

    // The enclave's kept error first.
    let kept = Exchange {
        kept: Some(header_wait()),
        ..bound(Ended::Closed)
    };
    assert_eq!(code(kept, signaled(6)), 9);
    // A verdict that passes its checks.
    let validated = verdict_of(verdict::Outcome::Validated(Box::new(valid())));
    assert_eq!(code(bound(validated), exited(0)), 0);
    // A refusal of the child keeps its kind.
    for (kind, wire) in [
        (ipc::REFUSAL_CROSS_CHECK, 3),
        (ipc::REFUSAL_SPV, 3),
        (ipc::REFUSAL_INTERNAL, 1),
    ] {
        let refused = verdict_of(verdict::Outcome::Refused(ipc::Refusal {
            kind,
            text: Bytes::from_static(b"refused"),
        }));
        assert_eq!(code(bound(refused), exited(0)), wire, "kind {kind}");
    }
    // The kill time.
    let err = outcome_of(bound(Ended::Deadline), signaled(9)).unwrap_err();
    assert!(matches!(err, EnclaveError::RgbValidationTimedOut), "{err}");
    assert_eq!(err.error_code(), 10);
    // A child that ended before its verdict.
    #[cfg(target_os = "linux")]
    for (signal, name) in CRASH_SIGNALS {
        let err = outcome_of(bound(Ended::Closed), signaled(signal)).unwrap_err();
        assert_eq!(err.error_code(), 3, "{err}");
        assert!(err
            .to_string()
            .contains(&format!("signal {signal} ({name})")));
    }
    #[cfg(target_os = "linux")]
    {
        let oom = text(bound(Ended::Closed), signaled(nix::libc::SIGKILL));
        assert!(oom.contains("runs out of memory"), "{oom}");
    }
    #[cfg(not(target_os = "linux"))]
    assert!(text(bound(Ended::Closed), signaled(6)).contains("ended with signal: 6"));
    assert_eq!(code(bound(Ended::Closed), signaled(9)), 1);
    assert_eq!(code(bound(Ended::Closed), signaled(15)), 1);
    let early = text(bound(Ended::Closed), exited(3));
    assert!(
        early.contains("ended with exit status: 3 before its verdict"),
        "{early}"
    );
    let unreaped = outcome(
        bound(Ended::Closed),
        Err(io::Error::other("no child")),
        ChainNet::BitcoinRegtest,
        NonZeroU32::new(SAFE),
    );
    assert_eq!(unreaped.unwrap_err().error_code(), 1);
    // A broken protocol.
    let unbound = Exchange {
        bound: None,
        ..bound(verdict_of(verdict::Outcome::Validated(Box::new(valid()))))
    };
    for broken in [
        bound(Ended::Protocol("a frame with no message".into())),
        bound(verdict_of(ipc::held())),
        bound(Ended::Verdict(ipc::Verdict::default())),
        unbound,
    ] {
        let err = text(broken, exited(0));
        assert!(
            err.contains("the RGB validator broke its protocol"),
            "{err}"
        );
    }
}

/// The scratch files of this process that hold `bytes`.
fn scratch_files_holding(bytes: &[u8]) -> usize {
    let prefix = format!("utexo-enclave-consignment-{}-", std::process::id());
    std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .filter(|entry| std::fs::read(entry.path()).is_ok_and(|held| held == bytes))
        .count()
}

/// A validator whose child is the lib entry of this test binary, acting out
/// `fault`.
fn faulty(fault: &str) -> RgbValidator {
    let program = ChildProgram::test_entry(lib_test_entry())
        .unwrap()
        .with_env(FAULT_ENV, fault);
    validator().with_program(program)
}

/// A request deadline that leaves the child `budget`.
fn deadline_in(budget: Duration) -> Instant {
    Instant::now() + RESPONSE_MARGIN + budget
}

/// The enclave ends a child at the kill time and reaps it, and the reply
/// still has time before the deadline.
#[test]
fn a_validator_past_the_deadline_is_ended_and_reaped() {
    let pid = RefCell::new(None);
    let record = |id: &str| {
        *pid.borrow_mut() = id.parse::<u32>().ok();
        Ok(())
    };
    let lists = ListAccess {
        bind_asset: &record,
        read: None,
    };
    let bytes = b"the file of a validator that hangs".to_vec();
    let deadline = deadline_in(Duration::from_secs(2));
    let err = faulty("hang")
        .validate_in_child(
            &bytes,
            None,
            &MinedBlocks::of(&[]),
            &lists,
            &in_force(),
            deadline,
        )
        .unwrap_err();
    assert!(Instant::now() < deadline);
    assert!(matches!(err, EnclaveError::RgbValidationTimedOut), "{err}");
    let pid = pid.into_inner().expect("the child sent its pid");
    assert_ne!(pid, std::process::id());
    #[cfg(target_os = "linux")]
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    assert_eq!(scratch_files_holding(&bytes), 0);
}

/// Sleeps until `at`.
fn sleep_until(at: Instant) {
    thread::sleep(at.saturating_duration_since(Instant::now()));
}

/// The state letter of process `pid` as `ps` gives it, while it exists.
fn process_state(pid: u32) -> Option<char> {
    let out = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().chars().next()
}

/// The kill timer ends a child at the kill time while the worker is still in
/// an answer that does not watch the time. The reply comes before the
/// deadline.
#[test]
fn the_kill_timer_ends_a_child_while_the_worker_answers_it() {
    let pid = Cell::new(None);
    let record = |id: &str| {
        pid.set(id.parse::<u32>().ok());
        Ok(())
    };
    let deadline = deadline_in(Duration::from_millis(1_500));
    let kill_at = deadline - RESPONSE_MARGIN;
    let slow = |_: &RejectListContract| {
        sleep_until(kill_at + RESPONSE_MARGIN / 4);
        // Killed, and not reaped while the worker is here.
        assert_eq!(process_state(pid.get().unwrap()), Some('Z'));
        sleep_until(kill_at + RESPONSE_MARGIN / 2);
        Ok(RejectListLog::default())
    };
    let lists = ListAccess {
        bind_asset: &record,
        read: Some(&slow),
    };
    let err = faulty("list")
        .validate_in_child(
            b"the file of a validator that asks for its list",
            None,
            &MinedBlocks::of(&[]),
            &lists,
            &in_force(),
            deadline,
        )
        .unwrap_err();
    assert!(Instant::now() < deadline);
    assert!(matches!(err, EnclaveError::RgbValidationTimedOut), "{err}");
    let pid = pid.get().expect("the child sent its pid");
    assert_ne!(pid, std::process::id());
    assert_eq!(process_state(pid), None);
}

/// A listed burn whose list read is still open at the kill time: the call ends
/// there, long before `evm_rpc_timeout_secs`, and the burn is refused before
/// the deadline as a validation that ran out of time. The read is the last
/// step of a validation, so a slow one leaves it too little time with a
/// healthy provider too, and a retry would cost the whole validation again.
#[test]
fn a_stalled_list_read_ends_at_the_kill_time() {
    let stalled = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = crate::test_support::stalled_evm_client(&stalled);
    let read = |_: &RejectListContract| {
        crate::networks::evm::events::check_node_chain_id(&client, 42161)
            .map(|_| RejectListLog::default())
    };
    let any_asset = |_: &str| Ok(());
    let lists = ListAccess {
        bind_asset: &any_asset,
        read: Some(&read),
    };
    let bytes = listed_burn().0.consignment();
    let chain = mined(&witness_ids(&bytes));
    let budget = Duration::from_secs(3);
    let rpc_timeout = Duration::from_secs(in_force().evm_rpc_timeout_secs);
    assert!(rpc_timeout > budget + RESPONSE_MARGIN);
    let deadline = deadline_in(budget);
    let err = validator()
        .validate_in_child(
            &bytes,
            Some(&bind_all),
            &chain,
            &lists,
            &in_force(),
            deadline,
        )
        .unwrap_err();
    assert!(Instant::now() < deadline);
    assert!(matches!(err, EnclaveError::RgbValidationTimedOut), "{err}");
    assert_eq!(err.error_code(), 10);
}

/// With no time left for a child, the validation times out before a spawn.
#[test]
fn no_time_left_starts_no_validator() {
    let missing = validator().with_program(ChildProgram::binary("/no/such/validator"));
    let err = missing
        .validate_in_child(
            b"no time",
            None,
            &MinedBlocks::of(&[]),
            &open_lists(),
            &in_force(),
            Instant::now() + RESPONSE_MARGIN / 2,
        )
        .unwrap_err();
    assert!(
        matches!(&err, EnclaveError::Io(e) if e.kind() == io::ErrorKind::TimedOut),
        "{err}"
    );
    assert!(err
        .to_string()
        .contains("request deadline passed before RGB validation"));
}

/// A child that does not start is a fault of the enclave, as is a validator
/// with no program.
#[test]
fn a_validator_that_cannot_start_is_an_enclave_fault() {
    let missing = validator().with_program(ChildProgram::binary("/no/such/validator"));
    let err = missing
        .validate_in_child(
            b"no child",
            None,
            &MinedBlocks::of(&[]),
            &open_lists(),
            &in_force(),
            far_deadline(),
        )
        .unwrap_err();
    assert_eq!(err.error_code(), 1, "{err}");
    assert!(err
        .to_string()
        .contains("cannot start the RGB validator /no/such/validator"));
    let none = RgbValidator::for_chain_net(ChainNet::BitcoinRegtest)
        .validate_in_child(
            b"no program",
            None,
            &MinedBlocks::of(&[]),
            &open_lists(),
            &in_force(),
            far_deadline(),
        )
        .unwrap_err();
    assert_eq!(none.error_code(), 1, "{none}");
}

/// A panic ends only the child. On Linux the burn is refused with code 3,
/// as a retry repeats the crash.
#[test]
fn a_panicking_validator_refuses_the_burn() {
    let err = faulty("panic")
        .validate_in_child(
            b"the file of a validator that panics",
            None,
            &MinedBlocks::of(&[]),
            &open_lists(),
            &in_force(),
            far_deadline(),
        )
        .unwrap_err();
    let text = err.to_string();
    #[cfg(target_os = "linux")]
    {
        assert_eq!(err.error_code(), 3, "{text}");
        assert!(text.contains("signal 6 (SIGABRT)"), "{text}");
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(err.error_code(), 1, "{text}");
        assert!(text.contains("signal: 6"), "{text}");
    }
}

/// A child that exits before its verdict is a fault of the enclave.
#[test]
fn a_validator_that_exits_early_is_an_enclave_fault() {
    let err = faulty("exit")
        .validate_in_child(
            b"the file of a validator that exits",
            None,
            &MinedBlocks::of(&[]),
            &open_lists(),
            &in_force(),
            far_deadline(),
        )
        .unwrap_err();
    assert_eq!(err.error_code(), 1, "{err}");
    assert!(err
        .to_string()
        .contains("ended with exit status: 3 before its verdict"));
}

/// A frame that does not decode ends the child. A frame over the cap is
/// refused before the enclave allocates it.
#[test]
fn a_validator_that_breaks_the_protocol_is_ended() {
    let bytes = b"the file of a validator that breaks the protocol".to_vec();
    let run = |validator: &RgbValidator| {
        validator.validate_in_child(
            &bytes,
            None,
            &MinedBlocks::of(&[]),
            &open_lists(),
            &in_force(),
            far_deadline(),
        )
    };
    let err = run(&faulty("garbage")).unwrap_err();
    assert_eq!(err.error_code(), 1, "{err}");
    assert!(
        err.to_string()
            .contains("broke its protocol: a frame that does not decode"),
        "{err}"
    );
    let (_, result, peak) = peak::measure(|| faulty("oversized"), run);
    let err = result.unwrap_err();
    assert!(err.to_string().contains("message too large"), "{err}");
    println!("an oversized frame of a child: peak heap {peak} bytes");
    assert!(peak < VALIDATOR_FRAME_FIXED_BYTES, "{peak}");
}

/// A header wait the enclave kept is the result after the child aborts.
#[test]
fn a_header_wait_wins_over_a_validator_that_then_aborts() {
    let side = Side::failing("headers", header_wait);
    let err = faulty("header-then-abort")
        .validate_in_child(
            b"the file of a validator that aborts",
            None,
            &side,
            &open_lists(),
            &in_force(),
            far_deadline(),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            EnclaveError::HeadersPending {
                required_tip: 120,
                tip: 100,
                ..
            }
        ),
        "{err}"
    );
}

/// The child sees no variable of the enclave process but `RUST_LOG`.
#[test]
fn the_validator_child_gets_only_the_log_filter_of_the_enclave() {
    assert!(std::env::vars_os().any(|(key, _)| key != "RUST_LOG"));
    let bytes = burn_bytes();
    let chain = mined(&witness_ids(&bytes));
    faulty("env")
        .validate_in_child(
            &bytes,
            Some(&bind_all),
            &chain,
            &open_lists(),
            &in_force(),
            far_deadline(),
        )
        .expect("the child saw no variable of the test process");
}

/// The scratch file is there while the child runs, and gone after a pass, a
/// refusal, an end at the kill time and a crash.
#[test]
fn the_scratch_file_is_gone_after_every_outcome() {
    let pass = burn_history(Some(54_321), Some(burn_reason_for(PAYEE)))
        .0
        .consignment();
    let chain = mined(&witness_ids(&pass));
    let held = Cell::new(0);
    let bind_asset = |_: &str| {
        held.set(scratch_files_holding(&pass));
        Ok(())
    };
    let lists = ListAccess {
        bind_asset: &bind_asset,
        read: None,
    };
    validator()
        .validate_in_child(
            &pass,
            Some(&bind_all),
            &chain,
            &lists,
            &in_force(),
            far_deadline(),
        )
        .expect("a valid burn");
    assert_eq!(held.get(), 1);
    assert_eq!(scratch_files_holding(&pass), 0);

    let cases: [(&str, &[u8], Duration); 3] = [
        (
            "refusal",
            b"a file the validator refuses",
            Duration::from_secs(60),
        ),
        (
            "hang",
            b"a file of a validator that hangs",
            Duration::from_secs(2),
        ),
        (
            "abort",
            b"a file of a validator that aborts",
            Duration::from_secs(60),
        ),
    ];
    for (case, bytes, budget) in cases {
        let validator = match case {
            "refusal" => validator(),
            fault => faulty(fault),
        };
        let result = validator.validate_in_child(
            bytes,
            None,
            &MinedBlocks::of(&[]),
            &open_lists(),
            &in_force(),
            deadline_in(budget),
        );
        assert!(result.is_err(), "{case}");
        assert_eq!(scratch_files_holding(bytes), 0, "{case}");
    }
}

/// The child closes a descriptor it inherited without close-on-exec.
#[cfg(target_os = "linux")]
#[test]
fn a_validator_child_holds_no_inherited_descriptor() {
    // Every child started while the pipe is open inherits it.
    let pipe = nix::unistd::pipe().unwrap();
    let bytes = burn_bytes();
    let chain = mined(&witness_ids(&bytes));
    let result = faulty("fds").validate_in_child(
        &bytes,
        Some(&bind_all),
        &chain,
        &open_lists(),
        &in_force(),
        far_deadline(),
    );
    drop(pipe);
    result.expect("the child closed every descriptor it inherited");
}

/// The child turns core files off and sets its stack limit.
#[cfg(target_os = "linux")]
#[test]
fn a_validator_child_sets_its_core_and_stack_limits() {
    let bytes = burn_bytes();
    let chain = mined(&witness_ids(&bytes));
    faulty("limits")
        .validate_in_child(
            &bytes,
            Some(&bind_all),
            &chain,
            &open_lists(),
            &in_force(),
            far_deadline(),
        )
        .expect("the child set its core and stack limits");
}

/// A probe child confines itself and is the first the OOM killer ends.
#[cfg(target_os = "linux")]
#[test]
fn the_probe_reports_a_confined_child_first_in_line_for_the_oom_killer() {
    let program = ChildProgram::test_entry(lib_test_entry()).unwrap();
    let report = probe(&program, Duration::from_secs(30)).unwrap();
    assert!(report.confined, "{report:?}");
    assert_eq!(report.oom_score_adj, OOM_SCORE_ADJ_MAX);
    assert!(report.vm_rss_bytes > 0, "{report:?}");
}

/// A probe child answers on an OS where it cannot confine itself.
#[cfg(not(target_os = "linux"))]
#[test]
fn a_probe_child_reports_no_confinement_where_the_os_has_none() {
    let program = ChildProgram::test_entry(lib_test_entry()).unwrap();
    let report = probe(&program, Duration::from_secs(30)).unwrap();
    assert!(!report.confined, "{report:?}");
}

/// Under a memory limit that holds the enclave and its child, the kernel ends
/// the child, and the enclave's key signs as before. The enclave holds more
/// memory than the child can take, so only the child's OOM score puts it
/// first.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root and cgroup v2; CI runs it in its own step"]
fn the_kernel_ends_a_child_out_of_memory_and_the_key_still_signs() {
    let state = crate::state::EnclaveState::new(bitcoin::Network::Bitcoin);
    state
        .initialize_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
        )
        .unwrap();
    let digest = [0x07; 32];
    let before = state.sign_evm(&digest).unwrap();
    let group = MemoryGroup::enter(MEMORY_GROUP_HEADROOM_BYTES);
    let err = faulty("grow")
        .validate_in_child(
            b"the file of a validator that grows",
            None,
            &MinedBlocks::of(&[]),
            &open_lists(),
            &in_force(),
            Instant::now() + Duration::from_secs(120),
        )
        .unwrap_err();
    let kills = group.oom_kills();
    drop(group);
    let text = err.to_string();
    assert_eq!(err.error_code(), 1, "{text}");
    assert!(
        text.contains("signal 9") && text.contains("runs out of memory"),
        "{text}"
    );
    assert!(kills >= 1, "the kernel ended no process of the group");
    assert_eq!(state.sign_evm(&digest).unwrap(), before);
}

/// The memory a [`MemoryGroup`] allows above its use when this process joins.
#[cfg(target_os = "linux")]
const MEMORY_GROUP_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;

/// This process in a cgroup of its own with a memory limit and no swap; the
/// children it starts join it. The process holds twice the headroom in the
/// group, at OOM score adjustment 0. Drop moves the process back, sets its
/// adjustment back and removes the group.
#[cfg(target_os = "linux")]
struct MemoryGroup {
    path: std::path::PathBuf,
    home: std::path::PathBuf,
    own_adj: String,
    _ballast: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl MemoryGroup {
    fn enter(headroom: u64) -> Self {
        let root = std::path::Path::new("/sys/fs/cgroup");
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let own = own
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .expect("a cgroup v2 path")
            .to_owned();
        let controllers = std::fs::read_to_string(root.join("cgroup.subtree_control")).unwrap();
        if !controllers.split_whitespace().any(|name| name == "memory") {
            std::fs::write(root.join("cgroup.subtree_control"), "+memory").unwrap();
        }
        let path = root.join(format!("utexo-oom-test-{}", std::process::id()));
        std::fs::create_dir(&path).expect("run as root: the test makes a cgroup");
        let own_adj = std::fs::read_to_string("/proc/self/oom_score_adj").unwrap();
        let mut group = Self {
            path,
            home: root.join(own),
            own_adj,
            _ballast: Vec::new(),
        };
        group.write("cgroup.procs", &std::process::id().to_string());
        std::fs::write("/proc/self/oom_score_adj", "0").unwrap();
        // Each page written, so the group holds it.
        let ballast = vec![1u8; usize::try_from(2 * headroom).unwrap()];
        group._ballast = std::hint::black_box(ballast);
        let used: u64 = group.read("memory.current").trim().parse().unwrap();
        group.write("memory.max", &(used + headroom).to_string());
        if group.path.join("memory.swap.max").exists() {
            group.write("memory.swap.max", "0");
        }
        group
    }

    fn read(&self, file: &str) -> String {
        std::fs::read_to_string(self.path.join(file)).unwrap()
    }

    fn write(&self, file: &str, value: &str) {
        std::fs::write(self.path.join(file), value).unwrap();
    }

    /// The processes of this group that the OOM killer ended.
    fn oom_kills(&self) -> u64 {
        self.read("memory.events")
            .lines()
            .find_map(|line| line.strip_prefix("oom_kill "))
            .and_then(|count| count.trim().parse().ok())
            .unwrap_or(0)
    }
}

#[cfg(target_os = "linux")]
impl Drop for MemoryGroup {
    fn drop(&mut self) {
        let _ = std::fs::write("/proc/self/oom_score_adj", self.own_adj.trim());
        let _ = std::fs::write(
            self.home.join("cgroup.procs"),
            std::process::id().to_string(),
        );
        let _ = std::fs::remove_dir(&self.path);
    }
}
