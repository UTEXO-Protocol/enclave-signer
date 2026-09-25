//! Tests for every part of `validation/`. Kept together because they share
//! the consignment fixtures and the Esplora stub.

use std::io::Cursor;

use rgb_consignment::{FungibleAllocation, FungibleEntry, SealInfo, TransitionInfo};
#[cfg(rgb_to_evm)]
use rgbstd::containers::ConsignmentExt;
use rgbstd::containers::{FileContent, Transfer};
#[cfg(rgb_to_evm)]
use sha3::{Digest, Keccak256};

// The source-path tests below (payload gate, source asset bind) are the
// RGB -> EVM direction.
#[cfg(rgb_to_evm)]
use crate::error::Result;
#[cfg(rgb_to_evm)]
use crate::networks::ValidationContext;
#[cfg(rgb_to_evm)]
use crate::proto::RgbSource;

use super::asset_bind::*;
use super::bfa;
#[cfg(feature = "bfa-validation")]
use super::bfa::*;
use super::consignment::*;
use super::indexer::*;
use super::schema::*;
#[cfg(rgb_to_evm)]
use super::source::*;
use super::types::*;

// Fixtures from the rgb-consignment-parser repo (`test-data/`). Mainnet
// NIA artefacts, shipped in-tree so the tests need no network access.
const TRANSFER_FIXTURE: &[u8] =
    include_bytes!("../../../../tests/fixtures/transfer_consignment.rgbc");
const CONTRACT_FIXTURE: &[u8] =
    include_bytes!("../../../../tests/fixtures/contract_consignment.rgbc");

use crate::config::BridgeConfig;
#[cfg(rgb_to_evm)]
use crate::config::{
    DEFAULT_MAX_CONSIGNMENT_BYTES, DEFAULT_MAX_MERKLE_PROOFS, DEFAULT_MAX_TOTAL_PROOF_BYTES,
};
#[cfg(rgb_to_evm)]
use crate::proto::MerkleProofEntry;

#[test]
fn rejects_invalid_bytes() {
    let validator = RgbValidator::new("http://localhost:1".to_string(), "regtest").unwrap();
    let err = validator
        .validate_consignment(b"not-a-consignment", &[])
        .unwrap_err();
    assert!(
        err.to_string().contains("deserialization failed"),
        "expected deserialization error, got: {err}"
    );
}

/// Stub Esplora answering only `GET /fee-estimates`, with a per-request
/// body sequence (later requests get the last body). Returns the URL.
fn spawn_fee_stub(bodies: Vec<&'static str>) -> String {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fee stub");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut served = 0usize;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let first = String::from_utf8_lossy(&buf[..n])
                .lines()
                .next()
                .unwrap_or_default()
                .to_string();
            let resp = if first.starts_with("GET /fee-estimates") {
                let body = bodies[served.min(bodies.len() - 1)];
                served += 1;
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else {
                "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

#[test]
fn fee_estimate_uses_exact_target_and_caches() {
    // First fetch returns target-6's rate; the second call must be served
    // from the 60s cache (the stub would answer 99.0 if re-queried).
    let url = spawn_fee_stub(vec![r#"{"1":50.0,"6":20.0,"25":5.0}"#, r#"{"6":99.0}"#]);
    let v = RgbValidator::new(url, "bitcoin").unwrap();
    assert_eq!(v.recommended_fee_rate_sat_vb().unwrap(), 20.0);
    assert_eq!(
        v.recommended_fee_rate_sat_vb().unwrap(),
        20.0,
        "second call must hit the cache, not the stub"
    );
}

#[test]
fn fee_estimate_electrum_stall_times_out_and_fails_closed() {
    use std::{io::BufRead, net::TcpListener, sync::mpsc, time::Duration};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (release_tx, release_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = String::new();
        std::io::BufReader::new(&stream)
            .read_line(&mut request)
            .unwrap();
        assert!(request.contains("blockchain.estimatefee"));
        let _ = release_rx.recv_timeout(Duration::from_secs(5));
    });
    let mut validator = RgbValidator::new(format!("tcp://{addr}"), "bitcoin").unwrap();
    validator.electrum_fee_timeout_secs = 1;
    let (result_tx, result_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        result_tx
            .send(validator.recommended_fee_rate_sat_vb())
            .unwrap();
    });

    let result = result_rx.recv_timeout(Duration::from_secs(3));
    let _ = release_tx.send(());
    server.join().unwrap();
    worker.join().unwrap();
    let err = result
        .expect("silent Electrum must time out before the server closes")
        .unwrap_err();
    assert!(err.to_string().contains("refusing to sign"), "{err}");
}

#[test]
fn fee_estimate_stalled_refresh_does_not_block_other_requests() {
    use std::{
        io::{BufRead, Write},
        net::TcpListener,
        sync::{mpsc, Arc},
        time::Duration,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (first, _) = listener.accept().unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = String::new();
        std::io::BufReader::new(&first)
            .read_line(&mut request)
            .unwrap();
        started_tx.send(()).unwrap();
        let stalled = std::thread::spawn(move || {
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
            drop(first);
        });
        let (mut second, _) = listener.accept().unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        request.clear();
        std::io::BufReader::new(&second)
            .read_line(&mut request)
            .unwrap();
        assert!(request.contains("blockchain.estimatefee"));
        // Each fee fetch uses a fresh client, whose first request has ID 0.
        second.write_all(b"{\"id\":0,\"result\":0.0002}\n").unwrap();
        stalled.join().unwrap();
    });
    let validator = Arc::new(RgbValidator::new(format!("tcp://{addr}"), "bitcoin").unwrap());
    let first_validator = Arc::clone(&validator);
    let first = std::thread::spawn(move || first_validator.recommended_fee_rate_sat_vb());
    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let second_validator = Arc::clone(&validator);
    let (result_tx, result_rx) = mpsc::channel();
    let second = std::thread::spawn(move || {
        result_tx
            .send(second_validator.recommended_fee_rate_sat_vb())
            .unwrap();
    });
    let result = result_rx.recv_timeout(Duration::from_secs(3));
    let _ = release_tx.send(());
    first.join().unwrap().unwrap_err();
    second.join().unwrap();
    server.join().unwrap();
    assert_eq!(
        result
            .expect("another fetch must finish while the first is stalled")
            .unwrap(),
        20.0
    );
    // The failed concurrent fetch must not discard the successful refresh.
    assert_eq!(validator.recommended_fee_rate_sat_vb().unwrap(), 20.0);
}

#[test]
fn fee_estimate_falls_back_to_nearest_target() {
    // No target 6: nearest is 1 (|6-1| = 5) over 25 (|6-25| = 19).
    let url = spawn_fee_stub(vec![r#"{"1":50.0,"25":5.0}"#]);
    let v = RgbValidator::new(url, "bitcoin").unwrap();
    assert_eq!(v.recommended_fee_rate_sat_vb().unwrap(), 50.0);
}

#[test]
fn fee_estimate_rejects_empty_response_on_mainnet() {
    // Anomalous on mainnet: the non-mainnet floor must not leak here.
    let url = spawn_fee_stub(vec![r#"{}"#]);
    let v = RgbValidator::new(url, "bitcoin").unwrap();
    let err = v.recommended_fee_rate_sat_vb().unwrap_err();
    assert!(
        err.to_string().contains("no targets"),
        "expected empty-estimates rejection, got: {err}"
    );
}

#[test]
fn fee_estimate_falls_back_to_pinned_floor_on_non_mainnet() {
    // No fee market -> `{}`, which pre-fix wedged every send-RGB PSBT.
    for network in ["signet", "regtest", "testnet"] {
        let url = spawn_fee_stub(vec![r#"{}"#]);
        let v = RgbValidator::new(url, network).unwrap();
        assert_eq!(
            v.recommended_fee_rate_sat_vb().unwrap(),
            NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB,
            "{network} must fall back to the pinned floor on an empty map"
        );
    }
}

#[test]
fn fee_estimate_prefers_a_real_estimate_over_the_floor_on_non_mainnet() {
    // The floor is empty-map-only; a real rate must win, or it would
    // silently loosen the bound.
    let url = spawn_fee_stub(vec![r#"{"6":2.0}"#]);
    let v = RgbValidator::new(url, "signet").unwrap();
    assert_eq!(v.recommended_fee_rate_sat_vb().unwrap(), 2.0);
}

#[test]
fn fee_estimate_fails_closed_when_unreachable_on_non_mainnet() {
    // The threat (host suppresses the egress): the floor must not
    // rescue a failed fetch, only an honest empty response earns it.
    let v = RgbValidator::new("http://127.0.0.1:1".into(), "signet").unwrap();
    let err = v.recommended_fee_rate_sat_vb().unwrap_err();
    assert!(
        err.to_string().contains("refusing to sign"),
        "expected fail-closed fetch error on signet, got: {err}"
    );
}

#[test]
fn fee_estimate_rejects_non_positive_rate() {
    let url = spawn_fee_stub(vec![r#"{"6":0.0}"#]);
    let v = RgbValidator::new(url, "bitcoin").unwrap();
    let err = v.recommended_fee_rate_sat_vb().unwrap_err();
    assert!(
        err.to_string().contains("not a positive finite rate"),
        "expected non-positive rejection, got: {err}"
    );
}

#[test]
fn fee_estimate_fails_closed_when_unreachable() {
    // Nothing listening: the fetch error must propagate as a refusal, not
    // a skip - the host controls this egress.
    let v = RgbValidator::new("http://127.0.0.1:1".into(), "bitcoin").unwrap();
    let err = v.recommended_fee_rate_sat_vb().unwrap_err();
    assert!(
        err.to_string().contains("refusing to sign"),
        "expected fail-closed fetch error, got: {err}"
    );
}

#[test]
fn stalled_esplora_times_out_instead_of_hanging() {
    // A host that accepts the connection and
    // never responds must cost at most the HTTP timeout.
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled stub");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        // Hold every connection open without writing a byte; keeping the
        // streams alive avoids an early RST that would fail fast for the
        // wrong reason.
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            held.push(stream);
        }
    });

    let validator = RgbValidator::new(format!("http://{addr}"), "bitcoin")
        .unwrap()
        .with_http_timeout(2);
    let start = std::time::Instant::now();
    let err = validator
        .validate_consignment(TRANSFER_FIXTURE, &[])
        .unwrap_err();
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "stalled Esplora must be bounded by the HTTP timeout, took {elapsed:?}: {err}"
    );
}

#[test]
fn rejects_unknown_network() {
    let err = RgbValidator::new("http://localhost:1".to_string(), "foonet").unwrap_err();
    assert!(err.to_string().contains("unknown bitcoin network"));
}

/// `asset_output_amount` must count only `OS_ASSET` allocations, not the
/// declarative `OS_BRIDGE` output that carries the mint right.
#[test]
fn transition_summary_excludes_bridge_right_from_asset_amount() {
    let alloc = |assignment_type: u16, amount: u64| FungibleAllocation {
        assignment_type,
        entries: vec![FungibleEntry {
            amount,
            seal: SealInfo::Revealed {
                txid: None,
                vout: 0,
            },
        }],
        total: amount,
    };
    let info = TransitionInfo {
        op_id: "mint-op".into(),
        transition_type: bfa::TS_BRIDGE,
        input_count: 1,
        fungible_allocations: vec![
            alloc(bfa::OS_ASSET, 500),
            // The mint right is declarative and carries no amount, so a
            // non-zero one here is adversarial by construction. The filter
            // must key on the assignment type, not on the amount.
            alloc(bfa::OS_BRIDGE, 1_000_000),
        ],
    };

    let summary = transition_summary(&info).expect("summary");
    assert_eq!(summary.asset_output_amount, 500);
    assert_eq!(summary.total_output_amount, 1_000_500);
}

/// For a Transfer everything is `OS_ASSET`, so the two sums agree - the
/// invariant the PSBT amount bind relies on when it switched from
/// `total_output_amount` to `asset_output_amount`.
#[test]
fn transfer_fixture_asset_amount_equals_total() {
    let (_, _, last_transition, _) =
        extract_transition_summary(TRANSFER_FIXTURE).expect("transfer parse");
    let last = last_transition.expect("transfer has a last transition");
    assert_eq!(last.transition_type, bfa::TS_TRANSFER);
    assert_eq!(last.asset_output_amount, last.total_output_amount);
}

#[test]
fn extracts_op_ids_and_last_transition_from_transfer_fixture() {
    let (all_op_ids, mint_op_ids, last_transition, _) =
        extract_transition_summary(TRANSFER_FIXTURE).expect("transfer parse");

    // Fixture is a Transfer with two witness bundles, one transition
    // each. Order of `all_op_ids` matches witness order.
    assert_eq!(
        all_op_ids,
        vec![
            "f5106c6ddb8b8fd3d1de3bda0106ae13ef0705dc36bfc543566362e5e8dd4bd5".to_string(),
            "74c1d59264894a1bd44887fe84b36739c024bd50188e69baeeda845569313543".to_string(),
        ]
    );
    // This transfer fixture carries no BFA TS_BRIDGE (mint) transition.
    assert!(mint_op_ids.is_empty(), "transfer fixture has no mints");

    let last = last_transition.expect("transfer has a last transition");
    assert_eq!(
        last.op_id,
        "74c1d59264894a1bd44887fe84b36739c024bd50188e69baeeda845569313543"
    );
    // 10000 is the NIA Transfer transition-type id under the schema
    // this fixture uses. Recorded here so a schema change in the
    // future will fail loud instead of silently mislabelling.
    assert_eq!(last.transition_type, 10000);
    // Last transition has two outputs: 14_999_948_000_000 (revealed
    // change leg, vout=1 on the witness tx) and 12_000_000
    // (confidential recipient leg). Total = 14_999_960_000_000.
    assert_eq!(last.total_output_amount, 14_999_960_000_000);
    assert_eq!(last.outputs.len(), 2);
    // The fixture's last transition is a Transfer (type 10000), not a
    // Burn (type 8010). `extract_transition_summary` leaves
    // `burned_asset_amount` `None` because the burn metadata read is
    // gated on `transition_type == bfa::TS_BURN`. A real burn-fixture
    // round-trip lives behind the validator-level path (which needs
    // network access for Esplora), tracked separately.
    assert_eq!(last.burned_asset_amount, None);
}

// Ignored: `transfer_consignment.rgbc` is an NIA consignment, which
// `trusted_typesystem_for_schema` now refuses. Needs a BFA consignment in
// `enclave/tests/fixtures/`.
#[test]
#[ignore]
fn trusted_typesystem_sourced_from_schema_not_consignment() {
    // The trusted type system must come from the canonical rgb-schemas
    // definitions, not from `transfer.types`. Rejection of a non-BFA schema
    // is covered by `non_bfa_schemas_are_rejected`; what needs a fixture is
    // this half - that a legitimate consignment's own types match the
    // canonical ones, which is only meaningful if they were not the source.
    let t = Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");

    let trusted = trusted_typesystem_for_schema(t.genesis.schema_id)
        .expect("fixture schema must be admitted");

    assert_eq!(
        trusted.id().to_string(),
        t.types.id().to_string(),
        "canonical type system for the fixture's schema should match the fixture's types"
    );
}

#[test]
fn bfa_constants_match_rgb_schemas_definitions() {
    // Lock these to the values published in
    // `rgb-protocol/rgb-schemas/src/lib.rs`. If upstream renumbers
    // them, this test fails loud - the consequences of a silent
    // mismatch (mis-classifying a Transfer as a Burn or vice versa)
    // would be much worse than a CI break.
    assert_eq!(bfa::TS_TRANSFER, 10000);
    assert_eq!(bfa::TS_BURN, 8010);
    assert_eq!(bfa::MS_BURNED_ASSET, 1001);
    // The mint right `OS_BRIDGE` is declarative - it carries no amount, so
    // it can never be summed into a minted total. These two numbers are
    // still marked TODO upstream; if they move, this fails loud rather
    // than mis-classifying a mint.
    assert_eq!(bfa::TS_BRIDGE, 8014);
    assert_eq!(bfa::OS_BRIDGE, 4014);
}

/// `BridgeLocation::Ethereum(TinyString)` strict-encodes as a one-byte
/// union tag (first variant, `tags = order`), a one-byte length, then the
/// address. Pinned here so a change in that layout fails loudly rather than
/// as an unexplained "invalid bridge location" at mint time.
#[cfg(feature = "bfa-validation")]
#[test]
fn decodes_the_genesis_bridge_location_layout() {
    let addr = "0x1111111111111111111111111111111111111111";
    let mut blob = vec![0u8, addr.len() as u8];
    blob.extend_from_slice(addr.as_bytes());
    assert_eq!(decode_bridge_location(&blob).unwrap(), addr);
}

#[cfg(feature = "bfa-validation")]
#[test]
fn refuses_a_malformed_bridge_location_blob() {
    assert!(decode_bridge_location(&[]).is_err());
    // Unknown union tag: a future non-Ethereum variant must not be guessed at.
    assert!(decode_bridge_location(&[1, 2, b'a', b'b']).is_err());
    assert!(decode_bridge_location(&[0]).is_err());
    // Declared length disagrees with the bytes that follow.
    assert!(decode_bridge_location(&[0, 4, b'a', b'b']).is_err());
    assert!(decode_bridge_location(&[0, 1, 0xff]).is_err());
}

/// The schema gate the BFA pre-pass applies on both directions: bytes that
/// are not a BFA operation must trigger no EVM lookup and no ancestor
/// requirement.
#[cfg(feature = "bfa-validation")]
#[test]
fn no_binding_for_a_non_bfa_consignment() {
    assert!(bfa_binding(TRANSFER_FIXTURE).unwrap().is_none());
}

/// Undecodable bytes are left to `validate_consignment`, which owns that
/// error - reporting it from the pre-pass would reorder the messages every
/// other path already asserts on.
#[cfg(feature = "bfa-validation")]
#[test]
fn binding_defers_undecodable_bytes() {
    assert!(bfa_binding(b"not-a-consignment").unwrap().is_none());
}

/// A `BfaBinding` whose last transition is `last`, over the given mint set.
#[cfg(feature = "bfa-validation")]
fn binding_with(mint_opids: Vec<[u8; 32]>, last: Option<(u16, [u8; 32])>) -> BfaBinding {
    BfaBinding {
        mint_opids,
        bridge_location: "0x0".into(),
        last_transition: last.map(|(transition_type, opid)| TransitionSummary {
            op_id: hex::encode(opid),
            transition_type,
            total_output_amount: 0,
            asset_output_amount: 0,
            outputs: vec![],
            burned_asset_amount: None,
            burn_recipient: None,
        }),
    }
}

/// The happy path: the last transition is a bridge mint that is also in the
/// mint list, so it names the deposit this request authorises.
#[cfg(feature = "bfa-validation")]
#[test]
fn terminal_opid_is_the_last_bridge_mint() {
    let b = binding_with(vec![[1; 32], [2; 32]], Some((bfa::TS_BRIDGE, [2; 32])));
    assert_eq!(b.terminal_opid().unwrap(), [2; 32]);
}

/// No transitions means no answer to "which deposit pays for this?".
#[cfg(feature = "bfa-validation")]
#[test]
fn terminal_opid_refuses_an_empty_consignment() {
    assert!(binding_with(vec![], None).terminal_opid().is_err());
}

/// A BFA consignment ending in a non-bridge transition is not a mint request.
#[cfg(feature = "bfa-validation")]
#[test]
fn terminal_opid_refuses_a_non_bridge_last_transition() {
    let b = binding_with(vec![[1; 32]], Some((bfa::TS_BURN, [1; 32])));
    assert!(b.terminal_opid().is_err());
}

/// The last transition is a bridge mint, but the flat parser did not list it
/// among the mints - refuse rather than guess.
#[cfg(feature = "bfa-validation")]
#[test]
fn terminal_opid_refuses_a_last_mint_absent_from_the_list() {
    let b = binding_with(vec![[1; 32]], Some((bfa::TS_BRIDGE, [9; 32])));
    assert!(b.terminal_opid().is_err());
}

/// Direct cover for the asset binding. The end-to-end `asset_bind` suites
/// below prove the binding is WIRED IN; these prove the rule itself, and
/// need no consignment, resolver or header chain.
mod asset_binding_rule {
    use super::*;

    const VALIDATED: &str = "rgb:the-real-asset";

    fn cfg(rgb_asset_id: &str, configured: bool) -> BridgeConfig {
        BridgeConfig {
            chain_id: if configured { 1 } else { 0 },
            bridge_contract: if configured { [0x11; 20] } else { [0u8; 20] },
            rgb_asset_id: rgb_asset_id.into(),
            gas_tx_allowed_to: None,
            ..Default::default()
        }
    }

    fn bind(validated: &str, declared: &str, c: &BridgeConfig, m: AssetBindMode) -> String {
        match assert_asset_binding(validated, declared, c, m) {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn binds_when_validated_declared_and_pin_all_agree() {
        for mode in [AssetBindMode::Source, AssetBindMode::Destination] {
            let err = bind(VALIDATED, VALIDATED, &cfg(VALIDATED, true), mode);
            assert!(err.is_empty(), "{mode:?} should bind, got: {err}");
        }
    }

    #[test]
    fn rejects_empty_validated_contract_id() {
        for mode in [AssetBindMode::Source, AssetBindMode::Destination] {
            let err = bind("", "", &cfg("", true), mode);
            assert!(err.contains("empty contract_id"), "{mode:?}: {err}");
        }
    }

    #[test]
    fn rejects_when_declared_disagrees_with_validated() {
        let err = bind(
            VALIDATED,
            "rgb:listener-lied",
            &cfg(VALIDATED, true),
            AssetBindMode::Source,
        );
        assert!(err.contains("contract_id mismatch") && err.contains("RGB source declares"));
        let err = bind(
            VALIDATED,
            "rgb:listener-lied",
            &cfg(VALIDATED, true),
            AssetBindMode::Destination,
        );
        assert!(err.contains("contract_id mismatch") && err.contains("RGB destination declares"));
    }

    /// The funds-theft path: a colluding listener declares the foreign
    /// asset consistently with the consignment. The pin must still reject.
    #[test]
    fn rejects_foreign_asset_even_when_declared_agrees() {
        for mode in [AssetBindMode::Source, AssetBindMode::Destination] {
            let err = bind(
                VALIDATED,
                VALIDATED,
                &cfg("rgb:some-other-pinned-asset", true),
                mode,
            );
            assert!(
                err.contains("contract_id mismatch") && err.contains("pinned RGB_ASSET_ID"),
                "{mode:?}: {err}"
            );
        }
    }

    /// The documented direction asymmetry, both halves in one place.
    #[test]
    fn missing_pin_is_fatal_only_on_the_destination_side() {
        // Destination: an unpinned asset is refused outright.
        let err = bind(
            VALIDATED,
            VALIDATED,
            &cfg("", false),
            AssetBindMode::Destination,
        );
        assert!(err.contains("asset-identity pin missing"), "{err}");

        // Source, fully-unconfigured: the pin block is skipped entirely and
        // the binding degrades to declared == validated.
        let err = bind(VALIDATED, VALIDATED, &cfg("", false), AssetBindMode::Source);
        assert!(
            err.is_empty(),
            "unconfigured source should bind, got: {err}"
        );

        // There is no third case: `is_configured()` already requires a
        // non-empty `RGB_ASSET_ID`, so the source arm's "pinned
        // chain/contract but RGB_ASSET_ID is empty" branch is unreachable
        // by construction. It is kept as a fail-closed backstop against a
        // future `is_configured()` that stops checking the pin.
        assert!(!cfg("", true).is_configured());
    }
}

#[test]
fn bfa_schema_resolves_a_trusted_typesystem() {
    // The release path runs every consignment through this resolver, and it
    // fails closed on an unknown schema. Without BFA registered a bridged
    // asset could be minted but never released.
    trusted_typesystem_for_schema(schemata::BFA_SCHEMA_ID)
        .expect("BFA must resolve a trusted type system");
}

/// BFA is the only schema the enclave validates. Any other schema id - the
/// standard fungible/collectible ones included - must fail closed.
#[test]
fn non_bfa_schemas_are_rejected() {
    use schemata::{CFA_SCHEMA_ID, IFA_SCHEMA_ID, NIA_SCHEMA_ID, UDA_SCHEMA_ID};

    for id in [IFA_SCHEMA_ID, NIA_SCHEMA_ID, CFA_SCHEMA_ID, UDA_SCHEMA_ID] {
        assert!(
            trusted_typesystem_for_schema(id).is_err(),
            "schema {id} must not resolve a trusted type system"
        );
    }
}

/// A BFA `Bridge` is the only mint shape. It is a signing shape only in the
/// mint/burn flow - the swap enclave signs `Transfer` and carries no mint
/// rule at all.
#[test]
fn bridge_transitions_are_the_only_mint_shape() {
    assert!(is_mint_transition(bfa::TS_BRIDGE));
    assert!(!is_mint_transition(bfa::TS_TRANSFER));
    assert!(!is_mint_transition(bfa::TS_BURN));
    assert_eq!(
        super::super::flow::is_signing_transition(bfa::TS_BRIDGE),
        cfg!(feature = "rgb-mint-burn")
    );
}

#[test]
fn last_transition_carries_revealed_and_confidential_seals() {
    let (_, _, last_transition, _) =
        extract_transition_summary(TRANSFER_FIXTURE).expect("transfer parse");
    let last = last_transition.expect("transfer has a last transition");

    // Both legs are `OS_ASSET` - the assignment tag the per-output
    // recipient bind filters on. Asserted against real
    // consignment bytes so the tag can't silently drift from the parser.
    assert!(
        last.outputs
            .iter()
            .all(|o| o.assignment_type == bfa::OS_ASSET),
        "transfer fixture legs should all be OS_ASSET"
    );

    // First entry is the change leg: revealed with no explicit txid
    // (points at the witness tx itself), vout=1, amount as above.
    let change = &last.outputs[0];
    assert_eq!(change.amount, 14_999_948_000_000);
    match &change.seal {
        OutputSeal::Revealed { txid, vout } => {
            assert!(txid.is_none(), "change leg seal txid should be None");
            assert_eq!(*vout, 1);
        }
        OutputSeal::Confidential { .. } => panic!("change leg should be Revealed"),
    }

    // Second entry is the recipient leg: confidential
    // (`utxob:UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP`).
    let recipient = &last.outputs[1];
    assert_eq!(recipient.amount, 12_000_000);
    match &recipient.seal {
        OutputSeal::Confidential { secret_seal } => {
            assert!(
                secret_seal.starts_with("utxob:"),
                "confidential seal should start with 'utxob:', got {secret_seal}"
            );
        }
        OutputSeal::Revealed { .. } => panic!("recipient leg should be Confidential"),
    }
}

#[test]
fn extracts_last_transfer_witness_from_transfer_fixture() {
    // `read_last_transfer_witness` works off the rgbstd `Transfer`
    // directly, so it needs no Esplora/network - load the fixture and
    // assert the witness-tx binding data the PSBT cross-check relies on.
    let transfer = Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");

    // The fixture's last transition is a Transfer (type 10000, asserted in
    // `extracts_op_ids_and_last_transition_from_transfer_fixture`).
    let (prevouts, op_id) =
        read_last_transfer_witness(&transfer, bfa::TS_TRANSFER).expect("extract witness");
    let last_bundle = transfer.bundles.iter().last().expect("fixture has bundles");

    // The rgb-lib sender embeds the full witness tx for a freshly-composed
    // transfer, so the prevouts (the witness tx's Bitcoin inputs) are
    // present and non-empty - the per-input canary is available.
    let prevouts = prevouts.expect("fixture embeds the full witness tx (PubWitness::Tx)");
    assert!(
        !prevouts.is_empty(),
        "witness tx must spend at least one input"
    );

    // The validated OpId (canonical burnId source) must be present and
    // equal the last bundle's last known-transition opid, read straight
    // from the validated object - not the flat parser.
    let op_id = op_id.expect("transfer fixture yields a validated opid");
    let expected_opid = last_bundle
        .bundle()
        .known_transitions
        .iter()
        .last()
        .expect("bundle has a known transition")
        .opid
        .to_string();
    assert_eq!(hex::encode(op_id), expected_opid);
}

#[test]
fn rejects_last_transfer_witness_on_type_mismatch() {
    // If the rgbstd bundle walk and the parser walk disagree on the last
    // transition type, we must fail closed rather than bind a txid from
    // one transition while gating on another. The fixture's last
    // transition is TS_TRANSFER (10000); claiming it's a burn (8010)
    // forces the consistency check to fire.
    let transfer = Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");
    let err = read_last_transfer_witness(&transfer, bfa::TS_BURN).unwrap_err();
    assert!(
        err.to_string()
            .contains("disagrees with parsed last transition type"),
        "expected type-mismatch rejection, got: {err}"
    );
}

#[test]
fn rejects_contract_with_explicit_kind_message() {
    let err = extract_transition_summary(CONTRACT_FIXTURE).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Contract") && msg.contains("expected Transfer"),
        "expected Contract->Transfer rejection, got: {msg}"
    );
}

#[test]
fn rejects_random_bytes_with_parse_error() {
    let err = extract_transition_summary(&[0u8; 64]).unwrap_err();
    assert!(
        err.to_string().contains("rgb-consignment parse failed"),
        "expected parse-failure rejection, got: {err}"
    );
}

// Consignment-flag pins - successors of the dropped
// `validation::evm_crosscheck` tests `accepts_valid_consignment_hash` /
// `ignores_consignment_valid_flag_when_bytes_present` (+ the P0 companion
// `rejects_empty_consignment_even_with_valid_flag`). Their target,
// `validate_evm_request`'s payload gate, is now `validate_source_payload`
// in this file. The wire type (`proto::RgbSource`) STILL carries the
// host-supplied `consignment_valid: bool` (tag 1); the gate never reads
// it - validity comes from the bytes, never the flag.

/// keccak256(bytes) in the wire shape `validate_source_payload` expects.
#[cfg(rgb_to_evm)]
fn keccak(bytes: &[u8]) -> Vec<u8> {
    Keccak256::digest(bytes).to_vec()
}

/// A well-formed `RgbSource` around the in-tree mainnet transfer fixture.
///
/// `consignment_valid` is deliberately `false`: the flag is not
/// authoritative, so anything that validates with this fixture also
/// proves a `false` flag cannot veto byte-derived validity.
#[cfg(rgb_to_evm)]
fn fixture_source(asset_id: &str) -> RgbSource {
    RgbSource {
        consignment_valid: false,
        asset_id: asset_id.into(),
        consignment: TRANSFER_FIXTURE.to_vec(),
        consignment_hash: keccak(TRANSFER_FIXTURE),
        merkle_proofs: vec![],
        commission: 0,
        mint_ancestors: vec![],
    }
}

/// Old `accepts_valid_consignment_hash`: consignment bytes plus their
/// matching keccak256 pass the payload gate. `Ok` here is "past the hash
/// check" in full - everything after this gate in `validate_source` is
/// validator/SPV work, not payload shape.
#[cfg(rgb_to_evm)]
#[test]
fn accepts_valid_consignment_hash() {
    assert!(validate_source_payload(
        &fixture_source("rgb:any-declared-asset"),
        &BridgeConfig::default()
    )
    .is_ok());
}

/// A consignment larger than the configured cap is rejected by the payload
/// gate with the aggregate-size error *before* any rgbstd parse (the error
/// is the size cap, not a decode failure).
#[cfg(rgb_to_evm)]
#[test]
fn rejects_oversized_consignment_before_parse() {
    let mut source = fixture_source("rgb:any-declared-asset");
    source.consignment = vec![0u8; DEFAULT_MAX_CONSIGNMENT_BYTES + 1];
    source.consignment_hash = keccak(&source.consignment);
    let err = validate_source_payload(&source, &BridgeConfig::default())
        .unwrap_err()
        .to_string();
    assert!(err.contains("consignment too large"), "unexpected: {err}");
}

/// Boundary: a consignment exactly at the cap passes the aggregate gate
/// (rejection is strictly `>` the cap).
#[cfg(rgb_to_evm)]
#[test]
fn accepts_consignment_at_size_cap() {
    let mut source = fixture_source("rgb:any-declared-asset");
    source.consignment = vec![0u8; DEFAULT_MAX_CONSIGNMENT_BYTES];
    source.consignment_hash = keccak(&source.consignment);
    assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
}

/// The caps are operator-configurable: a smaller `max_consignment_bytes`
/// rejects a consignment the default would accept.
#[cfg(rgb_to_evm)]
#[test]
fn honors_configured_consignment_cap() {
    let mut source = fixture_source("rgb:any-declared-asset");
    source.consignment = vec![0u8; 200];
    source.consignment_hash = keccak(&source.consignment);
    // The default cap accepts 200 bytes.
    assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
    // A 100-byte configured cap rejects the same source.
    let cfg = BridgeConfig {
        max_consignment_bytes: 100,
        ..BridgeConfig::default()
    };
    let err = validate_source_payload(&source, &cfg)
        .unwrap_err()
        .to_string();
    assert!(err.contains("consignment too large"), "unexpected: {err}");
}

/// Too many Merkle proofs is rejected on count alone, even when each proof
/// is individually tiny.
#[cfg(rgb_to_evm)]
#[test]
fn rejects_too_many_merkle_proofs() {
    let mut source = fixture_source("rgb:any-declared-asset");
    source.merkle_proofs = (0..DEFAULT_MAX_MERKLE_PROOFS + 1)
        .map(|_| MerkleProofEntry::default())
        .collect();
    let err = validate_source_payload(&source, &BridgeConfig::default())
        .unwrap_err()
        .to_string();
    assert!(err.contains("too many merkle proofs"), "unexpected: {err}");
}

/// Proofs that each stay under the per-path-depth cap but exceed the
/// aggregate byte budget are rejected by the aggregate gate - the case the
/// per-field caps miss.
#[cfg(rgb_to_evm)]
#[test]
fn rejects_aggregate_proof_bytes_over_budget() {
    // Each proof counts 32-byte txid + 32 siblings * 32 bytes = 1056 bytes,
    // all within MAX_MERKLE_PATH_DEPTH. Take just enough to cross the
    // aggregate cap while staying under the proof-count cap.
    let per_proof = 32 + 32 * 32;
    let n = DEFAULT_MAX_TOTAL_PROOF_BYTES / per_proof + 1;
    assert!(
        n <= DEFAULT_MAX_MERKLE_PROOFS,
        "test would trip the count cap first"
    );
    let proof = MerkleProofEntry {
        txid: vec![0u8; 32],
        block_height: 0,
        tx_position: 0,
        merkle_path: vec![vec![0u8; 32]; 32],
    };
    let mut source = fixture_source("rgb:any-declared-asset");
    source.merkle_proofs = vec![proof; n];
    let err = validate_source_payload(&source, &BridgeConfig::default())
        .unwrap_err()
        .to_string();
    assert!(err.contains("too large in aggregate"), "unexpected: {err}");
}

/// Old `ignores_consignment_valid_flag_when_bytes_present`: an identical
/// payload must validate identically whatever the host claims in
/// `consignment_valid` - the gate never reads the flag.
#[cfg(rgb_to_evm)]
#[test]
fn ignores_consignment_valid_flag_when_bytes_present() {
    let mut source = fixture_source("rgb:any-declared-asset");
    source.consignment_valid = false;
    assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
    source.consignment_valid = true;
    assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
}

/// Old `rejects_empty_consignment_even_with_valid_flag` (P0 regression):
/// a host-supplied `consignment_valid: true` with no consignment bytes
/// must be rejected - the flag can never substitute for the bytes.
#[cfg(rgb_to_evm)]
#[test]
fn rejects_empty_consignment_even_with_valid_flag() {
    let mut source = fixture_source("rgb:any-declared-asset");
    source.consignment = vec![];
    source.consignment_hash = vec![];
    source.consignment_valid = true;
    let err = validate_source_payload(&source, &BridgeConfig::default()).unwrap_err();
    assert!(
        err.to_string().contains("requires raw consignment bytes"),
        "expected raw-bytes-required rejection, got: {err}"
    );
}

/// Symmetric pin: the flag cannot rescue a wrong hash either.
#[cfg(rgb_to_evm)]
#[test]
fn rejects_consignment_hash_mismatch_even_with_valid_flag() {
    let mut source = fixture_source("rgb:any-declared-asset");
    source.consignment_hash = vec![0xDE; 32];
    source.consignment_valid = true;
    let err = validate_source_payload(&source, &BridgeConfig::default()).unwrap_err();
    assert!(
        err.to_string().contains("consignment hash mismatch"),
        "expected hash-mismatch rejection, got: {err}"
    );
}

// Asset-identity binding, SOURCE path - successor of the dropped
// `evm_crosscheck::asset_bind` suite. Its target,
// `bind_asset_identity`, was removed in the networks/ split; the legs are
// now INLINED in `validate_source` (this file) after
// `validate_consignment`, so the narrowest callable unit is
// `validate_source` itself, driven end-to-end with the in-tree mainnet
// fixture validated offline against a stub Esplora (the resolver only
// phones home for the genesis-hash chain-identity check; the fixture
// embeds its witness txs, which `add_consignment_txes` registers as
// tentative).
//
// Path asymmetry (deliberate, see each test): here the RGB_ASSET_ID pin
// is gated on `BridgeConfig::is_configured()`; the destination path
// (`validate_destination_anchor`, `networks/rgb/mod.rs`) enforces the pin
// unconditionally.

/// END-TO-END asset binding: these drive the whole validator, so they also
/// prove the bind is wired into the request path - what the pure-rule tests
/// in `validation::tests::asset_binding_rule` cannot show.
///
/// ALL IGNORED, one reason: `transfer_consignment.rgbc` is an NIA
/// consignment, which the enclave now refuses at the schema gate before any
/// of these reaches the asset bind. Drop every `#[ignore]` in this module
/// once a BFA consignment lands in `enclave/tests/fixtures/`.
#[cfg(rgb_to_evm)]
mod asset_bind {
    use super::*;
    use crate::config::BridgeConfig;
    use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
    use std::sync::Mutex;

    /// Contract id of `TRANSFER_FIXTURE`. Kept as a literal (the old
    /// suite's `PIN`), re-derived and asserted in [`fixture_asset_id`]
    /// so a fixture swap fails loud instead of silently retargeting
    /// every binding test.
    const FIXTURE_ASSET_ID: &str = "rgb:fuhLYX9G-eC8gDvf-V0XpYFH-ceSafoc-lGutAYq-~SExGU4";

    /// The validated asset identity: the fixture's genesis contract id.
    fn fixture_asset_id() -> String {
        let t = Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");
        let id = t.contract_id().to_string();
        assert_eq!(
            id, FIXTURE_ASSET_ID,
            "transfer fixture contract id drifted - update FIXTURE_ASSET_ID"
        );
        id
    }

    /// Stub Esplora serving only `GET /block-height/0` with the mainnet
    /// genesis hash - all offline rgbstd validation of the fixture needs:
    /// the resolver phones home only for the genesis-hash chain-identity
    /// check, and the fixture embeds its witness txs (registered as
    /// tentative via `add_consignment_txes`).
    fn spawn_stub_esplora() -> String {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub esplora");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let first = req.lines().next().unwrap_or("").to_string();
                if !first.starts_with("GET /block-height/0") {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    );
                    continue;
                }
                let body = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin)
                    .block_hash()
                    .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    /// Fully-pinned operator config (`is_configured() == true`) with the
    /// given RGB_ASSET_ID.
    fn pinned_config(rgb_asset_id: &str) -> BridgeConfig {
        BridgeConfig {
            chain_id: 1,
            bridge_contract: [0x11; 20],
            rgb_asset_id: rgb_asset_id.into(),
            gas_tx_allowed_to: None,
            ..Default::default()
        }
    }

    /// Fully-empty operator config (`is_configured() == false`) - the
    /// legacy dev/mock posture.
    fn unconfigured_config() -> BridgeConfig {
        BridgeConfig {
            chain_id: 0,
            bridge_contract: [0u8; 20],
            rgb_asset_id: String::new(),
            gas_tx_allowed_to: None,
            ..Default::default()
        }
    }

    /// Mainnet header chain whose checkpoint is stamped "now": the SPV
    /// staleness and chain-net checks pass, so a fully-bound source
    /// proceeds to the merkle-proof coverage check. Its distinctive
    /// "missing merkle proofs" error is this suite's proof that every
    /// asset-binding leg was traversed (real proofs for the fixture's
    /// mainnet witness txs are not constructible in a unit test).
    fn fresh_mainnet_chain() -> Mutex<HeaderChain> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        Mutex::new(HeaderChain::new(
            Network::Mainnet,
            Checkpoint {
                height: 0,
                hash: [0u8; 32],
                bits: 0x1d00_ffff,
                time: now,
                is_real: false,
            },
        ))
    }

    /// Drive `validate_source` (the unit the binding is inlined in) with
    /// a stub-Esplora validator and a fresh mainnet header chain.
    fn run_validate_source(
        source: &RgbSource,
        config: &BridgeConfig,
    ) -> Result<ValidatedConsignment> {
        let url = spawn_stub_esplora();
        let validator = RgbValidator::new(url, "bitcoin").expect("validator");
        let chain = fresh_mainnet_chain();
        let ctx = ValidationContext {
            bridge_config: config,
            rgb_validator: Some(&validator),
            header_chain: &chain,
            chain_pins: &crate::networks::rgb::spv_crosscheck::ChainPins::new(),
            // Source validation never reaches the destination PSBT bind.
            #[cfg(evm_to_rgb)]
            self_owned_psbt_outputs: None,
            bridge_events: &[],
        };
        validate_source(source, &ctx)
    }

    /// Happy path (old `binds_when_contract_id_matches_pin`): validated
    /// contract_id == declared asset_id == pinned RGB_ASSET_ID. Every
    /// binding leg passes and validation proceeds to the SPV stage -
    /// the failure there is *past* the binding, and specifically past
    /// the staleness + chain-net checks too.
    // Ignored: see the module note on the BFA fixture.
    #[test]
    #[ignore]
    fn binds_when_contract_id_matches_pin() {
        let id = fixture_asset_id();
        let err = run_validate_source(&fixture_source(&id), &pinned_config(&id)).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing merkle proofs"),
            "expected to reach the SPV proof-coverage stage, got: {msg}"
        );
        assert!(
            !msg.contains("contract_id mismatch") && !msg.contains("RGB_ASSET_ID"),
            "asset binding must have passed, got: {msg}"
        );
    }

    /// Old `binds_when_declared_is_empty`, semantics INVERTED by a
    /// deliberate post-merge strengthening: the networks/ split requires
    /// the RGB source to declare its asset - an empty `asset_id` now
    /// fails closed in `validate_source_payload` instead of binding via
    /// the pin alone. This same rejection is what carries the old
    /// `rejects_foreign_asset_even_when_declared_is_empty` guarantee:
    /// with an empty declared id *nothing* binds, foreign or not.
    #[test]
    fn rejects_when_declared_is_empty() {
        let err =
            run_validate_source(&fixture_source(""), &pinned_config(FIXTURE_ASSET_ID)).unwrap_err();
        assert!(
            err.to_string().contains("RGB source asset_id is empty"),
            "expected empty-declared rejection, got: {err}"
        );
    }

    /// Old `rejects_foreign_asset_even_when_declared_is_empty`, adapted:
    /// empty declarations are now rejected up-front (previous test), so
    /// the closest reachable form of the funds-theft path is a
    /// listener that *colludes* - declaring the foreign asset
    /// consistently with the consignment. The pin must still reject it:
    /// RGB_ASSET_ID is load-bearing regardless of what the listener says.
    // Ignored: see the module note on the BFA fixture.
    #[test]
    #[ignore]
    fn rejects_foreign_asset_even_when_declared_agrees() {
        let id = fixture_asset_id();
        let err = run_validate_source(
            &fixture_source(&id),
            &pinned_config("rgb:some-other-pinned-asset"),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("contract_id mismatch") && msg.contains("pinned RGB_ASSET_ID"),
            "expected pin mismatch, got: {msg}"
        );
    }

    /// Old `rejects_when_declared_disagrees_with_validated`: the listener
    /// declares a different asset than the validated identity. Fires on
    /// the declared-vs-validated leg (which runs before the pin block).
    // Ignored: see the module note on the BFA fixture.
    #[test]
    #[ignore]
    fn rejects_when_declared_disagrees_with_validated() {
        let err = run_validate_source(
            &fixture_source("rgb:listener-lied"),
            &pinned_config(FIXTURE_ASSET_ID),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("contract_id mismatch") && msg.contains("RGB source declares"),
            "expected declared-mismatch rejection, got: {msg}"
        );
    }

    /// Old `rejects_when_pin_absent` - the source-path ASYMMETRY: here
    /// the pin block is gated on `BridgeConfig::is_configured()`, so a
    /// fully-empty config skips the pin and the binding degrades to
    /// declared == validated, proceeding to SPV (this test pins exactly
    /// that). It does NOT fail closed here; the unconditional fail-closed
    /// successor lives on the destination path
    /// (`networks/rgb/mod.rs::tests::asset_bind::rejects_when_pin_absent`)
    /// and, for this RGB->EVM direction, in the EVM destination's
    /// `!is_configured()` rejection (`networks/evm/validation.rs`,
    /// `not(test)`-gated, asserted at the integration layer). The inner
    /// "pinned chain/contract but RGB_ASSET_ID is empty" branch in
    /// `validate_source` is unreachable: `is_configured()` already
    /// requires a non-empty RGB_ASSET_ID.
    // Ignored: see the module note on the BFA fixture.
    #[test]
    #[ignore]
    fn pin_check_skipped_when_config_unconfigured() {
        let id = fixture_asset_id();
        let err = run_validate_source(&fixture_source(&id), &unconfigured_config()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing merkle proofs"),
            "expected to reach the SPV proof-coverage stage with the pin block skipped, \
             got: {msg}"
        );
    }

    // Old `rejects_when_contract_id_absent`: NOT portable to this path.
    // The guard survives (validate_source rejects an empty validated
    // contract_id before any binding), but it is unreachable through the
    // narrowest callable unit: `RgbValidator::validate_consignment`
    // derives contract_id from the consignment's genesis, which is never
    // empty for a loadable Transfer, and `ValidationContext.rgb_validator`
    // is the concrete type - there is no seam to inject a fabricated
    // ValidatedConsignment. Recorded as not-feasible in the restoration
    // report rather than weakened into a vacuous test.
}
