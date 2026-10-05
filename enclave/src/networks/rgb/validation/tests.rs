//! Tests for all of `validation/`. They are in one file because they share
//! the consignment fixtures and the Esplora stub.

use std::io::Cursor;

use rgb_consignment::{FungibleAllocation, FungibleEntry, SealInfo, TransitionInfo};
#[cfg(rgb_to_evm)]
use rgbstd::containers::ConsignmentExt;
use rgbstd::containers::{FileContent, Transfer};
#[cfg(rgb_to_evm)]
use sha3::{Digest, Keccak256};

// The source-path tests (payload gate, source asset bind) are RGB -> EVM.
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

// Fixtures from the rgb-consignment-parser repo (`test-data/`). Mainnet NIA
// files in the tree, so the tests need no network access.
const TRANSFER_FIXTURE: &[u8] =
    include_bytes!("../../../../tests/fixtures/transfer_consignment.rgbc");
const CONTRACT_FIXTURE: &[u8] =
    include_bytes!("../../../../tests/fixtures/contract_consignment.rgbc");

// A real BFA consignment from a bridge run on signet: one `Bridge` mint of
// 100_000 units, then a `Burn` of 50_000 and a last `Burn` of 10_000, with
// 40_000 as change. It has the same bytes as
// `tests/fixtures/bfa_two_burns.rgb` in UTEXO-Protocol/rgb-lib. It contains
// its witness txs, so validation only needs the network for the genesis-hash
// check.
const BFA_BURN_FIXTURE: &[u8] =
    include_bytes!("../../../../tests/fixtures/bfa_burn_consignment.rgbc");

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

#[test]
fn stalled_esplora_times_out_instead_of_hanging() {
    // A host that accepts the connection and never responds must cost at most
    // the HTTP timeout.
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled stub");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        // Keep each connection open with no data. An early RST would fail
        // fast for the wrong reason.
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
            // The mint right has no amount, so this non-zero value is
            // adversarial. The filter must use the assignment type, not the amount.
            alloc(bfa::OS_BRIDGE, 1_000_000),
        ],
    };

    let summary = transition_summary(&info).expect("summary");
    assert_eq!(summary.asset_output_amount, 500);
    assert_eq!(summary.total_output_amount, 1_000_500);
}

/// For a Transfer, all outputs are `OS_ASSET`, so the two sums are equal.
/// The PSBT amount bind uses `asset_output_amount` and relies on this.
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

    // The fixture is a Transfer with two witness bundles, one transition
    // each. `all_op_ids` is in witness order.
    assert_eq!(
        all_op_ids,
        vec![
            "f5106c6ddb8b8fd3d1de3bda0106ae13ef0705dc36bfc543566362e5e8dd4bd5".to_string(),
            "74c1d59264894a1bd44887fe84b36739c024bd50188e69baeeda845569313543".to_string(),
        ]
    );
    assert!(mint_op_ids.is_empty(), "transfer fixture has no mints");

    let last = last_transition.expect("transfer has a last transition");
    assert_eq!(
        last.op_id,
        "74c1d59264894a1bd44887fe84b36739c024bd50188e69baeeda845569313543"
    );
    // 10000 is the NIA Transfer transition-type id for this fixture schema.
    // A schema change fails here, not silently.
    assert_eq!(last.transition_type, 10000);
    // Two outputs: 14_999_948_000_000 (revealed change leg, vout=1 on the
    // witness tx) and 12_000_000 (confidential recipient leg).
    assert_eq!(last.total_output_amount, 14_999_960_000_000);
    assert_eq!(last.outputs.len(), 2);
    // Not a Burn, so `burned_asset_amount` stays `None`. The burn metadata
    // read runs only for `bfa::TS_BURN`.
    assert_eq!(last.burned_asset_amount, None);
}

#[test]
fn trusted_typesystem_sourced_from_schema_not_consignment() {
    // The trusted type system must come from rgb-schemas, not from
    // `transfer.types`. `non_bfa_schemas_are_rejected` covers non-BFA schemas.
    // This test checks that a valid consignment's types match the canonical ones.
    let t = Transfer::load(Cursor::new(BFA_BURN_FIXTURE)).expect("load BFA fixture");

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
    // Values from `rgb-protocol/rgb-schemas/src/lib.rs`. If upstream changes
    // them, this test fails. A silent mismatch can classify a Transfer as a
    // Burn, or the opposite.
    assert_eq!(bfa::TS_TRANSFER, 10000);
    assert_eq!(bfa::TS_BURN, 8010);
    assert_eq!(bfa::MS_BURNED_ASSET, 1001);
    // Upstream still marks these two values TODO. If they change, this fails
    // and does not misclassify a mint.
    assert_eq!(bfa::TS_BRIDGE, 8014);
    assert_eq!(bfa::OS_BRIDGE, 4014);
}

/// `BridgeLocation::Ethereum(TinyString)` strict-encodes as a one-byte union
/// tag (first variant, `tags = order`), a one-byte length, then the address.
/// A layout change fails here, not as an unclear error at mint time.
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
    // Unknown union tag: do not guess a future non-Ethereum variant.
    assert!(decode_bridge_location(&[1, 2, b'a', b'b']).is_err());
    assert!(decode_bridge_location(&[0]).is_err());
    // Declared length does not match the bytes that follow.
    assert!(decode_bridge_location(&[0, 4, b'a', b'b']).is_err());
    assert!(decode_bridge_location(&[0, 1, 0xff]).is_err());
}

/// The BFA pre-pass schema gate, in both directions. Bytes that are not a BFA
/// operation cause no EVM lookup and no ancestor requirement.
#[cfg(feature = "bfa-validation")]
#[test]
fn no_binding_for_a_non_bfa_consignment() {
    assert!(bfa_binding(TRANSFER_FIXTURE).unwrap().is_none());
}

/// `validate_consignment` reports undecodable bytes. A pre-pass error would
/// change the error order that other tests assert.
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

/// Happy path: the last transition is a bridge mint in the mint list, so it
/// names the deposit that this request authorizes.
#[cfg(feature = "bfa-validation")]
#[test]
fn terminal_opid_is_the_last_bridge_mint() {
    let b = binding_with(vec![[1; 32], [2; 32]], Some((bfa::TS_BRIDGE, [2; 32])));
    assert_eq!(b.terminal_opid().unwrap(), [2; 32]);
}

/// With no transitions, the paying deposit is unknown.
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

/// The last transition is a bridge mint that is not in the mint list. Refuse,
/// do not guess.
#[cfg(feature = "bfa-validation")]
#[test]
fn terminal_opid_refuses_a_last_mint_absent_from_the_list() {
    let b = binding_with(vec![[1; 32]], Some((bfa::TS_BRIDGE, [9; 32])));
    assert!(b.terminal_opid().is_err());
}

/// Rule tests for the asset binding. The end-to-end `asset_bind` suites prove
/// that the binding is in the request path. These need no consignment,
/// resolver or header chain.
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

    /// Theft path: a colluding listener declares the foreign asset of the
    /// consignment. The pin must still reject it.
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

    /// The direction asymmetry, both sides.
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

        // Source, unconfigured: no pin check, only declared == validated.
        let err = bind(VALIDATED, VALIDATED, &cfg("", false), AssetBindMode::Source);
        assert!(
            err.is_empty(),
            "unconfigured source should bind, got: {err}"
        );

        // No third case: `is_configured()` requires a non-empty
        // `RGB_ASSET_ID`, so the source "RGB_ASSET_ID is empty" branch is
        // unreachable. It stays as a fail-closed backstop.
        assert!(!cfg("", true).is_configured());
    }
}

#[test]
fn bfa_schema_resolves_a_trusted_typesystem() {
    // The release path sends each consignment through this resolver, which
    // fails closed on an unknown schema. Without BFA, a minted asset cannot
    // be released.
    trusted_typesystem_for_schema(schemata::BFA_SCHEMA_ID)
        .expect("BFA must resolve a trusted type system");
}

/// BFA is the only schema that the enclave validates. All other schema ids,
/// standard ones included, must fail closed.
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
/// mint/burn flow. The swap enclave signs `Transfer` and has no mint rule.
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

    // Both legs are `OS_ASSET`, the tag that the per-output recipient bind
    // filters on. Real consignment bytes catch a drift in the parser.
    assert!(
        last.outputs
            .iter()
            .all(|o| o.assignment_type == bfa::OS_ASSET),
        "transfer fixture legs should all be OS_ASSET"
    );

    // First entry is the change leg: revealed, no txid (the witness tx),
    // vout=1.
    let change = &last.outputs[0];
    assert_eq!(change.amount, 14_999_948_000_000);
    match &change.seal {
        OutputSeal::Revealed { txid, vout } => {
            assert!(txid.is_none(), "change leg seal txid should be None");
            assert_eq!(*vout, 1);
        }
        OutputSeal::Confidential { .. } => panic!("change leg should be Revealed"),
    }

    // Second entry is the confidential recipient leg
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
    // `read_last_transfer_witness` reads the rgbstd `Transfer` directly, so
    // it needs no network.
    let transfer = Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");

    // The last transition is a Transfer (see
    // `extracts_op_ids_and_last_transition_from_transfer_fixture`).
    let (prevouts, op_id) =
        read_last_transfer_witness(&transfer, bfa::TS_TRANSFER).expect("extract witness");
    let last_bundle = transfer.bundles.iter().last().expect("fixture has bundles");

    // The rgb-lib sender embeds the full witness tx in a new transfer, so
    // the prevouts are present for the per-input canary.
    let prevouts = prevouts.expect("fixture embeds the full witness tx (PubWitness::Tx)");
    assert!(
        !prevouts.is_empty(),
        "witness tx must spend at least one input"
    );

    // The validated OpId must equal the opid of the last known transition in
    // the last bundle, from the validated object, not the flat parser.
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
    // If the rgbstd walk and the parser walk disagree on the last transition
    // type, fail closed. The fixture ends in TS_TRANSFER, so a TS_BURN claim
    // triggers the check.
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

// Payload gate tests for `validate_source_payload`. The wire type
// (`proto::RgbSource`) carries the host-supplied `consignment_valid: bool`
// (tag 1). The gate never reads it: validity comes from the bytes.

/// keccak256(bytes) in the wire shape `validate_source_payload` expects.
#[cfg(rgb_to_evm)]
fn keccak(bytes: &[u8]) -> Vec<u8> {
    Keccak256::digest(bytes).to_vec()
}

/// A well-formed `RgbSource` around the in-tree mainnet transfer fixture.
///
/// `consignment_valid` is `false` on purpose. A pass with this fixture also
/// proves that a `false` flag cannot override validity from the bytes.
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

/// Consignment bytes with a matching keccak256 pass the payload gate. After
/// this gate, `validate_source` does only validator and SPV work.
#[cfg(rgb_to_evm)]
#[test]
fn accepts_valid_consignment_hash() {
    assert!(validate_source_payload(
        &fixture_source("rgb:any-declared-asset"),
        &BridgeConfig::default()
    )
    .is_ok());
}

/// The payload gate rejects a consignment above the cap *before* the rgbstd
/// parse (the error is the size cap, not a decode failure).
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

/// Boundary: a consignment exactly at the cap passes (rejection is `>` cap).
#[cfg(rgb_to_evm)]
#[test]
fn accepts_consignment_at_size_cap() {
    let mut source = fixture_source("rgb:any-declared-asset");
    source.consignment = vec![0u8; DEFAULT_MAX_CONSIGNMENT_BYTES];
    source.consignment_hash = keccak(&source.consignment);
    assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
}

/// The operator sets the caps. A smaller `max_consignment_bytes` rejects a
/// consignment that the default accepts.
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

/// Too many Merkle proofs fail on count alone, even if each proof is small.
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

/// Proofs under the per-path-depth cap but over the total byte budget fail
/// the total gate. The per-field caps do not catch this case.
#[cfg(rgb_to_evm)]
#[test]
fn rejects_aggregate_proof_bytes_over_budget() {
    // Each proof is a 32-byte txid + 32 siblings x 32 bytes = 1056 bytes,
    // within MAX_MERKLE_PATH_DEPTH. Use enough to cross the total cap but
    // stay under the proof-count cap.
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

/// The same payload gives the same result for each `consignment_valid`
/// value. The gate never reads the flag.
#[cfg(rgb_to_evm)]
#[test]
fn ignores_consignment_valid_flag_when_bytes_present() {
    let mut source = fixture_source("rgb:any-declared-asset");
    source.consignment_valid = false;
    assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
    source.consignment_valid = true;
    assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
}

/// P0 regression: `consignment_valid: true` with no consignment bytes must
/// fail. The flag cannot replace the bytes.
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

/// The flag cannot fix a wrong hash.
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

// Asset-identity binding, SOURCE path. `validate_source` calls the binding
// after `validate_consignment`. The tests run `validate_source` end to end
// with the mainnet fixture and a stub Esplora.
//
// Intentional asymmetry: here the RGB_ASSET_ID pin applies only if
// `BridgeConfig::is_configured()`. The destination path
// (`validate_destination_anchor` in `networks/rgb/route.rs`) always enforces it.

/// End-to-end asset binding. These tests run the full validator, so they
/// prove that the bind is in the request path. The rule tests in
/// `validation::tests::asset_binding_rule` cannot show this.
///
/// They run on `BFA_BURN_FIXTURE`. The consignment history has a mint, and
/// only a `bfa-validation` build can run a mint script. Without that feature,
/// the cases that must pass RGB consensus are ignored.
#[cfg(rgb_to_evm)]
mod asset_bind {
    use super::*;
    use crate::config::BridgeConfig;
    use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
    use std::sync::Mutex;

    /// Contract id of `BFA_BURN_FIXTURE`. [`fixture_asset_id`] derives it again
    /// and asserts it, so a fixture change fails loudly.
    const FIXTURE_ASSET_ID: &str = "rgb:psO2jKZI-i4fudyA-ORTT8a~-SMaLO6u-69ELk2p-yPRGPJY";

    /// The validated asset identity: the genesis contract id of the fixture.
    fn fixture_asset_id() -> String {
        let t = Transfer::load(Cursor::new(BFA_BURN_FIXTURE)).expect("load BFA fixture");
        let id = t.contract_id().to_string();
        assert_eq!(
            id, FIXTURE_ASSET_ID,
            "BFA fixture contract id drifted - update FIXTURE_ASSET_ID"
        );
        id
    }

    /// An RGB source for the BFA fixture. It shadows [`super::fixture_source`],
    /// which uses the NIA fixture and stays for the payload-gate tests.
    fn fixture_source(asset_id: &str) -> RgbSource {
        RgbSource {
            consignment: BFA_BURN_FIXTURE.to_vec(),
            consignment_hash: keccak(BFA_BURN_FIXTURE),
            ..super::fixture_source(asset_id)
        }
    }

    /// The EVM lock for the one mint in the fixture, as the `FundsIn` read of
    /// the enclave reports it: the mint OpId and 100_000 units. Without an
    /// event that agrees, RGB consensus (`cea`) refuses the mint and each burn
    /// that comes from it.
    fn fixture_mint_events() -> Vec<rgbstd::vm::ether_extension::Event> {
        let mint_opid: [u8; 32] =
            hex::decode("6d72ee6970a5cd28ef6f00a67b95242e088941bd79980739c29a40fb4050e593")
                .unwrap()
                .try_into()
                .unwrap();
        vec![rgbstd::vm::ether_extension::Event::new(
            rgbstd::OpId::from(mint_opid),
            rgbstd::RevealedValue::new(100_000u64),
        )]
    }

    /// Stub Esplora that serves only `GET /block-height/0` with the signet
    /// genesis hash. Offline rgbstd validation of the fixture needs only this.
    /// The resolver calls out only for the genesis-hash chain check. The
    /// fixture embeds its witness txs (added as tentative by
    /// `add_consignment_txes`).
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
                let body = bitcoin::constants::genesis_block(bitcoin::Network::Signet)
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

    /// Fully pinned operator config (`is_configured() == true`) with the
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

    /// Empty operator config (`is_configured() == false`), as in dev/mock.
    fn unconfigured_config() -> BridgeConfig {
        BridgeConfig {
            chain_id: 0,
            bridge_contract: [0u8; 20],
            rgb_asset_id: String::new(),
            gas_tx_allowed_to: None,
            ..Default::default()
        }
    }

    /// Signet header chain with a checkpoint time of "now". The SPV
    /// staleness and chain-net checks pass, so a bound source reaches the
    /// Merkle-proof coverage check. Its "missing merkle proofs" error proves
    /// that all asset-binding checks passed. The fixture carries no proofs for
    /// its witness txs.
    fn fresh_signet_chain() -> Mutex<HeaderChain> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        Mutex::new(HeaderChain::new(
            Network::Signet,
            Checkpoint {
                height: 0,
                hash: [0u8; 32],
                bits: 0x1d00_ffff,
                time: now,
                is_real: false,
                chain_work: None,
            },
        ))
    }

    /// Runs `validate_source` with a stub-Esplora validator and a fresh
    /// signet header chain.
    fn run_validate_source(
        source: &RgbSource,
        config: &BridgeConfig,
    ) -> Result<ValidatedConsignment> {
        run_validate_source_with_events(source, config, &fixture_mint_events())
    }

    /// [`run_validate_source`] with explicit verified EVM locks.
    fn run_validate_source_with_events(
        source: &RgbSource,
        config: &BridgeConfig,
        events: &[rgbstd::vm::ether_extension::Event],
    ) -> Result<ValidatedConsignment> {
        let url = spawn_stub_esplora();
        let validator = RgbValidator::new(url, "signet").expect("validator");
        let chain = fresh_signet_chain();
        let ctx = ValidationContext {
            bridge_config: config,
            rgb_validator: Some(&validator),
            header_chain: &chain,
            chain_pins: &crate::networks::rgb::spv_crosscheck::ChainPins::new(),
            // Source validation never reaches the destination PSBT bind.
            #[cfg(evm_to_rgb)]
            self_owned_psbt_outputs: None,
            #[cfg(evm_to_rgb)]
            psbt_fee_key_paths: None,
            bridge_events: events,
        };
        validate_source(source, &ctx)
    }

    /// Happy path: validated contract_id == declared asset_id == pinned
    /// RGB_ASSET_ID. The failure is in the SPV stage, after the binding and
    /// after the staleness and chain-net checks.
    #[test]
    #[cfg_attr(
        not(feature = "bfa-validation"),
        ignore = "needs bfa-validation to run the mint script of the fixture"
    )]
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

    /// The RGB source must declare its asset. An empty `asset_id` fails
    /// closed in `validate_source_payload`. The pin alone does not bind.
    #[test]
    fn rejects_when_declared_is_empty() {
        let err =
            run_validate_source(&fixture_source(""), &pinned_config(FIXTURE_ASSET_ID)).unwrap_err();
        assert!(
            err.to_string().contains("RGB source asset_id is empty"),
            "expected empty-declared rejection, got: {err}"
        );
    }

    /// Empty declarations fail first. Thus the reachable theft path is a
    /// colluding listener that declares the foreign asset of the consignment.
    /// The RGB_ASSET_ID pin must still reject it.
    #[test]
    #[cfg_attr(
        not(feature = "bfa-validation"),
        ignore = "needs bfa-validation to run the mint script of the fixture"
    )]
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

    /// The listener declares an asset that is not the validated identity.
    /// The declared-vs-validated check fails before the pin check.
    #[test]
    #[cfg_attr(
        not(feature = "bfa-validation"),
        ignore = "needs bfa-validation to run the mint script of the fixture"
    )]
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

    /// Source-path asymmetry: the pin check needs `BridgeConfig::is_configured()`.
    /// An empty config skips the pin, checks only declared == validated, and
    /// reaches SPV. It does NOT fail closed here. The fail-closed checks are
    /// on the destination path
    /// (`networks/rgb/route/tests.rs::asset_bind::rejects_when_pin_absent`)
    /// and, for RGB->EVM, the EVM destination `!is_configured()` rejection
    /// (`networks/evm/validation.rs`, `not(test)`-gated).
    #[test]
    #[cfg_attr(
        not(feature = "bfa-validation"),
        ignore = "needs bfa-validation to run the mint script of the fixture"
    )]
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

    /// The full validator on a real burn. RGB consensus accepts the fixture:
    /// the mint script with its EVM lock, and the two burn scripts. The
    /// summary has the last burn: its OpId, the 10_000 burned units and its
    /// payout recipient. It does not have the earlier burn of 50_000.
    #[test]
    #[cfg(feature = "bfa-validation")]
    fn validates_a_real_burn_and_reads_its_terminal_burn() {
        let validator = RgbValidator::new(spawn_stub_esplora(), "signet").expect("validator");
        let validated = validator
            .validate_consignment(BFA_BURN_FIXTURE, &fixture_mint_events())
            .expect("the BFA burn fixture passes RGB consensus");

        assert_eq!(validated.contract_id, FIXTURE_ASSET_ID);
        assert_eq!(validated.chain_net, "sb");
        assert_eq!(
            validated.mint_op_ids,
            vec!["6d72ee6970a5cd28ef6f00a67b95242e088941bd79980739c29a40fb4050e593".to_string()]
        );
        assert_eq!(validated.all_op_ids.len(), 3, "one mint, two burns");

        let last = validated.last_transition.expect("terminal transition");
        assert_eq!(last.transition_type, bfa::TS_BURN);
        assert_eq!(
            last.op_id,
            "b1477c16bbb2c78d7206084fd0288561ab614de4b09a3cb974d05a1a29011018"
        );
        assert_eq!(last.burned_asset_amount, Some(10_000));
        assert_eq!(
            last.asset_output_amount, 40_000,
            "change kept by the burner"
        );
        assert_eq!(
            last.burn_recipient.map(hex::encode).as_deref(),
            Some("000000000000000000000000436365aab93332ad6555c78b6ab000fcea95c2eb")
        );
    }

    /// The burn comes from a mint. A mint is valid only with the EVM lock that
    /// the enclave verified. With no lock, or a lock for a different amount,
    /// the consignment is refused. Thus a burn of units with no backing does
    /// not get to the release binds.
    #[test]
    #[cfg(feature = "bfa-validation")]
    fn refuses_a_burn_whose_mint_has_no_matching_evm_lock() {
        let id = fixture_asset_id();
        let source = fixture_source(&id);
        let config = pinned_config(&id);

        let err = run_validate_source_with_events(&source, &config, &[]).unwrap_err();
        assert!(
            err.to_string().contains("without a verified FundsIn event"),
            "expected a mint with no EVM lock to be refused, got: {err}"
        );

        let mut short = fixture_mint_events();
        short[0] = rgbstd::vm::ether_extension::Event::new(
            *short[0].reason(),
            rgbstd::RevealedValue::new(99_999u64),
        );
        let err = run_validate_source_with_events(&source, &config, &short).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("evaluation of AluVM script for operation 6d72ee69")
                && msg.contains("Some(1)"),
            "expected the mint script to fail with ERRNO_ISSUED_MISMATCH, got: {msg}"
        );
    }

    /// The enclave finds the settling transition two times. The flat parser
    /// gives its OpId, which becomes `sourceBurnTxId`. The rgbstd walk gives
    /// the burned amount, the recipient and the witness tx. A consignment for
    /// which the two walks pick different burns would mix the OpId of one burn
    /// with the amount and recipient of a different burn.
    ///
    /// The host controls only the order of the bundles in the bytes. This test
    /// serializes the fixture in each order of its three bundles. The two
    /// walks always pick the same transition. RGB consensus accepts only the
    /// original order, because in each other order a transition comes before
    /// the state that it spends.
    #[test]
    #[cfg(feature = "bfa-validation")]
    fn the_two_walks_pick_the_same_transition_in_every_bundle_order() {
        let original = Transfer::load(Cursor::new(BFA_BURN_FIXTURE)).expect("load BFA fixture");
        let bundles: Vec<_> = original.bundles.iter().cloned().collect();
        assert_eq!(bundles.len(), 3, "one mint and two burns");
        let validator = RgbValidator::new(spawn_stub_esplora(), "signet").expect("validator");
        let events = fixture_mint_events();

        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut transfer = original.clone();
            transfer.bundles = Default::default();
            transfer
                .bundles
                .extend(order.iter().map(|i| bundles[*i].clone()))
                .expect("three bundles fit");
            let mut bytes = Vec::new();
            transfer
                .save(&mut bytes)
                .expect("serialize the consignment");

            let (_, _, flat_last, _) = extract_transition_summary(&bytes).expect("flat parse");
            let flat_opid = flat_last.expect("flat last transition").op_id;

            let reloaded = Transfer::load(Cursor::new(&bytes)).expect("reload");
            let rgbstd_opid = reloaded
                .bundles
                .iter()
                .last()
                .and_then(|wb| wb.bundle().known_transitions.iter().last())
                .map(|known| known.opid.to_string())
                .expect("rgbstd last transition");

            assert_eq!(
                flat_opid, rgbstd_opid,
                "bundle order {order:?}: the two walks pick different transitions"
            );

            let result = validator.validate_consignment(&bytes, &events);
            if order == [0, 1, 2] {
                result.expect("the original order passes RGB consensus");
            } else {
                let err = result.expect_err("a different bundle order must be refused");
                assert!(
                    err.to_string().contains("references previous state"),
                    "bundle order {order:?}: expected an ordering failure, got: {err}"
                );
            }
        }
    }

    /// The mint transition of the fixture, with the OpId that the consignment
    /// records for it.
    fn fixture_mint() -> (rgbstd::Transition, rgbstd::OpId) {
        let transfer = Transfer::load(Cursor::new(BFA_BURN_FIXTURE)).expect("load BFA fixture");
        let known = transfer
            .bundles
            .iter()
            .flat_map(|wb| wb.bundle().known_transitions.iter())
            .find(|k| k.transition.transition_type == rgbstd::TransitionType::with(bfa::TS_BRIDGE))
            .expect("the fixture has a mint");
        (known.transition.clone(), known.opid)
    }

    /// A deposit names its mint by OpId, and the OpId is a hash of the full
    /// transition. Thus the deposit fixes the mint right that the mint spends,
    /// and the outputs of the mint. A mint with a different right, or with
    /// different outputs, has a different OpId and is a different mint.
    #[test]
    fn a_mint_opid_commits_to_the_right_it_spends_and_to_its_outputs() {
        use rgbstd::Operation as _;

        let (mint, opid) = fixture_mint();
        assert_eq!(mint.id(), opid, "the OpId is the hash of the transition");

        // The mint spends one input, and that input is a mint right.
        let inputs: Vec<_> = (&mint.inputs).into_iter().collect();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].ty, rgbstd::AssignmentType::with(bfa::OS_BRIDGE));

        // A different mint right gives a different OpId.
        let mut other_right = mint.clone();
        let mut input = inputs[0];
        input.no += 1;
        other_right.inputs.push(input).expect("add an input");
        other_right
            .inputs
            .remove(&inputs[0])
            .expect("remove an input");
        assert_ne!(other_right.id(), opid);

        // Different outputs give a different OpId.
        let mut other_outputs = mint.clone();
        other_outputs
            .assignments
            .remove(&rgbstd::AssignmentType::with(bfa::OS_ASSET))
            .expect("remove the asset outputs");
        assert_ne!(other_outputs.id(), opid);
    }

    /// The mint right is a seal on one Bitcoin UTXO, and the witness tx of the
    /// mint spends that UTXO. Each tx that commits this mint must spend the
    /// same UTXO, so only one of them can confirm.
    #[test]
    fn the_mint_witness_tx_spends_the_utxo_of_the_mint_right() {
        use rgbstd::{Assign, Operation as _, TypedAssigns};

        let transfer = Transfer::load(Cursor::new(BFA_BURN_FIXTURE)).expect("load BFA fixture");
        let (mint, opid) = fixture_mint();
        let right = (&mint.inputs).into_iter().next().expect("one input");
        assert_eq!(
            right.op,
            transfer.genesis.id(),
            "the right comes from genesis"
        );

        // The seal of that right in genesis.
        let rights = transfer
            .genesis
            .assignments
            .get(&rgbstd::AssignmentType::with(bfa::OS_BRIDGE))
            .expect("genesis assigns mint rights");
        let TypedAssigns::Declarative(rights) = rights else {
            panic!("a mint right is declarative");
        };
        let Assign::Revealed { seal, .. } = &rights[right.no as usize] else {
            panic!("the genesis seal of the right is revealed");
        };

        // The witness tx of the bundle that has the mint.
        let witness_tx = transfer
            .bundles
            .iter()
            .find(|wb| wb.bundle().known_transitions.iter().any(|k| k.opid == opid))
            .and_then(|wb| wb.pub_witness.tx())
            .expect("the fixture embeds the mint witness tx");
        assert!(
            witness_tx
                .input
                .iter()
                .any(|txin| txin.previous_output.txid == seal.txid
                    && txin.previous_output.vout == seal.vout.into_u32()),
            "the mint witness tx must spend the UTXO of the mint right"
        );
    }

    /// The fixture with the mint witness tx changed: input `input` of that tx
    /// spends a different outpoint. The outputs do not change, so the
    /// commitment to the mint stays valid.
    #[cfg(feature = "bfa-validation")]
    fn fixture_with_mint_witness_input_replaced(input: usize) -> Vec<u8> {
        use rgbstd::validation::PubWitness;

        let original = Transfer::load(Cursor::new(BFA_BURN_FIXTURE)).expect("load BFA fixture");
        let (_, opid) = fixture_mint();
        let mut bundles: Vec<_> = original.bundles.iter().cloned().collect();
        let mint_bundle = bundles
            .iter_mut()
            .find(|wb| wb.bundle().known_transitions.iter().any(|k| k.opid == opid))
            .expect("the fixture has the mint bundle");
        let mut tx = mint_bundle
            .pub_witness
            .tx()
            .expect("the fixture embeds the mint witness tx")
            .clone();
        tx.input[input].previous_output.vout += 7;
        mint_bundle.pub_witness = PubWitness::Tx(tx);

        let mut transfer = original.clone();
        transfer.bundles = Default::default();
        transfer.bundles.extend(bundles).expect("three bundles fit");
        let mut bytes = Vec::new();
        transfer
            .save(&mut bytes)
            .expect("serialize the consignment");
        bytes
    }

    /// RGB consensus refuses a mint whose witness tx does not spend the UTXO
    /// of the mint right. The mint witness tx of the fixture has two inputs:
    /// input 0 spends the mint right, input 1 pays the fee.
    ///
    /// With a different outpoint on input 0, the consignment is refused: the
    /// tx does not close the seal of the right. With a different outpoint on
    /// input 1, consensus accepts the consignment. Thus the seal causes the
    /// refusal, not the change of the tx. A second tx for the same mint is
    /// possible, but it must spend the same UTXO, so only one tx can confirm.
    #[test]
    #[cfg(feature = "bfa-validation")]
    fn refuses_a_mint_witness_tx_that_does_not_spend_the_mint_right() {
        const RIGHT_UTXO: &str =
            "8c2a99d569e9d3cfb5abe1697cdb73d170835672db9c161d684cb01d50c6b9e6:1";

        let original = Transfer::load(Cursor::new(BFA_BURN_FIXTURE)).expect("load BFA fixture");
        let (_, opid) = fixture_mint();
        let witness_tx = original
            .bundles
            .iter()
            .find(|wb| wb.bundle().known_transitions.iter().any(|k| k.opid == opid))
            .and_then(|wb| wb.pub_witness.tx())
            .expect("the fixture embeds the mint witness tx");
        assert_eq!(witness_tx.input.len(), 2);
        assert_eq!(witness_tx.input[0].previous_output.to_string(), RIGHT_UTXO);

        let validator = RgbValidator::new(spawn_stub_esplora(), "signet").expect("validator");
        let events = fixture_mint_events();

        let err = validator
            .validate_consignment(&fixture_with_mint_witness_input_replaced(0), &events)
            .expect_err("a mint that does not spend the mint right must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("does not closes seal") && msg.contains(RIGHT_UTXO),
            "expected a seal-closing failure on the mint right, got: {msg}"
        );

        validator
            .validate_consignment(&fixture_with_mint_witness_input_replaced(1), &events)
            .expect("a different fee input does not break the seal of the right");
    }

    /// The enclave gives RGB consensus the EVM lock for the OpId that the
    /// deposit names. A lock for a different OpId does not validate the mint,
    /// although the amount is correct. Thus one deposit can back only the mint
    /// that it names.
    #[test]
    #[cfg(feature = "bfa-validation")]
    fn refuses_a_mint_whose_evm_lock_names_a_different_transition() {
        let id = fixture_asset_id();
        let other_mint = vec![rgbstd::vm::ether_extension::Event::new(
            rgbstd::OpId::from([0x77; 32]),
            rgbstd::RevealedValue::new(100_000u64),
        )];
        let err =
            run_validate_source_with_events(&fixture_source(&id), &pinned_config(&id), &other_mint)
                .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("evaluation of AluVM script for operation 6d72ee69")
                && msg.contains("Some(1)"),
            "expected the mint script to fail with ERRNO_ISSUED_MISMATCH, got: {msg}"
        );
    }

    /// The BFA fixture with `transfers` more `Transfer` transitions and one
    /// last `Burn` after its history. Each new transition spends the output of
    /// the transition before it, in its own witness tx.
    #[cfg(feature = "bfa-validation")]
    fn fixture_with_long_history(transfers: usize) -> Vec<u8> {
        use bitcoin::hashes::Hash as _;
        use rgbstd::containers::WitnessBundle;
        use rgbstd::rgbcore::commit_verify::{mpc, CommitId, TryCommitVerify};
        use rgbstd::rgbcore::dbc::opret::OpretProof;
        use rgbstd::rgbcore::dbc::Anchor;
        use rgbstd::rgbcore::seals::txout::TxPtr;
        use rgbstd::validation::{DbcProof, PubWitness};
        use rgbstd::{
            Assign, AssignmentType, Assignments, GraphSeal, Inputs, KnownTransition, MetaType,
            MetaValue, Metadata, Operation as _, Opout, RevealedValue, Transition,
            TransitionBundle, TransitionType, TypedAssigns,
        };
        use strict_encoding::StrictDumb;

        let mut transfer = Transfer::load(Cursor::new(BFA_BURN_FIXTURE)).expect("load BFA fixture");
        let contract_id = transfer.contract_id();
        let asset = AssignmentType::with(bfa::OS_ASSET);

        // The unspent output of the fixture: 40_000 units on an explicit seal.
        let last = transfer
            .bundles
            .iter()
            .last()
            .and_then(|wb| wb.bundle().known_transitions.iter().last())
            .expect("fixture last transition")
            .clone();
        let TypedAssigns::Fungible(outs) = last.transition.assignments.get(&asset).expect("change")
        else {
            panic!("asset output is fungible");
        };
        let Assign::Revealed { seal, state } = &outs[0] else {
            panic!("the change seal is revealed");
        };
        let amount = state.as_u64();
        let TxPtr::Txid(seal_txid) = seal.txid else {
            panic!("the fixture change seal names its txid");
        };
        let mut prev_opout = Opout::new(last.opid, asset, 0);
        let mut prev_outpoint = bitcoin::OutPoint::new(seal_txid, seal.vout.into_u32());

        let mut new_bundles = Vec::with_capacity(transfers + 1);
        for i in 0..=transfers {
            let is_burn = i == transfers;

            let mut inputs = Inputs::strict_dumb();
            inputs.push(prev_opout).unwrap();
            inputs.remove(&Opout::strict_dumb()).unwrap();

            let mut assignments = Assignments::<GraphSeal>::default();
            let mut metadata = Metadata::default();
            if is_burn {
                let mut burned = MetaValue::default();
                burned.extend(amount.to_le_bytes()).unwrap();
                metadata
                    .add_value(MetaType::with(bfa::MS_BURNED_ASSET), burned)
                    .unwrap();
                let mut recipient = MetaValue::default();
                recipient.extend([0x22u8; 32]).unwrap();
                metadata
                    .add_value(MetaType::with(bfa::MS_BURN_RECIPIENT), recipient)
                    .unwrap();
            } else {
                let mut typed = TypedAssigns::<GraphSeal>::Fungible(StrictDumb::strict_dumb());
                if let TypedAssigns::Fungible(legs) = &mut typed {
                    *legs.iter_mut().next().unwrap() = Assign::Revealed {
                        seal: GraphSeal::with_blinding(TxPtr::WitnessTx, 1u32, i as u64),
                        state: RevealedValue::new(amount),
                    };
                }
                assignments.insert(asset, typed).unwrap();
            }

            let transition = Transition {
                ffv: Default::default(),
                contract_id,
                nonce: i as u64,
                transition_type: TransitionType::with(if is_burn {
                    bfa::TS_BURN
                } else {
                    bfa::TS_TRANSFER
                }),
                metadata,
                globals: Default::default(),
                inputs,
                assignments,
                signature: None,
            };
            let opid = transition.id();

            let mut bundle = TransitionBundle::strict_dumb();
            bundle.input_map.insert(prev_opout, opid).unwrap();
            bundle.input_map.remove(&Opout::strict_dumb()).unwrap();
            *bundle.known_transitions.iter_mut().next().unwrap() =
                KnownTransition::new(opid, transition);
            let bundle_id = bundle.bundle_id();

            // Commit the bundle in an OP_RETURN output of its witness tx.
            let protocol = mpc::ProtocolId::from(contract_id);
            let mut source = mpc::MultiSource {
                static_entropy: Some(i as u64),
                ..Default::default()
            };
            source
                .messages
                .insert(protocol, mpc::Message::from(bundle_id))
                .unwrap();
            let tree = mpc::MerkleTree::try_commit(&source).expect("mpc tree");
            let commitment = tree.commit_id();
            let mpc_proof = mpc::MerkleBlock::from(tree)
                .to_merkle_proof(protocol)
                .expect("mpc proof");

            let tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: prev_outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![
                    bitcoin::TxOut {
                        value: bitcoin::Amount::ZERO,
                        script_pubkey: bitcoin::ScriptBuf::new_op_return(
                            commitment.to_byte_array(),
                        ),
                    },
                    bitcoin::TxOut {
                        value: bitcoin::Amount::from_sat(1_000),
                        script_pubkey: bitcoin::ScriptBuf::new_p2wpkh(
                            &bitcoin::WPubkeyHash::from_byte_array([0x33; 20]),
                        ),
                    },
                ],
            };
            prev_outpoint = bitcoin::OutPoint::new(tx.compute_txid(), 1);
            prev_opout = Opout::new(opid, asset, 0);

            new_bundles.push(WitnessBundle {
                pub_witness: PubWitness::Tx(tx),
                anchor: Anchor {
                    mpc_proof,
                    dbc_proof: DbcProof::Opret(OpretProof::default()),
                },
                bundle,
            });
        }
        transfer.bundles.extend(new_bundles).expect("bundles fit");
        let mut bytes = Vec::new();
        transfer
            .save(&mut bytes)
            .expect("serialize the consignment");
        bytes
    }

    /// A burn source for `consignment`, with one Merkle proof for each witness
    /// txid. Each proof has `depth` siblings. The proofs are not valid. They
    /// have the size of real proofs, which is what the request caps count.
    #[cfg(feature = "bfa-validation")]
    fn sized_source(consignment: &[u8], witness_txids: &[[u8; 32]], depth: usize) -> RgbSource {
        RgbSource {
            consignment: consignment.to_vec(),
            consignment_hash: keccak(consignment),
            merkle_proofs: witness_txids
                .iter()
                .enumerate()
                .map(|(i, txid)| MerkleProofEntry {
                    txid: txid.to_vec(),
                    block_height: 900_000 + i as u32,
                    tx_position: 4_000,
                    merkle_path: vec![vec![0x5a; 32]; depth],
                })
                .collect(),
            ..super::fixture_source(FIXTURE_ASSET_ID)
        }
    }

    /// RGB consensus accepts a history of 200 transfers after the fixture.
    /// This test is fast and keeps [`fixture_with_long_history`] correct. The
    /// test below uses the same function for 10_000 transfers.
    #[test]
    #[cfg(feature = "bfa-validation")]
    fn validates_a_history_of_200_transfers() {
        let consignment = fixture_with_long_history(200);
        let validator = RgbValidator::new(spawn_stub_esplora(), "signet").expect("validator");
        let validated = validator
            .validate_consignment(&consignment, &fixture_mint_events())
            .expect("the long history passes RGB consensus");

        // 1 mint and 2 burns in the fixture, then 200 transfers and 1 burn.
        assert_eq!(validated.all_op_ids.len(), 204);
        assert_eq!(validated.witness_txids.len(), 204);
        let last = validated.last_transition.expect("terminal transition");
        assert_eq!(last.transition_type, bfa::TS_BURN);
        assert_eq!(last.burned_asset_amount, Some(40_000));
    }

    /// A burn with a history of 10_000 transfers passes with the default
    /// limits. The test makes the real consignment and checks each limit:
    ///
    /// 1. RGB consensus accepts the consignment.
    /// 2. The consignment and its Merkle proofs pass the request caps
    ///    (`MAX_CONSIGNMENT_BYTES`, `MAX_MERKLE_PROOFS`,
    ///    `MAX_TOTAL_PROOF_BYTES`). Each proof has 13 siblings, the depth of a
    ///    full mainnet block.
    /// 3. The full sign request is smaller than the frame limit, and the
    ///    enclave reads it.
    ///
    /// Ignored by default because it is slow in a debug build. Set
    /// `SAVE_LONG_HISTORY_CONSIGNMENT` to a file path to keep the consignment.
    #[test]
    #[cfg(feature = "bfa-validation")]
    #[ignore = "validates a history of 10_000 transfers; run it on request"]
    fn a_history_of_10_000_transfers_fits_the_default_limits() {
        use crate::framing::{self, MAX_MESSAGE_SIZE};
        use crate::networks::evm::validation::MAX_FUNDS_OUT_CALL_DATA_LEN;
        use crate::proto::enclave_request::Request;
        use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};
        use crate::proto::{EnclaveRequest, EvmDestination, MintAncestor, SignRequest};

        const TRANSFERS: usize = 10_000;
        // 1 mint and 2 burns in the fixture, then the transfers and 1 burn.
        const TRANSITIONS: usize = TRANSFERS + 4;

        let consignment = fixture_with_long_history(TRANSFERS);
        if let Ok(path) = std::env::var("SAVE_LONG_HISTORY_CONSIGNMENT") {
            std::fs::write(&path, &consignment).expect("save the consignment");
        }

        // 1. RGB consensus.
        let validator = RgbValidator::new(spawn_stub_esplora(), "signet").expect("validator");
        let start = std::time::Instant::now();
        let validated = validator
            .validate_consignment(&consignment, &fixture_mint_events())
            .expect("the 10_000-transfer history passes RGB consensus");
        let validate_ms = start.elapsed().as_millis();
        assert_eq!(validated.all_op_ids.len(), TRANSITIONS);
        assert_eq!(validated.witness_txids.len(), TRANSITIONS);

        // 2. Request caps.
        let cfg = BridgeConfig::default();
        assert!(consignment.len() <= cfg.max_consignment_bytes);
        let mut source = sized_source(&consignment, &validated.witness_txids, 13);
        source.mint_ancestors = validated
            .mint_op_ids
            .iter()
            .map(|opid| MintAncestor {
                op_id: hex::decode(opid).expect("opid hex"),
                tx_hash: vec![0x77; 32],
            })
            .collect();
        validate_source_payload(&source, &cfg).expect("the source passes the default caps");
        let proof_bytes: usize = source
            .merkle_proofs
            .iter()
            .map(|p| p.txid.len() + p.merkle_path.iter().map(Vec::len).sum::<usize>())
            .sum();

        // 3. Frame. The calldata has its maximum size.
        let request = EnclaveRequest {
            request: Some(Request::Sign(SignRequest {
                amount: 40_000,
                source_network: Some(SourceNetwork::RgbSource(source)),
                destination_network: Some(DestinationNetwork::EvmDestination(EvmDestination {
                    call_data: vec![0x11; MAX_FUNDS_OUT_CALL_DATA_LEN],
                    ..Default::default()
                })),
            })),
        };
        let mut frame = Vec::new();
        framing::write_message(&mut frame, &request).expect("write the frame");
        let body = frame.len() - 4;
        assert!(
            body <= MAX_MESSAGE_SIZE as usize,
            "the request ({body} bytes) is larger than the frame limit"
        );
        let decoded: EnclaveRequest =
            framing::read_message(&mut Cursor::new(&frame)).expect("the enclave reads the frame");
        assert_eq!(decoded, request);

        println!(
            "10_000 transfers: consignment {} bytes, {} proofs, proof bytes {proof_bytes}, \
             request {body} bytes, consensus validation {validate_ms} ms",
            consignment.len(),
            TRANSITIONS,
        );
    }

    // No end-to-end test for an empty validated contract_id.
    // `validate_consignment` derives it from the genesis, so it is never
    // empty. `asset_binding_rule::rejects_empty_validated_contract_id` covers
    // the rule.
}

/// The release amount of a burn comes from its `MS_BURNED_ASSET` metadata
/// ([`read_last_transition_burned_asset`]). The burner cannot set that value
/// freely. The BFA burn script requires
/// `sum(OS_ASSET inputs) == MS_BURNED_ASSET + sum(OS_ASSET outputs)`, and RGB
/// consensus runs the script on each `TS_BURN`.
///
/// These tests run the pinned BFA schema and scripts through
/// `Schema::validate_state`, the step that `validate_consignment` runs for
/// each operation. They use the same contract-state and VM-extension types as
/// the enclave. Only the transition and its input state are synthetic.
#[cfg(feature = "bfa-validation")]
mod burn_amount_is_bound_by_consensus {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use rgbstd::contract::IssuerWrapper;
    use rgbstd::persistence::{MemContract, MemContractState};
    use rgbstd::validation::{Failure, ValidationError};
    use rgbstd::vm::ether_extension::{BridgedContract, Event, IssuedAmountCheckExt};
    use rgbstd::vm::{ContractStateEvolve, OrdOpRef, WitnessOrd};
    use rgbstd::{
        Assign, AssignmentType, Assignments, BundleId, Genesis, GraphSeal, Inputs, MetaType,
        MetaValue, Metadata, OpId, Operation, Opout, RevealedState, RevealedValue, Transition,
        TransitionType, Txid, TypedAssigns,
    };
    use schemata::{BridgedFungibleAsset, ERRNO_BURN_MISMATCH};
    use strict_encoding::StrictDumb;

    use super::bfa;

    type State<'a> = BridgedContract<'a, MemContract<MemContractState>>;

    fn asset() -> AssignmentType {
        AssignmentType::with(bfa::OS_ASSET)
    }

    fn meta_value(bytes: &[u8]) -> MetaValue {
        let mut value = MetaValue::default();
        value.extend(bytes.iter().copied()).unwrap();
        value
    }

    /// Runs consensus on one `TS_BURN`. `inputs` are the asset units of each
    /// closed allocation, `change` goes to new allocations, and `declared` is
    /// the `MS_BURNED_ASSET` value.
    fn validate_burn(inputs: &[u64], change: &[u64], declared: u64) -> Result<(), ValidationError> {
        let schema = BridgedFungibleAsset::schema();
        let types = BridgedFungibleAsset::types();
        let scripts = BridgedFungibleAsset::scripts();

        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();

        let mut metadata = Metadata::default();
        metadata
            .add_value(
                MetaType::with(bfa::MS_BURNED_ASSET),
                meta_value(&declared.to_le_bytes()),
            )
            .unwrap();
        metadata
            .add_value(
                MetaType::with(bfa::MS_BURN_RECIPIENT),
                meta_value(&[0x22; 32]),
            )
            .unwrap();

        // The state that the burn closes. A transition must have one input or
        // more, so a burn with no asset inputs closes a bridge right.
        let mut prev_state = BTreeMap::<AssignmentType, Vec<RevealedState>>::new();
        let mut opouts = std::collections::BTreeSet::new();
        for (no, units) in inputs.iter().enumerate() {
            opouts.insert(Opout::new(OpId::from([0x11; 32]), asset(), no as u16));
            prev_state
                .entry(asset())
                .or_default()
                .push(RevealedState::Fungible(RevealedValue::new(*units)));
        }
        if inputs.is_empty() {
            let right = AssignmentType::with(bfa::OS_BRIDGE);
            opouts.insert(Opout::new(OpId::from([0x11; 32]), right, 0));
            prev_state
                .entry(right)
                .or_default()
                .push(RevealedState::Void);
        }

        // `Inputs` cannot be empty. Add the real inputs to its dumb value, then
        // remove the dumb input.
        let mut inputs = Inputs::strict_dumb();
        for opout in opouts {
            inputs.push(opout).unwrap();
        }
        inputs.remove(&Opout::strict_dumb()).unwrap();

        let mut assignments = Assignments::<GraphSeal>::default();
        if !change.is_empty() {
            let leg = |units: &u64| Assign::Revealed {
                seal: GraphSeal::strict_dumb(),
                state: RevealedValue::new(*units),
            };
            // The vector type is not exported and cannot be empty. Start with
            // its dumb value (one element) and replace that element.
            let mut typed = TypedAssigns::<GraphSeal>::Fungible(StrictDumb::strict_dumb());
            if let TypedAssigns::Fungible(legs) = &mut typed {
                *legs.iter_mut().next().unwrap() = leg(&change[0]);
                for units in &change[1..] {
                    legs.push(leg(units)).unwrap();
                }
            }
            assignments.insert(asset(), typed).unwrap();
        }

        let transition = Transition {
            ffv: Default::default(),
            contract_id,
            nonce: 0,
            transition_type: TransitionType::with(bfa::TS_BURN),
            metadata,
            globals: Default::default(),
            inputs,
            assignments,
            signature: None,
        };

        let events: Vec<Event> = Vec::new();
        let state = Rc::new(RefCell::new(State::init(((&schema, contract_id), &events))));
        schema.validate_state::<State<'_>, IssuedAmountCheckExt>(
            &types,
            &scripts,
            &genesis,
            OrdOpRef::Transition(
                &transition,
                {
                    use bitcoin::hashes::Hash;
                    Txid::from_byte_array([0x33; 32])
                },
                WitnessOrd::Tentative,
                BundleId::strict_dumb(),
            ),
            state,
            &prev_state,
        )
    }

    fn assert_burn_mismatch(result: Result<(), ValidationError>) {
        match result {
            Err(ValidationError::InvalidConsignment(Failure::ScriptFailure(_, code, _))) => {
                assert_eq!(code, Some(ERRNO_BURN_MISMATCH), "burn script errno")
            }
            other => panic!("expected the burn script to reject, got {other:?}"),
        }
    }

    /// Valid burns: a full burn, and a partial burn with change.
    #[test]
    fn accepts_a_burn_that_declares_what_it_destroyed() {
        validate_burn(&[1_000], &[], 1_000).expect("full burn");
        validate_burn(&[600, 400], &[], 1_000).expect("full burn of two allocations");
        validate_burn(&[1_000], &[600], 400).expect("partial burn with change");
    }

    /// The burn destroys 1 unit and declares 1_000_000.
    #[test]
    fn rejects_a_burn_that_declares_more_than_it_destroyed() {
        assert_burn_mismatch(validate_burn(&[1], &[], 1_000_000));
        assert_burn_mismatch(validate_burn(&[1_000], &[], 1_001));
    }

    /// The burn keeps change but declares the full input as burned.
    #[test]
    fn rejects_a_burn_that_declares_its_change_as_burned() {
        assert_burn_mismatch(validate_burn(&[1_000], &[600], 1_000));
    }

    /// A burn with no asset inputs cannot declare a burned amount.
    #[test]
    fn rejects_a_burn_with_no_asset_inputs() {
        assert_burn_mismatch(validate_burn(&[], &[], 1_000));
    }

    /// The burn destroys more units than it declares.
    #[test]
    fn rejects_a_burn_that_declares_less_than_it_destroyed() {
        assert_burn_mismatch(validate_burn(&[1_000], &[], 999));
    }
}
