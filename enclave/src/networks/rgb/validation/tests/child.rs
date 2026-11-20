//! A validator child of this test binary validates as this process does: it
//! reads each burn the same, and refuses each consignment with the same error.

use std::cell::Cell;
use std::num::NonZeroU32;
use std::sync::Mutex;

use super::caps::{dummies_for, many_burns};
use super::*;
use crate::config::DEFAULT_SPV_MIN_CONFIRMATIONS;
use crate::error::EnclaveError;
use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
use crate::networks::rgb::spv_crosscheck::{buried_header_within, safe_height};
use crate::test_support::{chain_with_witnesses, far_deadline};

const MIB: u64 = 1024 * 1024;

/// One validation in this process and one in a child, with the same
/// resolvers and the values in force of the calling test.
fn here_and_in_child(
    bytes: &[u8],
    headers: &dyn BuriedHeaders,
    lists: &ListAccess<'_>,
) -> (Result<ValidatedConsignment>, Result<ValidatedConsignment>) {
    let validator = validator();
    let here = validator.validate_consignment(bytes, Some(&bind_all), headers, lists);
    let limits = crate::limits::get();
    let there = validator.validate_in_child(
        bytes,
        Some(&bind_all),
        headers,
        lists,
        &limits,
        far_deadline(),
    );
    (here, there)
}

/// The enclave chain as the burn path serves it: buried headers up to the
/// safe height that it reads once.
struct Served<'a> {
    chain: &'a Mutex<HeaderChain>,
    safe: Option<NonZeroU32>,
}

impl<'a> Served<'a> {
    fn new(chain: &'a Mutex<HeaderChain>) -> Self {
        let safe = safe_height(&chain.lock().unwrap(), DEFAULT_SPV_MIN_CONFIRMATIONS);
        Self { chain, safe }
    }
}

impl BuriedHeaders for Served<'_> {
    fn buried_header(&self, height: u32) -> Result<bitcoin::block::Header> {
        let chain = self.chain.lock().unwrap();
        buried_header_within(&chain, height, self.safe, DEFAULT_SPV_MIN_CONFIRMATIONS)
    }

    fn safe_height(&self) -> Option<NonZeroU32> {
        self.safe
    }
}

/// A plain burn, a burn of two mints and a listed burn read the same in a
/// child as here. Only the transitions by witness stay empty.
#[test]
fn a_burn_validated_in_the_child_reads_as_in_process() {
    let unrelated = [RejectListEntry {
        opout: OpoutKey {
            op: [0x99; 32],
            ty: 4000,
            no: 0,
        },
        reject: true,
    }];
    let reads = Cell::new(0);
    let read = |list: &RejectListContract| {
        reads.set(reads.get() + 1);
        assert_eq!(list.address, LIST);
        Ok(decisions(&unrelated, unrelated.len()))
    };
    let reading = ListAccess {
        bind_asset: &any_asset,
        read: Some(&read),
    };
    let cases = [
        ("a plain burn", burn_bytes(), open_lists()),
        (
            "a burn of two mints",
            burn_of_two_mints().consignment(),
            open_lists(),
        ),
        ("a listed burn", listed_burn().0.consignment(), reading),
    ];
    for (case, bytes, lists) in cases {
        let chain = mined(&witness_ids(&bytes));
        let (here, there) = here_and_in_child(&bytes, &chain, &lists);
        let (here, there) = (here.expect(case), there.expect(case));
        assert_same(&there, &here);
        assert!(there.transitions_by_witness.is_empty(), "{case}");
    }
    assert_eq!(reads.get(), 2, "the list is read here and for the child");
}

/// Each refusal comes back from a child with the code and the text it has
/// here: a refusal of the child's own, or an error the enclave keeps.
#[test]
fn a_refusal_through_the_child_matches_the_refusal_in_process() {
    let check = |case: &str,
                 bytes: &[u8],
                 headers: &dyn BuriedHeaders,
                 lists: &ListAccess<'_>,
                 code: u32| {
        let (here, there) = here_and_in_child(bytes, headers, lists);
        let (here, there) = (here.expect_err(case), there.expect_err(case));
        assert_eq!(there.to_string(), here.to_string(), "{case}");
        let codes = (here.error_code(), there.error_code());
        assert_eq!(codes, (code, code), "{case}: {there}");
    };
    let unmined = MinedBlocks::of(&[]);
    check(
        "invalid bytes",
        b"not-a-consignment",
        &unmined,
        &open_lists(),
        3,
    );
    let v0 = include_bytes!("../../../../../tests/fixtures/v0_bfa_burn.rgbc");
    check("a V0 file", v0, &unmined, &open_lists(), 3);

    let bytes = burn_bytes();
    let ids = witness_ids(&bytes);
    let burn = *ids.last().unwrap();
    let foreign =
        |_: &str| -> Result<()> { Err(EnclaveError::CrossCheck("not the pinned asset".into())) };
    let foreign = ListAccess {
        bind_asset: &foreign,
        read: None,
    };
    check("a foreign asset", &bytes, &mined(&ids), &foreign, 3);
    let unproven = reproven(&bytes, |txid, proof| {
        if txid == burn {
            *proof = None;
        }
    });
    check(
        "an unproven witness",
        &unproven,
        &mined(&ids),
        &open_lists(),
        3,
    );

    // The burn is proven at a height above the tip of the enclave chain.
    let display: Vec<[u8; 32]> = ids.iter().copied().map(display_bytes).collect();
    let enclave = chain_with_witnesses(&display, DEFAULT_SPV_MIN_CONFIRMATIONS - 1);
    let above = reproven(&bytes, |txid, proof| {
        if txid == burn {
            proof.as_mut().unwrap().block_height = NonZeroU32::new(900_000).unwrap();
        }
    });
    let served = Served::new(&enclave);
    check("a header above the tip", &above, &served, &open_lists(), 9);
    // The checkpoint is above every proof, so the chain has no such header.
    let checkpoint = Mutex::new(HeaderChain::new(
        Network::Regtest,
        Checkpoint {
            height: 100,
            hash: [0; 32],
            bits: 0x207f_ffff,
            time: 1_700_000_000,
            is_real: false,
            chain_work: None,
        },
    ));
    let served = Served::new(&checkpoint);
    check(
        "a header below the checkpoint",
        &bytes,
        &served,
        &open_lists(),
        3,
    );

    let (history, right, ..) = listed_burn();
    let rejected = [RejectListEntry {
        opout: key(right.opout),
        reject: true,
    }];
    let read = |_: &RejectListContract| Ok(decisions(&rejected, rejected.len()));
    let lists = ListAccess {
        bind_asset: &any_asset,
        read: Some(&read),
    };
    let listed = history.consignment();
    let chain = mined(&witness_ids(&listed));
    check("a burn the list rejects", &listed, &chain, &lists, 3);

    // Last, as the lowered cap holds for the rest of the test.
    crate::limits::change_for_test(|l| l.max_witness_check_cost = MIB);
    let wide = many_burns(issue(), 256, dummies_for(2 * MIB));
    check(
        "a refusal of the cost gate",
        &wide,
        &unmined,
        &open_lists(),
        3,
    );
}

/// The child takes the limits in force here: a cap that a change lowered
/// refuses a burn that the image value admits, and names the lowered value.
#[test]
fn the_validator_uses_the_limits_in_force() {
    let wide = many_burns(issue(), 256, dummies_for(2 * MIB));
    let unmined = MinedBlocks::of(&[]);
    let in_child = || {
        let limits = crate::limits::get();
        validator()
            .validate_in_child(
                &wide,
                Some(&bind_all),
                &unmined,
                &open_lists(),
                &limits,
                far_deadline(),
            )
            .unwrap_err()
            .to_string()
    };
    // The image value admits it: rgb-lib asks for a header the chain lacks.
    let err = in_child();
    assert!(err.contains("no header at height"), "{err}");
    crate::limits::change_for_test(|l| l.max_witness_check_cost = MIB);
    let err = in_child();
    assert!(err.contains(&format!("(max {MIB})")), "{err}");
}
