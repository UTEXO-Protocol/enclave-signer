//! The request memory model (`memory.rs`), measured on the enclave side of a
//! whole burn request: the frame read, the shape check, the decode and
//! `dispatch`, with the decoded request alive while a validator child
//! validates the source. The child holds the validation heap in its own
//! process, so the enclave keeps only the read of its frame.

use std::io::Cursor;

use sha3::{Digest, Keccak256};

use crate::config::BridgeConfig;
use crate::framing;
use crate::memory::{peak, WIRE_ELEMENT_BYTES};
use crate::networks::rgb::validation::RgbValidator;
use crate::proto::enclave_request::Request;
use crate::proto::enclave_response::Response;
use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};
use crate::proto::{EnclaveRequest, EvmDestination, RgbSource, SignRequest};
use crate::server::ServerContext;
use crate::state::EnclaveState;
use crate::test_support::bfa_consignment::{self as gen, History, Issue};
use crate::test_support::{chain_with_witnesses, far_deadline};

const BRIDGE: [u8; 20] = [0xB1; 20];
const CHAIN: u64 = 42161;
const PAYEE: [u8; 20] = [0x43; 20];
const MINTED: u64 = 100_000;

/// A mint, `transfers` transfers and a burn of everything.
fn burn_after(transfers: usize) -> History {
    let utxo = gen::outpoint(0xA0, 0);
    let mut history = History::issue(Issue::new(CHAIN, BRIDGE, vec![utxo]));
    let right = history.genesis_right(0, utxo);
    let mut units = history.mint_owned(right, MINTED, 90);
    for _ in 0..transfers {
        units = history.transfer(units, MINTED);
    }
    history.burn(
        units,
        MINTED,
        Some(MINTED),
        Some(gen::burn_reason_for(PAYEE)),
    );
    history
}

/// The framed burn request for `history`, every witness mined and proven,
/// and a burn signer that holds the chain. The asset has no reject list, so
/// no RPC read runs: responses from the RPC are outside the model. The
/// destination is empty: every source check passes, then the destination
/// check refuses the request. That keeps the test on the source path.
fn framed_burn(history: &History) -> (Vec<u8>, ServerContext) {
    let consignment = history.consignment();
    let witnesses: Vec<[u8; 32]> = history
        .bundles
        .iter()
        .map(|wb| {
            let mut txid = bitcoin::hashes::Hash::to_byte_array(wb.witness_id());
            txid.reverse();
            txid
        })
        .collect();
    let chain = chain_with_witnesses(&witnesses, 5);
    let cfg = BridgeConfig {
        funds_in_contract: BRIDGE,
        token_contract: [0x7e; 20],
        chain_id: CHAIN,
        rgb_asset_id: history.contract_id.to_string(),
        ..BridgeConfig::default()
    };
    let state = EnclaveState::default();
    state.initialize_from_seed([7; 64]).unwrap();
    let mut ctx = ServerContext::new(state, cfg, chain);
    ctx.launch.get_mut().unwrap().rgb_validator = Some(RgbValidator::new("regtest").unwrap());

    let request = EnclaveRequest {
        request: Some(Request::Sign(SignRequest {
            amount: MINTED,
            source_network: Some(SourceNetwork::RgbSource(RgbSource {
                consignment_hash: Keccak256::digest(&consignment).to_vec(),
                consignment,
                asset_id: history.contract_id.to_string(),
                ..Default::default()
            })),
            destination_network: Some(
                DestinationNetwork::EvmDestination(EvmDestination::default()),
            ),
        })),
    };
    let mut wire = Vec::new();
    framing::write_message(&mut wire, &request).unwrap();
    (wire, ctx)
}

/// Reads, checks, decodes and dispatches one framed request, as
/// `process_connection` does before it writes the response.
fn handle(wire: &[u8], ctx: &ServerContext) -> crate::proto::EnclaveResponse {
    let request = framing::read_request(&mut Cursor::new(wire)).unwrap();
    super::super::dispatch::dispatch(request, ctx, far_deadline()).0
}

/// The heap of the read and decode of a frame, as a multiple of the frame.
const FRAME_READ: usize = 3;

/// Measures the peak heap of [`handle`] for the burn of `history` on this
/// thread, and fails above the read of its frame and its decoded elements.
fn measure_dispatch(history: &History, what: &str) {
    let ((wire, _ctx), response, peak) =
        peak::measure(|| framed_burn(history), |(wire, ctx)| handle(wire, ctx));
    let Some(Response::Error(err)) = response.response else {
        panic!(
            "expected the destination refusal, got {:?}",
            response.response
        );
    };
    assert!(
        err.message.contains("call_data too short"),
        "the source did not pass: {}",
        err.message
    );
    let frame = wire.len() - 4;
    let elements = framing::count_request_elements(&wire[4..]).unwrap();
    let read = FRAME_READ * frame + elements * WIRE_ELEMENT_BYTES;
    println!(
        "{what}: {frame} frame bytes, {elements} elements, peak heap {peak} bytes, the read \
         {read} bytes"
    );
    assert!(
        peak <= read,
        "{what}: peak heap {peak} bytes is above the {read} bytes of the read of its frame"
    );
}

/// A burn with a history of 2_000 transfers, about 1 MiB of consignment and
/// a proof for each witness, through `dispatch`.
#[test]
fn a_burn_through_dispatch_keeps_no_validation_heap_in_the_enclave() {
    measure_dispatch(
        &burn_after(2_000),
        "burn of 2_000 transfers through dispatch",
    );
}

/// The same at the history the request limits are sized for (`config.rs`).
/// Slow in a debug build.
#[test]
#[ignore = "a history of 10_000 transfers; the burn-signer CI job runs it"]
fn a_burn_of_10_000_transfers_through_dispatch_keeps_no_validation_heap_in_the_enclave() {
    measure_dispatch(
        &burn_after(10_000),
        "burn of 10_000 transfers through dispatch",
    );
}
