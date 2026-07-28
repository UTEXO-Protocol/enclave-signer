//! Integration tests for the SPV header-sync RPCs (`SubmitHeaders`,
//! `GetLastSavedBlock`) — exercises the full wire path: TCP framing →
//! `dispatch` → `ServerContext.header_chain` → response.

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;

use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, Network};
use utexo_bridge_enclave::proto::enclave_request::Request as EReq;
use utexo_bridge_enclave::proto::enclave_response::Response as ERes;
use utexo_bridge_enclave::proto::*;

mod common;
use common::{send_request, start_test_server};

/// Build `count` synthetic regtest headers chained from `prev_hash`. The
/// test server is wired to `Network::Regtest` (see `common/mod.rs`), where
/// header validation is "chain linkage only", so we don't need to satisfy
/// real PoW.
fn synth_chain_from(prev_hash: [u8; 32], prev_time: u32, count: u32) -> Vec<Vec<u8>> {
    let mut prev = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(prev_hash),
    );
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: prev_time + 1 + i,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: i,
        };
        out.push(serialize(&header));
        prev = header.block_hash();
    }
    out
}

fn submit(port: u16, start_height: u32, headers: Vec<Vec<u8>>) -> EnclaveResponse {
    send_request(
        port,
        &EnclaveRequest {
            request: Some(EReq::SubmitHeaders(SubmitHeadersRequest {
                headers,
                start_height,
            })),
        },
    )
}

fn last_saved(port: u16) -> GetLastSavedBlockResponse {
    let resp = send_request(
        port,
        &EnclaveRequest {
            request: Some(EReq::GetLastSavedBlock(GetLastSavedBlockRequest {})),
        },
    );
    match resp.response {
        Some(ERes::GetLastSavedBlock(r)) => r,
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn fresh_enclave_reports_checkpoint_as_tip() {
    // Common test-server uses Regtest, whose checkpoint is the real regtest
    // genesis block (height=0). On boot, that's the tip.
    let port = start_test_server();
    let cp = checkpoint_for(Network::Regtest);
    let r = last_saved(port);
    assert_eq!(r.block_height, 0);
    assert_eq!(r.block_hash, cp.hash.to_vec());
}

#[test]
fn submit_then_query_round_trip() {
    let port = start_test_server();

    // Push 5 synthetic headers chained from the regtest genesis checkpoint.
    let cp = checkpoint_for(Network::Regtest);
    let headers = synth_chain_from(cp.hash, 1_700_000_000, 5);
    let resp = submit(port, 1, headers);

    match resp.response {
        Some(ERes::SubmitHeaders(r)) => {
            assert_eq!(r.headers_accepted, 5);
            assert_eq!(r.last_block_height, 5);
            assert_eq!(r.last_block_hash.len(), 32);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let after = last_saved(port);
    assert_eq!(after.block_height, 5);
    assert_ne!(after.block_hash, cp.hash.to_vec());
}

#[test]
fn submit_below_checkpoint_returns_error() {
    let port = start_test_server();
    // Checkpoint is at height 0; submitting at height 0 is below-checkpoint
    // territory because it would rewrite the trust anchor.
    let resp = submit(port, 0, synth_chain_from([0u8; 32], 1_700_000_000, 1));

    match resp.response {
        Some(ERes::Error(e)) => {
            assert_eq!(e.code, 3); // VALIDATION_FAILED (Spv error)
            assert!(
                e.message.contains("checkpoint"),
                "expected error to mention checkpoint, got: {}",
                e.message
            );
        }
        other => panic!("expected Error, got: {other:?}"),
    }
}

#[test]
fn submit_with_gap_returns_error() {
    let port = start_test_server();
    // Tip is the checkpoint at height 0; start_height=10 leaves a gap.
    let resp = submit(port, 10, synth_chain_from([0u8; 32], 1_700_000_000, 1));

    match resp.response {
        Some(ERes::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("gap"),
                "expected error to mention gap, got: {}",
                e.message
            );
        }
        other => panic!("expected Error, got: {other:?}"),
    }
}

#[test]
fn batched_submits_advance_tip_monotonically() {
    let port = start_test_server();

    // First batch of 3, chained from the regtest genesis checkpoint.
    let mut prev = checkpoint_for(Network::Regtest).hash;
    let batch1 = synth_chain_from(prev, 1_700_000_000, 3);
    // Recompute prev = hash of last header in batch1 so batch2 chains.
    let last1: bitcoin::block::Header = bitcoin::consensus::deserialize(&batch1[2]).unwrap();
    prev = *bitcoin::hashes::Hash::as_byte_array(&last1.block_hash());

    let resp1 = submit(port, 1, batch1);
    assert!(matches!(resp1.response, Some(ERes::SubmitHeaders(_))));
    assert_eq!(last_saved(port).block_height, 3);

    // Second batch of 2, picking up where we left off.
    let batch2 = synth_chain_from(prev, 1_700_000_004, 2);
    let resp2 = submit(port, 4, batch2);
    match resp2.response {
        Some(ERes::SubmitHeaders(r)) => {
            assert_eq!(r.last_block_height, 5);
            assert_eq!(r.headers_accepted, 2);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    assert_eq!(last_saved(port).block_height, 5);
}
