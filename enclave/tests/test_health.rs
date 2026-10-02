//! Integration tests for the `Health` readiness probe over the full wire path:
//! TCP framing -> `dispatch` -> `EnclaveState` + `ServerContext.header_chain`
//! -> response.
//!
//! Readiness is `endpoints_set && key_loaded && spv_synced`. `spv_synced` is
//! the same `assert_chain_ready` precondition that signing applies. These tests
//! pin each corner of that conjunction, so a not-ready enclave cannot report ready.
//!
//! SPV/RGB builds only. A `ccd`-only build has no header chain and reports SPV
//! readiness vacuously. A mint signer also skips the SPV half;
//! `test_signer_role.rs` covers it.
#![cfg(all(feature = "rgb-validation", rgb_to_evm))]

use std::time::{SystemTime, UNIX_EPOCH};

use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, Network};
use utexo_bridge_enclave::networks::rgb::spv_crosscheck::{
    SPV_MAX_TIP_AGE_SECS, SPV_MIN_CONFIRMATIONS,
};
use utexo_bridge_enclave::proto::enclave_request::Request as EReq;
use utexo_bridge_enclave::proto::enclave_response::Response as ERes;
use utexo_bridge_enclave::proto::*;
use utexo_bridge_enclave::state::EnclaveState;

mod common;
use common::{
    send_request, start_test_server, start_test_server_with, submit_headers, synth_chain_from,
};

fn now_unix() -> u32 {
    u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn health(port: u16) -> HealthResponse {
    let resp = send_request(
        port,
        &EnclaveRequest {
            request: Some(EReq::Health(HealthRequest {})),
        },
    );
    match resp.response {
        Some(ERes::Health(h)) => h,
        other => panic!("unexpected response: {other:?}"),
    }
}

/// Push `count` headers onto the regtest checkpoint. The last header has the
/// timestamp `last_time`. Readiness needs `SPV_MIN_CONFIRMATIONS` of depth.
fn submit_chain(port: u16, count: u32, last_time: u32) {
    let cp = checkpoint_for(Network::Regtest);
    let headers = synth_chain_from(cp.hash, last_time - count, count);
    let resp = submit_headers(port, 1, headers);
    match resp.response {
        Some(ERes::SubmitHeaders(r)) => assert_eq!(r.headers_accepted, count),
        other => panic!("submit failed: {other:?}"),
    }
}

/// Load a key without `allow-seed-import`. Entropy-based init is the
/// production path and has no feature gate.
fn with_key(state: &EnclaveState) {
    let mut entropy = [7u8; 32];
    state.initialize_from_entropy(&mut entropy).unwrap();
}

#[test]
fn fresh_enclave_is_not_ready() {
    let port = start_test_server();
    let h = health(port);

    assert!(!h.ready);
    assert!(!h.key_loaded);
    assert!(!h.spv_synced, "no headers accepted yet");
    assert_eq!(h.phase, "initial");
    assert_eq!(h.spv_max_tip_age_secs as u64, SPV_MAX_TIP_AGE_SECS);
}

#[test]
fn key_without_headers_is_not_ready() {
    let port = start_test_server_with(with_key);
    let h = health(port);

    assert!(h.key_loaded);
    assert_eq!(h.phase, "active");
    // The chain is still at the compiled-in checkpoint. A new checkpoint must
    // not read as synced, because nothing is confirmed yet.
    assert!(!h.spv_synced);
    assert!(!h.ready);
}

#[test]
fn headers_without_key_is_not_ready() {
    let port = start_test_server();
    submit_chain(port, SPV_MIN_CONFIRMATIONS, now_unix());
    let h = health(port);

    assert!(h.spv_synced);
    assert!(!h.key_loaded);
    assert!(!h.ready, "a synced chain alone must not report ready");
}

#[test]
fn key_and_fresh_chain_is_ready() {
    let port = start_test_server_with(with_key);
    submit_chain(port, SPV_MIN_CONFIRMATIONS, now_unix());
    let h = health(port);

    assert!(h.ready);
    // The test server presets the endpoints.
    assert!(h.endpoints_set);
    assert!(h.key_loaded);
    assert!(h.spv_synced);
    assert_eq!(h.spv_tip_height, SPV_MIN_CONFIRMATIONS);
}

#[test]
fn chain_too_shallow_to_confirm_is_not_ready() {
    let port = start_test_server_with(with_key);
    // The chain is fresh but one block short of the depth a proof needs.
    // A freshness-only check would report ready.
    submit_chain(port, SPV_MIN_CONFIRMATIONS - 1, now_unix());
    let h = health(port);

    assert!(h.key_loaded);
    assert!(!h.spv_synced, "shallower than SPV_MIN_CONFIRMATIONS");
    assert!(!h.ready);
}

#[test]
fn key_and_stale_chain_is_not_ready() {
    let port = start_test_server_with(with_key);
    // The chain is deep enough but one second past the age limit of signing.
    // Health and signing must agree on this boundary.
    let age = u32::try_from(SPV_MAX_TIP_AGE_SECS).unwrap() + 1;
    submit_chain(port, SPV_MIN_CONFIRMATIONS, now_unix() - age);
    let h = health(port);

    assert!(h.key_loaded);
    assert!(!h.spv_synced, "tip older than SPV_MAX_TIP_AGE_SECS");
    assert!(!h.ready);
    assert!(
        h.spv_tip_age_secs >= age,
        "reported age {} should be at least {age}",
        h.spv_tip_age_secs
    );
}
