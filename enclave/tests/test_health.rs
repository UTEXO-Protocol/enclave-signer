//! Integration tests for the `Health` readiness probe - the full wire path:
//! TCP framing -> `dispatch` -> `EnclaveState` + `ServerContext.header_chain`
//! -> response.
//!
//! Readiness is `key_loaded && spv_synced`, and `spv_synced` is the same
//! `assert_chain_ready` precondition signing applies. These tests pin every
//! corner of that conjunction so a later change to either half cannot quietly
//! make a not-yet-ready enclave advertise itself to deploy.
//!
//! SPV/RGB-only: a `ccd`-only build has no header chain and reports SPV
//! readiness vacuously, which is a different assertion set.
#![cfg(feature = "spv")]

use std::time::{SystemTime, UNIX_EPOCH};

use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, Network};
use utexo_bridge_enclave::networks::rgb::spv_validation::{
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

/// Push `count` headers onto the regtest checkpoint, the last one timestamped
/// `last_time`. `count` defaults matter: readiness needs `SPV_MIN_CONFIRMATIONS`
/// of depth, not just one header.
fn submit_chain(port: u16, count: u32, last_time: u32) {
    let cp = checkpoint_for(Network::Regtest);
    let headers = synth_chain_from(cp.hash, last_time - count, count);
    let resp = submit_headers(port, 1, headers);
    match resp.response {
        Some(ERes::SubmitHeaders(r)) => assert_eq!(r.headers_accepted, count),
        other => panic!("submit failed: {other:?}"),
    }
}

/// Seed a key without needing `allow-seed-import`: entropy-based init is the
/// production path and is not feature-gated.
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
    // The chain still sits on the compiled-in checkpoint. Even a freshly cut
    // checkpoint must not read as synced: nothing can be confirmed yet.
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
    assert!(h.key_loaded);
    assert!(h.spv_synced);
    assert_eq!(h.spv_tip_height, SPV_MIN_CONFIRMATIONS);
}

#[test]
fn chain_too_shallow_to_confirm_is_not_ready() {
    let port = start_test_server_with(with_key);
    // Fresh, but one block short of the depth a proof needs. Freshness alone
    // would have called this ready.
    submit_chain(port, SPV_MIN_CONFIRMATIONS - 1, now_unix());
    let h = health(port);

    assert!(h.key_loaded);
    assert!(!h.spv_synced, "shallower than SPV_MIN_CONFIRMATIONS");
    assert!(!h.ready);
}

#[test]
fn key_and_stale_chain_is_not_ready() {
    let port = start_test_server_with(with_key);
    // Deep enough, but one second past the age signing refuses at, so health
    // and signing agree on the boundary.
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
