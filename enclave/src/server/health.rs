//! `Health`: the readiness probe for deploy orchestration.
//!
//! All builds answer it. A build without `rgb-validation` always reports
//! SPV as synced.

use super::context::ServerContext;
use crate::error::Result;
use crate::proto::enclave_response::Response;
use crate::proto::*;

/// SPV part of the readiness answer:
/// `(synced, tip_height, tip_time, tip_age_secs, max_tip_age_secs)`.
#[cfg(feature = "rgb-validation")]
fn spv_health(ctx: &ServerContext) -> (bool, u32, u32, u32, u32) {
    use crate::networks::rgb::spv_crosscheck::{assert_chain_ready, SPV_MAX_TIP_AGE_SECS};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now();
    let chain = ctx
        .header_chain
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let synced = assert_chain_ready(&chain, now).is_ok();
    let (tip_height, tip_time) = (chain.tip_height(), chain.tip_time());
    drop(chain);

    let age = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(u64::from(tip_time));

    (
        synced,
        tip_height,
        tip_time,
        u32::try_from(age).unwrap_or(u32::MAX),
        SPV_MAX_TIP_AGE_SECS as u32,
    )
}

/// A `ccd`-only build has no header chain, so it has nothing to sync.
/// Zero values mean "not applicable".
#[cfg(not(feature = "rgb-validation"))]
fn spv_health(_ctx: &ServerContext) -> (bool, u32, u32, u32, u32) {
    (true, 0, 0, 0, 0)
}

/// Readiness probe: can the enclave sign now?
///
/// Ready means: endpoints are set, the key is loaded, and the header chain
/// passes `assert_chain_ready`. Signing uses the same SPV precondition.
/// A mint signer (no `rgb_to_evm`) does not read the header chain, so it
/// skips the SPV check.
pub(super) fn handle_health(ctx: &ServerContext) -> Result<EnclaveResponse> {
    let key_loaded = ctx.state.is_initialized();
    let phase = ctx.state.phase_name().to_string();
    let (spv_synced, spv_tip_height, spv_tip_time, spv_tip_age_secs, spv_max_tip_age_secs) =
        spv_health(ctx);

    let endpoints_set = ctx.launch.get().is_some();
    let ready = endpoints_set && key_loaded && (spv_synced || !cfg!(rgb_to_evm));

    tracing::debug!(
        ready,
        endpoints_set,
        key_loaded,
        spv_synced,
        %phase,
        spv_tip_height,
        spv_tip_age_secs,
        "Health"
    );

    Ok(EnclaveResponse {
        response: Some(Response::Health(HealthResponse {
            ready,
            key_loaded,
            spv_synced,
            phase,
            spv_tip_height,
            spv_tip_time,
            spv_tip_age_secs,
            spv_max_tip_age_secs,
            endpoints_set,
        })),
    })
}
