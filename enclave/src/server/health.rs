//! `Health`: the readiness probe deploy orchestration polls.
//!
//! Not feature-gated. Every build must answer it; a build without `spv`
//! reports SPV readiness vacuously.

use super::context::ServerContext;
use crate::error::Result;
use crate::proto::enclave_response::Response;
use crate::proto::*;

/// SPV half of the readiness answer:
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

/// A `ccd`-only build carries no header chain and rejects SubmitHeaders, so
/// there is nothing to sync. The zeroed heights say "not applicable here".
#[cfg(not(feature = "rgb-validation"))]
fn spv_health(_ctx: &ServerContext) -> (bool, u32, u32, u32, u32) {
    (true, 0, 0, 0, 0)
}

/// Readiness probe for deploy orchestration: answers "could I sign right now?".
///
/// Ready means the key is loaded *and* the header chain passes
/// `assert_chain_ready` - the same precondition signing applies - so a caller
/// that sees `ready` will not immediately hit an SPV refusal.
pub(super) fn handle_health(ctx: &ServerContext) -> Result<EnclaveResponse> {
    let key_loaded = ctx.state.is_initialized();
    let phase = ctx.state.phase_name().to_string();
    let (spv_synced, spv_tip_height, spv_tip_time, spv_tip_age_secs, spv_max_tip_age_secs) =
        spv_health(ctx);

    let ready = key_loaded && spv_synced;

    tracing::debug!(
        ready,
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
        })),
    })
}
