//! SPV header-sync requests: `SubmitHeaders` and `GetLastSavedBlock`.
//!
//! `server/mod.rs` gates this module on `rgb-validation`.

#[cfg(not(feature = "stage-signet"))]
use std::time::{SystemTime, UNIX_EPOCH};

use super::context::ServerContext;
use crate::error::{EnclaveError, Result};
#[cfg(not(feature = "stage-signet"))]
use crate::proto::enclave_response::Response;
use crate::proto::*;

// A poisoned mutex is recovered, not left to block the enclave.
// All chain mutations are atomic, so the chain stays consistent.
#[cfg(not(feature = "stage-signet"))]
pub(super) fn handle_submit_headers(
    ctx: &ServerContext,
    req: SubmitHeadersRequest,
) -> Result<EnclaveResponse> {
    let now = SystemTime::now();
    // Total rate limit across calls. `submit_headers` has the per-call cap.
    ctx.submit_rate_limiter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .check(req.headers.len() as u64, now)?;
    let now_unix = now
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::Internal(format!("system clock is before UNIX_EPOCH: {e}")))?
        .as_secs();

    let mut chain = ctx
        .header_chain
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let outcome = chain.submit_headers(req.start_height, &req.headers, now_unix)?;

    tracing::info!(
        last_block_height = outcome.last_block_height,
        headers_accepted = outcome.headers_accepted,
        reorg_depth = outcome.reorg_depth,
        "SubmitHeaders outcome"
    );

    Ok(EnclaveResponse {
        response: Some(Response::SubmitHeaders(SubmitHeadersResponse {
            last_block_height: outcome.last_block_height,
            last_block_hash: outcome.last_block_hash.to_vec(),
            headers_accepted: outcome.headers_accepted,
        })),
    })
}

#[cfg(not(feature = "stage-signet"))]
pub(super) fn handle_get_last_saved_block(
    ctx: &ServerContext,
    _req: GetLastSavedBlockRequest,
) -> Result<EnclaveResponse> {
    let chain = ctx
        .header_chain
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let height = chain.tip_height();
    let hash = chain.tip_hash();

    tracing::debug!(
        block_height = height,
        block_hash = %hex::encode(hash),
        "GetLastSavedBlock"
    );

    Ok(EnclaveResponse {
        response: Some(Response::GetLastSavedBlock(GetLastSavedBlockResponse {
            block_height: height,
            block_hash: hash.to_vec(),
        })),
    })
}

#[cfg(feature = "stage-signet")]
pub(super) fn handle_submit_headers(
    _ctx: &ServerContext,
    _req: SubmitHeadersRequest,
) -> Result<EnclaveResponse> {
    Err(EnclaveError::InvalidRequest(
        "SPV header synchronization is disabled in stage-signet builds".into(),
    ))
}

#[cfg(feature = "stage-signet")]
pub(super) fn handle_get_last_saved_block(
    _ctx: &ServerContext,
    _req: GetLastSavedBlockRequest,
) -> Result<EnclaveResponse> {
    Err(EnclaveError::InvalidRequest(
        "SPV header synchronization is disabled in stage-signet builds".into(),
    ))
}
