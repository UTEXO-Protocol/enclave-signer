//! Internal readiness endpoint: `GET /health`. See README for how deploy uses
//! it.
//!
//! An operations probe, not part of the signing API: loopback by default and on
//! its own port, unlike the gRPC listener on `0.0.0.0`. Must not be exposed
//! off-host.
//!
//! Every failure is a `503`, never a `5xx` the poller would have to
//! special-case: "not ready" and "cannot tell" are one answer to a caller that
//! is waiting.

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::enclave_proto::{enclave_request, enclave_response, EnclaveRequest, HealthResponse};
use crate::grpc_server::ParentAdapterService;

/// How long to wait before answering "cannot tell". Shorter than the 30s
/// signing timeout so a probe answers within its own poll interval rather than
/// leaving the poller to guess.
///
/// It bounds the *answer*, not the enclave-side work: the request runs on a
/// blocking thread that cannot be cancelled, so an abandoned probe is still
/// released by the socket read timeout and the enclave's own 30s request cap.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the router. Public so tests can serve it on an ephemeral port and
/// exercise the real HTTP path deploy will curl.
pub fn router(service: ParentAdapterService) -> Router {
    Router::new()
        .route("/health", get(health))
        .with_state(service)
}

/// Bind the readiness port. Separate from [`serve`] so a bad `HEALTH_PORT`
/// fails at boot: deploy waits on this endpoint, so a parent that silently has
/// none turns a config typo into a poll timeout.
pub async fn bind(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("cannot bind health endpoint on {addr} (check HEALTH_HOST/HEALTH_PORT): {e}"),
        )
    })
}

/// Serve the readiness endpoint on an already-bound listener.
pub async fn serve(
    listener: tokio::net::TcpListener,
    service: ParentAdapterService,
) -> std::io::Result<()> {
    tracing::info!(addr = ?listener.local_addr(), "starting health server");
    axum::serve(listener, router(service)).await
}

async fn health(
    State(service): State<ParentAdapterService>,
) -> (StatusCode, Json<serde_json::Value>) {
    match probe(&service).await {
        Ok(h) => {
            let code = if h.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            (
                code,
                Json(json!({
                    "ready": h.ready,
                    "key_loaded": h.key_loaded,
                    "spv_synced": h.spv_synced,
                    "phase": h.phase,
                    "spv_tip_height": h.spv_tip_height,
                    "spv_tip_time": h.spv_tip_time,
                    "spv_tip_age_secs": h.spv_tip_age_secs,
                    "spv_max_tip_age_secs": h.spv_max_tip_age_secs,
                })),
            )
        }
        Err(e) => {
            tracing::warn!(error = %e, "health probe failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "ready": false, "error": e })),
            )
        }
    }
}

/// Ask the enclave. Returns the reply, or a human-readable reason the probe
/// could not answer.
async fn probe(service: &ParentAdapterService) -> Result<HealthResponse, String> {
    let req = EnclaveRequest {
        request: Some(enclave_request::Request::Health(Default::default())),
    };

    let resp = tokio::time::timeout(PROBE_TIMEOUT, service.send_to_enclave(req))
        .await
        .map_err(|_| format!("enclave did not answer within {:?}", PROBE_TIMEOUT))?
        .map_err(|s| format!("enclave request failed: {}", s.message()))?;

    match resp.response {
        Some(enclave_response::Response::Health(h)) => Ok(h),
        Some(enclave_response::Response::Error(e)) => {
            Err(format!("enclave error (code {}): {}", e.code, e.message))
        }
        // An enclave built before Health existed drops the unknown oneof and
        // replies with no variant set. Report it as not-ready rather than
        // pretending the probe succeeded.
        other => Err(format!("unexpected enclave response variant: {other:?}")),
    }
}
