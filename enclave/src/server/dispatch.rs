//! Request router: one proto oneof variant to one handler.
//!
//! The only place that turns a handler `Err` into an `ErrorResponse`, so the
//! handlers themselves stay in `Result` land.

use super::cloning::{handle_get_clone, handle_initiate_cloning, handle_set_clone};
use super::context::ServerContext;
use super::health::handle_health;
use super::keys::{handle_get_attested_public_key, handle_get_public_key, handle_initialize};
use super::sign::handle_sign;
#[cfg(evm_to_rgb)]
use super::signers::handle_sign_btc;
#[cfg(feature = "ccd")]
use super::signers::handle_sign_ccd;
#[cfg(rgb_to_evm)]
use super::signers::handle_sign_raw_digest;
#[cfg(feature = "rgb-validation")]
use super::spv::{handle_get_last_saved_block, handle_submit_headers};
use crate::error::EnclaveError;
use crate::proto::enclave_request::Request;
use crate::proto::enclave_response::Response;
use crate::proto::*;
use crate::state::ReplayReservation;

/// Error for a request whose owning network was not compiled into this build.
/// Single-network EIFs (RGB-only / CCD-only) return this for requests that
/// belong to the other network, so the separation is observable to callers
/// rather than a silent no-op.
#[allow(dead_code)]
pub(super) fn unsupported_build(network: &str) -> EnclaveError {
    EnclaveError::InvalidRequest(format!(
        "enclave was not built with `{network}` support: this binary does not handle {network} \
         requests (rebuild with `--features {network}`)"
    ))
}

/// Error for a request that belongs to the other signer role: a mint signer
/// never releases and a burn signer never mints.
#[allow(dead_code)]
pub(super) fn wrong_signer_role(what: &str) -> EnclaveError {
    let role = if cfg!(feature = "mint-signer") {
        "the mint signer (EVM -> RGB)"
    } else if cfg!(feature = "burn-signer") {
        "the burn signer (RGB -> EVM)"
    } else {
        "a combined signer"
    };
    EnclaveError::InvalidRequest(format!("this enclave is {role}: it does not sign {what}"))
}

/// Dispatch one request. A sign that reserved a replay key hands the
/// reservation back un-committed, so the caller commits it only after the
/// response is written.
pub(super) fn dispatch(
    request: EnclaveRequest,
    ctx: &ServerContext,
) -> (EnclaveResponse, Option<ReplayReservation<'_>>) {
    let mut reservation = None;
    let result = match request.request {
        Some(Request::InitializeKey(req)) => {
            let path = if !req.mnemonic.is_empty() {
                "mnemonic-import"
            } else if req.seed.is_empty() {
                "entropy"
            } else {
                "seed-import"
            };
            tracing::info!("request: InitializeKey ({})", path);
            handle_initialize(ctx, req)
        }
        Some(Request::GetPublicKey(req)) => {
            tracing::info!("request: GetPublicKey");
            handle_get_public_key(ctx, req)
        }
        Some(Request::Sign(req)) => handle_sign(ctx, req).map(|(response, reserved)| {
            reservation = reserved;
            response
        }),
        Some(Request::SignBtc(req)) => {
            tracing::info!("request: SignBtc");
            // Plain-BTC signing prepares the UTXOs a mint spends.
            #[cfg(evm_to_rgb)]
            {
                handle_sign_btc(ctx, req)
            }
            #[cfg(not(evm_to_rgb))]
            {
                let _ = req;
                Err(wrong_signer_role("plain-BTC PSBTs"))
            }
        }
        // Removed. The EIP-191 `personal_sign` path was
        // gated by no feature and no policy, and signed arbitrary caller-supplied
        // bytes with the main bridge key. The proto still carries the variant, so
        // refuse explicitly instead of dropping the arm.
        Some(Request::SignRawMessage(_)) => {
            tracing::warn!("request: SignRawMessage - removed, refusing");
            Err(EnclaveError::InvalidRequest(
                "SignRawMessage is removed; no replacement".into(),
            ))
        }
        Some(Request::SignRawDigest(req)) => {
            tracing::info!("request: SignRawDigest");
            // The gas tx pays for the `fundsOut` submission.
            #[cfg(rgb_to_evm)]
            {
                handle_sign_raw_digest(ctx, req)
            }
            #[cfg(not(rgb_to_evm))]
            {
                let _ = req;
                Err(wrong_signer_role("EVM gas transactions"))
            }
        }
        Some(Request::SignCcd(req)) => {
            tracing::info!("request: SignCcd");
            #[cfg(feature = "ccd")]
            {
                handle_sign_ccd(&ctx.state, req)
            }
            #[cfg(not(feature = "ccd"))]
            {
                let _ = req;
                Err(unsupported_build("ccd"))
            }
        }
        Some(Request::ProxyFederation(_req)) => {
            tracing::info!("request: ProxyFederation");
            return (
                EnclaveResponse {
                    response: Some(Response::Error(ErrorResponse {
                        code: 1,
                        message: "unsupported request".into(),
                    })),
                },
                None,
            );
        }
        Some(Request::InitiateCloning(req)) => {
            tracing::info!("request: InitiateCloning");
            handle_initiate_cloning(&ctx.state, req)
        }
        Some(Request::GetClone(req)) => {
            tracing::info!("request: GetClone");
            handle_get_clone(ctx, req)
        }
        Some(Request::SetClone(req)) => {
            tracing::info!("request: SetClone");
            handle_set_clone(ctx, req)
        }
        Some(Request::SubmitHeaders(req)) => {
            tracing::info!(
                headers_len = req.headers.len(),
                start_height = req.start_height,
                "request: SubmitHeaders"
            );
            #[cfg(feature = "rgb-validation")]
            {
                handle_submit_headers(ctx, req)
            }
            #[cfg(not(feature = "rgb-validation"))]
            {
                let _ = req;
                Err(unsupported_build("rgb"))
            }
        }
        Some(Request::GetLastSavedBlock(req)) => {
            tracing::info!("request: GetLastSavedBlock");
            #[cfg(feature = "rgb-validation")]
            {
                handle_get_last_saved_block(ctx, req)
            }
            #[cfg(not(feature = "rgb-validation"))]
            {
                let _ = req;
                Err(unsupported_build("rgb"))
            }
        }
        Some(Request::GetAttestedPublicKey(req)) => {
            tracing::info!("request: GetAttestedPublicKey");
            handle_get_attested_public_key(ctx, req)
        }
        // Not feature-gated: every build must answer the readiness probe, and a
        // build without `spv` reports SPV readiness vacuously.
        Some(Request::Health(_)) => {
            tracing::debug!("request: Health");
            handle_health(ctx)
        }
        None => {
            tracing::warn!("received empty request (no oneof variant set)");
            return (
                EnclaveResponse {
                    response: Some(Response::Error(ErrorResponse {
                        code: 1,
                        message: "empty request".into(),
                    })),
                },
                None,
            );
        }
    };

    let response = match result {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!("handler error: {}", e);
            EnclaveResponse {
                response: Some(Response::Error(ErrorResponse {
                    code: e.error_code(),
                    message: e.to_string(),
                })),
            }
        }
    };
    (response, reservation)
}
