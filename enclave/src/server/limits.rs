//! `SetLimits` and `GetLimits`: the operator reads and changes the time,
//! memory and size limits at run time ([`crate::limits`]).

use super::context::ServerContext;
use crate::error::{EnclaveError, Result};
use crate::limits::{self, Limits};
use crate::proto::enclave_response::Response;
use crate::proto::{self, EnclaveResponse, LimitsResponse, SetLimitsRequest};

pub(super) fn handle_set_limits(
    ctx: &ServerContext,
    req: SetLimitsRequest,
) -> Result<EnclaveResponse> {
    let changes = Limits::from(&req.values.unwrap_or_default());
    let limits = limits::apply(&ctx.bridge_config, &changes, req.reset, |limits| {
        crate::memory::check_limits(limits, &ctx.build_ctx)
    })
    .map_err(EnclaveError::InvalidRequest)?;
    tracing::info!(?limits, "limits changed");
    Ok(limits_response(ctx, &limits))
}

pub(super) fn handle_get_limits(ctx: &ServerContext) -> Result<EnclaveResponse> {
    Ok(limits_response(ctx, &limits::in_force(&ctx.bridge_config)))
}

fn limits_response(ctx: &ServerContext, current: &Limits) -> EnclaveResponse {
    EnclaveResponse {
        response: Some(Response::Limits(LimitsResponse {
            current: Some(proto::Limits::from(current)),
            image: Some(proto::Limits::from(&Limits::image(&ctx.bridge_config))),
        })),
    }
}
