//! `SignRightsRefill`: the mint wallet sends one of its mint rights to 2..=255
//! of its own outputs. No source and no deposit back it, so the rule is shape
//! only: the rights and every sat stay ours, and no units move.
//!
//! Cheapest first, since the listener gRPC has no auth: a PSBT-only gate and
//! the rate limit, then the committed transition and its parent proof, then
//! key ownership of each new right. No network.

use std::time::Instant;

use super::context::ServerContext;
use super::signers::sign_colored_psbt;
use crate::error::Result;
use crate::networks::rgb::psbt_validation;
use crate::proto::{EnclaveResponse, SignRightsRefillRequest};

/// Signs a refill PSBT that passes every rule, or refuses.
pub(super) fn handle_sign_rights_refill(
    ctx: &ServerContext,
    req: SignRightsRefillRequest,
) -> Result<EnclaveResponse> {
    let psbt = psbt_validation::parse_psbt_shape(&req.psbt_bytes)?;
    ctx.state
        .with_keys(|keys| psbt_validation::refill_gate(&psbt, keys))?;
    // RR15 counts only requests past the gate, so junk cannot use it up.
    ctx.state.refill_rate.admit(Instant::now())?;
    let rights = crate::networks::rgb::validate_rights_refill(&req, &psbt, &ctx.bridge_config)?;
    ctx.state
        .with_keys(|keys| psbt_validation::assert_refill_rights_owned(&psbt, &rights, keys))?;
    tracing::info!(
        rights = rights.len(),
        txid = %psbt.unsigned_tx.compute_txid(),
        "rights refill validated"
    );
    sign_colored_psbt(ctx, &req.psbt_bytes)
}

#[cfg(test)]
mod tests;
