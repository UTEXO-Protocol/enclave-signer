//! BFA anchor binding: every mint anchor of a consignment is bound to the
//! deposit id it derives. The mint a PSBT signs must also have that deposit
//! on the pinned EVM chain, finalized.
//!
//! `server/mod.rs` gates this module on `bfa-validation`.

use super::context::ServerContext;
use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::networks::evm::events::derived_lock;
use crate::networks::rgb::validation::{BfaBridge, BoundAnchors, MintAnchor, VerifiedLock};

/// The asset's genesis must name the pinned Bridge on the pinned chain. Only
/// that contract's deposits can back a mint this federation signs.
fn check_bridge(cfg: &BridgeConfig, bridge: &BfaBridge) -> Result<()> {
    if bridge.chain_id != cfg.chain_id || bridge.address != cfg.funds_in_contract {
        return Err(EnclaveError::CrossCheck(format!(
            "asset bridge location 0x{} on chain {} is not the pinned funds-in contract 0x{} \
             on EVM_CHAIN_ID {}",
            hex::encode(bridge.address),
            bridge.chain_id,
            hex::encode(cfg.funds_in_contract),
            cfg.chain_id
        )));
    }
    Ok(())
}

/// The derived lock of each anchor, in consignment order; no RPC read.
fn derive_all(cfg: &BridgeConfig, anchors: &[MintAnchor]) -> Result<Vec<VerifiedLock>> {
    anchors
        .iter()
        .map(|a| derived_lock(cfg, a.opid, a.amount))
        .collect()
}

/// Binds a history the enclave does not sign a mint in (a burn, a transfer):
/// every anchor to its derived lock. The chain id is the pin; no RPC is read.
#[cfg(any(rgb_to_evm, feature = "rgb-swap"))]
pub(super) fn derived_locks(
    ctx: &ServerContext,
    bridge: &BfaBridge,
    anchors: &[MintAnchor],
) -> Result<BoundAnchors> {
    check_bridge(&ctx.bridge_config, bridge)?;
    Ok(BoundAnchors {
        evm_chain_id: ctx.bridge_config.chain_id,
        locks: derive_all(&ctx.bridge_config, anchors)?,
    })
}

/// Binds a mint's history. Ancestors get derived locks. The signed mint's
/// derived lock is bound only once the request's own receipt proves it.
#[cfg(all(feature = "rgb-mint-burn", evm_to_rgb))]
pub(super) fn mint_locks(
    ctx: &ServerContext,
    tx_hash: &[u8; 32],
    bridge: &BfaBridge,
    anchors: &[MintAnchor],
) -> Result<BoundAnchors> {
    use crate::networks::evm::events::{check_node_chain_id, verify_rgb_funds_in};

    let cfg = &ctx.bridge_config;
    check_bridge(cfg, bridge)?;
    let locks = derive_all(cfg, anchors)?;
    let signed = signed_mint(anchors)?;

    let client = ctx.launch()?.evm_rpc_client.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "bfa-mint build but the EVM RPC client is unavailable - refusing to sign a mint \
             without independently verifying its FundsIn lock"
                .into(),
        )
    })?;
    let evm_chain_id = check_node_chain_id(&**client, cfg.chain_id)?;
    let paid = verify_rgb_funds_in(
        &**client,
        &cfg.funds_in_contract,
        ctx.evm_rpc_config.min_confirmations,
        tx_hash,
        &signed.opid,
        signed.after_block,
    )?;
    bind_request_deposit(&derived_lock(cfg, signed.opid, signed.amount)?, &paid)?;
    Ok(BoundAnchors {
        evm_chain_id,
        locks,
    })
}

/// The one anchor of the bundle the PSBT signs: the mint this request pays.
#[cfg(all(feature = "rgb-mint-burn", evm_to_rgb))]
fn signed_mint(anchors: &[MintAnchor]) -> Result<&MintAnchor> {
    let mut signed = anchors.iter().filter(|a| a.in_last_bundle);
    match (signed.next(), signed.next()) {
        (Some(anchor), None) => Ok(anchor),
        _ => Err(EnclaveError::CrossCheck(
            "the signed bundle must hold exactly one mint anchor - refusing to guess which \
             mint this request pays"
                .into(),
        )),
    }
}

/// The request's deposit must equal the mint's derived lock.
#[cfg(all(feature = "rgb-mint-burn", evm_to_rgb))]
fn bind_request_deposit(derived: &VerifiedLock, paid: &VerifiedLock) -> Result<()> {
    if paid != derived {
        return Err(EnclaveError::CrossCheck(format!(
            "the request's deposit is not the one mint 0x{} derives: operationId 0x{} for {} \
             (net {}), the mint needs 0x{} for {} - refusing to sign",
            hex::encode(derived.mint_opid),
            hex::encode(paid.operation_id),
            paid.minted,
            paid.net_amount,
            hex::encode(derived.operation_id),
            derived.minted,
        )));
    }
    Ok(())
}

#[cfg(all(test, feature = "bfa-mint"))]
mod tests;
