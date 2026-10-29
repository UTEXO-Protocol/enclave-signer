//! BFA deposit binding. A consignment's mint anchors are bound to the deposit
//! ids they derive. The mint signer binds the mint its PSBT commits to the
//! request's own deposit on the pinned EVM chain, covered by the
//! `EVM_FINALITY_TAG` head (M6).
//!
//! `server/mod.rs` gates this module on `bfa-validation`.

use super::context::ServerContext;
use crate::error::{EnclaveError, Result};
use crate::networks::evm::events::derived_lock;
use crate::networks::rgb::validation::VerifiedLock;
#[cfg(any(rgb_to_evm, feature = "rgb-swap"))]
use crate::{
    config::BridgeConfig,
    networks::rgb::validation::{BfaBridge, BoundAnchors, MintAnchor},
};

/// The asset's genesis must name the pinned Bridge on the pinned chain. Only
/// that contract's deposits can back a mint this federation signs.
#[cfg(any(rgb_to_evm, feature = "rgb-swap"))]
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
#[cfg(any(rgb_to_evm, feature = "rgb-swap"))]
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

/// M6: the receipt of `tx_hash` holds the one deposit the mint derives, on the
/// pinned chain, before its `beforeBlock`. The pins are checked before any RPC.
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
pub(super) fn bind_mint_deposit(
    ctx: &ServerContext,
    tx_hash: &[u8; 32],
    mint: &crate::networks::rgb::psbt_validation::MintFacts,
) -> Result<()> {
    use crate::networks::evm::events::{check_node_chain_id, verify_rgb_funds_in};

    let cfg = &ctx.bridge_config;
    let derived = derived_lock(cfg, mint.opid, mint.issued)?;
    let client = ctx.launch()?.evm_rpc_client.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "bfa-mint build but the EVM RPC client is unavailable - refusing to sign a mint \
             without independently verifying its FundsIn lock"
                .into(),
        )
    })?;
    check_node_chain_id(&**client, cfg.chain_id)?;
    let paid = verify_rgb_funds_in(
        &**client,
        &cfg.funds_in_contract,
        cfg.evm_finality_tag,
        tx_hash,
        &mint.opid,
        mint.before_block,
    )?;
    bind_request_deposit(&derived, &paid)
}

/// The request's deposit must equal the mint's derived lock.
#[cfg(all(feature = "bfa-mint", evm_to_rgb))]
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
