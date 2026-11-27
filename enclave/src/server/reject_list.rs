//! Reads the entries of the asset's reject list over the pinned EVM RPC.
//! rgb-lib decides from them and walks the history
//! (`networks::rgb::validation::reject_list`).

use std::time::Instant;

use super::context::ServerContext;
use crate::error::{EnclaveError, Result};
use crate::networks::evm::events::check_node_chain_id;
use crate::networks::evm::reject_list::read_reject_list;
use crate::networks::rgb::validation::{RejectListContract, RejectListLog};

/// The list's entries, read before the request `deadline`. Only a list on
/// `EVM_CHAIN_ID` is read: the enclave has no RPC for another chain.
pub(super) fn read_entries(
    ctx: &ServerContext,
    list: &RejectListContract,
    deadline: Instant,
) -> Result<RejectListLog> {
    let chain_id = ctx.bridge_config.chain_id;
    if list.chain_id != chain_id {
        return Err(EnclaveError::CrossCheck(format!(
            "reject list 0x{} is on chain {}, but this enclave reads only EVM_CHAIN_ID {chain_id} \
             - refusing to sign",
            hex::encode(list.address),
            list.chain_id
        )));
    }
    let client = ctx.launch()?.evm_rpc_client.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "the asset declares a reject list, but the EVM RPC client is unavailable - refusing \
             to sign"
                .into(),
        )
    })?;
    check_node_chain_id(&**client, chain_id)?;
    read_reject_list(&**client, &list.address, deadline)
}

#[cfg(test)]
mod tests;
