//! The RGB consignment validator for one Bitcoin network.

use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::rgb::spv::Network;
use rgb_lib::ChainNet;

/// Validates RGB consignments of the configured Bitcoin network.
///
/// Witness status comes from the enclave's SPV proofs. The validator makes no
/// indexer call.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) chain_net: ChainNet,
}

impl RgbValidator {
    /// Creates a validator for `bitcoin_network`, a `BITCOIN_NETWORK` value
    /// (see [`Network::from_env_str`]).
    pub fn new(bitcoin_network: &str) -> Result<Self> {
        let chain_net = Network::from_env_str(bitcoin_network)
            .map_err(|e| {
                EnclaveError::Internal(format!("unknown bitcoin network {bitcoin_network}: {e}"))
            })?
            .chain_net();
        tracing::info!(%bitcoin_network, "RGB validator configured");
        Ok(Self { chain_net })
    }

    /// The validator of `chain_net` inside a validator child.
    #[cfg(all(rgb_to_evm, unix))]
    pub(super) fn for_chain_net(chain_net: ChainNet) -> Self {
        Self { chain_net }
    }
}
