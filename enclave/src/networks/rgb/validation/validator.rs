//! The RGB consignment validator for one Bitcoin network.

use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::rgb::spv::Network;
use rgbstd::ChainNet;

/// Validates RGB consignments of the configured Bitcoin network.
///
/// Witness status comes from the enclave's SPV proofs. The validator makes no
/// indexer call.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) chain_net: ChainNet,
}

impl RgbValidator {
    /// Creates a validator.
    ///
    /// - `indexer_url`: the launch value, `ssl://` or `tcp://` for Electrum,
    ///   `https://` or `http://` for Esplora. Any other scheme is refused.
    /// - `bitcoin_network`: a `BITCOIN_NETWORK` value (see
    ///   [`Network::from_env_str`]).
    pub fn new(indexer_url: String, bitcoin_network: &str) -> Result<Self> {
        if !is_electrum_url(&indexer_url)
            && !indexer_url.starts_with("https://")
            && !indexer_url.starts_with("http://")
        {
            return Err(EnclaveError::Internal(format!(
                "indexer URL {indexer_url:?} is not ssl:// or tcp:// (Electrum), \
                 https:// or http:// (Esplora)"
            )));
        }
        let chain_net = Network::from_env_str(bitcoin_network)
            .map_err(|e| {
                EnclaveError::Internal(format!("unknown bitcoin network {bitcoin_network}: {e}"))
            })?
            .chain_net();
        tracing::info!(%indexer_url, %bitcoin_network, "RGB validator configured");
        Ok(Self { chain_net })
    }
}

fn is_electrum_url(url: &str) -> bool {
    url.starts_with("ssl://") || url.starts_with("tcp://")
}
