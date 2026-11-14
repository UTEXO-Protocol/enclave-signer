//! Electrum and Esplora connections for no-SPV burn validation.
//!
//! rgb-lib checks witnesses through its upstream resolvers, using the safe
//! height supplied here. This path trusts the indexer's chain view.
//! `LookupsOnly` prevents consignment proofs from bypassing those lookups.

use std::num::NonZeroU32;
use std::time::Duration;

use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::rgb::spv::Network;
use bitcoin::Txid;
use rgbstd::indexers::electrum_blocking::{electrum_client, ElectrumClient};
use rgbstd::indexers::esplora_blocking::{esplora_client, EsploraClient};
use rgbstd::validation::{ResolveWitness, WitnessResolverError, WitnessStatus};
use rgbstd::ChainNet;

/// Validates RGB consignments and configures the no-SPV indexer connection.
///
/// A release client uses TLS through the vsock forwarder. TLS ends inside
/// the enclave against the configured server's cert.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) indexer_url: String,
    pub(super) chain_net: ChainNet,
    /// Test override for the read timeout in [`crate::limits`].
    pub(super) timeout_secs: Option<u64>,
}

impl RgbValidator {
    /// Creates a validator.
    ///
    /// - `indexer_url`: `ssl://` or `tcp://` for Electrum, `https://` or
    ///   `http://` for Esplora. Any other scheme is refused.
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
        Ok(Self {
            indexer_url,
            chain_net,
            timeout_secs: None,
        })
    }

    /// Sets a short indexer timeout for tests.
    #[cfg(test)]
    pub(super) fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    fn timeout_of(&self, limit: u64) -> u64 {
        self.timeout_secs.unwrap_or(limit)
    }

    /// Builds the resolver and fixes the confirmation boundary from one tip read.
    pub(super) fn indexer_resolver(
        &self,
        min_confirmations: u32,
    ) -> Result<(Box<dyn ResolveWitness>, NonZeroU32)> {
        let (resolver, tip): (Box<dyn ResolveWitness>, u32) = if is_electrum_url(&self.indexer_url)
        {
            let inner = self.electrum_client()?;
            let tip = electrum_tip(&inner)?;
            (Box::new(LookupsOnly(ElectrumClient { inner })), tip)
        } else {
            let inner = self.esplora_client();
            let tip = inner
                .get_height()
                .map_err(|e| indexer_error(format!("esplora tip lookup failed: {e}")))?;
            (Box::new(LookupsOnly(EsploraClient { inner })), tip)
        };
        let safe_height = confirmation_height(tip, min_confirmations)
            .map_err(|e| EnclaveError::CrossCheck(format!("witness confirmation policy: {e}")))?;
        Ok((resolver, safe_height))
    }

    fn esplora_client(&self) -> esplora_client::BlockingClient {
        esplora_client::Builder::new(&self.indexer_url)
            .timeout(self.timeout_of(crate::limits::get().esplora_timeout_secs))
            .build_blocking()
    }

    fn electrum_client(&self) -> Result<electrum_client::Client> {
        let cfg = electrum_client::Config::builder()
            .timeout(Some(Duration::from_secs(
                self.timeout_of(crate::limits::get().electrum_timeout_secs),
            )))
            .build();
        electrum_client::Client::from_config(&self.indexer_url, cfg)
            .map_err(|e| indexer_error(format!("electrum connection failed: {e}")))
    }
}

/// Disables header lookups so embedded proofs cannot bypass witness lookup.
/// The upstream proof verifier lacks the 64-byte-node check (CVE-2017-12842).
struct LookupsOnly<R>(R);

impl<R: ResolveWitness> ResolveWitness for LookupsOnly<R> {
    fn resolve_witness(
        &self,
        txid: Txid,
    ) -> std::result::Result<WitnessStatus, WitnessResolverError> {
        self.0.resolve_witness(txid)
    }

    fn check_chain_net(
        &self,
        chain_net: ChainNet,
    ) -> std::result::Result<(), WitnessResolverError> {
        self.0.check_chain_net(chain_net)
    }
}

fn electrum_tip(client: &electrum_client::Client) -> Result<u32> {
    use electrum_client::ElectrumApi;
    let tip = client
        .block_headers_subscribe()
        .map_err(|e| indexer_error(format!("electrum tip lookup failed: {e}")))?
        .height;
    u32::try_from(tip).map_err(|_| indexer_error(format!("electrum tip {tip} is not a u32")))
}

/// Computes `tip - min_confirmations + 1`. Rejects zero or underflow, since
/// passing no safe height would disable rgb-lib's confirmation policy.
pub(super) fn confirmation_height(
    tip: u32,
    min_confirmations: u32,
) -> std::result::Result<NonZeroU32, String> {
    min_confirmations
        .checked_sub(1)
        .and_then(|offset| tip.checked_sub(offset))
        .and_then(NonZeroU32::new)
        .ok_or_else(|| {
            format!(
                "indexer tip {tip} cannot provide a safe height for {min_confirmations} \
                 confirmation(s)"
            )
        })
}

fn indexer_error(reason: String) -> EnclaveError {
    EnclaveError::CrossCheck(format!(
        "the Bitcoin indexer cannot resolve the witnesses: {reason} - refusing to sign"
    ))
}

fn is_electrum_url(url: &str) -> bool {
    url.starts_with("ssl://") || url.starts_with("tcp://")
}
