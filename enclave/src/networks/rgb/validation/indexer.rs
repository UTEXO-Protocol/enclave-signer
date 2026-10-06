//! The witness-resolver client: all network calls of `RgbValidator`.
//!
//! The URL scheme selects Electrum (`ssl://`, `tcp://`) or Esplora (`https://`,
//! `http://`), through the host vsock forwarder. Esplora serves our custom
//! signet: rgb-ops' Electrum chain check needs a public-signet tx it lacks.
//! Each call crosses the trust boundary and has a timeout.
//! [`super::consensus`] runs RGB consensus on the results. The RGB-source
//! path also checks witness inclusion through SPV. The mint destination
//! path has no separate SPV inclusion check.

#[cfg(test)]
use super::types::ValidatedConsignment;
use crate::error::EnclaveError;
use crate::error::Result;
use rgbstd::ChainNet;

/// Per-socket timeout (seconds) for the Electrum witness resolver.
/// `Config::default()` has `timeout: None`, so a stalled read blocks the
/// worker thread indefinitely. This limit applies to each socket operation.
/// Retries and multiple calls can exceed the ingress response deadline.
/// The ingress deadline does not cancel resolver work. The timeout is compiled
/// into the image.
const ELECTRUM_WITNESS_TIMEOUT_SECS: u64 = 15;

/// Timeout (seconds) for one Esplora HTTP call, connect and read.
const ESPLORA_HTTP_TIMEOUT_SECS: u64 = 30;

// TEMPORARY. The `s/bfa` RGB branches use 0.11.1-rc.10, which pins
// electrum-client 0.24. Thus the `timeout` calls use the 0.24 shape (`u8`
// seconds), not the 0.25 `Duration`. Change them back to `Duration` when the
// `s/bfa` branches move to rc.11.

/// Validates RGB consignments using rgbstd and a witness resolver.
///
/// Production uses Electrum at `ssl://...:50002` through the vsock forwarder.
/// TLS ends inside the enclave against the real server cert, so the host
/// relays only ciphertext. Dev signet uses Esplora at an `https://` URL.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) indexer_url: String,
    pub(super) chain_net: ChainNet,
    /// [`ELECTRUM_WITNESS_TIMEOUT_SECS`] or [`ESPLORA_HTTP_TIMEOUT_SECS`].
    /// Only tests can change it (no env or host input).
    pub(super) timeout_secs: u64,
    /// Canned validation result, so tests run the signing path with no
    /// indexer.
    #[cfg(test)]
    pub(super) canned: Option<ValidatedConsignment>,
}

impl RgbValidator {
    /// Creates a validator.
    ///
    /// - `indexer_url`: `ssl://` or `tcp://` for Electrum, `https://` or
    ///   `http://` for Esplora. Any other scheme is refused.
    /// - `bitcoin_network`: "bitcoin" (or "mainnet"), "testnet" (or
    ///   "testnet3"), "signet", or "regtest".
    pub fn new(indexer_url: String, bitcoin_network: &str) -> Result<Self> {
        let timeout_secs = if is_electrum_url(&indexer_url) {
            ELECTRUM_WITNESS_TIMEOUT_SECS
        } else if indexer_url.starts_with("https://") || indexer_url.starts_with("http://") {
            ESPLORA_HTTP_TIMEOUT_SECS
        } else {
            return Err(EnclaveError::Internal(format!(
                "indexer URL {indexer_url:?} is not ssl:// or tcp:// (Electrum), \
                 https:// or http:// (Esplora)"
            )));
        };
        let chain_net = match bitcoin_network {
            "bitcoin" | "mainnet" => ChainNet::BitcoinMainnet,
            "testnet" | "testnet3" => ChainNet::BitcoinTestnet3,
            "signet" => ChainNet::BitcoinSignet,
            "regtest" => ChainNet::BitcoinRegtest,
            other => {
                return Err(EnclaveError::Internal(format!(
                    "unknown bitcoin network: {other}"
                )))
            }
        };
        tracing::info!(%indexer_url, %bitcoin_network, "RGB validator configured");
        Ok(Self {
            indexer_url,
            chain_net,
            timeout_secs,
            #[cfg(test)]
            canned: None,
        })
    }

    /// A validator that returns `validated` and does not call the indexer.
    #[cfg(test)]
    pub fn canned(validated: ValidatedConsignment) -> Self {
        let mut v =
            Self::new("tcp://indexer.invalid:1".into(), "bitcoin").expect("canned validator");
        v.canned = Some(validated);
        v
    }

    /// Sets a short timeout for the stalled-host test.
    #[cfg(test)]
    pub(super) fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// The witness resolver for this URL, with its timeout.
    pub(super) fn witness_resolver(&self) -> Result<rgbstd::indexers::AnyResolver> {
        use rgbstd::indexers::AnyResolver;
        if !is_electrum_url(&self.indexer_url) {
            use rgbstd::indexers::esplora_blocking::esplora_client;
            let builder =
                esplora_client::Builder::new(&self.indexer_url).timeout(self.timeout_secs);
            return AnyResolver::esplora_blocking(builder).map_err(|e| {
                tracing::error!(indexer_url = %self.indexer_url, "esplora resolver creation failed: {e}");
                EnclaveError::CrossCheck(format!("esplora resolver creation failed: {e}"))
            });
        }
        // `Config::default()` has `timeout: None`, so a stalled read blocks the
        // worker thread forever. This re-export matches `AnyResolver`.
        use rgbstd::indexers::electrum_blocking::electrum_client;
        let electrum_cfg = electrum_client::Config::builder()
            .timeout(Some(self.timeout_secs as u8))
            .build();
        AnyResolver::electrum_blocking(&self.indexer_url, Some(electrum_cfg)).map_err(|e| {
            tracing::error!(indexer_url = %self.indexer_url, "electrum resolver creation failed: {e}");
            EnclaveError::CrossCheck(format!("electrum resolver creation failed: {e}"))
        })
    }

    /// Fetches a raw transaction by txid from the witness indexer.
    ///
    /// The host controls the egress, so the bytes are hashed again and must
    /// match `txid`. A lying host can only make the fetch fail. The send-RGB
    /// change-leg proof (W-06 / #52) uses it to read the script of an outpoint
    /// that is not in the PSBT.
    pub fn fetch_transaction(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
        // Same backend and timeout as the witness resolver (final I-03 / #87).
        let tx = if is_electrum_url(&self.indexer_url) {
            self.fetch_electrum_tx(txid)?
        } else {
            self.fetch_esplora_tx(txid)?
        };

        let got = tx.compute_txid();
        if got != txid {
            return Err(EnclaveError::CrossCheck(format!(
                "indexer returned tx {got} for a request for tx {txid} - refusing to trust its \
                 outputs"
            )));
        }
        Ok(tx)
    }

    fn fetch_esplora_tx(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
        use rgbstd::indexers::esplora_blocking::esplora_client;
        esplora_client::Builder::new(&self.indexer_url)
            .timeout(self.timeout_secs)
            .build_blocking()
            .get_tx(&txid)
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("esplora fetch of tx {txid} failed: {e}"))
            })?
            .ok_or_else(|| EnclaveError::CrossCheck(format!("esplora does not know tx {txid}")))
    }

    fn fetch_electrum_tx(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
        use rgbstd::indexers::electrum_blocking::electrum_client::{Client, Config, ElectrumApi};
        let cfg = Config::builder()
            .timeout(Some(self.timeout_secs as u8))
            .build();
        let client = Client::from_config(&self.indexer_url, cfg).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "electrum client creation failed while resolving outpoint tx {txid}: {e}"
            ))
        })?;
        let raw = client.transaction_get_raw(&txid).map_err(|e| {
            EnclaveError::CrossCheck(format!("electrum fetch of tx {txid} failed: {e}"))
        })?;
        bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "electrum returned bytes for tx {txid} that do not decode: {e}"
            ))
        })
    }
}

fn is_electrum_url(url: &str) -> bool {
    url.starts_with("ssl://") || url.starts_with("tcp://")
}
