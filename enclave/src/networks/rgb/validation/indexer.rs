//! The witness-resolver client: all network calls of `RgbValidator`.
//!
//! The URL scheme selects Electrum or Esplora REST, through the host vsock
//! forwarder. Each call crosses the trust boundary. Each socket operation has a timeout.
//! [`super::consensus`] runs RGB consensus on the results. The RGB-source
//! path also checks witness inclusion through SPV. The mint destination
//! path has no separate SPV inclusion check.

#[cfg(test)]
use super::types::ValidatedConsignment;
use crate::error::EnclaveError;
use crate::error::Result;
use rgbstd::indexers::esplora_blocking::esplora_client;
use rgbstd::ChainNet;

/// Per-socket timeout (seconds) for the Electrum witness resolver.
/// `Config::default()` has `timeout: None`, so a stalled read blocks the
/// worker thread indefinitely. This limit applies to each socket operation.
/// Retries and multiple calls can exceed the ingress response deadline.
/// The ingress deadline does not cancel resolver work. The timeout is compiled
/// into the image.
const ELECTRUM_WITNESS_TIMEOUT_SECS: u64 = 15;

/// Timeout (seconds) for one blocking Esplora HTTP call (connect + read).
/// Compiled into the image, like the Electrum one.
const ESPLORA_HTTP_TIMEOUT_SECS: u64 = 30;

// TEMPORARY. The `s/bfa` RGB branches use 0.11.1-rc.10, which pins
// electrum-client 0.24. Thus the `timeout` calls use the 0.24 shape (`u8`
// seconds), not the 0.25 `Duration`. Change them back to `Duration` when the
// `s/bfa` branches move to rc.11.

/// Validates RGB consignments using rgbstd and a witness resolver.
///
/// The URL scheme selects the resolver: `ssl://` / `tcp://` -> Electrum
/// (`electrum-client`), `http://` / `https://` -> Esplora REST. Production
/// uses `ssl://...:50002` through the vsock forwarder. With `ssl://` or
/// `https://`, TLS ends inside the enclave against the real server cert, so
/// the host relays only ciphertext.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) indexer_url: String,
    pub(super) chain_net: ChainNet,
    /// [`ELECTRUM_WITNESS_TIMEOUT_SECS`] or [`ESPLORA_HTTP_TIMEOUT_SECS`] in
    /// production.
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
    /// - `indexer_url`: Electrum (`ssl://host:port`, `tcp://host:port`) or
    ///   Esplora (`http(s)://host[:port][/path]`). Any other scheme is refused.
    /// - `bitcoin_network`: "bitcoin" (or "mainnet"), "testnet" (or
    ///   "testnet3"), "signet", or "regtest".
    pub fn new(indexer_url: String, bitcoin_network: &str) -> Result<Self> {
        let timeout_secs = if is_electrum(&indexer_url) {
            ELECTRUM_WITNESS_TIMEOUT_SECS
        } else if indexer_url.starts_with("http://") || indexer_url.starts_with("https://") {
            ESPLORA_HTTP_TIMEOUT_SECS
        } else {
            return Err(EnclaveError::Internal(format!(
                "indexer URL {indexer_url:?} is not ssl://, tcp://, http:// or https://"
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

    /// True for an Electrum URL, false for Esplora.
    pub(super) fn is_electrum(&self) -> bool {
        is_electrum(&self.indexer_url)
    }

    /// Sets a short timeout for the stalled-host test.
    #[cfg(test)]
    pub(super) fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Fetches a raw transaction by txid from the witness indexer.
    ///
    /// The host controls the egress, so the bytes are hashed again and must
    /// match `txid`. A lying host can only make the fetch fail. The send-RGB
    /// change-leg proof (W-06 / #52) uses it to read the script of an outpoint
    /// that is not in the PSBT.
    pub fn fetch_transaction(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
        // Same backend and timeout as the witness resolver (final I-03 / #87).
        let tx = if self.is_electrum() {
            use rgbstd::indexers::electrum_blocking::electrum_client::{
                Client, Config, ElectrumApi,
            };
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
            })?
        } else {
            esplora_client::Builder::new(&self.indexer_url)
                .timeout(self.timeout_secs)
                .build_blocking()
                .get_tx(&txid)
                .map_err(|e| {
                    EnclaveError::CrossCheck(format!("esplora fetch of tx {txid} failed: {e}"))
                })?
                .ok_or_else(|| {
                    EnclaveError::CrossCheck(format!("esplora does not know tx {txid}"))
                })?
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
}

fn is_electrum(url: &str) -> bool {
    url.starts_with("ssl://") || url.starts_with("tcp://")
}
