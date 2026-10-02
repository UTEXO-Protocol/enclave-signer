//! The witness-resolver client: all network calls of `RgbValidator`.
//!
//! The URL scheme selects Esplora REST or Electrum, through the host vsock
//! forwarder. Each call crosses the trust boundary. Thus each call has a
//! timeout, and each answer is evidence to check, never trusted input.
//! [`super::consensus`] runs RGB consensus on the results.

#[cfg(test)]
use super::types::ValidatedConsignment;
use crate::error::EnclaveError;
use crate::error::Result;
use rgbstd::indexers::esplora_blocking::esplora_client;
use rgbstd::ChainNet;

/// Maximum time for one blocking Esplora HTTP call (connect + read), in
/// seconds. The egress goes through the host vsock proxy, so a stalled host
/// can block the worker thread. Aligned with `TOTAL_REQUEST_TIMEOUT` in
/// `conn.rs`. Compile-time and PCR-attested; the host cannot change it.
pub(super) const ESPLORA_HTTP_TIMEOUT_SECS: u64 = 30;

/// Per-socket timeout (seconds) for the Electrum witness resolver, used in
/// production. Electrum version of [`ESPLORA_HTTP_TIMEOUT_SECS`].
/// `Config::default()` has `timeout: None`, so a stalled read blocks the
/// worker thread forever. `electrum-client` retries `retry` times, so the
/// worst case is about `(retry+1) *` this value. That stays within the
/// `conn.rs` `TOTAL_REQUEST_TIMEOUT`. Compile-time and PCR-attested.
pub(super) const ELECTRUM_WITNESS_TIMEOUT_SECS: u64 = 15;

// TEMPORARY. The `s/bfa` RGB branches use 0.11.1-rc.10, which pins
// electrum-client 0.24. Thus the `timeout` calls use the 0.24 shape (`u8`
// seconds), not the 0.25 `Duration`. Change them back to `Duration` when the
// `s/bfa` branches move to rc.11.

/// Validates RGB consignments using rgbstd and a witness resolver.
///
/// The URL scheme selects the resolver backend: `ssl://` / `tcp://` ->
/// Electrum (`electrum-client`), other schemes (`http://` / `https://`) ->
/// Esplora REST. Production uses Electrum (`ssl://...:50002`) through the
/// vsock forwarder. With `ssl://`, TLS ends inside the enclave against the
/// real server cert, so the host relays only ciphertext.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) indexer_url: String,
    pub(super) chain_net: ChainNet,
    /// Per-request HTTP timeout, [`ESPLORA_HTTP_TIMEOUT_SECS`] in production.
    /// Only tests can change it (no env or host input).
    pub(super) http_timeout_secs: u64,
    /// Canned validation result, so tests run the signing path with no
    /// indexer.
    #[cfg(test)]
    pub(super) canned: Option<ValidatedConsignment>,
}

impl RgbValidator {
    /// Creates a validator.
    ///
    /// - `indexer_url`: witness-resolver endpoint. `ssl://host:port` /
    ///   `tcp://host:port` selects Electrum; `http(s)://...` selects Esplora.
    ///   Usually `ssl://<host>:50002` (Electrum) or `http://127.0.0.1:3443`
    ///   (Esplora).
    /// - `bitcoin_network`: "bitcoin" (or "mainnet"), "testnet" (or
    ///   "testnet3"), "signet", or "regtest".
    pub fn new(indexer_url: String, bitcoin_network: &str) -> Result<Self> {
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
            http_timeout_secs: ESPLORA_HTTP_TIMEOUT_SECS,
            #[cfg(test)]
            canned: None,
        })
    }

    /// A validator that returns `validated` and does not call the indexer.
    #[cfg(test)]
    pub fn canned(validated: ValidatedConsignment) -> Self {
        let mut v =
            Self::new("http://indexer.invalid".into(), "bitcoin").expect("canned validator");
        v.canned = Some(validated);
        v
    }

    /// Sets a short HTTP timeout for the stalled-host test.
    #[cfg(test)]
    pub(super) fn with_http_timeout(mut self, secs: u64) -> Self {
        self.http_timeout_secs = secs;
        self
    }

    /// Fetches a raw transaction by txid from the witness indexer.
    ///
    /// The host controls the egress, so the bytes are hashed again and must
    /// match `txid`. A lying host can only make the fetch fail. The send-RGB
    /// change-leg proof (W-06 / #52) uses it to read the script of an outpoint
    /// that is not in the PSBT.
    pub fn fetch_transaction(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
        // Same backend and timeouts as the witness resolver (final I-03 / #87).
        let is_electrum =
            self.indexer_url.starts_with("ssl://") || self.indexer_url.starts_with("tcp://");
        let tx = if is_electrum {
            use rgbstd::indexers::electrum_blocking::electrum_client::{
                Client, Config, ElectrumApi,
            };
            let cfg = Config::builder()
                .timeout(Some(ELECTRUM_WITNESS_TIMEOUT_SECS as u8))
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
            let client = esplora_client::Builder::new(&self.indexer_url)
                .timeout(self.http_timeout_secs)
                .build_blocking();
            client
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
