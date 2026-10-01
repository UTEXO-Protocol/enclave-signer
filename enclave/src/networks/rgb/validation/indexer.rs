//! The witness-resolver client: everything `RgbValidator` does over the
//! network.
//!
//! Esplora REST or Electrum, chosen from the URL scheme, always reached
//! through the host's vsock forwarder. Every call here crosses the trust
//! boundary, so each one is bounded by its own timeout and each answer is
//! evidence to check, never input to trust. Running RGB consensus over what
//! comes back is [`super::consensus`].

#[cfg(test)]
use super::types::ValidatedConsignment;
use crate::error::EnclaveError;
use crate::error::Result;
use rgbstd::indexers::esplora_blocking::esplora_client;
use rgbstd::ChainNet;

/// Hard cap on a single blocking Esplora HTTP call (connect + read), in
/// seconds. The egress runs through the host-controlled vsock proxy on the
/// signing path, so without a timeout a stalled host pins the worker
/// thread. Aligned with `conn.rs`'s `TOTAL_REQUEST_TIMEOUT`.
/// Compile-time and PCR-attested, not host-tunable.
pub(super) const ESPLORA_HTTP_TIMEOUT_SECS: u64 = 30;

/// Per-socket timeout (seconds) for the Electrum witness resolver, the
/// production signing path. Electrum analog of [`ESPLORA_HTTP_TIMEOUT_SECS`]
/// and the same problem: `Config::default()` leaves
/// `timeout: None`, so a stalled electrs read blocks the worker thread forever
/// and eventually wedges the whole enclave. `electrum-client` retries `retry`
/// times, so worst-case blocking is ~`(retry+1) *` this; kept within the
/// `conn.rs` `TOTAL_REQUEST_TIMEOUT` budget. Compile-time and PCR-attested.
pub(super) const ELECTRUM_WITNESS_TIMEOUT_SECS: u64 = 15;

// TEMPORARY, tied to the BFA dependency base. The `s/bfa` RGB branches are cut
// from 0.11.1-rc.10, which pins electrum-client 0.24, while this crate targets
// the 0.25 API that came with rc.11: `timeout` took a `Duration`. The
// `timeout` call sites below were stepped back to the 0.24 shape purely so the
// branch builds. REVERT THEM once the `s/bfa` branches are rebased onto rc.11 -
// this is an upstream fix, not ours.

/// Validates RGB consignments using rgbstd and a witness resolver.
///
/// The resolver backend is chosen from the URL scheme at validation time:
/// `ssl://` / `tcp://` -> Electrum (`electrum-client`), anything else
/// (`http://` / `https://`) -> Esplora REST. Production uses an Electrum
/// endpoint (`ssl://...:50002`) reached through the vsock forwarder; with an
/// `ssl://` URL the TLS handshake terminates inside the enclave against the
/// real server cert, so the host relays only ciphertext.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) indexer_url: String,
    pub(super) chain_net: ChainNet,
    /// Per-request HTTP timeout, [`ESPLORA_HTTP_TIMEOUT_SECS`] in production.
    /// Overridable only from tests (no env / host input reaches it).
    pub(super) http_timeout_secs: u64,
    /// Canned validation result for the crate's own tests, so the signing
    /// path runs with no indexer. Test-only by construction.
    #[cfg(test)]
    pub(super) canned: Option<ValidatedConsignment>,
}

impl RgbValidator {
    /// Create a new validator.
    ///
    /// - `indexer_url`: witness-resolver endpoint. `ssl://host:port` /
    ///   `tcp://host:port` selects Electrum; `http(s)://...` selects Esplora.
    ///   Through the vsock forwarder this is typically `ssl://<host>:50002`
    ///   (Electrum) or the legacy `http://127.0.0.1:3443` (Esplora).
    /// - `bitcoin_network`: One of "bitcoin", "testnet", "signet", "regtest".
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

    /// A validator that answers from `validated` instead of the indexer.
    /// Test-only by construction.
    #[cfg(test)]
    pub fn canned(validated: ValidatedConsignment) -> Self {
        let mut v =
            Self::new("http://indexer.invalid".into(), "bitcoin").expect("canned validator");
        v.canned = Some(validated);
        v
    }

    /// Shrink the HTTP timeout so the stalled-host test doesn't wait the
    /// production budget. Test-only by construction.
    #[cfg(test)]
    pub(super) fn with_http_timeout(mut self, secs: u64) -> Self {
        self.http_timeout_secs = secs;
        self
    }

    /// Fetch a raw transaction by txid from the witness indexer.
    ///
    /// The egress is host-controlled, so the bytes are re-hashed and must match
    /// `txid`: a lying host can only make the fetch fail. Used by the send-RGB
    /// change-leg proof (W-06 / #52) to read the script of an outpoint that is
    /// not in the PSBT.
    pub fn fetch_transaction(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
        // Backend and timeouts mirror the witness resolver (final I-03 / #87).
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
