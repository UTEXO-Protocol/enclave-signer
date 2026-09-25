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
// the 0.25 API that came with rc.11: `timeout` took a `Duration` and
// `estimate_fee` a second argument. The three call sites below were stepped
// back to the 0.24 shapes purely so the branch builds. REVERT THEM once the
// `s/bfa` branches are rebased onto rc.11 - this is an upstream fix, not ours.

/// How long a fetched fee estimate stays fresh. Fee markets move on
/// block cadence, so a minute of staleness is immaterial while keeping the
/// sign-path from hitting Esplora on every request.
pub(super) const FEE_ESTIMATE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Confirmation target (blocks) used for the recommended fee rate.
pub(super) const FEE_ESTIMATE_TARGET: u16 = 6;

/// Fee-rate floor (sat/vB) for non-mainnet chains, which have no fee market and
/// answer `/fee-estimates` with `{}`. Compile-time and reachable only via
/// PCR0-attested `chain_net`, so serving `{}` to dodge the check only yields a
/// tighter floor. Generous, since non-mainnet coins are valueless.
pub(super) const NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB: f64 = 10.0;

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
    /// Cached `(fetched_at, sat/vB)` recommended fee rate, guarded for
    /// the multi-threaded worker pool. `None` until the first fetch.
    pub(super) fee_estimate_cache: std::sync::Mutex<Option<(std::time::Instant, f64)>>,
    /// Per-request HTTP timeout, [`ESPLORA_HTTP_TIMEOUT_SECS`] in production.
    /// Overridable only from tests (no env / host input reaches it).
    pub(super) http_timeout_secs: u64,
    /// Socket timeout for fee lookups; only tests override the pinned default.
    pub(super) electrum_fee_timeout_secs: u8,
    /// Canned validation result and fee rate for the crate's own tests, so the
    /// signing path runs with no indexer. Test-only by construction.
    #[cfg(test)]
    pub(super) canned: Option<(ValidatedConsignment, f64)>,
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
            fee_estimate_cache: std::sync::Mutex::new(None),
            http_timeout_secs: ESPLORA_HTTP_TIMEOUT_SECS,
            electrum_fee_timeout_secs: ELECTRUM_WITNESS_TIMEOUT_SECS as u8,
            #[cfg(test)]
            canned: None,
        })
    }

    /// A validator that answers from `validated` and `fee_rate_sat_vb` instead
    /// of the indexer. Test-only by construction.
    #[cfg(test)]
    pub fn canned(validated: ValidatedConsignment, fee_rate_sat_vb: f64) -> Self {
        let mut v =
            Self::new("http://indexer.invalid".into(), "bitcoin").expect("canned validator");
        v.canned = Some((validated, fee_rate_sat_vb));
        v
    }

    /// Shrink the HTTP timeout so the stalled-host test doesn't wait the
    /// production budget. Test-only by construction.
    #[cfg(test)]
    pub(super) fn with_http_timeout(mut self, secs: u64) -> Self {
        self.http_timeout_secs = secs;
        self
    }

    /// Recommended fee rate (sat/vB) from the enclave's own witness-indexer
    /// egress, for the send-RGB PSBT fee-rate check. The backend mirrors the
    /// resolver: Electrum `estimate_fee` for ssl://|tcp://, else Esplora
    /// `/fee-estimates` at [`FEE_ESTIMATE_TARGET`]. Cached for
    /// [`FEE_ESTIMATE_TTL`]. Fail-closed when the fetch fails or the rate is
    /// unusable. The one exception is an honest "no fee market" answer on a
    /// non-mainnet chain, which yields
    /// [`NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB`].
    pub fn recommended_fee_rate_sat_vb(&self) -> Result<f64> {
        #[cfg(test)]
        if let Some((_, rate)) = &self.canned {
            return Ok(*rate);
        }
        {
            let cache = self
                .fee_estimate_cache
                .lock()
                .map_err(|e| EnclaveError::Internal(format!("fee-estimate cache poisoned: {e}")))?;
            if let Some((fetched_at, rate)) = *cache {
                if fetched_at.elapsed() < FEE_ESTIMATE_TTL {
                    return Ok(rate);
                }
            }
        }

        // Concurrent cache misses may fetch independently; network I/O must
        // never hold the shared cache lock.
        // Backend mirrors the witness resolver: ssl://|tcp:// is Electrum,
        // anything else Esplora REST. Both paths are fail-closed - a failed
        // fetch is a refusal, never a skipped check.
        let is_electrum =
            self.indexer_url.starts_with("ssl://") || self.indexer_url.starts_with("tcp://");
        let rate = if is_electrum {
            self.electrum_fee_rate_sat_vb()?
        } else {
            self.esplora_fee_rate_sat_vb()?
        };

        if !rate.is_finite() || rate <= 0.0 {
            return Err(EnclaveError::CrossCheck(format!(
                "fee-estimate response is not a positive finite rate: {rate}"
            )));
        }

        let fetched_at = std::time::Instant::now();
        let mut cache = self
            .fee_estimate_cache
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("fee-estimate cache poisoned: {e}")))?;
        // Do not overwrite a newer concurrent refresh.
        if cache
            .as_ref()
            .is_none_or(|(cached_at, _)| *cached_at < fetched_at)
        {
            *cache = Some((fetched_at, rate));
        }
        Ok(rate)
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

    /// Esplora `/fee-estimates` backend for [`Self::recommended_fee_rate_sat_vb`].
    /// Fetches the confirmation-target rate (nearest available) in sat/vB.
    fn esplora_fee_rate_sat_vb(&self) -> Result<f64> {
        let client = esplora_client::Builder::new(&self.indexer_url)
            .timeout(self.http_timeout_secs)
            .build_blocking();
        let estimates = client.get_fee_estimates().map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "fee-estimate fetch failed - refusing to sign a send-RGB PSBT without a \
                 fee-rate sanity bound: {e}"
            ))
        })?;

        // Exact target if present, else the nearest available one.
        let fetched = estimates.get(&FEE_ESTIMATE_TARGET).copied().or_else(|| {
            estimates
                .iter()
                .min_by_key(|(t, _)| t.abs_diff(FEE_ESTIMATE_TARGET))
                .map(|(_, r)| *r)
        });

        // An empty map is Esplora honestly reporting no fee market: expected on
        // signet/regtest, anomalous on mainnet. A failed fetch never reaches
        // here - it fails closed above, on every network.
        match fetched {
            Some(rate) => Ok(rate),
            None if self.chain_net == ChainNet::BitcoinMainnet => Err(EnclaveError::CrossCheck(
                "fee-estimate response carried no targets - refusing to sign a send-RGB \
                 PSBT without a fee-rate sanity bound"
                    .into(),
            )),
            None => {
                tracing::warn!(
                    chain_net = ?self.chain_net,
                    fallback_sat_vb = NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB,
                    "fee-estimate response carried no targets; falling back to the pinned \
                     non-mainnet floor"
                );
                Ok(NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB)
            }
        }
    }

    /// Electrum `estimate_fee` backend for
    /// [`Self::recommended_fee_rate_sat_vb`], the production path. Electrum
    /// reports BTC per 1000 vbytes; converted to sat/vB. A non-positive answer
    /// means it cannot estimate: fail-closed on mainnet, falls back to the
    /// pinned floor elsewhere, mirroring the Esplora empty-map case.
    fn electrum_fee_rate_sat_vb(&self) -> Result<f64> {
        use rgbstd::indexers::electrum_blocking::electrum_client::{Client, Config, ElectrumApi};
        let config = Config::builder()
            .timeout(Some(self.electrum_fee_timeout_secs))
            .retry(0)
            .build();
        let client = Client::from_config(&self.indexer_url, config).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "electrum fee-estimate client creation failed - refusing to sign a send-RGB \
                 PSBT without a fee-rate sanity bound: {e}"
            ))
        })?;
        let btc_per_kvb = client
            // electrum-client 0.24 takes only the target and always uses the
            // server-default estimation. See the REVERT note above FEE_ESTIMATE_TTL.
            .estimate_fee(FEE_ESTIMATE_TARGET as usize)
            .map_err(|e| {
                EnclaveError::CrossCheck(format!(
                    "electrum fee-estimate fetch failed - refusing to sign a send-RGB PSBT \
                     without a fee-rate sanity bound: {e}"
                ))
            })?;

        // Electrum returns BTC/kvB; a non-positive value (typically -1) means
        // "cannot estimate". Mirror the Esplora empty-map handling.
        if btc_per_kvb <= 0.0 {
            if self.chain_net == ChainNet::BitcoinMainnet {
                return Err(EnclaveError::CrossCheck(
                    "electrum returned no fee estimate - refusing to sign a send-RGB PSBT \
                     without a fee-rate sanity bound"
                        .into(),
                ));
            }
            tracing::warn!(
                chain_net = ?self.chain_net,
                fallback_sat_vb = NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB,
                "electrum returned no fee estimate; falling back to the pinned non-mainnet \
                 floor"
            );
            return Ok(NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB);
        }

        // BTC/kvB -> sat/vB: x1e8 sat/BTC / 1000 vB/kvB = x100_000.
        Ok(btc_per_kvb * 100_000.0)
    }
}
