//! The indexer client of `RgbValidator`, and the witness resolver that
//! consensus uses.
//!
//! Consensus resolves witnesses from the consignment itself: a V1 bundle
//! always carries its full tx ([`ConsignmentTxResolver`]). The RGB-source path
//! checks witness inclusion through SPV. The mint destination path has no
//! separate SPV inclusion check.
//!
//! The indexer only serves [`RgbValidator::fetch_transaction`]. The URL scheme
//! selects Electrum (`ssl://`, `tcp://`) or Esplora (`https://`, `http://`),
//! through the host vsock forwarder. Each call crosses the trust boundary and
//! has a timeout.

use std::collections::BTreeMap;
use std::time::Duration;

#[cfg(test)]
use super::types::ValidatedConsignment;
use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::rgb::spv::Network;
use rgbstd::containers::Transfer;
use rgbstd::validation::{ResolveWitness, WitnessResolverError, WitnessStatus};
use rgbstd::vm::WitnessOrd;
use rgbstd::ChainNet;

/// Per-socket timeout (seconds) for the Electrum client.
/// `Config::default()` has `timeout: None`, so a stalled read blocks the
/// worker thread indefinitely. This limit applies to each socket operation.
/// The ingress deadline does not cancel indexer work. The timeout is compiled
/// into the image.
const ELECTRUM_TIMEOUT_SECS: u64 = 15;

/// Timeout (seconds) for one Esplora HTTP call, connect and read.
const ESPLORA_HTTP_TIMEOUT_SECS: u64 = 30;

/// Validates RGB consignments using rgbstd, and fetches transactions.
///
/// Production uses Electrum at `ssl://...:50002` through the vsock forwarder.
/// TLS ends inside the enclave against the real server cert, so the host
/// relays only ciphertext. Dev signet uses Esplora at an `https://` URL.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) indexer_url: String,
    pub(super) chain_net: ChainNet,
    /// [`ELECTRUM_TIMEOUT_SECS`] or [`ESPLORA_HTTP_TIMEOUT_SECS`].
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
    /// - `bitcoin_network`: a `BITCOIN_NETWORK` value (see
    ///   [`Network::from_env_str`]).
    pub fn new(indexer_url: String, bitcoin_network: &str) -> Result<Self> {
        let timeout_secs = if is_electrum_url(&indexer_url) {
            ELECTRUM_TIMEOUT_SECS
        } else if indexer_url.starts_with("https://") || indexer_url.starts_with("http://") {
            ESPLORA_HTTP_TIMEOUT_SECS
        } else {
            return Err(EnclaveError::Internal(format!(
                "indexer URL {indexer_url:?} is not ssl:// or tcp:// (Electrum), \
                 https:// or http:// (Esplora)"
            )));
        };
        let chain_net = Network::from_env_str(bitcoin_network)
            .map_err(|e| {
                EnclaveError::Internal(format!("unknown bitcoin network {bitcoin_network}: {e}"))
            })?
            .chain_net();
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

    /// Fetches a raw transaction by txid from the indexer.
    ///
    /// The host controls the egress, so the bytes are hashed again and must
    /// match `txid`. A lying host can only make the fetch fail. The send-RGB
    /// change-leg proof (W-06 / #52) uses it to read the script of an outpoint
    /// that is not in the PSBT.
    pub fn fetch_transaction(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
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
            .timeout(Some(Duration::from_secs(self.timeout_secs)))
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

/// Answers each witness from the consignment, with no network call.
///
/// Every witness is `Tentative`: the resolver says nothing about depth. The
/// RGB-source path proves depth with SPV. Consignment SPV proofs fall through
/// to this answer, since no header source is offered.
pub(super) struct ConsignmentTxResolver {
    txes: BTreeMap<bitcoin::Txid, bitcoin::Transaction>,
    chain_net: ChainNet,
}

impl ConsignmentTxResolver {
    /// Owns the txs, so phase 2 can borrow the pending validation mutably.
    pub(super) fn new(transfer: &Transfer, chain_net: ChainNet) -> Self {
        let txes = transfer
            .bundles
            .iter()
            .map(|wb| (wb.witness_id(), wb.tx.clone()))
            .collect();
        Self { txes, chain_net }
    }
}

impl ResolveWitness for ConsignmentTxResolver {
    fn resolve_witness(
        &self,
        witness_id: bitcoin::Txid,
    ) -> std::result::Result<WitnessStatus, WitnessResolverError> {
        Ok(match self.txes.get(&witness_id) {
            Some(tx) => WitnessStatus::Resolved(tx.clone(), WitnessOrd::Tentative),
            None => WitnessStatus::Unresolved,
        })
    }

    fn check_chain_net(
        &self,
        chain_net: ChainNet,
    ) -> std::result::Result<(), WitnessResolverError> {
        if chain_net != self.chain_net {
            return Err(WitnessResolverError::WrongChainNet);
        }
        Ok(())
    }
}
