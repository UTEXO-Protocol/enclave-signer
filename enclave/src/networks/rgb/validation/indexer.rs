//! The indexer client of `RgbValidator`.
//!
//! It serves the on-chain status of the consignment witnesses
//! ([`IndexerWitnesses`]) to a burn signer built without `spv`. An `spv` build
//! reads witness status from SPV proofs instead, and needs no indexer to sign.
//! The URL scheme selects Electrum (`ssl://`, `tcp://`) or Esplora
//! (`https://`, `http://`), through the host vsock forwarder. Each call
//! crosses the trust boundary and has a timeout. An Electrum server must
//! serve verbose `blockchain.transaction.get`, as rgb-lib requires.
//! Witness resolution is delegated to rgb-lib's upstream resolvers. This
//! adapter checks the network, transaction identity and confirmation depth;
//! it trusts the indexer for inclusion, height and time.

use std::cell::OnceCell;
use std::time::Duration;

use bitcoin::constants::ChainHash;

#[cfg(test)]
use super::types::ValidatedConsignment;
use super::witness::ConfirmedWitnesses;
use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::rgb::spv::Network;
use rgbstd::indexers::electrum_blocking::{electrum_client, ElectrumClient};
use rgbstd::indexers::esplora_blocking::esplora_client;
use rgbstd::indexers::esplora_blocking::EsploraClient;
use rgbstd::validation::{ResolveWitness, WitnessStatus};
use rgbstd::vm::{WitnessOrd, WitnessPos};
use rgbstd::ChainNet;

/// Validates RGB consignments with rgb-lib and supplies indexer witnesses.
///
/// A release client uses TLS through the vsock forwarder. TLS ends inside
/// the enclave against the configured server's cert.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) indexer_url: String,
    pub(super) chain_net: ChainNet,
    /// The indexer read timeout of a test. Other callers read the limit
    /// ([`crate::limits`]).
    pub(super) timeout_secs: Option<u64>,
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
        self.timeout_secs = Some(secs);
        self
    }

    /// The timeout of an indexer read: `limit`, or the value of a test.
    fn timeout_of(&self, limit: u64) -> u64 {
        self.timeout_secs.unwrap_or(limit)
    }
}

impl RgbValidator {
    /// The witness source of a no-SPV burn, at `min_confirmations` depth. It
    /// connects on the first witness it is asked about.
    pub fn indexer_witnesses(&self, min_confirmations: u32) -> IndexerWitnesses<'_> {
        IndexerWitnesses {
            validator: self,
            min_confirmations,
            session: OnceCell::new(),
        }
    }

    fn esplora_client(&self) -> esplora_client::BlockingClient {
        esplora_client::Builder::new(&self.indexer_url)
            .timeout(self.timeout_of(crate::limits::get().esplora_timeout_secs))
            .build_blocking()
    }

    fn electrum_client(&self) -> std::result::Result<electrum_client::Client, String> {
        let cfg = electrum_client::Config::builder()
            .timeout(Some(Duration::from_secs(
                self.timeout_of(crate::limits::get().electrum_timeout_secs),
            )))
            .build();
        electrum_client::Client::from_config(&self.indexer_url, cfg).map_err(|e| e.to_string())
    }

    /// A session after checking the indexer's network and capturing its tip.
    fn connect(&self) -> std::result::Result<IndexerSession, String> {
        if is_electrum_url(&self.indexer_url) {
            electrum_session(self.electrum_client()?, self.chain_net)
        } else {
            esplora_session(self.esplora_client(), self.chain_net)
        }
    }
}

/// The witness source of a no-SPV burn. It trusts the configured indexer and
/// enforces the enclave's confirmation policy.
pub struct IndexerWitnesses<'a> {
    validator: &'a RgbValidator,
    min_confirmations: u32,
    session: OnceCell<IndexerSession>,
}

struct IndexerSession {
    resolver: Box<dyn ResolveWitness>,
    tip: u32,
}

impl IndexerWitnesses<'_> {
    fn session(&self) -> std::result::Result<&IndexerSession, String> {
        if self.session.get().is_none() {
            let _ = self.session.set(self.validator.connect()?);
        }
        self.session
            .get()
            .ok_or_else(|| "indexer session was not kept".into())
    }
}

impl ConfirmedWitnesses for IndexerWitnesses<'_> {
    fn confirmed(&self, tx: &bitcoin::Transaction) -> std::result::Result<WitnessPos, String> {
        let session = self.session()?;
        let txid = tx.compute_txid();
        let status = session
            .resolver
            .resolve_witness(txid)
            .map_err(|e| format!("indexer lookup failed: {e}"))?;
        let place = indexer_place(status, txid)?;
        mined_deep_enough(place, session.tip, self.min_confirmations)
    }
}

/// Where the indexer places a tx.
#[derive(Debug)]
pub(super) enum TxPlace {
    Unknown,
    Unmined,
    Mined(WitnessPos),
}

/// The position of `place` if it is `min_confirmations` deep below `tip`.
/// Testnet min-difficulty blocks count too: no header chain tells them apart.
pub(super) fn mined_deep_enough(
    place: TxPlace,
    tip: u32,
    min_confirmations: u32,
) -> std::result::Result<WitnessPos, String> {
    let pos = match place {
        TxPlace::Mined(pos) => pos,
        TxPlace::Unmined => return Err("the indexer reports it unmined".into()),
        TxPlace::Unknown => return Err("the indexer does not know it".into()),
    };
    let height = pos.height().get();
    let depth = tip
        .checked_sub(height)
        .map(|d| d + 1)
        .ok_or_else(|| format!("its block {height} is above the indexer tip {tip}"))?;
    if depth < min_confirmations {
        return Err(format!(
            "only {depth} confirmation(s) at block {height}, need {min_confirmations}"
        ));
    }
    Ok(pos)
}

/// The place of an upstream resolver's answer for `txid`.
pub(super) fn indexer_place(
    status: WitnessStatus,
    txid: bitcoin::Txid,
) -> std::result::Result<TxPlace, String> {
    let (tx, ord) = match status {
        WitnessStatus::Resolved(tx, ord) => (tx, ord),
        WitnessStatus::Unresolved => return Ok(TxPlace::Unknown),
    };
    let got = tx.compute_txid();
    if got != txid {
        return Err(format!("the indexer answered with tx {got}"));
    }
    Ok(match ord {
        WitnessOrd::Mined(pos) => TxPlace::Mined(pos),
        _ => TxPlace::Unmined,
    })
}

fn esplora_session(
    inner: esplora_client::BlockingClient,
    chain_net: ChainNet,
) -> std::result::Result<IndexerSession, String> {
    let tip = inner
        .get_height()
        .map_err(|e| format!("esplora tip lookup failed: {e}"))?;
    let resolver = EsploraClient { inner };
    resolver
        .check_chain_net(chain_net)
        .map_err(|e| format!("indexer does not serve {chain_net}: {e}"))?;
    Ok(IndexerSession {
        resolver: Box::new(resolver),
        tip,
    })
}

/// Checks the server's genesis block, then reads its tip.
fn electrum_session(
    client: electrum_client::Client,
    chain_net: ChainNet,
) -> std::result::Result<IndexerSession, String> {
    use electrum_client::ElectrumApi;
    let genesis = client
        .block_header(0)
        .map_err(|e| format!("electrum genesis lookup failed: {e}"))?
        .block_hash();
    if ChainHash::from_genesis_block_hash(genesis) != chain_net.chain_hash() {
        return Err(format!(
            "indexer does not serve {chain_net}: its genesis block is {genesis}"
        ));
    }
    let tip = client
        .block_headers_subscribe()
        .map_err(|e| format!("electrum tip lookup failed: {e}"))?
        .height;
    let tip = u32::try_from(tip).map_err(|_| format!("electrum tip {tip} is not a u32"))?;
    Ok(IndexerSession {
        resolver: Box::new(ElectrumClient { inner: client }),
        tip,
    })
}

fn is_electrum_url(url: &str) -> bool {
    url.starts_with("ssl://") || url.starts_with("tcp://")
}
