//! The indexer client of `RgbValidator`.
//!
//! It serves [`RgbValidator::fetch_transaction`] and, on the mint path, the
//! on-chain status of the consignment witnesses ([`IndexerWitnesses`]) and of
//! an off-tx seal. The burn path reads witness status from SPV proofs instead.
//! The URL scheme selects Electrum (`ssl://`, `tcp://`) or Esplora
//! (`https://`, `http://`), through the host vsock forwarder. Each call
//! crosses the trust boundary and has a timeout. Electrum calls are
//! non-verbose, so any Electrum server works.

use std::cell::OnceCell;
use std::num::NonZeroU32;
use std::time::Duration;

use bitcoin::constants::ChainHash;
use bitcoin::hashes::Hash;

#[cfg(test)]
use super::types::ValidatedConsignment;
use super::witness::ConfirmedWitnesses;
use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::rgb::spv::{verify_merkle_proof, Network};
use rgbstd::indexers::electrum_blocking::electrum_client;
use rgbstd::indexers::esplora_blocking::esplora_client;
use rgbstd::indexers::esplora_blocking::EsploraClient;
use rgbstd::validation::{ResolveWitness, WitnessStatus};
use rgbstd::vm::{WitnessOrd, WitnessPos};
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
        self.esplora_client()
            .get_tx(&txid)
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("esplora fetch of tx {txid} failed: {e}"))
            })?
            .ok_or_else(|| EnclaveError::CrossCheck(format!("esplora does not know tx {txid}")))
    }

    fn fetch_electrum_tx(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
        use electrum_client::ElectrumApi;
        let client = self.electrum_client().map_err(|e| {
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

impl RgbValidator {
    /// The mint path's witness source, at `min_confirmations` depth. It
    /// connects on the first witness it is asked about.
    pub fn indexer_witnesses(&self, min_confirmations: u32) -> IndexerWitnesses<'_> {
        IndexerWitnesses {
            validator: self,
            min_confirmations,
            session: OnceCell::new(),
        }
    }

    /// Refuses `outpoint` unless the indexer shows it mined and unspent, so
    /// state sealed there is not lost. `script` is the output's script.
    pub fn assert_unspent_and_mined(
        &self,
        outpoint: bitcoin::OutPoint,
        script: &bitcoin::Script,
    ) -> Result<()> {
        let live = if is_electrum_url(&self.indexer_url) {
            self.electrum_client()
                .and_then(|client| electrum_unspent_and_mined(&client, outpoint, script))
        } else {
            esplora_unspent_and_mined(&self.esplora_client(), outpoint)
        }
        .map_err(|e| {
            EnclaveError::CrossCheck(format!("indexer check of outpoint {outpoint} failed: {e}"))
        })?;
        if !live {
            return Err(EnclaveError::CrossCheck(format!(
                "outpoint {outpoint} is spent or not mined, per the indexer - state sealed there \
                 would be lost"
            )));
        }
        Ok(())
    }

    fn esplora_client(&self) -> esplora_client::BlockingClient {
        esplora_client::Builder::new(&self.indexer_url)
            .timeout(self.timeout_secs)
            .build_blocking()
    }

    fn electrum_client(&self) -> std::result::Result<electrum_client::Client, String> {
        let cfg = electrum_client::Config::builder()
            .timeout(Some(Duration::from_secs(self.timeout_secs)))
            .build();
        electrum_client::Client::from_config(&self.indexer_url, cfg).map_err(|e| e.to_string())
    }

    /// A session on the indexer, after it proved it serves our network.
    fn connect(&self) -> std::result::Result<IndexerSession, String> {
        if is_electrum_url(&self.indexer_url) {
            electrum_session(self.electrum_client()?, self.chain_net)
        } else {
            esplora_session(self.esplora_client(), self.chain_net)
        }
    }
}

/// The mint path's witness status, from the pinned indexer. TLS ends in the
/// enclave on a release image, so the host can only make a lookup fail.
pub struct IndexerWitnesses<'a> {
    validator: &'a RgbValidator,
    min_confirmations: u32,
    session: OnceCell<IndexerSession>,
}

enum Backend {
    Electrum(Box<electrum_client::Client>),
    Esplora(EsploraClient),
}

struct IndexerSession {
    backend: Backend,
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
        let place = match &session.backend {
            Backend::Electrum(client) => electrum_place(client, tx)?,
            Backend::Esplora(resolver) => {
                let txid = tx.compute_txid();
                let status = resolver
                    .resolve_witness(txid)
                    .map_err(|e| format!("indexer lookup failed: {e}"))?;
                esplora_place(status, txid)?
            }
        };
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

/// The place of an Esplora answer for `txid`.
pub(super) fn esplora_place(
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
        backend: Backend::Esplora(resolver),
        tip,
    })
}

fn esplora_unspent_and_mined(
    client: &esplora_client::BlockingClient,
    outpoint: bitcoin::OutPoint,
) -> std::result::Result<bool, String> {
    let status = client
        .get_tx_status(&outpoint.txid)
        .map_err(|e| format!("esplora tx status failed: {e}"))?;
    if !status.confirmed {
        return Ok(false);
    }
    let output = client
        .get_output_status(&outpoint.txid, u64::from(outpoint.vout))
        .map_err(|e| format!("esplora output status failed: {e}"))?;
    Ok(output.is_some_and(|o| !o.spent))
}

// Electrum, with non-verbose calls only: servers such as romanz/electrs do not
// serve verbose transactions.

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
        backend: Backend::Electrum(Box::new(client)),
        tip,
    })
}

/// Finds `tx` in the history of its first non-OP_RETURN output, then proves
/// its block with a merkle proof against that block's header.
fn electrum_place(
    client: &electrum_client::Client,
    tx: &bitcoin::Transaction,
) -> std::result::Result<TxPlace, String> {
    use electrum_client::ElectrumApi;
    let txid = tx.compute_txid();
    let script = tx
        .output
        .iter()
        .map(|o| o.script_pubkey.as_script())
        .find(|s| !s.is_op_return())
        .ok_or("it has no output an Electrum server indexes")?;
    let history = client
        .script_get_history(script)
        .map_err(|e| format!("electrum history lookup failed: {e}"))?;
    let Some(entry) = history.iter().find(|h| h.tx_hash == txid) else {
        return Ok(TxPlace::Unknown);
    };
    // 0 is the mempool, -1 the mempool with unconfirmed parents.
    let Some(height) = u32::try_from(entry.height).ok().and_then(NonZeroU32::new) else {
        return Ok(TxPlace::Unmined);
    };
    let header = client
        .block_header(height.get() as usize)
        .map_err(|e| format!("electrum header lookup of block {height} failed: {e}"))?;
    let proof = client
        .transaction_get_merkle(&txid, height.get() as usize)
        .map_err(|e| format!("electrum merkle lookup failed: {e}"))?;
    assert_in_block(txid, height, &header, &proof)?;
    WitnessPos::bitcoin(height, i64::from(header.time))
        .map(TxPlace::Mined)
        .ok_or_else(|| format!("block {height} has an invalid time {}", header.time))
}

/// `proof` places `txid` in the block of `header`, at `height`.
pub(super) fn assert_in_block(
    txid: bitcoin::Txid,
    height: NonZeroU32,
    header: &bitcoin::block::Header,
    proof: &electrum_client::GetMerkleRes,
) -> std::result::Result<(), String> {
    if proof.block_height != height.get() as usize {
        return Err(format!(
            "the merkle proof is for block {}, not {height}",
            proof.block_height
        ));
    }
    let pos = u32::try_from(proof.pos).map_err(|_| "the merkle position is not a u32")?;
    // Electrum sends the path in display order.
    let path: Vec<[u8; 32]> = proof
        .merkle
        .iter()
        .map(|node| {
            let mut node = *node;
            node.reverse();
            node
        })
        .collect();
    verify_merkle_proof(
        &txid.to_byte_array(),
        pos,
        &path,
        &header.merkle_root.to_byte_array(),
    )
    .map_err(|e| format!("its merkle proof does not match block {height}: {e:?}"))
}

fn electrum_unspent_and_mined(
    client: &electrum_client::Client,
    outpoint: bitcoin::OutPoint,
    script: &bitcoin::Script,
) -> std::result::Result<bool, String> {
    use electrum_client::ElectrumApi;
    let unspent = client
        .script_list_unspent(script)
        .map_err(|e| format!("electrum unspent lookup failed: {e}"))?;
    Ok(unspent
        .iter()
        .any(|u| u.tx_hash == outpoint.txid && u.tx_pos == outpoint.vout as usize && u.height > 0))
}

fn is_electrum_url(url: &str) -> bool {
    url.starts_with("ssl://") || url.starts_with("tcp://")
}
