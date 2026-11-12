//! RGB source validation: all checks on the `RgbSource` payload, from field
//! shape to the SPV cross-check of its witness transactions.

#[cfg(rgb_to_evm)]
use super::asset_bind::{assert_asset_binding, AssetBindMode};
#[cfg(rgb_to_evm)]
use super::reject_list::ListAccess;
#[cfg(rgb_to_evm)]
use super::types::ValidatedConsignment;
#[cfg(rgb_to_evm)]
use super::witness::WitnessCheck;
use crate::config::BridgeConfig;
use crate::error::EnclaveError;
use crate::error::Result;
#[cfg(all(rgb_to_evm, feature = "spv"))]
use crate::networks::rgb::spv_crosscheck;
#[cfg(rgb_to_evm)]
use crate::networks::ValidationContext;
#[cfg(rgb_to_evm)]
use crate::proto::RgbSource;
#[cfg(rgb_to_evm)]
use sha3::{Digest, Keccak256};
#[cfg(all(rgb_to_evm, feature = "spv"))]
use std::time::SystemTime;

/// Validates the source payload, asset binding, mint backing and RGB history.
///
/// SPV builds require proof of every witness at `SPV_MIN_CONFIRMATIONS` depth
/// in the enclave's header chain, with those blocks pinned until signing.
/// Without SPV, rgb-lib checks depth against the trusted indexer's chain view.
/// An unmined or shallow witness rejects the history in either mode.
///
/// The asset is bound before external reads. For listed assets, rgb-lib also
/// checks the burn and companion transfers for rejected ancestry.
/// Destination checks run separately.
#[cfg(rgb_to_evm)]
pub fn validate_source(
    source: &RgbSource,
    ctx: &ValidationContext<'_>,
) -> Result<ValidatedConsignment> {
    validate_source_payload(source, ctx.bridge_config)?;

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "RGB source validation requires rgb_validator to be configured".into(),
        )
    })?;

    #[cfg(feature = "spv")]
    let proven = {
        let chain = lock_chain(ctx)?;
        spv_crosscheck::proven_witnesses(
            &chain,
            &source.merkle_proofs,
            ctx.bridge_config.spv_min_confirmations,
        )?
    };
    #[cfg(feature = "spv")]
    let witnesses = WitnessCheck::Proven(&proven);
    #[cfg(not(feature = "spv"))]
    let witnesses = WitnessCheck::Indexer {
        min_confirmations: ctx.bridge_config.spv_min_confirmations,
    };
    let bind_asset = |contract_id: &str| {
        assert_asset_binding(
            contract_id,
            &source.asset_id,
            ctx.bridge_config,
            AssetBindMode::Source,
        )
    };
    let lists = ListAccess {
        bind_asset: &bind_asset,
        read: ctx.reject_list_reader,
    };
    // A burn consignment contains its full mint ancestry. Each mint leaves an
    // anchor that only a bound lock confirms.
    let validated = validator.validate_consignment(
        &source.consignment,
        ctx.anchor_binder,
        &witnesses,
        &lists,
    )?;

    bind_asset(&validated.contract_id)?;

    #[cfg(feature = "spv")]
    {
        let chain = lock_chain(ctx)?;
        spv_crosscheck::validate_source_chain(
            &chain,
            Some(&validated),
            &source.merkle_proofs,
            SystemTime::now(),
            ctx.chain_pins,
            ctx.bridge_config.spv_min_confirmations,
        )?;
    }

    Ok(validated)
}

#[cfg(all(rgb_to_evm, feature = "spv"))]
fn lock_chain<'a>(
    ctx: &'a ValidationContext<'_>,
) -> Result<std::sync::MutexGuard<'a, crate::networks::rgb::spv::HeaderChain>> {
    ctx.header_chain
        .lock()
        .map_err(|e| EnclaveError::Internal(format!("SPV header chain lock poisoned: {e}")))
}

/// Total size cap (`MAX_CONSIGNMENT_BYTES`, set by the operator). It runs
/// before the keccak hash and the RGB parse. Thus a request under each
/// per-field cap cannot force too much work.
///
/// `label` names the consignment in the rejection, for example `"RGB source"`.
pub fn assert_consignment_size(consignment: &[u8], cfg: &BridgeConfig, label: &str) -> Result<()> {
    let max = crate::limits::in_force(cfg).max_consignment_bytes;
    if consignment.len() as u64 > max {
        return Err(EnclaveError::CrossCheck(format!(
            "{label} consignment too large: {} bytes (max {max})",
            consignment.len()
        )));
    }
    Ok(())
}

#[cfg(rgb_to_evm)]
pub(super) fn validate_source_payload(source: &RgbSource, cfg: &BridgeConfig) -> Result<()> {
    if source.consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB source requires raw consignment bytes; consignment_valid is not authoritative"
                .into(),
        ));
    }
    assert_consignment_size(&source.consignment, cfg, "RGB source")?;
    let limits = crate::limits::in_force(cfg);
    if source.merkle_proofs.len() as u64 > limits.max_merkle_proofs {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source carries too many merkle proofs: {} (max {})",
            source.merkle_proofs.len(),
            limits.max_merkle_proofs
        )));
    }
    let total_proof_bytes: usize = source
        .merkle_proofs
        .iter()
        .map(|p| p.txid.len() + p.merkle_path.iter().map(|s| s.len()).sum::<usize>())
        .sum();
    if total_proof_bytes as u64 > limits.max_total_proof_bytes {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source merkle proofs too large in aggregate: {total_proof_bytes} bytes (max {})",
            limits.max_total_proof_bytes
        )));
    }
    // Integrity, NOT authorization. The listener controls both `consignment`
    // and `consignment_hash`, so a match only proves the wire copy is intact.
    // Authorization comes from RGB validation, SPV anchoring, and the bind of
    // validated facts (contract_id / op_id / amount).
    if source.consignment_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "consignment present but consignment_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(&source.consignment);
    if computed[..] != source.consignment_hash {
        return Err(EnclaveError::CrossCheck(
            "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
        ));
    }
    if source.asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB source asset_id is empty".into(),
        ));
    }

    Ok(())
}

/// No-SPV source validation with real consignments and mock indexer responses.
#[cfg(all(test, not(feature = "spv"), feature = "burn-signer"))]
mod indexer_only_source {
    use super::*;
    use crate::networks::rgb::spv::Network;
    use crate::networks::rgb::validation::{BoundAnchors, RgbValidator, VerifiedLock};
    use crate::test_support::bfa_consignment::{self as gen, History, Issue};
    use bitcoin::block::Header;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::hashes::Hash;
    use bitcoin::{Transaction, TxMerkleNode, Txid};
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    const MIN_CONFIRMATIONS: u32 = 6;
    /// The block of the first witness. Each next witness is one block higher.
    const FIRST_BLOCK: u32 = 100;
    /// Transaction used by rgb-ops to check verbose support.
    const SIGNET_PROBE: &str = "8153034f45e695453250a8fb7225a5e545144071d8ed7b0d3211efa1f3c92ad8";

    /// What the fake indexer serves.
    #[derive(Clone)]
    struct Indexer {
        witnesses: Vec<Transaction>,
        /// The confirmations of the last witness.
        depth: u32,
        mined: bool,
        network: bitcoin::Network,
        verbose: bool,
        /// Witnesses it does not know.
        unknown: Vec<Txid>,
        /// The tx it answers with for every witness.
        answer_with: Option<Transaction>,
        /// Blocks the chain grows by once the first tip read is answered.
        advance: u32,
        /// Blocks the Electrum node is ahead of its index: its tx answers
        /// count that many more confirmations.
        ahead: u32,
        /// Tip reads answered so far, over every connection.
        tip_reads: Arc<AtomicU32>,
    }

    impl Indexer {
        /// Every witness of `history` mined, the last one `MIN_CONFIRMATIONS` deep.
        fn of(history: &History) -> Self {
            Self {
                witnesses: history.bundles.iter().map(|b| b.tx.clone()).collect(),
                depth: MIN_CONFIRMATIONS,
                mined: true,
                network: bitcoin::Network::Signet,
                verbose: true,
                unknown: Vec::new(),
                answer_with: None,
                advance: 0,
                ahead: 0,
                tip_reads: Arc::default(),
            }
        }

        /// Advances after the first read to test a fixed confirmation boundary.
        fn tip(&self) -> u32 {
            let grown = if self.tip_reads.load(Ordering::SeqCst) > 0 {
                self.advance
            } else {
                0
            };
            FIRST_BLOCK + self.witnesses.len() as u32 + self.depth - 2 + grown
        }

        fn read_tip(&self) -> u32 {
            let tip = self.tip();
            self.tip_reads.fetch_add(1, Ordering::SeqCst);
            tip
        }

        /// The genesis header, or the header of a witness's block: the
        /// witness is the only tx of that block.
        fn header(&self, height: u32) -> Option<Header> {
            let genesis = bitcoin::constants::genesis_block(self.network).header;
            if height == 0 {
                return Some(genesis);
            }
            let tx = self
                .witnesses
                .get(height.checked_sub(FIRST_BLOCK)? as usize)?;
            Some(Header {
                merkle_root: TxMerkleNode::from_byte_array(tx.compute_txid().to_byte_array()),
                time: block_time(height),
                ..genesis
            })
        }

        /// The tx it answers for the witness `txid`, and the witness's block.
        fn witness(&self, txid: &str) -> Option<(&Transaction, u32)> {
            let (tx, height) = self
                .witnesses
                .iter()
                .zip(FIRST_BLOCK..)
                .find(|(tx, _)| tx.compute_txid().to_string() == txid)?;
            if self.unknown.contains(&tx.compute_txid()) {
                return None;
            }
            Some((self.answer_with.as_ref().unwrap_or(tx), height))
        }
    }

    fn block_time(height: u32) -> u32 {
        gen::ISSUED_AT as u32 + height
    }

    fn electrum_answer(
        indexer: &Indexer,
        method: &str,
        params: &Value,
    ) -> std::result::Result<Value, String> {
        let genesis = bitcoin::constants::genesis_block(indexer.network).header;
        let txid = params[0].as_str().unwrap_or_default();
        let verbose = params[1] == json!(true);
        Ok(match method {
            "server.version" => json!(["fake-indexer", "1.4"]),
            "blockchain.block.header" => {
                let height = params[0].as_u64().and_then(|h| u32::try_from(h).ok());
                let header = height
                    .and_then(|h| indexer.header(h))
                    .ok_or("no such block")?;
                json!(serialize_hex(&header))
            }
            "blockchain.headers.subscribe" => {
                json!({"height": indexer.read_tip(), "hex": serialize_hex(&genesis)})
            }
            "blockchain.transaction.get" if verbose && !indexer.verbose => {
                return Err("verbose transactions are currently unsupported".into())
            }
            "blockchain.transaction.get" if txid == SIGNET_PROBE => json!({"hex": "00"}),
            "blockchain.transaction.get" => {
                let (tx, height) = indexer
                    .witness(txid)
                    .ok_or("No such mempool or blockchain transaction")?;
                let mut answer = json!({"hex": serialize_hex(tx)});
                if indexer.mined {
                    answer["confirmations"] = json!(indexer.tip() + 1 - height + indexer.ahead);
                    answer["blocktime"] = json!(block_time(height));
                }
                answer
            }
            "blockchain.transaction.get_merkle" => match indexer.witness(txid) {
                Some((_, height)) if params[1] == json!(height) => {
                    json!({"block_height": height, "pos": 0, "merkle": []})
                }
                _ => return Err(format!("{txid} is not in block {}", params[1])),
            },
            other => return Err(format!("unexpected indexer request {other}")),
        })
    }

    /// Serves `indexer` as an Electrum server and returns its `tcp://` URL.
    fn serve_electrum(indexer: Indexer) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let indexer = indexer.clone();
                std::thread::spawn(move || {
                    let mut output = stream.try_clone().unwrap();
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { break };
                        let request: Value = serde_json::from_str(&line).unwrap();
                        let method = request["method"].as_str().unwrap_or_default();
                        let response = match electrum_answer(&indexer, method, &request["params"]) {
                            Ok(result) => {
                                json!({"jsonrpc": "2.0", "id": request["id"], "result": result})
                            }
                            Err(message) => json!({"jsonrpc": "2.0", "id": request["id"],
                                "error": {"code": 2, "message": message}}),
                        };
                        if writeln!(output, "{response}").is_err() {
                            break;
                        }
                    }
                });
            }
        });
        format!("tcp://{address}")
    }

    /// An Esplora transaction: the fields the resolver reads, and `status`.
    fn esplora_tx(tx: &Transaction, status: Value) -> Value {
        let inputs: Vec<Value> = tx
            .input
            .iter()
            .map(|input| {
                json!({"txid": input.previous_output.txid.to_string(),
                    "vout": input.previous_output.vout, "prevout": null,
                    "scriptsig": input.script_sig.to_hex_string(), "witness": [],
                    "sequence": input.sequence.0, "is_coinbase": false})
            })
            .collect();
        let outputs: Vec<Value> = tx
            .output
            .iter()
            .map(|output| {
                json!({"value": output.value.to_sat(),
                    "scriptpubkey": output.script_pubkey.to_hex_string()})
            })
            .collect();
        json!({"txid": tx.compute_txid().to_string(), "version": tx.version.0,
            "locktime": tx.lock_time.to_consensus_u32(), "vin": inputs, "vout": outputs,
            "size": 0, "weight": 0, "status": status, "fee": 0})
    }

    /// The hash of the block at a height, or the header of a block hash.
    fn esplora_block(indexer: &Indexer, path: &str) -> Option<String> {
        if let Some(height) = path.strip_prefix("/block-height/") {
            let header = indexer.header(height.parse().ok()?)?;
            return Some(header.block_hash().to_string());
        }
        let hash = path.strip_prefix("/block/")?.strip_suffix("/header")?;
        std::iter::once(0)
            .chain(FIRST_BLOCK..FIRST_BLOCK + indexer.witnesses.len() as u32)
            .filter_map(|height| indexer.header(height))
            .find(|header| header.block_hash().to_string() == hash)
            .map(|header| serialize_hex(&header))
    }

    fn esplora_answer(indexer: &Indexer, path: &str) -> (&'static str, String) {
        if let Some(block) = esplora_block(indexer, path) {
            return ("200 OK", block);
        }
        let genesis = bitcoin::constants::genesis_block(indexer.network).block_hash();
        let witness = path
            .strip_prefix("/tx/")
            .and_then(|txid| indexer.witness(txid));
        match (path, witness) {
            ("/blocks/tip/height", _) => ("200 OK", indexer.read_tip().to_string()),
            (_, Some((tx, height))) => {
                let status = if indexer.mined {
                    json!({"confirmed": true, "block_height": height,
                        "block_hash": genesis.to_string(), "block_time": block_time(height)})
                } else {
                    json!({"confirmed": false})
                };
                ("200 OK", esplora_tx(tx, status).to_string())
            }
            _ => ("404 Not Found", String::new()),
        }
    }

    /// Serves `indexer` as an Esplora server and returns its `http://` URL.
    fn serve_esplora(indexer: Indexer) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let path = request.split_whitespace().nth(1).unwrap_or_default();
                let (status, body) = esplora_answer(&indexer, path);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        format!("http://{address}")
    }

    fn both_indexers() -> [fn(Indexer) -> String; 2] {
        [serve_electrum, serve_esplora]
    }

    /// A mint, then a burn of all of it. With `op_return_only`, the burn
    /// witness has no output but its OP_RETURN commitment.
    fn burn_history(op_return_only: bool) -> History {
        let right = gen::outpoint(0xa0, 0);
        let mut issue = Issue::new(11_155_111, [0x11; 20], vec![right]);
        issue.chain_net = rgbstd::ChainNet::BitcoinSignet;
        let mut history = History::issue(issue);
        let units = history.mint_owned(history.genesis_right(0, right), 1_000, 90);
        let reason = Some(gen::burn_reason_for([0x43; 20]));
        if op_return_only {
            let burn = history.burn_transitions(units, 1_000, Some(1_000), reason);
            history.commit_psbt(burn, vec![units.outpoint], vec![]);
        } else {
            history.burn(units, 1_000, Some(1_000), reason);
        }
        history
    }

    fn validate(history: &History, indexer_url: String) -> Result<ValidatedConsignment> {
        validate_at_depth(history, indexer_url, MIN_CONFIRMATIONS)
    }

    /// `validate_source` with `min_confirmations` as the configured depth.
    fn validate_at_depth(
        history: &History,
        indexer_url: String,
        min_confirmations: u32,
    ) -> Result<ValidatedConsignment> {
        let consignment = history.consignment();
        let source = RgbSource {
            asset_id: history.contract_id.to_string(),
            consignment_hash: Keccak256::digest(&consignment).to_vec(),
            consignment,
            ..Default::default()
        };
        let config = BridgeConfig {
            bitcoin_network: crate::policy::BitcoinNetwork::Signet,
            chain_id: 11_155_111,
            bridge_contract: [0x11; 20],
            rgb_asset_id: source.asset_id.clone(),
            spv_min_confirmations: min_confirmations,
            ..Default::default()
        };
        let validator = RgbValidator::new(indexer_url, "signet")?.with_timeout(5);
        let bind = |bridge: &super::super::BfaBridge, anchors: &[super::super::MintAnchor]| {
            Ok(BoundAnchors {
                evm_chain_id: bridge.chain_id,
                locks: anchors
                    .iter()
                    .map(|a| VerifiedLock {
                        lock_id: a.lock_id,
                        minted: a.amount,
                        operation_id: [0xd0; 32],
                        net_amount: a.amount,
                    })
                    .collect(),
            })
        };
        let chain = crate::bootstrap::build_header_chain(Network::Signet);
        let pins = crate::networks::rgb::spv_crosscheck::ChainPins::new();
        let result = validate_source(
            &source,
            &ValidationContext {
                bridge_config: &config,
                rgb_validator: Some(&validator),
                header_chain: &chain,
                chain_pins: &pins,
                anchor_binder: Some(&bind),
                reject_list_reader: None,
            },
        );
        assert!(chain.lock().unwrap().is_empty());
        assert!(pins.none_pinned().unwrap());
        result
    }

    fn refusal(history: &History, url: String) -> String {
        validate(history, url).unwrap_err().to_string()
    }

    #[test]
    fn passes_a_burn_whose_witnesses_are_deep_enough() {
        for serve in both_indexers() {
            let history = burn_history(false);
            let validated = validate(&history, serve(Indexer::of(&history))).unwrap();
            assert_eq!(validated.witness_txids.len(), 2);
            assert!(validated.non_mined_witness_txids.is_empty());
            assert_eq!(
                validated.last_transition.unwrap().burned_asset_amount,
                Some(1_000)
            );
        }
    }

    /// Swap mint and burn heights so each is tested as the only shallow witness.
    #[test]
    fn refuses_a_witness_one_block_too_shallow() {
        for serve in both_indexers() {
            for swap in [false, true] {
                let history = burn_history(false);
                let mut indexer = Indexer {
                    depth: MIN_CONFIRMATIONS - 1,
                    ..Indexer::of(&history)
                };
                if swap {
                    indexer.witnesses.reverse();
                }
                let shallow = indexer.witnesses[1].compute_txid();
                let err = refusal(&history, serve(indexer));
                assert!(err.contains("1 witness tx(s)"), "{err}");
                assert!(err.contains("(safe height 100)"), "{err}");
                assert!(err.contains(&format!("{shallow} in block 101")), "{err}");
            }
        }
    }

    /// Esplora can report a witness height above its own tip.
    #[test]
    fn refuses_a_witness_above_the_indexer_tip() {
        let history = burn_history(false);
        let burn = history.bundles[1].witness_id();
        let indexer = Indexer {
            depth: 0,
            ..Indexer::of(&history)
        };
        let err = validate_at_depth(&history, serve_esplora(indexer), 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("1 witness tx(s)"), "{err}");
        assert!(err.contains("(safe height 100)"), "{err}");
        assert!(err.contains(&format!("{burn} in block 101")), "{err}");
    }

    /// A zero safe height must reject instead of disabling confirmation checks.
    #[test]
    fn refuses_an_indexer_chain_shorter_than_the_required_depth() {
        for serve in both_indexers() {
            let history = burn_history(false);
            let indexer = Indexer::of(&history);
            let too_deep = indexer.tip() + 1;
            let err = validate_at_depth(&history, serve(indexer), too_deep)
                .unwrap_err()
                .to_string();
            assert!(err.contains("cannot provide a safe height"), "{err}");
        }
    }

    /// Resolver tip updates must not move the confirmation boundary.
    #[test]
    fn a_newer_resolver_tip_does_not_increase_the_accepted_depth() {
        let history = burn_history(false);
        let burn = history.bundles[1].witness_id();
        let indexer = Indexer {
            depth: MIN_CONFIRMATIONS - 1,
            advance: 4,
            ..Indexer::of(&history)
        };
        let tip_reads = Arc::clone(&indexer.tip_reads);
        let err = refusal(&history, serve_electrum(indexer));
        assert!(tip_reads.load(Ordering::SeqCst) > 1);
        assert!(err.contains("(safe height 100)"), "{err}");
        assert!(err.contains(&format!("{burn} in block 101")), "{err}");
    }

    /// A one-block node/index gap is within the upstream search window.
    #[test]
    fn finds_the_block_when_the_node_is_one_block_ahead_of_its_index() {
        let history = burn_history(false);
        let indexer = Indexer {
            ahead: 1,
            ..Indexer::of(&history)
        };
        validate(&history, serve_electrum(indexer)).unwrap();
    }

    /// Larger gaps and impossible confirmation counts must fail lookup.
    #[test]
    fn refuses_a_node_further_ahead_than_the_search_window() {
        let history = burn_history(false);
        for (ahead, reason) in [
            (2, "can't be located"),
            (3, "can't be located"),
            (4, "can't be located"),
            (FIRST_BLOCK + 100, "returned invalid data"),
        ] {
            let indexer = Indexer {
                ahead,
                ..Indexer::of(&history)
            };
            let err = refusal(&history, serve_electrum(indexer));
            assert!(err.contains(reason), "{ahead}: {err}");
        }
    }

    #[test]
    fn refuses_unmined_witnesses() {
        for serve in both_indexers() {
            let history = burn_history(false);
            let first = history.bundles.iter().map(|b| b.witness_id().to_string());
            let first = first.min().unwrap();
            let indexer = Indexer {
                mined: false,
                ..Indexer::of(&history)
            };
            let err = refusal(&history, serve(indexer));
            assert!(err.contains("2 witness tx(s)"), "{err}");
            assert!(err.contains(&format!("{first} unmined")), "{err}");
        }
    }

    #[test]
    fn refuses_a_witness_the_indexer_does_not_know() {
        for serve in both_indexers() {
            let history = burn_history(false);
            let burn = history.bundles[1].witness_id();
            let indexer = Indexer {
                unknown: vec![burn],
                ..Indexer::of(&history)
            };
            let err = refusal(&history, serve(indexer));
            assert!(err.contains(&format!("public witness {burn}")), "{err}");
        }
    }

    #[test]
    fn refuses_an_indexer_of_another_network() {
        for serve in both_indexers() {
            let history = burn_history(false);
            let indexer = Indexer {
                network: bitcoin::Network::Regtest,
                ..Indexer::of(&history)
            };
            let err = refusal(&history, serve(indexer));
            assert!(err.contains("another chain-network pair"), "{err}");
        }
    }

    #[test]
    fn refuses_an_answer_for_another_transaction() {
        for serve in both_indexers() {
            let history = burn_history(false);
            let indexer = Indexer {
                answer_with: Some(history.bundles[0].tx.clone()),
                ..Indexer::of(&history)
            };
            let err = refusal(&history, serve(indexer));
            assert!(err.contains("doesn't match expected id"), "{err}");
        }
    }

    #[test]
    fn refuses_an_electrum_server_without_verbose_transactions() {
        let history = burn_history(false);
        let indexer = Indexer {
            verbose: false,
            ..Indexer::of(&history)
        };
        let err = refusal(&history, serve_electrum(indexer));
        assert!(
            err.contains("verbose transactions are unsupported"),
            "{err}"
        );
    }

    /// A burn with no change and no recipient output: only its txid finds it.
    #[test]
    fn finds_a_witness_whose_only_output_is_its_op_return() {
        for serve in both_indexers() {
            let history = burn_history(true);
            let burn = &history.bundles[1].tx;
            assert_eq!(burn.output.len(), 1);
            assert!(burn.output[0].script_pubkey.is_op_return());
            validate(&history, serve(Indexer::of(&history))).unwrap();
        }
    }

    /// An empty path matches the mock indexer's single-transaction blocks.
    fn carry_proofs(history: &mut History, path: Vec<TxMerkleNode>) {
        for (bundle, height) in history.bundles.iter_mut().zip(FIRST_BLOCK..) {
            bundle.spv_proof = Some(rgbstd::validation::SpvProof {
                block_height: std::num::NonZeroU32::new(height).unwrap(),
                pos: 0,
                merkle: amplify::confinement::Confined::try_from(path.clone()).unwrap(),
            });
        }
    }

    /// A carried proof must not bypass an unknown-witness response.
    #[test]
    fn refuses_a_carried_proof_of_a_witness_the_indexer_does_not_know() {
        for serve in both_indexers() {
            let mut history = burn_history(false);
            carry_proofs(&mut history, vec![]);
            let burn = history.bundles[1].witness_id();
            let indexer = Indexer {
                unknown: vec![burn],
                ..Indexer::of(&history)
            };
            let err = refusal(&history, serve(indexer));
            assert!(err.contains(&format!("public witness {burn}")), "{err}");
        }
    }

    /// Even with a bad carried proof, the indexer's answer decides witness status.
    #[test]
    fn ignores_a_carried_proof_that_does_not_match_the_header() {
        for serve in both_indexers() {
            let mut history = burn_history(false);
            carry_proofs(
                &mut history,
                vec![TxMerkleNode::from_byte_array([0x5a; 32])],
            );
            validate(&history, serve(Indexer::of(&history))).unwrap();
            let unmined = Indexer {
                mined: false,
                ..Indexer::of(&history)
            };
            let err = refusal(&history, serve(unmined));
            assert!(err.contains("2 witness tx(s)"), "{err}");
            assert!(!err.contains("InvalidSpvProof"), "{err}");
        }
    }
}
