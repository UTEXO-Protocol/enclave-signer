//! RGB source validation: all checks on the `RgbSource` payload, from field
//! shape to the SPV cross-check of its witness transactions.

#[cfg(rgb_to_evm)]
use super::asset_bind::{assert_asset_binding, AssetBindMode};
#[cfg(rgb_to_evm)]
use super::reject_list::{assert_not_rejected, RejectCheck};
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

/// Validates all fields and source-chain evidence of an RGB source.
///
/// It does not examine the destination network. The source-chain proof is:
///
/// 1. raw consignment bytes are present, hash-bound, and pass full
///    in-enclave RGB validation. Consensus sees a witness mined only if its
///    Merkle proof verified against the in-enclave header chain at
///    `SPV_MIN_CONFIRMATIONS` depth, so an unmined witness anywhere in the
///    history fails it;
/// 2. the validated asset matches the listener-declared `asset_id` and, if
///    configured, the operator-pinned `RGB_ASSET_ID`;
/// 3. the proofs cover exactly the witness txs, and the blocks they use are
///    pinned until signing;
/// 4. no input of the settling transition descends from an opout the asset's
///    reject list rejects.
///
/// Without `spv`, public-signet builds use the configured indexer for witness
/// confirmation at the same depth instead of the enclave header chain. They
/// trust that indexer's chain view and do not pin SPV blocks.
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
    #[cfg(not(feature = "spv"))]
    let proven = validator.indexer_witnesses(ctx.bridge_config.spv_min_confirmations);
    let witnesses = WitnessCheck {
        chain: &proven,
        allow_unbroadcast_last: false,
        infer_spent_ancestors: false,
    };
    // A burn consignment contains its full mint ancestry. Each mint leaves an
    // anchor that only a bound lock confirms.
    let validated =
        validator.validate_consignment(&source.consignment, ctx.anchor_binder, &witnesses)?;

    assert_asset_binding(
        &validated.contract_id,
        &source.asset_id,
        ctx.bridge_config,
        AssetBindMode::Source,
    )?;

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

    // Last: it reads the EVM RPC, and only after the asset bind.
    assert_not_rejected(
        &validated,
        ctx.reject_list_reader,
        RejectCheck::SettlingInputs,
    )?;

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
/// before the keccak hash and the rgbstd parse. Thus a request under each
/// per-field cap cannot force too much work.
///
/// `label` names the direction in the rejection, for example `"RGB source"`
/// or `"send-RGB"`. Both directions share it, so the message is the same.
pub fn assert_consignment_size(consignment: &[u8], cfg: &BridgeConfig, label: &str) -> Result<()> {
    if consignment.len() > cfg.max_consignment_bytes {
        return Err(EnclaveError::CrossCheck(format!(
            "{label} consignment too large: {} bytes (max {})",
            consignment.len(),
            cfg.max_consignment_bytes
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
    if source.merkle_proofs.len() > cfg.max_merkle_proofs {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source carries too many merkle proofs: {} (max {})",
            source.merkle_proofs.len(),
            cfg.max_merkle_proofs
        )));
    }
    let total_proof_bytes: usize = source
        .merkle_proofs
        .iter()
        .map(|p| p.txid.len() + p.merkle_path.iter().map(|s| s.len()).sum::<usize>())
        .sum();
    if total_proof_bytes > cfg.max_total_proof_bytes {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source merkle proofs too large in aggregate: {total_proof_bytes} bytes (max {})",
            cfg.max_total_proof_bytes
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

#[cfg(all(test, not(feature = "spv"), feature = "burn-signer"))]
mod indexer_only_source {
    use super::*;
    use crate::networks::rgb::spv::Network;
    use crate::networks::rgb::validation::{BoundAnchors, RgbValidator, VerifiedLock};
    use crate::test_support::bfa_consignment::{self as gen, History, Issue};
    use bitcoin::hashes::Hash;
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Write};

    /// Indexer answers can be well-formed without an independently verified
    /// chain. That is the indexer trust assumption this test exercises.
    fn indexer(history: &History, depth: u32, mined: bool, correct_network: bool) -> String {
        let txids: Vec<_> = history.bundles.iter().map(|b| b.witness_id()).collect();
        let headers: Vec<_> = txids
            .iter()
            .enumerate()
            .map(|(i, id)| bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array(id.to_byte_array()),
                time: gen::ISSUED_AT as u32 + 100 + i as u32,
                bits: bitcoin::CompactTarget::from_consensus(0x1e03_77ae),
                nonce: 0,
            })
            .collect();
        let tip = 100 + txids.len() as u32 - 1 + depth - 1;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let txids = txids.clone();
                let headers = headers.clone();
                std::thread::spawn(move || {
                    let mut output = stream.try_clone().unwrap();
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { break };
                        let request: Value = serde_json::from_str(&line).unwrap();
                        let params = &request["params"];
                        let header_hex = bitcoin::consensus::encode::serialize_hex;
                        let result = match request["method"].as_str().unwrap() {
                            "server.version" => json!(["test-indexer", "1.4"]),
                            "blockchain.headers.subscribe" => {
                                json!({"height": tip, "hex": header_hex(headers.last().unwrap())})
                            }
                            "blockchain.block.header" => {
                                let height = params[0].as_u64().unwrap() as usize;
                                if height == 0 {
                                    let network = if correct_network {
                                        bitcoin::Network::Signet
                                    } else {
                                        bitcoin::Network::Regtest
                                    };
                                    json!(header_hex(
                                        &bitcoin::constants::genesis_block(network).header
                                    ))
                                } else {
                                    json!(header_hex(&headers[height - 100]))
                                }
                            }
                            "blockchain.scripthash.get_history" => json!(txids
                                .iter()
                                .enumerate()
                                .map(|(i, id)| json!({
                                    "height": if mined { 100 + i } else { 0 },
                                    "tx_hash": id.to_string()
                                }))
                                .collect::<Vec<_>>()),
                            "blockchain.transaction.get_merkle" => json!({
                                "block_height": params[1], "pos": 0, "merkle": []
                            }),
                            method => panic!("unexpected indexer request: {method}"),
                        };
                        let response =
                            json!({"jsonrpc": "2.0", "id": request["id"], "result": result});
                        if writeln!(output, "{response}").is_err() {
                            break;
                        }
                    }
                });
            }
        });
        format!("tcp://{address}")
    }

    fn validate(depth: u32, mined: bool, correct_network: bool) -> Result<ValidatedConsignment> {
        let right = gen::outpoint(0xa0, 0);
        let mut issue = Issue::new(11_155_111, [0x11; 20], vec![right]);
        issue.chain_net = rgbstd::ChainNet::BitcoinSignet;
        let mut history = History::issue(issue);
        let units = history.mint_owned(history.genesis_right(0, right), 1_000, 90);
        history.burn(
            units,
            1_000,
            Some(1_000),
            Some(gen::burn_reason_for([0x43; 20])),
        );
        let consignment = history.consignment(vec![]);
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
            spv_min_confirmations: 6,
            ..Default::default()
        };
        let validator =
            RgbValidator::new(indexer(&history, depth, mined, correct_network), "signet")?;
        let bind = |bridge: &super::super::BfaBridge, anchors: &[super::super::MintAnchor]| {
            Ok(BoundAnchors {
                evm_chain_id: bridge.chain_id,
                locks: anchors
                    .iter()
                    .map(|a| VerifiedLock {
                        mint_opid: a.opid,
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
        assert!(pins.is_empty());
        result
    }

    #[test]
    fn validates_real_consensus_using_indexer_confirmations_without_spv() {
        let validated = validate(6, true, true).unwrap();
        assert_eq!(validated.witness_txids.len(), 2);
        assert!(validated.non_mined_witness_txids.is_empty());
        assert_eq!(
            validated.last_transition.unwrap().burned_asset_amount,
            Some(1_000)
        );
    }

    #[test]
    fn refuses_unmined_shallow_and_wrong_network_indexer_answers() {
        for (depth, mined, network, reason) in [
            (6, false, true, "unmined"),
            (5, true, true, "confirmation(s)"),
            (6, true, false, "does not serve"),
        ] {
            let error = validate(depth, mined, network).unwrap_err().to_string();
            assert!(error.contains(reason), "{error}");
        }
    }
}
