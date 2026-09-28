//! Probes that assert what a signer must NOT do. Each test states the
//! property an attacker would want violated; a failure here is a finding,
//! not a broken test.

// Feature-gated probes leave helpers unused in some lanes.
#![allow(dead_code, unused_imports)]

mod common;

use std::net::TcpStream;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::proto::enclave_request::Request as Req;
use utexo_bridge_enclave::proto::enclave_response::Response as Resp;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::*;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon about";

fn send(port: u16, req: Req) -> EnclaveResponse {
    common::send_request(port, &EnclaveRequest { request: Some(req) })
}

fn expect_error(resp: EnclaveResponse) -> ErrorResponse {
    match resp.response {
        Some(Resp::Error(e)) => e,
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// Keccak-256 of an uncompressed secp256k1 point's X||Y, last 20 bytes.
fn address_of(uncompressed_65: &[u8]) -> [u8; 20] {
    use sha3::{Digest, Keccak256};
    let h = Keccak256::digest(&uncompressed_65[1..]);
    h[12..].try_into().unwrap()
}

/// Recover the signer of `digest` from a 65-byte r||s||v signature under the
/// Ethereum convention (v is 27 or 28) and return its address, or the reason
/// it could not be recovered.
fn recover_address(digest: &[u8; 32], sig: &[u8]) -> Result<[u8; 20], String> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    if sig.len() != 65 {
        return Err(format!("signature is {} bytes, expected 65", sig.len()));
    }
    let v = sig[64];
    // The enclave's wire format carries the raw recovery id (0 or 1), as
    // `keys.rs` pins in its own tests; an `ecrecover` caller adds 27. Note
    // `KeyManager::sign_evm` documents "Ethereum ecrecover convention", which
    // reads as 27/28 - one of the two should change.
    if v > 1 {
        return Err(format!("v = {v}, expected the raw recovery id 0 or 1"));
    }
    let signature = Signature::from_slice(&sig[..64]).map_err(|e| e.to_string())?;
    if signature.normalize_s().is_some() {
        return Err("signature is not low-S normalized (EIP-2 malleable)".into());
    }
    let rid = RecoveryId::from_byte(v).ok_or("bad recovery id")?;
    let key = VerifyingKey::recover_from_prehash(digest, &signature, rid)
        .map_err(|e| format!("recover: {e}"))?;
    Ok(address_of(key.to_encoded_point(false).as_bytes()))
}

fn pinned() -> BridgeConfig {
    BridgeConfig {
        chain_id: 1,
        bridge_contract: [0xAA; 20],
        rgb_asset_id: "rgb:test".into(),
        ..Default::default()
    }
}

// ---- key material and signature encoding ------------------------------------

/// The EVM signature must recover, under the documented ecrecover convention,
/// to the address the enclave itself reports. A wrong `v`, a high-S signature
/// or a digest mismatch would leave every release unrecoverable on-chain.
#[cfg(all(
    feature = "ccd",
    feature = "rgb-validation",
    feature = "allow-seed-import"
))]
#[test]
fn evm_release_signature_recovers_to_the_reported_evm_address() {
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::SolCall;
    use utexo_bridge_enclave::networks::evm::signing::{build_evm_domain, funds_out_digest};
    use utexo_bridge_enclave::networks::evm::validation::{
        decode_funds_out_params, fundsOutCall, FundsOutParams,
    };

    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        pinned(),
    );
    let keys = match send(port, Req::GetPublicKey(GetPublicKeyRequest {})).response {
        Some(Resp::PublicKeys(k)) => k,
        other => panic!("{other:?}"),
    };
    let call_data = fundsOutCall {
        params: FundsOutParams {
            recipient: Address::from([0x11; 20]),
            amount: U256::from(5u64),
            burnId: U256::from(7u64),
            sourceChainId: U256::from(919u64),
            destinationChainId: U256::from(1u64),
            sourceAddress: "ccd".into(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
        },
    }
    .abi_encode();
    let destination = EvmDestination {
        call_data: call_data.clone(),
        nonce: 9,
        deadline: u64::MAX,
        chain_id: 1,
        proxy_contract: vec![0xAA; 20],
        calldata_amount: 5,
        calldata_commission: 0,
        lz_release: None,
    };
    let sig = match send(
        port,
        Req::Sign(SignRequest {
            amount: 5,
            source_network: Some(SourceNetwork::CcdSource(CcdSource {
                tx_hash: vec![0xCC; 32],
                commission: 0,
            })),
            destination_network: Some(DestinationNetwork::EvmDestination(destination.clone())),
        }),
    )
    .response
    {
        Some(Resp::EvmSignature(r)) => r.signature,
        other => panic!("{other:?}"),
    };

    let domain = build_evm_domain(&destination).unwrap();
    let params = decode_funds_out_params(&call_data).unwrap();
    let digest = funds_out_digest(&domain, &params, 9, u64::MAX).unwrap();
    let recovered = recover_address(&digest, &sig).unwrap();
    assert_eq!(recovered.to_vec(), keys.evm_address);
    assert_eq!(
        address_of(&[&[4u8][..], &keys.evm_uncompressed_pub].concat()).to_vec(),
        keys.evm_address,
        "reported uncompressed key and address disagree"
    );
}

/// Same property for the gas-tx key: the raw-digest signature must recover
/// to the reported gas address over keccak(0x02 || preimage).
#[cfg(all(not(feature = "dev-mode"), feature = "allow-seed-import"))]
#[test]
fn gas_tx_signature_recovers_to_the_reported_gas_address() {
    use sha3::{Digest, Keccak256};

    fn rlp_str(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            return vec![bytes[0]];
        }
        let mut out = vec![0x80 + bytes.len() as u8];
        out.extend_from_slice(bytes);
        out
    }
    fn rlp_scalar(v: u64) -> Vec<u8> {
        let be = v.to_be_bytes();
        let trimmed: Vec<u8> = be.iter().copied().skip_while(|&b| b == 0).collect();
        rlp_str(&trimmed)
    }
    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        let mut out = vec![0xc0 + payload.len() as u8];
        out.extend_from_slice(&payload);
        out
    }

    let to = [0x5A; 20];
    let selector = [0xde, 0xad, 0xbe, 0xef];
    let cfg = BridgeConfig {
        gas_tx_allowed_to: Some(to),
        gas_tx_max_gas_limit: 100_000,
        gas_tx_max_fee_per_gas: 1_000_000_000,
        gas_tx_allowed_selectors: vec![selector],
        ..pinned()
    };
    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        cfg,
    );
    let keys = match send(port, Req::GetPublicKey(GetPublicKeyRequest {})).response {
        Some(Resp::PublicKeys(k)) => k,
        other => panic!("{other:?}"),
    };
    let body = rlp_list(&[
        rlp_scalar(1),
        rlp_scalar(3),
        rlp_scalar(1_000),
        rlp_scalar(1_000_000),
        rlp_scalar(50_000),
        rlp_str(&to),
        rlp_scalar(0),
        rlp_str(&selector),
        rlp_list(&[]),
    ]);
    let mut preimage = vec![0x02];
    preimage.extend_from_slice(&body);
    let digest: [u8; 32] = Keccak256::digest(&preimage).into();

    let sig = match send(
        port,
        Req::SignRawDigest(SignRawDigestRequest {
            digest: vec![],
            unsigned_tx: preimage.clone(),
        }),
    )
    .response
    {
        Some(Resp::RawDigestSig(r)) => r.signature,
        other => panic!("{other:?}"),
    };
    let recovered = recover_address(&digest, &sig).unwrap();
    assert_eq!(recovered.to_vec(), keys.evm_gas_tx_address);
    assert_ne!(
        keys.evm_gas_tx_address, keys.evm_address,
        "the gas key must not be the bridge key"
    );
}

// ---- request ambiguity --------------------------------------------------------

/// A request carrying both a seed and a mnemonic is ambiguous. Silently
/// preferring one lets an operator believe a different key was installed.
#[cfg(feature = "allow-seed-import")]
#[test]
fn initialize_with_both_seed_and_mnemonic_is_refused() {
    let port = common::start_test_server();
    let resp = send(
        port,
        Req::InitializeKey(InitializeKeyRequest {
            seed: vec![0x5c; 64],
            mnemonic: MNEMONIC.into(),
            cloning_secret: String::new(),
        }),
    );
    let err = expect_error(resp);
    assert!(
        err.message.contains("both a seed and a mnemonic"),
        "{}",
        err.message
    );
}

// ---- replay ----------------------------------------------------------------------

/// A Concordium deposit must not be releasable twice by the same enclave.
/// The proxy's burnId is the durable guard; the enclave's soft guard must
/// cover this route too.
#[cfg(all(
    feature = "ccd",
    feature = "rgb-validation",
    feature = "allow-seed-import"
))]
#[test]
fn ccd_release_is_not_signed_twice_by_the_enclave() {
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::SolCall;
    use utexo_bridge_enclave::networks::evm::validation::{fundsOutCall, FundsOutParams};

    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        pinned(),
    );
    let call_data = fundsOutCall {
        params: FundsOutParams {
            recipient: Address::from([0x11; 20]),
            amount: U256::from(5u64),
            burnId: U256::from(7u64),
            sourceChainId: U256::from(919u64),
            destinationChainId: U256::from(1u64),
            sourceAddress: "ccd".into(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
        },
    }
    .abi_encode();
    let req = || {
        Req::Sign(SignRequest {
            amount: 5,
            source_network: Some(SourceNetwork::CcdSource(CcdSource {
                tx_hash: vec![0xCC; 32],
                commission: 0,
            })),
            destination_network: Some(DestinationNetwork::EvmDestination(EvmDestination {
                call_data: call_data.clone(),
                nonce: 9,
                deadline: u64::MAX,
                chain_id: 1,
                proxy_contract: vec![0xAA; 20],
                calldata_amount: 5,
                calldata_commission: 0,
                lz_release: None,
            })),
        })
    };
    assert!(matches!(
        send(port, req()).response,
        Some(Resp::EvmSignature(_))
    ));
    let err = expect_error(send(port, req()));
    assert!(
        err.message.contains("duplicate bridge operation"),
        "{}",
        err.message
    );
    assert!(err.message.contains("ccd_tx_hash"), "{}", err.message);
}

// ---- plain-BTC sighash ------------------------------------------------------------

/// A PSBT that asks for SIGHASH_NONE or SINGLE on the enclave's input is
/// refused rather than signed with a different sighash than requested.
#[cfg(feature = "allow-seed-import")]
#[test]
fn plain_btc_refuses_a_non_default_sighash_request() {
    use bitcoin::psbt::PsbtSighashType;
    use bitcoin::sighash::TapSighashType;
    use common::taproot_fixture as fx;
    use utexo_bridge_enclave::keys::{AccountType, KeyManager};

    let km = KeyManager::from_mnemonic(MNEMONIC, bitcoin::Network::Bitcoin).unwrap();
    let cfg = BridgeConfig {
        btc_max_total_sats: 1_000_000,
        ..Default::default()
    };
    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        cfg,
    );
    for ty in [TapSighashType::None, TapSighashType::Single] {
        let mut psbt = fx::psbt_with_our_input(&km, AccountType::Vanilla, true);
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(ty));
        let resp = send(
            port,
            Req::SignBtc(SignBtcRequest {
                psbt_bytes: psbt.serialize(),
            }),
        );
        let err = expect_error(resp);
        assert!(err.message.contains("non-ALL sighash"), "{}", err.message);
    }
}

// ---- header chain ----------------------------------------------------------------------

fn regtest_headers(count: u32) -> Vec<Vec<u8>> {
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, Network};
    let mut prev = bitcoin::BlockHash::from_byte_array(checkpoint_for(Network::Regtest).hash);
    let mut out = Vec::new();
    for h in 1..=count {
        let header = Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([h as u8; 32]),
            time: 1_700_000_000 + h,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        prev = header.block_hash();
        out.push(serialize(&header));
    }
    out
}

fn tip(port: u16) -> u32 {
    match send(port, Req::GetLastSavedBlock(GetLastSavedBlockRequest {})).response {
        Some(Resp::GetLastSavedBlock(r)) => r.block_height,
        other => panic!("{other:?}"),
    }
}

/// A batch whose later header does not link must be rejected as a whole;
/// a partially applied batch would leave the chain at a height the
/// listener never acknowledged.
#[cfg(feature = "spv")]
#[test]
fn a_header_batch_is_applied_atomically() {
    let port = common::start_test_server();
    let mut headers = regtest_headers(3);
    headers[2][4] ^= 0xFF; // break the third header's prev_blockhash
    let err = expect_error(send(
        port,
        Req::SubmitHeaders(SubmitHeadersRequest {
            headers,
            start_height: 1,
        }),
    ));
    assert!(!err.message.is_empty());
    assert_eq!(tip(port), 0, "nothing from the broken batch may be kept");

    let resp = send(
        port,
        Req::SubmitHeaders(SubmitHeadersRequest {
            headers: regtest_headers(3),
            start_height: 1,
        }),
    );
    assert!(
        matches!(resp.response, Some(Resp::SubmitHeaders(_))),
        "{resp:?}"
    );
    assert_eq!(tip(port), 3);
}

/// Two listeners racing the same batch must leave one consistent chain.
#[cfg(feature = "spv")]
#[test]
fn concurrent_header_submissions_keep_one_consistent_chain() {
    let port = common::start_test_server();
    let headers = regtest_headers(3);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let headers = headers.clone();
            std::thread::spawn(move || {
                send(
                    port,
                    Req::SubmitHeaders(SubmitHeadersRequest {
                        headers,
                        start_height: 1,
                    }),
                )
            })
        })
        .collect();
    let mut accepted = 0;
    for h in handles {
        if let Some(Resp::SubmitHeaders(r)) = h.join().unwrap().response {
            accepted += r.headers_accepted;
        }
    }
    assert!(accepted >= 3, "at least one submission must land");
    assert_eq!(tip(port), 3);
}

// ---- connection discipline -------------------------------------------------------------

/// One request per connection: a second frame on the same socket must not
/// be answered, so a client cannot pipeline past the per-connection deadline.
#[test]
fn a_second_frame_on_one_connection_is_not_answered() {
    let port = common::start_test_server();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let req = EnclaveRequest {
        request: Some(Req::GetPublicKey(GetPublicKeyRequest {})),
    };
    framing::write_message(&mut stream, &req).unwrap();
    let _first: EnclaveResponse = framing::read_message(&mut stream).unwrap();
    // The second frame may fail to write (peer closed) or be ignored.
    let _ = framing::write_message(&mut stream, &req);
    let second: Result<EnclaveResponse, _> = framing::read_message(&mut stream);
    assert!(second.is_err(), "a pipelined second request was answered");
}

// ---- SPV trust on non-mainnet networks --------------------------------------------

/// Headers must cost something to produce. On signet the enclave verifies
/// neither proof of work nor the BIP-325 block signature, so a host can
/// extend the enclave's signet chain with unmined headers for free - and
/// signet is the network the production checkpoint pins.
#[cfg(feature = "spv")]
#[test]
#[ignore = "FINDING: signet headers are accepted with zero work and no BIP-325 signature"]
fn signet_headers_without_work_are_refused() {
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};

    let cp = checkpoint_for(Network::Signet);
    let mut chain = HeaderChain::new(Network::Signet, cp);
    let header = Header {
        version: Version::ONE,
        prev_blockhash: bitcoin::BlockHash::from_byte_array(cp.hash),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x42; 32]),
        time: cp.time + 600,
        bits: bitcoin::CompactTarget::from_consensus(cp.bits),
        nonce: 0, // no attempt at meeting the target
    };
    let hash = header.block_hash();
    let target = bitcoin::Target::from_compact(header.bits);
    assert!(
        !target.is_met_by(hash),
        "fixture must not accidentally satisfy the signet target"
    );
    assert!(
        chain
            .submit_headers(cp.height + 1, &[serialize(&header)])
            .is_err(),
        "an unmined signet header was accepted at height {}",
        cp.height + 1
    );
}

// ---- plain-BTC fee burn ----------------------------------------------------------------

/// A plain-BTC PSBT that pays almost everything to miners must be refused:
/// the spend cap bounds the inputs, but nothing bounds the fee itself, so a
/// host can burn the whole cap on every signing.
#[cfg(feature = "allow-seed-import")]
#[test]
#[ignore = "FINDING: no fee bound on the plain-BTC path; the whole spend cap can go to miners"]
fn plain_btc_refuses_a_psbt_that_burns_the_inputs_as_fee() {
    use common::taproot_fixture as fx;
    use utexo_bridge_enclave::keys::{AccountType, KeyManager};

    let km = KeyManager::from_mnemonic(MNEMONIC, bitcoin::Network::Bitcoin).unwrap();
    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        BridgeConfig {
            btc_max_total_sats: 1_000_000,
            ..Default::default()
        },
    );
    let mut psbt = fx::psbt_with_our_input(&km, AccountType::Vanilla, true);
    // 100_000 sats in, 1 sat out, back to ourselves: 99_999 sats to miners.
    psbt.unsigned_tx.output[0].value = bitcoin::Amount::from_sat(1);
    let resp = send(
        port,
        Req::SignBtc(SignBtcRequest {
            psbt_bytes: psbt.serialize(),
        }),
    );
    expect_error(resp);
}

// ---- state machine ---------------------------------------------------------------------

/// While a clone is in flight the enclave holds no committed keys; every
/// signing entry point must refuse rather than sign with a half-installed
/// identity.
#[cfg(feature = "allow-seed-import")]
#[test]
fn nothing_signs_while_a_clone_is_in_flight() {
    use common::taproot_fixture as fx;
    use utexo_bridge_enclave::keys::{AccountType, KeyManager};

    let port = common::start_test_server_with_config(
        |_| {},
        BridgeConfig {
            btc_max_total_sats: 1_000_000,
            ..Default::default()
        },
    );
    match send(
        port,
        Req::InitiateCloning(InitiateCloningRequest {
            cloning_secret: "s".into(),
            cluster_public_key: vec![0x11; 20],
        }),
    )
    .response
    {
        Some(Resp::InitiateCloning(_)) => {}
        other => panic!("{other:?}"),
    }

    let km = KeyManager::from_mnemonic(MNEMONIC, bitcoin::Network::Bitcoin).unwrap();
    let psbt = fx::psbt_with_our_input(&km, AccountType::Vanilla, true);
    expect_error(send(
        port,
        Req::SignBtc(SignBtcRequest {
            psbt_bytes: psbt.serialize(),
        }),
    ));
    expect_error(send(
        port,
        Req::SignRawDigest(SignRawDigestRequest {
            digest: vec![],
            unsigned_tx: vec![0x02, 0xc0],
        }),
    ));
    expect_error(send(
        port,
        Req::SignCcd(SignCcdRequest {
            hash: vec![0xAB; 32],
        }),
    ));
    expect_error(send(port, Req::GetPublicKey(GetPublicKeyRequest {})));
    expect_error(send(
        port,
        Req::GetAttestedPublicKey(GetAttestedPublicKeyRequest {
            nonce: vec![0x37; 32],
        }),
    ));
    // And a second identity cannot be installed over the pending clone.
    expect_error(send(
        port,
        Req::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: MNEMONIC.into(),
            cloning_secret: String::new(),
        }),
    ));
}

// ---- races -----------------------------------------------------------------------------

/// Concurrent initialisations must install exactly one identity, and the
/// key every later reader sees must be the one whose request succeeded.
#[test]
fn concurrent_initializations_install_exactly_one_identity() {
    let port = common::start_test_server();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                send(
                    port,
                    Req::InitializeKey(InitializeKeyRequest {
                        seed: vec![],
                        mnemonic: String::new(),
                        cloning_secret: String::new(),
                    }),
                )
            })
        })
        .collect();
    let mut winners = Vec::new();
    for h in handles {
        if let Some(Resp::InitializeKey(r)) = h.join().unwrap().response {
            winners.push(r.evm_address);
        }
    }
    assert_eq!(winners.len(), 1, "exactly one InitializeKey may succeed");
    match send(port, Req::GetPublicKey(GetPublicKeyRequest {})).response {
        Some(Resp::PublicKeys(k)) => assert_eq!(k.evm_address, winners[0]),
        other => panic!("{other:?}"),
    }
}

/// The CCD replay guard reserves the key before signing, so concurrent
/// duplicates race for one slot and exactly one release is signed.
#[cfg(all(
    feature = "ccd",
    feature = "rgb-validation",
    feature = "allow-seed-import"
))]
#[test]
fn concurrent_duplicate_ccd_releases_yield_one_signature() {
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::SolCall;
    use utexo_bridge_enclave::networks::evm::validation::{fundsOutCall, FundsOutParams};

    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        pinned(),
    );
    let call_data = fundsOutCall {
        params: FundsOutParams {
            recipient: Address::from([0x11; 20]),
            amount: U256::from(5u64),
            burnId: U256::from(7u64),
            sourceChainId: U256::from(919u64),
            destinationChainId: U256::from(1u64),
            sourceAddress: "ccd".into(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
        },
    }
    .abi_encode();
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let call_data = call_data.clone();
            std::thread::spawn(move || {
                send(
                    port,
                    Req::Sign(SignRequest {
                        amount: 5,
                        source_network: Some(SourceNetwork::CcdSource(CcdSource {
                            tx_hash: vec![0xCC; 32],
                            commission: 0,
                        })),
                        destination_network: Some(DestinationNetwork::EvmDestination(
                            EvmDestination {
                                call_data,
                                nonce: i, // a fresh nonce each time: still one deposit
                                deadline: u64::MAX,
                                chain_id: 1,
                                proxy_contract: vec![0xAA; 20],
                                calldata_amount: 5,
                                calldata_commission: 0,
                                lz_release: None,
                            },
                        )),
                    }),
                )
            })
        })
        .collect();
    let signed = handles
        .into_iter()
        .map(|h| h.join().unwrap().response)
        .filter(|r| matches!(r, Some(Resp::EvmSignature(_))))
        .count();
    assert_eq!(signed, 1, "one deposit, one release");
}

/// An equal-length competing chain must not displace the one already
/// accepted: Bitcoin keeps the first-seen tip, and letting a host flip
/// between forks of equal work would let it toggle confirmations.
#[cfg(feature = "spv")]
#[test]
fn an_equal_length_fork_does_not_replace_the_tip() {
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, Network};

    let port = common::start_test_server();
    let main = regtest_headers(3);
    let resp = send(
        port,
        Req::SubmitHeaders(SubmitHeadersRequest {
            headers: main.clone(),
            start_height: 1,
        }),
    );
    let main_tip = match resp.response {
        Some(Resp::SubmitHeaders(r)) => r.last_block_hash,
        other => panic!("{other:?}"),
    };

    // A fork from height 2 with different contents and the same length.
    let cp = checkpoint_for(Network::Regtest);
    let mut prev = bitcoin::BlockHash::from_byte_array(cp.hash);
    let mut fork = Vec::new();
    for h in 1..=3u32 {
        let header = Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xF0 + h as u8; 32]),
            time: 1_700_000_000 + h,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 1,
        };
        prev = header.block_hash();
        fork.push(serialize(&header));
    }
    let _ = send(
        port,
        Req::SubmitHeaders(SubmitHeadersRequest {
            headers: fork[1..].to_vec(),
            start_height: 2,
        }),
    );
    let now = match send(port, Req::GetLastSavedBlock(GetLastSavedBlockRequest {})).response {
        Some(Resp::GetLastSavedBlock(r)) => r,
        other => panic!("{other:?}"),
    };
    assert_eq!(now.block_height, 3);
    assert_eq!(
        now.block_hash, main_tip,
        "an equal-length fork replaced the first-seen tip"
    );
}

// ---- CCD deposits are taken on the listener's word ----------------------------------

/// A release must be backed by evidence of the deposit it settles. For a
/// Concordium source the enclave holds none: any claimed tx hash and any
/// amount is signed. A compromised host can therefore mint releases at will
/// on this route; the EVM->RGB route verifies its deposit on-chain.
#[cfg(all(
    feature = "ccd",
    feature = "rgb-validation",
    feature = "allow-seed-import"
))]
#[test]
#[ignore = "FINDING: CCD->EVM releases carry no deposit evidence; any tx hash and amount is signed"]
fn ccd_release_requires_evidence_of_the_deposit() {
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::SolCall;
    use utexo_bridge_enclave::networks::evm::validation::{fundsOutCall, FundsOutParams};

    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        pinned(),
    );
    let amount = 1_000_000_000_000_000_000u64;
    let call_data = fundsOutCall {
        params: FundsOutParams {
            recipient: Address::from([0x66; 20]),
            amount: U256::from(amount),
            burnId: U256::from(1u64),
            sourceChainId: U256::from(919u64),
            destinationChainId: U256::from(1u64),
            sourceAddress: "nobody".into(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
        },
    }
    .abi_encode();
    let resp = send(
        port,
        Req::Sign(SignRequest {
            amount,
            source_network: Some(SourceNetwork::CcdSource(CcdSource {
                tx_hash: vec![0xDE; 32], // no such deposit exists anywhere
                commission: 0,
            })),
            destination_network: Some(DestinationNetwork::EvmDestination(EvmDestination {
                call_data,
                nonce: 1,
                deadline: u64::MAX,
                chain_id: 1,
                proxy_contract: vec![0xAA; 20],
                calldata_amount: amount,
                calldata_commission: 0,
                lz_release: None,
            })),
        }),
    );
    expect_error(resp);
}

/// The replay guard evicts its oldest entry when full. A flood of distinct
/// operations therefore re-opens the first one within the TTL - and on a
/// route where the host can invent operations for free that flood is cheap.
#[test]
#[ignore = "FINDING: the replay guard evicts on overflow, so a flood re-enables an old operation's replay"]
fn a_flood_of_operations_does_not_reopen_an_old_one() {
    use std::time::Duration;
    use utexo_bridge_enclave::state::NonceReplayGuard;

    let guard = NonceReplayGuard::with_capacity(3, Duration::from_secs(3600));
    guard.reserve([1; 32]).unwrap().commit();
    for k in 2..=4u8 {
        guard.reserve([k; 32]).unwrap().commit();
    }
    assert!(
        guard.reserve([1; 32]).is_err(),
        "the first operation became signable again after three others"
    );
}

// ---- EVM destination pins ---------------------------------------------------------------

/// The chain id inside the calldata must agree with the pinned chain, not
/// just the request's `chain_id` field.
#[cfg(all(
    feature = "ccd",
    feature = "rgb-validation",
    feature = "allow-seed-import"
))]
#[test]
fn calldata_destination_chain_id_must_match_the_pinned_chain() {
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::SolCall;
    use utexo_bridge_enclave::networks::evm::validation::{fundsOutCall, FundsOutParams};

    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        pinned(),
    );
    let call_data = fundsOutCall {
        params: FundsOutParams {
            recipient: Address::from([0x11; 20]),
            amount: U256::from(5u64),
            burnId: U256::from(7u64),
            sourceChainId: U256::from(919u64),
            destinationChainId: U256::from(2u64), // pinned chain is 1
            sourceAddress: "ccd".into(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
        },
    }
    .abi_encode();
    let resp = send(
        port,
        Req::Sign(SignRequest {
            amount: 5,
            source_network: Some(SourceNetwork::CcdSource(CcdSource {
                tx_hash: vec![0xCC; 32],
                commission: 0,
            })),
            destination_network: Some(DestinationNetwork::EvmDestination(EvmDestination {
                call_data,
                nonce: 1,
                deadline: u64::MAX,
                chain_id: 1,
                proxy_contract: vec![0xAA; 20],
                calldata_amount: 5,
                calldata_commission: 0,
                lz_release: None,
            })),
        }),
    );
    expect_error(resp);
}

// ---- cloning inputs ------------------------------------------------------------------------

/// A cluster key that is not an EVM address cannot open a cloning session,
/// and a refused attempt leaves the enclave initialisable.
#[test]
fn initiate_cloning_rejects_a_cluster_key_that_is_not_20_bytes() {
    let port = common::start_test_server();
    for len in [0usize, 19, 21, 32] {
        expect_error(send(
            port,
            Req::InitiateCloning(InitiateCloningRequest {
                cloning_secret: "s".into(),
                cluster_public_key: vec![0x11; len],
            }),
        ));
    }
    assert!(matches!(
        send(
            port,
            Req::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: String::new(),
                cloning_secret: String::new(),
            }),
        )
        .response,
        Some(Resp::InitializeKey(_))
    ));
}

/// A donor running different code (other PCRs) must not be able to hand the
/// requester a seed, even one that decrypts and derives the right address.
#[cfg(feature = "mock-attestation")]
#[test]
fn set_clone_rejects_a_donor_attestation_with_foreign_pcrs() {
    use utexo_bridge_enclave::cloning;
    use utexo_bridge_enclave::keys::KeyManager;

    let seed = [0x5c; 64];
    let cluster = KeyManager::from_seed(seed, bitcoin::Network::Bitcoin)
        .unwrap()
        .evm_address()
        .to_vec();
    let port = common::start_test_server();
    let requester_pk: [u8; 32] = match send(
        port,
        Req::InitiateCloning(InitiateCloningRequest {
            cloning_secret: "s".into(),
            cluster_public_key: cluster,
        }),
    )
    .response
    {
        Some(Resp::InitiateCloning(r)) => r.encryption_pubkey.try_into().unwrap(),
        other => panic!("{other:?}"),
    };
    let (ciphertext, donor_pub) = cloning::encrypt_seed_for_peer(&requester_pk, &seed).unwrap();
    let foreign = attestation_verify::ExpectedPcrs::new([0xAA; 48], [0u8; 48], [0u8; 48]);
    let doc = attestation_verify::build_mock_document_with_pcrs(
        &[0x99; 32],
        Some(&donor_pub),
        None,
        &foreign,
    )
    .unwrap();
    expect_error(send(
        port,
        Req::SetClone(SetCloneRequest {
            encrypted_seed: ciphertext,
            donor_pubkey: donor_pub.to_vec(),
            donor_attestation: doc,
        }),
    ));
    // Still no identity.
    expect_error(send(port, Req::GetPublicKey(GetPublicKeyRequest {})));
}

// ---- attestation nonce ------------------------------------------------------------------

/// The attestation nonce is the verifier's freshness proof; a short one
/// weakens it and must be refused rather than padded or truncated.
#[cfg(feature = "mock-attestation")]
#[test]
fn attested_public_key_rejects_a_nonce_that_is_not_32_bytes() {
    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        BridgeConfig::default(),
    );
    for len in [0usize, 16, 31, 33] {
        expect_error(send(
            port,
            Req::GetAttestedPublicKey(GetAttestedPublicKeyRequest {
                nonce: vec![0x37; len],
            }),
        ));
    }
}

// ---- request shape -----------------------------------------------------------------------

/// Concordium deposits are never released as RGB; the pair is refused as a
/// route, before any key is touched.
#[cfg(feature = "ccd")]
#[test]
fn ccd_source_to_rgb_destination_is_refused() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::Sign(SignRequest {
            amount: 1,
            source_network: Some(SourceNetwork::CcdSource(CcdSource {
                tx_hash: vec![0xCC; 32],
                commission: 0,
            })),
            destination_network: Some(
                DestinationNetwork::RgbDestination(RgbDestination::default()),
            ),
        }),
    ));
    assert!(!err.message.is_empty());
}

// ---- gas-tx signing volume ------------------------------------------------------------

/// The gas key pays real gas. Signing the same nonce twice is never useful
/// to the bridge, only to a host that wants a spare, differently-priced
/// transaction; nothing in the enclave dedups or rate-limits gas signing.
#[cfg(all(not(feature = "dev-mode"), feature = "allow-seed-import"))]
#[test]
#[ignore = "FINDING: gas-tx signing has no per-nonce dedup or rate limit; any number of signatures for one nonce"]
fn gas_tx_does_not_sign_the_same_nonce_twice() {
    fn rlp_str(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            return vec![bytes[0]];
        }
        let mut out = vec![0x80 + bytes.len() as u8];
        out.extend_from_slice(bytes);
        out
    }
    fn rlp_scalar(v: u64) -> Vec<u8> {
        let be = v.to_be_bytes();
        let trimmed: Vec<u8> = be.iter().copied().skip_while(|&b| b == 0).collect();
        rlp_str(&trimmed)
    }
    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        let mut out = vec![0xc0 + payload.len() as u8];
        out.extend_from_slice(&payload);
        out
    }
    let to = [0x5A; 20];
    let selector = [0xde, 0xad, 0xbe, 0xef];
    let cfg = BridgeConfig {
        gas_tx_allowed_to: Some(to),
        gas_tx_max_gas_limit: 100_000,
        gas_tx_max_fee_per_gas: 1_000_000_000,
        gas_tx_allowed_selectors: vec![selector],
        ..pinned()
    };
    let port = common::start_test_server_with_config(
        |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
        cfg,
    );
    let preimage_with_fee = |max_fee: u64| {
        let body = rlp_list(&[
            rlp_scalar(1),
            rlp_scalar(3), // the same nonce every time
            rlp_scalar(1_000),
            rlp_scalar(max_fee),
            rlp_scalar(50_000),
            rlp_str(&to),
            rlp_scalar(0),
            rlp_str(&selector),
            rlp_list(&[]),
        ]);
        let mut p = vec![0x02];
        p.extend_from_slice(&body);
        p
    };
    let sign = |unsigned_tx: Vec<u8>| {
        send(
            port,
            Req::SignRawDigest(SignRawDigestRequest {
                digest: vec![],
                unsigned_tx,
            }),
        )
    };
    assert!(matches!(
        sign(preimage_with_fee(1_000_000)).response,
        Some(Resp::RawDigestSig(_))
    ));
    expect_error(sign(preimage_with_fee(2_000_000)));
}

// ---- plain-BTC spend cap boundary --------------------------------------------------------

/// The cap bounds the value spent per transaction inclusively: exactly the
/// cap signs, one sat more does not.
#[cfg(feature = "allow-seed-import")]
#[test]
fn plain_btc_spend_cap_is_inclusive() {
    use common::taproot_fixture as fx;
    use utexo_bridge_enclave::keys::{AccountType, KeyManager};

    let km = KeyManager::from_mnemonic(MNEMONIC, bitcoin::Network::Bitcoin).unwrap();
    let psbt = fx::psbt_with_our_input(&km, AccountType::Vanilla, true);
    let input_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value.to_sat();
    for (cap, ok) in [(input_value, true), (input_value - 1, false)] {
        let port = common::start_test_server_with_config(
            |state| state.initialize_from_mnemonic(MNEMONIC).unwrap(),
            BridgeConfig {
                btc_max_total_sats: cap,
                ..Default::default()
            },
        );
        let resp = send(
            port,
            Req::SignBtc(SignBtcRequest {
                psbt_bytes: psbt.serialize(),
            }),
        );
        assert_eq!(
            matches!(resp.response, Some(Resp::SignedPsbt(_))),
            ok,
            "cap {cap} for {input_value} sats in"
        );
    }
}

// ---- reorg bound -------------------------------------------------------------------------

fn regtest_fork(count: u32, salt: u8) -> Vec<Vec<u8>> {
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, Network};
    let mut prev = bitcoin::BlockHash::from_byte_array(checkpoint_for(Network::Regtest).hash);
    let mut out = Vec::new();
    for h in 1..=count {
        let header = Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([salt ^ (h as u8); 32]),
            time: 1_700_000_000 + h,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        prev = header.block_hash();
        out.push(serialize(&header));
    }
    out
}

/// A longer fork may replace at most MAX_REORG_DEPTH blocks; a deeper one
/// is refused and the chain is untouched.
#[cfg(feature = "spv")]
#[test]
fn a_reorg_deeper_than_the_bound_is_refused() {
    use utexo_bridge_enclave::networks::rgb::spv::chain::MAX_REORG_DEPTH;
    let port = common::start_test_server();
    let main_len = MAX_REORG_DEPTH + 5;
    let resp = send(
        port,
        Req::SubmitHeaders(SubmitHeadersRequest {
            headers: regtest_headers(main_len),
            start_height: 1,
        }),
    );
    let main_tip = match resp.response {
        Some(Resp::SubmitHeaders(r)) => r.last_block_hash,
        other => panic!("{other:?}"),
    };

    // A longer fork replacing every block since the checkpoint: too deep.
    let fork = regtest_fork(main_len + 1, 0x80);
    expect_error(send(
        port,
        Req::SubmitHeaders(SubmitHeadersRequest {
            headers: fork,
            start_height: 1,
        }),
    ));
    let now = match send(port, Req::GetLastSavedBlock(GetLastSavedBlockRequest {})).response {
        Some(Resp::GetLastSavedBlock(r)) => r,
        other => panic!("{other:?}"),
    };
    assert_eq!((now.block_height, now.block_hash), (main_len, main_tip));

    // A longer fork exactly at the bound is accepted.
    let start = main_len - MAX_REORG_DEPTH + 1;
    let full = regtest_fork(main_len + 1, 0x80);
    // Rebuild the fork so it links to the main chain at `start - 1`.
    let mut linked = regtest_headers(start - 1);
    linked.truncate((start - 1) as usize);
    let _ = full;
    let fork_from_main = {
        use bitcoin::block::{Header, Version};
        use bitcoin::consensus::{deserialize, serialize};
        use bitcoin::hashes::Hash;
        let main = regtest_headers(main_len);
        let base: Header = deserialize(&main[(start - 2) as usize]).unwrap();
        let mut prev = base.block_hash();
        let mut out = Vec::new();
        for h in start..=main_len + 1 {
            let header = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xC0 ^ (h as u8); 32]),
                time: 1_700_000_000 + h,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            };
            prev = header.block_hash();
            out.push(serialize(&header));
        }
        out
    };
    let resp = send(
        port,
        Req::SubmitHeaders(SubmitHeadersRequest {
            headers: fork_from_main,
            start_height: start,
        }),
    );
    match resp.response {
        Some(Resp::SubmitHeaders(r)) => assert_eq!(r.last_block_height, main_len + 1),
        other => panic!("reorg at the bound refused: {other:?}"),
    }
}

// ---- init versus clone race ------------------------------------------------------------------

/// Initialising and starting a clone race for the same empty slot; exactly
/// one may win.
#[test]
fn init_and_initiate_cloning_race_yields_one_owner() {
    let port = common::start_test_server();
    let mut handles = Vec::new();
    for i in 0..8 {
        handles.push(std::thread::spawn(move || {
            let req = if i % 2 == 0 {
                Req::InitializeKey(InitializeKeyRequest {
                    seed: vec![],
                    mnemonic: String::new(),
                    cloning_secret: String::new(),
                })
            } else {
                Req::InitiateCloning(InitiateCloningRequest {
                    cloning_secret: "s".into(),
                    cluster_public_key: vec![0x11; 20],
                })
            };
            send(port, req)
        }));
    }
    let winners = handles
        .into_iter()
        .map(|h| h.join().unwrap().response)
        .filter(|r| {
            matches!(
                r,
                Some(Resp::InitializeKey(_)) | Some(Resp::InitiateCloning(_))
            )
        })
        .count();
    assert_eq!(winners, 1);
}

// ---- Merkle position bound ----------------------------------------------------------------

/// A position with bits beyond the path depth names a leaf the tree does
/// not have; it must not verify as if those bits were absent.
#[cfg(feature = "spv")]
#[test]
#[ignore = "FINDING: Merkle positions beyond the path depth are accepted (high bits ignored)"]
fn merkle_position_beyond_the_path_depth_is_refused() {
    use sha2::{Digest, Sha256};
    use utexo_bridge_enclave::networks::rgb::spv::verify_merkle_proof;

    let a = [0xA1u8; 32];
    let b = [0xB2u8; 32];
    let root: [u8; 32] = Sha256::digest(Sha256::digest([a, b].concat())).into();
    assert!(verify_merkle_proof(&a, 0, &[b], &root).is_ok());
    assert!(
        verify_merkle_proof(&a, 2, &[b], &root).is_err(),
        "position 2 in a two-leaf tree verified"
    );
}
