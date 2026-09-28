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
#[ignore = "FINDING: the mnemonic silently wins over the seed"]
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
    assert!(!err.message.is_empty());
}

// ---- replay ----------------------------------------------------------------------

/// A Concordium deposit must not be releasable twice by the same enclave.
/// The durable guard is the proxy's burnId; the enclave has a soft guard
/// only for EVM->RGB. This documents that CCD->EVM has none in the enclave.
#[cfg(all(
    feature = "ccd",
    feature = "rgb-validation",
    feature = "allow-seed-import"
))]
#[test]
#[ignore = "FINDING: no enclave-side replay guard for CCD->EVM; the proxy burnId is the only guard"]
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
    expect_error(send(port, req()));
}

// ---- plain-BTC sighash ------------------------------------------------------------

/// A PSBT that asks for SIGHASH_NONE or SINGLE on the enclave's input must be
/// refused, not silently signed with a different sighash: the wallet that
/// assembled it expects the type it requested.
#[cfg(feature = "allow-seed-import")]
#[test]
#[ignore = "FINDING: the requested sighash_type is ignored and SIGHASH_DEFAULT is signed instead"]
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
        expect_error(resp);
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
