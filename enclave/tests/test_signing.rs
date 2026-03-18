mod common;

use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::*;

/// Build a minimal 2-of-3 multisig PSBT for testing with a known pubkey.
#[cfg(feature = "allow-seed-import")]
fn build_test_multisig_psbt(our_pubkey: &bitcoin::PublicKey) -> Vec<u8> {
    use bitcoin::blockdata::opcodes::all::*;
    use bitcoin::blockdata::script::Builder as ScriptBuilder;
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
    let secp = Secp256k1::new();

    let sk2 = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let pk2 = bitcoin::PublicKey::new(sk2.public_key(&secp));
    let sk3 = SecretKey::from_slice(&[0x03; 32]).unwrap();
    let pk3 = bitcoin::PublicKey::new(sk3.public_key(&secp));

    let mut pubkeys = vec![*our_pubkey, pk2, pk3];
    pubkeys.sort_by_key(|k| k.to_bytes());

    let witness_script = ScriptBuilder::new()
        .push_int(2)
        .push_key(&pubkeys[0])
        .push_key(&pubkeys[1])
        .push_key(&pubkeys[2])
        .push_int(3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();

    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xAA; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(
                &bitcoin::WPubkeyHash::from_byte_array([0xBB; 20]),
            ),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

    let witness_script_hash = bitcoin::WScriptHash::hash(witness_script.as_bytes());
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2wsh(&witness_script_hash),
    });
    psbt.inputs[0].witness_script = Some(witness_script);

    psbt.serialize()
}

#[test]
fn test_sign_evm_roundtrip() {
    let port = common::start_test_server();

    // Initialize keys first
    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
        })),
    };
    let init_resp = common::send_request(port, &init_req);
    assert!(
        matches!(&init_resp.response, Some(Response::InitializeKey(_))),
        "init should succeed"
    );

    // Sign EVM
    let call_data =
        hex::decode("a9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000064")
            .unwrap();
    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(SignEvmRequest {
            call_data,
            nonce: 0,
            deadline: 1_700_000_000,
        })),
    };
    let sign_resp = common::send_request(port, &sign_req);

    match &sign_resp.response {
        Some(Response::EvmSignature(r)) => {
            assert_eq!(r.signature.len(), 65, "EVM signature must be 65 bytes");
            eprintln!("--- test_sign_evm_roundtrip ---");
            eprintln!("  signature: {}", hex::encode(&r.signature));
        }
        other => panic!("expected EvmSignatureResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_evm_before_init() {
    let port = common::start_test_server();

    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(SignEvmRequest {
            call_data: vec![0xAB; 4],
            nonce: 0,
            deadline: 1_700_000_000,
        })),
    };
    let resp = common::send_request(port, &sign_req);

    assert!(
        matches!(&resp.response, Some(Response::Error(_))),
        "sign before init should return error"
    );
}

#[test]
#[cfg(feature = "allow-seed-import")]
fn test_sign_psbt_roundtrip() {
    let port = common::start_test_server();

    // Initialize with known seed so we know the BTC pubkey
    let seed = [0x42u8; 64];
    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: seed.to_vec(),
        })),
    };
    let init_resp = common::send_request(port, &init_req);

    let btc_pubkey_bytes = match &init_resp.response {
        Some(Response::InitializeKey(r)) => r.btc_compressed_pub.clone(),
        other => panic!("expected InitializeKeyResponse, got {:?}", other),
    };

    let our_pubkey = bitcoin::PublicKey::from_slice(&btc_pubkey_bytes).unwrap();
    let psbt_bytes = build_test_multisig_psbt(&our_pubkey);

    let sign_req = EnclaveRequest {
        request: Some(Request::SignPsbt(SignPsbtRequest {
            evm_tx_hash: vec![],
            operation_idx: 0,
            psbt_bytes,
        })),
    };
    let sign_resp = common::send_request(port, &sign_req);

    match &sign_resp.response {
        Some(Response::SignedPsbt(r)) => {
            assert!(r.inputs_signed > 0, "should have signed at least one input");
            assert!(
                !r.signed_psbt.is_empty(),
                "signed PSBT bytes should not be empty"
            );
            eprintln!("--- test_sign_psbt_roundtrip ---");
            eprintln!("  inputs_signed: {}", r.inputs_signed);
        }
        other => panic!("expected SignedPsbtResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_psbt_before_init() {
    let port = common::start_test_server();

    let sign_req = EnclaveRequest {
        request: Some(Request::SignPsbt(SignPsbtRequest {
            evm_tx_hash: vec![],
            operation_idx: 0,
            psbt_bytes: vec![0xFF; 10],
        })),
    };
    let resp = common::send_request(port, &sign_req);

    assert!(
        matches!(&resp.response, Some(Response::Error(_))),
        "sign before init should return error"
    );
}

#[test]
fn test_sign_raw_message_roundtrip() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
        })),
    };
    let init_resp = common::send_request(port, &init_req);
    assert!(
        matches!(&init_resp.response, Some(Response::InitializeKey(_))),
        "init should succeed"
    );

    let sign_req = EnclaveRequest {
        request: Some(Request::SignRawMessage(SignRawMessageRequest {
            message: b"fundsIn authorization payload".to_vec(),
        })),
    };
    let sign_resp = common::send_request(port, &sign_req);

    match &sign_resp.response {
        Some(Response::RawSignature(r)) => {
            assert_eq!(r.signature.len(), 65, "raw signature must be 65 bytes");
            eprintln!("--- test_sign_raw_message_roundtrip ---");
            eprintln!("  signature: {}", hex::encode(&r.signature));
        }
        other => panic!("expected RawSignatureResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_raw_message_before_init() {
    let port = common::start_test_server();

    let sign_req = EnclaveRequest {
        request: Some(Request::SignRawMessage(SignRawMessageRequest {
            message: b"test".to_vec(),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    assert!(
        matches!(&resp.response, Some(Response::Error(_))),
        "sign before init should return error"
    );
}

#[test]
fn test_sign_raw_message_empty() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
        })),
    };
    common::send_request(port, &init_req);

    let sign_req = EnclaveRequest {
        request: Some(Request::SignRawMessage(SignRawMessageRequest {
            message: vec![],
        })),
    };
    let resp = common::send_request(port, &sign_req);

    assert!(
        matches!(&resp.response, Some(Response::Error(_))),
        "empty message should return error"
    );
}

#[test]
fn test_sign_raw_message_deterministic() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
        })),
    };
    common::send_request(port, &init_req);

    let msg = b"deterministic test payload".to_vec();

    let sign_req = EnclaveRequest {
        request: Some(Request::SignRawMessage(SignRawMessageRequest {
            message: msg.clone(),
        })),
    };
    let resp1 = common::send_request(port, &sign_req);

    let sign_req2 = EnclaveRequest {
        request: Some(Request::SignRawMessage(SignRawMessageRequest {
            message: msg,
        })),
    };
    let resp2 = common::send_request(port, &sign_req2);

    let sig1 = match &resp1.response {
        Some(Response::RawSignature(r)) => &r.signature,
        other => panic!("expected RawSignatureResponse, got {:?}", other),
    };
    let sig2 = match &resp2.response {
        Some(Response::RawSignature(r)) => &r.signature,
        other => panic!("expected RawSignatureResponse, got {:?}", other),
    };

    assert_eq!(sig1, sig2, "same message must produce same signature (RFC 6979)");
}

#[test]
fn test_sign_raw_message_different_messages_differ() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
        })),
    };
    common::send_request(port, &init_req);

    let req1 = EnclaveRequest {
        request: Some(Request::SignRawMessage(SignRawMessageRequest {
            message: b"message A".to_vec(),
        })),
    };
    let req2 = EnclaveRequest {
        request: Some(Request::SignRawMessage(SignRawMessageRequest {
            message: b"message B".to_vec(),
        })),
    };

    let sig1 = match common::send_request(port, &req1).response {
        Some(Response::RawSignature(r)) => r.signature,
        other => panic!("expected RawSignatureResponse, got {:?}", other),
    };
    let sig2 = match common::send_request(port, &req2).response {
        Some(Response::RawSignature(r)) => r.signature,
        other => panic!("expected RawSignatureResponse, got {:?}", other),
    };

    assert_ne!(sig1, sig2, "different messages must produce different signatures");
}

#[test]
#[cfg(feature = "allow-seed-import")]
fn test_sign_raw_message_recoverable() {
    use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
    use sha3::{Digest, Keccak256};

    let port = common::start_test_server();

    let seed = [0x42u8; 64];
    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: seed.to_vec(),
        })),
    };
    let init_resp = common::send_request(port, &init_req);

    let evm_address = match &init_resp.response {
        Some(Response::InitializeKey(r)) => r.evm_address.clone(),
        other => panic!("expected InitializeKeyResponse, got {:?}", other),
    };

    let message = b"fundsIn authorization test".to_vec();
    let sign_req = EnclaveRequest {
        request: Some(Request::SignRawMessage(SignRawMessageRequest {
            message: message.clone(),
        })),
    };
    let sign_resp = common::send_request(port, &sign_req);

    let sig_bytes = match &sign_resp.response {
        Some(Response::RawSignature(r)) => &r.signature,
        other => panic!("expected RawSignatureResponse, got {:?}", other),
    };

    // Recover the signer's public key from the signature
    let msg_hash: [u8; 32] = Keccak256::digest(&message).into();
    let signature = K256Signature::from_slice(&sig_bytes[..64]).unwrap();
    let recovery_id = RecoveryId::from_byte(sig_bytes[64]).unwrap();
    let recovered_key =
        VerifyingKey::recover_from_prehash(&msg_hash, &signature, recovery_id).unwrap();

    // Derive address from recovered key
    let pubkey_bytes = recovered_key.to_encoded_point(false);
    let pubkey_hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
    let recovered_address: Vec<u8> = pubkey_hash[12..].to_vec();

    assert_eq!(
        recovered_address, evm_address,
        "recovered address must match the enclave's EVM address"
    );
}
