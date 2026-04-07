mod common;

use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::*;

/// Build a mock fundsOut calldata with the given amount and commission.
/// fundsOut(address token, address recipient, uint256 amount, uint256 commission, ...)
fn mock_funds_out_calldata(
    token: [u8; 20],
    recipient: [u8; 20],
    amount: u64,
    commission: u64,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 7 * 32);
    // 4-byte selector (placeholder)
    data.extend_from_slice(&[0xab, 0xcd, 0xef, 0x12]);
    // address token (padded to 32 bytes)
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&token);
    data.extend_from_slice(&padded);
    // address recipient (padded to 32 bytes)
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&recipient);
    data.extend_from_slice(&padded);
    // uint256 amount
    let mut padded = [0u8; 32];
    padded[24..].copy_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&padded);
    // uint256 commission
    let mut padded = [0u8; 32];
    padded[24..].copy_from_slice(&commission.to_be_bytes());
    data.extend_from_slice(&padded);
    // remaining params (transactionId, sourceChain, sourceAddress) — zero-fill
    data.extend_from_slice(&[0u8; 32 * 3]);
    data
}

/// Build a valid enriched SignEvmRequest for testing.
fn valid_sign_evm_request(amount: u64, commission: u64) -> SignEvmRequest {
    SignEvmRequest {
        call_data: mock_funds_out_calldata([0x11; 20], [0x22; 20], amount, commission),
        nonce: 1,
        deadline: u64::MAX,
        consignment_valid: true,
        rgb_amount: amount + commission + 100, // plenty of headroom
        rgb_asset_id: "rgb:test".into(),
        chain_id: 1,
        proxy_contract: vec![0xAA; 20],
        calldata_amount: amount,
        calldata_commission: commission,
        consignment: vec![],
        consignment_hash: vec![],
    }
}

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
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                [0xBB; 20],
            )),
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

/// Build a valid enriched SignPsbtRequest for testing.
#[cfg(feature = "allow-seed-import")]
fn valid_sign_psbt_request(psbt_bytes: Vec<u8>) -> SignPsbtRequest {
    SignPsbtRequest {
        evm_tx_hash: vec![0xCC; 32],
        operation_idx: 0,
        evm_event_valid: true,
        evm_event_finalized: true,
        evm_token: vec![0x11; 20],
        evm_amount: 100_000,
        evm_recipient: vec![0x22; 20],
        evm_commission: 1_000,
        psbt_bytes,
        psbt_output_amount: 50_000,
        rgb_asset_id: "rgb:test".into(),
    }
}

// =============================================================================
// EVM signing tests
// =============================================================================

#[test]
fn test_sign_evm_roundtrip() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    let init_resp = common::send_request(port, &init_req);
    assert!(
        matches!(&init_resp.response, Some(Response::InitializeKey(_))),
        "init should succeed"
    );

    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(valid_sign_evm_request(1000, 50))),
    };
    let sign_resp = common::send_request(port, &sign_req);

    match &sign_resp.response {
        Some(Response::EvmSignature(r)) => {
            assert_eq!(r.signature.len(), 65, "EVM signature must be 65 bytes");
        }
        other => panic!("expected EvmSignatureResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_evm_before_init() {
    let port = common::start_test_server();

    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(valid_sign_evm_request(1000, 50))),
    };
    let resp = common::send_request(port, &sign_req);

    assert!(
        matches!(&resp.response, Some(Response::Error(_))),
        "sign before init should return error"
    );
}

// =============================================================================
// EVM enriched cross-check tests
// =============================================================================

#[test]
fn test_sign_evm_rejects_invalid_consignment() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let mut req = valid_sign_evm_request(1000, 50);
    req.consignment_valid = false;

    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(req)),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3, "cross-check failures should use code 3");
            assert!(e.message.contains("consignment"));
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_evm_rejects_amount_mismatch() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let mut req = valid_sign_evm_request(90, 20);
    req.rgb_amount = 100; // 90 + 20 = 110 > 100 => should fail

    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(req)),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("amount mismatch"));
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_evm_rejects_calldata_extraction_mismatch() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let mut req = valid_sign_evm_request(1000, 50);
    // Lie about the calldata amount — doesn't match what's in the raw bytes
    req.calldata_amount = 9999;
    req.rgb_amount = 99999; // make sure the amount check passes first

    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(req)),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("calldata amount mismatch"));
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

// =============================================================================
// PSBT signing tests
// =============================================================================

#[test]
#[cfg(feature = "allow-seed-import")]
fn test_sign_psbt_roundtrip() {
    let port = common::start_test_server();

    let seed = [0x42u8; 64];
    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: seed.to_vec(),
            mnemonic: String::new(),
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
        request: Some(Request::SignPsbt(valid_sign_psbt_request(psbt_bytes))),
    };
    let sign_resp = common::send_request(port, &sign_req);

    match &sign_resp.response {
        Some(Response::SignedPsbt(r)) => {
            assert!(r.inputs_signed > 0, "should have signed at least one input");
            assert!(
                !r.signed_psbt.is_empty(),
                "signed PSBT bytes should not be empty"
            );
        }
        other => panic!("expected SignedPsbtResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_psbt_before_init() {
    let port = common::start_test_server();

    let sign_req = EnclaveRequest {
        request: Some(Request::SignPsbt(SignPsbtRequest {
            evm_tx_hash: vec![0xAA; 32],
            operation_idx: 0,
            evm_event_valid: true,
            evm_event_finalized: true,
            evm_token: vec![],
            evm_amount: 1000,
            evm_recipient: vec![],
            evm_commission: 0,
            psbt_bytes: vec![0xFF; 10],
            psbt_output_amount: 500,
            rgb_asset_id: String::new(),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    assert!(
        matches!(&resp.response, Some(Response::Error(_))),
        "sign before init should return error"
    );
}

// =============================================================================
// PSBT enriched cross-check tests
// =============================================================================

#[test]
fn test_sign_psbt_rejects_unfinalized() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let sign_req = EnclaveRequest {
        request: Some(Request::SignPsbt(SignPsbtRequest {
            evm_tx_hash: vec![0xAA; 32],
            operation_idx: 0,
            evm_event_valid: true,
            evm_event_finalized: false,
            evm_token: vec![],
            evm_amount: 1000,
            evm_recipient: vec![],
            evm_commission: 0,
            psbt_bytes: vec![0xFF; 10],
            psbt_output_amount: 500,
            rgb_asset_id: String::new(),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("not yet finalized"));
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_psbt_rejects_amount_mismatch() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let sign_req = EnclaveRequest {
        request: Some(Request::SignPsbt(SignPsbtRequest {
            evm_tx_hash: vec![0xAA; 32],
            operation_idx: 0,
            evm_event_valid: true,
            evm_event_finalized: true,
            evm_token: vec![],
            evm_amount: 100,
            evm_recipient: vec![],
            evm_commission: 20,
            psbt_bytes: vec![0xFF; 10],
            psbt_output_amount: 90, // 90 + 20 = 110 > 100
            rgb_asset_id: String::new(),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("amount mismatch"));
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

// =============================================================================
// Vanilla PSBT signing tests (create_utxo — no EVM cross-checks)
// =============================================================================

#[test]
fn test_sign_vanilla_psbt_skips_evm_checks() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    // Vanilla PSBT: empty evm_tx_hash, no EVM enrichment.
    // This would fail bridge-mode cross-checks (evm_event_valid=false, etc.)
    // but should pass in vanilla mode.
    let sign_req = EnclaveRequest {
        request: Some(Request::SignPsbt(SignPsbtRequest {
            evm_tx_hash: vec![],     // empty = vanilla mode
            operation_idx: 0,
            evm_event_valid: false,  // would fail in bridge mode
            evm_event_finalized: false,
            evm_token: vec![],
            evm_amount: 0,
            evm_recipient: vec![],
            evm_commission: 0,
            psbt_bytes: vec![0xFF; 10], // not a real PSBT — will fail at signing, not validation
            psbt_output_amount: 0,
            rgb_asset_id: String::new(),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    // The request passes cross-checks (vanilla mode) but fails at actual PSBT
    // parsing since 0xFF bytes aren't a valid PSBT. That's fine — we're testing
    // that validation didn't reject it.
    match &resp.response {
        Some(Response::Error(e)) => {
            // Should NOT be a cross-check error (code 3) — should be a signing error
            assert_ne!(
                e.code, 3,
                "vanilla PSBT should not fail cross-checks, but got: {}",
                e.message
            );
        }
        Some(Response::SignedPsbt(_)) => {
            // Would only happen with a real valid PSBT — fine too
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

// =============================================================================
// Consignment hash integrity tests (wire protocol integration)
// =============================================================================

#[test]
fn test_sign_evm_rejects_consignment_hash_mismatch() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let mut req = valid_sign_evm_request(1000, 50);
    req.consignment = b"some-consignment-bytes".to_vec();
    req.consignment_hash = vec![0xDE; 32]; // wrong hash

    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(req)),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(
                e.code, 3,
                "hash mismatch should be cross-check error (code 3)"
            );
            assert!(
                e.message.contains("consignment hash mismatch"),
                "error should mention hash mismatch: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse for hash mismatch, got {:?}", other),
    }
}

#[test]
fn test_sign_evm_rejects_consignment_without_hash() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let mut req = valid_sign_evm_request(1000, 50);
    req.consignment = b"some-consignment-bytes".to_vec();
    req.consignment_hash = vec![]; // missing hash

    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(req)),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("consignment_hash is missing"));
        }
        other => panic!("expected ErrorResponse for missing hash, got {:?}", other),
    }
}

#[test]
fn test_sign_evm_accepts_valid_consignment_hash() {
    use sha3::{Digest, Keccak256};

    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let consignment = b"test-consignment-bytes";
    let hash = Keccak256::digest(consignment);

    let mut req = valid_sign_evm_request(1000, 50);
    req.consignment = consignment.to_vec();
    req.consignment_hash = hash.to_vec();

    let sign_req = EnclaveRequest {
        request: Some(Request::SignEvm(req)),
    };
    let resp = common::send_request(port, &sign_req);

    // Should succeed (hash is valid, cross-checks pass in dev-mode)
    match &resp.response {
        Some(Response::EvmSignature(r)) => {
            assert_eq!(r.signature.len(), 65);
        }
        other => panic!("expected EvmSignature, got {:?}", other),
    }
}

// =============================================================================
// Raw message signing tests
// =============================================================================

#[test]
fn test_sign_raw_message_roundtrip() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
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
            mnemonic: String::new(),
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
            mnemonic: String::new(),
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

    assert_eq!(
        sig1, sig2,
        "same message must produce same signature (RFC 6979)"
    );
}

#[test]
fn test_sign_raw_message_different_messages_differ() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
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

    assert_ne!(
        sig1, sig2,
        "different messages must produce different signatures"
    );
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
            mnemonic: String::new(),
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

    let msg_hash: [u8; 32] = Keccak256::digest(&message).into();
    let signature = K256Signature::from_slice(&sig_bytes[..64]).unwrap();
    let recovery_id = RecoveryId::from_byte(sig_bytes[64]).unwrap();
    let recovered_key =
        VerifyingKey::recover_from_prehash(&msg_hash, &signature, recovery_id).unwrap();

    let pubkey_bytes = recovered_key.to_encoded_point(false);
    let pubkey_hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
    let recovered_address: Vec<u8> = pubkey_hash[12..].to_vec();

    assert_eq!(
        recovered_address, evm_address,
        "recovered address must match the enclave's EVM address"
    );
}

// =============================================================================
// Federation proxy test
// =============================================================================

#[test]
fn test_proxy_federation_returns_not_ready() {
    let port = common::start_test_server();

    let req = EnclaveRequest {
        request: Some(Request::ProxyFederation(ProxyFederationRequest {
            message_hash: vec![0xAA; 32],
        })),
    };
    let resp = common::send_request(port, &req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(
                e.code, 2,
                "federation proxy should return NOT_READY (code 2)"
            );
            assert!(e.message.contains("federation proxy"));
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}
