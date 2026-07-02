mod common;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::*;

/// Pinned `BridgeConfig` matching the defaults of `valid_sign_evm_request`
/// (chain_id 1, proxy/bridge contract `0xAA…`, asset `rgb:test`). Tests
/// that need to pass the production fail-closed gate (audit TEE-SE-12) and
/// the pinned cross-check inject this rather than relying on env, which is
/// the empty/unconfigured default in CI.
#[allow(dead_code)]
fn pinned_bridge_config() -> BridgeConfig {
    BridgeConfig {
        chain_id: 1,
        bridge_contract: [0xAA; 20],
        rgb_asset_id: "rgb:test".into(),
    }
}

/// Build a mock `fundsOut` calldata in the 8-arg shape
/// `fundsOut(address,uint256,uint256,uint256,uint256,string,bytes,bytes)`
/// (selector `0xccddb768`) — the single `fundsOut` on the deployed
/// contract, accepted by `validation::evm_crosscheck`'s whitelist.
/// `amount` sits at offset 36 (after selector + recipient).
fn mock_funds_out_calldata(recipient: [u8; 20], amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 8 * 32);
    data.extend_from_slice(&[0xcc, 0xdd, 0xb7, 0x68]);
    // recipient (address, padded to 32 bytes) @ offset 4
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&recipient);
    data.extend_from_slice(&padded);
    // amount (uint256) @ offset 36
    let mut padded = [0u8; 32];
    padded[24..].copy_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&padded);
    // 6 more head slots zero-filled (burnId, sourceChainId,
    // destinationChainId, srcAddrOffset, proofOffset, settlementDataOffset).
    data.extend_from_slice(&[0u8; 32 * 6]);
    data
}

/// Placeholder consignment bytes for integration tests. `validate_evm_request`
/// only verifies the keccak hash; the in-enclave RGB validator
/// (configured in production via `ctx.rgb_validator`, left `None` in the
/// test harness) is what would deserialize and validate. Tests therefore
/// reach the cross-check layer with these bytes but never get past the
/// handler-level "requires validated consignment" check — which is what
/// the integration tests below assert.
const PLACEHOLDER_CONSIGNMENT: &[u8] = b"placeholder-consignment-bytes-for-integration-tests";

fn placeholder_consignment_hash() -> Vec<u8> {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(PLACEHOLDER_CONSIGNMENT).to_vec()
}

/// Build a valid enriched EVM-destination SignRequest for testing. `commission` is
/// retained on the proto fields for wire-compat but is no longer part of
/// the calldata (the contract takes commission on-chain).
fn valid_sign_evm_request(amount: u64, commission: u64) -> SignRequest {
    SignRequest {
        amount: amount + commission + 100, // plenty of headroom
        source_network: Some(SourceNetwork::RgbSource(RgbSource {
            consignment_valid: true,
            asset_id: "rgb:test".into(),
            consignment: PLACEHOLDER_CONSIGNMENT.to_vec(),
            consignment_hash: placeholder_consignment_hash(),
            merkle_proofs: vec![],
            commission,
        })),
        destination_network: Some(DestinationNetwork::EvmDestination(EvmDestination {
            call_data: mock_funds_out_calldata([0x22; 20], amount),
            nonce: 1,
            deadline: u64::MAX,
            chain_id: 1,
            proxy_contract: vec![0xAA; 20],
            calldata_amount: amount,
            calldata_commission: commission,
        })),
    }
}

#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
fn rgb_source_mut(req: &mut SignRequest) -> &mut RgbSource {
    match req.source_network.as_mut() {
        Some(SourceNetwork::RgbSource(source)) => source,
        other => panic!("expected RGB source, got {other:?}"),
    }
}

/// Build a minimal BIP-174-valid PSBT for tests that only care about
/// `validate_psbt_request` shape-checking accepting the bytes — the actual
/// signing path won't sign this (no witness data, no matchable keys), so
/// only use it for tests that expect rejection BEFORE the signer runs.
fn minimal_valid_psbt_bytes() -> Vec<u8> {
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::Psbt;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                    [0u8; 32],
                )),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    Psbt::from_unsigned_tx(unsigned_tx)
        .expect("from_unsigned_tx")
        .serialize()
}

/// Build a minimal 2-of-3 multisig PSBT for testing with a known pubkey.
#[cfg(all(feature = "allow-seed-import", not(feature = "rgb-validation")))]
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

    let mut pubkeys = [*our_pubkey, pk2, pk3];
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

/// Build a valid enriched RGB-destination SignRequest for testing.
#[cfg(all(feature = "allow-seed-import", not(feature = "rgb-validation")))]
fn valid_sign_psbt_request(psbt_bytes: Vec<u8>) -> SignRequest {
    sign_psbt_request(
        vec![0xCC; 32],
        true,
        true,
        100_000,
        1_000,
        psbt_bytes,
        50_000,
    )
}

fn sign_psbt_request(
    evm_tx_hash: Vec<u8>,
    evm_event_valid: bool,
    evm_event_finalized: bool,
    evm_amount: u64,
    evm_commission: u64,
    psbt_bytes: Vec<u8>,
    psbt_output_amount: u64,
) -> SignRequest {
    SignRequest {
        amount: evm_amount,
        source_network: Some(SourceNetwork::EvmSource(EvmSource {
            tx_hash: evm_tx_hash,
            event_valid: evm_event_valid,
            event_finalized: evm_event_finalized,
            token: vec![],
            recipient: vec![],
            commission: evm_commission,
        })),
        destination_network: Some(DestinationNetwork::RgbDestination(RgbDestination {
            operation_idx: 0,
            psbt_bytes,
            psbt_output_amount,
            asset_id: String::new(),
            consignment: vec![],
            consignment_hash: vec![],
        })),
    }
}

// =============================================================================
// EVM signing tests
// =============================================================================

// Note: there is no `test_sign_evm_roundtrip` (happy-path success) here.
// The test harness leaves `ctx.rgb_validator` as `None`, so even with
// valid placeholder bytes the handler refuses to sign fundsOut without
// an in-enclave validator having actually run. Constructing a real
// validator in tests would mean wiring an Esplora mock — out of scope
// for this P0 fix. Happy-path coverage of `validate_funds_out_*` lives
// in the unit tests in `validation::evm_crosscheck::tests`.

#[test]
fn test_sign_evm_before_init() {
    let port = common::start_test_server();

    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(valid_sign_evm_request(1000, 50))),
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

/// P0 regression: the host-supplied `consignment_valid` flag must not
/// bypass validation over the wire. Yulia's PoC #3 / boss's report:
/// previously, `consignment_valid:true` + `consignment:[]` produced a
/// signature with no real RGB backing. Now the cross-check rejects
/// empty bytes regardless of any listener claim.
#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
#[test]
fn test_sign_evm_rejects_consignment_valid_with_empty_bytes() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let mut req = valid_sign_evm_request(1_000_000_000, 0);
    {
        let source = rgb_source_mut(&mut req);
        source.consignment_valid = true;
        source.consignment = vec![];
        source.consignment_hash = vec![];
        source.asset_id = "rgb:fake-asset-no-real-backing".into();
    }

    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(req)),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3, "cross-check failures should use code 3");
            assert!(
                e.message.contains("requires raw consignment bytes"),
                "expected raw-bytes-required rejection, got: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

/// The handler-level check fires when bytes are present (so
/// `validate_evm_request` passes) but the in-enclave validator wasn't
/// configured / didn't run — production must never sign fundsOut
/// against unvalidated bytes. The test harness leaves `rgb_validator`
/// as `None`, which simulates the "validator missing" half.
#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
#[test]
fn test_sign_evm_rejects_funds_out_without_validator() {
    // Pinned config so the request clears the production fail-closed gate
    // (TEE-SE-12) and the pinned cross-check, leaving the handler-level
    // "validator didn't run" check as the failing predicate under test.
    let port = common::start_test_server_with_config(|_| {}, pinned_bridge_config());

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(valid_sign_evm_request(1000, 50))),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3, "cross-check failures should use code 3");
            // Either the handler-level check (no validator) or the SPV
            // gate (also requires a validated consignment) fires —
            // current source validation fails first when no validator is wired.
            assert!(
                e.message.contains("rgb_validator"),
                "expected rgb_validator rejection, got: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

/// Fail-closed regression (audit TEE-SE-12): a build that can validate
/// consignments must refuse to sign when no operator config is pinned,
/// rather than silently degrading to the listener-trusting model. The
/// integration harness builds the library without `cfg(test)`, so the
/// production guard in `validate_evm_request` is active here — exactly the
/// path a misprovisioned-but-running enclave would hit. Uses an
/// unconfigured `BridgeConfig` (constructed explicitly so a developer's
/// env can't accidentally configure it away).
#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
#[test]
fn test_sign_evm_rejects_unconfigured_bridge_config() {
    let unconfigured = BridgeConfig {
        chain_id: 0,
        bridge_contract: [0u8; 20],
        rgb_asset_id: String::new(),
    };
    let port = common::start_test_server_with_config(|_| {}, unconfigured);

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    // A fully-formed, otherwise-valid fundsOut request — the only thing
    // wrong is that the enclave was never provisioned with a pin.
    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(valid_sign_evm_request(1000, 50))),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3, "cross-check failures should use code 3");
            assert!(e.message.contains("rgb_validator"));
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

// Amount binding now lives in `validate_funds_out_transfer`, which runs
// against a `ValidatedConsignment` (the consignment is authoritative on
// the amount, not the listener-supplied `rgb_amount`/`calldata_*`
// fields). It's exhaustively unit-tested in
// `validation::evm_crosscheck::tests::transfer`. The old integration
// tests here asserted the removed `rgb_amount < calldata_amount +
// commission` / byte-offset-68 checks in `validate_evm_request`; those
// checks are gone with the single-`fundsOut` ABI (no commission slot,
// amount bound to the consignment instead), so the integration cases
// were removed rather than ported — they can't run without a configured
// in-enclave validator, which the harness doesn't wire.

/// Default-build coverage: `--features rgb-validation` is required to
/// sign fundsOut at all. The cross-check fails fast with a message
/// that names the missing feature, so a misconfigured deployment fails
/// loud instead of silently signing against unvalidated bytes.
#[cfg(all(not(feature = "rgb-validation"), not(feature = "dev-mode")))]
#[test]
fn test_sign_evm_rejects_funds_out_in_default_build() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(valid_sign_evm_request(1000, 50))),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("rgb-validation"),
                "expected feature-gate rejection, got: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

// =============================================================================
// PSBT signing tests
// =============================================================================

#[test]
#[cfg(all(feature = "allow-seed-import", not(feature = "rgb-validation")))]
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
        request: Some(Request::Sign(valid_sign_psbt_request(psbt_bytes))),
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
        request: Some(Request::Sign(sign_psbt_request(
            vec![0xAA; 32],
            true,
            true,
            1000,
            0,
            minimal_valid_psbt_bytes(),
            500,
        ))),
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
#[cfg(not(feature = "dev-mode"))]
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
        request: Some(Request::Sign(sign_psbt_request(
            vec![0xAA; 32],
            true,
            false,
            1000,
            0,
            minimal_valid_psbt_bytes(),
            500,
        ))),
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
#[cfg(not(feature = "dev-mode"))]
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
        request: Some(Request::Sign(sign_psbt_request(
            vec![0xAA; 32],
            true,
            true,
            100,
            20,
            minimal_valid_psbt_bytes(),
            90, // 90 + 20 = 110 > 100
        ))),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("amount mismatch")
                    || e.message.contains("consignment")
                    || e.message.contains("rgb_validator"),
                "expected amount or RGB validation rejection, got: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

// =============================================================================
// Vanilla PSBT signing tests (create_utxo — no EVM cross-checks)
// =============================================================================

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_sign_psbt_rejects_missing_evm_source_hash() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(sign_psbt_request(
            vec![],
            false,
            false,
            0,
            0,
            minimal_valid_psbt_bytes(),
            0,
        ))),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("evm_tx_hash must be 32 bytes"),
                "expected missing tx hash rejection, got: {}",
                e.message
            );
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

// =============================================================================
// Consignment hash integrity tests (wire protocol integration)
// =============================================================================

#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
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
    {
        let source = rgb_source_mut(&mut req);
        source.consignment = b"some-consignment-bytes".to_vec();
        source.consignment_hash = vec![0xDE; 32]; // wrong hash
    }

    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(req)),
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

#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
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
    {
        let source = rgb_source_mut(&mut req);
        source.consignment = b"some-consignment-bytes".to_vec();
        source.consignment_hash = vec![]; // missing hash
    }

    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(req)),
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

    // EIP-191 personal_sign envelope: the enclave hashes
    // `"\x19Ethereum Signed Message:\n" || len(msg) || msg`, NOT raw keccak(msg).
    // The verifier MUST rebuild the same preimage, otherwise pubkey recovery
    // returns a different address.
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    hasher.update(message.len().to_string().as_bytes());
    hasher.update(&message);
    let msg_hash: [u8; 32] = hasher.finalize().into();

    let signature = K256Signature::from_slice(&sig_bytes[..64]).unwrap();
    let recovery_id = RecoveryId::from_byte(sig_bytes[64]).unwrap();
    let recovered_key =
        VerifyingKey::recover_from_prehash(&msg_hash, &signature, recovery_id).unwrap();

    let pubkey_bytes = recovered_key.to_encoded_point(false);
    let pubkey_hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
    let recovered_address: Vec<u8> = pubkey_hash[12..].to_vec();

    assert_eq!(
        recovered_address, evm_address,
        "recovered address must match the enclave's EVM address — verifier must use the EIP-191 preimage"
    );

    // Sanity: raw-keccak preimage must NOT recover to the same address. If this
    // ever passes, the enclave dropped the EIP-191 prefix and is back to
    // signing arbitrary digests — i.e. the eth_sign tx-forgery hole is open.
    let raw_hash: [u8; 32] = Keccak256::digest(&message).into();
    let raw_recovered = VerifyingKey::recover_from_prehash(&raw_hash, &signature, recovery_id).ok();
    let raw_address = raw_recovered.map(|k| {
        let pk_bytes = k.to_encoded_point(false);
        Keccak256::digest(&pk_bytes.as_bytes()[1..])[12..].to_vec()
    });
    assert_ne!(
        raw_address.as_deref(),
        Some(evm_address.as_slice()),
        "raw-keccak recovery must NOT match enclave address — EIP-191 prefix is missing"
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
