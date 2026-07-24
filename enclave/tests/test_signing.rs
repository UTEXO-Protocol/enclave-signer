mod common;

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall};
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::*;

sol! {
    function fundsOut(
        address recipient,
        uint256 amount,
        uint256 burnId,
        uint256 sourceChainId,
        uint256 destinationChainId,
        string sourceAddress,
        bytes proof,
        bytes settlementData
    );
}

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
        ..Default::default()
    }
}

/// Pinned `BridgeConfig` for the plain-BTC (`SignBtc`) path: pins a single
/// allowed output `script_pubkey` and a total-output cap, so the plain-BTC
/// cross-check has a concrete allowlist to enforce. Mirrors how #81's
/// `gas_pinned_config()` pins the gas-tx destination.
#[allow(dead_code)]
fn btc_pinned_config(allowed_script: Vec<u8>, max_total_sats: u64) -> BridgeConfig {
    BridgeConfig {
        btc_allowed_scripts: vec![allowed_script],
        btc_max_total_sats: max_total_sats,
        ..Default::default()
    }
}

/// Build ABI-valid `fundsOut` calldata in the deployed 8-arg shape.
fn mock_funds_out_calldata(recipient: [u8; 20], amount: u64) -> Vec<u8> {
    fundsOutCall {
        recipient: Address::from(recipient),
        amount: U256::from(amount),
        burnId: U256::ZERO,
        sourceChainId: U256::ZERO,
        destinationChainId: U256::from(1u64),
        sourceAddress: String::new(),
        proof: Bytes::new(),
        settlementData: Bytes::new(),
    }
    .abi_encode()
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

/// Build a valid enriched EVM-destination SignRequest for testing. `commission`
/// stays outside the calldata but remains part of route-proof amount coverage.
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

/// Build a one-input, one-output PSBT for the plain-BTC (`SignBtc`) tests. The
/// input carries a populated `witness_utxo` (`input_spk`/`input_sats`) so the
/// validator can classify (P2WSH vs not) and bound it; the output pays
/// `output_spk` for `output_sats`. The signer won't actually sign it (no
/// matchable keys), so use it for tests expecting a cross-check rejection or a
/// 0-input signed response.
#[allow(dead_code)]
fn btc_psbt(
    input_spk: bitcoin::ScriptBuf,
    input_sats: u64,
    output_spk: bitcoin::ScriptBuf,
    output_sats: u64,
) -> Vec<u8> {
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
            value: Amount::from_sat(output_sats),
            script_pubkey: output_spk,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(input_sats),
        script_pubkey: input_spk,
    });
    psbt.serialize()
}

/// A deterministic P2WPKH script_pubkey — a bridge-controlled plain
/// output/input script for the plain-BTC tests.
#[allow(dead_code)]
fn btc_test_script(seed: u8) -> bitcoin::ScriptBuf {
    use bitcoin::hashes::Hash;
    bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([seed; 20]))
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
            // On-chain FundsIn operationId the enclave #60 check binds to (these
            // non-rgb-validation builds don't run that check; 0 is a placeholder).
            funds_in_operation_id: 0,
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
        ..Default::default()
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

// Amount binding now runs through route proofs: RGB source validation emits the
// consignment amount, EVM destination validation decodes `fundsOut.amount` and
// adds `calldata_commission`, then `validate_route_proofs` compares the two.

/// M-01 / #61: a build without `spv` must refuse to sign any `fundsOut`,
/// even when the request carries no merkle_proofs. Without SPV the enclave can
/// only anchor a consignment's witness txs through the host-controlled Esplora
/// resolver, so a fabricated anchor would otherwise be signed against. The
/// earlier guard only fired when `merkle_proofs[]` was non-empty, letting an
/// empty-proofs `fundsOut` slip through — this asserts that gap is closed.
/// (`not(rgb-validation)` ⇔ `not(spv)` for any build that compiles: `spv`
/// pulls in `rgb-validation`, and lib.rs's `compile_error!` forbids
/// rgb-validation without spv.) On this layout the refusal fires in RGB
/// source validation, whose message names the missing `rgb-validation`
/// feature, so a misconfigured deployment fails loud instead of silently
/// signing against unvalidated bytes.
#[cfg(all(not(feature = "rgb-validation"), not(feature = "dev-mode")))]
#[test]
fn test_no_spv_build_refuses_funds_out_even_without_merkle_proofs() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    // A fundsOut request carrying no merkle_proofs — exactly the shape that
    // previously bypassed the no-validation guard (M-01 / #61): the refusal
    // must fire even when the request supplies no SPV proofs at all.
    let req = valid_sign_evm_request(1000, 50);
    match &req.source_network {
        Some(SourceNetwork::RgbSource(source)) => assert!(
            source.merkle_proofs.is_empty(),
            "test precondition: the request must carry no merkle_proofs"
        ),
        other => panic!("expected RGB source, got {other:?}"),
    }
    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(req)),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains(
                    "RGB source validation requires the enclave to be built with \
                     --features rgb-validation"
                ),
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

/// Audit M-06 / #51: the listener-supplied `evm_event_valid` /
/// `evm_event_finalized` booleans no longer authorize *or* block signing. With
/// both `false`, the request is never rejected with the old boolean-driven
/// messages: EVM-event validity/finality is now established independently by
/// `networks::evm::evm_event` (unit-tested). Whatever else happens to the request
/// (rejected for a missing consignment under rgb-validation, or for no
/// enclave-owned PSBT input), it is never the booleans that decide it.
#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_sign_psbt_ignores_listener_evm_booleans() {
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
            false,
            false,
            1000,
            0,
            minimal_valid_psbt_bytes(),
            500,
        ))),
    };
    let resp = common::send_request(port, &sign_req);

    // Any error is fine (other real checks may reject this synthetic request),
    // but it must NOT be the removed listener-boolean checks.
    if let Some(Response::Error(e)) = &resp.response {
        assert!(
            !e.message.contains("not yet finalized")
                && !e.message.contains("not validated by Listener"),
            "listener booleans must no longer drive rejection, got: {}",
            e.message
        );
    }
}

/// Audit M-06 / #60 & #51: a build without the `evm-rpc` FundsIn verifier must
/// refuse a bridge-mode PSBT rather than sign it on the (now-removed) listener
/// booleans. This exercises the minimal build, where the `evm-rpc` fail-closed
/// guard is the first bridge-mode gate (no `rgb-validation` consignment
/// crosscheck precedes it). In `rgb-validation` builds the consignment binding
/// is an additional earlier gate; the guard still fires for a request that
/// carries a valid consignment but no in-enclave deposit verification.
#[cfg(all(
    not(feature = "rgb-validation"),
    not(feature = "evm-rpc"),
    not(feature = "dev-mode")
))]
#[test]
fn test_no_evm_rpc_build_refuses_bridge_psbt() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    // Bridge mode (EVM source + RGB destination) with a shape-valid PSBT and
    // consistent amounts, so it clears the route cross-checks and reaches the
    // evm-rpc fail-closed guard. The listener booleans are set true but ignored.
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

    match resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("--features evm-rpc"),
                "expected an evm-rpc feature refusal, got: {}",
                e.message
            );
        }
        other => panic!("expected a fail-closed error, got: {other:?}"),
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
// M-01/#69: bridge SignPsbt no longer has a vanilla bypass
// =============================================================================

// In a production (rgb-validation) build, a SignPsbt with no consignment is
// rejected fail-closed — the empty-`evm_tx_hash` "vanilla mode" that used to
// skip every bridge predicate is gone. This is the core M-01 regression gate.
#[cfg(feature = "rgb-validation")]
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

// TP-1 / M-01 (#69, PR #102): a length-VALID but all-ZERO evm_tx_hash must not
// be read as a "vanilla mode" signal. The closed bypass inferred "plain BTC,
// skip every bridge predicate" from a blank/empty evm_tx_hash; now a SignPsbt
// (EvmSource + RgbDestination) runs the bridge cross-checks unconditionally and
// fails closed when no consignment binds the PSBT. Companion to
// `test_sign_psbt_rejects_missing_evm_source_hash` (which covers the zero-LENGTH
// hash, rejected earlier at the 32-byte length check): a 32-byte all-zero hash
// clears that length gate, so the request must be caught by the unconditional
// consignment binding instead of slipping onto a vanilla signing path.
#[cfg(feature = "rgb-validation")]
#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_sign_psbt_zero_evm_hash_is_bridge_mode_not_vanilla() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    // All-zero 32-byte hash: passes the length check (unlike the empty-hash
    // sibling test) but is the exact "looks like no tx" shape the removed
    // vanilla-inference keyed on. The RgbDestination carries no consignment, so
    // bridge mode must fail closed — never sign this as a vanilla PSBT.
    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(sign_psbt_request(
            vec![0u8; 32],
            false,
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
            assert_eq!(e.code, 3, "bridge cross-check failures use code 3");
            // Bridge mode ran and rejected the missing consignment binding —
            // the zeroed hash did NOT route the request onto the vanilla path.
            assert!(
                e.message.contains("consignment"),
                "expected a consignment-binding rejection (bridge mode), got: {}",
                e.message
            );
        }
        other => panic!(
            "zero-hash SignPsbt must fail closed in bridge mode, never sign: {:?}",
            other
        ),
    }
}

// =============================================================================
// Plain-BTC signing (SignBtc): structural input guard + pinned allowlist + cap
// =============================================================================

fn init_server(port: u16) {
    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
        })),
    };
    common::send_request(port, &init_req);
}

#[test]
fn test_sign_btc_before_init() {
    let allowed = btc_test_script(0x11);
    let port = common::start_test_server_with_config(
        |_| {},
        btc_pinned_config(allowed.as_bytes().to_vec(), 100_000),
    );

    // Valid policy (non-P2WSH input, under cap, allowlisted output) so the only
    // reason to fail is the uninitialized key.
    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: btc_psbt(btc_test_script(0x11), 60_000, allowed, 50_000),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    assert!(
        matches!(&resp.response, Some(Response::Error(_))),
        "SignBtc before init should return error"
    );
}

// The structural M-01 guard for the plain-BTC path — the enclave refuses to
// co-sign a Colored (RGB-allocated) input under SignBtc's vanilla-only signing
// scope — is exercised at the unit level in
// `signing::taproot::tests::scoped_vanilla_refuses_a_colored_input` (it needs a
// known seed + a colored-account tapscript, which the integration harness's
// random init key can't construct). The integration tests below cover the
// operator-pinned destination/amount policy layer.

#[test]
fn test_sign_btc_rejects_non_allowlisted_output() {
    let allowed = btc_test_script(0x11);
    let port = common::start_test_server_with_config(
        |_| {},
        btc_pinned_config(allowed.as_bytes().to_vec(), 100_000),
    );
    init_server(port);

    // Input is fine, but pays an address the operator did NOT pin.
    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: btc_psbt(btc_test_script(0x11), 60_000, btc_test_script(0x99), 10_000),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("non-allowlisted"),
                "expected allowlist rejection, got: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_btc_rejects_input_value_over_cap() {
    let allowed = btc_test_script(0x11);
    let port = common::start_test_server_with_config(
        |_| {},
        btc_pinned_config(allowed.as_bytes().to_vec(), 100_000),
    );
    init_server(port);

    // Allowlisted destination, but the input value spent exceeds the cap.
    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: btc_psbt(btc_test_script(0x11), 200_000, allowed, 50_000),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("exceeds pinned cap"),
                "expected cap rejection, got: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_btc_accepts_allowlisted_under_cap() {
    let allowed = btc_test_script(0x11);
    let port = common::start_test_server_with_config(
        |_| {},
        btc_pinned_config(allowed.as_bytes().to_vec(), 100_000),
    );
    init_server(port);

    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: btc_psbt(btc_test_script(0x11), 60_000, allowed, 50_000),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    // Passes policy; the test seed matches no input. With the inputs_signed==0
    // guard this returns a (non-cross-check) Signing error rather than a code-3
    // policy rejection — assert only that policy did not reject it.
    match &resp.response {
        Some(Response::SignedPsbt(_)) => {}
        Some(Response::Error(e)) => assert_ne!(
            e.code, 3,
            "allowlisted output under cap should pass policy, got: {}",
            e.message
        ),
        other => panic!("unexpected response: {:?}", other),
    }
}

// A production (rgb-validation) build refuses plain-BTC signing when the
// allowlist/cap are unconfigured — fail-closed, mirroring the EVM path.
#[cfg(feature = "rgb-validation")]
#[test]
fn test_sign_btc_unconfigured_fails_closed_under_rgb_validation() {
    // Unconfigured BridgeConfig (no BTC_ALLOWED_SCRIPTS / BTC_MAX_TOTAL_SATS).
    let port = common::start_test_server_with_config(|_| {}, BridgeConfig::default());
    init_server(port);

    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            // Non-P2WSH input (passes the structural guard) so the failure is
            // specifically the unconfigured-policy fail-closed.
            psbt_bytes: btc_psbt(btc_test_script(0x11), 10_000, btc_test_script(0x11), 9_000),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("requires BTC_ALLOWED_SCRIPTS"),
                "expected fail-closed-unconfigured rejection, got: {}",
                e.message
            );
        }
        other => panic!(
            "unconfigured plain-BTC signing must fail closed under rgb-validation, got: {:?}",
            other
        ),
    }
}

// A production build also refuses plain-BTC signing under a HALF-pin (allowlist
// set but cap unset, or vice-versa) — the half-pin is treated as unconfigured.
#[cfg(feature = "rgb-validation")]
#[test]
fn test_sign_btc_half_pin_fails_closed_under_rgb_validation() {
    let allowed = btc_test_script(0x11);
    // allowlist set, cap == 0 (unset) → half-pin → unconfigured
    let port = common::start_test_server_with_config(
        |_| {},
        btc_pinned_config(allowed.as_bytes().to_vec(), 0),
    );
    init_server(port);

    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: btc_psbt(btc_test_script(0x11), 10_000, allowed, 9_000),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("requires BTC_ALLOWED_SCRIPTS"),
                "expected half-pin fail-closed rejection, got: {}",
                e.message
            );
        }
        other => panic!(
            "half-pin plain-BTC signing must fail closed under rgb-validation, got: {:?}",
            other
        ),
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

// =============================================================================
// EVM gas-tx (SignRawDigest) shape-allowlist tests (audit TEE-XC-09)
// =============================================================================
//
// These run through the real handler, so the production fail-closed gate in
// `networks::evm::gas_tx` is active (the integration crate builds the lib
// without cfg(test)). They cover the accept path and the two drain vectors.
// Gated on `not(dev-mode)` like the other cross-check tests: under dev-mode
// the handler keeps the legacy opaque-digest path instead of the allowlist.

/// Minimal RLP encoder for building gas-tx fixtures.
#[cfg(not(feature = "dev-mode"))]
fn rlp_str(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut out = Vec::new();
    if bytes.len() <= 55 {
        out.push(0x80 + bytes.len() as u8);
    } else {
        let lb: Vec<u8> = bytes
            .len()
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0xb7 + lb.len() as u8);
        out.extend_from_slice(&lb);
    }
    out.extend_from_slice(bytes);
    out
}

#[cfg(not(feature = "dev-mode"))]
fn rlp_scalar(v: u64) -> Vec<u8> {
    let trimmed: Vec<u8> = v
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|&b| b == 0)
        .collect();
    rlp_str(&trimmed)
}

#[cfg(not(feature = "dev-mode"))]
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for it in items {
        payload.extend_from_slice(it);
    }
    let mut out = Vec::new();
    if payload.len() <= 55 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let lb: Vec<u8> = payload
            .len()
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0xf7 + lb.len() as u8);
        out.extend_from_slice(&lb);
    }
    out.extend_from_slice(&payload);
    out
}

/// Unsigned EIP-1559 preimage: `0x02 || rlp([chainId, nonce, maxPrio, maxFee, gas, to, value, data, accessList])`.
#[cfg(not(feature = "dev-mode"))]
fn eip1559_unsigned(chain_id: u64, to: &[u8; 20], value: u64) -> Vec<u8> {
    let body = rlp_list(&[
        rlp_scalar(chain_id),
        rlp_scalar(7),
        rlp_scalar(1),
        rlp_scalar(100),
        rlp_scalar(21_000),
        rlp_str(to),
        rlp_scalar(value),
        rlp_str(&[]),
        rlp_list(&[]),
    ]);
    let mut out = vec![0x02];
    out.extend_from_slice(&body);
    out
}

/// `BridgeConfig` with the gas-tx destination pinned (chain_id 1, to 0xAA…).
#[cfg(not(feature = "dev-mode"))]
fn gas_pinned_config() -> BridgeConfig {
    BridgeConfig {
        chain_id: 1,
        bridge_contract: [0xBB; 20],
        rgb_asset_id: "rgb:test".into(),
        gas_tx_allowed_to: Some([0xAA; 20]),
        ..Default::default()
    }
}

#[cfg(not(feature = "dev-mode"))]
fn init(port: u16) {
    common::send_request(
        port,
        &EnclaveRequest {
            request: Some(Request::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: String::new(),
            })),
        },
    );
}

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_gas_tx_signs_pinned_destination() {
    let port = common::start_test_server_with_config(|_| {}, gas_pinned_config());
    init(port);

    let tx = eip1559_unsigned(1, &[0xAA; 20], 0);
    let resp = common::send_request(
        port,
        &EnclaveRequest {
            request: Some(Request::SignRawDigest(SignRawDigestRequest {
                digest: vec![],
                unsigned_tx: tx,
            })),
        },
    );

    match &resp.response {
        Some(Response::RawDigestSig(r)) => assert_eq!(r.signature.len(), 65),
        other => panic!("expected RawDigestSignatureResponse, got {:?}", other),
    }
}

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_gas_tx_rejects_opaque_digest() {
    let port = common::start_test_server_with_config(|_| {}, gas_pinned_config());
    init(port);

    // Legacy opaque-digest request (no preimage) must be refused.
    let resp = common::send_request(
        port,
        &EnclaveRequest {
            request: Some(Request::SignRawDigest(SignRawDigestRequest {
                digest: vec![0x11; 32],
                unsigned_tx: vec![],
            })),
        },
    );

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("unsigned transaction preimage"),
                "got: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_gas_tx_rejects_drain_to_attacker() {
    let port = common::start_test_server_with_config(|_| {}, gas_pinned_config());
    init(port);

    // Well-formed tx, but to an attacker address — the drain #68 closes.
    let tx = eip1559_unsigned(1, &[0xEE; 20], 0);
    let resp = common::send_request(
        port,
        &EnclaveRequest {
            request: Some(Request::SignRawDigest(SignRawDigestRequest {
                digest: vec![],
                unsigned_tx: tx,
            })),
        },
    );

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("destination"), "got: {}", e.message);
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}
