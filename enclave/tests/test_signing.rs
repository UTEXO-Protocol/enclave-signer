mod common;

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall};
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::*;

// Mirrors `IBridge.fundsOut(FundsOutParams)`: one dynamic tuple, not the old
// flat 8-argument encoding, which the decoder rejects outright.
sol! {
    struct FundsOutParams {
        address recipient;
        uint256 amount;
        uint256 burnId;
        uint256 sourceChainId;
        uint256 destinationChainId;
        string sourceAddress;
        bytes proof;
        bytes settlementData;
    }

    function fundsOut(FundsOutParams params);
}

/// Pinned `BridgeConfig` matching the defaults of `valid_sign_evm_request`.
/// Injected by tests that must pass the production fail-closed gate,
/// since env is unconfigured in CI.
#[allow(dead_code)]
fn pinned_bridge_config() -> BridgeConfig {
    BridgeConfig {
        chain_id: 1,
        bridge_contract: [0xAA; 20],
        rgb_asset_id: "rgb:test".into(),
        ..Default::default()
    }
}

/// Pinned `BridgeConfig` for the plain-BTC (`SignBtc`) path. Only the
/// value-spent cap is operator-supplied now - the destination rule (outputs
/// must pay back to scripts the enclave proves it controls) needs no config,
/// which is the point of dropping `BTC_ALLOWED_SCRIPTS`.
#[allow(dead_code)]
fn btc_capped_config(max_total_sats: u64) -> BridgeConfig {
    BridgeConfig {
        btc_max_total_sats: max_total_sats,
        // Sized for `create_utxo` allocation dust (1000 sats x 5).
        btc_max_unowned_sats: 5_000,
        ..Default::default()
    }
}

/// Build ABI-valid `fundsOut(FundsOutParams)` calldata in the deployed shape.
fn mock_funds_out_calldata(recipient: [u8; 20], amount: u64) -> Vec<u8> {
    fundsOutCall {
        params: FundsOutParams {
            recipient: Address::from(recipient),
            amount: U256::from(amount),
            burnId: U256::ZERO,
            sourceChainId: U256::ZERO,
            destinationChainId: U256::from(1u64),
            sourceAddress: String::new(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
        },
    }
    .abi_encode()
}

/// Placeholder consignment bytes. `validate_source_payload` only verifies the
/// keccak hash; the RGB validator that would deserialize them is `None` in this
/// harness. So tests reach the cross-check layer but stop at the handler's
/// "requires validated consignment" check, which is what they assert.
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
            mint_ancestors: vec![],
        })),
        destination_network: Some(DestinationNetwork::EvmDestination(EvmDestination {
            call_data: mock_funds_out_calldata([0x22; 20], amount),
            nonce: 1,
            deadline: u64::MAX,
            chain_id: 1,
            proxy_contract: vec![0xAA; 20],
            calldata_amount: amount,
            calldata_commission: commission,
            lz_release: None,
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
/// `validate_psbt_bytes` shape-checking accepting the bytes - the actual
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

/// The public half of the enclave's wallet as a listener sees it: the master
/// fingerprint and the vanilla BIP-86 account xpub, both from `InitializeKey`.
/// Everything the plain-BTC path needs to build a self-paying PSBT derives from
/// these, with no secret and no post-boot configuration.
#[allow(dead_code)]
struct EnclaveWallet {
    fingerprint: bitcoin::bip32::Fingerprint,
    account_xpub: bitcoin::bip32::Xpub,
    account_xpub_colored: bitcoin::bip32::Xpub,
}

/// NUMS internal key (BIP-341 unspendable key-path), as the bridge's taproot
/// multisig addresses use.
#[allow(dead_code)]
const NUMS_INTERNAL: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Initialise the enclave's key and keep the public wallet material from the
/// response.
#[allow(dead_code)]
fn init_wallet(port: u16) -> EnclaveWallet {
    use std::str::FromStr;

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };
    match common::send_request(port, &init_req).response {
        Some(Response::InitializeKey(r)) => EnclaveWallet {
            fingerprint: bitcoin::bip32::Fingerprint::from(
                <[u8; 4]>::try_from(r.master_fingerprint.as_slice()).expect("4-byte fingerprint"),
            ),
            account_xpub: bitcoin::bip32::Xpub::from_str(&r.account_xpub_vanilla)
                .expect("vanilla account xpub"),
            account_xpub_colored: bitcoin::bip32::Xpub::from_str(&r.account_xpub_colored)
                .expect("colored account xpub"),
        },
        other => panic!("InitializeKey failed: {:?}", other),
    }
}

/// One of the enclave's own 2-of-3 taproot addresses, derived from the account
/// xpub at `m/86'/0'/0'/chain/index` (the test server runs on mainnet, so coin
/// type 0). Returns the `script_pubkey` plus the material a PSBT needs to prove
/// the address is the enclave's.
#[allow(dead_code)]
struct OurAddress {
    spk: bitcoin::ScriptBuf,
    leaf: bitcoin::ScriptBuf,
    leaf_hash: bitcoin::taproot::TapLeafHash,
    internal: bitcoin::XOnlyPublicKey,
    control: bitcoin::taproot::ControlBlock,
    xonly: bitcoin::XOnlyPublicKey,
    path: bitcoin::bip32::DerivationPath,
    fingerprint: bitcoin::bip32::Fingerprint,
}

#[allow(dead_code)]
fn our_address(wallet: &EnclaveWallet, chain: u32, index: u32) -> OurAddress {
    address_on_account(wallet, &wallet.account_xpub, 0, chain, index)
}

/// The colored (RGB) counterpart of [`our_address`], at
/// `m/86'/827166'/0'/chain/index` - the account `create_utxo` funds.
#[allow(dead_code)]
fn our_colored_address(wallet: &EnclaveWallet, chain: u32, index: u32) -> OurAddress {
    address_on_account(wallet, &wallet.account_xpub_colored, 827166, chain, index)
}

#[allow(dead_code)]
fn address_on_account(
    wallet: &EnclaveWallet,
    account_xpub: &bitcoin::bip32::Xpub,
    coin_type: u32,
    chain: u32,
    index: u32,
) -> OurAddress {
    use bitcoin::bip32::ChildNumber;
    use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
    use bitcoin::blockdata::script::Builder;
    use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let child = [
        ChildNumber::Normal { index: chain },
        ChildNumber::Normal { index },
    ];
    let derived = account_xpub
        .derive_pub(&secp, &child.to_vec())
        .expect("derive child xpub");
    let ours = derived.to_x_only_pub();

    // 2-of-3 with two keys the enclave doesn't hold - the federation shape.
    let mut keys = [ours, foreign_xonly(0xA1), foreign_xonly(0xA2)];
    keys.sort();
    let leaf = Builder::new()
        .push_x_only_key(&keys[0])
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&keys[1])
        .push_opcode(OP_CHECKSIGADD)
        .push_x_only_key(&keys[2])
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUAL)
        .into_script();
    let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    let internal = bitcoin::XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
    let info = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();

    OurAddress {
        spk: bitcoin::ScriptBuf::new_p2tr(&secp, internal, info.merkle_root()),
        control: info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap(),
        leaf,
        leaf_hash,
        internal,
        xonly: ours,
        fingerprint: wallet.fingerprint,
        path: bitcoin::bip32::DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(coin_type).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            child[0],
            child[1],
        ]),
    }
}

/// A taproot address the enclave has no key in.
#[allow(dead_code)]
fn foreign_address() -> bitcoin::ScriptBuf {
    use bitcoin::blockdata::opcodes::all::OP_CHECKSIG;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::taproot::TaprootBuilder;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let leaf = Builder::new()
        .push_x_only_key(&foreign_xonly(0xB1))
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let internal = bitcoin::XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
    let info = TaprootBuilder::new()
        .add_leaf(0, leaf)
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    bitcoin::ScriptBuf::new_p2tr(&secp, internal, info.merkle_root())
}

#[allow(dead_code)]
fn foreign_xonly(b: u8) -> bitcoin::XOnlyPublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[b; 32]).unwrap();
    bitcoin::XOnlyPublicKey::from_keypair(&bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk))
        .0
}

/// Build a plain-BTC PSBT spending `input_sats` from the enclave's own address
/// and paying `outputs`. Inputs carry the taproot metadata that makes them
/// co-signable by the enclave, so an output paying back to `from.spk` is
/// recognised as self-pay with no output metadata at all.
#[allow(dead_code)]
fn btc_psbt(from: &OurAddress, input_sats: u64, outputs: &[(bitcoin::ScriptBuf, u64)]) -> Vec<u8> {
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::Psbt;
    use bitcoin::taproot::LeafVersion;
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
        output: outputs
            .iter()
            .map(|(spk, sat)| TxOut {
                value: Amount::from_sat(*sat),
                script_pubkey: spk.clone(),
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(input_sats),
        script_pubkey: from.spk.clone(),
    });
    psbt.inputs[0].tap_internal_key = Some(from.internal);
    psbt.inputs[0].tap_scripts.insert(
        from.control.clone(),
        (from.leaf.clone(), LeafVersion::TapScript),
    );
    psbt.inputs[0].tap_key_origins.insert(
        from.xonly,
        (vec![from.leaf_hash], (from.fingerprint, from.path.clone())),
    );
    psbt.serialize()
}

/// Like [`btc_psbt`], but each output is one of the enclave's own addresses and
/// carries the BIP-371 metadata (`PSBT_OUT_TAP_INTERNAL_KEY` / `_TREE` /
/// `_BIP32_DERIVATION`) that proves it - the shape `create_utxo` produces.
#[allow(dead_code)]
fn btc_psbt_to_ours(from: &OurAddress, input_sats: u64, outputs: &[(&OurAddress, u64)]) -> Vec<u8> {
    use bitcoin::psbt::Psbt;
    use bitcoin::taproot::TaprootBuilder;

    let spks: Vec<(bitcoin::ScriptBuf, u64)> = outputs
        .iter()
        .map(|(o, sat)| (o.spk.clone(), *sat))
        .collect();
    let mut psbt = Psbt::deserialize(&btc_psbt(from, input_sats, &spks)).expect("psbt");

    for (i, (out, _)) in outputs.iter().enumerate() {
        psbt.outputs[i].tap_internal_key = Some(out.internal);
        psbt.outputs[i].tap_tree = Some(
            TaprootBuilder::new()
                .add_leaf(0, out.leaf.clone())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        psbt.outputs[i].tap_key_origins.insert(
            out.xonly,
            (vec![out.leaf_hash], (out.fingerprint, out.path.clone())),
        );
    }
    psbt.serialize()
}

/// Build a minimal 2-of-3 multisig PSBT for testing with a known pubkey.
#[cfg(all(
    feature = "allow-seed-import",
    feature = "dev-mode",
    not(feature = "rgb-validation")
))]
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
#[cfg(all(
    feature = "allow-seed-import",
    feature = "dev-mode",
    not(feature = "rgb-validation")
))]
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
            // Unchecked in non-`evm-rpc` builds, but must still be 32 bytes.
            funds_in_operation_id: vec![0x33; 32],
        })),
        destination_network: Some(DestinationNetwork::RgbDestination(RgbDestination {
            operation_idx: 0,
            psbt_bytes,
            psbt_output_amount,
            asset_id: String::new(),
            consignment: vec![],
            mint_ancestors: Vec::new(),
        consignment_hash: vec![],
        })),
    }
}

// EVM signing tests

// No happy-path `test_sign_evm_roundtrip` here: the harness leaves
// `ctx.rgb_validator` as `None`, so the handler refuses to sign fundsOut
// without a validator having run, and a real one would need an Esplora mock.
// Happy-path coverage lives in the `evm::crosscheck` unit tests.

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

// EVM enriched cross-check tests

/// P0 regression: the host-supplied `consignment_valid` flag must not bypass
/// validation. `consignment_valid: true` with `consignment: []` once produced a
/// signature with no RGB backing; empty bytes are now rejected regardless.
#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
#[test]
fn test_sign_evm_rejects_consignment_valid_with_empty_bytes() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
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

/// The handler-level check fires when bytes are present but the in-enclave
/// validator did not run: production must never sign fundsOut against
/// unvalidated bytes. The harness leaves `rgb_validator` as `None`.
#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
#[test]
fn test_sign_evm_rejects_funds_out_without_validator() {
    // Pinned config so the request clears the production fail-closed gate
    // and the pinned cross-check, leaving the handler-level
    // "validator didn't run" check as the failing predicate under test.
    let port = common::start_test_server_with_config(|_| {}, pinned_bridge_config());

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
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
            // gate (also requires a validated consignment) fires -
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

/// Regression (CcdSource -> EvmDestination fundsOut): a Concordium-sourced
/// release must sign. A CCD source carries no RGB consignment, so the RGB->EVM
/// fundsOut binding must be skipped for it. Exercises the full `handle_sign`
/// path with the real fundsOut selector, which the
/// `route_proofs_accept_ccd_source_to_evm_destination` unit test does not
/// reach.
#[cfg(all(feature = "rgb-validation", feature = "ccd", not(feature = "dev-mode")))]
#[test]
fn test_sign_evm_accepts_ccd_source_funds_out() {
    let port = common::start_test_server_with_config(|_| {}, pinned_bridge_config());

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    let amount = 1000u64;
    let commission = 50u64;
    let sign_req = EnclaveRequest {
        request: Some(Request::Sign(SignRequest {
            amount: amount + commission + 100, // headroom, mirrors valid_sign_evm_request
            source_network: Some(SourceNetwork::CcdSource(CcdSource {
                tx_hash: vec![0xCC; 32],
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
                lz_release: None,
            })),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::EvmSignature(sig)) => {
            assert!(
                !sig.signature.is_empty(),
                "expected a non-empty EVM signature for CcdSource -> EvmDestination fundsOut"
            );
        }
        // A regression re-introduces the unconditional RGB binding, which fails here.
        other => panic!(
            "expected EvmSignature for CcdSource -> EvmDestination fundsOut, got {:?}",
            other
        ),
    }
}

/// Fail-closed regression: a build that can validate
/// consignments must refuse to sign with no operator config pinned, rather than
/// degrading to the listener-trusting model. The integration harness builds the
/// library without `cfg(test)`, so the production guard is active. The
/// unconfigured `BridgeConfig` is built explicitly so env cannot interfere.
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
            cloning_secret: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    // A fully-formed, otherwise-valid fundsOut request - the only thing
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

/// A build without `spv` must refuse every `fundsOut`, even with no
/// merkle_proofs. Without SPV the enclave can only anchor witness txs through
/// the host-controlled Esplora resolver, so a fabricated anchor would be signed
/// against. The earlier guard fired only on non-empty `merkle_proofs[]`.
///
/// `not(rgb-validation)` implies `not(spv)` for any build that compiles. The
/// refusal fires in RGB source validation, whose message names the missing
/// `rgb-validation` feature.
#[cfg(all(not(feature = "rgb-validation"), not(feature = "dev-mode")))]
#[test]
fn test_no_spv_build_refuses_funds_out_even_without_merkle_proofs() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    // A fundsOut request carrying no merkle_proofs - exactly the shape that
    // previously bypassed the no-validation guard: the refusal
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

// PSBT signing tests

// A successful bridge (EVM -> RGB) PSBT roundtrip needs the FundsIn
// cross-check bypassed. Without `rgb-validation` only `dev-mode` can sign one;
// `evm-rpc` implies `rgb-validation`, so it cannot combine with
// `not(rgb-validation)`. dev-mode is compile-guarded out of release builds.
#[test]
#[cfg(all(
    feature = "allow-seed-import",
    feature = "dev-mode",
    not(feature = "rgb-validation")
))]
fn test_sign_psbt_roundtrip() {
    let port = common::start_test_server();

    let seed = [0x42u8; 64];
    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: seed.to_vec(),
            mnemonic: String::new(),
            cloning_secret: String::new(),
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

// PSBT enriched cross-check tests

/// The listener's `evm_event_valid` / `evm_event_finalized`
/// booleans neither authorize nor block signing. With both `false` the request
/// is never rejected with the old boolean-driven messages; whatever else
/// happens to it, the booleans are not what decide.
#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_sign_psbt_ignores_listener_evm_booleans() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
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

/// A build without the `evm-rpc` FundsIn verifier must
/// refuse a bridge-mode PSBT rather than sign it on the removed listener
/// booleans. Exercises the minimal build, where the `evm-rpc` fail-closed guard
/// is the first bridge-mode gate.
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
            cloning_secret: String::new(),
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
            cloning_secret: String::new(),
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

// Bridge SignPsbt no longer has a vanilla bypass

// In a production (rgb-validation) build, a SignPsbt with no consignment is
// rejected fail-closed - the empty-`evm_tx_hash` "vanilla mode" that used to
// skip every bridge predicate is gone. This is the core regression gate.
#[cfg(feature = "rgb-validation")]
#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_sign_psbt_rejects_missing_evm_source_hash() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
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

// A length-valid but all-zero evm_tx_hash must not
// read as a "vanilla mode" signal. SignPsbt runs the bridge cross-checks
// unconditionally and fails closed when no consignment binds the PSBT.
// Companion to `test_sign_psbt_rejects_missing_evm_source_hash`, which covers
// the zero-length hash rejected at the 32-byte length check.
#[cfg(feature = "rgb-validation")]
#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_sign_psbt_zero_evm_hash_is_bridge_mode_not_vanilla() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        })),
    };
    common::send_request(port, &init_req);

    // All-zero 32-byte hash: passes the length check (unlike the empty-hash
    // sibling test) but is the exact "looks like no tx" shape the removed
    // vanilla-inference keyed on. The RgbDestination carries no consignment, so
    // bridge mode must fail closed - never sign this as a vanilla PSBT.
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
            // Bridge mode ran and rejected the missing consignment binding -
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

// Plain-BTC signing (SignBtc): structural input guard + output self-ownership
// + pinned value-spent cap
//
// The destination policy is not configuration: every output must pay back to a
// script the enclave proves it controls. These tests build their PSBTs the way
// a listener must, deriving the enclave's own address from the account xpub
// `InitializeKey` returns.

#[test]
fn test_sign_btc_before_init() {
    let port = common::start_test_server_with_config(|_| {}, btc_capped_config(100_000));

    // No key, so the request can't even be validated (the output check runs
    // against the enclave's own derivation) - it must fail, not sign.
    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: minimal_valid_psbt_bytes(),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    assert!(
        matches!(&resp.response, Some(Response::Error(_))),
        "SignBtc before init should return error"
    );
}

// The structural guard for the plain-BTC path (refusing to co-sign a
// Colored input under SignBtc's vanilla-only scope) is covered by
// `signing::taproot::tests::scoped_vanilla_refuses_a_colored_input`. Paying
// into the colored account is legitimate: see
// `test_sign_btc_accepts_create_utxo_colored_output` below.

/// `create_utxo`: vanilla input, one fresh Colored (RGB-allocation) output plus
/// vanilla change. Both destinations are the enclave's, so both must pass the
/// self-ownership check and the PSBT must get signed.
#[test]
fn test_sign_btc_accepts_create_utxo_colored_output() {
    let port = common::start_test_server_with_config(|_| {}, btc_capped_config(100_000));
    let wallet = init_wallet(port);
    let ours = our_address(&wallet, 0, 0);
    let colored = our_colored_address(&wallet, 0, 0);

    // The real shape under address reuse: colored allocation dust (1000 sats
    // each), with the vanilla change returning to the script being spent. The
    // dust is bounded by BTC_MAX_UNOWNED_SATS, not waved through on metadata.
    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: btc_psbt_to_ours(&ours, 60_000, &[(&colored, 5_000), (&ours, 50_000)]),
        })),
    };

    match &common::send_request(port, &sign_req).response {
        Some(Response::SignedPsbt(r)) => assert_eq!(r.inputs_signed, 1),
        other => panic!("create_utxo PSBT should sign, got {:?}", other),
    }
}

#[test]
fn test_sign_btc_rejects_output_the_enclave_does_not_control() {
    let port = common::start_test_server_with_config(|_| {}, btc_capped_config(100_000));
    let wallet = init_wallet(port);
    let ours = our_address(&wallet, 0, 0);

    // Input is the enclave's own, but the output pays an address it has no key
    // in - the redirect the old allowlist was meant to stop, now caught without
    // any operator configuration.
    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: btc_psbt(&ours, 60_000, &[(foreign_address(), 10_000)]),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("same custody"),
                "expected self-ownership rejection, got: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
fn test_sign_btc_rejects_input_value_over_cap() {
    let port = common::start_test_server_with_config(|_| {}, btc_capped_config(100_000));
    let wallet = init_wallet(port);
    let ours = our_address(&wallet, 0, 0);

    // Self-paying destination, but the input value spent exceeds the cap.
    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: btc_psbt(&ours, 200_000, &[(ours.spk.clone(), 50_000)]),
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

/// End-to-end happy path: a PSBT built only from the enclave's published xpub
/// passes policy and gets signed. This is the check that the rework is actually
/// usable - under the old allowlist an operator had no way to pin this address
/// before the enclave that owns it existed.
#[test]
fn test_sign_btc_accepts_self_paying_psbt_under_cap() {
    let port = common::start_test_server_with_config(|_| {}, btc_capped_config(100_000));
    let wallet = init_wallet(port);
    let ours = our_address(&wallet, 0, 0);

    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: btc_psbt(&ours, 60_000, &[(ours.spk.clone(), 50_000)]),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::SignedPsbt(r)) => assert_eq!(
            r.inputs_signed, 1,
            "the enclave co-controls the input, so it must sign it"
        ),
        other => panic!("self-paying PSBT under cap should sign, got {:?}", other),
    }
}

/// A fresh change address the transaction does not spend from: accepted via the
/// output's BIP-371 taproot metadata rather than by matching an input.
#[test]
fn test_sign_btc_rejects_fresh_change_address_proven_only_by_metadata() {
    use bitcoin::psbt::Psbt;
    use bitcoin::taproot::TaprootBuilder;

    let port = common::start_test_server_with_config(|_| {}, btc_capped_config(100_000));
    let wallet = init_wallet(port);
    let spend_from = our_address(&wallet, 0, 0);
    let change = our_address(&wallet, 1, 7);

    let mut psbt = Psbt::deserialize(&btc_psbt(
        &spend_from,
        60_000,
        &[(change.spk.clone(), 50_000)],
    ))
    .unwrap();
    psbt.outputs[0].tap_internal_key = Some(change.internal);
    psbt.outputs[0].tap_tree = Some(
        TaprootBuilder::new()
            .add_leaf(0, change.leaf.clone())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    psbt.outputs[0].tap_key_origins.insert(
        change.xonly,
        (
            vec![change.leaf_hash],
            (change.fingerprint, change.path.clone()),
        ),
    );

    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            psbt_bytes: psbt.serialize(),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    // Output metadata is coordinator-supplied. Rule (B) used to accept this;
    // it is now refused, and 50_000 sats is far over the unowned budget.
    // Address reuse is what makes change provable: it lands on a script the
    // transaction is already spending.
    match &resp.response {
        Some(Response::Error(e)) => assert!(
            e.message.contains("same custody"),
            "expected the custody rejection, got: {}",
            e.message
        ),
        other => panic!(
            "a change address proven only by output metadata must not sign, got {:?}",
            other
        ),
    }
}

// A production (rgb-validation) build refuses plain-BTC signing while the
// value-spent cap is unconfigured - fail-closed, mirroring the EVM path. The
// destination rule needs no config, so it is not part of this gate.
#[cfg(feature = "rgb-validation")]
#[test]
fn test_sign_btc_uncapped_fails_closed_under_rgb_validation() {
    let port = common::start_test_server_with_config(|_| {}, BridgeConfig::default());
    let wallet = init_wallet(port);
    let ours = our_address(&wallet, 0, 0);

    let sign_req = EnclaveRequest {
        request: Some(Request::SignBtc(SignBtcRequest {
            // Self-paying (passes the structural guards) so the failure is
            // specifically the unset cap.
            psbt_bytes: btc_psbt(&ours, 10_000, &[(ours.spk.clone(), 9_000)]),
        })),
    };
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(
                e.message.contains("requires BTC_MAX_TOTAL_SATS"),
                "expected fail-closed-uncapped rejection, got: {}",
                e.message
            );
        }
        other => panic!(
            "uncapped plain-BTC signing must fail closed under rgb-validation, got: {:?}",
            other
        ),
    }
}

// Consignment hash integrity tests (wire protocol integration)

#[cfg(all(feature = "rgb-validation", not(feature = "dev-mode")))]
#[test]
fn test_sign_evm_rejects_consignment_hash_mismatch() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
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
            cloning_secret: String::new(),
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

// Raw message signing (removed)

/// `SignRawMessage` used to sign arbitrary caller-supplied bytes with the main
/// bridge key under an EIP-191 envelope, gated by no feature and no policy. It
/// was removed; the proto variant still exists, so the enclave must refuse it
/// rather than sign anything.
#[test]
fn test_sign_raw_message_is_refused() {
    let port = common::start_test_server();

    let init_req = EnclaveRequest {
        request: Some(Request::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
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
    let resp = common::send_request(port, &sign_req);

    match &resp.response {
        Some(Response::Error(e)) => {
            assert!(
                e.message.contains("SignRawMessage is removed"),
                "unexpected error message: {}",
                e.message
            );
        }
        other => panic!("expected ErrorResponse for SignRawMessage, got {:?}", other),
    }
}

// Federation proxy test

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

// EVM gas-tx (SignRawDigest) shape-allowlist tests
//
// These run through the real handler, so the fail-closed gate in
// `networks::evm::gas_tx` is active. They cover the accept path and the two
// drain vectors. Gated on `not(dev-mode)`, where the handler keeps the legacy
// opaque-digest path.

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

/// `BridgeConfig` with the full gas-tx rule pinned: chain_id 1,
/// destination 0xAA..., gas <= 30_000, fee <= 1_000 wei, selector 0xdeadbeef.
#[cfg(not(feature = "dev-mode"))]
fn gas_pinned_config() -> BridgeConfig {
    BridgeConfig {
        chain_id: 1,
        bridge_contract: [0xBB; 20],
        rgb_asset_id: "rgb:test".into(),
        gas_tx_allowed_to: Some([0xAA; 20]),
        gas_tx_max_gas_limit: 30_000,
        gas_tx_max_fee_per_gas: 1_000,
        gas_tx_allowed_selectors: vec![[0xde, 0xad, 0xbe, 0xef]],
        ..Default::default()
    }
}

/// Unsigned EIP-1559 preimage with explicit gas/fee/data, for the cap and
/// calldata-allowlist integration tests.
#[cfg(not(feature = "dev-mode"))]
fn eip1559_full(to: &[u8; 20], max_fee: u64, gas: u64, data: &[u8]) -> Vec<u8> {
    let body = rlp_list(&[
        rlp_scalar(1),       // chainId
        rlp_scalar(7),       // nonce
        rlp_scalar(1),       // maxPriorityFeePerGas
        rlp_scalar(max_fee), // maxFeePerGas
        rlp_scalar(gas),     // gasLimit
        rlp_str(to),         // to
        rlp_scalar(0),       // value
        rlp_str(data),       // data
        rlp_list(&[]),       // accessList
    ]);
    let mut out = vec![0x02];
    out.extend_from_slice(&body);
    out
}

#[cfg(not(feature = "dev-mode"))]
fn init(port: u16) {
    common::send_request(
        port,
        &EnclaveRequest {
            request: Some(Request::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: String::new(),
                cloning_secret: String::new(),
            })),
        },
    );
}

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_gas_tx_signs_pinned_destination() {
    let port = common::start_test_server_with_config(|_| {}, gas_pinned_config());
    init(port);

    // Calldata leads with the pinned 0xdeadbeef selector (empty calldata is refused).
    let tx = eip1559_full(&[0xAA; 20], 100, 21_000, &[0xde, 0xad, 0xbe, 0xef]);
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

    // Well-formed tx, but to an attacker address - the drain this rule closes.
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

/// Send a gas-tx preimage through the real handler and return the response.
#[cfg(not(feature = "dev-mode"))]
fn sign_gas_tx(port: u16, unsigned_tx: Vec<u8>) -> EnclaveResponse {
    common::send_request(
        port,
        &EnclaveRequest {
            request: Some(Request::SignRawDigest(SignRawDigestRequest {
                digest: vec![],
                unsigned_tx,
            })),
        },
    )
}

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_gas_tx_rejects_gas_limit_over_cap() {
    let port = common::start_test_server_with_config(|_| {}, gas_pinned_config());
    init(port);

    // gasLimit 40_000 exceeds the pinned 30_000 cap - the fee-griefing bound.
    let tx = eip1559_full(&[0xAA; 20], 100, 40_000, &[]);
    match &sign_gas_tx(port, tx).response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("gasLimit"), "got: {}", e.message);
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_gas_tx_rejects_fee_over_cap() {
    let port = common::start_test_server_with_config(|_| {}, gas_pinned_config());
    init(port);

    // maxFeePerGas 5_000 exceeds the pinned 1_000 cap.
    let tx = eip1559_full(&[0xAA; 20], 5_000, 21_000, &[]);
    match &sign_gas_tx(port, tx).response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("maxFeePerGas"), "got: {}", e.message);
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_gas_tx_signs_allowlisted_selector() {
    let port = common::start_test_server_with_config(|_| {}, gas_pinned_config());
    init(port);

    // Calldata leading with the pinned 0xdeadbeef selector is accepted.
    let mut data = vec![0xde, 0xad, 0xbe, 0xef];
    data.extend_from_slice(&[0u8; 32]);
    let tx = eip1559_full(&[0xAA; 20], 100, 21_000, &data);
    match &sign_gas_tx(port, tx).response {
        Some(Response::RawDigestSig(r)) => assert_eq!(r.signature.len(), 65),
        other => panic!("expected RawDigestSignatureResponse, got {:?}", other),
    }
}

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_gas_tx_rejects_disallowed_selector() {
    let port = common::start_test_server_with_config(|_| {}, gas_pinned_config());
    init(port);

    // Calldata with a selector outside the allowlist is refused.
    let tx = eip1559_full(&[0xAA; 20], 100, 21_000, &[0x11, 0x22, 0x33, 0x44]);
    match &sign_gas_tx(port, tx).response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("selector"), "got: {}", e.message);
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}

#[test]
#[cfg(not(feature = "dev-mode"))]
fn test_gas_tx_fails_closed_when_caps_unpinned() {
    // A config that pins the destination but NOT the caps must refuse to sign:
    // an uncapped gas tx is never produced (fail-closed).
    let mut cfg = gas_pinned_config();
    cfg.gas_tx_max_gas_limit = 0;
    cfg.gas_tx_max_fee_per_gas = 0;
    let port = common::start_test_server_with_config(|_| {}, cfg);
    init(port);

    let tx = eip1559_full(&[0xAA; 20], 100, 21_000, &[]);
    match &sign_gas_tx(port, tx).response {
        Some(Response::Error(e)) => {
            assert_eq!(e.code, 3);
            assert!(e.message.contains("cap not pinned"), "got: {}", e.message);
        }
        other => panic!("expected ErrorResponse, got {:?}", other),
    }
}
