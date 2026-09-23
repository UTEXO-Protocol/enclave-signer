use std::io::{Cursor, Read, Write};

use sha3::{Digest, Keccak256};

use crate::config::{BridgeConfig, EvmRpcConfig};
use crate::framing;
use crate::networks::evm::events::{LogEntry, ReceiptData, BRIDGE_FUNDS_IN_SIG};
use crate::networks::rgb::validation::{
    bfa, OutputSeal, RgbValidator, TransitionOutput, TransitionSummary, ValidatedConsignment,
};
use crate::policy::{BuildContext, EvmDataSource, SecurityPolicy};
use crate::proto::enclave_request::Request;
use crate::proto::enclave_response::Response;
use crate::proto::sign_request::{DestinationNetwork, SourceNetwork};
use crate::proto::*;
use crate::server::{handle_connection, ServerContext, SubmitRateLimiter};
use crate::state::EnclaveState;
use crate::test_support::{bridge_funds_in_data, regtest_header_chain, FakeEvm};

/// Fixed seed, so every derived key and every txid is the same on each
/// run.
const SEED: [u8; 64] = [0x21; 64];
const ASSET_ID: &str = "rgb:test-asset";
const BRIDGE_CONTRACT: [u8; 20] = [0xAA; 20];
const FUNDS_IN_CONTRACT: [u8; 20] = [0xBB; 20];
const DEPOSIT_TX: [u8; 32] = [0xCC; 32];
const OPERATION_ID: [u8; 32] = [0x33; 32];
const DEPOSIT_BLOCK: u64 = 100;
const GROSS: u64 = 100_000;
const COMMISSION: u64 = 1_000;
const NET: u64 = GROSS - COMMISSION;

/// The deposit's invoice and the blinded seal it names.
const INVOICE: &str = "rgb:~/~/~/bc:utxob:dYwB28dy-yD6EBgm-MO~UKN_-FyEEdBL-E9hw8Oj-i9KxH5b-e9vZL";
const RECIPIENT_SEAL: &str = "utxob:dYwB28dy-yD6EBgm-MO~UKN_-FyEEdBL-E9hw8Oj-i9KxH5b-e9vZL";

/// NUMS internal key (BIP-341 unspendable key path), as the bridge's
/// taproot addresses use.
const NUMS_INTERNAL: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// A caller that is gone: the request still reads back, every write
/// fails.
struct DeadCaller(Cursor<Vec<u8>>);

impl Read for DeadCaller {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for DeadCaller {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "caller is gone",
        ))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Stands in for the EVM RPC: one confirmed `BridgeFundsIn` deposit.
fn stub_deposit() -> FakeEvm {
    FakeEvm {
        receipt: Some(ReceiptData {
            status_success: true,
            block_number: DEPOSIT_BLOCK,
            logs: vec![LogEntry {
                address: FUNDS_IN_CONTRACT,
                topics: vec![
                    Keccak256::digest(BRIDGE_FUNDS_IN_SIG.as_bytes()).into(),
                    OPERATION_ID,
                ],
                data: bridge_funds_in_data(GROSS, NET, COMMISSION, INVOICE),
            }],
        }),
        head: DEPOSIT_BLOCK + EvmRpcConfig::default().min_confirmations,
    }
}

fn foreign_xonly(b: u8) -> bitcoin::XOnlyPublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[b; 32]).unwrap();
    bitcoin::XOnlyPublicKey::from_keypair(&bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk))
        .0
}

/// A taproot address the enclave has no key in.
fn foreign_address() -> bitcoin::ScriptBuf {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    bitcoin::ScriptBuf::new_p2tr(&secp, foreign_xonly(0xB1), None)
}

/// The witness transaction of the deposit: one input on the enclave's
/// colored address `m/86'/827166'/0'/0/0` (a 2-of-3 taproot address, the
/// federation shape), the recipient's output, and colored change.
fn deposit_psbt(state: &EnclaveState) -> Vec<u8> {
    use bitcoin::bip32::ChildNumber;
    use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
    use bitcoin::blockdata::script::Builder;
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::Psbt;
    use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use std::str::FromStr;

    let keys = state.get_keys().expect("keys");
    let account_xpub =
        bitcoin::bip32::Xpub::from_str(&keys.account_xpub_colored).expect("colored xpub");
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let child = [
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ];
    let ours = account_xpub
        .derive_pub(&secp, &child.to_vec())
        .expect("derive child xpub")
        .to_x_only_pub();

    let mut keyset = [ours, foreign_xonly(0xA1), foreign_xonly(0xA2)];
    keyset.sort();
    let leaf = Builder::new()
        .push_x_only_key(&keyset[0])
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&keyset[1])
        .push_opcode(OP_CHECKSIGADD)
        .push_x_only_key(&keyset[2])
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
    let spk = ScriptBuf::new_p2tr(&secp, internal, info.merkle_root());
    let control = info
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .unwrap();
    let path = bitcoin::bip32::DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(86).unwrap(),
        ChildNumber::from_hardened_idx(827166).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
        child[0],
        child[1],
    ]);

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
        output: vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: foreign_address(),
            },
            TxOut {
                value: Amount::from_sat(58_000),
                script_pubkey: spk.clone(),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(60_000),
        script_pubkey: spk,
    });
    psbt.inputs[0].tap_internal_key = Some(internal);
    psbt.inputs[0]
        .tap_scripts
        .insert(control, (leaf, LeafVersion::TapScript));
    psbt.inputs[0].tap_key_origins.insert(
        ours,
        (
            vec![leaf_hash],
            (
                bitcoin::bip32::Fingerprint::from(keys.master_fingerprint),
                path,
            ),
        ),
    );
    psbt.serialize()
}

/// One BFA transfer paying the deposit's invoice, anchored to `txid`.
fn validated_consignment(txid: bitcoin::Txid) -> ValidatedConsignment {
    let transition = TransitionSummary {
        op_id: "11".repeat(32),
        transition_type: bfa::TS_TRANSFER,
        total_output_amount: NET,
        asset_output_amount: NET,
        outputs: vec![TransitionOutput {
            assignment_type: bfa::OS_ASSET,
            amount: NET,
            seal: OutputSeal::Confidential {
                secret_seal: RECIPIENT_SEAL.into(),
            },
        }],
        burned_asset_amount: None,
        burn_recipient: None,
    };
    ValidatedConsignment {
        contract_id: ASSET_ID.into(),
        chain_net: "bc".into(),
        witness_txids: vec![],
        all_op_ids: vec![transition.op_id.clone()],
        mint_op_ids: vec![],
        last_transition: Some(transition.clone()),
        last_witness_txid: Some(txid),
        last_transfer_witness_prevouts: None,
        last_transfer_op_id: None,
        non_mined_witness_txids: vec![],
        transitions_by_witness: vec![(txid, vec![transition])],
    }
}

fn deposit_request(psbt_bytes: Vec<u8>) -> EnclaveRequest {
    let consignment = b"answered by the canned validator".to_vec();
    EnclaveRequest {
        request: Some(Request::Sign(SignRequest {
            amount: GROSS,
            source_network: Some(SourceNetwork::EvmSource(EvmSource {
                tx_hash: DEPOSIT_TX.to_vec(),
                event_valid: true,
                event_finalized: true,
                token: vec![],
                recipient: vec![],
                commission: COMMISSION,
                funds_in_operation_id: OPERATION_ID.to_vec(),
            })),
            destination_network: Some(DestinationNetwork::RgbDestination(RgbDestination {
                operation_idx: 0,
                psbt_bytes,
                psbt_output_amount: NET,
                asset_id: ASSET_ID.into(),
                consignment_hash: Keccak256::digest(&consignment).to_vec(),
                consignment,
                mint_ancestors: Vec::new(),
            })),
        })),
    }
}

fn framed(request: &EnclaveRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    framing::write_message(&mut bytes, request).expect("frame request");
    bytes
}

/// Handle one request over a connection that stays up, and decode what
/// the caller received.
fn respond(ctx: &ServerContext, request: &EnclaveRequest) -> EnclaveResponse {
    let request = framed(request);
    let request_len = request.len();
    let mut caller = Cursor::new(request);
    handle_connection(&mut caller, ctx);
    framing::read_message(&mut &caller.into_inner()[request_len..]).expect("response frame")
}

/// The caller never reads the first signature. The retry must be signed,
/// not refused as a duplicate.
#[test]
fn a_retry_is_signed_when_the_first_response_never_reached_the_caller() {
    let bridge_config = BridgeConfig {
        chain_id: 1,
        bridge_contract: BRIDGE_CONTRACT,
        funds_in_contract: FUNDS_IN_CONTRACT,
        rgb_asset_id: ASSET_ID.into(),
        rgb_max_unowned_sats: 5_000,
        ..Default::default()
    };
    let policy = SecurityPolicy::resolve(
        &BuildContext::current(),
        &bridge_config,
        EvmDataSource::Disabled,
        None,
        0,
    );
    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    state.initialize_from_seed(SEED).expect("initialize keys");

    let psbt_bytes = deposit_psbt(&state);
    let txid = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
        .expect("psbt")
        .unsigned_tx
        .compute_txid();

    let ctx = ServerContext {
        state,
        bridge_config,
        policy,
        rgb_validator: Some(RgbValidator::canned(validated_consignment(txid), 50.0)),
        evm_rpc_client: Some(Box::new(stub_deposit())),
        evm_rpc_config: EvmRpcConfig::default(),
        header_chain: regtest_header_chain(),
        submit_rate_limiter: std::sync::Mutex::new(SubmitRateLimiter::default()),
    };

    let request = deposit_request(psbt_bytes);
    handle_connection(DeadCaller(Cursor::new(framed(&request))), &ctx);

    match respond(&ctx, &request).response {
        Some(Response::SignedPsbt(r)) => assert_eq!(r.inputs_signed, 1),
        other => panic!(
            "the retry of an undelivered signature must be signed, got {:?}",
            other
        ),
    }
}
