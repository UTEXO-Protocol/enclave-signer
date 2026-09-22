//! The send-RGB txid bind assumes every input finalizes with an empty
//! `scriptSig`. A P2SH-wrapped SegWit input pushes its redeemScript there
//! (BIP-16), which changes the txid, so the broadcastable tx is not the one
//! the consignment names.
//!
//! Runs through the wire and `handle_sign`: the bridge-location pin, the
//! `FundsIn` read and the invoice bind are all on the path. Issues a BFA
//! asset over regtest funding transactions. Mint-burn lane only.
#![cfg(all(feature = "rgb-mint-burn", feature = "bfa-validation"))]

use std::io::{Cursor, Read, Write};
use std::sync::Mutex;

use alloy_sol_types::{sol, SolEvent};
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL, OP_RETURN};
use bitcoin::blockdata::script::{Builder, PushBytesBuf};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use rgbinvoice::{Beneficiary, RgbInvoiceBuilder, XChainNet};
use rgbstd::containers::{
    BuilderSeal, ConsignmentExt, ContainerVer, FileContent, Transfer, WitnessBundle,
};
use rgbstd::contract::{AllocatedState, ContractBuilder, IssuerWrapper, TransitionBuilder};
use rgbstd::opret::{OpretFirst, OpretProof};
use rgbstd::persistence::{MemContract, MemContractState};
use rgbstd::rgbcore::commit_verify::mpc::{
    Commitment, MerkleBlock, MerkleTree, Message as MpcMessage, MultiSource, ProtocolId,
};
use rgbstd::rgbcore::commit_verify::{CommitId, EmbedCommitVerify, TryCommitVerify};
use rgbstd::stl::{AssetSpec, ContractTerms, RicardianContract};
use rgbstd::validation::{
    DbcProof, Failure, ResolveWitness, ValidationConfig, ValidationError, WitnessResolverError,
    WitnessStatus,
};
use rgbstd::vm::ether_extension::{BridgeLocation, BridgedContract, Event, IssuedAmountCheckExt};
use rgbstd::vm::WitnessOrd;
use rgbstd::{
    Amount as RgbAmount, Anchor, ChainNet, ContractId, GenesisSeal, GraphSeal, Identity,
    KnownTransition, OpId, Operation, Opout, Precision, PubWitness, RevealedValue,
};
use schemata::{BridgedFungibleAsset, OS_BRIDGE};
use sha3::{Digest, Keccak256};
use utexo_bridge_enclave::config::{BridgeConfig, EvmRpcConfig};
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::keys::{AccountType, KeyManager};
use utexo_bridge_enclave::networks::evm::evm_event::{EvmReceiptProvider, LogEntry, ReceiptData};
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network as SpvNet};
use utexo_bridge_enclave::networks::rgb::validation::RgbValidator;
use utexo_bridge_enclave::policy::{BuildContext, EvmDataSource, SecurityPolicy};
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::{
    EnclaveRequest, EnclaveResponse, EvmSource, RgbDestination, SignRequest,
};
use utexo_bridge_enclave::server::{self, ServerContext, SubmitRateLimiter};
use utexo_bridge_enclave::state::EnclaveState;

const SEED: [u8; 64] = [0x42; 64];
/// The bridge entry contract: pinned in the enclave and written into genesis.
const FUNDS_IN_CONTRACT: [u8; 20] = [0xB1; 20];
const DEPOSIT_TX: [u8; 32] = [0x11; 32];
const OPERATION_ID: [u8; 32] = [0xF7; 32];
const MINTED: u64 = 100_000;
const BRIDGE_FUNDS: u64 = 10_000;
const BRIDGE_CHANGE: u64 = 9_700;
const AUX_FUNDS: u64 = 2_000;
const USER_FUNDS: u64 = 1_000;
/// Unspendable internal key, as the bridge's addresses use.
const NUMS_INTERNAL: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

// The two logs `handle_sign` reads from the deposit receipt, in the shape
// `IBridge.sol` emits them.
sol! {
    event FundsIn(address indexed sender, uint256 rgbOpId, uint64 amount);
    event BridgeFundsIn(
        bytes32 indexed operationId, bytes32 indexed sourceTx, address indexed sender,
        uint256 senderNonce, uint256 amount, uint256 netAmount, uint256 tokenCommission,
        uint256 nativeCommission, uint256 sourceChainId, uint256 destinationChainId,
        string destinationAddress
    );
}

fn foreign(b: u8) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[b; 32]).unwrap())
}

/// Our Colored key at m/86'/827167'/0'/0/0, the account a deposit is signed under.
fn colored_key(keys: &KeyManager) -> (XOnlyPublicKey, DerivationPath) {
    let child = [ChildNumber::from(0), ChildNumber::from(0)];
    let sk = keys.derive_btc_child(AccountType::Colored, &child).unwrap();
    let xonly = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&Secp256k1::new(), &sk)).0;
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(86).unwrap(),
        ChildNumber::from_hardened_idx(827167).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
        child[0],
        child[1],
    ]);
    (xonly, path)
}

/// A 2-of-3 `multi_a` taproot output over `keys` behind the NUMS internal key.
struct Leaf {
    spk: ScriptBuf,
    script: ScriptBuf,
    hash: TapLeafHash,
    control: ControlBlock,
    keys: [XOnlyPublicKey; 3],
}

fn multisig_2_of_3(mut keys: [XOnlyPublicKey; 3]) -> Leaf {
    let secp = Secp256k1::new();
    keys.sort();
    let script = Builder::new()
        .push_x_only_key(&keys[0])
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&keys[1])
        .push_opcode(OP_CHECKSIGADD)
        .push_x_only_key(&keys[2])
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUAL)
        .into_script();
    let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
    let info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    Leaf {
        spk: ScriptBuf::new_p2tr(&secp, internal, info.merkle_root()),
        hash: TapLeafHash::from_script(&script, LeafVersion::TapScript),
        control: info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap(),
        script,
        keys,
    }
}

/// A regtest coinbase paying `value` to `spk` at output 0. `height` keeps the
/// txids distinct.
fn coinbase(height: i64, value: u64, spk: ScriptBuf) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Builder::new().push_int(height).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        }],
    }
}

/// The BIP-16 `scriptSig` of a P2SH-wrapped input: one push of the redeemScript.
fn push_redeem(redeem: &ScriptBuf) -> ScriptBuf {
    Builder::new()
        .push_slice(PushBytesBuf::try_from(redeem.to_bytes()).unwrap())
        .into_script()
}

fn spend(funding: &Transaction) -> TxIn {
    TxIn {
        previous_output: OutPoint::new(funding.compute_txid(), 0),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

/// The auxiliary input under test: P2SH-wrapped P2WPKH with its own funding.
/// Its only consensus-valid finalization pushes the redeemScript into `scriptSig`.
struct Aux {
    funding: Transaction,
    redeem: ScriptBuf,
    key: Keypair,
}

fn wrapped_segwit_aux() -> Aux {
    let key = foreign(0xC1);
    let pk = bitcoin::PublicKey::new(key.public_key());
    let redeem = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap());
    let funding = coinbase(102, AUX_FUNDS, ScriptBuf::new_p2sh(&redeem.script_hash()));
    Aux {
        funding,
        redeem,
        key,
    }
}

/// One BFA deposit, as the coordinator hands it to the enclave.
struct Deposit {
    consignment: Vec<u8>,
    witness_tx: Transaction,
    contract_id: ContractId,
    mint_opid: OpId,
    invoice: String,
    events: Vec<Event>,
    user_funding: Transaction,
}

/// Issues a BFA asset whose mint right sits on `bridge_funding:0`. Mints
/// `MINTED` units to the user's blinded seal via a `Bridge` transition
/// anchored in a witness tx that spends that right and `aux`, if any, and
/// rolls the right forward onto the bridge's change output.
fn issue_and_mint(
    bridge_funding: &Transaction,
    bridge_spk: &ScriptBuf,
    aux: Option<&Aux>,
) -> Deposit {
    let location = format!("0x{}", hex::encode(FUNDS_IN_CONTRACT));
    let contract = ContractBuilder::with(
        Identity::default(),
        BridgedFungibleAsset::schema(),
        BridgedFungibleAsset::types(),
        BridgedFungibleAsset::scripts(),
        ChainNet::BitcoinRegtest,
    )
    .add_global_state(
        "spec",
        AssetSpec::new("BUSDT", "Bridged USDT", Precision::Micro),
    )
    .unwrap()
    .add_global_state(
        "terms",
        ContractTerms {
            text: RicardianContract::default(),
            media: None,
        },
    )
    .unwrap()
    .add_global_state(
        "bridgeLocation",
        BridgeLocation::Ethereum(location.as_str().try_into().unwrap()),
    )
    .unwrap()
    .add_rights(
        "bridgeRight",
        GenesisSeal::with_blinding(bridge_funding.compute_txid(), 0u32, 0x1111),
    )
    .unwrap()
    .issue_contract_raw(1_700_000_000)
    .unwrap()
    .into_consignment();
    let contract_id = contract.contract_id();
    let mint_right = Opout::new(contract.genesis.id(), OS_BRIDGE, 0);

    // The recipient: a blinded seal on a UTXO the user already holds.
    let user_spk =
        ScriptBuf::new_p2tr(&Secp256k1::new(), foreign(0xD1).x_only_public_key().0, None);
    let user_funding = coinbase(103, USER_FUNDS, user_spk);
    let secret =
        GraphSeal::with_blinding(user_funding.compute_txid(), 0u32, 0x2222).to_secret_seal();

    let transition = TransitionBuilder::named_transition(
        contract_id,
        BridgedFungibleAsset::schema(),
        "bridge",
        BridgedFungibleAsset::types(),
    )
    .unwrap()
    .add_input(mint_right, AllocatedState::Void)
    .unwrap()
    .add_global_state("bridgedSupply", RgbAmount::from(MINTED))
    .unwrap()
    .add_fungible_state("assetOwner", BuilderSeal::Concealed(secret), MINTED)
    .unwrap()
    .add_rights("bridgeRight", GraphSeal::with_blinded_vout(1u32, 0x3333))
    .unwrap()
    .complete_transition()
    .unwrap();
    let mint_opid = transition.id();

    // amplify's non-empty containers cannot be named from this crate, so the
    // bundle and terminal of an in-tree consignment are retyped: every entry
    // is replaced, none is read.
    let donor = Transfer::load(Cursor::new(include_bytes!(
        "fixtures/transfer_consignment.rgbc"
    )))
    .unwrap();
    let mut bundle = donor.bundles.iter().next().unwrap().bundle.clone();
    bundle.input_map.insert(mint_right, mint_opid).unwrap();
    for stale in bundle.input_map.keys().copied().collect::<Vec<_>>() {
        if stale != mint_right {
            bundle.input_map.remove(&stale).unwrap();
        }
    }
    bundle
        .known_transitions
        .push(KnownTransition::new(mint_opid, transition))
        .unwrap();
    while bundle.known_transitions.len() > 1 {
        bundle.known_transitions.remove(0).unwrap();
    }
    let bundle_id = bundle.bundle_id();
    let mut terminal = donor.terminals.values().next().unwrap().clone();
    terminal.push(secret).unwrap();
    for stale in terminal.iter().copied().collect::<Vec<_>>() {
        if stale != secret {
            terminal.remove(&stale).unwrap();
        }
    }

    let mut witness_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![spend(bridge_funding)],
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
            },
            TxOut {
                value: Amount::from_sat(BRIDGE_CHANGE),
                script_pubkey: bridge_spk.clone(),
            },
        ],
    };
    if let Some(aux) = aux {
        witness_tx.input.push(spend(&aux.funding));
    }

    // LNPBP-4 commitment to the bundle, embedded in the OP_RETURN output.
    let mut source = MultiSource {
        static_entropy: Some(0x5eed),
        ..Default::default()
    };
    source
        .messages
        .insert(ProtocolId::from(contract_id), MpcMessage::from(bundle_id))
        .unwrap();
    let tree = MerkleTree::try_commit(&source).unwrap();
    let commitment = tree.commit_id();
    let mpc_proof = MerkleBlock::from(tree)
        .to_merkle_proof(ProtocolId::from(contract_id))
        .unwrap();
    let opret: OpretProof =
        <Transaction as EmbedCommitVerify<Commitment, OpretFirst>>::embed_commit(
            &mut witness_tx,
            &commitment,
        )
        .unwrap();

    let mut transfer = Transfer {
        version: ContainerVer::V0,
        transfer: true,
        terminals: Default::default(),
        genesis: contract.genesis,
        bundles: Default::default(),
        schema: contract.schema,
        types: contract.types,
        scripts: contract.scripts,
    };
    transfer
        .bundles
        .push(WitnessBundle {
            pub_witness: PubWitness::with(witness_tx.clone()),
            anchor: Anchor::new(mpc_proof, DbcProof::Opret(opret)),
            bundle,
        })
        .unwrap();
    transfer.terminals.insert(bundle_id, terminal).unwrap();
    let mut consignment = Vec::new();
    transfer.save(&mut consignment).unwrap();

    let invoice = RgbInvoiceBuilder::with(
        contract_id,
        XChainNet::with(ChainNet::BitcoinRegtest, Beneficiary::BlindedSeal(secret)),
    )
    .finish()
    .to_string();

    Deposit {
        consignment,
        witness_tx,
        contract_id,
        mint_opid,
        invoice,
        events: vec![Event::new(mint_opid, RevealedValue::from(MINTED))],
        user_funding,
    }
}

fn log<E: SolEvent>(event: &E) -> LogEntry {
    LogEntry {
        address: FUNDS_IN_CONTRACT,
        topics: event.encode_topics().into_iter().map(|t| t.0 .0).collect(),
        data: event.encode_data(),
    }
}

/// The receipt of the EVM deposit: `FundsIn` naming the mint's OpId and
/// `BridgeFundsIn` carrying the invoice, both from the pinned contract. What
/// the enclave reads instead of trusting the listener.
fn deposit_receipt(mint_opid: &OpId, invoice: &str) -> ReceiptData {
    let opid = alloy_primitives::B256::from_slice(&hex::decode(mint_opid.to_string()).unwrap());
    let funds_in = FundsIn {
        sender: [0xde; 20].into(),
        rgbOpId: alloy_primitives::U256::from_be_bytes(opid.0),
        amount: MINTED,
    };
    let bridge_funds_in = BridgeFundsIn {
        operationId: OPERATION_ID.into(),
        sourceTx: [0x5c; 32].into(),
        sender: [0xde; 20].into(),
        senderNonce: alloy_primitives::U256::ZERO,
        amount: alloy_primitives::U256::from(MINTED),
        netAmount: alloy_primitives::U256::from(MINTED),
        tokenCommission: alloy_primitives::U256::ZERO,
        nativeCommission: alloy_primitives::U256::ZERO,
        sourceChainId: alloy_primitives::U256::ZERO,
        destinationChainId: alloy_primitives::U256::ZERO,
        destinationAddress: invoice.into(),
    };
    ReceiptData {
        status_success: true,
        block_number: 100,
        logs: vec![log(&funds_in), log(&bridge_funds_in)],
    }
}

struct DepositChain(ReceiptData);

impl EvmReceiptProvider for DepositChain {
    fn get_transaction_receipt(
        &self,
        tx_hash: &[u8; 32],
    ) -> utexo_bridge_enclave::error::Result<Option<ReceiptData>> {
        Ok((*tx_hash == DEPOSIT_TX).then(|| self.0.clone()))
    }
    fn get_block_number(&self) -> utexo_bridge_enclave::error::Result<u64> {
        Ok(112)
    }
}

/// Stub Esplora for a regtest validator: the genesis hash for the chain
/// identity check and an empty fee-estimate map (regtest has no fee market).
fn spawn_regtest_stub() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = if req.starts_with("GET /block-height/0") {
                bitcoin::constants::genesis_block(Network::Regtest)
                    .block_hash()
                    .to_string()
            } else if req.starts_with("GET /fee-estimates") {
                "{}".to_string()
            } else {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n");
                continue;
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    format!("http://{addr}")
}

/// A production-shaped context: pinned bridge config, real validator, the
/// deposit's receipt behind the EVM client, keys from `SEED`.
fn context(contract_id: &ContractId, receipt: ReceiptData) -> ServerContext {
    let state = EnclaveState::new(Network::Regtest);
    state.initialize_from_seed(SEED).unwrap();
    let bridge_config = BridgeConfig {
        chain_id: 1,
        bridge_contract: [0x11; 20],
        funds_in_contract: FUNDS_IN_CONTRACT,
        rgb_asset_id: contract_id.to_string(),
        rgb_max_unowned_sats: 1_000,
        ..Default::default()
    };
    let policy = SecurityPolicy::resolve(
        &BuildContext::current(),
        &bridge_config,
        EvmDataSource::Disabled,
        None,
    );
    ServerContext {
        state,
        bridge_config,
        policy,
        rgb_validator: Some(RgbValidator::new(spawn_regtest_stub(), "regtest").unwrap()),
        evm_rpc_client: Some(Box::new(DepositChain(receipt))),
        evm_rpc_config: EvmRpcConfig::default(),
        header_chain: Mutex::new(HeaderChain::new(
            SpvNet::Regtest,
            checkpoint_for(SpvNet::Regtest),
        )),
        submit_rate_limiter: Mutex::new(SubmitRateLimiter::default()),
    }
}

/// One framed request in, one framed response out, as over vsock. The cursor
/// is read to its end and the response appended after it.
fn sign_over_the_wire(ctx: &ServerContext, req: SignRequest) -> EnclaveResponse {
    let mut wire = Cursor::new(Vec::new());
    let request = EnclaveRequest {
        request: Some(Request::Sign(req)),
    };
    framing::write_message(&mut wire, &request).unwrap();
    let request_len = wire.position();
    wire.set_position(0);
    server::handle_connection(&mut wire, ctx);
    wire.set_position(request_len);
    framing::read_message(&mut wire).unwrap()
}

struct Built {
    psbt: Psbt,
    deposit: Deposit,
    bridge_funding: Transaction,
    leaf: Leaf,
    our: XOnlyPublicKey,
}

/// One deposit as the coordinator would hand it over. The bridge's input is
/// the 2-of-3 leaf on its funding output; `aux`, if any, is appended.
fn build(aux: Option<&Aux>) -> Built {
    let keys = KeyManager::from_seed(SEED, Network::Regtest).unwrap();
    let (our, our_path) = colored_key(&keys);
    let leaf = multisig_2_of_3([
        our,
        foreign(0xA1).x_only_public_key().0,
        foreign(0xA2).x_only_public_key().0,
    ]);
    let bridge_funding = coinbase(101, BRIDGE_FUNDS, leaf.spk.clone());
    let deposit = issue_and_mint(&bridge_funding, &leaf.spk, aux);

    let mut psbt = Psbt::from_unsigned_tx(deposit.witness_tx.clone()).unwrap();
    psbt.inputs[0].witness_utxo = Some(bridge_funding.output[0].clone());
    psbt.inputs[0].non_witness_utxo = Some(bridge_funding.clone());
    psbt.inputs[0].tap_internal_key = Some(leaf.control.internal_key);
    psbt.inputs[0].tap_scripts.insert(
        leaf.control.clone(),
        (leaf.script.clone(), LeafVersion::TapScript),
    );
    psbt.inputs[0].tap_key_origins.insert(
        our,
        (vec![leaf.hash], (*keys.master_fingerprint(), our_path)),
    );
    if let Some(aux) = aux {
        psbt.inputs[1].witness_utxo = Some(aux.funding.output[0].clone());
        psbt.inputs[1].non_witness_utxo = Some(aux.funding.clone());
        psbt.inputs[1].redeem_script = Some(aux.redeem.clone());
    }

    Built {
        psbt,
        deposit,
        bridge_funding,
        leaf,
        our,
    }
}

/// The built deposit through the front door, over the wire.
fn drive(built: &Built) -> EnclaveResponse {
    let request = SignRequest {
        amount: MINTED,
        source_network: Some(SourceNetwork::EvmSource(EvmSource {
            tx_hash: DEPOSIT_TX.to_vec(),
            event_valid: true,
            event_finalized: true,
            token: Vec::new(),
            recipient: Vec::new(),
            commission: 0,
            funds_in_operation_id: OPERATION_ID.to_vec(),
        })),
        destination_network: Some(DestinationNetwork::RgbDestination(RgbDestination {
            operation_idx: 0,
            psbt_bytes: built.psbt.serialize(),
            psbt_output_amount: 0,
            asset_id: built.deposit.contract_id.to_string(),
            consignment: built.deposit.consignment.clone(),
            consignment_hash: Keccak256::digest(&built.deposit.consignment).to_vec(),
            mint_ancestors: Vec::new(),
        })),
    };
    let ctx = context(
        &built.deposit.contract_id,
        deposit_receipt(&built.deposit.mint_opid, &built.deposit.invoice),
    );
    sign_over_the_wire(&ctx, request)
}

fn signed_psbt(response: &EnclaveResponse) -> Result<(Psbt, u32), String> {
    match &response.response {
        Some(Response::SignedPsbt(r)) => {
            Ok((Psbt::deserialize(&r.signed_psbt).unwrap(), r.inputs_signed))
        }
        Some(Response::Error(e)) => Err(e.message.clone()),
        other => panic!("unexpected response: {other:?}"),
    }
}

/// Our leaf signature on input 0, from the same seed the enclave holds. Lets a
/// test build the transaction a finalizer would broadcast even on a build where
/// the enclave refuses to sign the PSBT.
fn sign_ours(psbt: &mut Psbt, built: &Built) {
    let secp = Secp256k1::new();
    let keys = KeyManager::from_seed(SEED, Network::Regtest).unwrap();
    let child = [ChildNumber::from(0), ChildNumber::from(0)];
    let sk = keys.derive_btc_child(AccountType::Colored, &child).unwrap();
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    let sighash = SighashCache::new(psbt.unsigned_tx.clone())
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            built.leaf.hash,
            TapSighashType::Default,
        )
        .unwrap();
    let signature = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(*sighash.as_byte_array()),
        &Keypair::from_secret_key(&secp, &sk),
    );
    psbt.inputs[0].tap_script_sigs.insert(
        (built.our, built.leaf.hash),
        bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        },
    );
}

/// Completes the PSBT as a finalizer would: a co-signer's second leaf
/// signature, the auxiliary input's own signature. Extracts the transaction
/// and re-verifies it: the control block commits to the leaf, two leaf
/// signatures verify, and the pushed redeemScript's P2WPKH signature verifies.
fn finalize(signed: &Psbt, leaf: &Leaf, our: XOnlyPublicKey, aux: Option<&Aux>) -> Transaction {
    let secp = Secp256k1::new();
    let cosigner = foreign(0xA1);
    let mut psbt = signed.clone();
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .zip(&psbt.unsigned_tx.input)
        .map(|(input, txin)| {
            let funding = input.non_witness_utxo.as_ref().unwrap();
            assert_eq!(funding.compute_txid(), txin.previous_output.txid);
            let prevout = funding.output[txin.previous_output.vout as usize].clone();
            assert_eq!(input.witness_utxo.as_ref(), Some(&prevout));
            prevout
        })
        .collect();

    let mut cache = SighashCache::new(psbt.unsigned_tx.clone());
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf.hash,
            TapSighashType::Default,
        )
        .unwrap();
    let ours = psbt.inputs[0].tap_script_sigs[&(our, leaf.hash)];
    assert_eq!(ours.sighash_type, TapSighashType::Default);
    let theirs =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(*sighash.as_byte_array()), &cosigner);
    // `multi_a` consumes signatures in reverse key order; an absent signer
    // contributes an empty element.
    let mut witness = Witness::new();
    for k in leaf.keys.iter().rev() {
        if *k == our {
            witness.push(ours.to_vec());
        } else if *k == cosigner.x_only_public_key().0 {
            witness.push(theirs.as_ref());
        } else {
            witness.push([]);
        }
    }
    witness.push(leaf.script.as_bytes());
    witness.push(leaf.control.serialize());
    psbt.inputs[0].final_script_witness = Some(witness);

    if let Some(aux) = aux {
        let sighash = cache
            .p2wpkh_signature_hash(1, &aux.redeem, prevouts[1].value, EcdsaSighashType::All)
            .unwrap();
        let sig = bitcoin::ecdsa::Signature::sighash_all(secp.sign_ecdsa(
            &Message::from_digest(*sighash.as_byte_array()),
            &aux.key.secret_key(),
        ));
        psbt.inputs[1].final_script_witness = Some(Witness::p2wpkh(&sig, &aux.key.public_key()));
        psbt.inputs[1].final_script_sig = Some(push_redeem(&aux.redeem));
    }
    let tx = psbt.extract_tx().unwrap();

    let mut cache = SighashCache::new(&tx);
    let output_key =
        XOnlyPublicKey::from_slice(&prevouts[0].script_pubkey.as_bytes()[2..]).unwrap();
    let w = tx.input[0].witness.to_vec();
    let control = ControlBlock::decode(&w[4]).unwrap();
    let script = ScriptBuf::from_bytes(w[3].clone());
    assert!(control.verify_taproot_commitment(&secp, output_key, &script));
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap();
    let msg = Message::from_digest(*sighash.as_byte_array());
    let valid = leaf
        .keys
        .iter()
        .rev()
        .zip(&w)
        .filter(|(_, item)| !item.is_empty())
        .map(|(k, item)| {
            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(item).unwrap();
            secp.verify_schnorr(&sig, &msg, k).unwrap();
        })
        .count();
    assert_eq!(valid, 2, "2-of-3 threshold on the final tx");
    if tx.input.len() > 1 {
        let w = tx.input[1].witness.to_vec();
        let pubkey = bitcoin::PublicKey::from_slice(&w[1]).unwrap();
        let redeem = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());
        assert_eq!(
            prevouts[1].script_pubkey,
            ScriptBuf::new_p2sh(&redeem.script_hash())
        );
        assert_eq!(tx.input[1].script_sig, push_redeem(&redeem));
        let sighash = cache
            .p2wpkh_signature_hash(1, &redeem, prevouts[1].value, EcdsaSighashType::All)
            .unwrap();
        let sig = bitcoin::ecdsa::Signature::from_slice(&w[0]).unwrap();
        secp.verify_ecdsa(
            &Message::from_digest(*sighash.as_byte_array()),
            &sig.signature,
            &pubkey.inner,
        )
        .unwrap();
    }
    let funded: u64 = prevouts.iter().map(|o| o.value.to_sat()).sum();
    let paid: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    assert!(funded >= paid, "spends more than it is funded");
    tx
}

/// A consumer resolving witnesses against the transactions that exist.
struct ChainWith(Vec<Transaction>);

impl ResolveWitness for ChainWith {
    fn resolve_witness(&self, w: &PubWitness) -> Result<WitnessStatus, WitnessResolverError> {
        Ok(self
            .0
            .iter()
            .find(|tx| tx.compute_txid() == w.txid())
            .map_or(WitnessStatus::Unresolved, |tx| {
                WitnessStatus::Resolved(tx.clone(), WitnessOrd::Tentative)
            }))
    }
    fn check_chain_net(&self, _: ChainNet) -> Result<(), WitnessResolverError> {
        Ok(())
    }
}

/// What the RGB consumer sees when it validates the consignment the enclave
/// signed for against the chain as it is.
fn consumer_validates(deposit: &Deposit, chain: Vec<Transaction>) -> Result<(), ValidationError> {
    let transfer = Transfer::load(Cursor::new(&deposit.consignment)).unwrap();
    let schema = transfer.schema.clone();
    let config = ValidationConfig {
        chain_net: ChainNet::BitcoinRegtest,
        trusted_typesystem: BridgedFungibleAsset::types(),
        build_opouts_dag: true,
        ..Default::default()
    };
    transfer
        .validate_with_extension::<IssuedAmountCheckExt, BridgedContract<'_, MemContract<MemContractState>>>(
            &ChainWith(chain),
            &config,
            ((&schema, deposit.contract_id), &deposit.events),
        )
        .map(|_| ())
}

fn bound_witness(consignment: &[u8]) -> Txid {
    Transfer::load(Cursor::new(consignment))
        .unwrap()
        .bundles
        .iter()
        .last()
        .unwrap()
        .witness_id()
}

/// Control: the bridge's native input alone. Signed through the front door,
/// finalized to the bound txid, valid for the consumer against the chain that
/// carries it. What the gate must keep working.
#[test]
fn native_deposit_signs_and_finalizes_to_the_bound_txid() {
    let native = build(None);
    let (signed, inputs_signed) = signed_psbt(&drive(&native)).expect("native deposit signs");
    assert_eq!(inputs_signed, 1);
    let bound = native.psbt.unsigned_tx.compute_txid();
    assert_eq!(bound_witness(&native.deposit.consignment), bound);
    let final_tx = finalize(&signed, &native.leaf, native.our, None);
    assert_eq!(final_tx.compute_txid(), bound);
    consumer_validates(
        &native.deposit,
        vec![
            native.bridge_funding.clone(),
            native.deposit.user_funding.clone(),
            final_tx,
        ],
    )
    .expect("consumer resolves the bound witness");
}

/// The same deposit plus one P2SH-P2WPKH input. The enclave must refuse it;
/// on the base it signed, which is what made the mismatch reachable.
#[test]
fn refuses_input_whose_finalized_script_sig_changes_the_bound_txid() {
    let aux = wrapped_segwit_aux();
    let wrapped = build(Some(&aux));
    let bound = wrapped.psbt.unsigned_tx.compute_txid();
    assert_eq!(bound_witness(&wrapped.deposit.consignment), bound);
    let refusal = match signed_psbt(&drive(&wrapped)) {
        Err(reason) => reason,
        Ok(_) => panic!(
            "enclave bound the consignment to witness {bound} and signed, but every \
             consensus-valid finalization of that PSBT has another txid"
        ),
    };
    assert!(
        refusal.contains("scriptSig"),
        "refused for another reason: {refusal}"
    );
}

/// The consequence the refusal exists for: a finalizer's broadcast tx has a
/// different txid, so a consumer cannot resolve the witness the consignment
/// names. The leaf signature is produced locally from the enclave's seed, so
/// the evidence does not depend on the enclave signing.
#[test]
fn finalized_wrapped_input_leaves_the_bound_witness_unresolvable() {
    let aux = wrapped_segwit_aux();
    let wrapped = build(Some(&aux));
    let bound = wrapped.psbt.unsigned_tx.compute_txid();
    assert_eq!(bound_witness(&wrapped.deposit.consignment), bound);

    let mut psbt = wrapped.psbt.clone();
    sign_ours(&mut psbt, &wrapped);
    let final_tx = finalize(&psbt, &wrapped.leaf, wrapped.our, Some(&aux));
    assert_ne!(final_tx.compute_txid(), bound);

    let err = consumer_validates(
        &wrapped.deposit,
        vec![
            wrapped.bridge_funding.clone(),
            aux.funding.clone(),
            wrapped.deposit.user_funding.clone(),
            final_tx,
        ],
    )
    .unwrap_err();
    assert!(
        matches!(err, ValidationError::InvalidConsignment(Failure::SealNoPubWitness(_, w)) if w == bound),
        "expected SealNoPubWitness({bound}), got: {err:?}"
    );
}
