//! A BFA mint over the wire, end to end, and the txid bind.
//!
//! The mint signer reads the mint from the PSBT rgb-lib commits and the PSBT
//! of the issuer's seed send that made its right. The txid bind assumes every
//! input finalizes with an empty `scriptSig`. A P2SH-wrapped SegWit input
//! pushes its redeemScript there (BIP-16), which changes the txid, so the
//! broadcastable tx is not the one the PSBT commits.
//!
//! Runs over the wire through `handle_sign`, so the `FundsIn` read with its
//! finality, the invoice bind, the mint-right rule and the parent proof are on
//! the path. A receiving consumer then validates the consignment in full.
//! Mint/burn flow only.
// A full mint over the wire: the EVM -> RGB direction.
#![cfg(all(feature = "rgb-mint-burn", feature = "bfa-validation", evm_to_rgb))]

// Shared with the unit tests; this file uses only the mint half.
#[allow(dead_code)]
#[path = "../src/test_support/bfa_consignment.rs"]
mod bfa_consignment;

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use alloy_sol_types::{sol, SolCall, SolEvent};
use bfa_consignment::Committed;
use bfa_consignment::{History, Issue, Utxo};
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::blockdata::script::{Builder, PushBytesBuf};
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use rgbinvoice::{Beneficiary, RgbInvoiceBuilder, XChainNet};
use rgbstd::containers::{
    AnchorResolverError, ConsignmentExt, FileContent, ResolveAnchor, Transfer,
};
use rgbstd::contract::IssuerWrapper;
use rgbstd::stl::{BridgeLocation, RejectListLocation};
use rgbstd::validation::{
    ExternalAnchor, Failure, ResolveWitness, ValidationConfig, ValidationError,
    WitnessResolverError, WitnessStatus,
};
use rgbstd::vm::WitnessOrd;
use rgbstd::{BuilderSeal, ChainNet, ContractId, GraphSeal, OpId, Opout};
use schemata::BridgedFungibleAsset;
use sha3::{Digest, Keccak256};
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::keys::{AccountType, KeyManager};
use utexo_bridge_enclave::networks::evm::events::{EvmReceiptProvider, LogEntry, ReceiptData};
use utexo_bridge_enclave::networks::evm::reject_list::{entriesCall, lengthCall, Entry};
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network as SpvNet};
use utexo_bridge_enclave::policy::{BuildContext, EvmDataSource, SecurityPolicy};
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::{
    EnclaveRequest, EnclaveResponse, EvmSource, RgbDestination, SignRequest,
};
use utexo_bridge_enclave::server::{self, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;

const SEED: [u8; 64] = [0x42; 64];
/// The bridge entry contract: pinned in the enclave and written into genesis.
const FUNDS_IN_CONTRACT: [u8; 20] = [0xB1; 20];
/// `EVM_CHAIN_ID` of the enclave and the chain in genesis.
const EVM_CHAIN_ID: u64 = 1;
const DEPOSIT_TX: [u8; 32] = [0x11; 32];
const TOKEN_CONTRACT: [u8; 20] = [0x7E; 20];
const MINTED: u64 = 100_000;
/// The mint's `beforeBlock`. The lock is at `LOCK_BLOCK`, which the node's
/// `EVM_FINALITY_TAG` head covers.
const BEFORE_BLOCK: u64 = 110;
const LOCK_BLOCK: u64 = 100;
const BRIDGE_FUNDS: u64 = 10_000;
const BRIDGE_CHANGE: u64 = 9_700;
const AUX_FUNDS: u64 = 2_000;
const USER_FUNDS: u64 = 1_000;
/// The `IRgbRejectList` a listed asset names, on `EVM_CHAIN_ID`.
const LIST: [u8; 20] = [0x4e; 20];

// The two logs `handle_sign` reads from the deposit receipt, in the shape
// `IBridge.sol` emits them.
sol! {
    event FundsIn(address indexed sender, uint256 indexed rgbOpId, uint64 amount);
    event BridgeFundsIn(
        bytes32 indexed operationId, bytes32 indexed sourceTx, address indexed sender,
        uint256 senderNonce, uint256 amount, uint256 netAmount, uint256 tokenCommission,
        uint256 nativeCommission, uint256 sourceChainId, uint256 destinationChainId,
        string destinationAddress, bytes settlementData
    );
}

fn foreign(b: u8) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[b; 32]).unwrap())
}

/// Our Colored key at m/86'/827167'/0'/0/0. A deposit is signed under it.
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

/// The bridge's own BIP-86 key-path address for `our` key.
fn bridge_address(our: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr(&Secp256k1::new(), our, None)
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
    /// The issuer's seed send. Its PSBT is the mint's parent proof.
    seed: Committed,
    mint: Committed,
    contract_id: ContractId,
    /// The seeded right the mint spent.
    right: Opout,
    invoice: String,
    user_funding: Transaction,
}

/// Issues a BFA asset, with `reject_list` if any. The issuer seeds its right
/// to the bridge's key-path output (`bridge_spk`, vout 1 of the seed). A
/// `mint` gives `MINTED` units to the user's blinded seal. Its witness tx
/// spends the right and `aux` (if any). The mint consumes the right, or in the
/// old form (`keeps_right`) passes it on to the bridge change.
fn issue_and_mint(
    bridge_spk: &ScriptBuf,
    aux: Option<&Aux>,
    reject_list: Option<RejectListLocation>,
    keeps_right: bool,
) -> Deposit {
    let issuer_utxo = OutPoint::new(Txid::from_byte_array([0x15; 32]), 0);
    let mut history = History::issue(Issue {
        reject_list,
        ..Issue::new(EVM_CHAIN_ID, FUNDS_IN_CONTRACT, vec![issuer_utxo])
    });
    let genesis_right = history.genesis_right(0, issuer_utxo);
    let seeded_to = TxOut {
        value: Amount::from_sat(BRIDGE_FUNDS),
        script_pubkey: bridge_spk.clone(),
    };
    let seed = history.send_rights(genesis_right, &[1], vec![], vec![seeded_to]);
    let right: Utxo = bfa_consignment::rights_made(&seed, &[1])[0];

    // The recipient: a blinded seal on a UTXO the user already holds.
    let user_spk =
        ScriptBuf::new_p2tr(&Secp256k1::new(), foreign(0xD1).x_only_public_key().0, None);
    let user_funding = coinbase(103, USER_FUNDS, user_spk);
    let secret =
        GraphSeal::with_blinding(user_funding.compute_txid(), 0u32, 0x2222).to_secret_seal();

    let extra = aux
        .map(|aux| vec![OutPoint::new(aux.funding.compute_txid(), 0)])
        .unwrap_or_default();
    let change = TxOut {
        value: Amount::from_sat(BRIDGE_CHANGE),
        script_pubkey: bridge_spk.clone(),
    };
    let to = BuilderSeal::Concealed(secret);
    let mint = if keeps_right {
        history
            .mint_keeping_right(right, MINTED, BEFORE_BLOCK, to, extra, vec![change])
            .0
    } else {
        history.mint(right, MINTED, BEFORE_BLOCK, to, extra, vec![change])
    };

    let invoice = RgbInvoiceBuilder::with(
        history.contract_id,
        XChainNet::with(ChainNet::BitcoinRegtest, Beneficiary::BlindedSeal(secret)),
    )
    .finish()
    .to_string();

    Deposit {
        consignment: history.consignment(),
        seed,
        mint,
        contract_id: history.contract_id,
        right: right.opout,
        invoice,
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

/// The EVM deposit receipt: `FundsIn` with the mint OpId and `BridgeFundsIn`
/// with the invoice, both from the pinned contract, at `block`. The enclave
/// reads this receipt and does not trust the listener.
fn deposit_receipt(
    mint_opid: &OpId,
    operation_id: [u8; 32],
    invoice: &str,
    block: u64,
) -> ReceiptData {
    let funds_in = FundsIn {
        sender: [0xde; 20].into(),
        rgbOpId: alloy_primitives::U256::from_be_bytes(bfa_consignment::opid_bytes(*mint_opid)),
        amount: MINTED,
    };
    let bridge_funds_in = BridgeFundsIn {
        operationId: operation_id.into(),
        sourceTx: [0x5c; 32].into(),
        sender: [0xde; 20].into(),
        senderNonce: alloy_primitives::U256::ZERO,
        amount: alloy_primitives::U256::from(MINTED),
        netAmount: alloy_primitives::U256::from(MINTED),
        tokenCommission: alloy_primitives::U256::ZERO,
        nativeCommission: alloy_primitives::U256::ZERO,
        sourceChainId: alloy_primitives::U256::ZERO,
        destinationChainId: alloy_primitives::U256::from(
            utexo_bridge_enclave::networks::evm::RGB_CHAIN_ID,
        ),
        destinationAddress: invoice.into(),
        settlementData: Default::default(),
    };
    ReceiptData {
        status_success: true,
        block_number: block,
        block_hash: [0x42; 32],
        logs: vec![log(&funds_in), log(&bridge_funds_in)],
    }
}

/// The EVM node: the deposit's receipt, the block its finality tag reports,
/// and the reject list at `LIST` as (opout, reject), all finalized.
struct DepositChain {
    receipt: ReceiptData,
    tagged_head: u64,
    list: Vec<(Opout, bool)>,
    /// The selector of each `eth_call` the enclave made.
    calls: Arc<Mutex<Vec<[u8; 4]>>>,
}

impl DepositChain {
    fn entries(&self, args: &[u8]) -> Vec<u8> {
        let call = entriesCall::abi_decode_raw(args).unwrap();
        let start = usize::try_from(call.start).unwrap();
        let end = usize::try_from(call.end).unwrap();
        let page: Vec<Entry> = self.list[start..end]
            .iter()
            .map(|(opout, reject)| Entry {
                opId: bfa_consignment::opid_bytes(opout.op).into(),
                assignmentType: amplify::Wrapper::to_inner(&opout.ty),
                no: opout.no,
                reject: *reject,
            })
            .collect();
        entriesCall::abi_encode_returns(&page)
    }
}

impl EvmReceiptProvider for DepositChain {
    fn get_transaction_receipt(
        &self,
        tx_hash: &[u8; 32],
    ) -> utexo_bridge_enclave::error::Result<Option<ReceiptData>> {
        Ok((*tx_hash == DEPOSIT_TX).then(|| self.receipt.clone()))
    }

    fn get_block_by_tag(
        &self,
        _tag: attestation_verify::EvmFinalityTag,
    ) -> utexo_bridge_enclave::error::Result<
        Option<utexo_bridge_enclave::networks::evm::events::BlockData>,
    > {
        self.get_block_by_number(self.tagged_head)
    }

    fn get_block_by_number(
        &self,
        number: u64,
    ) -> utexo_bridge_enclave::error::Result<
        Option<utexo_bridge_enclave::networks::evm::events::BlockData>,
    > {
        Ok(Some(
            utexo_bridge_enclave::networks::evm::events::BlockData {
                number,
                hash: self.receipt.block_hash,
            },
        ))
    }

    fn get_chain_id(&self) -> utexo_bridge_enclave::error::Result<u64> {
        Ok(EVM_CHAIN_ID)
    }

    fn call(
        &self,
        to: &[u8; 20],
        data: &[u8],
        _block: u64,
    ) -> utexo_bridge_enclave::error::Result<Vec<u8>> {
        assert_eq!(*to, LIST, "an eth_call to another contract");
        let selector: [u8; 4] = data[..4].try_into().unwrap();
        self.calls.lock().unwrap().push(selector);
        Ok(match selector {
            lengthCall::SELECTOR => {
                lengthCall::abi_encode_returns(&alloy_primitives::U256::from(self.list.len()))
            }
            entriesCall::SELECTOR => self.entries(&data[4..]),
            _ => panic!("unexpected eth_call selector 0x{}", hex::encode(selector)),
        })
    }
}

/// A production-shaped context: pinned bridge config, real validator, the
/// deposit's chain behind the EVM client, keys from `SEED`.
fn bridge_config(contract_id: &ContractId) -> BridgeConfig {
    BridgeConfig {
        chain_id: EVM_CHAIN_ID,
        bridge_contract: [0x11; 20],
        funds_in_contract: FUNDS_IN_CONTRACT,
        token_contract: TOKEN_CONTRACT,
        rgb_asset_id: contract_id.to_string(),
        rgb_max_unowned_sats: 1_000,
        ..Default::default()
    }
}

/// The operationId the Bridge derives for the deposit that backs this mint.
fn operation_id(deposit: &Deposit) -> [u8; 32] {
    utexo_bridge_enclave::networks::evm::events::rgb_mint_deposit_id(
        &bridge_config(&deposit.contract_id),
        &bfa_consignment::opid_bytes(deposit.mint.opid),
        MINTED,
    )
    .unwrap()
}

fn context(contract_id: &ContractId, chain: DepositChain) -> ServerContext {
    let state = EnclaveState::new(Network::Regtest);
    state.initialize_from_seed(SEED).unwrap();
    let bridge_config = bridge_config(contract_id);
    let policy = SecurityPolicy::resolve(
        &BuildContext::current(),
        &bridge_config,
        EvmDataSource::Disabled,
        None,
        "",
    );
    let mut ctx = ServerContext::new(
        state,
        bridge_config,
        Mutex::new(HeaderChain::new(
            SpvNet::Regtest,
            checkpoint_for(SpvNet::Regtest),
        )),
    );
    let launch = ctx.launch.get_mut().unwrap();
    launch.policy = policy;
    // No indexer: the mint signer reads no consignment.
    launch.evm_rpc_client = Some(Box::new(chain));
    ctx
}

/// One framed request in, one framed response out, as over vsock. The handler
/// writes the response after the request in the cursor.
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
}

/// One deposit as the coordinator would hand it over: the PSBT rgb-lib
/// committed, with the metadata it writes. The bridge's input is the seeded
/// right's output; `aux`, if any, is appended. The change is ours (rule C).
fn build_on(
    aux: Option<&Aux>,
    reject_list: Option<RejectListLocation>,
    keeps_right: bool,
) -> Built {
    let keys = KeyManager::from_seed(SEED, Network::Regtest).unwrap();
    let (our, our_path) = colored_key(&keys);
    let bridge_spk = bridge_address(our);
    let deposit = issue_and_mint(&bridge_spk, aux, reject_list, keeps_right);

    let origin = (vec![], (*keys.master_fingerprint(), our_path));
    let mut psbt = deposit.mint.psbt.clone();
    psbt.inputs[0].witness_utxo = Some(deposit.seed.tx.output[1].clone());
    psbt.inputs[0].non_witness_utxo = Some(deposit.seed.tx.clone());
    psbt.inputs[0].tap_internal_key = Some(our);
    psbt.inputs[0].tap_key_origins.insert(our, origin.clone());
    if let Some(aux) = aux {
        psbt.inputs[1].witness_utxo = Some(aux.funding.output[0].clone());
        psbt.inputs[1].non_witness_utxo = Some(aux.funding.clone());
        psbt.inputs[1].redeem_script = Some(aux.redeem.clone());
    }
    let change = psbt.outputs.len() - 1;
    psbt.outputs[change].tap_internal_key = Some(our);
    psbt.outputs[change].tap_key_origins.insert(our, origin);

    Built { psbt, deposit }
}

fn build(aux: Option<&Aux>) -> Built {
    build_on(aux, None, false)
}

/// The built deposit through the front door, over the wire, against a lock
/// at `lock_block` and a node whose finality tag reports `tagged_head`.
fn drive_with(built: &Built, lock_block: u64, tagged_head: u64) -> EnclaveResponse {
    let chain = deposit_chain(built, lock_block, tagged_head, vec![]);
    let ctx = context(&built.deposit.contract_id, chain);
    sign_over_the_wire(&ctx, sign_request(built))
}

/// The built deposit through the front door, the node holding `list`.
/// Returns the response and the selector of each `eth_call` made.
fn drive_listed(built: &Built, list: Vec<(Opout, bool)>) -> (EnclaveResponse, Vec<[u8; 4]>) {
    let chain = deposit_chain(built, LOCK_BLOCK, LOCK_BLOCK, list);
    let calls = Arc::clone(&chain.calls);
    let ctx = context(&built.deposit.contract_id, chain);
    let response = sign_over_the_wire(&ctx, sign_request(built));
    let calls = calls.lock().unwrap().clone();
    (response, calls)
}

fn deposit_chain(
    built: &Built,
    lock_block: u64,
    tagged_head: u64,
    list: Vec<(Opout, bool)>,
) -> DepositChain {
    DepositChain {
        receipt: deposit_receipt(
            &built.deposit.mint.opid,
            operation_id(&built.deposit),
            &built.deposit.invoice,
            lock_block,
        ),
        tagged_head,
        list,
        calls: Arc::default(),
    }
}

fn sign_request(built: &Built) -> SignRequest {
    SignRequest {
        amount: MINTED,
        source_network: Some(SourceNetwork::EvmSource(EvmSource {
            tx_hash: DEPOSIT_TX.to_vec(),
            event_valid: true,
            event_finalized: true,
            token: Vec::new(),
            recipient: Vec::new(),
            commission: 0,
            funds_in_operation_id: operation_id(&built.deposit).to_vec(),
        })),
        destination_network: Some(DestinationNetwork::RgbDestination(RgbDestination {
            operation_idx: 0,
            psbt_bytes: built.psbt.serialize(),
            psbt_output_amount: 0,
            asset_id: built.deposit.contract_id.to_string(),
            // The rollout bridge still sends the consignment; the mint signer
            // reads only the PSBT and its parent.
            consignment: built.deposit.consignment.clone(),
            consignment_hash: Keccak256::digest(&built.deposit.consignment).to_vec(),
            parent_psbt: built.deposit.seed.psbt.serialize(),
        })),
    }
}

fn drive(built: &Built) -> EnclaveResponse {
    drive_with(built, LOCK_BLOCK, LOCK_BLOCK)
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

/// Our key-path signature on input 0, from the enclave seed. A test can then
/// build the finalizer's broadcast tx even when the enclave refuses to sign.
fn sign_ours(psbt: &mut Psbt) {
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
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap();
    let tweaked = Keypair::from_secret_key(&secp, &sk).tap_tweak(&secp, None);
    let signature = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(*sighash.as_byte_array()),
        &tweaked.to_keypair(),
    );
    psbt.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::Default,
    });
}

/// Completes the PSBT as a finalizer does, with our key-path signature and the
/// auxiliary input signature. It extracts the tx and verifies both signatures.
fn finalize(signed: &Psbt, aux: Option<&Aux>) -> Transaction {
    let secp = Secp256k1::new();
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

    let ours = psbt.inputs[0].tap_key_sig.expect("our key-path signature");
    assert_eq!(ours.sighash_type, TapSighashType::Default);
    psbt.inputs[0].final_script_witness = Some(Witness::p2tr_key_spend(&ours));

    let mut cache = SighashCache::new(psbt.unsigned_tx.clone());
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
    assert_eq!(w.len(), 1, "a key-path spend carries one signature");
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap();
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&w[0]).unwrap();
    secp.verify_schnorr(
        &sig,
        &Message::from_digest(*sighash.as_byte_array()),
        &output_key,
    )
    .expect("key-path signature verifies on the final tx");
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
    fn resolve_witness(&self, witness_id: Txid) -> Result<WitnessStatus, WitnessResolverError> {
        Ok(self
            .0
            .iter()
            .find(|tx| tx.compute_txid() == witness_id)
            .map_or(WitnessStatus::Unresolved, |tx| {
                WitnessStatus::Resolved(tx.clone(), WitnessOrd::Tentative)
            }))
    }
    fn check_chain_net(&self, _: ChainNet) -> Result<(), WitnessResolverError> {
        Ok(())
    }
}

/// The consumer's view of the EVM chain: the deposit's `FundsIn` exists.
struct LockedOnChain(OpId);

impl ResolveAnchor for LockedOnChain {
    fn evm_chain_id(&self) -> Result<u64, AnchorResolverError> {
        Ok(EVM_CHAIN_ID)
    }
    fn is_confirmed(
        &self,
        _: &BridgeLocation,
        anchor: &ExternalAnchor,
    ) -> Result<bool, AnchorResolverError> {
        let ExternalAnchor::MintEvent { opid, amount, .. } = anchor;
        Ok(*opid == self.0 && *amount == MINTED)
    }
}

/// The RGB consumer result when it validates the signed consignment against
/// the given chain, as the release rgb-lib does.
fn consumer_validates(deposit: &Deposit, chain: Vec<Transaction>) -> Result<(), ValidationError> {
    let transfer = Transfer::load(Cursor::new(&deposit.consignment)).unwrap();
    let config = ValidationConfig {
        chain_net: ChainNet::BitcoinRegtest,
        safe_height: None,
        build_opouts_dag: true,
    };
    let mut pending =
        transfer.validate_deterministic(&BridgedFungibleAsset::schema_rules(), &config)?;
    let location = BridgedFungibleAsset::bridge_location(pending.consignment().genesis()).unwrap();
    pending
        .resolve_all_anchors(location, &LockedOnChain(deposit.mint.opid))
        .expect("the consumer confirms the mint against its lock");
    pending.pending().resolve_all(&ChainWith(chain))?;
    assert!(pending.pending().is_resolved());
    pending.finalize();
    Ok(())
}

fn bound_witness(consignment: &[u8]) -> Txid {
    Transfer::load(Cursor::new(consignment))
        .unwrap()
        .bundled_witnesses()
        .last()
        .unwrap()
        .witness_id()
}

fn refusal(response: &EnclaveResponse) -> String {
    match signed_psbt(response) {
        Err(reason) => reason,
        Ok(_) => panic!("the enclave signed"),
    }
}

/// Control: the bridge native input alone. The enclave signs it, it finalizes
/// to the bound txid, and the consumer accepts it.
#[test]
fn signs_valid_mint_that_finalizes_to_the_bound_txid() {
    let native = build(None);
    let (signed, inputs_signed) = signed_psbt(&drive(&native)).expect("native deposit signs");
    assert_eq!(inputs_signed, 1);
    let bound = native.psbt.unsigned_tx.compute_txid();
    assert_eq!(bound_witness(&native.deposit.consignment), bound);
    let final_tx = finalize(&signed, None);
    assert_eq!(final_tx.compute_txid(), bound);
    consumer_validates(
        &native.deposit,
        vec![
            native.deposit.seed.tx.clone(),
            native.deposit.user_funding.clone(),
            final_tx,
        ],
    )
    .expect("consumer resolves the bound witness");
}

/// Plan B needs the PSBT that made the right: it pins the right's UTXO.
#[test]
fn refuses_a_mint_without_its_parent_psbt() {
    let native = build(None);
    let chain = deposit_chain(&native, LOCK_BLOCK, LOCK_BLOCK, vec![]);
    let ctx = context(&native.deposit.contract_id, chain);
    let mut request = sign_request(&native);
    if let Some(DestinationNetwork::RgbDestination(destination)) =
        request.destination_network.as_mut()
    {
        destination.parent_psbt.clear();
    }
    let refusal = refusal(&sign_over_the_wire(&ctx, request));
    assert!(refusal.contains("parent_psbt required"), "{refusal}");
}

/// The same deposit plus one P2SH-P2WPKH input. The enclave must refuse it.
#[test]
fn refuses_input_whose_finalized_script_sig_changes_the_bound_txid() {
    let aux = wrapped_segwit_aux();
    let wrapped = build(Some(&aux));
    let bound = wrapped.psbt.unsigned_tx.compute_txid();
    assert_eq!(bound_witness(&wrapped.deposit.consignment), bound);
    let refusal = refusal(&drive(&wrapped));
    assert!(
        refusal.contains("scriptSig"),
        "refused for another reason: {refusal}"
    );
}

/// Why the refusal exists: the finalized tx has a different txid, so a consumer
/// cannot resolve the witness that the consignment names. The test signs
/// locally with the enclave seed, so the result does not need the enclave to sign.
#[test]
fn finalized_wrapped_input_leaves_the_bound_witness_unresolvable() {
    let aux = wrapped_segwit_aux();
    let wrapped = build(Some(&aux));
    let bound = wrapped.psbt.unsigned_tx.compute_txid();
    assert_eq!(bound_witness(&wrapped.deposit.consignment), bound);

    let mut psbt = wrapped.psbt.clone();
    sign_ours(&mut psbt);
    let final_tx = finalize(&psbt, Some(&aux));
    assert_ne!(final_tx.compute_txid(), bound);

    let err = consumer_validates(
        &wrapped.deposit,
        vec![
            wrapped.deposit.seed.tx.clone(),
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

/// The lock is real but above the `EVM_FINALITY_TAG` head: retry later.
#[test]
fn refuses_a_lock_above_the_finality_head() {
    let response = drive_with(&build(None), LOCK_BLOCK, LOCK_BLOCK - 1);
    let Some(Response::Error(error)) = &response.response else {
        panic!("an unsafe deposit must not be signed");
    };
    assert_eq!(error.code, 8, "the caller must recognize a finality wait");
    let refusal = refusal(&response);
    assert!(refusal.contains("above RPC safe block"), "{refusal}");
}

/// An RGB receiver refuses a lock at or after the mint's `beforeBlock`.
#[test]
fn refuses_a_lock_at_or_after_before_block() {
    for lock_block in [BEFORE_BLOCK, BEFORE_BLOCK + 1] {
        let refusal = refusal(&drive_with(&build(None), lock_block, lock_block));
        assert!(
            refusal.contains("not before the mint's beforeBlock"),
            "{refusal}"
        );
    }
}

/// The old mint form passes its right on to the bridge change, an output the
/// enclave owns. The mint signer refuses it all the same.
#[test]
fn refuses_a_mint_that_passes_its_right_on() {
    let refusal = refusal(&drive(&build_on(None, None, true)));
    assert!(refusal.contains("passes 1 mintRight"), "{refusal}");
}

fn build_listed() -> Built {
    let list = bfa_consignment::evm_reject_list(EVM_CHAIN_ID, LIST);
    build_on(None, Some(list), false)
}

/// The mint signer reads no reject list: the connector's rgb-lib checks it
/// before `mint_begin`, and a deposit already names this mint. Even a list
/// that rejects the right is never read.
#[test]
fn signs_a_listed_mint_without_reading_the_list() {
    let listed = build_listed();
    let (response, calls) = drive_listed(&listed, vec![(listed.deposit.right, true)]);
    signed_psbt(&response).expect("the mint signer does not read the list");
    assert!(calls.is_empty(), "eth_call made: {calls:?}");
}
