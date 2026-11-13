//! Real BFA/SPV Burn fixtures and independent release-signature oracles.

#[allow(dead_code)]
#[path = "../../src/test_support/bfa_consignment.rs"]
pub(super) mod bfa_consignment;

use std::io::Cursor;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{sol, Eip712Domain, SolCall, SolStruct, SolValue};
use attestation_verify::EvmFinalityTag;
use bfa_consignment::{History, Issue};
use bitcoin::block::{Header, Version};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Network, TxMerkleNode};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::error::Result;
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::keys::KeyManager;
use utexo_bridge_enclave::networks::evm::events::{BlockData, EvmReceiptProvider, ReceiptData};
use utexo_bridge_enclave::networks::evm::reject_list::lengthCall;
use utexo_bridge_enclave::networks::rgb::spv::{Checkpoint, HeaderChain, Network as SpvNet};
use utexo_bridge_enclave::networks::rgb::validation::RgbValidator;
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::{
    BurnDestination, EnclaveRequest, EnclaveResponse, EvmDestination, LzReleaseParams,
    MerkleProofEntry, RgbSource, SignRequest,
};
use utexo_bridge_enclave::server::{self, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;

pub(super) const SEED: [u8; 64] = [0x42; 64];
pub(super) const CHAIN_ID: u64 = 42161;
pub(super) const RGB_CHAIN_ID: u64 = 827166;
pub(super) const BRIDGE: [u8; 20] = [0xb1; 20];
pub(super) const PROXY: [u8; 20] = [0x11; 20];
pub(super) const TOKEN: [u8; 20] = [0x7e; 20];
pub(super) const LIST: [u8; 20] = [0x4e; 20];
pub(super) const PAYEE: [u8; 20] = [0x43; 20];
pub(super) const MINTED: u64 = 100_000;
pub(super) const BURNED: u64 = 60_000;
pub(super) const BURN_HEIGHT: u32 = 12;
pub(super) const TIP: u32 = 18;

// ABI and EIP-712 types are independently declared here, as a consumer of the
// signed response would declare them. Do not call the enclave digest helpers.
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
        bytes32 sourceBurnTxId;
    }
    function fundsOut(FundsOutParams params);
    function lzFundsOut(
        uint256 amount, uint256 burnId, uint256 sourceChainId,
        uint256 destinationChainId, string sourceAddress, bytes proof,
        bytes settlementData, uint32 dstEid, bytes32 recipient,
        uint256 minAmountLD, bytes extraOptions, bytes32 sourceBurnTxId
    );
    struct TeeFundsOut {
        address recipient; uint256 amount; uint256 burnId;
        uint256 sourceChainId; uint256 destinationChainId; string sourceAddress;
        bytes proof; bytes settlementData; bytes32 sourceBurnTxId;
        uint256 nonce; uint256 deadline;
    }
    struct TeeLzFundsOut {
        uint256 amount; uint256 burnId; uint256 sourceChainId;
        uint256 destinationChainId; string sourceAddress; bytes proof;
        bytes settlementData; uint32 dstEid; bytes32 recipient;
        uint256 minAmountLD; bytes extraOptions; bytes32 sourceBurnTxId;
        uint256 nonce; uint256 deadline;
    }
    struct UtexoBurnDestinationV1 {
        uint64 destinationChainId; uint32 dstEid; bytes recipient;
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Route {
    Direct,
    LayerZero,
}

impl Route {
    fn chain(self) -> u64 {
        match self {
            Self::Direct => CHAIN_ID,
            Self::LayerZero => 137,
        }
    }
    fn eid(self) -> u32 {
        match self {
            Self::Direct => 0,
            Self::LayerZero => 30109,
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn mine(mut header: Header) -> Header {
    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    header
}

/// The relay contract's stored-header layout: header, cumulative work,
/// height, difficulty-epoch timestamp and ten prior timestamps. Calculated
/// independently from the fixture headers, not by the enclave relay helper.
fn relay_commit(headers: &[Header], height: u32) -> B256 {
    let mut work = headers[0].work();
    let mut times = [headers[0].time; 10];
    for h in 1..=height as usize {
        times.rotate_left(1);
        times[9] = headers[h - 1].time;
        work = work + headers[h].work();
    }
    let mut record = serialize(&headers[height as usize]);
    record.extend_from_slice(&work.to_be_bytes());
    record.extend_from_slice(&height.to_be_bytes());
    record.extend_from_slice(&headers[0].time.to_be_bytes());
    for time in times {
        record.extend_from_slice(&time.to_be_bytes());
    }
    assert_eq!(record.len(), 160);
    keccak256(record)
}

fn chain(history: &History) -> (HeaderChain, Vec<MerkleProofEntry>, Bytes) {
    assert_eq!(
        history.bundles.len(),
        2,
        "one mint, then one split/burn bundle"
    );
    let checkpoint = mine(Header {
        version: Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: (now() - 120) as u32,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: 0,
    });
    let mut chain = HeaderChain::new(
        SpvNet::Regtest,
        Checkpoint {
            height: 0,
            hash: checkpoint.block_hash().to_byte_array(),
            bits: checkpoint.bits.to_consensus(),
            time: checkpoint.time,
            is_real: false,
            chain_work: Some(checkpoint.work().to_be_bytes()),
        },
    );
    let mut headers = vec![checkpoint];
    let mut proofs = Vec::new();
    for height in 1..=TIP {
        let merkle_root = if (11..=BURN_HEIGHT).contains(&height) {
            let txid = history.bundles[(height - 11) as usize].witness_id();
            proofs.push(MerkleProofEntry {
                txid: hex::decode(txid.to_string()).unwrap(),
                block_height: height,
                tx_position: 0,
                merkle_path: vec![],
            });
            TxMerkleNode::from_byte_array(txid.to_byte_array())
        } else {
            TxMerkleNode::from_byte_array([0xab; 32])
        };
        let header = mine(Header {
            version: Version::ONE,
            prev_blockhash: headers.last().unwrap().block_hash(),
            merkle_root,
            time: checkpoint.time + height,
            bits: checkpoint.bits,
            nonce: 0,
        });
        chain
            .submit_headers(height, &[serialize(&header)], now())
            .unwrap();
        headers.push(header);
    }
    let proof = (
        U256::from(BURN_HEIGHT),
        relay_commit(&headers, BURN_HEIGHT),
        U256::from(TIP),
        relay_commit(&headers, TIP),
    )
        .abi_encode()
        .into();
    (chain, proofs, proof)
}

/// Empty, deployed reject list. Any unexpected receipt/network call is a
/// fixture failure: burn ancestry derives settlement IDs; it does not fetch
/// a deposit receipt.
struct EmptyRejectList(Arc<AtomicUsize>);
impl EvmReceiptProvider for EmptyRejectList {
    fn get_transaction_receipt(&self, _: &[u8; 32]) -> Result<Option<ReceiptData>> {
        panic!("burn must derive ancestry deposits, not read receipts")
    }
    fn get_block_by_tag(&self, tag: EvmFinalityTag) -> Result<Option<BlockData>> {
        let number = match tag {
            EvmFinalityTag::Latest => 200,
            EvmFinalityTag::Finalized => 100,
            other => panic!("unexpected reject-list block tag {other:?}"),
        };
        Ok(Some(BlockData {
            number,
            hash: [0x22; 32],
        }))
    }
    fn get_block_by_number(&self, _: u64) -> Result<Option<BlockData>> {
        panic!("unexpected canonical receipt lookup")
    }
    fn get_chain_id(&self) -> Result<u64> {
        Ok(CHAIN_ID)
    }
    fn call(&self, to: &[u8; 20], data: &[u8], block: u64) -> Result<Vec<u8>> {
        assert_eq!(to, &LIST);
        assert_eq!(data, lengthCall::SELECTOR);
        assert!(matches!(block, 100 | 200));
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(U256::ZERO.abi_encode())
    }
}

// The contract's typehash names this word `rgbOpId`, but it holds the
// LockId of the mint transition in its exact Bitcoin witness transaction.
pub(super) fn mint_deposit_id(lock_id: [u8; 32]) -> B256 {
    keccak256((
        keccak256("UtexoRgbMintDeposit(address bridge,uint256 chainId,address token,uint256 rgbNetwork,uint256 rgbOpId,uint256 netAmount)"),
        Address::from(BRIDGE), U256::from(CHAIN_ID), Address::from(TOKEN),
        U256::from(RGB_CHAIN_ID), B256::from(lock_id), U256::from(MINTED),
    ).abi_encode())
}

pub(super) fn burn_id(p: &FundsOutParams) -> U256 {
    U256::from_be_bytes(keccak256((
        keccak256("UtexoBurnId(address bridge,uint256 chainId,address token,uint256 amount,uint256 sourceChainId,bytes32 sourceAddressHash,bytes32 sourceBurnTxId)"),
        Address::from(BRIDGE), U256::from(CHAIN_ID), Address::from(TOKEN), p.amount,
        p.sourceChainId, keccak256(p.sourceAddress.as_bytes()), p.sourceBurnTxId,
    ).abi_encode()).0)
}

pub(super) struct Fixture {
    pub(super) ctx: ServerContext,
    pub(super) source: RgbSource,
    pub(super) mint: bfa_consignment::Mint,
    pub(super) params: FundsOutParams,
    pub(super) route: Route,
    pub(super) list_reads: Arc<AtomicUsize>,
}

impl Fixture {
    pub(super) fn new(route: Route) -> Self {
        Self::with_claimed_burn(route, BURNED)
    }

    pub(super) fn with_claimed_burn(route: Route, claimed_burned: u64) -> Self {
        let right = bfa_consignment::outpoint(0xa0, 0);
        let mut issue = Issue::new(CHAIN_ID, BRIDGE, vec![right]);
        issue.reject_list = Some(bfa_consignment::evm_reject_list(CHAIN_ID, LIST));
        let mut history = History::issue(issue);
        let units = history.mint_owned(history.genesis_right(0, right), MINTED, 90);
        let reason = UtexoBurnDestinationV1 {
            destinationChainId: route.chain(),
            dstEid: route.eid(),
            recipient: PAYEE.to_vec().into(),
        }
        .eip712_hash_struct()
        .0;
        let mut transitions = history.burn_transitions(units, MINTED, Some(BURNED), Some(reason));
        // The allocation consumed by the burn always holds BURNED units. A
        // mismatched global below makes a well-formed, fully anchored file
        // that only RGB consensus can refuse; its wire hash and SPV match.
        let value = rgbstd::GlobalValues::with(rgbstd::RevealedData::new(
            amplify::confinement::SmallBlob::try_from(claimed_burned.to_le_bytes().to_vec())
                .unwrap(),
        ));
        transitions
            .last_mut()
            .unwrap()
            .globals
            .insert(schemata::GS_BURNED_ASSET, value)
            .unwrap();
        let burn = history.commit_psbt(
            transitions,
            vec![units.outpoint],
            vec![bfa_consignment::dust(0x04)],
        );
        let (chain, merkle_proofs, proof) = chain(&history);
        let consignment = history.consignment();
        let source = RgbSource {
            consignment_valid: false, // The host flag cannot authorize this burn.
            asset_id: history.contract_id.to_string(),
            consignment_hash: keccak256(&consignment).to_vec(),
            consignment,
            merkle_proofs,
            commission: 0,
        };
        let mut params = FundsOutParams {
            recipient: Address::from(PAYEE),
            amount: U256::from(BURNED),
            burnId: U256::ZERO,
            sourceChainId: U256::from(RGB_CHAIN_ID),
            destinationChainId: U256::from(route.chain()),
            sourceAddress: String::new(),
            proof,
            settlementData: (vec![mint_deposit_id(history.mints[0].lock_id())],)
                .abi_encode_params()
                .into(),
            sourceBurnTxId: bfa_consignment::opid_bytes(burn.opid).into(),
        };
        params.burnId = burn_id(&params);
        let config = BridgeConfig {
            chain_id: CHAIN_ID,
            bridge_contract: PROXY,
            funds_in_contract: BRIDGE,
            token_contract: TOKEN,
            rgb_asset_id: source.asset_id.clone(),
            bitcoin_network: utexo_bridge_enclave::policy::BitcoinNetwork::Regtest,
            ..Default::default()
        };
        let state = EnclaveState::new(Network::Regtest);
        state.initialize_from_seed(SEED).unwrap();
        let mut ctx = ServerContext::new(state, config, Mutex::new(chain));
        let list_reads = Arc::new(AtomicUsize::new(0));
        let launch = ctx.launch.get_mut().unwrap();
        // SPV supplies every witness. Contacting this unreachable indexer is
        // a failure, rather than a second source of trusted validation facts.
        launch.rgb_validator =
            Some(RgbValidator::new("tcp://127.0.0.1:1".into(), "regtest").unwrap());
        launch.evm_rpc_client = Some(Box::new(EmptyRejectList(list_reads.clone())));
        Self {
            ctx,
            source,
            mint: history.mints[0],
            params,
            route,
            list_reads,
        }
    }

    pub(super) fn request(&self, p: FundsOutParams) -> SignRequest {
        let mut recipient = [0u8; 32];
        recipient[12..].copy_from_slice(p.recipient.as_slice());
        let amount: u64 = p.amount.try_into().unwrap();
        let (call_data, lz_release) = match self.route {
            Route::Direct => (fundsOutCall { params: p }.abi_encode(), None),
            Route::LayerZero => (
                lzFundsOutCall {
                    amount: p.amount,
                    burnId: p.burnId,
                    sourceChainId: p.sourceChainId,
                    destinationChainId: p.destinationChainId,
                    sourceAddress: p.sourceAddress,
                    proof: p.proof,
                    settlementData: p.settlementData,
                    dstEid: self.route.eid(),
                    recipient: recipient.into(),
                    minAmountLD: U256::from(amount - 10),
                    extraOptions: [vec![0, 3, 1, 0, 17, 1], 200_000u128.to_be_bytes().to_vec()]
                        .concat()
                        .into(),
                    sourceBurnTxId: p.sourceBurnTxId,
                }
                .abi_encode(),
                Some(LzReleaseParams {
                    dst_eid: self.route.eid(),
                    min_amount_ld: amount - 10,
                    recipient: recipient.to_vec(),
                }),
            ),
        };
        SignRequest {
            amount: BURNED,
            source_network: Some(SourceNetwork::RgbSource(self.source.clone())),
            destination_network: Some(DestinationNetwork::EvmDestination(EvmDestination {
                call_data,
                nonce: 7,
                deadline: now() + 3600,
                chain_id: CHAIN_ID,
                proxy_contract: PROXY.to_vec(),
                calldata_amount: amount,
                calldata_commission: 0,
                lz_release,
                burn_destination: Some(BurnDestination {
                    version: 1,
                    destination_chain_id: self.route.chain(),
                    dst_eid: self.route.eid(),
                    recipient: PAYEE.to_vec(),
                }),
            })),
        }
    }

    pub(super) fn control(&self) {
        let request = self.request(self.params.clone());
        let destination = destination(&request);
        let response = exchange(&self.ctx, request.clone());
        let Some(Response::EvmSignature(signed)) = response.response else {
            panic!("valid {:?} burn must sign: {response:?}", self.route);
        };
        assert_eq!(signed.call_data, destination.call_data);
        let want = KeyManager::from_seed(SEED, Network::Regtest).unwrap();
        assert_eq!(
            recover(&signed.signature, digest(destination)),
            *want.evm_address()
        );
        // The signature must not verify as this signer for another nonce.
        let mut changed = destination.clone();
        changed.nonce += 1;
        assert_ne!(
            recover(&signed.signature, digest(&changed)),
            *want.evm_address()
        );
        assert!(
            self.list_reads.load(Ordering::SeqCst) >= 2,
            "consensus must consult the issuer's list"
        );
    }
}

pub(super) fn destination(request: &SignRequest) -> &EvmDestination {
    let Some(DestinationNetwork::EvmDestination(d)) = &request.destination_network else {
        panic!("EVM destination")
    };
    d
}

pub(super) fn exchange(ctx: &ServerContext, request: SignRequest) -> EnclaveResponse {
    let mut wire = Cursor::new(Vec::new());
    framing::write_message(
        &mut wire,
        &EnclaveRequest {
            request: Some(Request::Sign(request)),
        },
    )
    .unwrap();
    let response_at = wire.position();
    wire.set_position(0);
    server::handle_connection(&mut wire, ctx);
    wire.set_position(response_at);
    framing::read_message(&mut wire).unwrap()
}

pub(super) fn digest(d: &EvmDestination) -> [u8; 32] {
    let domain = Eip712Domain::new(
        Some("MultisigProxy".into()),
        Some("1".into()),
        Some(U256::from(d.chain_id)),
        Some(Address::from_slice(&d.proxy_contract)),
        None,
    );
    if d.lz_release.is_some() {
        let p = lzFundsOutCall::abi_decode(&d.call_data).unwrap();
        TeeLzFundsOut {
            amount: p.amount,
            burnId: p.burnId,
            sourceChainId: p.sourceChainId,
            destinationChainId: p.destinationChainId,
            sourceAddress: p.sourceAddress,
            proof: p.proof,
            settlementData: p.settlementData,
            dstEid: p.dstEid,
            recipient: p.recipient,
            minAmountLD: p.minAmountLD,
            extraOptions: p.extraOptions,
            sourceBurnTxId: p.sourceBurnTxId,
            nonce: U256::from(d.nonce),
            deadline: U256::from(d.deadline),
        }
        .eip712_signing_hash(&domain)
        .0
    } else {
        let p = fundsOutCall::abi_decode(&d.call_data).unwrap().params;
        TeeFundsOut {
            recipient: p.recipient,
            amount: p.amount,
            burnId: p.burnId,
            sourceChainId: p.sourceChainId,
            destinationChainId: p.destinationChainId,
            sourceAddress: p.sourceAddress,
            proof: p.proof,
            settlementData: p.settlementData,
            sourceBurnTxId: p.sourceBurnTxId,
            nonce: U256::from(d.nonce),
            deadline: U256::from(d.deadline),
        }
        .eip712_signing_hash(&domain)
        .0
    }
}

pub(super) fn recover(bytes: &[u8], digest: [u8; 32]) -> [u8; 20] {
    assert_eq!(bytes.len(), 65);
    let signature = Signature::from_slice(&bytes[..64]).unwrap();
    let recovery = RecoveryId::from_byte(bytes[64]).unwrap();
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery).unwrap();
    keccak256(&key.to_sec1_point(false).as_bytes()[1..])[12..]
        .try_into()
        .unwrap()
}
