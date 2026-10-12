//! Builds BFA consignments in process with the pinned RGB crates: a real
//! genesis, then mints, transfers and burns, each in a witness tx that
//! commits its bundle in an OP_RETURN output. Tests need no stored V1
//! fixture. Deterministic: fixed times, nonces, blinding and entropy.
//!
//! It uses only external crates, so integration tests include it with
//! `#[path]`.

use std::collections::BTreeMap;

use amplify::confinement::{Confined, NonEmptyVec};
use amplify::{ByteArray, Bytes20, Bytes32};
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::{absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction};
use bitcoin::{TxIn, TxOut, Witness};
use rgbstd::containers::{ConsignmentVer, FileContent, TerminalSeals, Transfer, WitnessBundle};
use rgbstd::contract::{AllocatedState, ContractBuilder, IssuerWrapper, TransitionBuilder};
use rgbstd::opret::{OpretFirst, OpretProof};
use rgbstd::rgbcore::commit_verify::mpc::{
    Commitment, MerkleBlock, MerkleTree, Message, MultiSource, ProtocolId,
};
use rgbstd::rgbcore::commit_verify::{CommitId, EmbedCommitVerify, TryCommitVerify};
use rgbstd::stl::{
    AssetSpec, BlockNumber, BridgeLocation, BurnReason, ContractTerms, EvmAddress, EvmContract,
    RejectListLocation, RicardianContract,
};
use rgbstd::validation::{DbcProof, SchemaRules};
use rgbstd::{
    Amount as RgbAmount, Anchor, BuilderSeal, ChainNet, ContractId, Genesis, GenesisSeal,
    GraphSeal, Identity, KnownTransition, OpId, Operation, Opout, Precision, RevealedValue,
    Transition, TransitionBundle,
};
use schemata::{BridgedFungibleAsset, OS_ASSET, OS_MINT};

/// The genesis timestamp of every generated asset.
pub const ISSUED_AT: i64 = 1_700_000_000;

/// An unspent allocation: the opout that assigns it and the outpoint of its
/// seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utxo {
    pub opout: Opout,
    pub outpoint: OutPoint,
}

/// A mint the history made, as its anchor names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mint {
    pub opid: OpId,
    pub amount: u64,
    pub after_block: u64,
}

/// One transition committed in its witness tx.
#[derive(Debug, Clone)]
pub struct Committed {
    pub opid: OpId,
    pub tx: Transaction,
}

/// A BFA contract and the bundles built on it, in order.
pub struct History {
    pub contract_id: ContractId,
    /// Built once: a schema build per transition is slow.
    rules: SchemaRules,
    pub genesis: Genesis,
    pub bundles: Vec<WitnessBundle>,
    pub mints: Vec<Mint>,
    nonce: u64,
}

/// The genesis global state a test may vary.
pub struct Issue {
    pub chain_id: u64,
    pub bridge: [u8; 20],
    pub rights: Vec<OutPoint>,
    pub reject_list: bool,
    pub chain_net: ChainNet,
}

impl Issue {
    /// One mint right per outpoint, on regtest, without a reject list.
    pub fn new(chain_id: u64, bridge: [u8; 20], rights: Vec<OutPoint>) -> Self {
        Self {
            chain_id,
            bridge,
            rights,
            reject_list: false,
            chain_net: ChainNet::BitcoinRegtest,
        }
    }
}

/// A distinct outpoint of a funding tx nobody needs to see.
pub fn outpoint(tag: u8, vout: u32) -> OutPoint {
    OutPoint::new(bitcoin::Txid::from_byte_array([tag; 32]), vout)
}

/// The OpId as the EVM `FundsIn` topic and the bridge carry it.
pub fn opid_bytes(opid: OpId) -> [u8; 32] {
    opid.to_byte_array()
}

/// `burnReason` in the bridge format: 12 zero bytes, then the EVM address.
pub fn burn_reason_for(address: [u8; 20]) -> [u8; 32] {
    let mut reason = [0u8; 32];
    reason[12..].copy_from_slice(&address);
    reason
}

fn bridge_location(chain_id: u64, address: [u8; 20]) -> BridgeLocation {
    BridgeLocation::Evm(EvmContract {
        chain_id,
        address: EvmAddress::from(Bytes20::from_byte_array(address)),
    })
}

impl History {
    /// Issues a BFA asset. Genesis right `i` sits on `issue.rights[i]`.
    pub fn issue(issue: Issue) -> Self {
        let mut builder = ContractBuilder::with(
            Identity::default(),
            BridgedFungibleAsset::schema_rules(),
            issue.chain_net,
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
            bridge_location(issue.chain_id, issue.bridge),
        )
        .unwrap();
        if issue.reject_list {
            builder = builder
                .add_global_state(
                    "rejectList",
                    RejectListLocation::Evm(EvmContract {
                        chain_id: issue.chain_id,
                        address: EvmAddress::from(Bytes20::from_byte_array([0x4e; 20])),
                    }),
                )
                .unwrap();
        }
        for (i, right) in issue.rights.iter().enumerate() {
            let seal = GenesisSeal::with_blinding(right.txid, right.vout, 0x1000 + i as u64);
            builder = builder.add_rights("mintRight", seal).unwrap();
        }
        let genesis = builder
            .issue_contract_raw(ISSUED_AT)
            .unwrap()
            .into_consignment()
            .genesis;
        Self {
            contract_id: genesis.contract_id(),
            genesis,
            bundles: Vec::new(),
            mints: Vec::new(),
            rules: BridgedFungibleAsset::schema_rules(),
            nonce: 0,
        }
    }

    /// Genesis mint right `no`.
    pub fn genesis_right(&self, no: u16, outpoint: OutPoint) -> Utxo {
        Utxo {
            opout: Opout::new(self.genesis.id(), OS_MINT, no),
            outpoint,
        }
    }

    /// A transition of `name`, with a fresh nonce.
    pub fn transition(&mut self, name: &'static str) -> TransitionBuilder {
        self.nonce += 1;
        TransitionBuilder::named_transition(
            self.contract_id,
            self.rules.schema().clone(),
            name,
            self.rules.types().clone(),
        )
        .unwrap()
        .set_nonce(self.nonce)
    }

    /// Commits `transitions` as one bundle in a witness tx that spends
    /// `inputs` and pays `outputs` after its OP_RETURN (which is vout 0).
    pub fn commit(
        &mut self,
        transitions: Vec<Transition>,
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    ) -> Transaction {
        self.commit_bundle(bundle_of(transitions), inputs, outputs)
    }

    /// [`Self::commit`] for a bundle the caller built.
    pub fn commit_bundle(
        &mut self,
        bundle: TransitionBundle,
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    ) -> Transaction {
        let protocol = ProtocolId::from(self.contract_id);
        let mut source = MultiSource {
            static_entropy: Some(0x5eed + self.bundles.len() as u64),
            ..Default::default()
        };
        source
            .messages
            .insert(protocol, Message::from(bundle.bundle_id()))
            .unwrap();
        let tree = MerkleTree::try_commit(&source).unwrap();
        let commitment = tree.commit_id();
        let mpc_proof = MerkleBlock::from(tree).to_merkle_proof(protocol).unwrap();

        let mut tx = witness_tx(inputs, outputs);
        let opret: OpretProof =
            <Transaction as EmbedCommitVerify<Commitment, OpretFirst>>::embed_commit(
                &mut tx,
                &commitment,
            )
            .unwrap();
        self.bundles.push(WitnessBundle {
            tx: tx.clone(),
            spv_proof: None,
            anchor: Anchor::new(mpc_proof, DbcProof::Opret(opret)),
            bundle,
        });
        tx
    }

    /// Mints `amount` to `to`, and passes the right on to vout 1 of the
    /// witness tx. The tx spends the right, then `extra_inputs`, and pays
    /// `outputs` (vout 1..).
    pub fn mint(
        &mut self,
        right: Utxo,
        amount: u64,
        after_block: u64,
        to: BuilderSeal<GraphSeal>,
        extra_inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    ) -> (Committed, Utxo) {
        let mint = self
            .transition("mint")
            .add_input(right.opout, AllocatedState::Void)
            .unwrap()
            .add_metadata("afterBlock", BlockNumber::from(after_block))
            .unwrap()
            .add_global_state("issuedSupply", RgbAmount::from(amount))
            .unwrap()
            .add_fungible_state("assetOwner", to, amount)
            .unwrap()
            .add_rights("mintRight", GraphSeal::with_blinded_vout(1u32, self.nonce))
            .unwrap()
            .complete_transition()
            .unwrap();
        let opid = mint.id();
        let inputs = std::iter::once(right.outpoint)
            .chain(extra_inputs)
            .collect();
        let tx = self.commit(vec![mint], inputs, outputs);
        self.mints.push(Mint {
            opid,
            amount,
            after_block,
        });
        let next_right = Utxo {
            opout: Opout::new(opid, OS_MINT, 0),
            outpoint: OutPoint::new(tx.compute_txid(), 1),
        };
        (Committed { opid, tx }, next_right)
    }

    /// Mints `amount` to a revealed seal on vout 2 of its witness tx, so a
    /// later transition can spend it. Returns the right and the units.
    pub fn mint_owned(&mut self, right: Utxo, amount: u64, after_block: u64) -> (Utxo, Utxo) {
        let to = BuilderSeal::from(GraphSeal::with_blinded_vout(2u32, 0x2000 + self.nonce));
        let (minted, next_right) = self.mint(
            right,
            amount,
            after_block,
            to,
            vec![],
            vec![dust(0x01), dust(0x02)],
        );
        let units = Utxo {
            opout: Opout::new(minted.opid, OS_ASSET, 0),
            outpoint: OutPoint::new(minted.tx.compute_txid(), 2),
        };
        (next_right, units)
    }

    /// Moves `input` (holding `amount`) to vout 1 of a new witness tx.
    pub fn transfer(&mut self, input: Utxo, amount: u64) -> Utxo {
        let transfer = self
            .transition("transfer")
            .add_input(
                input.opout,
                AllocatedState::from(RevealedValue::from(amount)),
            )
            .unwrap()
            .add_fungible_state(
                "assetOwner",
                GraphSeal::with_blinded_vout(1u32, self.nonce),
                amount,
            )
            .unwrap()
            .complete_transition()
            .unwrap();
        let opid = transfer.id();
        let tx = self.commit(vec![transfer], vec![input.outpoint], vec![dust(0x03)]);
        Utxo {
            opout: Opout::new(opid, OS_ASSET, 0),
            outpoint: OutPoint::new(tx.compute_txid(), 1),
        }
    }

    /// Burns `burned` of `input` (holding `held`) and keeps the rest as
    /// change on vout 1. `None` leaves the global out.
    pub fn burn(
        &mut self,
        input: Utxo,
        held: u64,
        burned: Option<u64>,
        reason: Option<[u8; 32]>,
    ) -> Committed {
        let burn = self.burn_transition(input, held, burned, reason);
        let opid = burn.id();
        let tx = self.commit(vec![burn], vec![input.outpoint], vec![dust(0x04)]);
        Committed { opid, tx }
    }

    /// The transition [`Self::burn`] commits, for a bundle the caller builds.
    pub fn burn_transition(
        &mut self,
        input: Utxo,
        held: u64,
        burned: Option<u64>,
        reason: Option<[u8; 32]>,
    ) -> Transition {
        let mut burn = self
            .transition("burn")
            .add_input(input.opout, AllocatedState::from(RevealedValue::from(held)))
            .unwrap();
        if let Some(burned) = burned {
            burn = burn
                .add_global_state("burnedAsset", RgbAmount::from(burned))
                .unwrap();
        }
        if let Some(reason) = reason {
            burn = burn
                .add_global_state(
                    "burnReason",
                    BurnReason::from(Bytes32::from_byte_array(reason)),
                )
                .unwrap();
        }
        let change = held - burned.unwrap_or(0);
        if change > 0 {
            burn = burn
                .add_fungible_state(
                    "assetOwner",
                    GraphSeal::with_blinded_vout(1u32, self.nonce),
                    change,
                )
                .unwrap();
        }
        burn.complete_transition().unwrap()
    }

    /// The consignment, with `terminals` on the last bundle.
    pub fn transfer_with(&self, terminals: Vec<BuilderSeal<GraphSeal>>) -> Transfer {
        let mut transfer = Transfer {
            version: ConsignmentVer::V1,
            transfer: true,
            terminals: Default::default(),
            genesis: self.genesis.clone(),
            bundles: Confined::try_from(self.bundles.clone()).unwrap(),
        };
        if let (Some(last), Some((first, rest))) = (self.bundles.last(), terminals.split_first()) {
            let mut seals = NonEmptyVec::with(*first);
            for seal in rest {
                seals.push(*seal).unwrap();
            }
            transfer
                .terminals
                .insert(last.bundle.bundle_id(), TerminalSeals::from(seals))
                .unwrap();
        }
        transfer
    }

    /// The TFR file bytes, as the bridge sends them.
    pub fn consignment(&self, terminals: Vec<BuilderSeal<GraphSeal>>) -> Vec<u8> {
        save(&self.transfer_with(terminals))
    }
}

/// The TFR file bytes of `transfer`.
pub fn save(transfer: &Transfer) -> Vec<u8> {
    let mut bytes = Vec::new();
    transfer.save(&mut bytes).unwrap();
    bytes
}

/// A 1000-sat output to a throwaway P2WPKH.
pub fn dust(tag: u8) -> TxOut {
    TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([tag; 20])),
    }
}

/// One bundle of `transitions`: each input maps to its transition.
pub fn bundle_of(transitions: Vec<Transition>) -> TransitionBundle {
    let known: Vec<KnownTransition> = transitions
        .into_iter()
        .map(|t| KnownTransition::new(t.id(), t))
        .collect();
    let input_map: BTreeMap<Opout, OpId> = known
        .iter()
        .flat_map(|k| k.transition.inputs.iter().map(|input| (*input, k.opid)))
        .collect();
    TransitionBundle {
        input_map: Confined::try_from(input_map).unwrap(),
        known_transitions: Confined::try_from(known).unwrap(),
    }
}

fn witness_tx(inputs: Vec<OutPoint>, outputs: Vec<TxOut>) -> Transaction {
    let commitment = TxOut {
        value: Amount::ZERO,
        script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
    };
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs
            .into_iter()
            .map(|previous_output| TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: std::iter::once(commitment).chain(outputs).collect(),
    }
}
