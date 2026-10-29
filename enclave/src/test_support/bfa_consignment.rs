//! Builds BFA consignments in process with the pinned RGB crates: a real
//! genesis, then mints, transfers of units, propagates of rights and burns,
//! each in a witness tx that commits its bundle in an OP_RETURN output. Each one is
//! committed as rgb-lib does it, through psbtu's `rgb_commit`, so its PSBT is
//! the one a signer gets. Tests need no stored V1 fixture. Deterministic:
//! fixed times, nonces, blinding and entropy.
//!
//! It uses only external crates, so integration tests include it with
//! `#[path]`.

use std::collections::BTreeMap;

use amplify::confinement::Confined;
use amplify::{ByteArray, Bytes20, Bytes32};
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::{absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction};
use bitcoin::{TxIn, TxOut, Witness};
use psrgbt::{RgbOutExt, RgbPsbtExt};
use rgbstd::containers::{ConsignmentVer, FileContent, Transfer, WitnessBundle};
use rgbstd::contract::{AllocatedState, ContractBuilder, IssuerWrapper, TransitionBuilder};
use rgbstd::opret::{OpretFirst, OpretProof};
use rgbstd::rgbcore::commit_verify::mpc::{
    Commitment, MerkleBlock, MerkleTree, Message, MultiSource, ProtocolId,
};
use rgbstd::rgbcore::commit_verify::{CommitId, EmbedCommitVerify, TryCommitVerify};
use rgbstd::stl::{
    BlockNumber, BridgeLocation, BurnReason, ContractTerms, EvmAddress, EvmContract, Name,
    RejectListLocation, RicardianContract, UnicodeTicker,
};
use rgbstd::txout::CloseMethod;
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
    pub before_block: u64,
}

/// One transition committed in its witness tx, and the PSBT of that tx.
#[derive(Debug, Clone)]
pub struct Committed {
    pub opid: OpId,
    pub tx: Transaction,
    // Only the mint signer's tests read the PSBT.
    #[cfg_attr(not(all(feature = "bfa-mint", evm_to_rgb)), allow(dead_code))]
    pub psbt: Psbt,
}

impl Committed {
    fn of(opid: OpId, psbt: Psbt) -> Self {
        Self {
            opid,
            tx: psbt.unsigned_tx.clone(),
            psbt,
        }
    }
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
    pub reject_list: Option<RejectListLocation>,
    pub chain_net: ChainNet,
}

impl Issue {
    /// One mint right per outpoint, on regtest, without a reject list.
    pub fn new(chain_id: u64, bridge: [u8; 20], rights: Vec<OutPoint>) -> Self {
        Self {
            chain_id,
            bridge,
            rights,
            reject_list: None,
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

/// A reject list kept by the contract at `address` on chain `chain_id`.
pub fn evm_reject_list(chain_id: u64, address: [u8; 20]) -> RejectListLocation {
    RejectListLocation::Evm(EvmContract {
        chain_id,
        address: EvmAddress::from(Bytes20::from_byte_array(address)),
    })
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
        .add_global_state("ticker", UnicodeTicker::from("BUSDT"))
        .unwrap()
        .add_global_state("name", Name::from("Bridged USDT"))
        .unwrap()
        .add_global_state("precision", Precision::Micro)
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
        if let Some(list) = issue.reject_list {
            builder = builder.add_global_state("rejectList", list).unwrap();
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
        self.commit_psbt(transitions, inputs, outputs).unsigned_tx
    }

    /// [`Self::commit`] as rgb-lib's `prepare_rgb_psbt` does it: each
    /// transition pushed to the PSBT, the OP_RETURN marked as host with the
    /// entropy, then `rgb_commit`. Returns the committed PSBT.
    pub fn commit_psbt(
        &mut self,
        transitions: Vec<Transition>,
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    ) -> Psbt {
        // psbtu orders known transitions by a hash map; the bundle keeps ours.
        let bundle = bundle_of(transitions.clone());
        let tree = self.mpc_tree(&bundle);
        let mut psbt = witness_psbt(inputs, outputs);
        for transition in transitions {
            psbt.push_rgb_transition(transition).unwrap();
        }
        rgb_commit(&mut psbt, 0, tree.entropy());
        self.push_bundle(bundle, psbt.unsigned_tx.clone(), tree);
        psbt
    }

    /// [`Self::commit`] for a bundle the caller built, which no PSBT holds.
    pub fn commit_bundle(
        &mut self,
        bundle: TransitionBundle,
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    ) -> Transaction {
        let tree = self.mpc_tree(&bundle);
        let mut tx = witness_tx(inputs, outputs);
        <Transaction as EmbedCommitVerify<Commitment, OpretFirst>>::embed_commit(
            &mut tx,
            &tree.commit_id(),
        )
        .unwrap();
        self.push_bundle(bundle, tx.clone(), tree);
        tx
    }

    /// The MPC tree of the next bundle: its one message, fixed entropy.
    fn mpc_tree(&self, bundle: &TransitionBundle) -> MerkleTree {
        let mut source = MultiSource {
            static_entropy: Some(0x5eed + self.bundles.len() as u64),
            ..Default::default()
        };
        source
            .messages
            .insert(
                ProtocolId::from(self.contract_id),
                Message::from(bundle.bundle_id()),
            )
            .unwrap();
        MerkleTree::try_commit(&source).unwrap()
    }

    /// Records `bundle`, committed by `tx` under `tree`'s root in an OP_RETURN.
    fn push_bundle(&mut self, bundle: TransitionBundle, tx: Transaction, tree: MerkleTree) {
        let protocol = ProtocolId::from(self.contract_id);
        let mpc_proof = MerkleBlock::from(tree).to_merkle_proof(protocol).unwrap();
        self.bundles.push(WitnessBundle {
            tx,
            spv_proof: None,
            anchor: Anchor::new(mpc_proof, DbcProof::Opret(OpretProof::default())),
            bundle,
        });
    }

    /// Mints `amount` to `to`. The mint consumes the right, as rgb-lib builds
    /// it. The tx spends the right, then `extra_inputs`, and pays `outputs`
    /// (vout 1..).
    pub fn mint(
        &mut self,
        right: Utxo,
        amount: u64,
        before_block: u64,
        to: BuilderSeal<GraphSeal>,
        extra_inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    ) -> Committed {
        let mint = self
            .mint_transition(right, amount, before_block, to)
            .complete_transition()
            .unwrap();
        self.commit_mint(mint, amount, before_block, right, extra_inputs, outputs)
    }

    /// [`Self::mint`] in the old form, which passes a new right on to vout 1.
    /// The schema refuses it now; a refusal fixture only.
    pub fn mint_keeping_right(
        &mut self,
        right: Utxo,
        amount: u64,
        before_block: u64,
        to: BuilderSeal<GraphSeal>,
        extra_inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    ) -> (Committed, Utxo) {
        let mint = self
            .mint_transition(right, amount, before_block, to)
            .add_rights("mintRight", GraphSeal::with_blinded_vout(1u32, self.nonce))
            .unwrap()
            .complete_transition()
            .unwrap();
        let minted = self.commit_mint(mint, amount, before_block, right, extra_inputs, outputs);
        let kept = Utxo {
            opout: Opout::new(minted.opid, OS_MINT, 0),
            outpoint: OutPoint::new(minted.tx.compute_txid(), 1),
        };
        (minted, kept)
    }

    /// The mint of `amount` to `to` on `right`, still open for more outputs.
    fn mint_transition(
        &mut self,
        right: Utxo,
        amount: u64,
        before_block: u64,
        to: BuilderSeal<GraphSeal>,
    ) -> TransitionBuilder {
        self.transition("mint")
            .add_input(right.opout, AllocatedState::Void)
            .unwrap()
            .add_metadata("beforeBlock", BlockNumber::from(before_block))
            .unwrap()
            .add_global_state("issuedSupply", RgbAmount::from(amount))
            .unwrap()
            .add_fungible_state("assetOwner", to, amount)
            .unwrap()
    }

    /// Commits `mint` in a tx that spends `right`, then `extra_inputs`, and
    /// records its anchor.
    fn commit_mint(
        &mut self,
        mint: Transition,
        amount: u64,
        before_block: u64,
        right: Utxo,
        extra_inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    ) -> Committed {
        let opid = mint.id();
        let inputs = std::iter::once(right.outpoint)
            .chain(extra_inputs)
            .collect();
        let psbt = self.commit_psbt(vec![mint], inputs, outputs);
        self.mints.push(Mint {
            opid,
            amount,
            before_block,
        });
        Committed::of(opid, psbt)
    }

    /// Mints `amount` to a revealed seal on vout 2 of its witness tx, so a
    /// later transition can spend it. Returns the units.
    pub fn mint_owned(&mut self, right: Utxo, amount: u64, before_block: u64) -> Utxo {
        let to = BuilderSeal::from(GraphSeal::with_blinded_vout(2u32, 0x2000 + self.nonce));
        let minted = self.mint(
            right,
            amount,
            before_block,
            to,
            vec![],
            vec![dust(0x01), dust(0x02)],
        );
        Utxo {
            opout: Opout::new(minted.opid, OS_ASSET, 0),
            outpoint: OutPoint::new(minted.tx.compute_txid(), 2),
        }
    }

    /// A rights send to witness invoices: spends `right` and makes `count`
    /// rights, on vouts 1..=count of its witness tx. One right in, any number
    /// out.
    pub fn duplicate_right(&mut self, right: Utxo, count: u16) -> Vec<Utxo> {
        let vouts: Vec<u32> = (1..=u32::from(count)).collect();
        let outputs = (1..=count).map(|_| dust(0x05)).collect();
        let sent = self.send_rights(right, &vouts, vec![], outputs);
        rights_made(&sent, &vouts)
    }

    /// The rights send a mint wallet refills with: spends `right`, then
    /// `extra_inputs`, and puts one right on each of `vouts` of a tx that pays
    /// `outputs` (vout 1..).
    pub fn send_rights(
        &mut self,
        right: Utxo,
        vouts: &[u32],
        extra_inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    ) -> Committed {
        let send = self.rights_transition(right, vouts);
        let opid = send.id();
        let inputs = std::iter::once(right.outpoint)
            .chain(extra_inputs)
            .collect();
        let psbt = self.commit_psbt(vec![send], inputs, outputs);
        Committed::of(opid, psbt)
    }

    /// The propagate [`Self::send_rights`] commits, for a bundle the caller
    /// builds. Rights move only by propagate, one right in.
    pub fn rights_transition(&mut self, right: Utxo, vouts: &[u32]) -> Transition {
        let mut send = self
            .transition("propagate")
            .add_input(right.opout, AllocatedState::Void)
            .unwrap();
        for &vout in vouts {
            let seal = GraphSeal::with_blinded_vout(vout, self.nonce);
            send = send.add_rights("mintRight", seal).unwrap();
        }
        send.complete_transition().unwrap()
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

    /// Burns `burned` of `input` (holding `held`). The rest goes to vout 1 as
    /// rgb-lib does it: a split transfer first, then the burn of its output.
    /// `None` burns it all without the global, which consensus refuses.
    pub fn burn(
        &mut self,
        input: Utxo,
        held: u64,
        burned: Option<u64>,
        reason: Option<[u8; 32]>,
    ) -> Committed {
        let transitions = self.burn_transitions(input, held, burned, reason);
        let opid = transitions.last().unwrap().id();
        let psbt = self.commit_psbt(transitions, vec![input.outpoint], vec![dust(0x04)]);
        Committed::of(opid, psbt)
    }

    /// The transitions [`Self::burn`] commits, in bundle order: the split, if
    /// there is change, then the burn.
    pub fn burn_transitions(
        &mut self,
        input: Utxo,
        held: u64,
        burned: Option<u64>,
        reason: Option<[u8; 32]>,
    ) -> Vec<Transition> {
        let change = burned.map_or(0, |burned| held - burned);
        if change == 0 {
            return vec![self.burn_transition(input, held, burned, reason)];
        }
        let (split, burnable) = self.split(input, held, change);
        let burn = self.burn_transition(burnable, held - change, burned, reason);
        vec![split, burn]
    }

    /// The split of a burn with change: `change` to vout 1, the rest to a seal
    /// on the outpoint the burn tx spends, as rgb-lib puts it.
    fn split(&mut self, input: Utxo, held: u64, change: u64) -> (Transition, Utxo) {
        let burnable_seal = GraphSeal::with_blinding(
            input.outpoint.txid,
            input.outpoint.vout,
            0x6000 + self.nonce,
        );
        let split = self
            .transition("transfer")
            .add_input(input.opout, AllocatedState::from(RevealedValue::from(held)))
            .unwrap()
            .add_fungible_state(
                "assetOwner",
                GraphSeal::with_blinded_vout(1u32, self.nonce),
                change,
            )
            .unwrap()
            .add_fungible_state("assetOwner", burnable_seal, held - change)
            .unwrap()
            .complete_transition()
            .unwrap();
        let opout = Opout::new(split.id(), OS_ASSET, seal_index(&split, burnable_seal));
        (
            split,
            Utxo {
                opout,
                outpoint: input.outpoint,
            },
        )
    }

    /// The burn of the whole of `input` (holding `held`), for a bundle the
    /// caller builds. The schema gives a burn no outputs.
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
        burn.complete_transition().unwrap()
    }

    /// The consignment of the history.
    pub fn as_transfer(&self) -> Transfer {
        Transfer {
            version: ConsignmentVer::V1,
            transfer: true,
            genesis: self.genesis.clone(),
            bundles: Confined::try_from(self.bundles.clone()).unwrap(),
        }
    }

    /// The TFR file bytes, as the bridge sends them.
    pub fn consignment(&self) -> Vec<u8> {
        save(&self.as_transfer())
    }
}

/// The index of the `OS_ASSET` output on `seal`: the builder sorts outputs by seal.
fn seal_index(transition: &Transition, seal: GraphSeal) -> u16 {
    let assigns = transition.assignments.get(&OS_ASSET).unwrap().as_fungible();
    let no = assigns
        .iter()
        .position(|a| a.revealed_seal() == Some(seal))
        .unwrap();
    u16::try_from(no).unwrap()
}

/// The rights `sent` made, one per vout of `vouts` in ascending order, as
/// [`History::send_rights`] numbers them.
pub fn rights_made(sent: &Committed, vouts: &[u32]) -> Vec<Utxo> {
    let txid = sent.tx.compute_txid();
    vouts
        .iter()
        .zip(0u16..)
        .map(|(&vout, no)| Utxo {
            opout: Opout::new(sent.opid, OS_MINT, no),
            outpoint: OutPoint::new(txid, vout),
        })
        .collect()
}

/// The TFR file bytes of `transfer`.
pub fn save(transfer: &Transfer) -> Vec<u8> {
    let mut bytes = Vec::new();
    transfer.save(&mut bytes).unwrap();
    bytes
}

/// The PSBT of a witness tx that spends `inputs` and pays `outputs` after an
/// empty OP_RETURN at vout 0. It holds no RGB data yet.
pub fn witness_psbt(inputs: Vec<OutPoint>, outputs: Vec<TxOut>) -> Psbt {
    Psbt::from_unsigned_tx(witness_tx(inputs, outputs)).unwrap()
}

/// Commits the RGB data `psbt` holds as rgb-lib does: output `host` is the
/// opret host with `entropy`, then psbtu's `rgb_commit`.
pub fn rgb_commit(psbt: &mut Psbt, host: usize, entropy: u64) {
    let output = &mut psbt.outputs[host];
    output.set_opret_host();
    output.set_mpc_entropy(entropy).unwrap();
    psbt.set_rgb_close_method(CloseMethod::OpretFirst);
    psbt.rgb_commit().unwrap();
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
