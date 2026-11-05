//! On-chain witness resolution: the tx from the consignment, its status from a
//! trusted source. An unmined witness fails, so single-use seals hold.

use std::cell::RefCell;
use std::collections::BTreeMap;

use bitcoin::{Transaction, Txid};
use rgbstd::containers::Transfer;
use rgbstd::validation::{ResolveWitness, WitnessResolverError, WitnessStatus};
use rgbstd::vm::{WitnessOrd, WitnessPos};
use rgbstd::ChainNet;

/// The on-chain status of witness txs.
pub trait ConfirmedWitnesses {
    /// The block position of `tx` if it is mined at the required depth.
    /// `Err` says why not: unknown, unmined, too shallow or a failed lookup.
    fn confirmed(&self, tx: &Transaction) -> std::result::Result<WitnessPos, String>;
}

/// Positions already proven, as the burn path's verified SPV proofs give them.
impl ConfirmedWitnesses for BTreeMap<Txid, WitnessPos> {
    fn confirmed(&self, tx: &Transaction) -> std::result::Result<WitnessPos, String> {
        self.get(&tx.compute_txid()).copied().ok_or_else(|| {
            "no merkle proof in the request proves it mined at the required depth against the \
             enclave header chain"
                .into()
        })
    }
}

/// How consensus learns that the witnesses are mined.
pub struct WitnessCheck<'a> {
    pub chain: &'a dyn ConfirmedWitnesses,
    /// Mint path only: the last bundle's witness is the mint tx being signed,
    /// so it may be unmined. The PSBT binding then requires it to be the PSBT.
    pub allow_unbroadcast_last: bool,
    /// Mint path only: a witness that a mined witness spends is mined at least
    /// as deep, so only the witnesses no mined witness spends are looked up.
    pub infer_spent_ancestors: bool,
}

/// A witness position, and the witness whose lookup gave it.
type Answer = (Txid, std::result::Result<WitnessPos, String>);

/// The consensus resolver. No `get_block_header`: a proof the consignment
/// carries then falls through to `resolve_witness`, never marking a tx mined.
pub(super) struct OnChainResolver<'a> {
    txes: BTreeMap<Txid, Transaction>,
    chain_net: ChainNet,
    check: &'a WitnessCheck<'a>,
    /// The witness that may stay unmined, if any.
    unbroadcast: Option<Txid>,
    /// For each witness, another witness that spends one of its outputs.
    spender: BTreeMap<Txid, Txid>,
    /// Answers given so far, so each witness costs at most one lookup.
    answers: RefCell<BTreeMap<Txid, Answer>>,
}

impl<'a> OnChainResolver<'a> {
    /// Built from our parsed transfer before rgb-lib runs; owns its txs.
    pub(super) fn new(
        transfer: &Transfer,
        chain_net: ChainNet,
        check: &'a WitnessCheck<'a>,
    ) -> Self {
        let txes: BTreeMap<Txid, Transaction> = transfer
            .bundles
            .iter()
            .map(|wb| (wb.witness_id(), wb.tx.clone()))
            .collect();
        let unbroadcast = check
            .allow_unbroadcast_last
            .then(|| transfer.bundles.last().map(|wb| wb.witness_id()))
            .flatten();
        let spender = if check.infer_spent_ancestors {
            spenders(&txes, unbroadcast)
        } else {
            BTreeMap::new()
        };
        Self {
            txes,
            chain_net,
            check,
            unbroadcast,
            spender,
            answers: RefCell::new(BTreeMap::new()),
        }
    }

    /// The answer of the last witness up `txid`'s spender chain, which has no
    /// cycle. With no `safe_height`, the borrowed position only means "mined".
    fn answer(&self, txid: Txid, tx: &Transaction) -> Answer {
        let mut path = Vec::new();
        let mut top = (txid, tx);
        let answer = loop {
            if let Some(known) = self.answers.borrow().get(&top.0) {
                break known.clone();
            }
            path.push(top.0);
            let next = self.spender.get(&top.0);
            match next.and_then(|id| self.txes.get_key_value(id)) {
                Some((id, spender_tx)) => top = (*id, spender_tx),
                None => break (top.0, self.check.chain.confirmed(top.1)),
            }
        };
        let mut answers = self.answers.borrow_mut();
        for id in path {
            answers.insert(id, answer.clone());
        }
        answer
    }
}

/// Maps each witness to a witness that spends one of its outputs. The
/// unbroadcast one is left out: it proves no depth.
fn spenders(txes: &BTreeMap<Txid, Transaction>, unbroadcast: Option<Txid>) -> BTreeMap<Txid, Txid> {
    let mut spender = BTreeMap::new();
    for (id, tx) in txes.iter().filter(|(id, _)| Some(**id) != unbroadcast) {
        for input in &tx.input {
            let parent = input.previous_output.txid;
            if parent != *id && txes.contains_key(&parent) {
                spender.entry(parent).or_insert(*id);
            }
        }
    }
    spender
}

impl ResolveWitness for OnChainResolver<'_> {
    fn resolve_witness(
        &self,
        witness_id: Txid,
    ) -> std::result::Result<WitnessStatus, WitnessResolverError> {
        let Some(tx) = self.txes.get(&witness_id) else {
            return Ok(WitnessStatus::Unresolved);
        };
        if self.unbroadcast == Some(witness_id) {
            return Ok(WitnessStatus::Resolved(tx.clone(), WitnessOrd::Tentative));
        }
        let (source, answer) = self.answer(witness_id, tx);
        let pos = answer.map_err(|reason| {
            let via = if source == witness_id {
                String::new()
            } else {
                format!(" (checked through {source}, which builds on it)")
            };
            WitnessResolverError::ResolverIssue(
                Some(witness_id),
                format!("witness tx is not confirmed on chain: {reason}{via}"),
            )
        })?;
        Ok(WitnessStatus::Resolved(tx.clone(), WitnessOrd::Mined(pos)))
    }

    fn check_chain_net(
        &self,
        chain_net: ChainNet,
    ) -> std::result::Result<(), WitnessResolverError> {
        if chain_net != self.chain_net {
            return Err(WitnessResolverError::WrongChainNet);
        }
        Ok(())
    }
}
