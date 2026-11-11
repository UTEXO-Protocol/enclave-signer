//! Witness source selection and the adapter for enclave-verified SPV positions.
//! No-SPV validation uses the indexer resolver in `indexer.rs`.

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

/// Where consensus gets the on-chain status of the witnesses.
pub enum WitnessCheck<'a> {
    /// Positions whose inclusion and depth the enclave has verified.
    Proven(&'a dyn ConfirmedWitnesses),
    /// Trusted indexer results, with confirmation depth enforced by rgb-lib.
    Indexer { min_confirmations: u32 },
}

type Answer = std::result::Result<WitnessPos, String>;

/// Feeds verified positions to rgb-lib. Header lookups stay disabled so a
/// proof in the consignment cannot substitute for enclave verification.
pub(super) struct OnChainResolver<'a> {
    txes: BTreeMap<Txid, Transaction>,
    chain_net: ChainNet,
    chain: &'a dyn ConfirmedWitnesses,
    /// Answers given so far, so each witness costs at most one lookup.
    answers: RefCell<BTreeMap<Txid, Answer>>,
}

impl<'a> OnChainResolver<'a> {
    /// Combines consignment transactions with their verified positions.
    pub(super) fn new(
        transfer: &Transfer,
        chain_net: ChainNet,
        chain: &'a dyn ConfirmedWitnesses,
    ) -> Self {
        let txes: BTreeMap<Txid, Transaction> = transfer
            .bundles
            .iter()
            .map(|wb| (wb.witness_id(), wb.tx.clone()))
            .collect();
        Self {
            txes,
            chain_net,
            chain,
            answers: RefCell::new(BTreeMap::new()),
        }
    }

    fn answer(&self, txid: Txid, tx: &Transaction) -> Answer {
        if let Some(known) = self.answers.borrow().get(&txid) {
            return known.clone();
        }
        let answer = self.chain.confirmed(tx);
        self.answers.borrow_mut().insert(txid, answer.clone());
        answer
    }
}

impl ResolveWitness for OnChainResolver<'_> {
    fn resolve_witness(
        &self,
        witness_id: Txid,
    ) -> std::result::Result<WitnessStatus, WitnessResolverError> {
        let Some(tx) = self.txes.get(&witness_id) else {
            return Ok(WitnessStatus::Unresolved);
        };
        let pos = self.answer(witness_id, tx).map_err(|reason| {
            WitnessResolverError::ResolverIssue(
                Some(witness_id),
                format!("witness tx is not confirmed on chain: {reason}"),
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
