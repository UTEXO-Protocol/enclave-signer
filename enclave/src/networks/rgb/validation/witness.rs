//! On-chain witness resolution: the tx from the consignment, its status from a
//! trusted source. An unmined witness fails, so single-use seals hold.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::num::NonZeroU32;

use bitcoin::{Transaction, Txid};
use rgbstd::containers::Transfer;
use rgbstd::validation::{ResolveWitness, WitnessResolverError, WitnessStatus};
use rgbstd::vm::{WitnessOrd, WitnessPos};
use rgbstd::ChainNet;

/// The on-chain status of witness txs.
pub trait ConfirmedWitnesses {
    /// The block position of a mined `tx`. The source either verifies depth
    /// itself or supplies `safe_height` for rgb-lib to enforce it.
    /// `Err` says why not: unknown, unmined, too shallow or a failed lookup.
    fn confirmed(&self, tx: &Transaction) -> std::result::Result<WitnessPos, String>;

    /// The latest height rgb-lib may accept without an `UnsafeHistory` warning.
    /// `None` means this source has already checked confirmation depth.
    fn safe_height(&self) -> std::result::Result<Option<NonZeroU32>, String> {
        Ok(None)
    }
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
}

type Answer = std::result::Result<WitnessPos, String>;

/// The consensus resolver. No `get_block_header`: a proof the consignment
/// carries then falls through to `resolve_witness`, never marking a tx mined.
pub(super) struct OnChainResolver<'a> {
    txes: BTreeMap<Txid, Transaction>,
    chain_net: ChainNet,
    check: &'a WitnessCheck<'a>,
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
        Self {
            txes,
            chain_net,
            check,
            answers: RefCell::new(BTreeMap::new()),
        }
    }

    fn answer(&self, txid: Txid, tx: &Transaction) -> Answer {
        if let Some(known) = self.answers.borrow().get(&txid) {
            return known.clone();
        }
        let answer = self.check.chain.confirmed(tx);
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
