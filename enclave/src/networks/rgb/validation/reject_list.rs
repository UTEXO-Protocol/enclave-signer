//! The BFA reject list, with rgb-lib 98a8af6 semantics (`api/evm.rs`
//! `RejectListLog::decisions`).
//!
//! The genesis may name an `IRgbRejectList` contract. Each entry rejects or
//! allows one opout. The server reads the list over the pinned EVM RPC, this
//! module turns its entries into decisions, and rgb-lib walks the history
//! with them (`validate_consignment_with_resolver`).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use amplify::{ByteArray, Wrapper};
use rgb_lib::no_wallet::{RejectList, RejectListSource, ResolveRejectList};
use rgbstd::{AssignmentType, OpId, Opout};

use crate::error::{EnclaveError, Result};

/// One operation output: OpId, assignment type and output number, the
/// layout of the contract's `Entry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpoutKey {
    pub op: [u8; 32],
    pub ty: u16,
    pub no: u16,
}

impl From<Opout> for OpoutKey {
    fn from(opout: Opout) -> Self {
        Self {
            op: opout.op.to_byte_array(),
            ty: opout.ty.to_inner(),
            no: opout.no,
        }
    }
}

impl From<OpoutKey> for Opout {
    fn from(key: OpoutKey) -> Self {
        Opout::new(
            OpId::from_byte_array(key.op),
            AssignmentType::with(key.ty),
            key.no,
        )
    }
}

impl std::fmt::Display for OpoutKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}/{}/{}", hex::encode(self.op), self.ty, self.no)
    }
}

/// The `IRgbRejectList` contract a BFA genesis names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectListContract {
    pub chain_id: u64,
    pub address: [u8; 20],
}

/// One list entry: `reject = false` allows the opout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectListEntry {
    pub opout: OpoutKey,
    pub reject: bool,
}

/// The opouts the list rejects and allows now. Disjoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decisions {
    pub reject: BTreeSet<OpoutKey>,
    pub allow: BTreeSet<OpoutKey>,
}

/// Decisions from the entries in append order, the first `finalized` of them
/// in finalized blocks. The latest finalized entry wins; a pending reject
/// counts at once, a pending allow not at all.
pub fn decisions(entries: &[RejectListEntry], finalized: usize) -> Decisions {
    let (finalized, pending) = entries.split_at(finalized.min(entries.len()));
    let latest: BTreeMap<OpoutKey, bool> = finalized.iter().map(|e| (e.opout, e.reject)).collect();
    let mut out = Decisions {
        reject: pending
            .iter()
            .filter(|e| e.reject)
            .map(|e| e.opout)
            .collect(),
        allow: BTreeSet::new(),
    };
    for (opout, rejected) in latest {
        if rejected {
            out.reject.insert(opout);
        } else if !out.reject.contains(&opout) {
            out.allow.insert(opout);
        }
    }
    out
}

/// Reads a list's current decisions. The server reads it over the pinned EVM
/// RPC; a build without one passes `None` and refuses an asset with a list.
pub type RejectListReader<'a> = &'a dyn Fn(&RejectListContract) -> Result<Decisions>;

/// `bind_asset` runs on the genesis contract id before rgb-lib, so only the
/// pinned asset's list is ever read; with no `read`er a listed asset refuses.
pub struct ListAccess<'a> {
    pub bind_asset: &'a dyn Fn(&str) -> Result<()>,
    pub read: Option<RejectListReader<'a>>,
}

/// rgb-lib's reject-list resolver: it reads only the list of the genesis the
/// asset bind passed, and keeps the reader's own error.
pub(super) struct ListResolver<'a> {
    list: RejectListContract,
    read: RejectListReader<'a>,
    failure: RefCell<Option<EnclaveError>>,
}

impl<'a> ListResolver<'a> {
    pub(super) fn new(list: RejectListContract, read: RejectListReader<'a>) -> Self {
        Self {
            list,
            read,
            failure: RefCell::new(None),
        }
    }

    /// The reader's error, which rgb-lib would report as a network one.
    pub(super) fn take_failure(&self) -> Option<EnclaveError> {
        self.failure.borrow_mut().take()
    }

    fn fail(&self, e: EnclaveError) -> rgb_lib::Error {
        let details = e.to_string();
        *self.failure.borrow_mut() = Some(e);
        rgb_lib::Error::Network { details }
    }

    fn contract(source: &RejectListSource) -> Option<RejectListContract> {
        let RejectListSource::Evm(contract) = source else {
            return None;
        };
        Some(RejectListContract {
            chain_id: contract.chain_id,
            address: contract.address.to_byte_array(),
        })
    }
}

impl ResolveRejectList for ListResolver<'_> {
    fn get_reject_list(
        &self,
        source: &RejectListSource,
    ) -> std::result::Result<RejectList, rgb_lib::Error> {
        if Self::contract(source) != Some(self.list) {
            return Err(self.fail(EnclaveError::CrossCheck(format!(
                "rgb-lib asked for the reject list {source:?}, not the genesis list 0x{} on chain \
                 {} - refusing to read it",
                hex::encode(self.list.address),
                self.list.chain_id
            ))));
        }
        let decisions = (self.read)(&self.list).map_err(|e| self.fail(e))?;
        let rejected = decisions.reject.into_iter().map(|o| (o.into(), false));
        let allowed = decisions.allow.into_iter().map(|o| (o.into(), true));
        Ok(RejectList::from_decisions(rejected.chain(allowed)))
    }
}
