//! The BFA reject list.
//!
//! The genesis may name an `IRgbRejectList` contract. Each entry rejects or
//! allows one opout. rgb-lib reads the location from the genesis and asks the
//! resolver for the entries (`validate_consignment_with_resolver`). The server
//! reads them over the pinned EVM RPC. rgb-lib decides from them which opouts
//! the list rejects and allows, and walks the history with that.

use std::cell::{Cell, RefCell};

use amplify::{ByteArray, Wrapper};
use rgb_lib::no_wallet::{EvmRejectList, EvmRejectListEntry, ResolveRejectList};
use rgb_lib::EvmContract;
use rgb_lib::{AssignmentType, OpId, Opout};

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

/// The entries of a list as of the latest block, in append order. The first
/// `finalized` of them were appended in finalized blocks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RejectListLog {
    pub entries: Vec<RejectListEntry>,
    pub finalized: usize,
}

/// Reads the entries of a list. The server reads them over the pinned EVM
/// RPC; a build without one passes `None` and refuses an asset with a list.
pub type RejectListReader<'a> = &'a dyn Fn(&RejectListContract) -> Result<RejectListLog>;

/// `bind_asset` runs on the genesis contract id before rgb-lib, so only the
/// pinned asset's list is ever read; with no `read`er a listed asset refuses.
pub struct ListAccess<'a> {
    pub bind_asset: &'a dyn Fn(&str) -> Result<()>,
    pub read: Option<RejectListReader<'a>>,
}

/// rgb-lib's reject-list resolver. rgb-lib names the list: it decodes the
/// location from the genesis it has validated, and the asset bind has
/// already fixed that genesis. The resolver keeps the reader's own error.
pub(super) struct ListResolver<'a> {
    read: RejectListReader<'a>,
    /// The list rgb-lib asked for, for the refusal text.
    asked: Cell<Option<RejectListContract>>,
    failure: RefCell<Option<EnclaveError>>,
}

impl<'a> ListResolver<'a> {
    pub(super) fn new(read: RejectListReader<'a>) -> Self {
        Self {
            read,
            asked: Cell::new(None),
            failure: RefCell::new(None),
        }
    }

    /// The EVM list rgb-lib asked for, if it asked for one.
    pub(super) fn asked(&self) -> Option<RejectListContract> {
        self.asked.get()
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
}

impl ResolveRejectList for ListResolver<'_> {
    /// The enclave has no egress to a URL, and its host would be untrusted.
    fn get_url_reject_list(&self, _url: &str) -> std::result::Result<String, rgb_lib::Error> {
        Err(self.fail(EnclaveError::CrossCheck(
            "BFA genesis names a reject list that is not an EVM contract - this enclave reads \
             only an EVM reject list, refusing to sign"
                .into(),
        )))
    }

    /// The entries as read. rgb-lib refuses a log that reports more finalized
    /// entries than it holds.
    fn get_evm_reject_list(
        &self,
        contract: &EvmContract,
    ) -> std::result::Result<EvmRejectList, rgb_lib::Error> {
        let list = RejectListContract {
            chain_id: contract.chain_id,
            address: contract.address.to_byte_array(),
        };
        self.asked.set(Some(list));
        let log = (self.read)(&list).map_err(|e| self.fail(e))?;
        Ok(EvmRejectList {
            entries: log
                .entries
                .into_iter()
                .map(|e| {
                    // Formatting doubles the buffer as it grows, and rgb-lib
                    // holds every text while it decides.
                    let mut opout = Opout::from(e.opout).to_string();
                    opout.shrink_to_fit();
                    EvmRejectListEntry {
                        opout,
                        reject: e.reject,
                    }
                })
                .collect(),
            finalized: log.finalized,
        })
    }
}
