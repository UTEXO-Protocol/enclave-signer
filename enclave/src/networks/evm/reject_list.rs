//! Reads an `IRgbRejectList` contract (bridge-smart-contracts #176) the way
//! rgb-lib 98a8af6 does (`api/evm.rs` `reject_list_entries_paged`).
//!
//! The list is append-only. `length()` is read at the finalized and at the
//! latest block, every page at the latest one. Each failure refuses.

use std::time::{Duration, Instant};

use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};
use attestation_verify::EvmFinalityTag;

use super::events::EvmReceiptProvider;
use crate::error::{EnclaveError, Result};
use crate::networks::rgb::validation::{OpoutKey, RejectListEntry};

sol! {
    /// `IRgbRejectList.Entry`.
    struct Entry {
        bytes32 opId;
        uint16 assignmentType;
        uint16 no;
        bool reject;
    }

    function length() external view returns (uint256);
    function entries(uint256 start, uint256 end) external view returns (Entry[] memory page);
}

/// Entries per `entries` call, as rgb-lib reads them.
pub const PAGE_SIZE: u64 = 1000;

/// A longer list is refused: it bounds the calls and memory of one request.
/// 20 pages: at about a second each they fit the 30 s request deadline.
pub const MAX_ENTRIES: u64 = 20_000;

/// Kept free before the request deadline to write the response.
const RESPONSE_MARGIN: Duration = Duration::from_secs(2);

/// The list as of the latest block, and how many leading entries are
/// finalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectListLog {
    pub entries: Vec<RejectListEntry>,
    pub finalized: usize,
}

/// Reads the whole list at `contract`. Refuses before an RPC call that would
/// end past `deadline`, the request's, judged by the slowest call so far.
pub fn read_reject_list(
    provider: &dyn EvmReceiptProvider,
    contract: &[u8; 20],
    deadline: Instant,
) -> Result<RejectListLog> {
    let mut rpc = Budgeted {
        provider,
        contract,
        deadline,
        slowest: Duration::ZERO,
    };
    let latest = rpc.block_number(EvmFinalityTag::Latest)?;
    // A load-balanced node may report a finalized block past the latest one.
    let finalized = rpc.block_number(EvmFinalityTag::Finalized)?.min(latest);
    // A contract deployed after the finalized block has no finalized entries.
    let finalized_len = rpc.length_at(finalized)?.unwrap_or(0);
    let len = rpc
        .length_at(latest)?
        .ok_or_else(|| list_error(contract, "has no contract code at the latest block".into()))?;
    if finalized_len > len {
        return Err(list_error(
            contract,
            format!("is shorter at the latest block ({len}) than at the finalized one ({finalized_len})"),
        ));
    }
    if len > MAX_ENTRIES {
        return Err(list_error(
            contract,
            format!("holds {len} entries, over the {MAX_ENTRIES} this enclave reads"),
        ));
    }
    Ok(RejectListLog {
        entries: rpc.read_entries(len, latest)?,
        finalized: finalized_len as usize,
    })
}

/// The provider under the request deadline.
struct Budgeted<'a> {
    provider: &'a dyn EvmReceiptProvider,
    contract: &'a [u8; 20],
    deadline: Instant,
    slowest: Duration,
}

impl Budgeted<'_> {
    /// Runs one RPC call if the slowest call so far still fits the deadline.
    fn run<T>(&mut self, call: impl FnOnce(&dyn EvmReceiptProvider) -> Result<T>) -> Result<T> {
        let started = Instant::now();
        if started + self.slowest + RESPONSE_MARGIN > self.deadline {
            return Err(list_error(
                self.contract,
                "read exceeded the request budget (list too long or EVM RPC too slow)".into(),
            ));
        }
        let out = call(self.provider);
        self.slowest = self.slowest.max(started.elapsed());
        out
    }

    fn read_entries(&mut self, len: u64, block: u64) -> Result<Vec<RejectListEntry>> {
        let contract = self.contract;
        let mut out = Vec::with_capacity(len as usize);
        let mut start = 0;
        while start < len {
            let end = (start + PAGE_SIZE).min(len);
            let data = entriesCall {
                start: U256::from(start),
                end: U256::from(end),
            }
            .abi_encode();
            let raw = self.run(|p| p.call(contract, &data, block))?;
            let page = entriesCall::abi_decode_returns_validate(&raw)
                .map_err(|e| list_error(contract, format!("returned a bad entries page: {e}")))?;
            if page.len() as u64 != end - start {
                return Err(list_error(
                    contract,
                    format!("returned {} entries for [{start}, {end})", page.len()),
                ));
            }
            out.extend(page.into_iter().map(entry));
            start = end;
        }
        Ok(out)
    }

    /// `length()` at `block`; `None` when no code is there.
    fn length_at(&mut self, block: u64) -> Result<Option<u64>> {
        let contract = self.contract;
        let raw = self.run(|p| p.call(contract, &lengthCall {}.abi_encode(), block))?;
        if raw.is_empty() {
            return Ok(None);
        }
        let len = lengthCall::abi_decode_returns_validate(&raw)
            .map_err(|e| list_error(contract, format!("returned a bad length: {e}")))?;
        u64::try_from(len)
            .map(Some)
            .map_err(|_| list_error(contract, format!("length {len} does not fit u64")))
    }

    fn block_number(&mut self, tag: EvmFinalityTag) -> Result<u64> {
        self.run(|p| p.get_block_by_tag(tag))?
            .map(|b| b.number)
            .ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "evm-rpc: the node reports no {tag:?} block - cannot read the reject list"
                ))
            })
    }
}

fn entry(e: Entry) -> RejectListEntry {
    RejectListEntry {
        opout: OpoutKey {
            op: e.opId.0,
            ty: e.assignmentType,
            no: e.no,
        },
        reject: e.reject,
    }
}

fn list_error(contract: &[u8; 20], detail: String) -> EnclaveError {
    EnclaveError::CrossCheck(format!(
        "reject list 0x{} {detail} - refusing to sign",
        hex::encode(contract)
    ))
}

#[cfg(test)]
mod tests;
