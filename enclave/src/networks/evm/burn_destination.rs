//! Burn destination: what the 32-byte `MS_BURN_RECIPIENT` of a burn commits
//! to. Format spec: `docs/burn-destination.md`.
//!
//! - V0 (legacy): 12 zero bytes + a 20-byte EVM address. Direct route only.
//! - V1: EIP-712 `hashStruct` of `UtexoBurnDestinationV1`. The backend sends
//!   the fields; the enclave hashes them and compares.
//!
//! A new version gets a new type string, so its hashes never match an old one.
//! Every version stays verifiable forever: a burn on RGB is permanent.

use super::{ADDRESS_LEN, HASH_LEN};
use crate::error::{EnclaveError, Result};
use alloy_primitives::Bytes;
use alloy_sol_types::{sol, SolStruct};

sol! {
    /// Record version 1. The type string and encoding come from this struct.
    struct UtexoBurnDestinationV1 {
        uint64 destinationChainId;
        uint32 dstEid;
        bytes recipient;
    }
}

/// Wire value of `version` for [`UtexoBurnDestinationV1`].
pub const VERSION_V1: u32 = 1;

/// The record fields, from proto `EvmDestination.burn_destination`.
/// Transport only: never hashed as bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnDestinationRecord {
    pub version: u32,
    pub destination_chain_id: u64,
    pub dst_eid: u32,
    pub recipient: Vec<u8>,
}

impl From<&crate::proto::BurnDestination> for BurnDestinationRecord {
    fn from(wire: &crate::proto::BurnDestination) -> Self {
        Self {
            version: wire.version,
            destination_chain_id: wire.destination_chain_id,
            dst_eid: wire.dst_eid,
            recipient: wire.recipient.clone(),
        }
    }
}

impl BurnDestinationRecord {
    /// A V1 record.
    pub fn v1(destination_chain_id: u64, dst_eid: u32, recipient: &[u8]) -> Self {
        Self {
            version: VERSION_V1,
            destination_chain_id,
            dst_eid,
            recipient: recipient.to_vec(),
        }
    }

    /// The V1 hash that goes into `MS_BURN_RECIPIENT`.
    pub fn hash_v1(&self) -> [u8; HASH_LEN] {
        self.to_sol_v1().eip712_hash_struct().0
    }

    fn to_sol_v1(&self) -> UtexoBurnDestinationV1 {
        UtexoBurnDestinationV1 {
            destinationChainId: self.destination_chain_id,
            dstEid: self.dst_eid,
            recipient: Bytes::copy_from_slice(&self.recipient),
        }
    }
}

/// The release a burn authorises, in calldata terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnTarget {
    /// `destinationChainId`. `None` for V0: the pin check alone applies.
    pub destination_chain_id: Option<u64>,
    /// `dstEid`. `None` = direct `fundsOut`.
    pub dst_eid: Option<u32>,
    /// Payee, left-padded to one word.
    pub recipient: [u8; HASH_LEN],
}

/// Reads the burn target from the burn metadata and the backend record.
///
/// High 12 bytes zero => V0, and no record is allowed. Otherwise the record is
/// required, its version must be known, and its hash must equal `meta`.
pub fn resolve(meta: &[u8], record: Option<&BurnDestinationRecord>) -> Result<BurnTarget> {
    let meta: &[u8; HASH_LEN] = meta.try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "MS_BURN_RECIPIENT is {} bytes, expected {HASH_LEN}",
            meta.len()
        ))
    })?;

    if meta[..HASH_LEN - ADDRESS_LEN] == [0u8; HASH_LEN - ADDRESS_LEN] {
        if record.is_some() {
            return Err(EnclaveError::CrossCheck(
                "burn_destination sent for a legacy (V0) burn".into(),
            ));
        }
        return Ok(BurnTarget {
            destination_chain_id: None,
            dst_eid: None,
            recipient: *meta,
        });
    }

    let record = record.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "burn commits to a destination hash, but the request has no burn_destination".into(),
        )
    })?;
    match record.version {
        VERSION_V1 => resolve_v1(meta, record),
        v => Err(EnclaveError::CrossCheck(format!(
            "unknown burn_destination version {v}"
        ))),
    }
}

fn resolve_v1(meta: &[u8; HASH_LEN], record: &BurnDestinationRecord) -> Result<BurnTarget> {
    if record.destination_chain_id == 0 {
        return Err(EnclaveError::CrossCheck(
            "burn_destination destinationChainId must be > 0".into(),
        ));
    }
    // Direct: an EVM address. LayerZero: up to one `bytes32` word.
    let len = record.recipient.len();
    let len_ok = if record.dst_eid == 0 {
        len == ADDRESS_LEN
    } else {
        (1..=HASH_LEN).contains(&len)
    };
    if !len_ok {
        return Err(EnclaveError::CrossCheck(format!(
            "burn_destination recipient is {len} bytes (dstEid {})",
            record.dst_eid
        )));
    }
    let hash = record.hash_v1();
    if &hash != meta {
        return Err(EnclaveError::CrossCheck(format!(
            "burn_destination hash 0x{} != burn MS_BURN_RECIPIENT 0x{}",
            hex::encode(hash),
            hex::encode(meta)
        )));
    }
    let mut recipient = [0u8; HASH_LEN];
    recipient[HASH_LEN - len..].copy_from_slice(&record.recipient);
    Ok(BurnTarget {
        destination_chain_id: Some(record.destination_chain_id),
        dst_eid: (record.dst_eid != 0).then_some(record.dst_eid),
        recipient,
    })
}

#[cfg(test)]
mod tests;
