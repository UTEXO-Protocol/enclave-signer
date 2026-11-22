//! The frames between the burn signer and its validator child, and the
//! records they carry. Both ends are this binary, so these messages are not
//! part of `enclave-proto`.
//!
//! A frame has the layout of a request frame (`crate::framing`). A message of
//! the child has no repeated field: a list is one `bytes` field of records of
//! fixed width, and each variable field is a `Bytes`. So the enclave decodes a
//! frame of the child without a copy of it. The integers of a record are
//! little-endian.

use std::borrow::Cow;
use std::collections::BTreeSet;

use bitcoin::hashes::Hash as _;
use prost::bytes::Bytes;
use rgb_lib::TypeOfTransition;

use super::bfa::{MintAnchor, VerifiedLock};
use super::reject_list::{self, OpoutKey};
use super::types::{ValidatedConsignment, WitnessBlock};
use crate::error::EnclaveError;
use crate::limits::Limits;
use crate::memory::VALIDATOR_FRAME_FIXED_BYTES;
use crate::server::dispatch::{fit_error_text, MAX_ERROR_TEXT_BYTES};

/// A message with no fields.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Empty {}

/// One frame from the enclave to its child.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct ToChild {
    #[prost(oneof = "to_child::Body", tags = "1, 2, 3, 4, 5, 6")]
    pub body: Option<to_child::Body>,
}

pub(super) mod to_child {
    /// What the enclave sends: the start, then one answer for each request.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        /// The first frame.
        #[prost(message, tag = "1")]
        Start(super::Start),
        /// The answer to `BindAsset`.
        #[prost(message, tag = "2")]
        AssetBound(super::Empty),
        /// The answer to `Anchors`.
        #[prost(message, tag = "3")]
        Bound(super::Bound),
        /// The answer to `Header`: its 80-byte consensus encoding.
        #[prost(bytes = "vec", tag = "4")]
        Header(Vec<u8>),
        /// The answer to `RejectList`.
        #[prost(message, tag = "5")]
        Decisions(super::Decisions),
        /// The enclave refused the request and keeps the reason.
        #[prost(message, tag = "6")]
        Refused(super::Empty),
    }
}

/// The values in force and the one job of the child.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Start {
    /// The values in force of the enclave.
    #[prost(message, optional, tag = "1")]
    pub limits: Option<crate::proto::Limits>,
    #[prost(oneof = "start::Job", tags = "2, 3")]
    pub job: Option<start::Job>,
}

pub(super) mod start {
    /// The one job of a child.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Job {
        /// Validate one consignment file.
        #[prost(message, tag = "2")]
        Validate(super::Validate),
        /// Report how the child set itself up.
        #[prost(message, tag = "3")]
        Probe(super::Empty),
    }
}

/// A consignment file to validate.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Validate {
    /// The absolute UTF-8 path of the file that the enclave wrote.
    #[prost(string, tag = "1")]
    pub consignment_path: String,
    /// `ChainNet::prefix()` of the validator.
    #[prost(string, tag = "2")]
    pub chain_net: String,
    /// The one safe-height read of the validation; 0 when there is none.
    #[prost(uint32, tag = "3")]
    pub safe_height: u32,
    /// The enclave binds mint anchors to their locks.
    #[prost(bool, tag = "4")]
    pub bind_anchors: bool,
    /// The enclave reads the reject list of the asset.
    #[prost(bool, tag = "5")]
    pub read_reject_list: bool,
}

/// The answer to `Anchors`.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Bound {
    #[prost(uint64, tag = "1")]
    pub evm_chain_id: u64,
    /// [`LOCK_RECORD_BYTES`] records.
    #[prost(bytes = "vec", tag = "2")]
    pub locks: Vec<u8>,
}

/// The answer to `RejectList`: [`OPOUT_RECORD_BYTES`] records in each list.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Decisions {
    #[prost(bytes = "vec", tag = "1")]
    pub reject: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub allow: Vec<u8>,
}

/// One frame from the child to the enclave.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct ToEnclave {
    #[prost(oneof = "to_enclave::Body", tags = "1, 2, 3, 4, 5, 6")]
    pub body: Option<to_enclave::Body>,
}

pub(super) mod to_enclave {
    /// What the child sends: requests and then its verdict, or a probe report.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "1")]
        BindAsset(super::BindAsset),
        #[prost(message, tag = "2")]
        Anchors(super::Anchors),
        /// The header at this height: `SpvProof.block_height`, at least 1.
        #[prost(uint32, tag = "3")]
        Header(u32),
        #[prost(message, tag = "4")]
        RejectList(super::ListAddress),
        /// The last frame of a `Validate` job.
        #[prost(message, tag = "5")]
        Verdict(super::Verdict),
        /// The only frame of a `Probe` job.
        #[prost(message, tag = "6")]
        Ready(super::Ready),
    }
}

/// Binds the asset of a contract id: UTF-8, at most [`MAX_CONTRACT_ID_BYTES`].
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct BindAsset {
    #[prost(bytes = "bytes", tag = "1")]
    pub contract_id: Bytes,
}

/// Binds mint anchors: no record asks only for the chain id.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Anchors {
    /// [`ANCHOR_RECORD_BYTES`] records.
    #[prost(bytes = "bytes", tag = "1")]
    pub records: Bytes,
}

/// Reads a reject list.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct ListAddress {
    #[prost(uint64, tag = "1")]
    pub chain_id: u64,
    /// The 20-byte address of the list contract.
    #[prost(bytes = "bytes", tag = "2")]
    pub address: Bytes,
}

/// The result of a `Validate` job.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Verdict {
    #[prost(oneof = "verdict::Outcome", tags = "1, 2")]
    pub outcome: Option<verdict::Outcome>,
    /// `VmHWM` of the child, 0 where unknown. Only logged.
    #[prost(uint64, tag = "3")]
    pub peak_rss_bytes: u64,
}

pub(super) mod verdict {
    /// The consignment the child validated, or why it did not.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Outcome {
        /// Boxed, so that a verdict stays as small as the other frames.
        #[prost(message, boxed, tag = "1")]
        Validated(Box<super::Validated>),
        #[prost(message, tag = "2")]
        Refused(super::Refusal),
    }
}

/// The part of a validated consignment that the enclave reads.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Validated {
    /// UTF-8.
    #[prost(bytes = "bytes", tag = "1")]
    pub contract_id: Bytes,
    /// UTF-8: the rgbstd prefix of the network.
    #[prost(bytes = "bytes", tag = "2")]
    pub chain_net: Bytes,
    /// [`WITNESS_BLOCK_RECORD_BYTES`] records, in ascending txid order.
    #[prost(bytes = "bytes", tag = "3")]
    pub witness_blocks: Bytes,
    #[prost(message, optional, tag = "4")]
    pub settling: Option<Settling>,
    /// [`LOCK_RECORD_BYTES`] records.
    #[prost(bytes = "bytes", tag = "5")]
    pub mint_locks: Bytes,
}

/// The settling transition and the witness tx that anchors it.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Settling {
    /// 32 bytes, in the internal order of a `bitcoin::Txid`.
    #[prost(bytes = "bytes", tag = "1")]
    pub witness_txid: Bytes,
    /// 32 bytes.
    #[prost(bytes = "bytes", tag = "2")]
    pub op_id: Bytes,
    /// A [`transition_code`].
    #[prost(uint32, tag = "3")]
    pub transition_type: u32,
    #[prost(uint64, tag = "4")]
    pub asset_output_amount: u64,
    #[prost(uint64, optional, tag = "5")]
    pub burned_asset_amount: Option<u64>,
    /// Empty for none, else 32 bytes.
    #[prost(bytes = "bytes", tag = "6")]
    pub burn_reason: Bytes,
}

/// A refusal of the child: a `REFUSAL_*` kind and a UTF-8 text.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Refusal {
    #[prost(uint32, tag = "1")]
    pub kind: u32,
    #[prost(bytes = "bytes", tag = "2")]
    pub text: Bytes,
}

/// How a probe child set itself up.
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Ready {
    /// Each confinement step passed, and the OOM score reads back at the top.
    #[prost(bool, tag = "1")]
    pub confined: bool,
    #[prost(int32, tag = "2")]
    pub oom_score_adj: i32,
    #[prost(uint64, tag = "3")]
    pub vm_data_bytes: u64,
    #[prost(uint64, tag = "4")]
    pub vm_rss_bytes: u64,
}

/// A refusal with the text of an `EnclaveError::CrossCheck`.
pub(super) const REFUSAL_CROSS_CHECK: u32 = 1;
/// A refusal with the text of an `EnclaveError::Spv`.
pub(super) const REFUSAL_SPV: u32 = 2;
/// A refusal with the text of an `EnclaveError::Internal`, or the display
/// text of any other error.
pub(super) const REFUSAL_INTERNAL: u32 = 3;
/// A refusal with no text: the enclave refused a request and keeps the reason.
pub(super) const REFUSAL_HELD: u32 = 4;

/// The longest contract id a child sends. The display form of a contract id
/// is far shorter, and the refusal of a bind quotes the id.
pub(super) const MAX_CONTRACT_ID_BYTES: usize = 256;

/// A 32-byte id, txid or hash.
const ID_BYTES: usize = size_of::<[u8; 32]>();
/// A witness block: txid in display order, height, hash in internal order.
pub(super) const WITNESS_BLOCK_RECORD_BYTES: usize = ID_BYTES + size_of::<u32>() + ID_BYTES;
/// A lock: lock id, minted amount, operation id, net amount.
pub(super) const LOCK_RECORD_BYTES: usize =
    ID_BYTES + size_of::<u64>() + ID_BYTES + size_of::<u64>();
/// A mint anchor: OpId, lock id, amount, before block.
pub(super) const ANCHOR_RECORD_BYTES: usize =
    ID_BYTES + ID_BYTES + size_of::<u64>() + size_of::<u64>();
/// An opout: OpId, assignment type, output number.
pub(super) const OPOUT_RECORD_BYTES: usize = ID_BYTES + size_of::<u16>() + size_of::<u16>();

pub(super) fn pack_witness_blocks(blocks: &[WitnessBlock]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blocks.len() * WITNESS_BLOCK_RECORD_BYTES);
    for block in blocks {
        out.extend_from_slice(&block.txid);
        out.extend_from_slice(&block.height.to_le_bytes());
        out.extend_from_slice(&block.hash);
    }
    out
}

pub(super) fn unpack_witness_blocks(bytes: &[u8]) -> Result<Vec<WitnessBlock>, String> {
    let records = records::<WITNESS_BLOCK_RECORD_BYTES>(bytes, "witness block")?;
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let mut f = Fields(record);
        out.push(WitnessBlock {
            txid: f.take()?,
            height: u32::from_le_bytes(f.take()?),
            hash: f.take()?,
        });
    }
    Ok(out)
}

pub(super) fn pack_locks(locks: &[VerifiedLock]) -> Vec<u8> {
    let mut out = Vec::with_capacity(locks.len() * LOCK_RECORD_BYTES);
    for lock in locks {
        out.extend_from_slice(&lock.lock_id);
        out.extend_from_slice(&lock.minted.to_le_bytes());
        out.extend_from_slice(&lock.operation_id);
        out.extend_from_slice(&lock.net_amount.to_le_bytes());
    }
    out
}

pub(super) fn unpack_locks(bytes: &[u8]) -> Result<Vec<VerifiedLock>, String> {
    let records = records::<LOCK_RECORD_BYTES>(bytes, "lock")?;
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let mut f = Fields(record);
        out.push(VerifiedLock {
            lock_id: f.take()?,
            minted: u64::from_le_bytes(f.take()?),
            operation_id: f.take()?,
            net_amount: u64::from_le_bytes(f.take()?),
        });
    }
    Ok(out)
}

pub(super) fn pack_anchors(anchors: &[MintAnchor]) -> Vec<u8> {
    let mut out = Vec::with_capacity(anchors.len() * ANCHOR_RECORD_BYTES);
    for anchor in anchors {
        out.extend_from_slice(&anchor.opid);
        out.extend_from_slice(&anchor.lock_id);
        out.extend_from_slice(&anchor.amount.to_le_bytes());
        out.extend_from_slice(&anchor.before_block.to_le_bytes());
    }
    out
}

pub(super) fn unpack_anchors(bytes: &[u8]) -> Result<Vec<MintAnchor>, String> {
    let records = records::<ANCHOR_RECORD_BYTES>(bytes, "mint anchor")?;
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let mut f = Fields(record);
        out.push(MintAnchor {
            opid: f.take()?,
            lock_id: f.take()?,
            amount: u64::from_le_bytes(f.take()?),
            before_block: u64::from_le_bytes(f.take()?),
        });
    }
    Ok(out)
}

pub(super) fn pack_opouts<'a>(opouts: impl Iterator<Item = &'a OpoutKey>) -> Vec<u8> {
    // A set reports its exact length, so the list takes one allocation.
    let mut out = Vec::with_capacity(opouts.size_hint().0.saturating_mul(OPOUT_RECORD_BYTES));
    for opout in opouts {
        out.extend_from_slice(&opout.op);
        out.extend_from_slice(&opout.ty.to_le_bytes());
        out.extend_from_slice(&opout.no.to_le_bytes());
    }
    out
}

pub(super) fn unpack_opouts(bytes: &[u8]) -> Result<BTreeSet<OpoutKey>, String> {
    let records = records::<OPOUT_RECORD_BYTES>(bytes, "opout")?;
    let mut out = BTreeSet::new();
    for record in records {
        let mut f = Fields(record);
        out.insert(OpoutKey {
            op: f.take()?,
            ty: u16::from_le_bytes(f.take()?),
            no: u16::from_le_bytes(f.take()?),
        });
    }
    Ok(out)
}

/// The answer to a reject-list read. The sets drop once packed.
pub(super) fn pack_decisions(decisions: reject_list::Decisions) -> Decisions {
    Decisions {
        reject: pack_opouts(decisions.reject.iter()),
        allow: pack_opouts(decisions.allow.iter()),
    }
}

/// The decisions of an answer to a reject-list read. Each packed list is
/// freed once its set is built.
pub(super) fn unpack_decisions(answer: Decisions) -> Result<reject_list::Decisions, String> {
    let unpack = |packed: Vec<u8>| unpack_opouts(&packed);
    let reject = unpack(answer.reject)?;
    let allow = unpack(answer.allow)?;
    Ok(reject_list::Decisions { reject, allow })
}

/// The largest frame the enclave sends a child under `limits`: the answer to
/// a reject-list read at `max_reject_list_entries`, which can be longer than
/// a request frame. Each other frame of the enclave fits the fixed part.
pub(super) fn enclave_frame_bytes(limits: &Limits) -> u64 {
    limits
        .max_reject_list_entries
        .saturating_mul(OPOUT_RECORD_BYTES as u64)
        .saturating_add(VALIDATOR_FRAME_FIXED_BYTES as u64)
}

/// The records of `N` bytes in `bytes`, or why they do not fit exactly.
fn records<'a, const N: usize>(bytes: &'a [u8], what: &str) -> Result<&'a [[u8; N]], String> {
    match bytes.as_chunks::<N>() {
        (records, []) => Ok(records),
        _ => Err(format!(
            "{} bytes of {what} records, not a whole number of {N}-byte records",
            bytes.len()
        )),
    }
}

/// The fields of one record, read in order.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let (field, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or_else(|| format!("a record ends before a field of {N} bytes"))?;
        self.0 = rest;
        Ok(*field)
    }
}

/// The wire code of a transition type.
pub(super) fn transition_code(transition: TypeOfTransition) -> u32 {
    match transition {
        TypeOfTransition::Inflate => 1,
        TypeOfTransition::Transfer => 2,
        TypeOfTransition::Burn => 3,
        TypeOfTransition::Link => 4,
        TypeOfTransition::TransferInflation => 5,
        TypeOfTransition::TransferLink => 6,
        TypeOfTransition::Mint => 7,
        TypeOfTransition::Propagate => 8,
    }
}

/// The transition type of a wire code, or `None` for a code of no type.
pub(super) fn transition_type(code: u32) -> Option<TypeOfTransition> {
    Some(match code {
        1 => TypeOfTransition::Inflate,
        2 => TypeOfTransition::Transfer,
        3 => TypeOfTransition::Burn,
        4 => TypeOfTransition::Link,
        5 => TypeOfTransition::TransferInflation,
        6 => TypeOfTransition::TransferLink,
        7 => TypeOfTransition::Mint,
        8 => TypeOfTransition::Propagate,
        _ => return None,
    })
}

/// The refusal a child sends for its own error. A cross-check, SPV or internal
/// error keeps its kind and text. Any other error becomes an internal one with
/// its display text, so a child never chooses a retryable code. The text is
/// cut as dispatch cuts the reply of the error the enclave rebuilds, so
/// dispatch returns that reply unchanged.
pub(super) fn refusal(e: &EnclaveError) -> Refusal {
    let (kind, text) = match e {
        EnclaveError::CrossCheck(text) => (REFUSAL_CROSS_CHECK, Cow::Borrowed(text.as_str())),
        EnclaveError::Spv(text) => (REFUSAL_SPV, Cow::Borrowed(text.as_str())),
        EnclaveError::Internal(text) => (REFUSAL_INTERNAL, Cow::Borrowed(text.as_str())),
        // Listed so that a new variant must choose its kind here.
        #[cfg(feature = "kms-persistence")]
        EnclaveError::Custody { .. } => (REFUSAL_INTERNAL, Cow::Owned(e.to_string())),
        EnclaveError::KeyNotInitialized
        | EnclaveError::AlreadyInitialized
        | EnclaveError::InvalidKey(_)
        | EnclaveError::InvalidRequest(_)
        | EnclaveError::Framing(_)
        | EnclaveError::ProtobufDecode(_)
        | EnclaveError::Io(_)
        | EnclaveError::Signing(_)
        | EnclaveError::EvmFinalityPending { .. }
        | EnclaveError::HeadersPending { .. }
        | EnclaveError::NotReady { .. }
        | EnclaveError::Attestation(_)
        | EnclaveError::Certificate(_)
        | EnclaveError::Clone(_)
        | EnclaveError::PcrMismatch { .. }
        | EnclaveError::NonceReplay
        | EnclaveError::ExportCapReached { .. }
        | EnclaveError::DigestMismatch
        | EnclaveError::PubkeyMismatch
        | EnclaveError::IdentityMismatch => (REFUSAL_INTERNAL, Cow::Owned(e.to_string())),
    };
    let prefix = rebuilt(kind, String::new()).map_or_else(|_| String::new(), |e| e.to_string());
    let shown = fit_error_text(format!("{prefix}{text}"));
    Refusal {
        kind,
        text: Bytes::copy_from_slice(&shown.as_bytes()[prefix.len()..]),
    }
}

/// The error of a refusal the child sent, or why the refusal breaks the
/// protocol. A held refusal has no error of its own: the enclave answers with
/// the one it kept.
pub(super) fn refusal_error(refusal: &Refusal) -> Result<EnclaveError, String> {
    if refusal.text.len() > MAX_ERROR_TEXT_BYTES {
        return Err(format!(
            "a refusal text of {} bytes, over {MAX_ERROR_TEXT_BYTES}",
            refusal.text.len()
        ));
    }
    let text = std::str::from_utf8(&refusal.text)
        .map_err(|e| format!("a refusal text that is not UTF-8: {e}"))?
        .to_owned();
    rebuilt(refusal.kind, text)
}

/// The error of a refusal of `kind` with `text`, as the enclave rebuilds it.
fn rebuilt(kind: u32, text: String) -> Result<EnclaveError, String> {
    match kind {
        REFUSAL_CROSS_CHECK => Ok(EnclaveError::CrossCheck(text)),
        REFUSAL_SPV => Ok(EnclaveError::Spv(text)),
        REFUSAL_INTERNAL => Ok(EnclaveError::Internal(text)),
        REFUSAL_HELD => Err("a held refusal, but the enclave refused no request".into()),
        kind => Err(format!("a refusal of the unknown kind {kind}")),
    }
}

/// The outcome of a child after the enclave refused one of its requests.
pub(super) fn held() -> verdict::Outcome {
    verdict::Outcome::Refused(Refusal {
        kind: REFUSAL_HELD,
        text: Bytes::new(),
    })
}

/// What a child sends of the consignment it validated. The transitions by
/// witness and the outputs of the settling transition stay behind.
pub(super) fn validated(consignment: &ValidatedConsignment) -> Validated {
    let settling = match (
        &consignment.settling_transition,
        consignment.settling_witness_txid,
        consignment.settling_op_id,
    ) {
        (Some(transition), Some(txid), Some(op_id)) => Some(Settling {
            witness_txid: Bytes::copy_from_slice(&txid.to_byte_array()),
            op_id: Bytes::copy_from_slice(&op_id),
            transition_type: transition_code(transition.transition_type),
            asset_output_amount: transition.asset_output_amount,
            burned_asset_amount: transition.burned_asset_amount,
            burn_reason: transition
                .burn_reason
                .map_or_else(Bytes::new, |reason| Bytes::copy_from_slice(&reason)),
        }),
        _ => None,
    };
    Validated {
        contract_id: Bytes::copy_from_slice(consignment.contract_id.as_bytes()),
        chain_net: Bytes::copy_from_slice(consignment.chain_net.as_bytes()),
        witness_blocks: pack_witness_blocks(&consignment.witness_blocks).into(),
        settling,
        mint_locks: pack_locks(&consignment.mint_locks).into(),
    }
}

#[cfg(test)]
mod tests;
