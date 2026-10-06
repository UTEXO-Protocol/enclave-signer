//! The Bridged Fungible Asset (BFA) schema: transition, assignment and
//! metadata keys, and the mint/burn binding that the enclave reads from a
//! consignment before it signs.
//!
//! The keys are schema constants from `rgb-protocol/rgb-schemas`. A unit test
//! compares them with the crate definitions, so a schema update cannot
//! change them silently.

#[cfg(feature = "bfa-validation")]
use std::io::Cursor;

#[cfg(feature = "bfa-validation")]
use rgbstd::containers::{FileContent, Transfer};

use crate::error::{EnclaveError, Result};

#[cfg(feature = "bfa-validation")]
use super::consignment::extract_transition_summary;
#[cfg(feature = "bfa-validation")]
use super::types::TransitionSummary;

/// BFA transition that moves an asset allocation to a new owner. The
/// send/receive flow uses it as the last transition.
pub const TS_TRANSFER: u16 = 10000;
/// BFA transition that mints units against an EVM lock. The enclave reads
/// its OpIds for the spec section 6 OpId binding.
pub const TS_BRIDGE: u16 = 8014;
/// BFA transition that destroys asset units. In the mint/burn unlock flow it
/// is the last transition. The amount is in its [`MS_BURNED_ASSET`] metadata.
pub const TS_BURN: u16 = 8010;

/// BFA burn metadata key for the destroyed `OS_ASSET` amount. The value is a
/// strict-encoded `rgbstd::Amount` (u64).
pub const MS_BURNED_ASSET: u16 = 1001;
/// BFA burn metadata key for the EVM-side redemption recipient: 32 opaque
/// bytes, mandatory on each `TS_BURN`. Consensus does not validate them.
/// They are inside the burn operation, so its OpId covers them and the
/// spender of the burned units signs them. Thus a release can trust them.
pub const MS_BURN_RECIPIENT: u16 = 1003;

/// BFA fungible assignment type for asset ownership (`assetOwner`). Only
/// these allocations carry asset units.
pub const OS_ASSET: u16 = 4000;
/// BFA declarative assignment type for the mint right (`bridgeRight`). It has
/// no amount, so it cannot add to a minted total.
pub const OS_BRIDGE: u16 = 4014;

/// Decodes one OpId hex string from the parser into 32 bytes.
pub(super) fn decode_opid(hex_opid: &str) -> Result<[u8; 32]> {
    let hex_opid = hex_opid.strip_prefix("0x").unwrap_or(hex_opid);
    let bytes = hex::decode(hex_opid).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "BFA mint opid hex decode failed: {e} ({hex_opid:?})"
        ))
    })?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        EnclaveError::CrossCheck(format!("BFA mint opid is not 32 bytes (got {})", v.len()))
    })
}

/// What the enclave must verify on-chain before RGB consensus sees a BFA
/// operation: the `FundsIn` logs to fetch, and the contract that can emit them.
///
/// Both directions use it. Consensus runs the script of each transition in the
/// consignment again. Thus the `cea` of each earlier mint needs its own
/// verified event, on both paths. A burn contains a full mint ancestry.
/// The mint direction also needs [`BfaBinding::terminal_opid`].
#[cfg(feature = "bfa-validation")]
pub struct BfaBinding {
    /// Each `TS_BRIDGE` in the consignment, in consignment order. Its OpId and
    /// minted units name the one deposit that can back it.
    pub mints: Vec<BfaMint>,
    /// `bridgeLocation` exactly as the asset genesis writes it. It is compared
    /// with the enclave `funds_in_contract` pin before any log is trusted.
    pub bridge_location: String,
    /// The last transition of the consignment, or `None`. Only the mint
    /// direction uses it, through [`Self::terminal_opid`].
    pub(super) last_transition: Option<TransitionSummary>,
}

#[cfg(feature = "bfa-validation")]
impl BfaBinding {
    /// The mint that this request authorizes: the OpId of the last transition.
    /// Only it binds to the deposit of this request. Each other entry in
    /// `mints` is an ancestor with its own deposit.
    ///
    /// Mint direction only. Each failure refuses the signature. If the last
    /// transition is not a bridge mint, or is not in the transition list, the
    /// paying deposit is unknown. Do not guess it.
    pub fn terminal_opid(&self) -> Result<[u8; 32]> {
        let last = self
            .last_transition
            .as_ref()
            .ok_or_else(|| EnclaveError::CrossCheck("BFA consignment has no transitions".into()))?;
        if last.transition_type != TS_BRIDGE {
            return Err(EnclaveError::CrossCheck(format!(
                "BFA consignment's last transition is type {}, expected the bridge mint {}",
                last.transition_type, TS_BRIDGE
            )));
        }
        let terminal_opid = decode_opid(&last.op_id)?;
        // The terminal transition selects the paying deposit, so it must be in
        // the consignment.
        if !self.mints.iter().any(|mint| mint.opid == terminal_opid) {
            return Err(EnclaveError::CrossCheck(
                "BFA consignment's last transition is a bridge mint but is absent from the \
                 transition list - refusing to guess which mint this request authorises"
                    .into(),
            ));
        }
        Ok(terminal_opid)
    }
}

/// One `TS_BRIDGE` of a consignment and the units it minted.
#[cfg(feature = "bfa-validation")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BfaMint {
    pub opid: [u8; 32],
    /// The mint's `OS_ASSET` outputs. Consensus binds them to
    /// `GS_BRIDGED_SUPPLY` and, through `cea`, to the lock event.
    pub minted: u64,
}

/// Reads the BFA binding from raw consignment bytes, before validation.
/// Returns `Ok(None)` for all other schemas.
///
/// A mint spends the bridge right from the previous mint. Thus mint N contains
/// mints 1..N-1, and consensus runs `cea` on each. Each needs its own verified
/// lock.
#[cfg(feature = "bfa-validation")]
pub fn bfa_binding(consignment_bytes: &[u8]) -> Result<Option<BfaBinding>> {
    // Bytes that do not load are not a BFA operation here.
    // `validate_consignment` reports the parse failure, which keeps the error
    // order.
    let Ok(transfer) = Transfer::load(Cursor::new(consignment_bytes)) else {
        return Ok(None);
    };
    if transfer.genesis.schema_id != schemata::BFA_SCHEMA_ID {
        return Ok(None);
    }

    // Use the flat parser, not `read_last_transfer_witness`, which needs the
    // rgbstd validation walk. The OpIds are necessary *before* validation to
    // select the logs to verify.
    let (_, mint_op_ids, last_transition, by_witness) =
        extract_transition_summary(consignment_bytes)?;
    let mints = mint_op_ids
        .iter()
        .map(|hex_opid| {
            let minted = by_witness
                .iter()
                .flat_map(|(_, transitions)| transitions)
                .find(|t| t.transition_type == TS_BRIDGE && &t.op_id == hex_opid)
                .map(|t| t.asset_output_amount)
                .ok_or_else(|| {
                    EnclaveError::CrossCheck(format!(
                        "BFA mint {hex_opid} is not among the consignment's transitions"
                    ))
                })?;
            Ok(BfaMint {
                opid: decode_opid(hex_opid)?,
                minted,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Some(BfaBinding {
        mints,
        bridge_location: genesis_bridge_location(&transfer)?,
        last_transition,
    }))
}

/// Reads the asset `bridgeLocation` from the genesis global state.
///
/// Decoded by hand: `BfaWrapper::bridge_location()` needs a *validated*
/// contract and panics on bad input, and the enclave uses `panic = "abort"`.
/// `BridgeLocation::Ethereum(TinyString)` strict-encodes as a one-byte union
/// tag, a one-byte length, then the address string.
#[cfg(feature = "bfa-validation")]
pub(super) fn genesis_bridge_location(transfer: &Transfer) -> Result<String> {
    let values = transfer
        .genesis
        .globals
        .get(&schemata::GS_BRIDGE_LOCATION)
        .ok_or_else(|| {
            EnclaveError::CrossCheck("BFA genesis carries no bridgeLocation global state".into())
        })?;
    if values.len() != 1 {
        return Err(EnclaveError::CrossCheck(format!(
            "BFA genesis carries {} bridgeLocation values, expected exactly one",
            values.len()
        )));
    }
    decode_bridge_location(values[0].as_slice())
}

/// Strict-decodes one `BridgeLocation` blob. See [`genesis_bridge_location`].
#[cfg(feature = "bfa-validation")]
pub(super) fn decode_bridge_location(raw: &[u8]) -> Result<String> {
    /// `tags = order` on a single-variant union, so `Ethereum` is tag 0.
    const ETHEREUM_TAG: u8 = 0;

    let (&tag, rest) = raw
        .split_first()
        .ok_or_else(|| EnclaveError::CrossCheck("BFA bridgeLocation blob is empty".into()))?;
    if tag != ETHEREUM_TAG {
        return Err(EnclaveError::CrossCheck(format!(
            "BFA bridgeLocation union tag {tag} is not the Ethereum variant"
        )));
    }
    let (&len, addr) = rest.split_first().ok_or_else(|| {
        EnclaveError::CrossCheck("BFA bridgeLocation blob has no length byte".into())
    })?;
    if addr.len() != usize::from(len) {
        return Err(EnclaveError::CrossCheck(format!(
            "BFA bridgeLocation declares {len} bytes but carries {}",
            addr.len()
        )));
    }
    String::from_utf8(addr.to_vec())
        .map_err(|e| EnclaveError::CrossCheck(format!("BFA bridgeLocation is not utf-8: {e}")))
}
