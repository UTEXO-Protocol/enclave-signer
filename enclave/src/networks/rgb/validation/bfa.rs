//! The Bridged Fungible Asset (BFA) schema: its transition, assignment and
//! metadata keys, plus the mint/burn binding the enclave reads off a
//! consignment before it will sign against one.
//!
//! The keys are schema constants from `rgb-protocol/rgb-schemas`. A unit test
//! checks them against the crate's own definitions, so a schema bump cannot
//! silently move them.

#[cfg(feature = "bfa-validation")]
use std::io::Cursor;

#[cfg(feature = "bfa-validation")]
use rgbstd::containers::{FileContent, Transfer};

#[cfg(feature = "bfa-validation")]
use crate::error::{EnclaveError, Result};

#[cfg(feature = "bfa-validation")]
use super::consignment::extract_transition_summary;
#[cfg(feature = "bfa-validation")]
use super::types::TransitionSummary;

/// BFA transition that moves an existing asset allocation from one
/// owner to another. Pools-mode swaps use this on their last
/// transition.
pub const TS_TRANSFER: u16 = 10000;
/// BFA transition that mints units against an EVM lock. The enclave reads
/// its OpIds for spec section 6 OpId binding.
pub const TS_BRIDGE: u16 = 8014;
/// BFA transition that destroys asset units. Mint-burn unlock flows
/// produce a burn on their last transition; the destroyed amount is
/// in the transition's metadata under [`MS_BURNED_ASSET`].
pub const TS_BURN: u16 = 8010;

/// BFA burn-transition metadata key carrying the destroyed amount of
/// `OS_ASSET` (the regular fungible asset allocation type). The
/// associated value is a strict-encoded `rgbstd::Amount` (u64).
pub const MS_BURNED_ASSET: u16 = 1001;
/// BFA burn metadata carrying where the redemption is owed on the EVM side:
/// 32 opaque bytes the schema makes mandatory on every `TS_BURN`. Consensus
/// neither interprets nor validates them, but they sit inside the burn
/// operation, so they are covered by its OpId and signed by whoever spent
/// the burned units - which is what lets a release trust them.
pub const MS_BURN_RECIPIENT: u16 = 1003;

/// BFA fungible assignment type for regular asset ownership
/// (`assetOwner`) - the allocations that actually carry asset units.
pub const OS_ASSET: u16 = 4000;
/// BFA declarative assignment type carrying the right to mint
/// (`bridgeRight`). It holds no amount, so it can never be summed into a
/// minted total by mistake.
pub const OS_BRIDGE: u16 = 4014;

/// Decode one parser-supplied OpId hex string into 32 bytes.
#[cfg(feature = "bfa-validation")]
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

/// What the enclave must verify on-chain before RGB consensus may see a BFA
/// operation: which `FundsIn` logs to fetch, and which contract may have
/// emitted them.
///
/// Both directions read the same thing. A mint verifies one lock because it
/// *is* one mint, but consensus re-runs the script of every transition in the
/// consignment, so on either path every historical mint's `cea` needs its own
/// verified event - and the burn path carries a whole ancestry of them. The
/// mint direction additionally needs [`BfaBinding::terminal_opid`].
#[cfg(feature = "bfa-validation")]
pub struct BfaBinding {
    /// Every `TS_BRIDGE` OpId in the consignment, in consignment order.
    /// Untrusted - each only selects the log to verify; the ether extension
    /// re-binds it to the operation inside consensus.
    pub mint_opids: Vec<[u8; 32]>,
    /// `bridgeLocation` exactly as the asset's genesis writes it, to compare
    /// against the enclave's own `funds_in_contract` pin before any log is
    /// trusted.
    pub bridge_location: String,
    /// The consignment's last transition, or `None` when it has none. Only the
    /// mint direction cares, via [`Self::terminal_opid`].
    pub(super) last_transition: Option<TransitionSummary>,
}

#[cfg(feature = "bfa-validation")]
impl BfaBinding {
    /// The mint this request authorises: the OpId of the consignment's last
    /// transition. It is the only one bound to the request's own deposit -
    /// every other entry in `mint_opids` is an ancestor and must carry its own.
    ///
    /// Mint-direction only, and every failure refuses the signature: a
    /// consignment whose last transition is not a bridge mint, or whose last
    /// transition is absent from the transition list, gives no answer to "which
    /// deposit pays for this?" and must not be guessed at.
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
        // The terminal transition decides which deposit pays for this mint, so
        // it must be one of the transitions actually in the consignment.
        if !self.mint_opids.contains(&terminal_opid) {
            return Err(EnclaveError::CrossCheck(
                "BFA consignment's last transition is a bridge mint but is absent from the \
                 transition list - refusing to guess which mint this request authorises"
                    .into(),
            ));
        }
        Ok(terminal_opid)
    }
}

/// Read a BFA operation's binding out of raw consignment bytes, before
/// validation. `Ok(None)` for every other schema, so the swap path is untouched.
///
/// A mint spends the bridge right its predecessor rolled forward, so mint N
/// carries mints 1..N-1 in the history consensus re-runs `cea` over. Each one
/// needs its own event, so each needs its own verified lock.
#[cfg(feature = "bfa-validation")]
pub fn bfa_binding(consignment_bytes: &[u8]) -> Result<Option<BfaBinding>> {
    // Bytes that do not load are not a BFA operation as far as this stage is
    // concerned; `validate_consignment` reports the parse failure on the path
    // that owns it, so that ordering of error messages is preserved.
    let Ok(transfer) = Transfer::load(Cursor::new(consignment_bytes)) else {
        return Ok(None);
    };
    if transfer.genesis.schema_id != schemata::BFA_SCHEMA_ID {
        return Ok(None);
    }

    // The flat parser, not `read_last_transfer_witness`: that one reports the
    // OpId rgbstd derived while walking a transfer it is about to validate, and
    // here the OpIds are needed *before* validation, to pick the logs to verify.
    let (_, mint_op_ids, last_transition, _) = extract_transition_summary(consignment_bytes)?;

    Ok(Some(BfaBinding {
        mint_opids: mint_op_ids
            .iter()
            .map(|hex_opid| decode_opid(hex_opid))
            .collect::<Result<Vec<_>>>()?,
        bridge_location: genesis_bridge_location(&transfer)?,
        last_transition,
    }))
}

/// Read the asset's `bridgeLocation` straight out of the genesis global state.
///
/// Hand-decoded because `BfaWrapper::bridge_location()` needs a *validated*
/// contract and panics on anything unexpected, and the enclave builds with
/// `panic = "abort"`. `BridgeLocation::Ethereum(TinyString)` strict-encodes as
/// a one-byte union tag, a one-byte length, then the address string.
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

/// Strict-decode one `BridgeLocation` blob. See [`genesis_bridge_location`].
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
