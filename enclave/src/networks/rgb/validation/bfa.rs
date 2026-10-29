//! BFA mint anchors and their binding to EVM locks.
//!
//! Each BFA `mint` leaves an external anchor: its own OpId, the amount it
//! issues and the EVM block its lock must follow. Consensus cannot confirm an
//! anchor. The enclave confirms one only against a lock that a binder bound
//! to that exact `(OpId, amount)`: a receipt-verified lock for the mint being
//! signed, a derived deposit id for every other one.
//!
//! The binder lives in `server/bfa.rs`, because it reads the pins and the EVM
//! RPC. This module holds the shapes it works on and the consensus resolver.

use std::collections::BTreeSet;

use amplify::ByteArray;
use rgbstd::containers::{AnchorResolverError, PendingConsignment, ResolveAnchor};
use rgbstd::stl::{BridgeLocation, EvmAddress, EvmContract};
use rgbstd::validation::ExternalAnchor;
use rgbstd::{Genesis, OpId};
use schemata::BridgedFungibleAsset;

use crate::error::{EnclaveError, Result};

/// One EVM deposit behind a BFA mint, verified from a receipt or derived.
///
/// `operation_id` / `net_amount` are the `BridgeFundsIn` record that the
/// settlement module stored. `operation_id` hashes `net_amount`, so it is the
/// only id that a `fundsOut.settlementData` can cite for this deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLock {
    /// The mint that this lock backs.
    pub mint_opid: [u8; 32],
    pub minted: u64,
    pub operation_id: [u8; 32],
    pub net_amount: u64,
}

/// One mint anchor that phase 1 of consensus left open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintAnchor {
    /// The mint's own OpId.
    pub opid: [u8; 32],
    /// The mint's `issuedSupply`, which consensus made equal to its
    /// `assetOwner` outputs.
    pub amount: u64,
    /// The mint's `afterBlock`: its lock must be in a later EVM block.
    pub after_block: u64,
    /// The mint is in the last bundle: the one a mint PSBT signs.
    pub in_last_bundle: bool,
}

/// The bridge contract that a BFA genesis commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BfaBridge {
    pub chain_id: u64,
    pub address: [u8; 20],
}

impl BfaBridge {
    /// Reads `bridgeLocation` from a genesis that phase 1 validated.
    pub(super) fn from_genesis(genesis: &Genesis) -> Result<Self> {
        let location = BridgedFungibleAsset::bridge_location(genesis)
            .map_err(|e| EnclaveError::CrossCheck(format!("BFA genesis bridge location: {e}")))?;
        let BridgeLocation::Evm(EvmContract { chain_id, address }) = location;
        Ok(Self {
            chain_id,
            address: address.to_byte_array(),
        })
    }

    fn location(&self) -> BridgeLocation {
        BridgeLocation::Evm(EvmContract {
            chain_id: self.chain_id,
            address: EvmAddress::from(amplify::Bytes20::from_byte_array(self.address)),
        })
    }
}

/// The locks a binder bound the anchors to, and the chain id its EVM source
/// reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundAnchors {
    pub evm_chain_id: u64,
    pub locks: Vec<VerifiedLock>,
}

/// Binds every mint anchor of a consignment to a lock, or refuses.
pub type AnchorBinder<'a> = &'a dyn Fn(&BfaBridge, &[MintAnchor]) -> Result<BoundAnchors>;

/// The anchors phase 1 left open. `last_bundle` holds the OpIds of the
/// bundle a mint PSBT signs.
pub(super) fn mint_anchors<'a>(
    unresolved: impl Iterator<Item = &'a ExternalAnchor>,
    last_bundle: &BTreeSet<OpId>,
) -> Vec<MintAnchor> {
    unresolved
        .map(|anchor| {
            let ExternalAnchor::MintEvent {
                opid,
                amount,
                after_block,
            } = anchor;
            MintAnchor {
                opid: opid.to_byte_array(),
                amount: *amount,
                after_block: *after_block,
                in_last_bundle: last_bundle.contains(opid),
            }
        })
        .collect()
}

/// The locks must be the anchors, one for one: an extra lock would be cited in
/// settlement, a missing one would leave a mint unbacked.
pub(super) fn check_bijection(anchors: &[MintAnchor], locks: &[VerifiedLock]) -> Result<()> {
    let wanted: BTreeSet<([u8; 32], u64)> = anchors.iter().map(|a| (a.opid, a.amount)).collect();
    let bound: BTreeSet<([u8; 32], u64)> = locks.iter().map(|l| (l.mint_opid, l.minted)).collect();
    if wanted.len() != anchors.len() || bound.len() != locks.len() || wanted != bound {
        return Err(EnclaveError::CrossCheck(format!(
            "the consignment carries {} mint anchor(s) but {} lock(s) were bound to them - every \
             mint needs exactly its own lock",
            anchors.len(),
            locks.len()
        )));
    }
    Ok(())
}

/// Confirms an anchor only when a bound lock carries its exact
/// `(OpId, amount)`. The binder has checked the bridge pins.
struct BoundLocks<'a>(&'a BoundAnchors);

impl ResolveAnchor for BoundLocks<'_> {
    fn evm_chain_id(&self) -> std::result::Result<u64, AnchorResolverError> {
        Ok(self.0.evm_chain_id)
    }

    fn is_confirmed(
        &self,
        _location: &BridgeLocation,
        anchor: &ExternalAnchor,
    ) -> std::result::Result<bool, AnchorResolverError> {
        let ExternalAnchor::MintEvent { opid, amount, .. } = anchor;
        let opid = opid.to_byte_array();
        Ok(self
            .0
            .locks
            .iter()
            .any(|lock| lock.mint_opid == opid && lock.minted == *amount))
    }
}

/// Phase 2 for the anchors: the checked resolver compares the bound chain id
/// with the genesis one, then each anchor must match a bound lock.
pub(super) fn resolve_anchors(
    pending: &mut PendingConsignment<true>,
    bridge: &BfaBridge,
    bound: &BoundAnchors,
) -> Result<()> {
    pending
        .resolve_all_anchors(bridge.location(), &BoundLocks(bound))
        .map_err(|e| EnclaveError::CrossCheck(format!("BFA mint anchor not confirmed: {e}")))
}

/// Decodes one OpId hex string from the flat parser into 32 bytes.
pub(super) fn decode_opid(hex_opid: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_opid).map_err(|e| {
        EnclaveError::CrossCheck(format!("opid hex decode failed: {e} ({hex_opid:?})"))
    })?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        EnclaveError::CrossCheck(format!("opid is not 32 bytes (got {})", v.len()))
    })
}
