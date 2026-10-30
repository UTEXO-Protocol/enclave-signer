//! BFA mint anchors and their binding to EVM locks.
//!
//! Each BFA `mint` leaves an external anchor: its own OpId, the amount it
//! issues and the EVM block its lock must precede. Consensus cannot confirm an
//! anchor. The enclave confirms one only against a lock that a binder bound
//! to that exact `(OpId, amount)`: a receipt-verified lock for the mint being
//! signed, a derived deposit id for every other one.
//!
//! The binder lives in `server/bfa.rs`, because it reads the pins and the EVM
//! RPC. This module holds the shapes it works on and rgb-lib's anchor resolver.

use std::cell::RefCell;
use std::collections::BTreeSet;

use amplify::ByteArray;
use rgbstd::containers::{AnchorResolverError, ResolveAnchor, Transfer};
use rgbstd::stl::{BridgeLocation, EvmContract};
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
    /// The mint's `beforeBlock`: its lock must be in an EVM (L2) block < before_block.
    pub before_block: u64,
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
    fn from_genesis(genesis: &Genesis) -> Result<Self> {
        let location = BridgedFungibleAsset::bridge_location(genesis)
            .map_err(|e| EnclaveError::CrossCheck(format!("BFA genesis bridge location: {e}")))?;
        let BridgeLocation::Evm(EvmContract { chain_id, address }) = location;
        Ok(Self {
            chain_id,
            address: address.to_byte_array(),
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

/// Binds mint anchors to locks, or refuses. An empty slice asks only for the
/// pins check and the chain id.
pub type AnchorBinder<'a> = &'a dyn Fn(&BfaBridge, &[MintAnchor]) -> Result<BoundAnchors>;

/// One anchor consensus left open. `last_bundle` holds the OpIds of the
/// bundle a mint PSBT signs.
fn mint_anchor(anchor: &ExternalAnchor, last_bundle: &BTreeSet<OpId>) -> MintAnchor {
    let ExternalAnchor::Mint {
        opid,
        amount,
        before_block,
    } = anchor;
    MintAnchor {
        opid: opid.to_byte_array(),
        amount: *amount,
        before_block: *before_block,
        in_last_bundle: last_bundle.contains(opid),
    }
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

/// rgb-lib's anchor resolver: it confirms each mint anchor only against the
/// lock the binder binds to it, with no RPC, and keeps the pairs.
pub(super) struct BindingResolver<'a> {
    genesis: &'a Genesis,
    bind: AnchorBinder<'a>,
    last_bundle: BTreeSet<OpId>,
    bound: RefCell<Vec<(MintAnchor, VerifiedLock)>>,
    failure: RefCell<Option<EnclaveError>>,
}

impl<'a> BindingResolver<'a> {
    pub(super) fn new(transfer: &'a Transfer, bind: AnchorBinder<'a>) -> Self {
        let last_bundle = transfer
            .bundles
            .iter()
            .last()
            .map(|wb| wb.bundle.known_transitions.iter().map(|k| k.opid).collect())
            .unwrap_or_default();
        Self {
            genesis: &transfer.genesis,
            bind,
            last_bundle,
            bound: RefCell::new(Vec::new()),
            failure: RefCell::new(None),
        }
    }

    /// The binder's own error, which rgb-lib would report as a network one.
    pub(super) fn take_failure(&self) -> Option<EnclaveError> {
        self.failure.borrow_mut().take()
    }

    /// The locks of the anchors rgb-lib confirmed, one for one.
    pub(super) fn into_locks(self) -> Result<Vec<VerifiedLock>> {
        let (anchors, locks): (Vec<_>, Vec<_>) = self.bound.into_inner().into_iter().unzip();
        check_bijection(&anchors, &locks)?;
        Ok(locks)
    }

    fn fail(&self, e: EnclaveError) -> AnchorResolverError {
        let issue = AnchorResolverError::ResolverIssue(e.to_string());
        *self.failure.borrow_mut() = Some(e);
        issue
    }

    /// Asks the binder for `anchors`, from the genesis rgb-lib validated.
    fn bind(
        &self,
        anchors: &[MintAnchor],
    ) -> std::result::Result<BoundAnchors, AnchorResolverError> {
        BfaBridge::from_genesis(self.genesis)
            .and_then(|bridge| (self.bind)(&bridge, anchors))
            .map_err(|e| self.fail(e))
    }
}

impl ResolveAnchor for BindingResolver<'_> {
    /// An empty bind checks the bridge pins and names the chain they are on.
    fn evm_chain_id(&self) -> std::result::Result<u64, AnchorResolverError> {
        self.bind(&[]).map(|bound| bound.evm_chain_id)
    }

    fn is_confirmed(
        &self,
        _location: &BridgeLocation,
        anchor: &ExternalAnchor,
    ) -> std::result::Result<bool, AnchorResolverError> {
        let anchor = mint_anchor(anchor, &self.last_bundle);
        match self.bind(&[anchor])?.locks.as_slice() {
            [lock] if lock.mint_opid == anchor.opid && lock.minted == anchor.amount => {
                self.bound.borrow_mut().push((anchor, lock.clone()));
                Ok(true)
            }
            locks => Err(self.fail(EnclaveError::CrossCheck(format!(
                "{} lock(s) were bound to mint 0x{} of {} units - every mint needs exactly its \
                 own lock",
                locks.len(),
                hex::encode(anchor.opid),
                anchor.amount
            )))),
        }
    }
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
