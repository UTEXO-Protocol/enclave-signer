//! In-enclave RGB consignment validation using rgbstd + Esplora resolver.
//!
//! Validates raw consignment bytes by deserializing them into an RGB `Transfer`,
//! connecting to an Esplora indexer to resolve witness transactions, and running
//! the full rgbstd validation pipeline. This replaces trusting the Listener's
//! `consignment_valid` boolean.

use std::collections::BTreeSet;
use std::io::Cursor;
#[cfg(feature = "spv")]
use std::time::SystemTime;

use rgb_consignment::{
    ConsignmentInfo, FungibleAllocation, FungibleEntry, SealInfo, TransitionInfo, WitnessInfo,
};
use rgbstd::containers::{ConsignmentExt, FileContent, Transfer};
use rgbstd::indexers::esplora_blocking::esplora_client;
use rgbstd::indexers::AnyResolver;
#[cfg(feature = "bfa-mint")]
use rgbstd::persistence::{MemContract, MemContractState};
use rgbstd::schema::{MetaType, TransitionType};
use rgbstd::validation::{ValidationConfig, ValidationError};
use rgbstd::vm::ether_extension::Event;
#[cfg(feature = "bfa-mint")]
use rgbstd::vm::ether_extension::{BridgedContract, IssuedAmountCheckExt};
use rgbstd::ChainNet;
use sha3::{Digest, Keccak256};

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::networks::ValidationContext;
use crate::proto::RgbSource;

#[cfg(feature = "spv")]
use super::spv_validation;

/// Validate all fields and source-chain evidence owned by an RGB source.
///
/// Does not inspect the destination network. The source-chain proof is:
///
/// 1. raw consignment bytes must be present, hash-bound, and pass full
///    in-enclave RGB validation;
/// 2. the validated consignment asset must match the listener-declared
///    `asset_id` and, when configured, the operator-pinned `RGB_ASSET_ID`;
/// 3. when built with `spv`, every consignment witness tx must have a matching
///    Merkle proof against the in-enclave Bitcoin header chain with sufficient
///    confirmations;
/// 4. when built without `spv`, reject any supplied Merkle proofs so build
///    mismatches fail closed instead of silently ignoring host-provided SPV
///    evidence.
pub fn validate_source(
    source: &RgbSource,
    ctx: &ValidationContext<'_>,
) -> Result<ValidatedConsignment> {
    validate_source_payload(source, ctx.bridge_config)?;

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "RGB source validation requires rgb_validator to be configured".into(),
        )
    })?;

    // A burn consignment carries its whole mint ancestry, and every one of those
    // mint transitions ends in `cea` - consensus re-runs them, so it needs the
    // locks the enclave verified for itself.
    #[cfg(feature = "bfa-mint")]
    let validated = validator.validate_consignment(&source.consignment, ctx.bridge_events)?;
    #[cfg(not(feature = "bfa-mint"))]
    let validated = validator.validate_consignment(&source.consignment, &[])?;

    if validated.contract_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "validated consignment has empty contract_id - cannot bind asset identity".into(),
        ));
    }
    if validated.contract_id != source.asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: consignment has {} but RGB source declares {}",
            validated.contract_id, source.asset_id
        )));
    }
    if ctx.bridge_config.is_configured() {
        if ctx.bridge_config.rgb_asset_id.is_empty() {
            return Err(EnclaveError::CrossCheck(
                "bridge config pinned chain/contract but RGB_ASSET_ID is empty - \
                 set all three env vars or none"
                    .into(),
            ));
        }
        if validated.contract_id != ctx.bridge_config.rgb_asset_id {
            return Err(EnclaveError::CrossCheck(format!(
                "contract_id mismatch: consignment asset {} != pinned RGB_ASSET_ID {}",
                validated.contract_id, ctx.bridge_config.rgb_asset_id
            )));
        }
    }

    #[cfg(feature = "spv")]
    {
        let chain = ctx
            .header_chain
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("SPV header chain lock poisoned: {e}")))?;
        spv_validation::validate_source_chain(
            &chain,
            Some(&validated),
            &source.merkle_proofs,
            SystemTime::now(),
        )?;
    }

    #[cfg(not(feature = "spv"))]
    {
        if !source.merkle_proofs.is_empty() {
            return Err(EnclaveError::CrossCheck(
                "RGB source supplied merkle_proofs but enclave was not built with --features spv"
                    .into(),
            ));
        }
    }

    Ok(validated)
}

fn validate_source_payload(source: &RgbSource, cfg: &BridgeConfig) -> Result<()> {
    if source.consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB source requires raw consignment bytes; consignment_valid is not authoritative"
                .into(),
        ));
    }
    // Aggregate size/compute caps, enforced before the keccak hash and the
    // rgbstd parse so a request cannot force disproportionate work while
    // staying under every per-field cap.
    if source.consignment.len() > cfg.max_consignment_bytes {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source consignment too large: {} bytes (max {})",
            source.consignment.len(),
            cfg.max_consignment_bytes
        )));
    }
    if source.merkle_proofs.len() > cfg.max_merkle_proofs {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source carries too many merkle proofs: {} (max {})",
            source.merkle_proofs.len(),
            cfg.max_merkle_proofs
        )));
    }
    let total_proof_bytes: usize = source
        .merkle_proofs
        .iter()
        .map(|p| p.txid.len() + p.merkle_path.iter().map(|s| s.len()).sum::<usize>())
        .sum();
    if total_proof_bytes > cfg.max_total_proof_bytes {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB source merkle proofs too large in aggregate: {total_proof_bytes} bytes (max {})",
            cfg.max_total_proof_bytes
        )));
    }
    // Integrity, NOT authorization: the listener
    // controls both `consignment` and `consignment_hash`, so a match only
    // proves the wire copy was not corrupted. Authorization comes from the
    // in-enclave RGB validation, SPV anchoring, and the binding of validated
    // facts (contract_id / op_id / amount).
    if source.consignment_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "consignment present but consignment_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(&source.consignment);
    if computed[..] != source.consignment_hash {
        return Err(EnclaveError::CrossCheck(
            "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
        ));
    }
    if source.asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB source asset_id is empty".into(),
        ));
    }

    Ok(())
}

/// Schema-defined `transition_type` and `metadata` keys for the Inflatable
/// Fungible Asset (IFA) schema used for USDT, from `rgb-protocol/rgb-schemas`
/// (`TS_*` transition-type ids, `MS_*` metadata-type ids). Rotating the schema
/// means updating these.
pub mod ifa {
    /// IFA transition that moves an existing asset allocation from one
    /// owner to another. Pools-mode swaps use this on their last
    /// transition.
    pub const TS_TRANSFER: u16 = 10000;
    /// IFA transition that mints new units against the contract's inflation
    /// rights. The enclave reads its OpIds for spec section 6 OpId binding.
    pub const TS_INFLATION: u16 = 8000;
    /// IFA transition that destroys asset units. Mint-burn unlock flows
    /// produce a burn on their last transition; the destroyed amount is
    /// in the transition's metadata under [`MS_BURNED_ASSET`].
    pub const TS_BURN: u16 = 8010;

    /// IFA burn-transition metadata key carrying the destroyed amount of
    /// `OS_ASSET` (the regular fungible asset allocation type). The
    /// associated value is a strict-encoded `rgbstd::Amount` (u64).
    pub const MS_BURNED_ASSET: u16 = 1001;

    /// IFA fungible assignment type for regular asset ownership
    /// (`assetOwner`) - the allocations that actually carry asset units.
    pub const OS_ASSET: u16 = 4000;
    /// IFA fungible assignment type carrying the remaining right-to-mint
    /// (`inflationAllowance`). Its `amount` is mint capacity, not asset units;
    /// summing it with `OS_ASSET` would let a consignment claim allowance as
    /// minted value.
    pub const OS_INFLATION: u16 = 4010;
}

/// Transition and assignment types of the BFA (Bridged Fungible Asset) schema.
///
/// BFA mints differently from IFA: the right it spends is DECLARATIVE - `OS_BRIDGE`
/// carries no amount at all - and the minted amount is checked by RGB consensus
/// against the bridge contract's `FundsIn` log rather than against a right the
/// wallet holds. Transfer and burn keep IFA's types and values.
#[cfg(feature = "rgb-validation")]
pub mod bfa {
    /// BFA transition that mints units against an EVM lock. The enclave reads its
    /// OpIds for the same OpId binding it does for IFA `TS_INFLATION`.
    pub const TS_BRIDGE: u16 = 8014;
    /// BFA declarative assignment type carrying the right to mint (`bridgeRight`).
    /// Unlike IFA's `OS_INFLATION` it holds no amount, so it can never be summed
    /// into a minted total by mistake.
    pub const OS_BRIDGE: u16 = 4014;
    /// BFA burn metadata carrying where the redemption is owed on the EVM side:
    /// 32 opaque bytes the schema makes mandatory on every `TS_BURN`. Consensus
    /// neither interprets nor validates them, but they sit inside the burn
    /// operation, so they are covered by its OpId and signed by whoever spent
    /// the burned units - which is what lets a release trust them.
    pub const MS_BURN_RECIPIENT: u16 = 1003;
}

/// Decode one parser-supplied OpId hex string into 32 bytes.
#[cfg(feature = "bfa-mint")]
fn decode_opid(hex_opid: &str) -> Result<[u8; 32]> {
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
/// mint: which `FundsIn` logs to fetch, and which contract may have emitted
/// them.
#[cfg(feature = "bfa-mint")]
pub struct BfaMintBinding {
    /// Every `TS_BRIDGE` OpId in the consignment, in consignment order.
    /// Untrusted - each only selects the log to verify; the ether extension
    /// re-binds it to the operation inside consensus.
    pub mint_opids: Vec<[u8; 32]>,
    /// The mint this request authorises: the OpId of the consignment's last
    /// transition. It is the only one bound to the request's own deposit -
    /// every other entry is an ancestor and must carry its own.
    pub terminal_opid: [u8; 32],
    /// `bridgeLocation` exactly as the asset's genesis writes it.
    pub bridge_location: String,
}

/// Read a BFA mint's binding out of raw consignment bytes, before validation.
/// `Ok(None)` for every other schema, so the swap path is untouched.
#[cfg(feature = "bfa-mint")]
pub fn bfa_mint_binding(consignment_bytes: &[u8]) -> Result<Option<BfaMintBinding>> {
    // Bytes that do not load are not a BFA mint as far as this stage is
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
    // here the OpId is needed *before* validation, to pick the log to verify.
    let (_, mint_op_ids, last_transition, _) = extract_transition_summary(consignment_bytes)?;

    let last = last_transition
        .ok_or_else(|| EnclaveError::CrossCheck("BFA consignment has no transitions".into()))?;
    if last.transition_type != bfa::TS_BRIDGE {
        return Err(EnclaveError::CrossCheck(format!(
            "BFA consignment's last transition is type {}, expected the bridge mint {}",
            last.transition_type,
            bfa::TS_BRIDGE
        )));
    }
    let terminal_opid = decode_opid(&last.op_id)?;

    // A mint spends the bridge right its predecessor rolled forward, so mint N
    // carries mints 1..N-1 in the history consensus re-runs `cea` over. Each one
    // needs its own event, so each needs its own verified lock.
    let mut mint_opids = Vec::with_capacity(mint_op_ids.len());
    for hex_opid in &mint_op_ids {
        mint_opids.push(decode_opid(hex_opid)?);
    }
    // The terminal transition decides which deposit pays for this mint, so it
    // must be one of the transitions actually in the consignment.
    if !mint_opids.contains(&terminal_opid) {
        return Err(EnclaveError::CrossCheck(
            "BFA consignment's last transition is a bridge mint but is absent from the \
             transition list - refusing to guess which mint this request authorises"
                .into(),
        ));
    }

    Ok(Some(BfaMintBinding {
        mint_opids,
        terminal_opid,
        bridge_location: genesis_bridge_location(&transfer)?,
    }))
}

/// Every `TS_BRIDGE` transition a BFA consignment descends from, plus the
/// asset's genesis `bridgeLocation`.
///
/// The mint direction verifies one lock because it *is* one mint. A burn is
/// different: consensus re-runs the script of every transition in the
/// consignment, so every historical mint's `cea` needs its own verified event.
/// This is the flat parse, deliberately - the OpIds are needed *before*
/// validation, to pick which logs to fetch.
#[cfg(feature = "bfa-mint")]
pub fn bfa_ancestry_binding(consignment_bytes: &[u8]) -> Result<Option<BfaAncestryBinding>> {
    let Ok(transfer) = Transfer::load(Cursor::new(consignment_bytes)) else {
        return Ok(None);
    };
    if transfer.genesis.schema_id != schemata::BFA_SCHEMA_ID {
        return Ok(None);
    }

    let (_, mint_op_ids, _, _) = extract_transition_summary(consignment_bytes)?;

    let mut opids = Vec::with_capacity(mint_op_ids.len());
    for hex_opid in &mint_op_ids {
        opids.push(decode_opid(hex_opid)?);
    }

    Ok(Some(BfaAncestryBinding {
        mint_opids: opids,
        bridge_location: genesis_bridge_location(&transfer)?,
    }))
}

/// What the enclave must verify on-chain before RGB consensus may see a BFA
/// burn: every mint in the consignment's ancestry, and the contract allowed to
/// have emitted their `FundsIn` logs.
#[cfg(feature = "bfa-mint")]
pub struct BfaAncestryBinding {
    /// OpIds of every `TS_BRIDGE` transition in the consignment. Untrusted -
    /// they only select which logs to fetch; each one is then verified.
    pub mint_opids: Vec<[u8; 32]>,
    /// The asset's genesis `bridgeLocation`, to compare against the enclave's
    /// own `funds_in_contract` pin before any log is trusted.
    pub bridge_location: String,
}

/// Read the asset's `bridgeLocation` straight out of the genesis global state.
///
/// Hand-decoded because `BfaWrapper::bridge_location()` needs a *validated*
/// contract and panics on anything unexpected, and the enclave builds with
/// `panic = "abort"`. `BridgeLocation::Ethereum(TinyString)` strict-encodes as
/// a one-byte union tag, a one-byte length, then the address string.
#[cfg(feature = "bfa-mint")]
fn genesis_bridge_location(transfer: &Transfer) -> Result<String> {
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
#[cfg(feature = "bfa-mint")]
fn decode_bridge_location(raw: &[u8]) -> Result<String> {
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

/// Resolve the trusted strict type-system to pin a consignment against, keyed
/// on its `schema_id` and sourced from the canonical `rgb-schemas` crate.
///
/// `ValidationConfig.trusted_typesystem` must never come
/// from the consignment under validation. Feeding `transfer.types` back in
/// makes rgbstd compare the consignment's types against themselves, so the
/// control always passes and a malicious consignment can ship its own type
/// definitions for the schema's `SemId`s.
///
/// All four standard fungible/collectible schemas are accepted; the exact asset
/// is pinned separately via `contract_id` -> `RGB_ASSET_ID`. An unknown
/// schema_id is rejected fail-closed. Schema ids are compared by canonical
/// string form so the comparison survives `rgb-schemas` resolving a different
/// `rgb-consensus` build than the validator.
#[cfg(feature = "rgb-validation")]
fn trusted_typesystem_for_schema(schema_id: &str) -> Result<rgbstd::TypeSystem> {
    use rgbstd::contract::IssuerWrapper;
    use schemata::{
        CollectibleFungibleAsset, InflatableFungibleAsset, NonInflatableAsset, UniqueDigitalAsset,
        CFA_SCHEMA_ID, IFA_SCHEMA_ID, NIA_SCHEMA_ID, UDA_SCHEMA_ID,
    };

    // Only a `bfa-mint` build knows the bridged schema; without the feature it
    // falls through to the fail-closed arm exactly as it did before BFA existed.
    #[cfg(feature = "bfa-mint")]
    {
        if schema_id == schemata::BFA_SCHEMA_ID.to_string() {
            return Ok(schemata::BridgedFungibleAsset::types());
        }
    }

    let types = if schema_id == IFA_SCHEMA_ID.to_string() {
        InflatableFungibleAsset::types()
    } else if schema_id == NIA_SCHEMA_ID.to_string() {
        NonInflatableAsset::types()
    } else if schema_id == CFA_SCHEMA_ID.to_string() {
        CollectibleFungibleAsset::types()
    } else if schema_id == UDA_SCHEMA_ID.to_string() {
        UniqueDigitalAsset::types()
    } else {
        return Err(EnclaveError::CrossCheck(format!(
            "consignment uses unknown/unsupported RGB schema {schema_id} - refusing to validate \
             (cannot source a trusted type system)"
        )));
    };
    Ok(types)
}

/// Data extracted from a successfully validated RGB consignment.
#[derive(Debug, Clone)]
pub struct ValidatedConsignment {
    /// RGB contract identifier (e.g., "rgb:2TGhRyP3-..."). Globally unique
    /// per asset; derived from the genesis operation in RGB 0.11.
    pub contract_id: String,
    /// Bitcoin network the consignment is anchored to, in rgbstd's prefix
    /// form: `"bc"`, `"bc:testnet3"`/`"tb"`, `"bc:signet"`/`"sb"`, or `"bc:regtest"`.
    /// Used to reject cross-network replay (e.g. a regtest consignment
    /// presented to a mainnet enclave).
    pub chain_net: String,
    /// Bitcoin txids that anchor each transition bundle in the consignment,
    /// in **display (big-endian) byte order** - same encoding as
    /// `MerkleProofEntry.txid` on the wire. Deduplicated and sorted so
    /// equality checks against the listener's set are stable.
    pub witness_txids: Vec<[u8; 32]>,
    /// Every state-transition `op_id` in the consignment, in witness order
    /// (bundle k's transitions before bundle k+1's). Spec section 6 requires
    /// every mint OpId committed to EVM state to be cross-checked across RGB
    /// validations.
    pub all_op_ids: Vec<String>,
    /// The `op_id`s of every IFA `TS_INFLATION` (mint) transition in the
    /// consignment, in witness order - the subset of [`Self::all_op_ids`]
    /// that corresponds to EVM lock records (`fundsIn`).
    ///
    /// Not currently consumed by the EVM side: on the route-agnostic Bridge
    /// the `fundsOut` citation comes from deposit receipts and is enforced
    /// on-chain by `RgbSettlementModule.beforeFundsOut`. Kept as the RGB half
    /// of that correspondence.
    pub mint_op_ids: Vec<String>,
    /// The most recent state transition: the state change the EVM action this
    /// consignment authorises commits to. `None` only for malformed transfers
    /// with no transition bundles, which rgbstd rejects upstream.
    pub last_transition: Option<TransitionSummary>,
    /// Bitcoin txid of the witness transaction anchoring the last transition,
    /// whatever its transition type (burn included).
    ///
    /// Two consumers. In the send-RGB direction the PSBT being signed IS that
    /// witness tx, and the PSBT cross-check binds
    /// `psbt.unsigned_tx.compute_txid()` to this after gating on the last
    /// transition being a Transfer or Inflation. The RGB->EVM `fundsOut`
    /// source-block bind uses it ungated, so it works for transfer and burn
    /// alike.
    ///
    /// A `bitcoin::Txid` rather than display-order bytes, to avoid the txid
    /// byte-order footgun. `None` only for a consignment with no bundles.
    pub last_witness_txid: Option<bitcoin::Txid>,
    /// Bitcoin input prevouts of that witness transaction, when the
    /// consignment embeds the full tx (`PubWitness::Tx`). Used by the PSBT
    /// cross-check as a redundant per-input canary over the txid bind. `None`
    /// for `PubWitness::Txid`, where the txid bind alone anchors every input.
    pub last_transfer_witness_prevouts: Option<Vec<bitcoin::OutPoint>>,
    /// Authoritative OpId (32-byte commitment hash) of the consignment's
    /// **last** transition, read from the rgbstd-**validated** `Transfer`
    /// (`KnownTransition.opid` of the same last bundle as
    /// `last_witness_txid`), NOT from the flat `rgb_consignment`
    /// parser. This is the value `validate()` authenticated and anchored on
    /// chain.
    ///
    /// No longer feeds the EVM `fundsOut` `burnId`: the new
    /// Bridge derives that itself and reverts `InvalidBurnId` otherwise. `None`
    /// for a consignment with no bundles or a non-Transfer last transition.
    pub last_transfer_op_id: Option<[u8; 32]>,
    /// Witness txids that rgbstd `validate()` classified as **not mined**
    /// (`WitnessOrd::Tentative` / `Ignored`), in **display (big-endian) byte
    /// order** - same encoding as [`Self::witness_txids`]. `validate()` already
    /// hard-rejects `Archived`/unresolvable witnesses, so only these softer
    /// not-yet-confirmed states reach here, and only because this set is built
    /// from the rgbstd status that was previously discarded.
    ///
    /// A non-empty set is **expected** for the send-RGB (EVM-lock -> RGB-send)
    /// PSBT path: that witness tx is freshly composed and unbroadcast, so it is
    /// legitimately `Tentative`. It is an **anomaly** for the RGB->EVM
    /// `fundsOut` direction, where the witness is already confirmed on-chain
    /// and SPV-verified - the SignEvm path rejects any non-mined witness as
    /// defense-in-depth atop the SPV depth check (see
    /// `evm::validation::assert_witnesses_confirmed`).
    pub non_mined_witness_txids: Vec<[u8; 32]>,
    /// Every transition in the consignment, grouped by the witness tx that
    /// commits it.
    ///
    /// A single Bitcoin transaction commits a bundle, which may hold several
    /// transitions. Binding only [`Self::last_transition`] would let an
    /// attacker park a large transfer earlier in the bundle, so the send-RGB
    /// PSBT cross-check binds the whole group via
    /// [`Self::transitions_committed_by`].
    pub transitions_by_witness: Vec<(bitcoin::Txid, Vec<TransitionSummary>)>,
}

impl ValidatedConsignment {
    /// Every transition committed by witness transaction `txid`.
    ///
    /// Empty when the consignment commits nothing to that transaction - which
    /// callers must treat as a rejection, not as "nothing to check".
    pub fn transitions_committed_by(&self, txid: bitcoin::Txid) -> Vec<&TransitionSummary> {
        self.transitions_by_witness
            .iter()
            .filter(|(witness_txid, _)| *witness_txid == txid)
            .flat_map(|(_, transitions)| transitions.iter())
            .collect()
    }
}

/// Flat summary of one RGB state transition. Mirrors
/// `rgb_consignment::TransitionInfo` but in types we own, so the parser dep
/// doesn't leak into our public surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionSummary {
    /// Operation id: 64-char lowercase hex of the 32-byte RGB OpId, as the
    /// parser yields it. The hex form is load-bearing, not baid64 -
    /// `evm::crosscheck::decode_op_id_to_bytes32` decodes it to 32 bytes.
    pub op_id: String,
    /// IFA-schema transition-type id; compare against [`ifa::TS_TRANSFER`]
    /// / [`ifa::TS_BURN`] / [`ifa::TS_INFLATION`] to classify the EVM
    /// action this consignment authorises.
    pub transition_type: u16,
    /// Sum of all fungible amounts across all output assignments of this
    /// transition. For a Transfer this is the total of recipient + change
    /// outputs; for a Burn this is **zero** because burns have no output
    /// assignments - the destroyed amount lives in [`Self::burned_asset_amount`].
    pub total_output_amount: u64,
    /// Sum of the fungible amounts on `OS_ASSET`-typed output assignments
    /// only - the allocations that actually carry asset units. For a
    /// Transfer this equals [`Self::total_output_amount`] (transfers move
    /// only `OS_ASSET`); for an Inflation (mint) it is the freshly minted
    /// value, **excluding** the `OS_INFLATION` allowance outputs, whose
    /// amounts are remaining mint capacity, not asset units.
    pub asset_output_amount: u64,
    /// Concrete output assignments, each tagged with a destination seal
    /// and an amount. Empty for Burn transitions.
    pub outputs: Vec<TransitionOutput>,
    /// Asset units destroyed by this transition, from the IFA
    /// `MS_BURNED_ASSET` metadata field. `Some(0)` is schema-legal, but the
    /// EVM cross-check layer requires it strictly positive to sign an unlock.
    ///
    /// `None` when the transition is not a burn, or when a burn transition is
    /// malformed (which rgbstd validation should already have rejected).
    pub burned_asset_amount: Option<u64>,
    /// Where the burn's proceeds are owed on the EVM side, from the BFA
    /// `MS_BURN_RECIPIENT` metadata field: exactly 32 bytes, as the schema
    /// requires. `None` for a non-burn, and for an IFA burn, which declares
    /// `burnedInflation` in that slot instead.
    pub burn_recipient: Option<Vec<u8>>,
}

/// One fungible output assignment on a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionOutput {
    /// IFA fungible assignment type ([`ifa::OS_ASSET`] or
    /// [`ifa::OS_INFLATION`]). Load-bearing: only `OS_ASSET` entries carry
    /// asset units, so the per-output recipient bind must filter on this just
    /// as `asset_output_amount` does.
    pub assignment_type: u16,
    /// Amount in the asset's smallest unit.
    pub amount: u64,
    /// Destination seal - either a revealed `txid:vout` or a hidden
    /// commitment.
    pub seal: OutputSeal,
}

/// Where a fungible output lives. Mirrors `rgb_consignment::SealInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSeal {
    /// Concrete `txid:vout`. `txid` is `None` when the seal points at the
    /// witness tx of its containing bundle - resolve by combining with
    /// the bundle's witness txid in display order.
    Revealed {
        /// Display-order bytes - matches `witness_txids` encoding.
        txid: Option<[u8; 32]>,
        vout: u32,
    },
    /// Hidden recipient seal (`utxob:...` SHA-256 commitment string).
    Confidential { secret_seal: String },
}

/// Hard cap on a single blocking Esplora HTTP call (connect + read), in
/// seconds. The egress runs through the host-controlled vsock proxy on the
/// signing path, so without a timeout a stalled host pins the worker
/// thread. Aligned with `conn.rs`'s `TOTAL_REQUEST_TIMEOUT`.
/// Compile-time and PCR-attested, not host-tunable.
const ESPLORA_HTTP_TIMEOUT_SECS: u64 = 30;

/// Per-socket timeout (seconds) for the Electrum witness resolver, the
/// production signing path. Electrum analog of [`ESPLORA_HTTP_TIMEOUT_SECS`]
/// and the same problem: `Config::default()` leaves
/// `timeout: None`, so a stalled electrs read blocks the worker thread forever
/// and eventually wedges the whole enclave. `electrum-client` retries `retry`
/// times, so worst-case blocking is ~`(retry+1) *` this; kept within the
/// `conn.rs` `TOTAL_REQUEST_TIMEOUT` budget. Compile-time and PCR-attested.
const ELECTRUM_WITNESS_TIMEOUT_SECS: u64 = 15;

// TEMPORARY, tied to the BFA dependency base. The `s/bfa` RGB branches are cut
// from 0.11.1-rc.10, which pins electrum-client 0.24, while this crate targets
// the 0.25 API that came with rc.11: `timeout` took a `Duration` and
// `estimate_fee` a second argument. The three call sites below were stepped
// back to the 0.24 shapes purely so the branch builds. REVERT THEM once the
// `s/bfa` branches are rebased onto rc.11 - this is an upstream fix, not ours.

/// How long a fetched fee estimate stays fresh. Fee markets move on
/// block cadence, so a minute of staleness is immaterial while keeping the
/// sign-path from hitting Esplora on every request.
const FEE_ESTIMATE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Confirmation target (blocks) used for the recommended fee rate.
const FEE_ESTIMATE_TARGET: u16 = 6;

/// Fee-rate floor (sat/vB) for non-mainnet chains, which have no fee market and
/// answer `/fee-estimates` with `{}`. Compile-time and reachable only via
/// PCR0-attested `chain_net`, so serving `{}` to dodge the check only yields a
/// tighter floor. Generous, since non-mainnet coins are valueless.
const NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB: f64 = 10.0;

/// Validates RGB consignments using rgbstd and a witness resolver.
///
/// The resolver backend is chosen from the URL scheme at validation time:
/// `ssl://` / `tcp://` -> Electrum (`electrum-client`), anything else
/// (`http://` / `https://`) -> Esplora REST. Production uses an Electrum
/// endpoint (`ssl://...:50002`) reached through the vsock forwarder; with an
/// `ssl://` URL the TLS handshake terminates inside the enclave against the
/// real server cert, so the host relays only ciphertext.
#[derive(Debug)]
pub struct RgbValidator {
    indexer_url: String,
    chain_net: ChainNet,
    /// Cached `(fetched_at, sat/vB)` recommended fee rate, guarded for
    /// the multi-threaded worker pool. `None` until the first fetch.
    fee_estimate_cache: std::sync::Mutex<Option<(std::time::Instant, f64)>>,
    /// Per-request HTTP timeout, [`ESPLORA_HTTP_TIMEOUT_SECS`] in production.
    /// Overridable only from tests (no env / host input reaches it).
    http_timeout_secs: u64,
}

impl RgbValidator {
    /// Create a new validator.
    ///
    /// - `indexer_url`: witness-resolver endpoint. `ssl://host:port` /
    ///   `tcp://host:port` selects Electrum; `http(s)://...` selects Esplora.
    ///   Through the vsock forwarder this is typically `ssl://<host>:50002`
    ///   (Electrum) or the legacy `http://127.0.0.1:3443` (Esplora).
    /// - `bitcoin_network`: One of "bitcoin", "testnet", "signet", "regtest".
    pub fn new(indexer_url: String, bitcoin_network: &str) -> Result<Self> {
        let chain_net = match bitcoin_network {
            "bitcoin" | "mainnet" => ChainNet::BitcoinMainnet,
            "testnet" | "testnet3" => ChainNet::BitcoinTestnet3,
            "signet" => ChainNet::BitcoinSignet,
            "regtest" => ChainNet::BitcoinRegtest,
            other => {
                return Err(EnclaveError::Internal(format!(
                    "unknown bitcoin network: {other}"
                )))
            }
        };
        tracing::info!(%indexer_url, %bitcoin_network, "RGB validator configured");
        Ok(Self {
            indexer_url,
            chain_net,
            fee_estimate_cache: std::sync::Mutex::new(None),
            http_timeout_secs: ESPLORA_HTTP_TIMEOUT_SECS,
        })
    }

    /// Shrink the HTTP timeout so the stalled-host test doesn't wait the
    /// production budget. Test-only by construction.
    #[cfg(test)]
    fn with_http_timeout(mut self, secs: u64) -> Self {
        self.http_timeout_secs = secs;
        self
    }

    /// Recommended fee rate (sat/vB) from the enclave's own witness-indexer
    /// egress, for the send-RGB PSBT fee-rate check. The backend mirrors the
    /// resolver: Electrum `estimate_fee` for ssl://|tcp://, else Esplora
    /// `/fee-estimates` at [`FEE_ESTIMATE_TARGET`]. Cached for
    /// [`FEE_ESTIMATE_TTL`]. Fail-closed when the fetch fails or the rate is
    /// unusable. The one exception is an honest "no fee market" answer on a
    /// non-mainnet chain, which yields
    /// [`NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB`].
    pub fn recommended_fee_rate_sat_vb(&self) -> Result<f64> {
        let now = std::time::Instant::now();
        let mut cache = self
            .fee_estimate_cache
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("fee-estimate cache poisoned: {e}")))?;
        if let Some((fetched_at, rate)) = *cache {
            if now.duration_since(fetched_at) < FEE_ESTIMATE_TTL {
                return Ok(rate);
            }
        }

        // Backend mirrors the witness resolver: ssl://|tcp:// is Electrum,
        // anything else Esplora REST. Both paths are fail-closed - a failed
        // fetch is a refusal, never a skipped check.
        let is_electrum =
            self.indexer_url.starts_with("ssl://") || self.indexer_url.starts_with("tcp://");
        let rate = if is_electrum {
            self.electrum_fee_rate_sat_vb()?
        } else {
            self.esplora_fee_rate_sat_vb()?
        };

        if !rate.is_finite() || rate <= 0.0 {
            return Err(EnclaveError::CrossCheck(format!(
                "fee-estimate response is not a positive finite rate: {rate}"
            )));
        }

        *cache = Some((now, rate));
        Ok(rate)
    }

    /// Fetch a raw transaction by txid from the witness indexer.
    ///
    /// The egress is host-controlled, so the bytes are re-hashed and must match
    /// `txid`: a lying host can only make the fetch fail. Used by the send-RGB
    /// change-leg proof (W-06 / #52) to read the script of an outpoint that is
    /// not in the PSBT.
    pub fn fetch_transaction(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
        // Backend and timeouts mirror the witness resolver (final I-03 / #87).
        let is_electrum =
            self.indexer_url.starts_with("ssl://") || self.indexer_url.starts_with("tcp://");
        let tx = if is_electrum {
            use rgbstd::indexers::electrum_blocking::electrum_client::{
                Client, Config, ElectrumApi,
            };
            let cfg = Config::builder()
                .timeout(Some(ELECTRUM_WITNESS_TIMEOUT_SECS as u8))
                .build();
            let client = Client::from_config(&self.indexer_url, cfg).map_err(|e| {
                EnclaveError::CrossCheck(format!(
                    "electrum client creation failed while resolving outpoint tx {txid}: {e}"
                ))
            })?;
            let raw = client.transaction_get_raw(&txid).map_err(|e| {
                EnclaveError::CrossCheck(format!("electrum fetch of tx {txid} failed: {e}"))
            })?;
            bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw).map_err(|e| {
                EnclaveError::CrossCheck(format!(
                    "electrum returned bytes for tx {txid} that do not decode: {e}"
                ))
            })?
        } else {
            let client = esplora_client::Builder::new(&self.indexer_url)
                .timeout(self.http_timeout_secs)
                .build_blocking();
            client
                .get_tx(&txid)
                .map_err(|e| {
                    EnclaveError::CrossCheck(format!("esplora fetch of tx {txid} failed: {e}"))
                })?
                .ok_or_else(|| {
                    EnclaveError::CrossCheck(format!("esplora does not know tx {txid}"))
                })?
        };

        let got = tx.compute_txid();
        if got != txid {
            return Err(EnclaveError::CrossCheck(format!(
                "indexer returned tx {got} for a request for tx {txid} - refusing to trust its \
                 outputs"
            )));
        }
        Ok(tx)
    }

    /// Esplora `/fee-estimates` backend for [`Self::recommended_fee_rate_sat_vb`].
    /// Fetches the confirmation-target rate (nearest available) in sat/vB.
    fn esplora_fee_rate_sat_vb(&self) -> Result<f64> {
        let client = esplora_client::Builder::new(&self.indexer_url)
            .timeout(self.http_timeout_secs)
            .build_blocking();
        let estimates = client.get_fee_estimates().map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "fee-estimate fetch failed - refusing to sign a send-RGB PSBT without a \
                 fee-rate sanity bound: {e}"
            ))
        })?;

        // Exact target if present, else the nearest available one.
        let fetched = estimates.get(&FEE_ESTIMATE_TARGET).copied().or_else(|| {
            estimates
                .iter()
                .min_by_key(|(t, _)| t.abs_diff(FEE_ESTIMATE_TARGET))
                .map(|(_, r)| *r)
        });

        // An empty map is Esplora honestly reporting no fee market: expected on
        // signet/regtest, anomalous on mainnet. A failed fetch never reaches
        // here - it fails closed above, on every network.
        match fetched {
            Some(rate) => Ok(rate),
            None if self.chain_net == ChainNet::BitcoinMainnet => Err(EnclaveError::CrossCheck(
                "fee-estimate response carried no targets - refusing to sign a send-RGB \
                 PSBT without a fee-rate sanity bound"
                    .into(),
            )),
            None => {
                tracing::warn!(
                    chain_net = ?self.chain_net,
                    fallback_sat_vb = NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB,
                    "fee-estimate response carried no targets; falling back to the pinned \
                     non-mainnet floor"
                );
                Ok(NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB)
            }
        }
    }

    /// Electrum `estimate_fee` backend for
    /// [`Self::recommended_fee_rate_sat_vb`], the production path. Electrum
    /// reports BTC per 1000 vbytes; converted to sat/vB. A non-positive answer
    /// means it cannot estimate: fail-closed on mainnet, falls back to the
    /// pinned floor elsewhere, mirroring the Esplora empty-map case.
    fn electrum_fee_rate_sat_vb(&self) -> Result<f64> {
        use rgbstd::indexers::electrum_blocking::electrum_client::{Client, ElectrumApi};
        let client = Client::new(&self.indexer_url).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "electrum fee-estimate client creation failed - refusing to sign a send-RGB \
                 PSBT without a fee-rate sanity bound: {e}"
            ))
        })?;
        let btc_per_kvb = client
            // electrum-client 0.24 takes only the target and always uses the
            // server-default estimation. See the REVERT note above FEE_ESTIMATE_TTL.
            .estimate_fee(FEE_ESTIMATE_TARGET as usize)
            .map_err(|e| {
                EnclaveError::CrossCheck(format!(
                    "electrum fee-estimate fetch failed - refusing to sign a send-RGB PSBT \
                     without a fee-rate sanity bound: {e}"
                ))
            })?;

        // Electrum returns BTC/kvB; a non-positive value (typically -1) means
        // "cannot estimate". Mirror the Esplora empty-map handling.
        if btc_per_kvb <= 0.0 {
            if self.chain_net == ChainNet::BitcoinMainnet {
                return Err(EnclaveError::CrossCheck(
                    "electrum returned no fee estimate - refusing to sign a send-RGB PSBT \
                     without a fee-rate sanity bound"
                        .into(),
                ));
            }
            tracing::warn!(
                chain_net = ?self.chain_net,
                fallback_sat_vb = NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB,
                "electrum returned no fee estimate; falling back to the pinned non-mainnet \
                 floor"
            );
            return Ok(NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB);
        }

        // BTC/kvB -> sat/vB: x1e8 sat/BTC / 1000 vB/kvB = x100_000.
        Ok(btc_per_kvb * 100_000.0)
    }

    /// Validate raw consignment bytes. Returns extracted data on success,
    /// or a `CrossCheck` error if validation fails.
    ///
    /// `bridge_events` are the EVM lock events RGB consensus checks a BFA mint
    /// against; they are ignored by every other schema. The caller must have
    /// verified each one itself - the extension binds amount and OpId, not the
    /// emitting contract.
    pub fn validate_consignment(
        &self,
        consignment_bytes: &[u8],
        #[cfg_attr(not(feature = "bfa-mint"), allow(unused_variables))] bridge_events: &[Event],
    ) -> Result<ValidatedConsignment> {
        let start = std::time::Instant::now();
        let bytes_len = consignment_bytes.len();
        tracing::info!(
            bytes_len,
            indexer_url = %self.indexer_url,
            "starting RGB consignment validation"
        );

        // 1. Deserialize the consignment from its file format (magic + strict-encoded).
        let transfer = Transfer::load(Cursor::new(consignment_bytes)).map_err(|e| {
            tracing::warn!(bytes_len, "consignment deserialization failed: {e}");
            EnclaveError::CrossCheck(format!("consignment deserialization failed: {e}"))
        })?;

        let contract_id = transfer.contract_id().to_string();
        let bundles_count = transfer.bundles.len();
        tracing::info!(
            %contract_id,
            bundles_count,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "deserialized RGB transfer"
        );

        // Pre-validation extraction: no networking, and it must run before
        // `validate()` takes ownership of `transfer`. chain_net +
        // witness_txids are needed by the SPV crosscheck.
        let chain_net = transfer.genesis.chain_net.prefix().to_string();
        let mut txid_set: BTreeSet<[u8; 32]> = BTreeSet::new();
        for wb in transfer.bundles.iter() {
            // rgbstd's Txid stringifies in display order, so decoding the
            // hex gives display-order bytes. Reversal happens later, inside
            // the Merkle verifier, which needs internal order.
            let display_hex = wb.witness_id().to_string();
            let bytes = hex::decode(&display_hex).map_err(|e| {
                EnclaveError::CrossCheck(format!(
                    "witness_id hex decode failed for bundle: {e} (got {display_hex:?})"
                ))
            })?;
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                EnclaveError::CrossCheck(format!(
                    "witness_id is not 32 bytes (got {} bytes from {display_hex:?})",
                    bytes.len()
                ))
            })?;
            txid_set.insert(arr);
        }
        let witness_txids: Vec<[u8; 32]> = txid_set.into_iter().collect();

        // Second walk via `rgb_consignment::parse` for op_ids, types, and
        // output assignments in a flat shape. The parser already exposes the
        // typed `TransitionInfo` / `FungibleAllocation` shape needed here; a
        // direct rgbstd walk would duplicate it against evolving internal
        // types. The parse cost is small next to the network validation.
        let (all_op_ids, mint_op_ids, mut last_transition, transitions_by_witness) =
            extract_transition_summary(consignment_bytes)?;
        let transitions_count = all_op_ids.len();

        // The parser drops `Transition.metadata`, so read IFA
        // `MS_BURNED_ASSET` straight from rgbstd's `Transfer`. Only the last
        // transition matters; a non-burn leaves the field `None`.
        if let Some(ref mut last) = last_transition {
            if last.transition_type == ifa::TS_BURN {
                last.burned_asset_amount = read_last_transition_burned_asset(&transfer)?;
                last.burn_recipient = read_last_transition_burn_recipient(&transfer)?;
            }
        }

        // Last bundle's witness tx, ungated by transition type, so the fundsOut
        // source-block bind also works on a burn. The PSBT path applies its own
        // transition-type gate before reading this.
        let last_witness_txid = transfer.bundles.iter().last().map(|wb| wb.witness_id());

        // Rest of the send-RGB PSBT binding for that same bundle: its input
        // prevouts when the bundle embeds the full tx, plus the validated OpId.
        // Gated on the last transition being the type this build's flow signs
        // (see `super::flow`); the check inside asserts the transition type and
        // the witness agree.
        let (last_transfer_witness_prevouts, last_transfer_op_id) = match last_transition {
            Some(ref last) if super::flow::is_signing_transition(last.transition_type) => {
                read_last_transfer_witness(&transfer, last.transition_type)?
            }
            _ => (None, None),
        };

        // 2. Create the witness resolver. Backend from the URL scheme:
        //    ssl://|tcp:// -> Electrum, otherwise Esplora REST. Electrum is
        //    the production path: TLS terminates inside the enclave against
        //    the real server cert, so a compromised host cannot forge witness
        // data. The Esplora `.timeout()` is load-bearing - it bounds a
        // stalled call on the signing path.
        let is_electrum =
            self.indexer_url.starts_with("ssl://") || self.indexer_url.starts_with("tcp://");
        let mut resolver = if is_electrum {
            // Bound the blocking electrs reads: `Config::default()` has
            // `timeout: None`, so a stalled read pins the worker thread
            // forever (see ELECTRUM_WITNESS_TIMEOUT_SECS). Same crate
            // re-export as the fee client so the `Config` type matches
            // `AnyResolver::electrum_blocking`.
            use rgbstd::indexers::electrum_blocking::electrum_client;
            let electrum_cfg = electrum_client::Config::builder()
                .timeout(Some(ELECTRUM_WITNESS_TIMEOUT_SECS as u8))
                .build();
            AnyResolver::electrum_blocking(&self.indexer_url, Some(electrum_cfg)).map_err(|e| {
                tracing::error!(indexer_url = %self.indexer_url, "electrum resolver creation failed: {e}");
                EnclaveError::CrossCheck(format!("electrum resolver creation failed: {e}"))
            })?
        } else {
            let builder =
                esplora_client::Builder::new(&self.indexer_url).timeout(self.http_timeout_secs);
            AnyResolver::esplora_blocking(builder).map_err(|e| {
                tracing::error!(indexer_url = %self.indexer_url, "esplora resolver creation failed: {e}");
                EnclaveError::CrossCheck(format!("esplora resolver creation failed: {e}"))
            })?
        };

        // Register transactions bundled in the consignment so the resolver
        // treats them as tentative witnesses (not yet mined).
        resolver.add_consignment_txes(&transfer);

        // Pin the trusted type system from the
        // canonical `rgb-schemas` definitions, NOT from `transfer.types` -
        // the consignment's own types would be compared against themselves.
        // An unknown schema_id is rejected fail-closed inside the helper.
        let schema_id = transfer.genesis.schema_id.to_string();
        let trusted_typesystem = trusted_typesystem_for_schema(&schema_id).inspect_err(|_| {
            tracing::warn!(%contract_id, %schema_id, "no trusted type system for consignment schema");
        })?;

        // 3. Build validation config.
        let config = ValidationConfig {
            chain_net: self.chain_net,
            trusted_typesystem,
            build_opouts_dag: true,
            ..Default::default()
        };

        // 4. Run full RGB validation (makes blocking HTTP calls to Esplora).
        tracing::debug!(%contract_id, "calling rgbstd validate (this may block on Esplora)");
        // A BFA mint script ends with `cea`, which the plain validator decodes as
        // `Fail` and so rejects every mint; only the ether extension can run it.
        #[cfg(feature = "bfa-mint")]
        let validation_result = if schema_id == schemata::BFA_SCHEMA_ID.to_string() {
            // Fail closed, and say why: `cea` would reject an empty event set as
            // an opaque script failure, and validating a mint with no verified
            // lock behind it is the same as accepting an unbacked mint.
            if bridge_events.is_empty() {
                return Err(EnclaveError::CrossCheck(
                    "BFA consignment supplied without a verified FundsIn event - refusing to \
                     validate a mint with nothing backing it"
                        .into(),
                ));
            }
            let events: Vec<Event> = bridge_events.to_vec();

            let schema = transfer.schema.clone();
            let contract = transfer.contract_id();
            transfer
                .validate_with_extension::<IssuedAmountCheckExt, BridgedContract<'_, MemContract<MemContractState>>>(
                    &resolver,
                    &config,
                    ((&schema, contract), &events),
                )
        } else {
            transfer.validate(&resolver, &config)
        };
        #[cfg(not(feature = "bfa-mint"))]
        let validation_result = transfer.validate(&resolver, &config);

        let valid = validation_result.map_err(|e| {
            // ValidationError carries the Failure that condemned the consignment,
            // but its Display is a doc comment that drops it - so on its own the
            // log says only "invalid" and an operator has nothing to act on.
            let detail = match &e {
                ValidationError::InvalidConsignment(failure) => failure.to_string(),
                other => other.to_string(),
            };
            tracing::warn!(
                %contract_id,
                elapsed_ms = start.elapsed().as_millis() as u64,
                %detail,
                "RGB validation failed: {e}"
            );
            EnclaveError::CrossCheck(format!("RGB consignment validation failed: {e}: {detail}"))
        })?;

        // Warnings only. Witness confirmation is deliberately NOT derived
        // from `tx_ord_map` (follow-up): rgb-ops' `resolve_witness`
        // hard-codes every consignment-supplied tx to `WitnessOrd::Tentative`
        // regardless of on-chain depth, so reading it as "not yet mined"
        // rejected every fundsOut.
        //
        // Confirmation for the RGB->EVM direction comes from the in-enclave
        // SPV header chain instead: `validate_source` requires a valid merkle
        // proof for every witness txid at `SPV_MIN_CONFIRMATIONS` depth.
        // `non_mined_witness_txids` stays empty so the
        // `assert_witnesses_confirmed` call site remains a structural guard.
        let status = valid.validation_status();
        for warning in &status.warnings {
            tracing::warn!(%contract_id, "RGB validation warning: {warning}");
        }
        let non_mined_witness_txids: Vec<[u8; 32]> = Vec::new();

        tracing::info!(
            %contract_id,
            %chain_net,
            validity = %status.validity(),
            witness_txids_count = witness_txids.len(),
            non_mined_count = non_mined_witness_txids.len(),
            warnings = status.warnings.len(),
            transitions_count,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "RGB consignment validated successfully"
        );

        Ok(ValidatedConsignment {
            contract_id,
            chain_net,
            witness_txids,
            all_op_ids,
            mint_op_ids,
            last_transition,
            last_witness_txid,
            last_transfer_witness_prevouts,
            last_transfer_op_id,
            non_mined_witness_txids,
            transitions_by_witness,
        })
    }
}

/// Extract the rest of the witness-tx identity binding for the consignment's
/// **last** transition out of the rgbstd `Transfer`: when that bundle embeds
/// the full witness tx (`PubWitness::Tx`), its Bitcoin input prevouts.
/// Consumed by the send-RGB PSBT cross-check alongside
/// [`ValidatedConsignment::last_witness_txid`], which names the same bundle.
///
/// Reads the same `transfer.bundles.iter().last()` bundle as
/// [`read_last_transition_burned_asset`] and asserts its last known transition
/// type equals `expected_type`, the type the flat parser reported. The two
/// walks are independent traversals of the same data, so a disagreement is
/// rejected fail-closed.
///
/// Also returns the validated OpId of that transition, read from the rgbstd
/// bundle rather than the flat parser.
///
/// Returns `(None, None)` only for a bundle-less transfer, which rgbstd
/// rejects upstream.
fn read_last_transfer_witness(
    transfer: &Transfer,
    expected_type: u16,
) -> Result<LastTransferBinding> {
    let Some(last_bundle) = transfer.bundles.iter().last() else {
        return Ok((None, None));
    };

    // OpId of the validated last transition, from the same bundle. rgbstd's
    // `OpId` displays as lowercase hex of its 32-byte commitment hash, so
    // hex-decode it back. Sourced from the validated object, not the flat
    // parser.
    let mut op_id: Option<[u8; 32]> = None;
    if let Some(known) = last_bundle.bundle().known_transitions.iter().last() {
        let actual = known.transition.transition_type;
        let expected = TransitionType::with(expected_type);
        if actual != expected {
            return Err(EnclaveError::CrossCheck(format!(
                "consignment last-bundle transition type {actual} disagrees with parsed last \
                 transition type {expected} - refusing to bind PSBT to an ambiguous witness"
            )));
        }
        let opid_hex = known.opid.to_string();
        let bytes = hex::decode(&opid_hex).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "validated opid hex decode failed: {e} ({opid_hex:?})"
            ))
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            EnclaveError::CrossCheck(format!("validated opid is not 32 bytes (got {})", v.len()))
        })?;
        op_id = Some(arr);
    }

    let prevouts = last_bundle
        .pub_witness
        .tx()
        .map(|tx| tx.input.iter().map(|txin| txin.previous_output).collect());

    Ok((prevouts, op_id))
}

/// Binding data for the consignment's last transfer bundle:
/// `(witness input prevouts, validated last-transition OpId)`. Both `Option`
/// because a bundle-less transfer (rejected upstream by rgbstd) yields
/// `(None, None)`. See [`read_last_transfer_witness`].
type LastTransferBinding = (Option<Vec<bitcoin::OutPoint>>, Option<[u8; 32]>);

/// Mint transitions - the ones that map 1:1 to an EVM lock record. BFA's
/// `TS_BRIDGE` counts only in a `bfa-mint` build, so a swap enclave classifies
/// exactly what it classified before BFA existed.
pub(super) fn is_mint_transition(transition_type: u16) -> bool {
    #[cfg(feature = "bfa-mint")]
    {
        if transition_type == bfa::TS_BRIDGE {
            return true;
        }
    }
    transition_type == ifa::TS_INFLATION
}

/// Parse the consignment with `rgb_consignment::parse` and pull out the
/// flat transition summary (every op_id, the most recent transition's shape,
/// and every transition grouped by the witness tx that commits it). Errors if
/// the consignment isn't a Transfer or if any field fails to decode.
#[allow(clippy::type_complexity)]
fn extract_transition_summary(
    consignment_bytes: &[u8],
) -> Result<(
    Vec<String>,
    Vec<String>,
    Option<TransitionSummary>,
    Vec<(bitcoin::Txid, Vec<TransitionSummary>)>,
)> {
    let info = rgb_consignment::parse(consignment_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("rgb-consignment parse failed: {e}")))?;

    let transfer = match info {
        ConsignmentInfo::Transfer(t) => t,
        // A Contract / Kit cannot authorise an EVM action. Rejected
        // explicitly so a mistaken upload fails closed.
        ConsignmentInfo::Contract(_) => {
            return Err(EnclaveError::CrossCheck(
                "consignment is a Contract, expected Transfer".into(),
            ));
        }
        ConsignmentInfo::Kit(_) => {
            return Err(EnclaveError::CrossCheck(
                "consignment is a Kit, expected Transfer".into(),
            ));
        }
    };

    let all_op_ids: Vec<String> = transfer
        .witnesses
        .iter()
        .flat_map(|w: &WitnessInfo| w.transitions.iter())
        .map(|t: &TransitionInfo| t.op_id.clone())
        .collect();

    // The mint (IFA `TS_INFLATION`) subset - these map 1:1 to EVM lock
    // records (`fundsIn`). The `fundsOut` `fundsInIds[]` must each correspond
    // to one of these (spec section 6).
    let mint_op_ids: Vec<String> = transfer
        .witnesses
        .iter()
        .flat_map(|w: &WitnessInfo| w.transitions.iter())
        .filter(|t: &&TransitionInfo| is_mint_transition(t.transition_type))
        .map(|t: &TransitionInfo| t.op_id.clone())
        .collect();

    let last_transition = transfer
        .witnesses
        .last()
        .and_then(|w| w.transitions.last())
        .map(transition_summary)
        .transpose()?;

    // Every transition, grouped by the witness tx that commits it. One tx can
    // carry several, so reading only `last_transition` would leave the rest of
    // the value it moves unbound. The PSBT cross-check binds the whole group.
    let mut transitions_by_witness: Vec<(bitcoin::Txid, Vec<TransitionSummary>)> =
        Vec::with_capacity(transfer.witnesses.len());
    for w in transfer.witnesses.iter() {
        let txid = txid_from_display_hex(&w.txid)?;
        let summaries: Result<Vec<TransitionSummary>> =
            w.transitions.iter().map(transition_summary).collect();
        transitions_by_witness.push((txid, summaries?));
    }

    Ok((
        all_op_ids,
        mint_op_ids,
        last_transition,
        transitions_by_witness,
    ))
}

/// Parse a display-order (big-endian) txid hex string into a `bitcoin::Txid`.
///
/// The parser stringifies txids in display order while `bitcoin::Txid` stores
/// them reversed, so the flip lives here rather than at each comparison site.
fn txid_from_display_hex(display_hex: &str) -> Result<bitcoin::Txid> {
    use bitcoin::hashes::Hash;

    let mut raw = decode_display_txid(display_hex)?;
    raw.reverse();
    Ok(bitcoin::Txid::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(raw),
    ))
}

fn transition_summary(t: &TransitionInfo) -> Result<TransitionSummary> {
    let total_output_amount: u64 =
        t.fungible_allocations
            .iter()
            .try_fold(0u64, |acc, a: &FungibleAllocation| {
                acc.checked_add(a.total).ok_or_else(|| {
                    EnclaveError::CrossCheck(format!(
                        "consignment transition total_output_amount overflow (op_id {})",
                        t.op_id
                    ))
                })
            })?;

    // `OS_ASSET` allocations only. An Inflation transition also carries
    // `OS_INFLATION` outputs whose amounts are mint capacity, not value.
    let asset_output_amount: u64 = t
        .fungible_allocations
        .iter()
        .filter(|a: &&FungibleAllocation| a.assignment_type == ifa::OS_ASSET)
        .try_fold(0u64, |acc, a: &FungibleAllocation| {
            acc.checked_add(a.total).ok_or_else(|| {
                EnclaveError::CrossCheck(format!(
                    "consignment transition asset_output_amount overflow (op_id {})",
                    t.op_id
                ))
            })
        })?;

    let outputs: Result<Vec<TransitionOutput>> = t
        .fungible_allocations
        .iter()
        .flat_map(|a: &FungibleAllocation| {
            let assignment_type = a.assignment_type;
            a.entries
                .iter()
                .map(move |e| transition_output(assignment_type, e))
        })
        .collect();

    Ok(TransitionSummary {
        op_id: t.op_id.clone(),
        transition_type: t.transition_type,
        total_output_amount,
        asset_output_amount,
        outputs: outputs?,
        // Filled by `read_last_transition_burned_asset` /
        // `read_last_transition_burn_recipient` if the transition is a burn;
        // the parser doesn't expose metadata so we leave these `None` here.
        burned_asset_amount: None,
        burn_recipient: None,
    })
}

/// Walk the rgbstd `Transfer` to the last witness bundle's last known
/// transition and read the IFA `MS_BURNED_ASSET` value from its metadata. The
/// flat parser drops `Transition.metadata`, so the unlock cross-check gets the
/// destroyed amount from here.
///
/// The value is a strict-encoded `rgbstd::Amount` (`u64`, 8 bytes,
/// little-endian). Decoded manually rather than via
/// `StrictDeserialize::from_strict_serialized`, to avoid threading the
/// `rgb-strict-encoding`-as-`strict_encoding` rename through our deps.
///
/// Returns `Ok(None)` when there is no last transition or the metadata key is
/// absent (which for a `TS_BURN` implies a schema mismatch), and `Err` when the
/// blob is the wrong size for a `u64`.
/// Walk to the last known transition and read the BFA `MS_BURN_RECIPIENT`
/// value from its metadata - the 32 bytes naming where the redemption is owed.
///
/// Returns `Ok(None)` when there is no last transition or the key is absent
/// (an IFA burn declares `burnedInflation` there instead), and `Err` when the
/// blob is not exactly 32 bytes, because a release must never be pointed at a
/// truncated or padded address.
fn read_last_transition_burn_recipient(transfer: &Transfer) -> Result<Option<Vec<u8>>> {
    let Some(last_bundle) = transfer.bundles.iter().last() else {
        return Ok(None);
    };
    let Some(known) = last_bundle.bundle().known_transitions.iter().last() else {
        return Ok(None);
    };
    let recipient_meta_key = MetaType::with(bfa::MS_BURN_RECIPIENT);
    for (mt, mv) in &known.transition.metadata {
        if *mt != recipient_meta_key {
            continue;
        }
        let raw: &[u8] = mv.as_unconfined().as_slice();
        if raw.len() != 32 {
            return Err(EnclaveError::CrossCheck(format!(
                "MS_BURN_RECIPIENT metadata is {} bytes, expected 32",
                raw.len()
            )));
        }
        return Ok(Some(raw.to_vec()));
    }
    Ok(None)
}

fn read_last_transition_burned_asset(transfer: &Transfer) -> Result<Option<u64>> {
    let Some(last_bundle) = transfer.bundles.iter().last() else {
        return Ok(None);
    };
    let Some(known) = last_bundle.bundle().known_transitions.iter().last() else {
        return Ok(None);
    };
    let burned_meta_key = MetaType::with(ifa::MS_BURNED_ASSET);
    for (mt, mv) in &known.transition.metadata {
        if *mt != burned_meta_key {
            continue;
        }
        let raw: &[u8] = mv.as_unconfined().as_slice();
        let bytes: [u8; 8] = raw.try_into().map_err(|_| {
            EnclaveError::CrossCheck(format!(
                "MS_BURNED_ASSET metadata is {} bytes, expected 8 (strict-encoded u64)",
                raw.len()
            ))
        })?;
        return Ok(Some(u64::from_le_bytes(bytes)));
    }
    Ok(None)
}

fn transition_output(assignment_type: u16, e: &FungibleEntry) -> Result<TransitionOutput> {
    let seal = match &e.seal {
        SealInfo::Revealed { txid, vout } => {
            let txid_bytes = txid
                .as_ref()
                .map(|hex_str| decode_display_txid(hex_str))
                .transpose()?;
            OutputSeal::Revealed {
                txid: txid_bytes,
                vout: *vout,
            }
        }
        SealInfo::Confidential { secret_seal } => OutputSeal::Confidential {
            secret_seal: secret_seal.clone(),
        },
    };
    Ok(TransitionOutput {
        assignment_type,
        amount: e.amount,
        seal,
    })
}

fn decode_display_txid(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "seal txid hex decode failed: {e} (got {hex_str:?})"
        ))
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "seal txid is not 32 bytes (got {} bytes from {hex_str:?})",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures from the rgb-consignment-parser repo (`test-data/`). Mainnet
    // NIA artefacts, shipped in-tree so the tests need no network access.
    const TRANSFER_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/transfer_consignment.rgbc");
    const CONTRACT_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/contract_consignment.rgbc");

    use crate::config::{
        BridgeConfig, DEFAULT_MAX_CONSIGNMENT_BYTES, DEFAULT_MAX_MERKLE_PROOFS,
        DEFAULT_MAX_TOTAL_PROOF_BYTES,
    };
    use crate::proto::MerkleProofEntry;

    #[test]
    fn rejects_invalid_bytes() {
        let validator = RgbValidator::new("http://localhost:1".to_string(), "regtest").unwrap();
        let err = validator
            .validate_consignment(b"not-a-consignment", &[])
            .unwrap_err();
        assert!(
            err.to_string().contains("deserialization failed"),
            "expected deserialization error, got: {err}"
        );
    }

    /// Stub Esplora answering only `GET /fee-estimates`, with a per-request
    /// body sequence (later requests get the last body). Returns the URL.
    fn spawn_fee_stub(bodies: Vec<&'static str>) -> String {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fee stub");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut served = 0usize;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let first = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let resp = if first.starts_with("GET /fee-estimates") {
                    let body = bodies[served.min(bodies.len() - 1)];
                    served += 1;
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn fee_estimate_uses_exact_target_and_caches() {
        // First fetch returns target-6's rate; the second call must be served
        // from the 60s cache (the stub would answer 99.0 if re-queried).
        let url = spawn_fee_stub(vec![r#"{"1":50.0,"6":20.0,"25":5.0}"#, r#"{"6":99.0}"#]);
        let v = RgbValidator::new(url, "bitcoin").unwrap();
        assert_eq!(v.recommended_fee_rate_sat_vb().unwrap(), 20.0);
        assert_eq!(
            v.recommended_fee_rate_sat_vb().unwrap(),
            20.0,
            "second call must hit the cache, not the stub"
        );
    }

    #[test]
    fn fee_estimate_falls_back_to_nearest_target() {
        // No target 6: nearest is 1 (|6-1| = 5) over 25 (|6-25| = 19).
        let url = spawn_fee_stub(vec![r#"{"1":50.0,"25":5.0}"#]);
        let v = RgbValidator::new(url, "bitcoin").unwrap();
        assert_eq!(v.recommended_fee_rate_sat_vb().unwrap(), 50.0);
    }

    #[test]
    fn fee_estimate_rejects_empty_response_on_mainnet() {
        // Anomalous on mainnet: the non-mainnet floor must not leak here.
        let url = spawn_fee_stub(vec![r#"{}"#]);
        let v = RgbValidator::new(url, "bitcoin").unwrap();
        let err = v.recommended_fee_rate_sat_vb().unwrap_err();
        assert!(
            err.to_string().contains("no targets"),
            "expected empty-estimates rejection, got: {err}"
        );
    }

    #[test]
    fn fee_estimate_falls_back_to_pinned_floor_on_non_mainnet() {
        // No fee market -> `{}`, which pre-fix wedged every send-RGB PSBT.
        for network in ["signet", "regtest", "testnet"] {
            let url = spawn_fee_stub(vec![r#"{}"#]);
            let v = RgbValidator::new(url, network).unwrap();
            assert_eq!(
                v.recommended_fee_rate_sat_vb().unwrap(),
                NON_MAINNET_FALLBACK_FEE_RATE_SAT_VB,
                "{network} must fall back to the pinned floor on an empty map"
            );
        }
    }

    #[test]
    fn fee_estimate_prefers_a_real_estimate_over_the_floor_on_non_mainnet() {
        // The floor is empty-map-only; a real rate must win, or it would
        // silently loosen the bound.
        let url = spawn_fee_stub(vec![r#"{"6":2.0}"#]);
        let v = RgbValidator::new(url, "signet").unwrap();
        assert_eq!(v.recommended_fee_rate_sat_vb().unwrap(), 2.0);
    }

    #[test]
    fn fee_estimate_fails_closed_when_unreachable_on_non_mainnet() {
        // The threat (host suppresses the egress): the floor must not
        // rescue a failed fetch, only an honest empty response earns it.
        let v = RgbValidator::new("http://127.0.0.1:1".into(), "signet").unwrap();
        let err = v.recommended_fee_rate_sat_vb().unwrap_err();
        assert!(
            err.to_string().contains("refusing to sign"),
            "expected fail-closed fetch error on signet, got: {err}"
        );
    }

    #[test]
    fn fee_estimate_rejects_non_positive_rate() {
        let url = spawn_fee_stub(vec![r#"{"6":0.0}"#]);
        let v = RgbValidator::new(url, "bitcoin").unwrap();
        let err = v.recommended_fee_rate_sat_vb().unwrap_err();
        assert!(
            err.to_string().contains("not a positive finite rate"),
            "expected non-positive rejection, got: {err}"
        );
    }

    #[test]
    fn fee_estimate_fails_closed_when_unreachable() {
        // Nothing listening: the fetch error must propagate as a refusal, not
        // a skip - the host controls this egress.
        let v = RgbValidator::new("http://127.0.0.1:1".into(), "bitcoin").unwrap();
        let err = v.recommended_fee_rate_sat_vb().unwrap_err();
        assert!(
            err.to_string().contains("refusing to sign"),
            "expected fail-closed fetch error, got: {err}"
        );
    }

    #[test]
    fn stalled_esplora_times_out_instead_of_hanging() {
        // A host that accepts the connection and
        // never responds must cost at most the HTTP timeout.
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled stub");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Hold every connection open without writing a byte; keeping the
            // streams alive avoids an early RST that would fail fast for the
            // wrong reason.
            let mut held = Vec::new();
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                held.push(stream);
            }
        });

        let validator = RgbValidator::new(format!("http://{addr}"), "bitcoin")
            .unwrap()
            .with_http_timeout(2);
        let start = std::time::Instant::now();
        let err = validator
            .validate_consignment(TRANSFER_FIXTURE, &[])
            .unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(60),
            "stalled Esplora must be bounded by the HTTP timeout, took {elapsed:?}: {err}"
        );
    }

    #[test]
    fn rejects_unknown_network() {
        let err = RgbValidator::new("http://localhost:1".to_string(), "foonet").unwrap_err();
        assert!(err.to_string().contains("unknown bitcoin network"));
    }

    /// `asset_output_amount` must count only `OS_ASSET` allocations, not
    /// the `OS_INFLATION` allowance outputs that carry mint capacity.
    #[test]
    fn transition_summary_excludes_inflation_allowance_from_asset_amount() {
        let alloc = |assignment_type: u16, amount: u64| FungibleAllocation {
            assignment_type,
            entries: vec![FungibleEntry {
                amount,
                seal: SealInfo::Revealed {
                    txid: None,
                    vout: 0,
                },
            }],
            total: amount,
        };
        let info = TransitionInfo {
            op_id: "mint-op".into(),
            transition_type: ifa::TS_INFLATION,
            input_count: 1,
            fungible_allocations: vec![
                alloc(ifa::OS_ASSET, 500),
                // Remaining right-to-mint: must NOT count as asset units.
                alloc(ifa::OS_INFLATION, 1_000_000),
            ],
        };

        let summary = transition_summary(&info).expect("summary");
        assert_eq!(summary.asset_output_amount, 500);
        assert_eq!(summary.total_output_amount, 1_000_500);
    }

    /// For a Transfer everything is `OS_ASSET`, so the two sums agree - the
    /// invariant the PSBT amount bind relies on when it switched from
    /// `total_output_amount` to `asset_output_amount`.
    #[test]
    fn transfer_fixture_asset_amount_equals_total() {
        let (_, _, last_transition, _) =
            extract_transition_summary(TRANSFER_FIXTURE).expect("transfer parse");
        let last = last_transition.expect("transfer has a last transition");
        assert_eq!(last.transition_type, ifa::TS_TRANSFER);
        assert_eq!(last.asset_output_amount, last.total_output_amount);
    }

    #[test]
    fn extracts_op_ids_and_last_transition_from_transfer_fixture() {
        let (all_op_ids, mint_op_ids, last_transition, _) =
            extract_transition_summary(TRANSFER_FIXTURE).expect("transfer parse");

        // Fixture is a Transfer with two witness bundles, one transition
        // each. Order of `all_op_ids` matches witness order.
        assert_eq!(
            all_op_ids,
            vec![
                "f5106c6ddb8b8fd3d1de3bda0106ae13ef0705dc36bfc543566362e5e8dd4bd5".to_string(),
                "74c1d59264894a1bd44887fe84b36739c024bd50188e69baeeda845569313543".to_string(),
            ]
        );
        // This transfer fixture carries no IFA TS_INFLATION (mint) transition.
        assert!(mint_op_ids.is_empty(), "transfer fixture has no mints");

        let last = last_transition.expect("transfer has a last transition");
        assert_eq!(
            last.op_id,
            "74c1d59264894a1bd44887fe84b36739c024bd50188e69baeeda845569313543"
        );
        // 10000 is the NIA Transfer transition-type id under the schema
        // this fixture uses. Recorded here so a schema change in the
        // future will fail loud instead of silently mislabelling.
        assert_eq!(last.transition_type, 10000);
        // Last transition has two outputs: 14_999_948_000_000 (revealed
        // change leg, vout=1 on the witness tx) and 12_000_000
        // (confidential recipient leg). Total = 14_999_960_000_000.
        assert_eq!(last.total_output_amount, 14_999_960_000_000);
        assert_eq!(last.outputs.len(), 2);
        // The fixture's last transition is a Transfer (type 10000), not a
        // Burn (type 8010). `extract_transition_summary` leaves
        // `burned_asset_amount` `None` because the burn metadata read is
        // gated on `transition_type == ifa::TS_BURN`. A real burn-fixture
        // round-trip lives behind the validator-level path (which needs
        // network access for Esplora), tracked separately.
        assert_eq!(last.burned_asset_amount, None);
    }

    #[test]
    fn trusted_typesystem_sourced_from_schema_not_consignment() {
        // The trusted type system must come from the
        // canonical rgb-schemas definitions, not from `transfer.types`.
        // The in-tree fixture is an NIA consignment, so its schema_id resolves
        // to a canonical type system whose id matches NIA's.
        let t = Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");
        let schema_id = t.genesis.schema_id.to_string();

        let trusted =
            trusted_typesystem_for_schema(&schema_id).expect("fixture schema must be known");

        // The canonical type system is what rgb-schemas ships for this schema,
        // and the fixture's own types match it (a legit consignment).
        assert_eq!(
            trusted.id().to_string(),
            t.types.id().to_string(),
            "canonical type system for the fixture's schema should match the fixture's types"
        );

        // An unknown schema id is rejected fail-closed.
        let err = trusted_typesystem_for_schema("rgb:sch:unknown-schema-id").unwrap_err();
        assert!(
            err.to_string().contains("unknown/unsupported RGB schema"),
            "expected unknown-schema rejection, got: {err}"
        );
    }

    #[test]
    fn ifa_constants_match_rgb_schemas_definitions() {
        // Lock these to the values published in
        // `rgb-protocol/rgb-schemas/src/lib.rs`. If upstream renumbers
        // them, this test fails loud - the consequences of a silent
        // mismatch (mis-classifying a Transfer as a Burn or vice versa)
        // would be much worse than a CI break.
        assert_eq!(ifa::TS_TRANSFER, 10000);
        assert_eq!(ifa::TS_BURN, 8010);
        assert_eq!(ifa::TS_INFLATION, 8000);
        assert_eq!(ifa::MS_BURNED_ASSET, 1001);
    }

    #[test]
    fn bfa_constants_match_schema() {
        // Same reasoning as the IFA constants above, and one addition worth
        // stating: BFA reuses IFA's transfer and burn types but mints through
        // its own `TS_BRIDGE`, and its mint right `OS_BRIDGE` is declarative -
        // it carries no amount, so unlike `OS_INFLATION` it can never be summed
        // into a minted total. These numbers are still marked TODO upstream; if
        // they move, this fails loud rather than mis-classifying a mint.
        assert_eq!(bfa::TS_BRIDGE, 8014);
        assert_eq!(bfa::OS_BRIDGE, 4014);
        assert_ne!(bfa::TS_BRIDGE, ifa::TS_INFLATION);
        assert_ne!(bfa::OS_BRIDGE, ifa::OS_INFLATION);
    }

    /// `BridgeLocation::Ethereum(TinyString)` strict-encodes as a one-byte
    /// union tag (first variant, `tags = order`), a one-byte length, then the
    /// address. Pinned here so a change in that layout fails loudly rather than
    /// as an unexplained "invalid bridge location" at mint time.
    #[cfg(feature = "bfa-mint")]
    #[test]
    fn decodes_the_genesis_bridge_location_layout() {
        let addr = "0x1111111111111111111111111111111111111111";
        let mut blob = vec![0u8, addr.len() as u8];
        blob.extend_from_slice(addr.as_bytes());
        assert_eq!(decode_bridge_location(&blob).unwrap(), addr);
    }

    #[cfg(feature = "bfa-mint")]
    #[test]
    fn refuses_a_malformed_bridge_location_blob() {
        assert!(decode_bridge_location(&[]).is_err());
        // Unknown union tag: a future non-Ethereum variant must not be guessed at.
        assert!(decode_bridge_location(&[1, 2, b'a', b'b']).is_err());
        assert!(decode_bridge_location(&[0]).is_err());
        // Declared length disagrees with the bytes that follow.
        assert!(decode_bridge_location(&[0, 4, b'a', b'b']).is_err());
        assert!(decode_bridge_location(&[0, 1, 0xff]).is_err());
    }

    /// The swap path must be untouched: a non-BFA consignment yields no binding
    /// and so triggers no EVM lookup.
    #[cfg(feature = "bfa-mint")]
    #[test]
    fn no_mint_binding_for_a_non_bfa_consignment() {
        assert!(bfa_mint_binding(TRANSFER_FIXTURE).unwrap().is_none());
    }

    /// Undecodable bytes are left to `validate_consignment`, which owns that
    /// error - reporting it from the mint pre-pass would reorder the messages
    /// every other path already asserts on.
    #[cfg(feature = "bfa-mint")]
    #[test]
    fn mint_binding_defers_undecodable_bytes() {
        assert!(bfa_mint_binding(b"not-a-consignment").unwrap().is_none());
    }

    /// The burn ancestry pre-pass shares the mint pre-pass's schema gate: an
    /// IFA or swap consignment must trigger no EVM lookup and no ancestor
    /// requirement, or every non-BFA burn on the stand would start failing.
    #[cfg(feature = "bfa-mint")]
    #[test]
    fn no_ancestry_binding_for_a_non_bfa_consignment() {
        assert!(bfa_ancestry_binding(TRANSFER_FIXTURE).unwrap().is_none());
    }

    #[cfg(feature = "bfa-mint")]
    #[test]
    fn ancestry_binding_defers_undecodable_bytes() {
        assert!(bfa_ancestry_binding(b"not-a-consignment")
            .unwrap()
            .is_none());
    }

    #[cfg(feature = "bfa-mint")]
    #[test]
    fn bfa_schema_resolves_a_trusted_typesystem() {
        // The release path runs every consignment through this resolver, and it
        // fails closed on an unknown schema. Without BFA registered a bridged
        // asset could be minted but never released.
        use schemata::BFA_SCHEMA_ID;

        trusted_typesystem_for_schema(&BFA_SCHEMA_ID.to_string())
            .expect("BFA must resolve a trusted type system");
    }

    /// The swap enclave must not have gained BFA behaviour: every BFA branch is
    /// feature-gated, so a bridged consignment fails closed as it did before.
    #[cfg(not(feature = "bfa-mint"))]
    #[test]
    fn bfa_schema_is_unknown_without_the_feature() {
        use schemata::BFA_SCHEMA_ID;

        assert!(trusted_typesystem_for_schema(&BFA_SCHEMA_ID.to_string()).is_err());
    }

    /// `bfa-mint` implies `rgb-mint-burn`, so a BFA `Bridge` is a mint here and
    /// a signing shape for the flow. Without the feature it is neither, in
    /// either flow - that is what keeps a swap enclave free of any mint rule.
    #[test]
    fn bridge_transitions_count_as_mints_only_with_the_feature() {
        assert!(is_mint_transition(ifa::TS_INFLATION));
        assert_eq!(
            is_mint_transition(bfa::TS_BRIDGE),
            cfg!(feature = "bfa-mint")
        );
        assert_eq!(
            super::super::flow::is_signing_transition(bfa::TS_BRIDGE),
            cfg!(feature = "bfa-mint")
        );
    }

    #[test]
    fn last_transition_carries_revealed_and_confidential_seals() {
        let (_, _, last_transition, _) =
            extract_transition_summary(TRANSFER_FIXTURE).expect("transfer parse");
        let last = last_transition.expect("transfer has a last transition");

        // Both legs are `OS_ASSET` - the assignment tag the per-output
        // recipient bind filters on. Asserted against real
        // consignment bytes so the tag can't silently drift from the parser.
        assert!(
            last.outputs
                .iter()
                .all(|o| o.assignment_type == ifa::OS_ASSET),
            "transfer fixture legs should all be OS_ASSET"
        );

        // First entry is the change leg: revealed with no explicit txid
        // (points at the witness tx itself), vout=1, amount as above.
        let change = &last.outputs[0];
        assert_eq!(change.amount, 14_999_948_000_000);
        match &change.seal {
            OutputSeal::Revealed { txid, vout } => {
                assert!(txid.is_none(), "change leg seal txid should be None");
                assert_eq!(*vout, 1);
            }
            OutputSeal::Confidential { .. } => panic!("change leg should be Revealed"),
        }

        // Second entry is the recipient leg: confidential
        // (`utxob:UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP`).
        let recipient = &last.outputs[1];
        assert_eq!(recipient.amount, 12_000_000);
        match &recipient.seal {
            OutputSeal::Confidential { secret_seal } => {
                assert!(
                    secret_seal.starts_with("utxob:"),
                    "confidential seal should start with 'utxob:', got {secret_seal}"
                );
            }
            OutputSeal::Revealed { .. } => panic!("recipient leg should be Confidential"),
        }
    }

    #[test]
    fn extracts_last_transfer_witness_from_transfer_fixture() {
        // `read_last_transfer_witness` works off the rgbstd `Transfer`
        // directly, so it needs no Esplora/network - load the fixture and
        // assert the witness-tx binding data the PSBT cross-check relies on.
        let transfer =
            Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");

        // The fixture's last transition is a Transfer (type 10000, asserted in
        // `extracts_op_ids_and_last_transition_from_transfer_fixture`).
        let (prevouts, op_id) =
            read_last_transfer_witness(&transfer, ifa::TS_TRANSFER).expect("extract witness");
        let last_bundle = transfer.bundles.iter().last().expect("fixture has bundles");

        // The rgb-lib sender embeds the full witness tx for a freshly-composed
        // transfer, so the prevouts (the witness tx's Bitcoin inputs) are
        // present and non-empty - the per-input canary is available.
        let prevouts = prevouts.expect("fixture embeds the full witness tx (PubWitness::Tx)");
        assert!(
            !prevouts.is_empty(),
            "witness tx must spend at least one input"
        );

        // The validated OpId (canonical burnId source) must be present and
        // equal the last bundle's last known-transition opid, read straight
        // from the validated object - not the flat parser.
        let op_id = op_id.expect("transfer fixture yields a validated opid");
        let expected_opid = last_bundle
            .bundle()
            .known_transitions
            .iter()
            .last()
            .expect("bundle has a known transition")
            .opid
            .to_string();
        assert_eq!(hex::encode(op_id), expected_opid);
    }

    #[test]
    fn rejects_last_transfer_witness_on_type_mismatch() {
        // If the rgbstd bundle walk and the parser walk disagree on the last
        // transition type, we must fail closed rather than bind a txid from
        // one transition while gating on another. The fixture's last
        // transition is TS_TRANSFER (10000); claiming it's a burn (8010)
        // forces the consistency check to fire.
        let transfer =
            Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");
        let err = read_last_transfer_witness(&transfer, ifa::TS_BURN).unwrap_err();
        assert!(
            err.to_string()
                .contains("disagrees with parsed last transition type"),
            "expected type-mismatch rejection, got: {err}"
        );
    }

    #[test]
    fn rejects_contract_with_explicit_kind_message() {
        let err = extract_transition_summary(CONTRACT_FIXTURE).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Contract") && msg.contains("expected Transfer"),
            "expected Contract->Transfer rejection, got: {msg}"
        );
    }

    #[test]
    fn rejects_random_bytes_with_parse_error() {
        let err = extract_transition_summary(&[0u8; 64]).unwrap_err();
        assert!(
            err.to_string().contains("rgb-consignment parse failed"),
            "expected parse-failure rejection, got: {err}"
        );
    }

    // Consignment-flag pins - successors of the dropped
    // `validation::evm_crosscheck` tests `accepts_valid_consignment_hash` /
    // `ignores_consignment_valid_flag_when_bytes_present` (+ the P0 companion
    // `rejects_empty_consignment_even_with_valid_flag`). Their target,
    // `validate_evm_request`'s payload gate, is now `validate_source_payload`
    // in this file. The wire type (`proto::RgbSource`) STILL carries the
    // host-supplied `consignment_valid: bool` (tag 1); the gate never reads
    // it - validity comes from the bytes, never the flag.

    /// keccak256(bytes) in the wire shape `validate_source_payload` expects.
    fn keccak(bytes: &[u8]) -> Vec<u8> {
        Keccak256::digest(bytes).to_vec()
    }

    /// A well-formed `RgbSource` around the in-tree mainnet transfer fixture.
    ///
    /// `consignment_valid` is deliberately `false`: the flag is not
    /// authoritative, so anything that validates with this fixture also
    /// proves a `false` flag cannot veto byte-derived validity.
    fn fixture_source(asset_id: &str) -> RgbSource {
        RgbSource {
            consignment_valid: false,
            asset_id: asset_id.into(),
            consignment: TRANSFER_FIXTURE.to_vec(),
            consignment_hash: keccak(TRANSFER_FIXTURE),
            merkle_proofs: vec![],
            commission: 0,
            mint_ancestors: vec![],
        }
    }

    /// Old `accepts_valid_consignment_hash`: consignment bytes plus their
    /// matching keccak256 pass the payload gate. `Ok` here is "past the hash
    /// check" in full - everything after this gate in `validate_source` is
    /// validator/SPV work, not payload shape.
    #[test]
    fn accepts_valid_consignment_hash() {
        assert!(validate_source_payload(
            &fixture_source("rgb:any-declared-asset"),
            &BridgeConfig::default()
        )
        .is_ok());
    }

    /// A consignment larger than the configured cap is rejected by the payload
    /// gate with the aggregate-size error *before* any rgbstd parse (the error
    /// is the size cap, not a decode failure).
    #[test]
    fn rejects_oversized_consignment_before_parse() {
        let mut source = fixture_source("rgb:any-declared-asset");
        source.consignment = vec![0u8; DEFAULT_MAX_CONSIGNMENT_BYTES + 1];
        source.consignment_hash = keccak(&source.consignment);
        let err = validate_source_payload(&source, &BridgeConfig::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("consignment too large"), "unexpected: {err}");
    }

    /// Boundary: a consignment exactly at the cap passes the aggregate gate
    /// (rejection is strictly `>` the cap).
    #[test]
    fn accepts_consignment_at_size_cap() {
        let mut source = fixture_source("rgb:any-declared-asset");
        source.consignment = vec![0u8; DEFAULT_MAX_CONSIGNMENT_BYTES];
        source.consignment_hash = keccak(&source.consignment);
        assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
    }

    /// The caps are operator-configurable: a smaller `max_consignment_bytes`
    /// rejects a consignment the default would accept.
    #[test]
    fn honors_configured_consignment_cap() {
        let mut source = fixture_source("rgb:any-declared-asset");
        source.consignment = vec![0u8; 200];
        source.consignment_hash = keccak(&source.consignment);
        // The default cap accepts 200 bytes.
        assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
        // A 100-byte configured cap rejects the same source.
        let cfg = BridgeConfig {
            max_consignment_bytes: 100,
            ..BridgeConfig::default()
        };
        let err = validate_source_payload(&source, &cfg)
            .unwrap_err()
            .to_string();
        assert!(err.contains("consignment too large"), "unexpected: {err}");
    }

    /// Too many Merkle proofs is rejected on count alone, even when each proof
    /// is individually tiny.
    #[test]
    fn rejects_too_many_merkle_proofs() {
        let mut source = fixture_source("rgb:any-declared-asset");
        source.merkle_proofs = (0..DEFAULT_MAX_MERKLE_PROOFS + 1)
            .map(|_| MerkleProofEntry::default())
            .collect();
        let err = validate_source_payload(&source, &BridgeConfig::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("too many merkle proofs"), "unexpected: {err}");
    }

    /// Proofs that each stay under the per-path-depth cap but exceed the
    /// aggregate byte budget are rejected by the aggregate gate - the case the
    /// per-field caps miss.
    #[test]
    fn rejects_aggregate_proof_bytes_over_budget() {
        // Each proof counts 32-byte txid + 32 siblings * 32 bytes = 1056 bytes,
        // all within MAX_MERKLE_PATH_DEPTH. Take just enough to cross the
        // aggregate cap while staying under the proof-count cap.
        let per_proof = 32 + 32 * 32;
        let n = DEFAULT_MAX_TOTAL_PROOF_BYTES / per_proof + 1;
        assert!(
            n <= DEFAULT_MAX_MERKLE_PROOFS,
            "test would trip the count cap first"
        );
        let proof = MerkleProofEntry {
            txid: vec![0u8; 32],
            block_height: 0,
            tx_position: 0,
            merkle_path: vec![vec![0u8; 32]; 32],
        };
        let mut source = fixture_source("rgb:any-declared-asset");
        source.merkle_proofs = vec![proof; n];
        let err = validate_source_payload(&source, &BridgeConfig::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("too large in aggregate"), "unexpected: {err}");
    }

    /// Old `ignores_consignment_valid_flag_when_bytes_present`: an identical
    /// payload must validate identically whatever the host claims in
    /// `consignment_valid` - the gate never reads the flag.
    #[test]
    fn ignores_consignment_valid_flag_when_bytes_present() {
        let mut source = fixture_source("rgb:any-declared-asset");
        source.consignment_valid = false;
        assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
        source.consignment_valid = true;
        assert!(validate_source_payload(&source, &BridgeConfig::default()).is_ok());
    }

    /// Old `rejects_empty_consignment_even_with_valid_flag` (P0 regression):
    /// a host-supplied `consignment_valid: true` with no consignment bytes
    /// must be rejected - the flag can never substitute for the bytes.
    #[test]
    fn rejects_empty_consignment_even_with_valid_flag() {
        let mut source = fixture_source("rgb:any-declared-asset");
        source.consignment = vec![];
        source.consignment_hash = vec![];
        source.consignment_valid = true;
        let err = validate_source_payload(&source, &BridgeConfig::default()).unwrap_err();
        assert!(
            err.to_string().contains("requires raw consignment bytes"),
            "expected raw-bytes-required rejection, got: {err}"
        );
    }

    /// Symmetric pin: the flag cannot rescue a wrong hash either.
    #[test]
    fn rejects_consignment_hash_mismatch_even_with_valid_flag() {
        let mut source = fixture_source("rgb:any-declared-asset");
        source.consignment_hash = vec![0xDE; 32];
        source.consignment_valid = true;
        let err = validate_source_payload(&source, &BridgeConfig::default()).unwrap_err();
        assert!(
            err.to_string().contains("consignment hash mismatch"),
            "expected hash-mismatch rejection, got: {err}"
        );
    }

    // Asset-identity binding, SOURCE path - successor of the dropped
    // `evm_crosscheck::asset_bind` suite. Its target,
    // `bind_asset_identity`, was removed in the networks/ split; the legs are
    // now INLINED in `validate_source` (this file) after
    // `validate_consignment`, so the narrowest callable unit is
    // `validate_source` itself, driven end-to-end with the in-tree mainnet
    // fixture validated offline against a stub Esplora (the resolver only
    // phones home for the genesis-hash chain-identity check; the fixture
    // embeds its witness txs, which `add_consignment_txes` registers as
    // tentative).
    //
    // Path asymmetry (deliberate, see each test): here the RGB_ASSET_ID pin
    // is gated on `BridgeConfig::is_configured()`; the destination path
    // (`validate_destination_anchor`, `networks/rgb/mod.rs`) enforces the pin
    // unconditionally.

    mod asset_bind {
        use super::*;
        use crate::config::BridgeConfig;
        use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
        use std::sync::Mutex;

        /// Contract id of `TRANSFER_FIXTURE`. Kept as a literal (the old
        /// suite's `PIN`), re-derived and asserted in [`fixture_asset_id`]
        /// so a fixture swap fails loud instead of silently retargeting
        /// every binding test.
        const FIXTURE_ASSET_ID: &str = "rgb:fuhLYX9G-eC8gDvf-V0XpYFH-ceSafoc-lGutAYq-~SExGU4";

        /// The validated asset identity: the fixture's genesis contract id.
        fn fixture_asset_id() -> String {
            let t = Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");
            let id = t.contract_id().to_string();
            assert_eq!(
                id, FIXTURE_ASSET_ID,
                "transfer fixture contract id drifted - update FIXTURE_ASSET_ID"
            );
            id
        }

        /// Stub Esplora serving only `GET /block-height/0` with the mainnet
        /// genesis hash - all offline rgbstd validation of the fixture needs:
        /// the resolver phones home only for the genesis-hash chain-identity
        /// check, and the fixture embeds its witness txs (registered as
        /// tentative via `add_consignment_txes`).
        fn spawn_stub_esplora() -> String {
            use std::io::{Read as _, Write as _};
            use std::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub esplora");
            let addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first = req.lines().next().unwrap_or("").to_string();
                    if !first.starts_with("GET /block-height/0") {
                        let _ = stream.write_all(
                            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        );
                        continue;
                    }
                    let body = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin)
                        .block_hash()
                        .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            });
            format!("http://{addr}")
        }

        /// Fully-pinned operator config (`is_configured() == true`) with the
        /// given RGB_ASSET_ID.
        fn pinned_config(rgb_asset_id: &str) -> BridgeConfig {
            BridgeConfig {
                chain_id: 1,
                bridge_contract: [0x11; 20],
                rgb_asset_id: rgb_asset_id.into(),
                gas_tx_allowed_to: None,
                ..Default::default()
            }
        }

        /// Fully-empty operator config (`is_configured() == false`) - the
        /// legacy dev/mock posture.
        fn unconfigured_config() -> BridgeConfig {
            BridgeConfig {
                chain_id: 0,
                bridge_contract: [0u8; 20],
                rgb_asset_id: String::new(),
                gas_tx_allowed_to: None,
                ..Default::default()
            }
        }

        /// Mainnet header chain whose checkpoint is stamped "now": the SPV
        /// staleness and chain-net checks pass, so a fully-bound source
        /// proceeds to the merkle-proof coverage check. Its distinctive
        /// "missing merkle proofs" error is this suite's proof that every
        /// asset-binding leg was traversed (real proofs for the fixture's
        /// mainnet witness txs are not constructible in a unit test).
        fn fresh_mainnet_chain() -> Mutex<HeaderChain> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            Mutex::new(HeaderChain::new(
                Network::Mainnet,
                Checkpoint {
                    height: 0,
                    hash: [0u8; 32],
                    bits: 0x1d00_ffff,
                    time: now,
                    is_real: false,
                },
            ))
        }

        /// Drive `validate_source` (the unit the binding is inlined in) with
        /// a stub-Esplora validator and a fresh mainnet header chain.
        fn run_validate_source(
            source: &RgbSource,
            config: &BridgeConfig,
        ) -> Result<ValidatedConsignment> {
            let url = spawn_stub_esplora();
            let validator = RgbValidator::new(url, "bitcoin").expect("validator");
            let chain = fresh_mainnet_chain();
            let ctx = ValidationContext {
                bridge_config: config,
                rgb_validator: Some(&validator),
                header_chain: &chain,
                // Source validation never reaches the destination PSBT bind.
                self_owned_psbt_outputs: None,
                #[cfg(feature = "bfa-mint")]
                bridge_events: &[],
            };
            validate_source(source, &ctx)
        }

        /// Happy path (old `binds_when_contract_id_matches_pin`): validated
        /// contract_id == declared asset_id == pinned RGB_ASSET_ID. Every
        /// binding leg passes and validation proceeds to the SPV stage -
        /// the failure there is *past* the binding, and specifically past
        /// the staleness + chain-net checks too.
        #[test]
        fn binds_when_contract_id_matches_pin() {
            let id = fixture_asset_id();
            let err = run_validate_source(&fixture_source(&id), &pinned_config(&id)).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("missing merkle proofs"),
                "expected to reach the SPV proof-coverage stage, got: {msg}"
            );
            assert!(
                !msg.contains("contract_id mismatch") && !msg.contains("RGB_ASSET_ID"),
                "asset binding must have passed, got: {msg}"
            );
        }

        /// Old `binds_when_declared_is_empty`, semantics INVERTED by a
        /// deliberate post-merge strengthening: the networks/ split requires
        /// the RGB source to declare its asset - an empty `asset_id` now
        /// fails closed in `validate_source_payload` instead of binding via
        /// the pin alone. This same rejection is what carries the old
        /// `rejects_foreign_asset_even_when_declared_is_empty` guarantee:
        /// with an empty declared id *nothing* binds, foreign or not.
        #[test]
        fn rejects_when_declared_is_empty() {
            let err = run_validate_source(&fixture_source(""), &pinned_config(FIXTURE_ASSET_ID))
                .unwrap_err();
            assert!(
                err.to_string().contains("RGB source asset_id is empty"),
                "expected empty-declared rejection, got: {err}"
            );
        }

        /// Old `rejects_foreign_asset_even_when_declared_is_empty`, adapted:
        /// empty declarations are now rejected up-front (previous test), so
        /// the closest reachable form of the funds-theft path is a
        /// listener that *colludes* - declaring the foreign asset
        /// consistently with the consignment. The pin must still reject it:
        /// RGB_ASSET_ID is load-bearing regardless of what the listener says.
        #[test]
        fn rejects_foreign_asset_even_when_declared_agrees() {
            let id = fixture_asset_id();
            let err = run_validate_source(
                &fixture_source(&id),
                &pinned_config("rgb:some-other-pinned-asset"),
            )
            .unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("contract_id mismatch") && msg.contains("pinned RGB_ASSET_ID"),
                "expected pin mismatch, got: {msg}"
            );
        }

        /// Old `rejects_when_declared_disagrees_with_validated`: the listener
        /// declares a different asset than the validated identity. Fires on
        /// the declared-vs-validated leg (which runs before the pin block).
        #[test]
        fn rejects_when_declared_disagrees_with_validated() {
            let err = run_validate_source(
                &fixture_source("rgb:listener-lied"),
                &pinned_config(FIXTURE_ASSET_ID),
            )
            .unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("contract_id mismatch") && msg.contains("RGB source declares"),
                "expected declared-mismatch rejection, got: {msg}"
            );
        }

        /// Old `rejects_when_pin_absent` - the source-path ASYMMETRY: here
        /// the pin block is gated on `BridgeConfig::is_configured()`, so a
        /// fully-empty config skips the pin and the binding degrades to
        /// declared == validated, proceeding to SPV (this test pins exactly
        /// that). It does NOT fail closed here; the unconditional fail-closed
        /// successor lives on the destination path
        /// (`networks/rgb/mod.rs::tests::asset_bind::rejects_when_pin_absent`)
        /// and, for this RGB->EVM direction, in the EVM destination's
        /// `!is_configured()` rejection (`networks/evm/validation.rs`,
        /// `not(test)`-gated, asserted at the integration layer). The inner
        /// "pinned chain/contract but RGB_ASSET_ID is empty" branch in
        /// `validate_source` is unreachable: `is_configured()` already
        /// requires a non-empty RGB_ASSET_ID.
        #[test]
        fn pin_check_skipped_when_config_unconfigured() {
            let id = fixture_asset_id();
            let err =
                run_validate_source(&fixture_source(&id), &unconfigured_config()).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("missing merkle proofs"),
                "expected to reach the SPV proof-coverage stage with the pin block skipped, \
                 got: {msg}"
            );
        }

        // Old `rejects_when_contract_id_absent`: NOT portable to this path.
        // The guard survives (validate_source rejects an empty validated
        // contract_id before any binding), but it is unreachable through the
        // narrowest callable unit: `RgbValidator::validate_consignment`
        // derives contract_id from the consignment's genesis, which is never
        // empty for a loadable Transfer, and `ValidationContext.rgb_validator`
        // is the concrete type - there is no seam to inject a fabricated
        // ValidatedConsignment. Recorded as not-feasible in the restoration
        // report rather than weakened into a vacuous test.
    }
}
