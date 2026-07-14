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
use rgbstd::schema::{MetaType, TransitionType};
use rgbstd::validation::ValidationConfig;
use rgbstd::vm::WitnessOrd;
use rgbstd::ChainNet;
use sha3::{Digest, Keccak256};

use crate::error::{EnclaveError, Result};
use crate::networks::ValidationContext;
use crate::proto::RgbSource;

#[cfg(feature = "spv")]
use super::spv_validation;

/// Validate all fields and source-chain evidence owned by an RGB source.
///
/// This deliberately does not inspect or care about the destination network.
/// For an RGB source, the source-chain proof is:
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
    validate_source_payload(source)?;

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "RGB source validation requires rgb_validator to be configured".into(),
        )
    })?;

    let validated = validator.validate_consignment(&source.consignment)?;

    if validated.contract_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "validated consignment has empty contract_id — cannot bind asset identity".into(),
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
                "bridge config pinned chain/contract but RGB_ASSET_ID is empty — \
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

fn validate_source_payload(source: &RgbSource) -> Result<()> {
    if source.consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB source requires raw consignment bytes; consignment_valid is not authoritative"
                .into(),
        ));
    }
    // Hash integrity check between listener-supplied bytes and the pre-computed
    // keccak. This is INTEGRITY, NOT AUTHORIZATION (audit I-02 / Oxorio I-09):
    // the listener controls BOTH `consignment` and `consignment_hash`, so a
    // match only proves the wire copy was not corrupted in transit - it says
    // nothing about whether the consignment authorizes this release.
    // Authorization comes solely from the independent in-enclave RGB validation
    // (`validate_consignment` below, `rgbstd::Transfer::validate` against an
    // Esplora resolver), SPV anchoring, and the binding of validated facts
    // (contract_id / op_id / amount). Keep this as defence-in-depth tamper
    // detection; never read a hash match as proof of intent.
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
/// Fungible Asset (IFA) schema we use for USDT. Sourced from the
/// `rgb-protocol/rgb-schemas` `src/lib.rs` definitions (`TS_*` for
/// transition-type ids, `MS_*` for metadata-type ids). Constants are tied
/// to the schema's contract — rotating the schema = updating these.
pub mod ifa {
    /// IFA transition that moves an existing asset allocation from one
    /// owner to another. Pools-mode swaps use this on their last
    /// transition.
    pub const TS_TRANSFER: u16 = 10000;
    /// IFA transition that mints new units against the contract's
    /// inflation rights. Mint-mode locks produce this server-side; the
    /// enclave reads OpIds of these transitions for spec §6 OpId binding.
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
    /// (`assetOwner`) — the allocations that actually carry asset units.
    pub const OS_ASSET: u16 = 4000;
    /// IFA fungible assignment type carrying the remaining right-to-mint
    /// (`inflationAllowance`). Its `amount` is mint *capacity*, not asset
    /// units — summing it together with `OS_ASSET` would let an inflation
    /// consignment claim allowance as minted value (#54).
    pub const OS_INFLATION: u16 = 4010;
}

/// Resolve the **trusted** strict type-system the validator must pin a
/// consignment against, sourced from the canonical `rgb-schemas` crate by the
/// consignment's `schema_id` — exactly as rgb-lib does
/// (`AssetSchema::types()` → `InflatableFungibleAsset::types()` etc.).
///
/// **Audit 4th W-01 / #92.** RGB's `ValidationConfig.trusted_typesystem` must
/// come from an enclave-pinned source, never from the consignment under
/// validation: feeding `transfer.types` back in makes rgbstd compare the
/// consignment's types against themselves (`validator.rs::validate_schema`),
/// so the control always passes and a malicious consignment can ship its own
/// type definitions for the schema's `SemId`s. Instead we look the schema_id
/// up against the schema definitions compiled into `rgb-schemas` and hand the
/// validator *that* type system; rgbstd then rejects any consignment whose
/// types differ from the canonical set.
///
/// All four standard fungible/collectible schemas are accepted here; the
/// bridge additionally pins the exact asset via `contract_id` →
/// `RGB_ASSET_ID` (`bind_asset_identity`), so schema breadth at this layer is
/// not asset-scoping. An **unknown** schema_id is rejected fail-closed.
///
/// Schema ids are compared by their canonical string form so the comparison
/// is robust to `rgb-schemas` resolving a different `rgb-consensus` build than
/// the enclave's validator (the `SchemaId` *value* is a content commitment and
/// stringifies identically across versions).
#[cfg(feature = "rgb-validation")]
fn trusted_typesystem_for_schema(schema_id: &str) -> Result<rgbstd::TypeSystem> {
    use rgbstd::contract::IssuerWrapper;
    use schemata::{
        CollectibleFungibleAsset, InflatableFungibleAsset, NonInflatableAsset, UniqueDigitalAsset,
        CFA_SCHEMA_ID, IFA_SCHEMA_ID, NIA_SCHEMA_ID, UDA_SCHEMA_ID,
    };

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
            "consignment uses unknown/unsupported RGB schema {schema_id} — refusing to validate \
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
    /// in **display (big-endian) byte order** — same encoding as
    /// `MerkleProofEntry.txid` on the wire. Deduplicated and sorted so
    /// equality checks against the listener's set are stable.
    pub witness_txids: Vec<[u8; 32]>,
    /// Every state-transition `op_id` in the consignment, in witness order
    /// (bundle k's transitions before bundle k+1's). Spec §6 requires
    /// every mint OpId committed to EVM state to be cross-checked across
    /// RGB validations. The downstream filter for "which of these is a
    /// mint" lives in a follow-up PR once the IFA-schema `MINT`
    /// `transition_type` constant is confirmed.
    pub all_op_ids: Vec<String>,
    /// The `op_id`s of every IFA `TS_INFLATION` (mint) transition in the
    /// consignment, in witness order — the subset of [`Self::all_op_ids`]
    /// that corresponds to EVM lock records (`fundsIn`). The `fundsOut`
    /// calldata's `fundsInIds[]` (inside `settlementData`) must each
    /// correspond to one of these (under the agreed OpId→id transform), so
    /// a release can only consume locks this consignment's RGB history
    /// actually inflated (spec §6 / §7). See
    /// `evm::validation::apply_op_id_binding`.
    pub mint_op_ids: Vec<String>,
    /// The most recent state transition — the change of state the EVM
    /// action this consignment authorises commits to. Follow-up PRs
    /// classify this as Transfer-to-federation (pools / spec §9.2,
    /// §9.3) or Burn (mint-burn unlock / spec §8) and extract the
    /// authoritative amount + destination binding from it. `None` only
    /// for malformed transfers with no transition bundles, which rgbstd
    /// validation rejects upstream — kept as `Option` for type
    /// completeness.
    pub last_transition: Option<TransitionSummary>,
    /// Bitcoin txid of the witness transaction anchoring the consignment's
    /// **last** transition — the freshly-composed transfer in the send-RGB
    /// (EVM-lock → RGB-send) direction. The PSBT being signed in that flow
    /// IS this witness transaction; the PSBT cross-check binds
    /// `psbt.unsigned_tx.compute_txid()` to this value so a signed PSBT
    /// can't move bridge BTC without finalizing exactly the validated RGB
    /// transition. A `bitcoin::Txid` (not display-order bytes) so the
    /// comparison is type-safe and avoids the txid byte-order footgun.
    /// `None` only for a consignment with no bundles (rgbstd rejects those).
    pub last_transfer_witness_txid: Option<bitcoin::Txid>,
    /// Bitcoin input prevouts of that same witness transaction, when the
    /// consignment embeds the full witness tx (`PubWitness::Tx`, which the
    /// rgb-lib sender does for a freshly-composed transfer). Used by the
    /// PSBT cross-check as a redundant per-input canary over the txid bind:
    /// the set of PSBT input outpoints must equal this set. `None` when the
    /// consignment carries only the witness txid (`PubWitness::Txid`), in
    /// which case the txid identity bind alone anchors every input.
    pub last_transfer_witness_prevouts: Option<Vec<bitcoin::OutPoint>>,
    /// Authoritative OpId (32-byte commitment hash) of the consignment's
    /// **last** transition, read from the rgbstd-**validated** `Transfer`
    /// (`KnownTransition.opid` of the same last bundle as
    /// `last_transfer_witness_txid`), NOT from the flat `rgb_consignment`
    /// parser. This is the value `validate()` authenticated and anchored on
    /// chain, so deriving the EVM `fundsOut` `burnId` from it
    /// (`evm::validation::apply_op_id_binding`, audit M-02 / #93) binds the
    /// contract's single-use `consumedBurnIds` guard to validated consignment
    /// data, not a parallel/unauthenticated parse. `None` only for a
    /// consignment with no bundles (rgbstd rejects those) or a non-Transfer
    /// last transition (the burnId binding only applies to the transfer flow).
    pub last_transfer_op_id: Option<[u8; 32]>,
    /// Witness txids that rgbstd `validate()` classified as **not mined**
    /// (`WitnessOrd::Tentative` / `Ignored`), in **display (big-endian) byte
    /// order** - same encoding as [`Self::witness_txids`]. `validate()` already
    /// hard-rejects `Archived`/unresolvable witnesses, so only these softer
    /// not-yet-confirmed states reach here, and only because this set is built
    /// from the rgbstd status that was previously discarded (audit 4th
    /// I-03 / #95).
    ///
    /// A non-empty set is **expected** for the send-RGB (EVM-lock -> RGB-send)
    /// PSBT path: that witness tx is freshly composed and unbroadcast, so it is
    /// legitimately `Tentative`. It is an **anomaly** for the RGB->EVM
    /// `fundsOut` direction, where the witness is already confirmed on-chain
    /// and SPV-verified - the SignEvm path rejects any non-mined witness as
    /// defense-in-depth atop the SPV depth check (see
    /// `evm::validation::assert_witnesses_confirmed`).
    pub non_mined_witness_txids: Vec<[u8; 32]>,
}

/// Flat summary of one RGB state transition. Mirrors
/// `rgb_consignment::TransitionInfo` but in types we own, so the parser dep
/// doesn't leak into our public surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionSummary {
    /// Operation id — the 64-char lowercase hex of the 32-byte RGB OpId, as
    /// the consignment parser yields it (verified by the fixture test). The
    /// EVM OpId cross-check compares this as a string; the `fundsInIds`
    /// value-binding hex-decodes it to 32 bytes
    /// (`evm::crosscheck::decode_op_id_to_bytes32`), so the hex form is
    /// load-bearing - not baid64. (The `burnId` is bound instead from the
    /// rgbstd-validated [`ValidatedConsignment::last_transfer_op_id`], not this
    /// flat-parser value - audit M-02 / #93.)
    pub op_id: String,
    /// IFA-schema transition-type id; compare against [`ifa::TS_TRANSFER`]
    /// / [`ifa::TS_BURN`] / [`ifa::TS_INFLATION`] to classify the EVM
    /// action this consignment authorises.
    pub transition_type: u16,
    /// Sum of all fungible amounts across all output assignments of this
    /// transition. For a Transfer this is the total of recipient + change
    /// outputs; for a Burn this is **zero** because burns have no output
    /// assignments — the destroyed amount lives in [`Self::burned_asset_amount`].
    pub total_output_amount: u64,
    /// Sum of the fungible amounts on `OS_ASSET`-typed output assignments
    /// only — the allocations that actually carry asset units. For a
    /// Transfer this equals [`Self::total_output_amount`] (transfers move
    /// only `OS_ASSET`); for an Inflation (mint) it is the freshly minted
    /// value, **excluding** the `OS_INFLATION` allowance outputs, whose
    /// amounts are remaining mint capacity, not asset units (#54).
    pub asset_output_amount: u64,
    /// Concrete output assignments, each tagged with a destination seal
    /// and an amount. Empty for Burn transitions.
    pub outputs: Vec<TransitionOutput>,
    /// Asset units destroyed by this transition, read from the IFA
    /// `MS_BURNED_ASSET` metadata field. `Some(0)` is allowed by the
    /// schema (partial burn writing 0 to OS_ASSET), but for our
    /// mint-burn unlock flow the bridge only ever signs unlocks against
    /// transitions where this is strictly positive — the EVM-crosscheck
    /// layer enforces that.
    ///
    /// `None` when:
    /// * the transition is not a burn (`transition_type != ifa::TS_BURN`); or
    /// * the burn transition is malformed (missing or wrong-sized
    ///   `MS_BURNED_ASSET` metadata) — rgbstd validation would have
    ///   already rejected such a consignment, so reaching this branch
    ///   in practice indicates an internal contract / schema mismatch.
    pub burned_asset_amount: Option<u64>,
}

/// One fungible output assignment on a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionOutput {
    /// Amount in the asset's smallest unit.
    pub amount: u64,
    /// Destination seal — either a revealed `txid:vout` or a hidden
    /// commitment.
    pub seal: OutputSeal,
}

/// Where a fungible output lives. Mirrors `rgb_consignment::SealInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSeal {
    /// Concrete `txid:vout`. `txid` is `None` when the seal points at the
    /// witness tx of its containing bundle — resolve by combining with
    /// the bundle's witness txid in display order.
    Revealed {
        /// Display-order bytes — matches `witness_txids` encoding.
        txid: Option<[u8; 32]>,
        vout: u32,
    },
    /// Hidden recipient seal (`utxob:...` SHA-256 commitment string).
    Confidential { secret_seal: String },
}

/// Validates RGB consignments using rgbstd and an Esplora-backed resolver.
#[derive(Debug)]
pub struct RgbValidator {
    esplora_url: String,
    chain_net: ChainNet,
}

impl RgbValidator {
    /// Create a new validator.
    ///
    /// - `esplora_url`: HTTP URL for the Esplora API (e.g., `http://127.0.0.1:3443`
    ///   when using the vsock forwarder, or a direct URL in dev mode).
    /// - `bitcoin_network`: One of "bitcoin", "testnet", "signet", "regtest".
    pub fn new(esplora_url: String, bitcoin_network: &str) -> Result<Self> {
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
        tracing::info!(%esplora_url, %bitcoin_network, "RGB validator configured");
        Ok(Self {
            esplora_url,
            chain_net,
        })
    }

    /// Validate raw consignment bytes. Returns extracted data on success,
    /// or a `CrossCheck` error if validation fails.
    pub fn validate_consignment(&self, consignment_bytes: &[u8]) -> Result<ValidatedConsignment> {
        let start = std::time::Instant::now();
        let bytes_len = consignment_bytes.len();
        tracing::info!(
            bytes_len,
            esplora_url = %self.esplora_url,
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

        // Pre-validation extraction: cheap, no networking, no consumption
        // of `transfer` (rgbstd::Transfer::validate consumes self further
        // down). chain_net + witness_txids are needed by the SPV crosscheck;
        // we read them out before validate() runs because validate() takes
        // ownership.
        let chain_net = transfer.genesis.chain_net.prefix().to_string();
        let mut txid_set: BTreeSet<[u8; 32]> = BTreeSet::new();
        for wb in transfer.bundles.iter() {
            // rgbstd's Txid stringifies in display order; decoding the hex
            // gives us display-order bytes (no reversal needed at this
            // boundary — reversal happens later, only inside the Merkle
            // verifier where internal-order is required).
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

        // F1 extraction: walk the consignment a second time via
        // `rgb_consignment::parse` to pull out transition op_ids, types,
        // and output assignments in a flat shape. We do the second parse
        // (rather than reaching into the rgbstd `Transfer` directly)
        // because the parser already exposes the typed `TransitionInfo` /
        // `FungibleAllocation` shape this code path needs, and the rgbstd
        // walk would duplicate ~80 lines we'd then have to keep in sync
        // with rgb-ops's evolving internal types. The parse cost is small
        // relative to the network validation below.
        let (all_op_ids, mint_op_ids, mut last_transition) =
            extract_transition_summary(consignment_bytes)?;
        let transitions_count = all_op_ids.len();

        // Burn-amount extraction: the parser doesn't surface
        // `Transition.metadata`, so we read the IFA `MS_BURNED_ASSET`
        // metadata field directly from rgbstd's `Transfer`. Only the
        // last transition matters for the unlock cross-check; if it's
        // not a burn, the field stays `None`.
        if let Some(ref mut last) = last_transition {
            if last.transition_type == ifa::TS_BURN {
                last.burned_asset_amount = read_last_transition_burned_asset(&transfer)?;
            }
        }

        // Witness-tx identity binding for the send-RGB (EVM-lock → RGB-send)
        // PSBT path. We extract the last bundle's witness txid (and, when the
        // bundle embeds the full tx, its input prevouts) so the PSBT
        // cross-check can prove the PSBT being signed IS this witness
        // transaction. Gated on the last transition being a Transfer (the
        // pools-mode send shape) or an Inflation (the mint-RGB shape, #54);
        // the consistency check inside reads the parsed transition type to
        // ensure the txid and the transition come from the same witness.
        let (last_transfer_witness_txid, last_transfer_witness_prevouts, last_transfer_op_id) =
            match last_transition {
                Some(ref last)
                    if matches!(last.transition_type, ifa::TS_TRANSFER | ifa::TS_INFLATION) =>
                {
                    read_last_transfer_witness(&transfer, last.transition_type)?
                }
                _ => (None, None, None),
            };

        // 2. Create an Esplora-backed resolver.
        let builder = esplora_client::Builder::new(&self.esplora_url);
        let mut resolver = AnyResolver::esplora_blocking(builder).map_err(|e| {
            tracing::error!(esplora_url = %self.esplora_url, "esplora resolver creation failed: {e}");
            EnclaveError::CrossCheck(format!("esplora resolver creation failed: {e}"))
        })?;

        // Register transactions bundled in the consignment so the resolver
        // treats them as tentative witnesses (not yet mined).
        resolver.add_consignment_txes(&transfer);

        // Pin the trusted type system (audit 4th W-01 / #92). Source it from
        // the canonical `rgb-schemas` definitions keyed on the consignment's
        // schema_id, NOT from `transfer.types`. Passing the consignment's own
        // types makes rgbstd compare them against themselves (always passes);
        // the canonical set makes `validate()` reject any consignment that
        // ships substituted type definitions for the schema's SemIds. An
        // unknown schema_id is rejected fail-closed inside the helper.
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
        let valid = transfer.validate(&resolver, &config).map_err(|e| {
            tracing::warn!(
                %contract_id,
                elapsed_ms = start.elapsed().as_millis() as u64,
                "RGB validation failed: {e}"
            );
            EnclaveError::CrossCheck(format!("RGB consignment validation failed: {e}"))
        })?;

        // Inspect the validation status instead of discarding it (audit 4th
        // I-03 / #95). A hard failure already came back as Err above; what
        // reaches here is `Ok` with a status that may still carry warnings and
        // a per-witness ordinal map. Without `safe_height` set, rgbstd's
        // `validity()` is `Valid` even when witnesses are not mined, so the
        // only signal of a not-yet-confirmed witness is `tx_ord_map` - we read
        // it out rather than trust `validity()` alone.
        //
        // We deliberately do NOT set `ValidationConfig.safe_height`: doing so
        // would flag recency against the *Esplora resolver's* tip, which is
        // host-controlled and untrusted. Recency for the RGB->EVM direction is
        // enforced authoritatively by the in-enclave SPV header chain
        // (`SPV_MIN_CONFIRMATIONS`); surfacing the witness ordinals here lets
        // that direction reject non-mined witnesses as defense-in-depth.
        let status = valid.validation_status();
        let mut non_mined: BTreeSet<[u8; 32]> = BTreeSet::new();
        for (txid, ord) in status.tx_ord_map.iter() {
            if !matches!(ord, WitnessOrd::Mined(_)) {
                // `txid` is `bitcoin::Txid`; its Display is display-order hex,
                // matching the `witness_txids` encoding decoded above.
                let display_hex = txid.to_string();
                let bytes = hex::decode(&display_hex).map_err(|e| {
                    EnclaveError::CrossCheck(format!(
                        "witness ordinal txid hex decode failed: {e} (got {display_hex:?})"
                    ))
                })?;
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    EnclaveError::CrossCheck(format!(
                        "witness ordinal txid is not 32 bytes (got {} bytes from {display_hex:?})",
                        bytes.len()
                    ))
                })?;
                tracing::warn!(%contract_id, txid = %display_hex, witness_ord = %ord, "consignment witness tx is not mined");
                non_mined.insert(arr);
            }
        }
        for warning in &status.warnings {
            tracing::warn!(%contract_id, "RGB validation warning: {warning}");
        }
        let non_mined_witness_txids: Vec<[u8; 32]> = non_mined.into_iter().collect();

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
            last_transfer_witness_txid,
            last_transfer_witness_prevouts,
            last_transfer_op_id,
            non_mined_witness_txids,
        })
    }
}

/// Extract the witness-tx identity binding for the consignment's **last**
/// transition out of the rgbstd `Transfer`: the witness txid of the bundle
/// carrying the most recent transition, and — when that bundle embeds the
/// full witness tx (`PubWitness::Tx`) — its Bitcoin input prevouts. Consumed
/// by the send-RGB PSBT cross-check to bind the PSBT being signed to the
/// consignment's `TS_TRANSFER` witness transaction.
///
/// Reads the **same** `transfer.bundles.iter().last()` bundle that
/// [`read_last_transition_burned_asset`] uses, and asserts that bundle's last
/// known transition type equals `expected_type` (the type the flat
/// `rgb_consignment` parser reported for the last transition). The parser
/// walk (`transfer.witnesses.last()`) and the rgbstd walk
/// (`transfer.bundles.iter().last()`) are two independent traversals of the
/// same data; binding a txid from one transition while gating on another
/// would be a latent mismatch, so a disagreement is rejected fail-closed.
///
/// Also returns the validated OpId (32-byte commitment hash) of that last
/// transition, read from the same rgbstd bundle - the authoritative source for
/// the EVM `fundsOut` burnId binding (audit M-02 / #93), NOT the flat parser.
///
/// Returns `(None, None, None)` only when the transfer has no bundles — a state
/// rgbstd validation rejects upstream.
fn read_last_transfer_witness(
    transfer: &Transfer,
    expected_type: u16,
) -> Result<LastTransferBinding> {
    let Some(last_bundle) = transfer.bundles.iter().last() else {
        return Ok((None, None, None));
    };

    // Read the authoritative OpId of the validated last transition from the
    // same bundle. rgbstd's `OpId` is the transition's commitment hash; its
    // `Display` is lowercase hex of the 32 bytes, so we hex-decode it back to
    // the raw array. Sourcing it here (the validated object) rather than from
    // the flat `rgb_consignment` parser is what makes the EVM burnId binding a
    // derivation from validated data (audit M-02 / #93).
    let mut op_id: Option<[u8; 32]> = None;
    if let Some(known) = last_bundle.bundle().known_transitions.iter().last() {
        let actual = known.transition.transition_type;
        let expected = TransitionType::with(expected_type);
        if actual != expected {
            return Err(EnclaveError::CrossCheck(format!(
                "consignment last-bundle transition type {actual} disagrees with parsed last \
                 transition type {expected} — refusing to bind PSBT to an ambiguous witness"
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

    // `witness_id()` is `bitcoin::Txid` (rgb re-exports the same bitcoin 0.32
    // crate the enclave depends on), so no byte-order conversion is needed.
    let txid = last_bundle.witness_id();
    let prevouts = last_bundle
        .pub_witness
        .tx()
        .map(|tx| tx.input.iter().map(|txin| txin.previous_output).collect());

    Ok((Some(txid), prevouts, op_id))
}

/// Binding data for the consignment's last transfer bundle:
/// `(witness txid, witness input prevouts, validated last-transition OpId)`.
/// All `Option` because a bundle-less transfer (rejected upstream by rgbstd)
/// yields `(None, None, None)`. See [`read_last_transfer_witness`].
type LastTransferBinding = (
    Option<bitcoin::Txid>,
    Option<Vec<bitcoin::OutPoint>>,
    Option<[u8; 32]>,
);

/// Parse the consignment with `rgb_consignment::parse` and pull out the
/// flat transition summary (every op_id + the most recent transition's
/// shape). Errors if the consignment isn't a Transfer or if any field
/// fails to decode.
#[allow(clippy::type_complexity)]
fn extract_transition_summary(
    consignment_bytes: &[u8],
) -> Result<(Vec<String>, Vec<String>, Option<TransitionSummary>)> {
    let info = rgb_consignment::parse(consignment_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("rgb-consignment parse failed: {e}")))?;

    let transfer = match info {
        ConsignmentInfo::Transfer(t) => t,
        // A Contract / Kit can't authorise an EVM action — the listener
        // wouldn't send one over SignEvm, but reject explicitly so a
        // mistaken upload fails closed instead of silently passing the
        // SPV stage.
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

    // The mint (IFA `TS_INFLATION`) subset — these map 1:1 to EVM lock
    // records (`fundsIn`). The `fundsOut` `fundsInIds[]` must each correspond
    // to one of these (spec §6).
    let mint_op_ids: Vec<String> = transfer
        .witnesses
        .iter()
        .flat_map(|w: &WitnessInfo| w.transitions.iter())
        .filter(|t: &&TransitionInfo| t.transition_type == ifa::TS_INFLATION)
        .map(|t: &TransitionInfo| t.op_id.clone())
        .collect();

    let last_transition = transfer
        .witnesses
        .last()
        .and_then(|w| w.transitions.last())
        .map(transition_summary)
        .transpose()?;

    Ok((all_op_ids, mint_op_ids, last_transition))
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

    // Asset units only: `OS_ASSET`-typed allocations. An Inflation (mint)
    // transition also carries `OS_INFLATION` allowance outputs whose amounts
    // are remaining mint *capacity* — counting those as minted value would
    // let a mint consignment cover an EVM lock it never minted for (#54).
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
        .flat_map(|a: &FungibleAllocation| a.entries.iter().map(transition_output))
        .collect();

    Ok(TransitionSummary {
        op_id: t.op_id.clone(),
        transition_type: t.transition_type,
        total_output_amount,
        asset_output_amount,
        outputs: outputs?,
        // Filled by `read_last_transition_burned_asset` if the
        // transition is a burn; the parser doesn't expose metadata so
        // we leave this `None` here.
        burned_asset_amount: None,
    })
}

/// Walk the rgbstd `Transfer` to the last witness bundle's last known
/// transition and pull the IFA `MS_BURNED_ASSET` value out of its
/// metadata. The parser drops `Transition.metadata` on the floor — we
/// read it here directly so the unlock cross-check has the destroyed
/// amount available.
///
/// The metadata value for `MS_BURNED_ASSET` is a strict-encoded
/// `rgbstd::Amount`, which is defined as `pub struct Amount(u64)` with
/// the standard `StrictEncode` derive — i.e. 8 bytes, little-endian.
/// We decode the `u64` manually rather than reaching for
/// `StrictDeserialize::from_strict_serialized` to avoid threading
/// the `rgb-strict-encoding`-as-`strict_encoding` rename through
/// our deps; the encoding shape has been stable since RGB 0.11 and
/// changes here would break wire compatibility upstream regardless.
///
/// Returns `Ok(None)` if there's no last transition (a validated
/// transfer should never produce that) or if the metadata key is
/// absent — rgbstd validation rejects a `TS_BURN` transition with no
/// `MS_BURNED_ASSET`, so reaching the `None` branch in production
/// implies a schema mismatch. Returns `Err` if the metadata blob is
/// the wrong size for a `u64`.
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

fn transition_output(e: &FungibleEntry) -> Result<TransitionOutput> {
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

    // Fixtures borrowed from the rgb-consignment-parser repo
    // (`test-data/consignment_out` and `test-data/asset`). Both are
    // mainnet NIA artefacts produced by the upstream rgb-lib test
    // harness; we ship them in-tree so the unit tests don't depend on
    // network access or the parser repo's working copy.
    const TRANSFER_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/transfer_consignment.rgbc");
    const CONTRACT_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/contract_consignment.rgbc");

    #[test]
    fn rejects_invalid_bytes() {
        let validator = RgbValidator::new("http://localhost:1".to_string(), "regtest").unwrap();
        let err = validator
            .validate_consignment(b"not-a-consignment")
            .unwrap_err();
        assert!(
            err.to_string().contains("deserialization failed"),
            "expected deserialization error, got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_network() {
        let err = RgbValidator::new("http://localhost:1".to_string(), "foonet").unwrap_err();
        assert!(err.to_string().contains("unknown bitcoin network"));
    }

    /// #54: `asset_output_amount` must count only `OS_ASSET`-typed
    /// allocations. An inflation (mint) transition also carries
    /// `OS_INFLATION` allowance outputs whose amounts are remaining mint
    /// capacity — counting them as minted value would let a mint consignment
    /// cover an EVM lock it never minted for.
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

    /// For a Transfer everything is `OS_ASSET`, so the two sums agree — the
    /// invariant the PSBT amount bind relies on when it switched from
    /// `total_output_amount` to `asset_output_amount` (#54).
    #[test]
    fn transfer_fixture_asset_amount_equals_total() {
        let (_, _, last_transition) =
            extract_transition_summary(TRANSFER_FIXTURE).expect("transfer parse");
        let last = last_transition.expect("transfer has a last transition");
        assert_eq!(last.transition_type, ifa::TS_TRANSFER);
        assert_eq!(last.asset_output_amount, last.total_output_amount);
    }

    #[test]
    fn extracts_op_ids_and_last_transition_from_transfer_fixture() {
        let (all_op_ids, mint_op_ids, last_transition) =
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
        // The W-01 fix (#92): the trusted type system must come from the
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
        // them, this test fails loud — the consequences of a silent
        // mismatch (mis-classifying a Transfer as a Burn or vice versa)
        // would be much worse than a CI break.
        assert_eq!(ifa::TS_TRANSFER, 10000);
        assert_eq!(ifa::TS_BURN, 8010);
        assert_eq!(ifa::TS_INFLATION, 8000);
        assert_eq!(ifa::MS_BURNED_ASSET, 1001);
    }

    #[test]
    fn last_transition_carries_revealed_and_confidential_seals() {
        let (_, _, last_transition) =
            extract_transition_summary(TRANSFER_FIXTURE).expect("transfer parse");
        let last = last_transition.expect("transfer has a last transition");

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
        // directly, so it needs no Esplora/network — load the fixture and
        // assert the witness-tx binding data the PSBT cross-check relies on.
        let transfer =
            Transfer::load(Cursor::new(TRANSFER_FIXTURE)).expect("load transfer fixture");

        // The fixture's last transition is a Transfer (type 10000, asserted in
        // `extracts_op_ids_and_last_transition_from_transfer_fixture`).
        let (txid, prevouts, op_id) =
            read_last_transfer_witness(&transfer, ifa::TS_TRANSFER).expect("extract witness");

        // Every validated transfer has at least one bundle, so the txid is set.
        let txid = txid.expect("transfer fixture has a witness txid");
        // It must equal the last bundle's witness id (the bundle we bind to).
        let last_bundle = transfer.bundles.iter().last().expect("fixture has bundles");
        let expected = last_bundle.witness_id();
        assert_eq!(txid, expected);

        // The rgb-lib sender embeds the full witness tx for a freshly-composed
        // transfer, so the prevouts (the witness tx's Bitcoin inputs) are
        // present and non-empty — the per-input canary is available.
        let prevouts = prevouts.expect("fixture embeds the full witness tx (PubWitness::Tx)");
        assert!(
            !prevouts.is_empty(),
            "witness tx must spend at least one input"
        );

        // The validated OpId (canonical burnId source, #93) must be present and
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
            "expected Contract→Transfer rejection, got: {msg}"
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

    // =========================================================================
    // Consignment-flag pins — successors of the dropped
    // `validation::evm_crosscheck` tests `accepts_valid_consignment_hash` /
    // `ignores_consignment_valid_flag_when_bytes_present` (+ the P0 companion
    // `rejects_empty_consignment_even_with_valid_flag`). Their target,
    // `validate_evm_request`'s payload gate, is now `validate_source_payload`
    // in this file. The wire type (`proto::RgbSource`) STILL carries the
    // host-supplied `consignment_valid: bool` (tag 1); the gate never reads
    // it — validity comes from the bytes, never the flag.
    // =========================================================================

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
        }
    }

    /// Old `accepts_valid_consignment_hash`: consignment bytes plus their
    /// matching keccak256 pass the payload gate. `Ok` here is "past the hash
    /// check" in full — everything after this gate in `validate_source` is
    /// validator/SPV work, not payload shape.
    #[test]
    fn accepts_valid_consignment_hash() {
        assert!(validate_source_payload(&fixture_source("rgb:any-declared-asset")).is_ok());
    }

    /// Old `ignores_consignment_valid_flag_when_bytes_present`: an identical
    /// payload must validate identically whatever the host claims in
    /// `consignment_valid` — the gate never reads the flag.
    #[test]
    fn ignores_consignment_valid_flag_when_bytes_present() {
        let mut source = fixture_source("rgb:any-declared-asset");
        source.consignment_valid = false;
        assert!(validate_source_payload(&source).is_ok());
        source.consignment_valid = true;
        assert!(validate_source_payload(&source).is_ok());
    }

    /// Old `rejects_empty_consignment_even_with_valid_flag` (P0 regression):
    /// a host-supplied `consignment_valid: true` with no consignment bytes
    /// must be rejected — the flag can never substitute for the bytes.
    #[test]
    fn rejects_empty_consignment_even_with_valid_flag() {
        let mut source = fixture_source("rgb:any-declared-asset");
        source.consignment = vec![];
        source.consignment_hash = vec![];
        source.consignment_valid = true;
        let err = validate_source_payload(&source).unwrap_err();
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
        let err = validate_source_payload(&source).unwrap_err();
        assert!(
            err.to_string().contains("consignment hash mismatch"),
            "expected hash-mismatch rejection, got: {err}"
        );
    }

    // =========================================================================
    // Asset-identity binding, SOURCE path — successor of the dropped
    // `evm_crosscheck::asset_bind` suite (audit TEE-SE-01). Its target,
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
    // =========================================================================

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
                "transfer fixture contract id drifted — update FIXTURE_ASSET_ID"
            );
            id
        }

        /// Stub Esplora serving only `GET /block-height/0` with the mainnet
        /// genesis hash — all offline rgbstd validation of the fixture needs:
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

        /// Fully-empty operator config (`is_configured() == false`) — the
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
            };
            validate_source(source, &ctx)
        }

        /// Happy path (old `binds_when_contract_id_matches_pin`): validated
        /// contract_id == declared asset_id == pinned RGB_ASSET_ID. Every
        /// binding leg passes and validation proceeds to the SPV stage —
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
        /// the RGB source to declare its asset — an empty `asset_id` now
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
        /// the closest reachable form of the TEE-SE-01 funds-theft path is a
        /// listener that *colludes* — declaring the foreign asset
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

        /// Old `rejects_when_pin_absent` — the source-path ASYMMETRY: here
        /// the pin block is gated on `BridgeConfig::is_configured()`, so a
        /// fully-empty config skips the pin and the binding degrades to
        /// declared == validated, proceeding to SPV (this test pins exactly
        /// that). It does NOT fail closed here; the unconditional fail-closed
        /// successor lives on the destination path
        /// (`networks/rgb/mod.rs::tests::asset_bind::rejects_when_pin_absent`)
        /// and, for this RGB→EVM direction, in the EVM destination's
        /// `!is_configured()` rejection (`networks/evm/validation.rs`,
        /// `not(test)`-gated, asserted at the integration layer). The inner
        /// "pinned chain/contract but RGB_ASSET_ID is empty" branch in
        /// `validate_source` is unreachable: `is_configured()` already
        /// requires a non-empty RGB_ASSET_ID (audit 4th M-03 / #94).
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
        // is the concrete type — there is no seam to inject a fabricated
        // ValidatedConsignment. Recorded as not-feasible in the restoration
        // report rather than weakened into a vacuous test.
    }
}
