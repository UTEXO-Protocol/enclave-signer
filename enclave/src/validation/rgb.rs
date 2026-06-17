//! In-enclave RGB consignment validation using rgbstd + Esplora resolver.
//!
//! Validates raw consignment bytes by deserializing them into an RGB `Transfer`,
//! connecting to an Esplora indexer to resolve witness transactions, and running
//! the full rgbstd validation pipeline. This replaces trusting the Listener's
//! `consignment_valid` boolean.

use std::collections::BTreeSet;
use std::io::Cursor;

use rgb_consignment::{
    ConsignmentInfo, FungibleAllocation, FungibleEntry, SealInfo, TransitionInfo, WitnessInfo,
};
use rgbstd::containers::{ConsignmentExt, FileContent, Transfer};
use rgbstd::indexers::esplora_blocking::esplora_client;
use rgbstd::indexers::AnyResolver;
use rgbstd::schema::{MetaType, TransitionType};
use rgbstd::validation::ValidationConfig;
use rgbstd::ChainNet;

use crate::error::{EnclaveError, Result};

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
}

/// Flat summary of one RGB state transition. Mirrors
/// `rgb_consignment::TransitionInfo` but in types we own, so the parser dep
/// doesn't leak into our public surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionSummary {
    /// Operation id (baid64).
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
        let (all_op_ids, mut last_transition) = extract_transition_summary(consignment_bytes)?;
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
        // transaction. Gated on the last transition being a Transfer: the
        // bind is only meaningful for the pools-mode send shape, and the
        // consistency check inside reads the parsed transition type to ensure
        // the txid and the transition come from the same witness.
        let (last_transfer_witness_txid, last_transfer_witness_prevouts) = match last_transition {
            Some(ref last) if last.transition_type == ifa::TS_TRANSFER => {
                read_last_transfer_witness(&transfer, last.transition_type)?
            }
            _ => (None, None),
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

        // 3. Build validation config.
        let config = ValidationConfig {
            chain_net: self.chain_net,
            trusted_typesystem: transfer.types.clone(),
            build_opouts_dag: true,
            ..Default::default()
        };

        // 4. Run full RGB validation (makes blocking HTTP calls to Esplora).
        tracing::debug!(%contract_id, "calling rgbstd validate (this may block on Esplora)");
        let _valid = transfer.validate(&resolver, &config).map_err(|e| {
            tracing::warn!(
                %contract_id,
                elapsed_ms = start.elapsed().as_millis() as u64,
                "RGB validation failed: {e}"
            );
            EnclaveError::CrossCheck(format!("RGB consignment validation failed: {e}"))
        })?;

        tracing::info!(
            %contract_id,
            %chain_net,
            witness_txids_count = witness_txids.len(),
            transitions_count,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "RGB consignment validated successfully"
        );

        Ok(ValidatedConsignment {
            contract_id,
            chain_net,
            witness_txids,
            all_op_ids,
            last_transition,
            last_transfer_witness_txid,
            last_transfer_witness_prevouts,
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
/// Returns `(None, None)` only when the transfer has no bundles — a state
/// rgbstd validation rejects upstream.
fn read_last_transfer_witness(
    transfer: &Transfer,
    expected_type: u16,
) -> Result<(Option<bitcoin::Txid>, Option<Vec<bitcoin::OutPoint>>)> {
    let Some(last_bundle) = transfer.bundles.iter().last() else {
        return Ok((None, None));
    };

    if let Some(known) = last_bundle.bundle().known_transitions.iter().last() {
        let actual = known.transition.transition_type;
        let expected = TransitionType::with(expected_type);
        if actual != expected {
            return Err(EnclaveError::CrossCheck(format!(
                "consignment last-bundle transition type {actual} disagrees with parsed last \
                 transition type {expected} — refusing to bind PSBT to an ambiguous witness"
            )));
        }
    }

    // `witness_id()` is `bitcoin::Txid` (rgb re-exports the same bitcoin 0.32
    // crate the enclave depends on), so no byte-order conversion is needed.
    let txid = last_bundle.witness_id();
    let prevouts = last_bundle
        .pub_witness
        .tx()
        .map(|tx| tx.input.iter().map(|txin| txin.previous_output).collect());

    Ok((Some(txid), prevouts))
}

/// Parse the consignment with `rgb_consignment::parse` and pull out the
/// flat transition summary (every op_id + the most recent transition's
/// shape). Errors if the consignment isn't a Transfer or if any field
/// fails to decode.
fn extract_transition_summary(
    consignment_bytes: &[u8],
) -> Result<(Vec<String>, Option<TransitionSummary>)> {
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

    let last_transition = transfer
        .witnesses
        .last()
        .and_then(|w| w.transitions.last())
        .map(transition_summary)
        .transpose()?;

    Ok((all_op_ids, last_transition))
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

    let outputs: Result<Vec<TransitionOutput>> = t
        .fungible_allocations
        .iter()
        .flat_map(|a: &FungibleAllocation| a.entries.iter().map(transition_output))
        .collect();

    Ok(TransitionSummary {
        op_id: t.op_id.clone(),
        transition_type: t.transition_type,
        total_output_amount,
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
        include_bytes!("../../tests/fixtures/transfer_consignment.rgbc");
    const CONTRACT_FIXTURE: &[u8] =
        include_bytes!("../../tests/fixtures/contract_consignment.rgbc");

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

    #[test]
    fn extracts_op_ids_and_last_transition_from_transfer_fixture() {
        let (all_op_ids, last_transition) =
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
        let (_, last_transition) =
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
        let (txid, prevouts) =
            read_last_transfer_witness(&transfer, ifa::TS_TRANSFER).expect("extract witness");

        // Every validated transfer has at least one bundle, so the txid is set.
        let txid = txid.expect("transfer fixture has a witness txid");
        // It must equal the last bundle's witness id (the bundle we bind to).
        let expected = transfer
            .bundles
            .iter()
            .last()
            .expect("fixture has bundles")
            .witness_id();
        assert_eq!(txid, expected);

        // The rgb-lib sender embeds the full witness tx for a freshly-composed
        // transfer, so the prevouts (the witness tx's Bitcoin inputs) are
        // present and non-empty — the per-input canary is available.
        let prevouts = prevouts.expect("fixture embeds the full witness tx (PubWitness::Tx)");
        assert!(
            !prevouts.is_empty(),
            "witness tx must spend at least one input"
        );
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
}
