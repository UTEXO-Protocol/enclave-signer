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
use rgbstd::validation::ValidationConfig;
use rgbstd::ChainNet;

use crate::error::{EnclaveError, Result};

/// Data extracted from a successfully validated RGB consignment.
#[derive(Debug, Clone)]
pub struct ValidatedConsignment {
    /// RGB contract identifier (e.g., "rgb:2TGhRyP3-..."). Globally unique
    /// per asset; derived from the genesis operation in RGB 0.11.
    pub contract_id: String,
    /// Bitcoin network the consignment is anchored to, in rgbstd's prefix
    /// form: `"bc"`, `"bc:testnet3"`, `"bc:signet"`, or `"bc:regtest"`.
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
}

/// Flat summary of one RGB state transition. Mirrors
/// `rgb_consignment::TransitionInfo` but in types we own, so the parser dep
/// doesn't leak into our public surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionSummary {
    /// Operation id (baid64).
    pub op_id: String,
    /// IFA-schema transition-type id (Transfer / Burn / Mint / ...). The
    /// schema-specific `u16` constants are not interpreted here — that
    /// happens in the EVM-crosscheck layer once the constants are
    /// confirmed against `rgb-ops`'s IFA schema definition.
    pub transition_type: u16,
    /// Sum of all fungible amounts across all output assignments of this
    /// transition. For a Transfer this is the total of recipient + change
    /// outputs; for a Burn this is **zero** because burns have no output
    /// assignments (the burned amount lives in transition metadata,
    /// surfaced separately in a follow-up PR).
    pub total_output_amount: u64,
    /// Concrete output assignments, each tagged with a destination seal
    /// and an amount. Empty for Burn transitions.
    pub outputs: Vec<TransitionOutput>,
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
        let (all_op_ids, last_transition) = extract_transition_summary(consignment_bytes)?;
        let transitions_count = all_op_ids.len();

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
        })
    }
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
    })
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
