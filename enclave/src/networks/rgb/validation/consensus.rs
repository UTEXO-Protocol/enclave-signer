//! Running RGB consensus over a consignment.
//!
//! The one place raw consignment bytes become a [`super::types::ValidatedConsignment`].
//! A second `impl RgbValidator` block: the resolver plumbing it calls lives in
//! [`super::indexer`], and this is the policy that decides what passes.

use super::bfa;
use super::consignment::{
    extract_transition_summary, read_last_transfer_witness, read_last_transition_burn_recipient,
    read_last_transition_burned_asset,
};
use super::indexer::{RgbValidator, ELECTRUM_WITNESS_TIMEOUT_SECS};
use super::schema::trusted_typesystem_for_schema;
use super::types::ValidatedConsignment;
use crate::error::EnclaveError;
use crate::error::Result;
use rgbstd::containers::{ConsignmentExt, FileContent, Transfer};
use rgbstd::indexers::esplora_blocking::esplora_client;
use rgbstd::indexers::AnyResolver;
#[cfg(feature = "bfa-validation")]
use rgbstd::persistence::MemContract;
#[cfg(feature = "bfa-validation")]
use rgbstd::persistence::MemContractState;
use rgbstd::validation::ValidationConfig;
use rgbstd::validation::ValidationError;
#[cfg(feature = "bfa-validation")]
use rgbstd::vm::ether_extension::BridgedContract;
use rgbstd::vm::ether_extension::Event;
#[cfg(feature = "bfa-validation")]
use rgbstd::vm::ether_extension::IssuedAmountCheckExt;
use std::collections::BTreeSet;
use std::io::Cursor;

impl RgbValidator {
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
        #[cfg_attr(not(feature = "bfa-validation"), allow(unused_variables))]
        bridge_events: &[Event],
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

        // The parser drops `Transition.metadata`, so read BFA
        // `MS_BURNED_ASSET` straight from rgbstd's `Transfer`. Only the last
        // transition matters; a non-burn leaves the field `None`.
        if let Some(ref mut last) = last_transition {
            if last.transition_type == bfa::TS_BURN {
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
        // (see `crate::networks::rgb::flow`); the check inside asserts the transition type and
        // the witness agree.
        let (last_transfer_witness_prevouts, last_transfer_op_id) = match last_transition {
            Some(ref last)
                if crate::networks::rgb::flow::is_signing_transition(last.transition_type) =>
            {
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
        let schema_id = transfer.genesis.schema_id;
        let trusted_typesystem = trusted_typesystem_for_schema(schema_id).inspect_err(|_| {
            tracing::warn!(%contract_id, %schema_id, "consignment schema is not admitted");
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
        // No schema branch: the gate above admits BFA and nothing else, so
        // every consignment reaching here needs the extension.
        #[cfg(feature = "bfa-validation")]
        let validation_result = {
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
        };
        #[cfg(not(feature = "bfa-validation"))]
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
