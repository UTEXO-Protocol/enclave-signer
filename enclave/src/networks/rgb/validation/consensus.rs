//! Runs RGB consensus over a consignment.
//!
//! This is the only place where raw consignment bytes become a
//! [`super::types::ValidatedConsignment`]. The resolver plumbing is in
//! [`super::indexer`]. This file holds the policy that decides what passes.

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
    /// Validates raw consignment bytes and returns the extracted data.
    ///
    /// `bridge_events` are the EVM lock events that RGB consensus checks a BFA
    /// mint against. The caller must verify each one. The extension binds
    /// amount and OpId, not the emitting contract.
    pub fn validate_consignment(
        &self,
        consignment_bytes: &[u8],
        #[cfg_attr(not(feature = "bfa-validation"), allow(unused_variables))]
        bridge_events: &[Event],
    ) -> Result<ValidatedConsignment> {
        #[cfg(test)]
        if let Some(validated) = &self.canned {
            return Ok(validated.clone());
        }
        let start = std::time::Instant::now();
        let bytes_len = consignment_bytes.len();
        tracing::info!(
            bytes_len,
            indexer_url = %self.indexer_url,
            "starting RGB consignment validation"
        );

        // 1. Deserialize the consignment file format (magic + strict-encoded).
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

        // Extract before `validate()` takes ownership of `transfer`. The SPV
        // cross-check needs chain_net and witness_txids.
        let chain_net = transfer.genesis.chain_net.prefix().to_string();
        let mut txid_set: BTreeSet<[u8; 32]> = BTreeSet::new();
        for wb in transfer.bundles.iter() {
            // The rgbstd Txid string is in display order, so the hex decodes
            // to display-order bytes. The Merkle verifier reverses them later.
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

        // Second walk with `rgb_consignment::parse` for op_ids, types, and
        // output assignments in a flat shape. A direct rgbstd walk would
        // duplicate the parser against changing internal types.
        let (all_op_ids, mint_op_ids, mut last_transition, transitions_by_witness) =
            extract_transition_summary(consignment_bytes)?;
        let transitions_count = all_op_ids.len();

        // The parser drops `Transition.metadata`, so read the BFA burn metadata
        // from the rgbstd `Transfer`. Only the last transition is read.
        if let Some(ref mut last) = last_transition {
            if last.transition_type == bfa::TS_BURN {
                last.burned_asset_amount = read_last_transition_burned_asset(&transfer)?;
                last.burn_recipient = read_last_transition_burn_recipient(&transfer)?;
            }
        }

        // Witness tx of the last bundle, for all transition types, so the
        // fundsOut source-block bind also works on a burn. The PSBT path does
        // its own transition-type check.
        let last_witness_txid = transfer.bundles.iter().last().map(|wb| wb.witness_id());

        // Bind data for the same bundle: input prevouts (if the bundle has the
        // full tx) and the validated OpId. Read for the transition types that
        // authorize an EVM action: the type this flow signs on a deposit (see
        // `crate::networks::rgb::flow`) and a burn. The `fundsOut` binds take
        // the burn OpId from here, not from the flat parser.
        let (last_transfer_witness_prevouts, last_transfer_op_id) = match last_transition {
            Some(ref last)
                if crate::networks::rgb::flow::is_signing_transition(last.transition_type)
                    || last.transition_type == bfa::TS_BURN =>
            {
                read_last_transfer_witness(&transfer, last.transition_type)?
            }
            _ => (None, None),
        };

        // The two walks must name the same last transition. The flat parser
        // and the rgbstd walk read the same bytes in the same order, so a
        // mismatch is a parser change or a bug. Refuse, so no bind downstream
        // can mix the fields of two transitions.
        if let (Some(ref last), Some(validated_opid)) = (&last_transition, last_transfer_op_id) {
            let flat_opid = super::bfa::decode_opid(&last.op_id)?;
            if flat_opid != validated_opid {
                return Err(EnclaveError::CrossCheck(format!(
                    "consignment last transition disagrees between the flat parser (0x{}) and \
                     the validated transfer (0x{}) - refusing to sign",
                    hex::encode(flat_opid),
                    hex::encode(validated_opid)
                )));
            }
        }

        // 2. Create the witness resolver. ssl:// or tcp:// selects Electrum,
        //    other schemes select Esplora REST. Production uses Electrum: TLS
        //    ends inside the enclave, so a compromised host cannot forge
        //    witness data. The Esplora `.timeout()` limits a stalled call.
        let is_electrum =
            self.indexer_url.starts_with("ssl://") || self.indexer_url.starts_with("tcp://");
        let mut resolver = if is_electrum {
            // `Config::default()` has `timeout: None`, so a stalled read
            // blocks the worker thread forever (see ELECTRUM_WITNESS_TIMEOUT_SECS).
            // Use this re-export so that `Config` matches
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

        // The resolver treats the consignment txs as tentative (not mined).
        resolver.add_consignment_txes(&transfer);

        // Use the trusted type system from `rgb-schemas`, NOT `transfer.types`.
        // An unknown schema_id fails closed in the helper.
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

        // 4. Run full RGB validation (blocking calls to the indexer).
        tracing::debug!(%contract_id, "calling rgbstd validate (this may block on Esplora)");
        // A BFA mint script ends with `cea`. The plain validator decodes it as
        // `Fail`, so only the ether extension can run it. The schema gate
        // admits only BFA, so no schema branch is necessary.
        #[cfg(feature = "bfa-validation")]
        let validation_result = {
            // Fail closed with a clear reason. `cea` reports an empty event set
            // as an opaque script failure. A mint with no verified lock is unbacked.
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
            // The ValidationError Display drops the Failure, so log the
            // Failure for the operator.
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

        // Warnings only. Witness confirmation does NOT come from `tx_ord_map`.
        // rgb-ops `resolve_witness` sets each consignment tx to
        // `WitnessOrd::Tentative` at any depth, which would reject each fundsOut.
        //
        // RGB->EVM confirmation comes from the in-enclave SPV header chain.
        // `validate_source` requires a Merkle proof for each witness txid at
        // `SPV_MIN_CONFIRMATIONS` depth. `non_mined_witness_txids` stays empty,
        // so the `assert_witnesses_confirmed` call site stays a structural guard.
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
