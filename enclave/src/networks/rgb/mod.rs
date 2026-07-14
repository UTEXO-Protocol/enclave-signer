pub mod btc_crosscheck;
pub mod psbt_validation;
pub mod signing;
pub mod spv;
#[cfg(feature = "spv")]
pub mod spv_validation;
#[cfg(feature = "rgb-validation")]
pub mod validation;

#[cfg(not(feature = "rgb-validation"))]
use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::{RouteProof, ValidationContext};
use crate::proto::{RgbDestination, RgbSource};
#[cfg(feature = "rgb-validation")]
use sha3::{Digest, Keccak256};

fn dev_mode_bypass() -> bool {
    cfg!(all(feature = "dev-mode", not(test)))
}

/// Dispatch RGB source validation to the implementation enabled for this build.
///
/// `mod.rs` owns module wiring only. Field-level checks, consignment
/// validation, asset binding, and SPV verification live in `validation.rs`
/// when `rgb-validation` is enabled.
pub fn validate_source(
    amount: u64,
    source: &RgbSource,
    ctx: &ValidationContext<'_>,
) -> Result<crate::networks::SourceProof> {
    use crate::networks::SourceProof;

    if dev_mode_bypass() {
        let _ = source;
        let _ = ctx;
        return Ok(SourceProof {
            proof: RouteProof {
                amount,
                operation_id: None,
            },
            #[cfg(feature = "rgb-validation")]
            rgb_consignment: None,
        });
    }

    #[cfg(feature = "rgb-validation")]
    {
        let validated = validation::validate_source(source, ctx)?;
        let proof = route_proof_from_validated_consignment(&validated)?;
        Ok(SourceProof {
            proof,
            rgb_consignment: Some(validated),
        })
    }

    #[cfg(not(feature = "rgb-validation"))]
    {
        let _ = amount;
        let _ = source;
        let _ = ctx;
        Err(EnclaveError::CrossCheck(
            "RGB source validation requires the enclave to be built with --features rgb-validation"
                .into(),
        ))
    }
}

#[cfg(feature = "rgb-validation")]
fn route_proof_from_validated_consignment(
    validated: &validation::ValidatedConsignment,
) -> Result<RouteProof> {
    use crate::error::EnclaveError;
    use validation::ifa;

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "RGB source requires a consignment with at least one transition".into(),
        )
    })?;

    let amount = match last.transition_type {
        ifa::TS_TRANSFER => last.total_output_amount,
        ifa::TS_BURN => last.burned_asset_amount.ok_or_else(|| {
            EnclaveError::CrossCheck(
                "burn transition is missing MS_BURNED_ASSET metadata — cannot validate amount"
                    .into(),
            )
        })?,
        other => {
            return Err(EnclaveError::CrossCheck(format!(
                "unsupported RGB transition_type for route proof: {other}"
            )));
        }
    };

    Ok(RouteProof {
        amount,
        operation_id: Some(normalize_rgb_operation_id(&last.op_id)?),
    })
}

#[cfg(feature = "rgb-validation")]
fn normalize_rgb_operation_id(op_id: &str) -> Result<String> {
    use crate::error::EnclaveError;

    let normalized = op_id.strip_prefix("0x").unwrap_or(op_id);
    if normalized.len() != 64 {
        return Err(EnclaveError::CrossCheck(format!(
            "RGB operation_id must be 32-byte hex, got {} hex chars",
            normalized.len()
        )));
    }
    if !normalized.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(EnclaveError::CrossCheck(
            "RGB operation_id is not hex-decodable".into(),
        ));
    }

    Ok(normalized.to_ascii_lowercase())
}

/// Validate fields owned by an RGB destination before route-level validation.
pub fn validate_destination(
    destination: &RgbDestination,
    _ctx: &ValidationContext<'_>,
) -> Result<()> {
    #[cfg(not(feature = "dev-mode"))]
    {
        psbt_validation::validate_psbt_bytes(&destination.psbt_bytes)?;
    }
    #[cfg(feature = "dev-mode")]
    let _ = destination;

    Ok(())
}

#[cfg(feature = "rgb-validation")]
pub fn validate_destination_anchor(
    destination: &RgbDestination,
    source_amount: u64,
    source_commission: u64,
    ctx: &ValidationContext<'_>,
) -> Result<()> {
    use crate::error::EnclaveError;

    if destination.consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "send-RGB PSBT signing requires a consignment to bind the PSBT to the RGB transition"
                .into(),
        ));
    }
    // Wire-tamper detection, mirroring the EVM path's defence-in-depth check.
    // INTEGRITY, NOT AUTHORIZATION (audit I-02 / Oxorio I-09): the listener
    // controls both `consignment` and `consignment_hash`, so a match only
    // proves the wire copy is intact - authorization is the full rgbstd
    // validation + witness-txid bind below, never this hash.
    if destination.consignment_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "consignment present but consignment_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(&destination.consignment);
    if computed[..] != destination.consignment_hash {
        return Err(EnclaveError::CrossCheck(
            "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
        ));
    }
    if destination.asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB destination asset_id is empty".into(),
        ));
    }

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT carries a consignment but the RGB validator is not configured".into(),
        )
    })?;
    let validated = validator.validate_consignment(&destination.consignment)?;

    if validated.contract_id != destination.asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: consignment has {} but RGB destination declares {}",
            validated.contract_id, destination.asset_id
        )));
    }
    // Asset-identity pin (audit TEE-SE-01). Fail closed when RGB_ASSET_ID is not
    // pinned: dev-ng refused to bind a send-RGB PSBT to an unpinned asset in
    // every non-dev-mode build (this function is already dev-mode-gated at the
    // dispatch), mirroring the EVM funds-out path's `!is_configured()` gate. An
    // unconfigured yet rgb-validation-enabled enclave must not sign in
    // listener-trusting mode.
    if ctx.bridge_config.rgb_asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "asset-identity pin missing: RGB_ASSET_ID is not configured — refusing to bind a \
             send-RGB PSBT to an unpinned asset"
                .into(),
        ));
    }
    if validated.contract_id != ctx.bridge_config.rgb_asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: consignment asset {} != pinned RGB_ASSET_ID {}",
            validated.contract_id, ctx.bridge_config.rgb_asset_id
        )));
    }

    let psbt = bitcoin::psbt::Psbt::deserialize(&destination.psbt_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("psbt_bytes is not a valid PSBT: {e}")))?;
    psbt_validation::validate_psbt_anchors_transition(
        &psbt,
        &validated,
        source_amount,
        source_commission,
    )
}

#[cfg(all(test, feature = "rgb-validation"))]
mod tests {
    use super::*;
    use validation::{ifa, TransitionSummary, ValidatedConsignment};

    fn validated_consignment(
        transition_type: u16,
        total_output_amount: u64,
        burned_asset_amount: Option<u64>,
        op_id: &str,
    ) -> ValidatedConsignment {
        ValidatedConsignment {
            contract_id: "rgb:test-asset".into(),
            chain_net: "bc:regtest".into(),
            witness_txids: vec![],
            all_op_ids: vec![op_id.into()],
            mint_op_ids: vec![],
            last_transition: Some(TransitionSummary {
                op_id: op_id.into(),
                transition_type,
                total_output_amount,
                asset_output_amount: total_output_amount,
                outputs: vec![],
                burned_asset_amount,
            }),
            last_transfer_witness_txid: None,
            last_transfer_witness_prevouts: None,
            last_transfer_op_id: None,
            non_mined_witness_txids: vec![],
        }
    }

    #[test]
    fn route_proof_uses_transfer_output_amount() {
        let op_id = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let proof = route_proof_from_validated_consignment(&validated_consignment(
            ifa::TS_TRANSFER,
            1_500,
            None,
            op_id,
        ))
        .unwrap();

        assert_eq!(proof.amount, 1_500);
        assert_eq!(
            proof.operation_id.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn route_proof_uses_burn_metadata_amount() {
        let op_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let proof = route_proof_from_validated_consignment(&validated_consignment(
            ifa::TS_BURN,
            0,
            Some(700),
            op_id,
        ))
        .unwrap();

        assert_eq!(proof.amount, 700);
        assert_eq!(proof.operation_id.as_deref(), Some(op_id));
    }

    #[test]
    fn route_proof_rejects_burn_without_burned_amount() {
        let err = route_proof_from_validated_consignment(&validated_consignment(
            ifa::TS_BURN,
            0,
            None,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ))
        .unwrap_err();

        assert!(err.to_string().contains("burn transition is missing"));
    }

    #[test]
    fn route_proof_rejects_non_hex_operation_id() {
        let err = route_proof_from_validated_consignment(&validated_consignment(
            ifa::TS_TRANSFER,
            100,
            None,
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ))
        .unwrap_err();

        assert!(err.to_string().contains("not hex-decodable"));
    }
}
