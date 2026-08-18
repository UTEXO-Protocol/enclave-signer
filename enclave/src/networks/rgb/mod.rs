pub mod btc_crosscheck;
pub mod btc_ownership;
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

/// Returns the **recipient leg** of the bound consignment in asset units - see
/// [`psbt_validation::validate_psbt_anchors_transition`]. This is the
/// enclave-derived destination amount the route-level cross-check uses, in
/// place of the host-supplied `psbt_output_amount` (W-06 / #52).
#[cfg(feature = "rgb-validation")]
pub fn validate_destination_anchor(
    destination: &RgbDestination,
    source_amount: u64,
    source_commission: u64,
    ctx: &ValidationContext<'_>,
) -> Result<u64> {
    use crate::error::EnclaveError;

    if destination.consignment.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "send-RGB PSBT signing requires a consignment to bind the PSBT to the RGB transition"
                .into(),
        ));
    }
    // Aggregate size cap (operator-configurable via `MAX_CONSIGNMENT_BYTES`),
    // before the keccak hash and the rgbstd parse below - the destination
    // consignment is otherwise bounded only by the generic 4 MB wire frame.
    if destination.consignment.len() > ctx.bridge_config.max_consignment_bytes {
        return Err(EnclaveError::CrossCheck(format!(
            "send-RGB consignment too large: {} bytes (max {})",
            destination.consignment.len(),
            ctx.bridge_config.max_consignment_bytes
        )));
    }
    // Integrity, not authorization (audit I-02 / Oxorio I-09): the listener
    // controls both `consignment` and `consignment_hash`, so a match only
    // proves the wire copy is intact. Authorization is the rgbstd validation
    // plus the witness-txid bind below.
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
    // Asset-identity pin (audit TEE-SE-01), fail-closed when RGB_ASSET_ID is
    // unset: an unconfigured yet rgb-validation-enabled enclave must not sign in
    // listener-trusting mode. Mirrors the EVM funds-out `!is_configured()` gate.
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
    // Fail closed: the per-output recipient bind (W-06 / #52) needs to tell a
    // bridge change output from a payout, and it cannot do that without the
    // enclave's own keys. No resolver means no bind, so refuse to sign.
    let self_owned = ctx.self_owned_psbt_outputs.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "send-RGB PSBT cannot be bound: no self-owned-output resolver is wired in, so the \
             enclave cannot distinguish bridge change from a payout to a third party"
                .into(),
        )
    })?;
    let recipient_amount = psbt_validation::validate_psbt_anchors_transition(
        &psbt,
        &validated,
        source_amount,
        source_commission,
        self_owned,
    )?;

    // Fee-rate sanity (#55), after the pure anchor checks so the cached Esplora
    // round-trip is the last thing that can reject. Fail-closed when the
    // estimate is unavailable, since the host controls that egress.
    let recommended = validator.recommended_fee_rate_sat_vb()?;
    psbt_validation::check_psbt_fee_rate(&psbt, recommended)?;

    Ok(recipient_amount)
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
            // These cases never reach the PSBT bind (garbage `psbt_bytes`).
            transitions_by_witness: vec![],
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

    // =========================================================================
    // Asset-identity binding, destination path (audit TEE-SE-01). The legs are
    // inlined in `validate_destination_anchor` after `validate_consignment`, so
    // that function is the narrowest callable unit. Driven end-to-end with the
    // in-tree mainnet transfer fixture against a stub Esplora.
    //
    // Deliberate asymmetry: this path enforces the RGB_ASSET_ID pin
    // unconditionally, while the source path gates it on
    // `BridgeConfig::is_configured()`.
    // =========================================================================

    mod asset_bind {
        use super::*;
        use crate::config::BridgeConfig;
        use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
        use crate::networks::rgb::validation::RgbValidator;
        use rgbstd::containers::{ConsignmentExt, FileContent, Transfer};
        use std::io::Cursor;
        use std::sync::Mutex;

        const TRANSFER_FIXTURE: &[u8] =
            include_bytes!("../../../tests/fixtures/transfer_consignment.rgbc");

        /// Contract id of `TRANSFER_FIXTURE`. Kept as a literal (the old
        /// suite's `PIN`), re-derived and asserted in [`fixture_asset_id`] so
        /// a fixture swap fails loud instead of silently retargeting every
        /// binding test.
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

        /// Fully-empty operator config - no RGB_ASSET_ID pin at all.
        fn unconfigured_config() -> BridgeConfig {
            BridgeConfig {
                chain_id: 0,
                bridge_contract: [0u8; 20],
                rgb_asset_id: String::new(),
                gas_tx_allowed_to: None,
                ..Default::default()
            }
        }

        /// A destination around the fixture consignment, hash-bound, with
        /// deliberately garbage `psbt_bytes`. PSBT deserialization runs after
        /// every asset-binding leg, so its distinctive error proves the binding
        /// was traversed.
        fn fixture_destination(asset_id: &str) -> RgbDestination {
            RgbDestination {
                operation_idx: 0,
                psbt_bytes: b"not-a-psbt".to_vec(),
                psbt_output_amount: 0,
                asset_id: asset_id.into(),
                consignment: TRANSFER_FIXTURE.to_vec(),
                consignment_hash: Keccak256::digest(TRANSFER_FIXTURE).to_vec(),
            }
        }

        /// Drive `validate_destination_anchor` (the unit the binding is
        /// inlined in) with a stub-Esplora validator.
        fn run_validate_destination_anchor(
            destination: &RgbDestination,
            config: &BridgeConfig,
        ) -> Result<u64> {
            let url = spawn_stub_esplora();
            let validator = RgbValidator::new(url, "bitcoin").expect("validator");
            let chain = Mutex::new(HeaderChain::new(
                Network::Mainnet,
                Checkpoint {
                    height: 0,
                    hash: [0u8; 32],
                    bits: 0x1d00_ffff,
                    time: 1_700_000_000,
                    is_real: false,
                },
            ));
            // Every case in this suite fails before the PSBT stage (the
            // fixture's `psbt_bytes` are deliberately garbage), so the
            // resolver is never called - but it must be present, or the
            // fail-closed guard would mask the error each test asserts on.
            let self_owned = |_: &bitcoin::psbt::Psbt| Ok(std::collections::HashSet::new());
            let ctx = ValidationContext {
                bridge_config: config,
                rgb_validator: Some(&validator),
                header_chain: &chain,
                self_owned_psbt_outputs: Some(&self_owned),
            };
            validate_destination_anchor(destination, 0, 0, &ctx)
        }

        /// Happy path (old `binds_when_contract_id_matches_pin`): validated
        /// contract_id == declared asset_id == pinned RGB_ASSET_ID. Every
        /// binding leg passes and validation proceeds to the PSBT stage.
        #[test]
        fn binds_when_contract_id_matches_pin() {
            let id = fixture_asset_id();
            let err =
                run_validate_destination_anchor(&fixture_destination(&id), &pinned_config(&id))
                    .unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("psbt_bytes is not a valid PSBT"),
                "expected to reach the PSBT stage past asset binding, got: {msg}"
            );
            assert!(
                !msg.contains("contract_id mismatch") && !msg.contains("RGB_ASSET_ID"),
                "asset binding must have passed, got: {msg}"
            );
        }

        /// The destination must declare its asset: an empty `asset_id` fails
        /// closed before the validator runs, rather than binding via the pin
        /// alone. With an empty declared id nothing binds, foreign or not.
        #[test]
        fn rejects_when_declared_is_empty() {
            let err = run_validate_destination_anchor(
                &fixture_destination(""),
                &pinned_config(FIXTURE_ASSET_ID),
            )
            .unwrap_err();
            assert!(
                err.to_string()
                    .contains("RGB destination asset_id is empty"),
                "expected empty-declared rejection, got: {err}"
            );
        }

        /// Empty declarations are rejected up-front, so the reachable form of
        /// the TEE-SE-01 funds-theft path is a listener that declares the
        /// foreign asset consistently with the consignment. The RGB_ASSET_ID
        /// pin must still reject it.
        #[test]
        fn rejects_foreign_asset_even_when_declared_agrees() {
            let id = fixture_asset_id();
            let err = run_validate_destination_anchor(
                &fixture_destination(&id),
                &pinned_config("rgb:some-other-pinned-asset"),
            )
            .unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("contract_id mismatch") && msg.contains("pinned RGB_ASSET_ID"),
                "expected pin mismatch, got: {msg}"
            );
        }

        /// This path fails closed on a missing RGB_ASSET_ID pin
        /// unconditionally, with no `is_configured()` gate: an
        /// rgb-validation-enabled enclave with no pin must not sign a send-RGB
        /// PSBT in listener-trusting mode.
        #[test]
        fn rejects_when_pin_absent() {
            let id = fixture_asset_id();
            let err =
                run_validate_destination_anchor(&fixture_destination(&id), &unconfigured_config())
                    .unwrap_err();
            assert!(
                err.to_string().contains("asset-identity pin missing"),
                "expected pin-missing rejection, got: {err}"
            );
        }

        /// The listener declares a different asset than the validated
        /// identity. Fires on the declared-vs-validated leg, before the pin.
        #[test]
        fn rejects_when_declared_disagrees_with_validated() {
            let err = run_validate_destination_anchor(
                &fixture_destination("rgb:listener-lied"),
                &pinned_config(FIXTURE_ASSET_ID),
            )
            .unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("contract_id mismatch") && msg.contains("RGB destination declares"),
                "expected declared-mismatch rejection, got: {msg}"
            );
        }

        // An absent contract_id has no explicit guard on this path: the
        // property is structural, since `asset_id` must be non-empty and equal
        // the validated contract_id. It is also unreachable through the
        // narrowest callable unit, because `validate_consignment` derives
        // contract_id from the consignment's genesis and no fabricated
        // ValidatedConsignment can be injected. The source path keeps an
        // explicit (equally unreachable) guard.
    }
}
