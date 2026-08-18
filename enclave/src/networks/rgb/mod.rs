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
use crate::proto::{RgbBurnDestination, RgbDestination, RgbInflationDestination, RgbSource};
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
    )?;

    // Fee-rate sanity (#55), after the pure anchor checks so the (cached)
    // Esplora round-trip is the last thing that can reject. Fail-closed when
    // the estimate is unavailable: the host controls the Esplora egress, so
    // "no estimate → skip" would let the host disable the check.
    let recommended = validator.recommended_fee_rate_sat_vb()?;
    psbt_validation::check_psbt_fee_rate(&psbt, recommended)
}

/// Validate fields owned by an RGB inflation (mint) destination before
/// route-level validation. Mirrors [`validate_destination`].
pub fn validate_inflation_destination(
    destination: &RgbInflationDestination,
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

/// The mint counterpart of [`validate_destination_anchor`]: bind the PSBT the
/// enclave is about to sign to the inflation the deposit paid for.
///
/// An inflation ships no consignment - nothing is handed to a counterparty -
/// so its binding evidence is the fascia rgb-lib prepared. Authorisation is
/// the pair: the EVM deposit is verified independently on the source side
/// (`verify_funds_in_event`), and this anchor proves the PSBT finalises an
/// inflation of exactly that deposit's net amount on the pinned asset:
///
/// 1. wire integrity: `keccak256(fascia) == fascia_hash` (integrity, not
///    authorization - the listener controls both, same note as the send path);
/// 2. the fascia parses, names ONE contract, and carries ONLY IFA
///    `TS_INFLATION` transitions (no transfer may ride the mint witness);
/// 3. that contract is the declared asset AND the operator-pinned
///    `RGB_ASSET_ID` (fail closed when unpinned, mirroring the send anchor);
/// 4. the PSBT's unsigned txid IS the fascia's seal witness txid - the
///    signature cannot finalise any other transition;
/// 5. minted `OS_ASSET` units == validated deposit net amount, exactly -
///    the enclave-side twin of the connector's AMOUNT MISMATCH gate;
/// 6. fee-rate sanity, same as the send path.
///
/// Returns the minted amount for the route proof.
#[cfg(feature = "rgb-validation")]
pub fn validate_inflation_anchor(
    destination: &RgbInflationDestination,
    source_amount: u64,
    source_commission: u64,
    ctx: &ValidationContext<'_>,
) -> Result<u64> {
    use crate::error::EnclaveError;

    if destination.fascia.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "mint PSBT signing requires the inflation fascia to bind the PSBT to the RGB \
             transition"
                .into(),
        ));
    }
    if destination.fascia_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "fascia present but fascia_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(&destination.fascia);
    if computed[..] != destination.fascia_hash {
        return Err(EnclaveError::CrossCheck(
            "fascia hash mismatch: keccak256(fascia) != fascia_hash".into(),
        ));
    }
    if destination.asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB inflation destination asset_id is empty".into(),
        ));
    }

    let fascia = validation::validate_inflation_fascia(&destination.fascia)?;

    if fascia.contract_id != destination.asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: fascia inflates {} but the destination declares {}",
            fascia.contract_id, destination.asset_id
        )));
    }
    if ctx.bridge_config.rgb_asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "asset-identity pin missing: RGB_ASSET_ID is not configured - refusing to mint an \
             unpinned asset"
                .into(),
        ));
    }
    if fascia.contract_id != ctx.bridge_config.rgb_asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: fascia inflates {} != pinned RGB_ASSET_ID {}",
            fascia.contract_id, ctx.bridge_config.rgb_asset_id
        )));
    }

    let psbt = bitcoin::psbt::Psbt::deserialize(&destination.psbt_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("psbt_bytes is not a valid PSBT: {e}")))?;
    let psbt_txid = psbt.unsigned_tx.compute_txid();
    if psbt_txid != fascia.witness_txid {
        return Err(EnclaveError::CrossCheck(format!(
            "PSBT/fascia witness mismatch: signing txid {psbt_txid} but the fascia anchors \
             {} - this signature would not finalise the prepared inflation",
            fascia.witness_txid
        )));
    }

    let expected_minted = source_amount
        .checked_sub(source_commission)
        .ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "source commission {source_commission} exceeds deposit amount {source_amount}"
            ))
        })?;
    if fascia.minted_amount != expected_minted {
        return Err(EnclaveError::CrossCheck(format!(
            "MINT AMOUNT MISMATCH: fascia mints {} but the validated deposit nets {} \
             (amount {} - commission {})",
            fascia.minted_amount, expected_minted, source_amount, source_commission
        )));
    }

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "mint PSBT signing requires a configured RGB validator for the fee-rate check".into(),
        )
    })?;
    let recommended = validator.recommended_fee_rate_sat_vb()?;
    psbt_validation::check_psbt_fee_rate(&psbt, recommended)?;

    Ok(fascia.minted_amount)
}

/// Validate fields owned by an RGB burn destination before route-level
/// validation. Mirrors [`validate_inflation_destination`].
pub fn validate_burn_destination(
    destination: &RgbBurnDestination,
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

/// The burn counterpart of [`validate_inflation_anchor`]: bind the PSBT the
/// enclave is about to sign to the bridge's own rebalance burn.
///
/// A burn is SOURCELESS - the bridge destroys its own units, so no deposit
/// and no consignment exist when the signature is requested. Authorisation is
/// therefore structural, carried entirely by the fascia:
///
/// 1. wire integrity: `keccak256(fascia) == fascia_hash`;
/// 2. the fascia parses, names ONE contract, and carries ONLY IFA `TS_BURN`
///    transitions (plus co-located `TS_TRANSFER` change legs, uncounted);
/// 3. that contract is the declared asset AND the operator-pinned
///    `RGB_ASSET_ID` - the signature cannot destroy any other asset;
/// 4. the PSBT's unsigned txid IS the fascia's seal witness txid - the
///    signature cannot finalise any other transition;
/// 5. burned `MS_BURNED_ASSET` units == the declared `burn_amount`, exactly,
///    and zero-burn fascias were already refused in the walk;
/// 6. fee-rate sanity, same as the send and mint paths.
///
/// Returns the burned amount for the route proof.
#[cfg(feature = "rgb-validation")]
pub fn validate_burn_anchor(
    destination: &RgbBurnDestination,
    ctx: &ValidationContext<'_>,
) -> Result<u64> {
    use crate::error::EnclaveError;

    if destination.fascia.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "burn PSBT signing requires the burn fascia to bind the PSBT to the RGB transition"
                .into(),
        ));
    }
    if destination.fascia_hash.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "fascia present but fascia_hash is missing".into(),
        ));
    }
    let computed = Keccak256::digest(&destination.fascia);
    if computed[..] != destination.fascia_hash {
        return Err(EnclaveError::CrossCheck(
            "fascia hash mismatch: keccak256(fascia) != fascia_hash".into(),
        ));
    }
    if destination.asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "RGB burn destination asset_id is empty".into(),
        ));
    }

    let fascia = validation::validate_burn_fascia(&destination.fascia)?;

    if fascia.contract_id != destination.asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: fascia burns {} but the destination declares {}",
            fascia.contract_id, destination.asset_id
        )));
    }
    if ctx.bridge_config.rgb_asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "asset-identity pin missing: RGB_ASSET_ID is not configured - refusing to burn an \
             unpinned asset"
                .into(),
        ));
    }
    if fascia.contract_id != ctx.bridge_config.rgb_asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: fascia burns {} != pinned RGB_ASSET_ID {}",
            fascia.contract_id, ctx.bridge_config.rgb_asset_id
        )));
    }

    let psbt = bitcoin::psbt::Psbt::deserialize(&destination.psbt_bytes)
        .map_err(|e| EnclaveError::CrossCheck(format!("psbt_bytes is not a valid PSBT: {e}")))?;
    let psbt_txid = psbt.unsigned_tx.compute_txid();
    if psbt_txid != fascia.witness_txid {
        return Err(EnclaveError::CrossCheck(format!(
            "PSBT/fascia witness mismatch: signing txid {psbt_txid} but the fascia anchors \
             {} - this signature would not finalise the prepared burn",
            fascia.witness_txid
        )));
    }

    if fascia.burned_amount != destination.burn_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "BURN AMOUNT MISMATCH: fascia burns {} but the request declares {}",
            fascia.burned_amount, destination.burn_amount
        )));
    }

    let validator = ctx.rgb_validator.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "burn PSBT signing requires a configured RGB validator for the fee-rate check".into(),
        )
    })?;
    let recommended = validator.recommended_fee_rate_sat_vb()?;
    psbt_validation::check_psbt_fee_rate(&psbt, recommended)?;

    Ok(fascia.burned_amount)
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

    // =========================================================================
    // Asset-identity binding, DESTINATION path — successor of the dropped
    // `evm_crosscheck::asset_bind` suite (audit TEE-SE-01). Its target,
    // `bind_asset_identity`, was removed in the networks/ split; the legs are
    // now INLINED in `validate_destination_anchor` after
    // `validate_consignment`, so that function is the narrowest callable
    // unit. Driven end-to-end with the in-tree mainnet transfer fixture
    // validated offline against a stub Esplora (the resolver only phones
    // home for the genesis-hash chain-identity check; the fixture embeds its
    // witness txs, registered as tentative via `add_consignment_txes`).
    //
    // Path asymmetry (deliberate): this path enforces the RGB_ASSET_ID pin
    // UNCONDITIONALLY — a post-merge strengthening — whereas the source path
    // (`validation::validate_source`) gates it on
    // `BridgeConfig::is_configured()`; see
    // `validation::tests::asset_bind::pin_check_skipped_when_config_unconfigured`.
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

        /// Fully-empty operator config — no RGB_ASSET_ID pin at all.
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
        /// deliberately garbage `psbt_bytes`: PSBT deserialization runs
        /// strictly AFTER every asset-binding leg, so its distinctive error
        /// is this suite's proof that the binding was traversed (a PSBT
        /// genuinely anchored to the fixture's mainnet witness tx is not
        /// constructible in a unit test).
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
        ) -> Result<()> {
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
            let ctx = ValidationContext {
                bridge_config: config,
                rgb_validator: Some(&validator),
                header_chain: &chain,
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

        /// Old `binds_when_declared_is_empty`, semantics INVERTED by a
        /// deliberate post-merge strengthening: the destination must declare
        /// its asset — an empty `asset_id` fails closed before the validator
        /// even runs, instead of binding via the pin alone. This same
        /// rejection carries the old
        /// `rejects_foreign_asset_even_when_declared_is_empty` guarantee:
        /// with an empty declared id *nothing* binds, foreign or not.
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

        /// Old `rejects_foreign_asset_even_when_declared_is_empty`, adapted:
        /// empty declarations are rejected up-front (previous test), so the
        /// closest reachable form of the TEE-SE-01 funds-theft path is a
        /// listener that *colludes* — declaring the foreign asset
        /// consistently with the consignment. The pin must still reject it:
        /// RGB_ASSET_ID is load-bearing regardless of what the listener says.
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

        /// Old `rejects_when_pin_absent` — semantics carry, STRENGTHENED:
        /// this path fails closed on a missing RGB_ASSET_ID pin
        /// UNCONDITIONALLY (no `is_configured()` gate), a deliberate
        /// post-merge hardening. An rgb-validation-enabled enclave with no
        /// pin must not sign a send-RGB PSBT in listener-trusting mode.
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

        /// Old `rejects_when_declared_disagrees_with_validated`: the listener
        /// declares a different asset than the validated identity. Fires on
        /// the declared-vs-validated leg (which runs before the pin block).
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

        // Old `rejects_when_contract_id_absent`: NOT portable to this path.
        // This path has no explicit empty-contract_id guard; the property is
        // enforced structurally instead — `asset_id` must be non-empty and
        // equal the validated contract_id, so an empty validated identity can
        // never bind. It is also unreachable through the narrowest callable
        // unit: `RgbValidator::validate_consignment` derives contract_id from
        // the consignment's genesis (never empty for a loadable Transfer) and
        // `ValidationContext.rgb_validator` is the concrete type, so no
        // fabricated ValidatedConsignment can be injected. Recorded as
        // not-feasible in the restoration report. The source path keeps an
        // explicit (equally unreachable) guard — see
        // `validation::validate_source`.
    }
}
