#[cfg(feature = "rgb-validation")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "rgb-validation")]
use sha3::{Digest, Keccak256};

use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::proto::SignEvmRequest;
#[cfg(feature = "rgb-validation")]
use crate::validation::rgb::{ifa, ValidatedConsignment};

/// `keccak256("fundsOut(address,uint256,uint256,uint256,uint256,string,bytes,bytes)")[0..4]`.
///
/// The deployed `Bridge` contract (`utexo-smart-contracts/dev`, route-plugin
/// refactor) exposes a **single** `fundsOut`. The pre-refactor 6-arg
/// `fundsOut(address,address,uint256,uint256,string,string)` (`0x1ad880b2`)
/// no longer exists. Both the pools/transfer flow (live now) and the
/// future mint/burn unlock flow go through this one selector — they are
/// deployed as separate `Bridge` instances and disambiguated by
/// **contract address**, not by selector.
///
/// Layout:
/// `[4 selector][32 recipient][32 amount][32 burnId][32 sourceChainId][32 destinationChainId][32 srcAddrOffset][32 proofOffset][32 settlementDataOffset]...`.
/// `proof = abi.encode(uint256 blockHeight, bytes32 commitmentHash)` and
/// `settlementData = abi.encode(uint256[] fundsInIds)` (mint/burn only).
pub const FUNDS_OUT_SELECTOR_POOLS: [u8; 4] = [0xcc, 0xdd, 0xb7, 0x68];

/// 4-byte function selectors the enclave is willing to sign `fundsOut`
/// calldata for. Anything else is rejected up-front before any byte-level
/// extraction runs.
///
/// One entry today — the contract has a single `fundsOut`. The handler
/// routes it to [`validate_funds_out_transfer`] (the live pools flow).
/// Mint/burn unlock validation ([`validate_funds_out_burn`]) is not wired
/// yet; it lands in the mint/burn epic, dispatched by contract address.
const FUNDS_OUT_SELECTORS: &[[u8; 4]] = &[FUNDS_OUT_SELECTOR_POOLS];

/// Byte offset of `amount` in the `fundsOut` calldata. After the 4-byte
/// selector and the 32-byte `recipient` head slot, `amount` (uint256)
/// sits at byte 36..68. Shared by the transfer and (future) burn paths
/// since both use the same ABI.
///
/// Only consumed by the cross-check helpers behind `rgb-validation`;
/// gate the const the same way so default builds don't warn.
#[cfg(feature = "rgb-validation")]
const FUNDS_OUT_AMOUNT_OFFSET: usize = 36;

/// Validate enriched SignEvmRequest before signing.
/// Returns Ok(()) if all cross-checks pass, Err(EnclaveError::CrossCheck) if any fail.
///
/// When `bridge_config.is_configured()` is true, the request's `chain_id`,
/// `proxy_contract`, and `rgb_asset_id` are pinned: any mismatch fails
/// closed. This is the production posture and the reason these fields are
/// bound into the attestation `user_data` commitment — a compromised
/// listener cannot redirect signatures to a different chain or contract.
/// When unconfigured (dev / mock builds with no env), the legacy "trust
/// the request" behaviour kicks in so existing tests and ad-hoc setups
/// keep working.
pub fn validate_evm_request(req: &SignEvmRequest, bridge_config: &BridgeConfig) -> Result<()> {
    // 0. Selector whitelist. Fail-closed before any offset extraction:
    //    every other byte-level check in this function assumes calldata is
    //    a known `fundsOut` shape. A listener that swapped the selector
    //    (e.g. to `transfer(address,uint256)`) would otherwise pass the
    //    later amount-at-offset-68 check on bytes that mean something else
    //    entirely.
    if req.call_data.len() < 4 {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need at least 4 bytes for selector, got {}",
            req.call_data.len()
        )));
    }
    let selector: [u8; 4] = req.call_data[..4]
        .try_into()
        .expect("4-byte slice always converts");
    if !FUNDS_OUT_SELECTORS.contains(&selector) {
        return Err(EnclaveError::CrossCheck(format!(
            "unexpected calldata selector 0x{}: not in fundsOut whitelist",
            hex::encode(selector)
        )));
    }

    // 1. Consignment requirement for fundsOut.
    //    fundsOut signatures release funds; they must be backed by an
    //    RGB consignment that this enclave has validated itself. The
    //    listener-supplied `consignment_valid` boolean is not authoritative —
    //    anyone who can reach the enclave can set it — so we ignore it
    //    here and enforce the only thing we can verify in this scope:
    //    raw bytes are present. The handler enforces the matching
    //    "validator ran successfully" half.
    //
    //    Default builds (no `rgb-validation`) cannot validate at all, so
    //    they refuse to sign fundsOut outright. Production / CI builds
    //    use `--features rgb-validation,spv` and run the full block below.
    #[cfg(not(feature = "rgb-validation"))]
    {
        let _ = selector;
        let _ = bridge_config;
        Err(EnclaveError::CrossCheck(
            "fundsOut signing requires the enclave to be built with --features rgb-validation"
                .into(),
        ))
    }

    #[cfg(feature = "rgb-validation")]
    {
        if req.consignment.is_empty() {
            return Err(EnclaveError::CrossCheck(
                "fundsOut signing requires raw consignment bytes — refusing to trust \
                 host-supplied consignment_valid flag"
                    .into(),
            ));
        }

        // 1b. Hash integrity check between listener-supplied bytes and the
        //     pre-computed keccak. Full RGB validation
        //     (`rgbstd::Transfer::validate` against an Esplora resolver)
        //     happens in `handle_sign_evm` before this function runs; the
        //     hash check is the defence-in-depth tamper detection on the
        //     wire copy.
        if req.consignment_hash.is_empty() {
            return Err(EnclaveError::CrossCheck(
                "consignment present but consignment_hash is missing".into(),
            ));
        }
        let computed = Keccak256::digest(&req.consignment);
        if &computed[..] != req.consignment_hash.as_slice() {
            return Err(EnclaveError::CrossCheck(
                "consignment hash mismatch: keccak256(consignment) != consignment_hash".into(),
            ));
        }

        // 2 + 3. Amount binding to the consignment is done in
        //    `validate_funds_out_transfer` (called from the handler):
        //    it reads `amount` from calldata at FUNDS_OUT_AMOUNT_OFFSET
        //    and binds it to the validated transfer's output value. The
        //    contract's `fundsOut` carries no commission slot (commission
        //    is taken on-chain by `CommissionManager`), so there is no
        //    commission to cross-check here, and we don't trust the
        //    listener-supplied `rgb_amount`/`calldata_*` fields for the
        //    amount decision — the consignment is authoritative.

        // 4. Chain/domain present
        if req.chain_id == 0 {
            return Err(EnclaveError::CrossCheck("chain_id must be > 0".into()));
        }
        if req.proxy_contract.len() != 20 {
            return Err(EnclaveError::CrossCheck(format!(
                "proxy_contract must be 20 bytes, got {}",
                req.proxy_contract.len()
            )));
        }

        // 4a. Fail-closed when unconfigured (audit TEE-SE-12). A build that
        //     can validate consignments (rgb-validation enabled — this whole
        //     block) must refuse to sign when the operator pinned nothing:
        //     otherwise a misprovisioned-but-running enclave silently degrades
        //     to the pre-pin, listener-trusting model. The escape hatch is
        //     intentionally narrow: dev-mode skips this function entirely (see
        //     `handle_sign_evm`), and the library unit tests (`cfg(test)`) keep
        //     exercising the legacy unconfigured path. Integration tests pin a
        //     config explicitly via `start_test_server_with_config`.
        #[cfg(not(test))]
        if !bridge_config.is_configured() {
            return Err(EnclaveError::CrossCheck(
                "bridge config unconfigured: set EVM_CHAIN_ID / BRIDGE_CONTRACT / RGB_ASSET_ID \
                 — refusing to sign in listener-trusting mode"
                    .into(),
            ));
        }

        // 4b. Pinned-config cross-check. When the operator configured
        //     EVM_CHAIN_ID / BRIDGE_CONTRACT / RGB_ASSET_ID at boot, the
        //     listener-supplied values MUST match — otherwise a compromised
        //     listener could redirect signatures to a different chain or
        //     contract. The same values are committed into the attestation
        //     `user_data` so an external verifier can confirm what this
        //     enclave is provisioned for.
        if bridge_config.is_configured() {
            if req.chain_id != bridge_config.chain_id {
                return Err(EnclaveError::CrossCheck(format!(
                    "chain_id mismatch: request {} != pinned {}",
                    req.chain_id, bridge_config.chain_id
                )));
            }
            if req.proxy_contract.as_slice() != bridge_config.bridge_contract {
                return Err(EnclaveError::CrossCheck(format!(
                    "proxy_contract mismatch: request {} != pinned {}",
                    hex::encode(&req.proxy_contract),
                    hex::encode(bridge_config.bridge_contract)
                )));
            }
            // rgb_asset_id is optional on the request only when the listener
            // sends nothing (legacy path). Once a request declares an asset,
            // it must match the pin. The pin itself is always required when
            // configured — if the operator pinned chain/contract but left
            // RGB_ASSET_ID unset, the bridge cannot identify the asset and
            // we'd be back to trusting the listener.
            if bridge_config.rgb_asset_id.is_empty() {
                return Err(EnclaveError::CrossCheck(
                    "bridge config pinned chain/contract but RGB_ASSET_ID is empty — \
                     set all three env vars or none"
                        .into(),
                ));
            }
            if !req.rgb_asset_id.is_empty() && req.rgb_asset_id != bridge_config.rgb_asset_id {
                return Err(EnclaveError::CrossCheck(format!(
                    "rgb_asset_id mismatch: request {} != pinned {}",
                    req.rgb_asset_id, bridge_config.rgb_asset_id
                )));
            }
        }

        // 5. Deadline not expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| EnclaveError::Internal(format!("system time error: {}", e)))?
            .as_secs();
        if req.deadline <= now {
            return Err(EnclaveError::CrossCheck("request deadline expired".into()));
        }

        Ok(())
    }
}

/// Asset-identity binding (audit TEE-SE-01).
///
/// The in-enclave RGB validator derives `contract_id` from the
/// consignment's genesis — it is the authoritative asset identity, not
/// anything the listener declares. This binds that identity to the
/// operator-pinned `RGB_ASSET_ID` and **fails closed when either side is
/// absent**: without both, the enclave cannot prove the consignment is
/// against the bridge's own asset, so a foreign-asset burn could otherwise
/// authorise a USDT0 unlock (the listener-triggerable funds-theft path the
/// finding describes).
///
/// `declared_rgb_asset_id` is the listener-supplied `req.rgb_asset_id`:
/// advisory only. When present it must agree with the validated identity,
/// but — unlike the previous check — an *empty* declared value no longer
/// short-circuits the binding. The pin and the validated `contract_id` are
/// what authorise the unlock.
#[cfg(feature = "rgb-validation")]
pub fn bind_asset_identity(
    validated_contract_id: &str,
    declared_rgb_asset_id: &str,
    pinned_rgb_asset_id: &str,
) -> Result<()> {
    if pinned_rgb_asset_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "asset-identity pin missing: RGB_ASSET_ID is not configured — refusing to bind \
             consignment to an unknown asset"
                .into(),
        ));
    }
    if validated_contract_id.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "validated consignment has empty contract_id — cannot bind asset identity".into(),
        ));
    }
    if validated_contract_id != pinned_rgb_asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: consignment asset {} != pinned RGB_ASSET_ID {}",
            validated_contract_id, pinned_rgb_asset_id
        )));
    }
    // Defence-in-depth: when the listener declares an asset it must agree
    // with the validated identity. Never load-bearing on its own.
    if !declared_rgb_asset_id.is_empty() && validated_contract_id != declared_rgb_asset_id {
        return Err(EnclaveError::CrossCheck(format!(
            "contract_id mismatch: consignment has {} but request declares {}",
            validated_contract_id, declared_rgb_asset_id
        )));
    }
    Ok(())
}

/// Mint/burn-side amount cross-check for the unlock flow.
///
/// **Not wired into the handler yet.** The contract exposes a single
/// `fundsOut` selector ([`FUNDS_OUT_SELECTOR_POOLS`]) shared by the
/// pools/transfer flow (live) and the mint/burn unlock flow (future),
/// disambiguated by **contract address**. Until the mint/burn `Bridge`
/// deployment exists and the handler routes to it by address, the
/// handler sends this selector to [`validate_funds_out_transfer`] only,
/// so a burn consignment is rejected there ("requires a Transfer
/// transition"). This function is kept (and tested) so the unlock-side
/// logic is ready to wire in the mint/burn epic (issues #57 / #59 / #66).
///
/// Enforces the bridge-spec §8 invariant: an unlock can only release at
/// most as many EVM units as the RGB side actually destroyed. Concretely:
///
///   1. The consignment's most recent transition must be an IFA `Burn`
///      (`transition_type == ifa::TS_BURN`).
///   2. The burn transition must carry an `MS_BURNED_ASSET` metadata
///      value (the destroyed amount). rgbstd validation rejects burns
///      with no such metadata, so reaching this branch with `None`
///      indicates a schema mismatch.
///   3. The calldata's `amount` (at [`FUNDS_OUT_AMOUNT_OFFSET`]) must be
///      ≤ the burned amount. Equal is fine; over is the attack we block.
///
/// A no-op for any other selector.
#[cfg(feature = "rgb-validation")]
pub fn validate_funds_out_burn(
    req: &SignEvmRequest,
    validated: &ValidatedConsignment,
) -> Result<()> {
    if req.call_data.len() < 4 || req.call_data[..4] != FUNDS_OUT_SELECTOR_POOLS {
        return Ok(());
    }

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "mint/burn fundsOut requires a consignment with at least one transition".into(),
        )
    })?;
    if last.transition_type != ifa::TS_BURN {
        return Err(EnclaveError::CrossCheck(format!(
            "mint/burn fundsOut requires a Burn transition (last transition_type = {}, want {})",
            last.transition_type,
            ifa::TS_BURN
        )));
    }
    let burned = last.burned_asset_amount.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "burn transition is missing MS_BURNED_ASSET metadata — cannot validate amount".into(),
        )
    })?;

    let calldata_amount = extract_uint256_as_u64(&req.call_data, FUNDS_OUT_AMOUNT_OFFSET)?;
    if burned < calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "burn amount mismatch: burned ({}) < calldata amount ({})",
            burned, calldata_amount
        )));
    }
    Ok(())
}

/// Pools-side amount cross-check for the `fundsOut` transfer flow
/// (selector [`FUNDS_OUT_SELECTOR_POOLS`]).
///
/// Binds the calldata `amount` to the consignment's actual asset value,
/// closing the host-supplied trust gap that a byte-level check in
/// [`validate_evm_request`] cannot catch on its own. Concretely:
///
///   1. The consignment's most recent transition must be an IFA
///      `Transfer` (`transition_type == ifa::TS_TRANSFER`). Pools-mode
///      `fundsOut` releases funds against a federation-bound transfer;
///      any other shape (e.g. a burn) on this selector means a
///      consignment that doesn't authorise a pools release — and, until
///      the mint/burn flow is wired by contract address, that includes
///      rejecting burn consignments outright.
///   2. The transition's `total_output_amount` (sum across recipient
///      and change legs) must cover the EVM-side release `amount`. This
///      is a coarse binding — it doesn't yet verify which output landed
///      on the federation seal (issue #58) — but with the SPV +
///      contract_id pins it raises the bar to "attacker must have a
///      real, confirmed RGB transfer to the bridge for ≥ the withdrawal
///      amount" rather than "attacker sets a field on the wire."
///
/// The contract's `fundsOut` carries no commission slot (commission is
/// taken on-chain by `CommissionManager`), so only `amount` is checked.
///
/// A no-op for any other selector — same dispatch convention as
/// [`validate_funds_out_burn`].
#[cfg(feature = "rgb-validation")]
pub fn validate_funds_out_transfer(
    req: &SignEvmRequest,
    validated: &ValidatedConsignment,
) -> Result<()> {
    if req.call_data.len() < 4 || req.call_data[..4] != FUNDS_OUT_SELECTOR_POOLS {
        return Ok(());
    }

    let last = validated.last_transition.as_ref().ok_or_else(|| {
        EnclaveError::CrossCheck(
            "pools fundsOut requires a consignment with at least one transition".into(),
        )
    })?;
    if last.transition_type != ifa::TS_TRANSFER {
        return Err(EnclaveError::CrossCheck(format!(
            "pools fundsOut requires a Transfer transition (last transition_type = {}, want {})",
            last.transition_type,
            ifa::TS_TRANSFER
        )));
    }

    // Read `amount` straight from the calldata bytes rather than
    // trusting `req.calldata_amount`, then bind it to the consignment's
    // output value — the consignment is the authority on how much RGB
    // actually moved to the bridge.
    let calldata_amount = extract_uint256_as_u64(&req.call_data, FUNDS_OUT_AMOUNT_OFFSET)?;

    if last.total_output_amount < calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "transfer amount mismatch: consignment total_output_amount ({}) < calldata amount ({})",
            last.total_output_amount, calldata_amount
        )));
    }
    Ok(())
}

/// Lightweight ABI extraction: read a uint256 from call_data at a given byte offset.
/// Returns the value as u64. Fails if call_data is too short or the value exceeds u64.
///
/// Only called from cross-check paths that are themselves gated on
/// `rgb-validation`; the `test` cfg keeps it available for the
/// helper's own unit tests in default builds.
#[cfg(any(feature = "rgb-validation", test))]
fn extract_uint256_as_u64(call_data: &[u8], offset: usize) -> Result<u64> {
    let end = offset + 32;
    if call_data.len() < end {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need {} bytes, got {}",
            end,
            call_data.len()
        )));
    }
    let slot = &call_data[offset..end];
    // High 24 bytes must be zero for value to fit in u64
    if slot[..24].iter().any(|&b| b != 0) {
        return Err(EnclaveError::CrossCheck(
            "uint256 value exceeds u64 range".into(),
        ));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&slot[24..32]);
    Ok(u64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    // The top-level `Keccak256` / `Digest` imports are gated on
    // `rgb-validation`, so the test module needs its own.
    use sha3::{Digest, Keccak256};

    /// Default unconfigured BridgeConfig — exercises the legacy "trust the
    /// request" path. Tests that specifically want to verify the pinned
    /// cross-check construct their own configured BridgeConfig.
    fn unconfigured() -> BridgeConfig {
        BridgeConfig {
            chain_id: 0,
            bridge_contract: [0u8; 20],
            rgb_asset_id: String::new(),
            gas_tx_allowed_to: None,
        }
    }

    /// Build a mock `fundsOut` calldata in the 8-arg shape
    /// (`fundsOut(address,uint256,uint256,uint256,uint256,string,bytes,bytes)`
    /// = [`FUNDS_OUT_SELECTOR_POOLS`]) with `amount` at
    /// [`FUNDS_OUT_AMOUNT_OFFSET`] (byte 36). Remaining head slots are
    /// zero-filled — `validate_evm_request` doesn't read them.
    fn mock_funds_out_calldata(amount: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 8 * 32);
        data.extend_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
        // recipient (32, address)
        data.extend_from_slice(&[0u8; 32]);
        // amount (uint256) @ offset 36
        let mut amt = [0u8; 32];
        amt[24..].copy_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&amt);
        // 6 more head slots zero-filled (burnId, sourceChainId,
        // destinationChainId, srcAddrOffset, proofOffset, settlementDataOffset).
        data.extend_from_slice(&[0u8; 32 * 6]);
        data
    }

    /// Placeholder consignment bytes for unit tests. `validate_evm_request`
    /// only verifies the keccak hash matches the bytes — it does not deserialize
    /// or RGB-validate them. The handler-level `validate_funds_out_*` checks
    /// run against `ValidatedConsignment` and are exercised in their own test
    /// modules below.
    ///
    /// `allow(dead_code)`: only consumed by the rgb-validation-gated tests
    /// below; in default builds those tests don't compile and the helpers
    /// go unused.
    #[allow(dead_code)]
    const PLACEHOLDER_CONSIGNMENT: &[u8] =
        b"placeholder-consignment-bytes-for-evm-crosscheck-unit-tests";

    #[allow(dead_code)]
    fn placeholder_consignment_hash() -> Vec<u8> {
        Keccak256::digest(PLACEHOLDER_CONSIGNMENT).to_vec()
    }

    #[allow(dead_code)]
    fn valid_evm_request() -> SignEvmRequest {
        let amount = 1000u64;
        let commission = 50u64;
        SignEvmRequest {
            call_data: mock_funds_out_calldata(amount),
            nonce: 1,
            deadline: u64::MAX, // far future
            consignment_valid: true,
            rgb_amount: 1100, // >= amount + commission
            rgb_asset_id: "rgb:test-asset".into(),
            chain_id: 1,
            proxy_contract: vec![0xAA; 20],
            calldata_amount: amount,
            calldata_commission: commission,
            consignment: PLACEHOLDER_CONSIGNMENT.to_vec(),
            consignment_hash: placeholder_consignment_hash(),
            merkle_proofs: vec![],
        }
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn valid_request_passes() {
        assert!(validate_evm_request(&valid_evm_request(), &unconfigured()).is_ok());
    }

    /// P0 regression: the host-supplied `consignment_valid` flag must not
    /// short-circuit validation. A request claiming `valid:true` with no
    /// consignment bytes must be rejected — see Yulia's PoC #3 and the
    /// boss's bypass report. The handler-level check (in `handle_sign_evm`)
    /// catches "bytes present but validator didn't run"; this test pins
    /// the cross-check's half of the contract.
    #[cfg(feature = "rgb-validation")]
    #[test]
    fn rejects_empty_consignment_even_with_valid_flag() {
        let mut req = valid_evm_request();
        req.consignment_valid = true;
        req.consignment = vec![];
        req.consignment_hash = vec![];
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        assert!(
            err.to_string().contains("requires raw consignment bytes"),
            "expected raw-bytes-required rejection, got: {err}"
        );
    }

    /// Symmetric pin: the flag should not be load-bearing in the other
    /// direction either. Once bytes are present and the hash matches,
    /// `consignment_valid:false` from a host that wants to break things
    /// shouldn't matter — validation comes from the bytes, not the flag.
    #[cfg(feature = "rgb-validation")]
    #[test]
    fn ignores_consignment_valid_flag_when_bytes_present() {
        let mut req = valid_evm_request();
        req.consignment_valid = false;
        assert!(validate_evm_request(&req, &unconfigured()).is_ok());
    }

    // Amount binding moved out of `validate_evm_request` (no more
    // `rgb_amount < calldata_amount + commission` or byte-offset-68
    // checks) and into `validate_funds_out_transfer`, which binds the
    // calldata amount to the consignment. See the `transfer` submodule
    // for that coverage.

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn rejects_expired_deadline() {
        let mut req = valid_evm_request();
        req.deadline = 1; // Unix timestamp 1 is long expired
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        assert!(err.to_string().contains("deadline expired"));
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn rejects_missing_proxy_contract() {
        let mut req = valid_evm_request();
        req.proxy_contract = vec![];
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        assert!(err.to_string().contains("proxy_contract must be 20 bytes"));
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn rejects_zero_chain_id() {
        let mut req = valid_evm_request();
        req.chain_id = 0;
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        assert!(err.to_string().contains("chain_id must be > 0"));
    }

    /// Default-build coverage: every selector that would otherwise pass
    /// the whitelist must be refused at the rgb-validation gate.
    /// Complements the SPV / handler-level checks that fire in
    /// rgb-validation builds.
    #[cfg(not(feature = "rgb-validation"))]
    #[test]
    fn rejects_funds_out_in_default_build() {
        let req = valid_evm_request();
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        assert!(
            err.to_string().contains("rgb-validation"),
            "expected feature-gate rejection, got: {err}"
        );
    }

    #[test]
    fn extract_uint256_works() {
        let mut data = vec![0u8; 40];
        // Put value 42 at offset 8 (bytes 8..40)
        data[39] = 42;
        assert_eq!(extract_uint256_as_u64(&data, 8).unwrap(), 42);
    }

    #[test]
    fn extract_uint256_rejects_short_data() {
        let data = vec![0u8; 10];
        assert!(extract_uint256_as_u64(&data, 0).is_err());
    }

    #[test]
    fn extract_uint256_rejects_overflow() {
        let mut data = vec![0u8; 32];
        data[0] = 1; // high byte set — exceeds u64
        assert!(extract_uint256_as_u64(&data, 0).is_err());
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn accepts_valid_consignment_hash() {
        let mut req = valid_evm_request();
        let consignment = b"test-consignment-bytes";
        let hash = Keccak256::digest(consignment);
        req.consignment = consignment.to_vec();
        req.consignment_hash = hash.to_vec();
        assert!(validate_evm_request(&req, &unconfigured()).is_ok());
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn rejects_consignment_hash_mismatch() {
        let mut req = valid_evm_request();
        req.consignment = b"test-consignment-bytes".to_vec();
        req.consignment_hash = vec![0xDE; 32]; // wrong hash
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        assert!(err.to_string().contains("consignment hash mismatch"));
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn rejects_consignment_without_hash() {
        let mut req = valid_evm_request();
        req.consignment = b"test-consignment-bytes".to_vec();
        req.consignment_hash = vec![]; // missing hash
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        assert!(err.to_string().contains("consignment_hash is missing"));
    }

    #[test]
    fn rejects_unknown_selector() {
        let mut req = valid_evm_request();
        // Swap the first 4 bytes for an unrelated selector. Leave the rest
        // of the calldata intact so the only failing predicate is the
        // whitelist check at the top of validate_evm_request.
        req.call_data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unexpected calldata selector") && msg.contains("deadbeef"),
            "expected selector rejection, got: {msg}"
        );
    }

    #[test]
    fn rejects_calldata_shorter_than_selector() {
        let mut req = valid_evm_request();
        // 3 bytes can't carry a 4-byte selector.
        req.call_data = vec![0x1a, 0xd8, 0x80];
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        assert!(
            err.to_string().contains("call_data too short"),
            "expected too-short rejection, got: {err}"
        );
    }

    // =========================================================================
    // Mint/burn fundsOut tests — `validate_funds_out_burn`
    // =========================================================================

    #[cfg(feature = "rgb-validation")]
    mod burn {
        use super::*;
        use crate::validation::rgb::{TransitionOutput, TransitionSummary, ValidatedConsignment};

        /// Build mint/burn-shape calldata with the given `amount` at
        /// `FUNDS_OUT_AMOUNT_OFFSET`. Everything else (recipient, burnId,
        /// chain ids, dynamic offsets) is zero-filled — none of those
        /// fields are inspected by `validate_funds_out_burn` today. Uses
        /// the single `fundsOut` selector; burn-vs-transfer is decided by
        /// the consignment's transition type, not the selector.
        fn mock_mintburn_calldata(amount: u64) -> Vec<u8> {
            let mut data = Vec::with_capacity(4 + 8 * 32);
            data.extend_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
            // recipient (32, address)
            data.extend_from_slice(&[0u8; 32]);
            // amount (uint256) — offset 36
            let mut amt = [0u8; 32];
            amt[24..].copy_from_slice(&amount.to_be_bytes());
            data.extend_from_slice(&amt);
            // 6 more head-slots zero-filled (burnId, sourceChainId,
            // destinationChainId, srcAddrOffset, proofOffset,
            // settlementDataOffset).
            data.extend_from_slice(&[0u8; 32 * 6]);
            data
        }

        fn validated_with_last(transition: TransitionSummary) -> ValidatedConsignment {
            ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: vec![transition.op_id.clone()],
                last_transition: Some(transition),
            }
        }

        fn burn_transition(burned: Option<u64>) -> TransitionSummary {
            TransitionSummary {
                op_id: "burn-op".into(),
                transition_type: crate::validation::rgb::ifa::TS_BURN,
                total_output_amount: 0,
                outputs: Vec::<TransitionOutput>::new(),
                burned_asset_amount: burned,
            }
        }

        fn req_with_calldata(call_data: Vec<u8>) -> SignEvmRequest {
            SignEvmRequest {
                call_data,
                nonce: 1,
                deadline: u64::MAX,
                consignment_valid: true,
                rgb_amount: 0,
                rgb_asset_id: "rgb:test".into(),
                chain_id: 1,
                proxy_contract: vec![0xAA; 20],
                calldata_amount: 0,
                calldata_commission: 0,
                consignment: vec![],
                consignment_hash: vec![],
                merkle_proofs: vec![],
            }
        }

        #[test]
        fn passes_when_burned_covers_calldata_amount() {
            let req = req_with_calldata(mock_mintburn_calldata(500));
            let validated = validated_with_last(burn_transition(Some(500)));
            assert!(validate_funds_out_burn(&req, &validated).is_ok());
        }

        #[test]
        fn passes_when_burned_exceeds_calldata_amount() {
            let req = req_with_calldata(mock_mintburn_calldata(500));
            let validated = validated_with_last(burn_transition(Some(1_000)));
            assert!(validate_funds_out_burn(&req, &validated).is_ok());
        }

        #[test]
        fn rejects_when_burned_less_than_calldata_amount() {
            let req = req_with_calldata(mock_mintburn_calldata(500));
            let validated = validated_with_last(burn_transition(Some(499)));
            let err = validate_funds_out_burn(&req, &validated).unwrap_err();
            assert!(
                err.to_string().contains("burn amount mismatch"),
                "expected burn amount mismatch, got: {err}"
            );
        }

        #[test]
        fn rejects_when_last_transition_is_not_burn() {
            let req = req_with_calldata(mock_mintburn_calldata(500));
            // Build a Transfer instead of a Burn.
            let mut t = burn_transition(None);
            t.transition_type = crate::validation::rgb::ifa::TS_TRANSFER;
            let validated = validated_with_last(t);
            let err = validate_funds_out_burn(&req, &validated).unwrap_err();
            assert!(
                err.to_string().contains("requires a Burn transition"),
                "expected Burn-required rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_when_burned_asset_metadata_missing() {
            let req = req_with_calldata(mock_mintburn_calldata(500));
            let validated = validated_with_last(burn_transition(None));
            let err = validate_funds_out_burn(&req, &validated).unwrap_err();
            assert!(
                err.to_string().contains("MS_BURNED_ASSET metadata"),
                "expected metadata-missing rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_when_consignment_has_no_transition() {
            let req = req_with_calldata(mock_mintburn_calldata(500));
            let validated = ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: vec![],
                last_transition: None,
            };
            let err = validate_funds_out_burn(&req, &validated).unwrap_err();
            assert!(
                err.to_string().contains("at least one transition"),
                "expected no-transition rejection, got: {err}"
            );
        }

        #[test]
        fn no_op_for_non_funds_out_selector() {
            // Calldata with a selector that isn't `fundsOut` —
            // `validate_funds_out_burn` must not run any burn-side checks
            // against it. Pair it with a deliberately-bad consignment
            // (Transfer with no burn metadata) to make sure the function
            // bails before reading anything.
            let mut req = req_with_calldata(vec![0u8; 100]);
            req.call_data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            let validated = validated_with_last(burn_transition(None));
            assert!(validate_funds_out_burn(&req, &validated).is_ok());
        }
    }

    // =========================================================================
    // Pools fundsOut tests — `validate_funds_out_transfer`
    // =========================================================================

    #[cfg(feature = "rgb-validation")]
    mod transfer {
        use super::*;
        use crate::validation::rgb::{TransitionOutput, TransitionSummary, ValidatedConsignment};

        fn validated_with_last(transition: TransitionSummary) -> ValidatedConsignment {
            ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: vec![transition.op_id.clone()],
                last_transition: Some(transition),
            }
        }

        fn transfer_transition(total_output_amount: u64) -> TransitionSummary {
            TransitionSummary {
                op_id: "transfer-op".into(),
                transition_type: crate::validation::rgb::ifa::TS_TRANSFER,
                total_output_amount,
                outputs: Vec::<TransitionOutput>::new(),
                burned_asset_amount: None,
            }
        }

        /// 8-arg `fundsOut` calldata with `amount` at
        /// [`FUNDS_OUT_AMOUNT_OFFSET`] (byte 36). The contract carries no
        /// commission slot, so there's nothing else for the transfer
        /// check to read.
        fn mock_pools_calldata(amount: u64) -> Vec<u8> {
            let mut data = Vec::with_capacity(4 + 8 * 32);
            data.extend_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
            // recipient (32, address)
            data.extend_from_slice(&[0u8; 32]);
            // amount (uint256) @ offset 36
            let mut amt = [0u8; 32];
            amt[24..].copy_from_slice(&amount.to_be_bytes());
            data.extend_from_slice(&amt);
            // 6 more head slots zero-filled.
            data.extend_from_slice(&[0u8; 32 * 6]);
            data
        }

        fn req_with_calldata(call_data: Vec<u8>) -> SignEvmRequest {
            SignEvmRequest {
                call_data,
                nonce: 1,
                deadline: u64::MAX,
                consignment_valid: true,
                rgb_amount: 0,
                rgb_asset_id: "rgb:test".into(),
                chain_id: 1,
                proxy_contract: vec![0xAA; 20],
                calldata_amount: 0,
                calldata_commission: 0,
                consignment: vec![],
                consignment_hash: vec![],
                merkle_proofs: vec![],
            }
        }

        #[test]
        fn passes_when_total_output_covers_calldata_amount() {
            let req = req_with_calldata(mock_pools_calldata(1000));
            let validated = validated_with_last(transfer_transition(1000));
            assert!(validate_funds_out_transfer(&req, &validated).is_ok());
        }

        #[test]
        fn passes_when_total_output_exceeds_calldata_amount() {
            let req = req_with_calldata(mock_pools_calldata(1000));
            let validated = validated_with_last(transfer_transition(2000));
            assert!(validate_funds_out_transfer(&req, &validated).is_ok());
        }

        /// P0 regression: even with a valid consignment that deserializes
        /// and validates, the EVM-side release cannot exceed the RGB-side
        /// transfer total. A consignment for 1 unit must not authorise a
        /// withdrawal for 10^9.
        #[test]
        fn rejects_when_total_output_less_than_calldata_amount() {
            let req = req_with_calldata(mock_pools_calldata(1_000_000_000));
            let validated = validated_with_last(transfer_transition(1));
            let err = validate_funds_out_transfer(&req, &validated).unwrap_err();
            assert!(
                err.to_string().contains("transfer amount mismatch"),
                "expected transfer amount mismatch, got: {err}"
            );
        }

        /// A burn consignment arriving on the (single) `fundsOut`
        /// selector must be rejected by the transfer check — this is how
        /// mint/burn stays off until it's wired by contract address.
        #[test]
        fn rejects_when_last_transition_is_not_transfer() {
            let req = req_with_calldata(mock_pools_calldata(500));
            let mut t = transfer_transition(500);
            t.transition_type = crate::validation::rgb::ifa::TS_BURN;
            let validated = validated_with_last(t);
            let err = validate_funds_out_transfer(&req, &validated).unwrap_err();
            assert!(
                err.to_string().contains("requires a Transfer transition"),
                "expected Transfer-required rejection, got: {err}"
            );
        }

        #[test]
        fn rejects_when_consignment_has_no_transition() {
            let req = req_with_calldata(mock_pools_calldata(500));
            let validated = ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: vec![],
                last_transition: None,
            };
            let err = validate_funds_out_transfer(&req, &validated).unwrap_err();
            assert!(
                err.to_string().contains("at least one transition"),
                "expected no-transition rejection, got: {err}"
            );
        }

        #[test]
        fn no_op_for_non_funds_out_selector() {
            // Calldata with a selector that isn't `fundsOut` —
            // `validate_funds_out_transfer` must not run any transfer-side
            // checks against it.
            let mut req = req_with_calldata(vec![0u8; 4 + 8 * 32]);
            req.call_data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            let validated = validated_with_last(transfer_transition(0));
            assert!(validate_funds_out_transfer(&req, &validated).is_ok());
        }
    }

    // =========================================================================
    // Asset-identity binding — `bind_asset_identity` (audit TEE-SE-01,
    // coverage map U-1 / T-01). The validated consignment's `contract_id`
    // must match the pinned RGB_ASSET_ID; neither side may be absent.
    // =========================================================================

    #[cfg(feature = "rgb-validation")]
    mod asset_bind {
        use super::*;

        const PIN: &str = "rgb:test-asset";

        /// Happy path: validated contract_id == pin, listener agrees.
        #[test]
        fn binds_when_contract_id_matches_pin() {
            assert!(bind_asset_identity(PIN, PIN, PIN).is_ok());
        }

        /// Listener may stay silent; the pin + validated identity carry it.
        #[test]
        fn binds_when_declared_is_empty() {
            assert!(bind_asset_identity(PIN, "", PIN).is_ok());
        }

        /// The core bypass: an empty `req.rgb_asset_id` must NOT skip the
        /// binding. A foreign-asset consignment with no declared id must be
        /// rejected against the pin rather than waved through.
        #[test]
        fn rejects_foreign_asset_even_when_declared_is_empty() {
            let err = bind_asset_identity("rgb:foreign-asset", "", PIN).unwrap_err();
            assert!(
                err.to_string().contains("contract_id mismatch")
                    && err.to_string().contains("pinned RGB_ASSET_ID"),
                "expected pin mismatch, got: {err}"
            );
        }

        /// Fail-closed when the operator pinned no asset.
        #[test]
        fn rejects_when_pin_absent() {
            let err = bind_asset_identity(PIN, PIN, "").unwrap_err();
            assert!(
                err.to_string().contains("asset-identity pin missing"),
                "expected pin-missing rejection, got: {err}"
            );
        }

        /// Fail-closed when the consignment yields no contract identity.
        #[test]
        fn rejects_when_contract_id_absent() {
            let err = bind_asset_identity("", PIN, PIN).unwrap_err();
            assert!(
                err.to_string().contains("empty contract_id"),
                "expected empty-contract_id rejection, got: {err}"
            );
        }

        /// Listener declares a different asset than the validated identity:
        /// the defence-in-depth leg fires even though the pin matches.
        #[test]
        fn rejects_when_declared_disagrees_with_validated() {
            let err = bind_asset_identity(PIN, "rgb:listener-lied", PIN).unwrap_err();
            assert!(
                err.to_string().contains("request declares"),
                "expected declared-mismatch rejection, got: {err}"
            );
        }
    }

    // =========================================================================
    // Fail-closed when unconfigured (4a) — `validate_evm_request` rejects in
    // production builds (audit TEE-SE-12). The unconfigured guard is compiled
    // out under `cfg(test)`, so this is asserted at the integration layer
    // (`enclave/tests/test_signing.rs`) where the library is built without
    // `cfg(test)`. The unit tests here continue to exercise the legacy
    // unconfigured path via `unconfigured()`.
    // =========================================================================

    // =========================================================================
    // Pinned-config cross-check (4b) — `validate_evm_request` with pinned
    // operator config from env vars. Gated on `rgb-validation` because the
    // post-selector validation body lives behind that cfg.
    // =========================================================================

    #[cfg(feature = "rgb-validation")]
    fn pinned() -> BridgeConfig {
        BridgeConfig {
            chain_id: 1,
            bridge_contract: [0xAA; 20],
            rgb_asset_id: "rgb:test-asset".into(),
            gas_tx_allowed_to: None,
        }
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn pinned_config_accepts_matching_request() {
        // valid_evm_request() defaults exactly match `pinned()` — sanity
        // check that the pinned path doesn't reject a legitimate request.
        assert!(validate_evm_request(&valid_evm_request(), &pinned()).is_ok());
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn pinned_config_rejects_chain_id_mismatch() {
        let mut req = valid_evm_request();
        req.chain_id = 42; // pinned config expects 1
        let err = validate_evm_request(&req, &pinned()).unwrap_err();
        assert!(err.to_string().contains("chain_id mismatch"), "got: {err}");
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn pinned_config_rejects_proxy_contract_mismatch() {
        let mut req = valid_evm_request();
        req.proxy_contract = vec![0xBB; 20]; // pinned is 0xAA
        let err = validate_evm_request(&req, &pinned()).unwrap_err();
        assert!(
            err.to_string().contains("proxy_contract mismatch"),
            "got: {err}"
        );
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn pinned_config_rejects_rgb_asset_mismatch() {
        let mut req = valid_evm_request();
        req.rgb_asset_id = "rgb:wrong-asset".into();
        let err = validate_evm_request(&req, &pinned()).unwrap_err();
        assert!(
            err.to_string().contains("rgb_asset_id mismatch"),
            "got: {err}"
        );
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn pinned_config_rejects_partial_pin_missing_asset() {
        // Operator misconfiguration: pinned chain/contract but no asset.
        // The function must fail-closed instead of silently allowing any
        // asset, since the half-pin gives a misleading attestation.
        let half_pinned = BridgeConfig {
            chain_id: 1,
            bridge_contract: [0xAA; 20],
            rgb_asset_id: String::new(),
            gas_tx_allowed_to: None,
        };
        let err = validate_evm_request(&valid_evm_request(), &half_pinned).unwrap_err();
        assert!(
            err.to_string().contains("RGB_ASSET_ID is empty"),
            "got: {err}"
        );
    }
}
