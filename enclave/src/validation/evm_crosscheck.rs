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
/// The deployed `Bridge` contract (`bridge-smart-contracts/dev`, route-plugin
/// refactor) exposes a **single** `fundsOut`. The pre-refactor 6-arg
/// `fundsOut(address,address,uint256,uint256,string,string)` (`0x1ad880b2`)
/// no longer exists. Both the pools/transfer flow (live now) and the
/// mint/burn unlock flow go through this one selector; despite the
/// `_POOLS` suffix this constant is the single shared `fundsOut` selector.
/// The enclave disambiguates the two flows by the **consignment's last
/// transition type** (`TS_TRANSFER` → pools, `TS_BURN` → unlock), not by
/// the selector — see [`validate_funds_out_transfer`] /
/// [`validate_funds_out_burn`].
///
/// Layout (verified against `Bridge.sol` on `dev`; the MultisigProxy
/// default-allowlists exactly this selector):
/// `[4 selector][32 recipient][32 amount][32 burnId][32 sourceChainId][32 destinationChainId][32 srcAddrOffset][32 proofOffset][32 settlementDataOffset]...`.
/// The first five 32-byte slots are static and readable at fixed offsets;
/// `sourceAddress`/`proof`/`settlementData` store ABI tail offsets (relative
/// to the start of the argument block, i.e. byte 4) in their head slots.
/// `proof = abi.encode(uint256 blockHeight, bytes32 commitmentHash)` and
/// `settlementData = abi.encode(uint256[] fundsInIds)` (RGB-route settlement;
/// `fundsInIds` is `uint256[]`, carried on both flows).
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

/// Upper bound on `fundsOut` calldata length. The fixed ABI head is
/// 4 + 9*32 = 292 bytes; the dynamic tails (srcAddr, proof, settlementData)
/// add at most a few hundred bytes for the live transfer flow. 64 KiB is far
/// above any legitimate fundsOut encoding yet rejects a multi-megabyte
/// calldata (bounded only by the 4 MB framing limit today) before any
/// byte-level extraction or signing work runs (audit I-06 / #90). Compile-time
/// so the posture is PCR-attested, not host-tunable.
pub const MAX_FUNDS_OUT_CALL_DATA_LEN: usize = 64 * 1024;

/// Byte offset of `amount` in the `fundsOut` calldata. After the 4-byte
/// selector and the 32-byte `recipient` head slot, `amount` (uint256)
/// sits at byte 36..68. Shared by the transfer and (future) burn paths
/// since both use the same ABI.
///
/// Only consumed by the cross-check helpers behind `rgb-validation`;
/// gate the const the same way so default builds don't warn.
#[cfg(feature = "rgb-validation")]
const FUNDS_OUT_AMOUNT_OFFSET: usize = 36;

/// Byte offset of `burnId` (uint256) in the `fundsOut` calldata. After the
/// 4-byte selector, the `recipient` head slot (4..36) and the `amount` head
/// slot (36..68), `burnId` sits at bytes 68..100. Confirmed against
/// `Bridge.sol` on `dev` (`burnId` is `fundsOut` param #3, an opaque
/// single-use `uint256` tracked by `consumedBurnIds[burnId]`).
#[cfg(feature = "rgb-validation")]
const FUNDS_OUT_BURN_ID_OFFSET: usize = 68;

/// Byte offset of the `settlementData` head slot in the `fundsOut` calldata.
/// `settlementData` is the 8th argument (a dynamic `bytes`), so after the
/// 4-byte selector its 32-byte head word — which holds the ABI tail offset,
/// not the data — sits at bytes 228..260 (`4 + 7 * 32`). The actual
/// `abi.encode(uint256[] fundsInIds)` payload lives in the tail; see
/// [`extract_funds_in_ids`].
#[cfg(feature = "rgb-validation")]
const FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET: usize = 4 + 7 * 32;

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
    // Semantic upper bound on calldata, well below the generic 4 MB frame, so
    // a maximally packed request is rejected before any offset extraction or
    // signing (audit I-06 / #90).
    if req.call_data.len() > MAX_FUNDS_OUT_CALL_DATA_LEN {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too large: {} bytes (max {})",
            req.call_data.len(),
            MAX_FUNDS_OUT_CALL_DATA_LEN
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

        // 4a. Partial config is always a hard error (audit 4th M-03 / #94).
        //     The operator set some of EVM_CHAIN_ID / BRIDGE_CONTRACT /
        //     RGB_ASSET_ID but not all, so the pin is ambiguous: a zero
        //     chain_id can never match a real request, and a zero
        //     bridge_contract would otherwise accept an EVM request for the
        //     zero address. This is never a legitimate dev shape, so — unlike
        //     the fully-unconfigured fallback below — it is not gated on
        //     cfg(test).
        if bridge_config.is_partially_configured() {
            return Err(EnclaveError::CrossCheck(
                "bridge config partially set: EVM_CHAIN_ID / BRIDGE_CONTRACT / RGB_ASSET_ID \
                 must all be set (non-zero) or all unset — refusing to sign with an ambiguous pin"
                    .into(),
            ));
        }

        // 4b. Fail-closed when fully unconfigured (audit TEE-SE-12). A build
        //     that can validate consignments (rgb-validation enabled — this
        //     whole block) must refuse to sign when the operator pinned
        //     nothing: otherwise a misprovisioned-but-running enclave silently
        //     degrades to the pre-pin, listener-trusting model. The escape
        //     hatch is intentionally narrow: dev-mode skips this function
        //     entirely (see `handle_sign_evm`), and the library unit tests
        //     (`cfg(test)`) keep exercising the legacy unconfigured path.
        //     Integration tests pin a config explicitly via
        //     `start_test_server_with_config`.
        #[cfg(not(test))]
        if !bridge_config.is_configured() {
            return Err(EnclaveError::CrossCheck(
                "bridge config unconfigured: set EVM_CHAIN_ID / BRIDGE_CONTRACT / RGB_ASSET_ID \
                 — refusing to sign in listener-trusting mode"
                    .into(),
            ));
        }

        // 4c. Pinned-config cross-check. When the operator configured
        //     EVM_CHAIN_ID / BRIDGE_CONTRACT / RGB_ASSET_ID at boot, the
        //     listener-supplied values MUST match — otherwise a compromised
        //     listener could redirect signatures to a different chain or
        //     contract. The same values are committed into the attestation
        //     `user_data` so an external verifier can confirm what this
        //     enclave is provisioned for. `is_configured()` now guarantees all
        //     three fields are non-zero / non-empty (audit 4th M-03 / #94), so
        //     none of the comparisons below can be satisfied by a zero pin.
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
            // it must match the pin. The pin's own non-emptiness is now
            // guaranteed by `is_configured()` (audit 4th M-03 / #94), so the
            // previous "pinned chain/contract but RGB_ASSET_ID empty" branch is
            // unreachable and has been removed.
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

/// Defense-in-depth recency check for the RGB->EVM `fundsOut` direction
/// (audit 4th I-03 / #95).
///
/// In this direction the consignment describes a transfer that is already
/// settled on Bitcoin, so every witness transaction anchoring it must be
/// mined. rgbstd's `validate()` already hard-rejects `Archived`/unresolvable
/// witnesses, but accepts `Tentative`/`Ignored` ones (legitimate for the
/// unbroadcast send-RGB PSBT flow, never for a confirmed unlock). The SPV
/// stage independently checks inclusion + depth; this check refuses to sign
/// if rgbstd itself classified any witness as not-mined, so confirmation is
/// not load-bearing on the in-enclave header chain alone.
///
/// `validated.non_mined_witness_txids` is in display byte order.
#[cfg(feature = "rgb-validation")]
pub fn assert_witnesses_confirmed(validated: &ValidatedConsignment) -> Result<()> {
    if !validated.non_mined_witness_txids.is_empty() {
        let list: Vec<String> = validated
            .non_mined_witness_txids
            .iter()
            .map(hex::encode)
            .collect();
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut requires every consignment witness tx to be mined, but rgbstd classified \
             {} witness(es) as not-yet-confirmed (tentative/ignored): {} - refusing to sign",
            list.len(),
            list.join(", ")
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

/// The OpId → on-chain-id transform: how a 32-byte RGB OpId maps to the
/// `uint256` the contract carries as `burnId` and as each `fundsInIds[]`
/// entry.
///
/// **`keccak256(op_id_bytes)`** — the consignment parser yields the OpId as
/// 64-char hex; we hex-decode to the raw 32 bytes and keccak them. The digest
/// is the big-endian `uint256` the calldata carries.
///
/// This MUST match the derivation the backend (`bridge-utexo`) uses when it
/// builds the `fundsOut` calldata: both sides key the contract's
/// `consumedBurnIds` / `fundsInRecords` on the SAME value, computed
/// independently. The whole OpId binding hinges on this single function —
/// if the team pins a different preimage (e.g. `keccak256(ascii_hex)`), this
/// is the only line that changes.
#[cfg(feature = "rgb-validation")]
fn op_id_to_calldata_id(op_id: &str) -> Result<[u8; 32]> {
    let bytes = decode_op_id_to_bytes32(op_id)?;
    Ok(Keccak256::digest(bytes).into())
}

/// OpId binding applied to a `fundsOut` calldata before signing (audit
/// TEE-SE-02, spec §6/§7).
///
/// The enclave does NOT trust — or even read — the listener's
/// `burnId`/`fundsInIds`. It derives them from the consignment it validated
/// and **overwrites** the calldata it is about to sign:
///   - `burnId` (offset 68) := `keccak256(validated release-transition OpId)`,
///     where the OpId is `ValidatedConsignment::last_transfer_op_id` - read
///     from the rgbstd-**validated** `Transfer`, NOT the flat parser (audit
///     M-02 / #93). This binds the contract's single-use `consumedBurnIds`
///     guard to the operation `validate()` actually authenticated; and
///   - `settlementData` := `abi.encode(uint256[] fundsInIds)` over
///     `op_id_to_calldata_id(opid)` for **every** IFA `TS_INFLATION` (mint)
///     transition in the consignment's history.
///
/// Returns the rewritten calldata. Because the MultisigProxy signature commits
/// to `keccak256(callData)`, these bytes are authoritative — a compromised
/// backend cannot influence which replay slot (`consumedBurnIds`) or lock
/// records (`fundsInRecords`) the release touches. The output is a pure
/// function of the consignment, so every federation signer rewrites it
/// identically. **The caller MUST submit exactly the returned bytes** (the
/// signature is over them, not over the original).
///
/// Layout (verified against `Bridge.sol` on `dev`): the static head words
/// (recipient/amount/burnId/sourceChainId/destChainId) are at fixed offsets
/// and `settlementData` is the **last** dynamic argument, so its tail is
/// rebuilt in place; `sourceAddress` and the SPV `proof` are preserved exactly.
#[cfg(feature = "rgb-validation")]
pub fn apply_op_id_binding(call_data: &[u8], validated: &ValidatedConsignment) -> Result<Vec<u8>> {
    // burnId is derived from the rgbstd-VALIDATED OpId of the release
    // (TS_TRANSFER) transition (`last_transfer_op_id`), not the flat parser -
    // so the contract's single-use `consumedBurnIds` key is bound to the
    // operation `validate()` authenticated (audit M-02 / #93). Fail closed if
    // it wasn't extracted (no bundles, or a non-Transfer last transition).
    let op_id = validated.last_transfer_op_id.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "OpId binding requires the validated OpId of the release transition, but none was \
             extracted (the last transition is not a validated Transfer) - refusing to sign"
                .into(),
        )
    })?;
    let burn_id: [u8; 32] = Keccak256::digest(op_id).into();
    let funds_in_ids: Vec<[u8; 32]> = validated
        .mint_op_ids
        .iter()
        .map(|o| op_id_to_calldata_id(o))
        .collect::<Result<_>>()?;

    // The 8-word head (after the 4-byte selector) must be present to locate
    // the burnId slot and the settlementData offset.
    let head_end = FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET + 32; // 260
    if call_data.len() < head_end {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut calldata too short: need {head_end} head bytes, got {}",
            call_data.len()
        )));
    }

    let mut out = call_data.to_vec();

    // (1) Overwrite burnId in place (a static head slot).
    out[FUNDS_OUT_BURN_ID_OFFSET..FUNDS_OUT_BURN_ID_OFFSET + 32].copy_from_slice(&burn_id);

    // (2) Replace settlementData (the last dynamic arg). Read its tail offset
    //     (relative to the args start, byte 4), drop the old tail, and append a
    //     fresh `abi.encode(uint256[] fundsInIds)`. The head offset word still
    //     points at the same start, so it needs no update.
    let sd_rel = bytes32_to_usize(&extract_bytes32(
        &out,
        FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET,
    )?)?;
    let sd_start = 4usize
        .checked_add(sd_rel)
        .ok_or_else(|| EnclaveError::CrossCheck("settlementData offset overflow".into()))?;
    if sd_start < head_end || sd_start > out.len() {
        return Err(EnclaveError::CrossCheck(format!(
            "settlementData offset out of range: {sd_start} (head_end {head_end}, len {})",
            out.len()
        )));
    }
    out.truncate(sd_start);

    // settlementData is a dynamic `bytes`: [length][payload], where payload is
    // `abi.encode(uint256[])` = [0x20 offset][N][ids...].
    let payload_len = 64 + funds_in_ids.len() * 32;
    out.extend_from_slice(&u256_word(payload_len)); // bytes length
    out.extend_from_slice(&u256_word(32)); // inner array offset (0x20)
    out.extend_from_slice(&u256_word(funds_in_ids.len())); // N
    for id in &funds_in_ids {
        out.extend_from_slice(id);
    }

    Ok(out)
}

/// Encode a `usize` as a big-endian 32-byte ABI word.
#[cfg(feature = "rgb-validation")]
fn u256_word(n: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(n as u64).to_be_bytes());
    w
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

/// Read a 32-byte word (a `bytes32`/`uint256` head slot) from `call_data` at
/// a fixed byte offset. Unlike [`extract_uint256_as_u64`] this preserves the
/// full 32 bytes — used for the `burnId` binding, where the value is an
/// opaque 256-bit identifier that must be compared byte-for-byte, not
/// clamped to `u64`.
///
/// Safe only for the static `fundsOut` head slots (recipient, amount,
/// burnId, sourceChainId, destinationChainId). The dynamic
/// `sourceAddress`/`proof`/`settlementData` args store ABI tail offsets in
/// their head slots and must be traversed, not read at a fixed absolute
/// offset.
#[cfg(any(feature = "rgb-validation", test))]
fn extract_bytes32(call_data: &[u8], offset: usize) -> Result<[u8; 32]> {
    let end = offset + 32;
    if call_data.len() < end {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short: need {} bytes, got {}",
            end,
            call_data.len()
        )));
    }
    call_data[offset..end]
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("bytes32 slice conversion failed".into()))
}

/// Decode an RGB OpId string (the 64-char hex of the 32-byte OpId, as the
/// consignment parser yields it) into raw bytes. Fails closed if the string
/// is not exactly 32 bytes of hex — the `burnId` binding needs the canonical
/// 32-byte form, so a non-hex / wrong-length OpId is a hard error rather than
/// a silent skip.
#[cfg(feature = "rgb-validation")]
fn decode_op_id_to_bytes32(op_id: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(op_id).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "op_id is not hex-decodable (got {op_id:?}): {e} — burnId binding needs the \
             32-byte OpId form"
        ))
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "op_id decodes to {} bytes, expected 32 (op_id {op_id:?})",
            bytes.len()
        ))
    })
}

/// Interpret a 32-byte ABI word as a `usize` (used for ABI offsets/lengths).
/// Fails closed if the high 24 bytes are non-zero (a value that wouldn't fit
/// a `usize` is a malformed/hostile offset, not something to truncate).
#[cfg(any(feature = "rgb-validation", test))]
fn bytes32_to_usize(word: &[u8; 32]) -> Result<usize> {
    if word[..24].iter().any(|&b| b != 0) {
        return Err(EnclaveError::CrossCheck(
            "ABI offset/length word exceeds usize range".into(),
        ));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    Ok(u64::from_be_bytes(buf) as usize)
}

/// Parse the `fundsOut` `settlementData` (`abi.encode(uint256[] fundsInIds)`)
/// and return each `fundsInId` as a raw 32-byte word.
///
/// Two levels of ABI indirection: (1) the `settlementData` head slot at
/// [`FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET`] holds a tail offset measured from
/// the start of the argument block (byte 4); (2) at that tail the `bytes` has
/// a length word followed by its payload, which is itself
/// `abi.encode(uint256[])` = `[0x20 offset][len N][N words]`. Every read is
/// bounds-checked (via [`extract_bytes32`]) and every offset/length is range
/// checked (via [`bytes32_to_usize`]); a malformed or truncated blob is a hard
/// error. Returns an empty vec when `settlementData` is empty.
///
/// The enclave OVERWRITES `settlementData` ([`apply_op_id_binding`]) rather
/// than reading it, so this reader exists only to verify, in tests, that the
/// writer's encoding round-trips — hence the `test` gate.
#[cfg(all(feature = "rgb-validation", test))]
fn extract_funds_in_ids(call_data: &[u8]) -> Result<Vec<[u8; 32]>> {
    // (1) settlementData tail offset (relative to the args start = byte 4).
    let rel = bytes32_to_usize(&extract_bytes32(
        call_data,
        FUNDS_OUT_SETTLEMENT_DATA_HEAD_OFFSET,
    )?)?;
    let sd_start = 4usize
        .checked_add(rel)
        .ok_or_else(|| EnclaveError::CrossCheck("settlementData offset overflow".into()))?;

    // settlementData `bytes`: [length word][payload].
    let sd_len = bytes32_to_usize(&extract_bytes32(call_data, sd_start)?)?;
    if sd_len == 0 {
        return Ok(vec![]); // no fundsInIds claimed
    }
    let sd_body = sd_start
        .checked_add(32)
        .ok_or_else(|| EnclaveError::CrossCheck("settlementData body overflow".into()))?;
    let sd_end = sd_body
        .checked_add(sd_len)
        .ok_or_else(|| EnclaveError::CrossCheck("settlementData length overflow".into()))?;
    if call_data.len() < sd_end {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data too short for settlementData: need {sd_end}, got {}",
            call_data.len()
        )));
    }
    let sd = &call_data[sd_body..sd_end];

    // (2) sd = abi.encode(uint256[]) = [offset (0x20)][len N][N words].
    let arr_off = bytes32_to_usize(&extract_bytes32(sd, 0)?)?;
    let n = bytes32_to_usize(&extract_bytes32(sd, arr_off)?)?;
    let elems_start = arr_off
        .checked_add(32)
        .ok_or_else(|| EnclaveError::CrossCheck("fundsInIds elements offset overflow".into()))?;
    let span = n
        .checked_mul(32)
        .and_then(|x| elems_start.checked_add(x))
        .ok_or_else(|| EnclaveError::CrossCheck("fundsInIds array size overflow".into()))?;
    if sd.len() < span {
        return Err(EnclaveError::CrossCheck(format!(
            "settlementData too short for {n} fundsInIds: need {span}, got {}",
            sd.len()
        )));
    }

    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        ids.push(extract_bytes32(sd, elems_start + i * 32)?);
    }
    Ok(ids)
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

    #[test]
    fn extract_bytes32_works() {
        let mut data = vec![0u8; 4 + 32 + 32 + 32];
        let mut word = [0u8; 32];
        word[0] = 0xab;
        word[31] = 0xcd;
        data[68..100].copy_from_slice(&word); // burnId head slot
        assert_eq!(extract_bytes32(&data, 68).unwrap(), word);
    }

    #[test]
    fn extract_bytes32_rejects_short_data() {
        let data = vec![0u8; 90]; // burnId slot ends at 100
        assert!(extract_bytes32(&data, 68).is_err());
    }

    #[test]
    fn bytes32_to_usize_works() {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&320u64.to_be_bytes());
        assert_eq!(bytes32_to_usize(&w).unwrap(), 320);
    }

    #[test]
    fn bytes32_to_usize_rejects_out_of_range() {
        let mut w = [0u8; 32];
        w[0] = 1; // high byte set — exceeds usize/u64
        assert!(bytes32_to_usize(&w).is_err());
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

    #[test]
    fn rejects_calldata_over_size_cap() {
        // A maximally packed calldata must be rejected up-front (audit I-06 /
        // #90), before selector dispatch or any offset extraction. Start from
        // a valid fundsOut request and pad the tail past the cap.
        let mut req = valid_evm_request();
        req.call_data
            .resize(super::MAX_FUNDS_OUT_CALL_DATA_LEN + 1, 0u8);
        let err = validate_evm_request(&req, &unconfigured()).unwrap_err();
        assert!(
            err.to_string().contains("call_data too large"),
            "expected too-large rejection, got: {err}"
        );
    }

    #[test]
    fn accepts_calldata_at_size_cap() {
        // Exactly at the cap is allowed; the selector head is preserved so
        // dispatch still recognizes the fundsOut shape.
        let mut req = valid_evm_request();
        req.call_data
            .resize(super::MAX_FUNDS_OUT_CALL_DATA_LEN, 0u8);
        req.call_data[..4].copy_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
        // Under default (no rgb-validation) the call still fails later for
        // requiring rgb-validation; assert only that it is NOT the size error.
        if let Err(e) = validate_evm_request(&req, &unconfigured()) {
            assert!(
                !e.to_string().contains("call_data too large"),
                "calldata exactly at the cap must not trip the size check, got: {e}"
            );
        }
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
                mint_op_ids: vec![],
                last_transition: Some(transition),
                last_transfer_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
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
                mint_op_ids: vec![],
                last_transition: None,
                last_transfer_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
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
                mint_op_ids: vec![],
                last_transition: Some(transition),
                last_transfer_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
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
        fn witnesses_confirmed_passes_when_all_mined() {
            // No non-mined witnesses surfaced -> the recency guard is a no-op
            // (audit 4th I-03 / #95).
            let validated = validated_with_last(transfer_transition(1000));
            assert!(super::super::assert_witnesses_confirmed(&validated).is_ok());
        }

        #[test]
        fn witnesses_confirmed_rejects_non_mined() {
            // A tentative/ignored witness in the RGB->EVM direction is an
            // anomaly: the unlock settles an already-confirmed transfer.
            let mut validated = validated_with_last(transfer_transition(1000));
            validated.non_mined_witness_txids = vec![[0xABu8; 32]];
            let err = super::super::assert_witnesses_confirmed(&validated).unwrap_err();
            assert!(
                err.to_string().contains("mined"),
                "expected not-mined rejection, got: {err}"
            );
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
                mint_op_ids: vec![],
                last_transition: None,
                last_transfer_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id: None,
                non_mined_witness_txids: vec![],
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
    // OpId binding — `apply_op_id_binding` (audit TEE-SE-02, spec §6/§7). The
    // enclave derives burnId / fundsInIds from the consignment it validated and
    // OVERWRITES them in the calldata it signs. No listener-supplied OpId is
    // trusted or even read. `extract_funds_in_ids` confirms the writer's
    // settlementData round-trips through the reader.
    // =========================================================================

    #[cfg(feature = "rgb-validation")]
    mod op_id_binding {
        use super::*;
        use crate::validation::rgb::{ifa, TransitionSummary, ValidatedConsignment};

        const OP_ID: &str = "74c1d59264894a1bd44887fe84b36739c024bd50188e69baeeda845569313543";
        const MINT_A: &str = "f5106c6ddb8b8fd3d1de3bda0106ae13ef0705dc36bfc543566362e5e8dd4bd5";
        const MINT_B: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        /// The binding transform: keccak256 of the raw 32-byte OpId.
        fn id(op_id: &str) -> [u8; 32] {
            Keccak256::digest(hex::decode(op_id).unwrap()).into()
        }

        fn u256(n: usize) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&(n as u64).to_be_bytes());
            w
        }

        /// Build `fundsOut` calldata with the given `burnId` (offset 68) and
        /// `fundsInIds` (encoded in `settlementData = abi.encode(uint256[])`).
        /// `sourceAddress` and `proof` are present but empty. The ABI tail
        /// layout mirrors what `extract_funds_in_ids` traverses.
        fn mock_funds_out(burn_id: [u8; 32], funds_in_ids: &[[u8; 32]]) -> Vec<u8> {
            let mut d = Vec::new();
            d.extend_from_slice(&FUNDS_OUT_SELECTOR_POOLS);
            d.extend_from_slice(&[0u8; 32]); // recipient
            d.extend_from_slice(&[0u8; 32]); // amount
            d.extend_from_slice(&burn_id); // burnId @68
            d.extend_from_slice(&[0u8; 32]); // sourceChainId
            d.extend_from_slice(&[0u8; 32]); // destinationChainId
            d.extend_from_slice(&u256(256)); // sourceAddress tail offset (rel byte 4)
            d.extend_from_slice(&u256(288)); // proof tail offset
            d.extend_from_slice(&u256(320)); // settlementData tail offset
            d.extend_from_slice(&u256(0)); // sourceAddress length = 0
            d.extend_from_slice(&u256(0)); // proof length = 0
                                           // settlementData bytes = abi.encode(uint256[]) = [0x20][N][ids...]
            let payload_len = 64 + funds_in_ids.len() * 32;
            d.extend_from_slice(&u256(payload_len)); // settlementData length
            d.extend_from_slice(&u256(32)); // inner array offset (0x20)
            d.extend_from_slice(&u256(funds_in_ids.len())); // N
            for fid in funds_in_ids {
                d.extend_from_slice(fid);
            }
            d
        }

        fn transition(op_id: &str, transition_type: u16) -> TransitionSummary {
            TransitionSummary {
                op_id: op_id.into(),
                transition_type,
                total_output_amount: 0,
                outputs: Vec::new(),
                burned_asset_amount: None,
            }
        }

        /// The validated last-transfer OpId bytes for a given hex OpId - the
        /// authoritative burnId source (`ValidatedConsignment::last_transfer_op_id`).
        fn op_id_bytes(op_id: &str) -> [u8; 32] {
            hex::decode(op_id).unwrap().try_into().unwrap()
        }

        fn validated(
            last: Option<TransitionSummary>,
            mint_op_ids: Vec<String>,
        ) -> ValidatedConsignment {
            // The burnId is derived from the rgbstd-VALIDATED OpId, so mirror
            // production: `last_transfer_op_id` carries the same OpId as the
            // last transition (set by `read_last_transfer_witness` for a
            // TS_TRANSFER last transition).
            let last_transfer_op_id = last.as_ref().map(|t| op_id_bytes(&t.op_id));
            ValidatedConsignment {
                contract_id: "rgb:test".into(),
                chain_net: "bc".into(),
                witness_txids: vec![],
                all_op_ids: last
                    .as_ref()
                    .map(|t| vec![t.op_id.clone()])
                    .unwrap_or_default(),
                mint_op_ids,
                last_transition: last,
                last_transfer_witness_txid: None,
                last_transfer_witness_prevouts: None,
                last_transfer_op_id,
                non_mined_witness_txids: vec![],
            }
        }

        // ---- apply_op_id_binding (override, not verify) ----

        /// Writes burnId@68 = keccak256(validated OpId), overriding whatever the
        /// bridge put there. The OpId is sourced from the rgbstd-validated
        /// transfer (`last_transfer_op_id`), not the flat parser (audit M-02 / #93).
        #[test]
        fn writes_burn_id_from_validated_op_id() {
            let cd = mock_funds_out([0xEE; 32], &[]); // bogus burnId in input
            let v = validated(Some(transition(OP_ID, ifa::TS_TRANSFER)), vec![]);
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert_eq!(
                extract_bytes32(&out, FUNDS_OUT_BURN_ID_OFFSET).unwrap(),
                id(OP_ID)
            );
        }

        /// Fail closed when no validated OpId was extracted (e.g. a non-Transfer
        /// last transition): the enclave must refuse rather than fall back to a
        /// listener- or flat-parser-supplied burnId.
        #[test]
        fn rejects_when_validated_op_id_missing() {
            let cd = mock_funds_out([0xEE; 32], &[]);
            let mut v = validated(Some(transition(OP_ID, ifa::TS_TRANSFER)), vec![]);
            v.last_transfer_op_id = None;
            let err = apply_op_id_binding(&cd, &v).unwrap_err();
            assert!(
                err.to_string().contains("validated OpId of the release transition"),
                "got: {err}"
            );
        }

        /// Writes ALL mint OpIds into settlementData, overriding the bridge's set.
        #[test]
        fn writes_all_mint_funds_in_ids() {
            let cd = mock_funds_out([0xEE; 32], &[[0x11; 32], [0x22; 32]]);
            let v = validated(
                Some(transition(OP_ID, ifa::TS_BURN)),
                vec![MINT_A.into(), MINT_B.into()],
            );
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert_eq!(
                extract_funds_in_ids(&out).unwrap(),
                vec![id(MINT_A), id(MINT_B)]
            );
        }

        /// No mints in the consignment → empty fundsInIds (not an error).
        #[test]
        fn writes_empty_funds_in_ids_when_no_mints() {
            let cd = mock_funds_out([0xEE; 32], &[[0x11; 32]]);
            let v = validated(Some(transition(OP_ID, ifa::TS_BURN)), vec![]);
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert!(extract_funds_in_ids(&out).unwrap().is_empty());
        }

        /// Override, not verify: a fully bogus input (wrong burnId AND wrong
        /// fundsInIds) is rewritten to the consignment's values.
        #[test]
        fn overrides_whatever_the_bridge_sent() {
            let cd = mock_funds_out([0xEE; 32], &[[0xAB; 32]]);
            let v = validated(Some(transition(OP_ID, ifa::TS_BURN)), vec![MINT_A.into()]);
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert_eq!(
                extract_bytes32(&out, FUNDS_OUT_BURN_ID_OFFSET).unwrap(),
                id(OP_ID)
            );
            assert_eq!(extract_funds_in_ids(&out).unwrap(), vec![id(MINT_A)]);
        }

        /// The non-OpId fields (recipient, amount) are left exactly as sent.
        #[test]
        fn preserves_non_op_id_fields() {
            let mut cd = mock_funds_out([0xEE; 32], &[[0x11; 32]]);
            cd[4..36].copy_from_slice(&u256(0xBEEF)); // recipient marker
            cd[36..68].copy_from_slice(&u256(123_456)); // amount marker
            let v = validated(Some(transition(OP_ID, ifa::TS_BURN)), vec![MINT_A.into()]);
            let out = apply_op_id_binding(&cd, &v).unwrap();
            assert_eq!(&out[4..36], &u256(0xBEEF));
            assert_eq!(&out[36..68], &u256(123_456));
        }

        /// A mint OpId that isn't 32-byte hex can not be transformed - fail
        /// closed. (The burnId now comes from the pre-validated
        /// `last_transfer_op_id` bytes, so the only string-decoded OpIds left
        /// are the `fundsInIds` mint set.)
        #[test]
        fn rejects_non_hex_op_id() {
            let cd = mock_funds_out([0xEE; 32], &[]);
            let v = validated(Some(transition(OP_ID, ifa::TS_TRANSFER)), vec!["not-hex".into()]);
            let err = apply_op_id_binding(&cd, &v).unwrap_err();
            assert!(
                err.to_string().contains("hex-decodable")
                    || err.to_string().contains("expected 32"),
                "expected op_id decode rejection, got: {err}"
            );
        }

        /// Calldata too short to hold the fundsOut head is rejected.
        #[test]
        fn rejects_calldata_too_short() {
            let v = validated(Some(transition(OP_ID, ifa::TS_BURN)), vec![]);
            let err = apply_op_id_binding(&[0u8; 100], &v).unwrap_err();
            assert!(err.to_string().contains("too short"), "got: {err}");
        }

        /// No validated release OpId to bind against -> hard error.
        #[test]
        fn rejects_no_transition() {
            let cd = mock_funds_out([0xEE; 32], &[]);
            let v = validated(None, vec![]);
            let err = apply_op_id_binding(&cd, &v).unwrap_err();
            assert!(
                err.to_string().contains("validated OpId of the release transition"),
                "got: {err}"
            );
        }

        // ---- settlementData ABI round-trip (writer vs reader agree) ----

        #[test]
        fn settlement_parser_round_trips() {
            let ids = [id(MINT_A), id(MINT_B)];
            let cd = mock_funds_out(id(OP_ID), &ids);
            assert_eq!(extract_funds_in_ids(&cd).unwrap(), ids.to_vec());
        }

        #[test]
        fn settlement_parser_empty() {
            let cd = mock_funds_out(id(OP_ID), &[]);
            assert!(extract_funds_in_ids(&cd).unwrap().is_empty());
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
        // asset, since the half-pin gives a misleading attestation. After
        // #94 this is caught by the unified partial-config gate.
        let half_pinned = BridgeConfig {
            chain_id: 1,
            bridge_contract: [0xAA; 20],
            rgb_asset_id: String::new(),
            gas_tx_allowed_to: None,
        };
        let err = validate_evm_request(&valid_evm_request(), &half_pinned).unwrap_err();
        assert!(err.to_string().contains("partially set"), "got: {err}");
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn pinned_config_rejects_zero_bridge_contract() {
        // A zero bridge_contract is a partial pin (audit 4th M-03 / #94): it
        // must never be treated as a valid pin that would accept an EVM
        // request for the zero address.
        let zero_contract = BridgeConfig {
            chain_id: 1,
            bridge_contract: [0u8; 20],
            rgb_asset_id: "rgb:asset".into(),
            gas_tx_allowed_to: None,
        };
        let err = validate_evm_request(&valid_evm_request(), &zero_contract).unwrap_err();
        assert!(err.to_string().contains("partially set"), "got: {err}");
    }
}
