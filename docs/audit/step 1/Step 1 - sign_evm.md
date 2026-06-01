# Step 1 Flow Review — Sign EVM (RGB → EVM unlock / `fundsOut`)

**Component:** `utexo-bridge-enclave` (the TEE), `dev` @ HEAD `bb2b396`.
**Flow:** an enriched `SignEvmRequest` arrives over the enclave wire protocol; the
TEE validates it and, if every predicate passes, returns an EIP-712 ECDSA signature
authorising a `fundsOut(...)` call on the EVM `MultisigProxy`.
**Reviewed:** 2026-05-29. Methodology: `internal_audit/release 1.0/prompts/`.
**Asset:** the EVM-side released token is **USDT0**; the RGB side is the bridge's
IFA-schema RGB asset (pinned as `RGB_ASSET_ID`). Amount fields are in each side's
smallest unit and the flow assumes a 1:1 RGB-unit ↔ USDT0-unit mapping.

> This reviews only the TEE half. The on-chain `MultisigProxy` quorum, `burnId`
> replay consumption, and lock-record check (spec Sec 8 / Sec 11) live in the
> contracts repo and are out of scope here — see `internal_audit/release 1.0/
> smart contracts/` and the FundsOut contract flow.

---

## 1. Code scope

Loaded (only what this flow executes):

| File | Symbols |
|---|---|
| `enclave/src/server.rs` | `dispatch` (SignEvm arm, :86-89), `handle_sign_evm` (:330-464), `build_evm_domain` (:519-558) |
| `enclave/src/validation/rgb.rs` | `RgbValidator::validate_consignment` (:176-297), `ValidatedConsignment`, `TransitionSummary`, `ifa::{TS_TRANSFER,TS_BURN,MS_BURNED_ASSET}` |
| `enclave/src/validation/evm_crosscheck.rs` | `validate_evm_request` (:60-238), `validate_funds_out_burn` (:262-297), `validate_funds_out_transfer` (:323-364), `extract_uint256_as_u64` (:372-392), `FUNDS_OUT_SELECTOR_*` |
| `enclave/src/validation/spv_crosscheck.rs` | `assert_chain_not_stale`, `assert_chain_net`, `validate_spv_proofs`, `SPV_MIN_CONFIRMATIONS=6` |
| `enclave/src/signing/evm.rs` | `Eip712Domain::separator_hash`, `sign_request_digest` |
| `enclave/src/state.rs` | `EnclaveState::sign_evm` (:325-328), `with_active` (:343-346) |
| `enclave/src/keys.rs` | `KeyManager::sign_evm` (:267-279) |
| `enclave/src/config.rs` | `BridgeConfig::is_configured` |
| `proto/enclave.proto` | `SignEvmRequest` (:123-152), `MerkleProofEntry` (:159-164) |

Production feature set: `--features spv,rgb-validation` (`spv` implies `rgb-validation`
per `Cargo.toml`). `dev-mode` (skips all cross-checks) is compile-time excluded from
release. Skipped: cloning, attestation, PSBT, SubmitHeaders, governance.

---

## 2. Sequence diagram (verified against `handle_sign_evm`, top-to-bottom)

```mermaid
sequenceDiagram
    autonumber
    participant L as Go Listener (untrusted)
    participant P as parent (untrusted)
    participant S as handle_sign_evm
    participant R as RgbValidator
    participant E as Esplora (via vsock_forwarder)
    participant X as evm_crosscheck
    participant C as HeaderChain
    participant V as spv_crosscheck
    participant K as EnclaveState/KeyManager

    L->>P: gRPC Sign(EnrichedEvmPayload)
    P->>S: SignEvmRequest (len-prefixed proto)

    Note over S: cfg(not "spv") && !merkle_proofs.is_empty() → Err(Spv) [build-skew guard]

    alt consignment non-empty AND rgb_validator = Some
        S->>R: validate_consignment(req.consignment)
        R->>R: Transfer::load → else Err(CrossCheck "deserialization failed")
        R->>E: esplora resolve witness txs + rgbstd validate()
        E-->>R: tx data
        R-->>S: ValidatedConsignment{contract_id, chain_net, witness_txids, all_op_ids, last_transition}
        Note over S: if !req.rgb_asset_id.is_empty() && v.contract_id != req.rgb_asset_id → Err(CrossCheck)
    else validator None
        Note over S: validated_consignment = None (warn)
    end

    S->>X: validate_evm_request(req, bridge_config)   %% cfg(not dev-mode)
    X->>X: call_data.len() < 4 → Err; selector ∉ FUNDS_OUT_SELECTORS → Err
    X->>X: req.consignment.is_empty() → Err  (consignment_valid flag NOT read)
    X->>X: consignment_hash empty / keccak256(consignment) != consignment_hash → Err
    X->>X: legacy 0x1ad880b2: req.rgb_amount < calldata_amount+commission → Err; offsets 68/100 != declared → Err
    X->>X: chain_id == 0 → Err; proxy_contract.len() != 20 → Err
    X->>X: if bridge_config.is_configured(): chain_id/proxy_contract != pin → Err; pin asset empty → Err; req.rgb_asset_id nonempty && != pin → Err
    X->>X: deadline <= now → Err
    X-->>S: Ok | Err(CrossCheck)

    Note over S: cfg(rgb-validation, not dev-mode), selector ∈ {legacy, mint/burn}
    S->>S: validated_consignment.as_ref() else Err(CrossCheck "requires a validated consignment")
    S->>X: validate_funds_out_burn(req, validated)
    X->>X: mint/burn 0x179bef59: last != TS_BURN → Err; burned_asset_amount None → Err; burned < amount@36 → Err
    S->>X: validate_funds_out_transfer(req, validated)
    X->>X: legacy 0x1ad880b2: last != TS_TRANSFER → Err; total_output_amount < amount@68+commission@100 → Err

    Note over S: cfg("spv")
    S->>S: validated_consignment.as_ref() else Err(Spv)
    S->>C: lock header_chain
    S->>V: assert_chain_not_stale(now, 2h age, 2h future) → Err(Spv) if stale/future
    S->>V: assert_chain_net(validated.chain_net, chain.network()) → Err(Spv) on mismatch
    S->>V: validate_spv_proofs(witness_txids, merkle_proofs, MIN_CONF=6)
    V->>V: set-equality(expected, proofs); per proof: header_at, depth>=6, merkle root
    V-->>S: Ok | Err(Spv)

    S->>S: build_evm_domain(req)  (name="Tricorn", version="1", chain_id, proxy_contract)
    S->>S: digest = keccak(0x1901 || domainSep || structHash(callData,nonce,deadline))
    S->>K: state.sign_evm(digest)
    K->>K: with_active: Phase!=Active → Err(KeyNotInitialized)
    K-->>S: signature r||s||v (65 bytes)
    S-->>P: EvmSignatureResponse{signature}
    P-->>L: gRPC Signature
```

Annotations (non-obvious only):
- The `consignment_valid` proto field (#4) is **not read** anywhere in the decision
  after #47. Validation comes from the bytes, not the flag.
- `validate_funds_out_burn` / `validate_funds_out_transfer` each **no-op** for the
  selector that isn't theirs (early `Ok(())`), so calling both is safe — exactly
  one fires.
- ECDSA via `k256::sign_prehash_recoverable` is deterministic (RFC 6979): the same
  `(callData, nonce, deadline, domain)` always yields the same signature.

---

## 3. Trust boundaries

### 3a. User / listener-controlled inputs (every `SignEvmRequest` field is listener-supplied; the listener is **untrusted**)

| Field | Validated on-chain-of-custody in TEE? |
|---|---|
| `call_data` | Selector ∈ whitelist; for legacy, amount@68/commission@100 cross-checked vs declared fields. Recipient bytes **not** validated. |
| `nonce`, `deadline` | `deadline > now` checked. `nonce` **not** checked in TEE — on-chain `MultisigProxy` enforces ordering/consumption. |
| `consignment` + `consignment_hash` | `keccak256(consignment) == consignment_hash`; full rgbstd validation against Esplora. |
| `consignment_valid` (#4) | **Ignored** (not read). |
| `rgb_amount` (#5) | Legacy: lower-bounds `calldata_amount+commission`. Superseded as the authoritative amount by the consignment-derived check (`validate_funds_out_*`). |
| `rgb_asset_id` (#6) | Compared to pin **and** to consignment `contract_id` **only when non-empty** — see TEE-SE-01. |
| `chain_id`, `proxy_contract` (#7/#8) | Shape-checked; equality-pinned to `BridgeConfig` when configured. |
| `calldata_amount`, `calldata_commission` (#9/#10) | Legacy: must equal byte offsets 68/100. |
| `merkle_proofs` (#13) | Set-equality vs consignment witness txids + inclusion + depth ≥ 6. |

### 3b. Internal dependencies

| Dependency | Trust model |
|---|---|
| `rgbstd` validation | Trusted to validate consignment internal consistency + chain_net. Does **not** bind the consignment to the bridge's asset (no contract_id pin inside). |
| `HeaderChain` (SPV) | Built in-enclave from a compile-time checkpoint; only mutated by `SubmitHeaders` (separate flow, also listener-driven but PoW/work-validated). |
| `BridgeConfig` | Pinned from env at boot, committed into attestation `user_data` (#43). Authoritative for chain/contract/asset *when configured*. |
| `KeyManager` (Active) | Holds the seed in `SecretBox`; signs only in `Phase::Active`. |

### 3c. Off-chain assumptions

- The on-chain `MultisigProxy` consumes the EIP-712 `nonce` (and `burnId` on the
  contract side) so the TEE need not implement signing-replay protection. **If the
  contract's nonce/burnId semantics differ from the listener's, replay protection
  has a gap the TEE cannot see** (TEE-SE-08).
- The deployed `MultisigProxy` EIP-712 domain is `name="Tricorn"`, `version="1"`.
  **Assumed, not verified against the contract** (TEE-SE-05).
- The RGB asset's smallest unit maps 1:1 to USDT0's smallest unit (amount checks
  compare RGB units to EVM calldata units directly).

---

## 4. Invariants

| ID | Invariant | Class | Test |
|---|---|---|---|
| L-1 | A `fundsOut` signature is produced only if a consignment was validated **in-enclave** (listener `consignment_valid` is never trusted). | enforced (`evm_crosscheck.rs:107`; `server.rs:395`) | existing (`rejects_empty_consignment_even_with_valid_flag`, `ignores_consignment_valid_flag_when_bytes_present`) |
| L-2 | EVM release amount ≤ amount the RGB side destroyed (burn) or transferred (legacy), derived from the validated consignment. | enforced (`validate_funds_out_burn:290`, `validate_funds_out_transfer:357`) | existing (burn/transfer submodules) |
| L-3 | A `fundsOut` signature is bound to the pinned `chain_id` and bridge contract. | enforced *when configured* (`evm_crosscheck.rs:192-205`) | existing (`pinned_config_rejects_*`) |
| L-4 | The validated consignment's RGB contract is the bridge's pinned asset. | **violated** — bypassable when `req.rgb_asset_id` is empty (TEE-SE-01) | **missing** |
| L-5 | Every consignment witness tx is ≥ 6 confirmations deep in the validated header chain, and the proof set exactly equals the witness set. | enforced (`validate_spv_proofs`) | existing (spv_crosscheck tests) |
| L-6 | The consignment's network equals the enclave's network. | enforced (`assert_chain_net` + rgbstd `chain_net`) | existing |
| L-7 | The chain tip is fresh (≤ 2h old, ≤ 2h future) before signing. | enforced (`assert_chain_not_stale`) | existing (staleness tests) |
| L-8 | Signing requires `Phase::Active`. | enforced (`state.rs:343-345`) | existing (`sign_evm_on_initial_errors`) |
| L-9 | The EVM payload is bound to the RGB `OpId`. | **violated/absent** — no `op_id` in `SignEvmRequest`, never checked (TEE-SE-02) | **missing** |
| L-10 | The EVM recipient is bound to / derived from the validated RGB payload. | **violated/absent** — recipient is unvalidated calldata (TEE-SE-03) | **missing** |
| L-11 | The EIP-712 digest matches the deployed `MultisigProxy` domain. | assumed (hardcoded "Tricorn"/"1") | **missing** (no contract-derived fixture) |

---

## 5. Security questions (with answers)

- **Can a release be authorised for an RGB asset other than the bridge's?**
  **Yes**, when the listener sends an empty `rgb_asset_id`. The pin-match
  (`evm_crosscheck.rs:219`) and the consignment-`contract_id` check
  (`server.rs:360`) are both guarded by `!req.rgb_asset_id.is_empty()`, and the
  pinned `RGB_ASSET_ID` is never compared to the validated consignment's
  `contract_id` directly. A valid, confirmed burn/transfer of an unrelated RGB
  asset for ≥ the unlock amount would pass. → **TEE-SE-01**.
- **Can the same operation execute twice?** Not via the TEE: signatures are
  deterministic and replay consumption is on-chain (`nonce`/`burnId`). TEE has no
  signing-replay guard by design → confirm contract side (TEE-SE-08).
- **What is the unique identifier of the operation? Who assigns it?** The spec's
  cross-domain identifier is the RGB `OpId`; it is **not transmitted or bound** by
  the TEE (L-9). The on-chain side cannot rely on a TEE-checked `OpId`.
- **Can a signed payload be replayed on another chain/contract?** Domain binds
  `chainId` + `verifyingContract`; pinned when configured (L-3). Cross-chain replay
  is blocked **iff** `BridgeConfig` is configured.
- **Can signed fields change between signing and execution?** The TEE signs exactly
  `callData` it was given; recipient/amount inside `callData` are listener-chosen.
  Amount is bound to the consignment (L-2); **recipient is not** (L-10).
- **Can a wrong-network consignment be used?** No — `assert_chain_net` + rgbstd
  `chain_net` (L-6).
- **Can a frozen/old Bitcoin feed defeat SPV?** No — `assert_chain_not_stale` (L-7).
- **Can `block_height = u32::MAX` underflow the depth check?** No — `checked_sub`
  in `verify_one_proof` (`spv_crosscheck.rs:221`).
- **Does the digest match the contract?** Unverified (L-11) — domain name/version
  hardcoded.

---

## 6. Observations (fact → concern → mitigation/open)

- **O-1 (asset binding).** *Fact:* pinned `RGB_ASSET_ID` is compared only to the
  listener's `req.rgb_asset_id`, never to the validated consignment's `contract_id`;
  both comparisons skip on empty `req.rgb_asset_id`. *Concern:* the asset pin is
  defeatable by an untrusted listener, and the amount check (L-2) is in the
  *wrong asset's* units. *Mitigation:* **open** → TEE-SE-01.
- **O-2 (`<=` vs `==`).** *Fact:* L-2 enforces `release ≤ destroyed/transferred`,
  not the spec's strict `==`. *Concern:* a release strictly smaller than the burn
  silently passes; over-burn dust is unaccounted in-TEE. *Mitigation:* design
  decision → TEE-SE-04.
- **O-3 (vestigial field).** *Fact:* `consignment_valid` (#4) is no longer read.
  *Concern:* misleading wire contract; a future reader may think it's load-bearing.
  *Mitigation:* doc/cleanup → TEE-SE-07.
- **O-4 (u64 amount clamp).** *Fact:* `extract_uint256_as_u64` rejects any calldata
  amount > `u64::MAX` (`evm_crosscheck.rs:384`). *Concern:* a legitimate uint256
  amount > 2^64 is unsignable; wire types (`uint256` vs `u64`) are mismatched.
  *Mitigation:* design note → TEE-SE-09 (RGB amounts are u64, so low risk today).
- **O-5 (mint/burn inert).** *Fact:* the mint/burn selector path is correct but the
  production listener still emits the legacy 6-arg `fundsOut`; the burn path is
  exercised only by synthetic tests. *Concern:* no real-burn round-trip coverage.
  *Mitigation:* test gap → T-02.

---

## 7. Items

> Severity is a **draft** — final severity/owner set by a human (per methodology).

| ID | Type | Item | Suggested sev | Source | Status |
|---|---|---|---|---|---|
| TEE-SE-01 | Finding | Asset-identity bypass: empty `req.rgb_asset_id` skips both the pin match (`evm_crosscheck.rs:219`) and the consignment `contract_id` check (`server.rs:360`); the pinned `RGB_ASSET_ID` is never bound to the validated `contract_id`. A listener-supplied unrelated (but valid, confirmed, sufficiently-large) consignment can authorise a USDT0 unlock. **Fix (state the invariant, not a formula):** when `bridge_config.is_configured()`, require the *validated consignment's* `contract_id == bridge_config.rgb_asset_id`, independent of the listener field. | High (funds theft; listener-triggerable, and listener is untrusted) | §5 Q1, L-4, O-1 | open |
| TEE-SE-02 | Finding/design | RGB `OpId` not bound: no `op_id` field in `SignEvmRequest`, never extracted-for-decision nor put in the signed struct. Spec Sec 6/7/13 core primitive. | High | L-9; cross-ref `cross-flow-findings.md` | open (known) |
| TEE-SE-03 | Finding/design | EVM recipient not derived from / bound to the RGB payload (Sec 13). | Medium–High | L-10 | open (known) |
| TEE-SE-04 | Design question | Amount bind is `<=`, not the spec's strict `==`. Decide intended semantics. | Low–Medium | L-2, O-2 | open |
| TEE-SE-05 | Finding/design | EIP-712 domain `name`/`version` hardcoded `"Tricorn"`/`"1"` (`server.rs:553`); not verified against deployed `MultisigProxy`. | Medium | L-11 | open (known) |
| TEE-SE-06 | Design question | `SPV_MIN_CONFIRMATIONS = 6` for all networks; UTEXO signet has ~30s blocks (≈3 min at 6). Consider per-network depth. | Low–Medium | `spv_crosscheck.rs:41` | open (known) |
| TEE-SE-07 | Doc/cleanup | `consignment_valid` (proto #4) is vestigial; mark deprecated or remove. | Info | O-3 | open |
| TEE-SE-08 | Backend question | Confirm on-chain `MultisigProxy` `nonce`/`burnId` semantics match the listener-supplied `nonce` so signing-replay is fully covered off-TEE. | — | §3c | open |
| TEE-SE-09 | Observation | `uint256` calldata amount clamped to `u64`; document the assumption or widen. | Info | O-4 | open |

---

## 8. Tests

### Existing coverage mapped

| Invariant / question | Existing test |
|---|---|
| L-1 | `evm_crosscheck::tests::{rejects_empty_consignment_even_with_valid_flag, ignores_consignment_valid_flag_when_bytes_present}` |
| L-2 (burn) | `evm_crosscheck::tests::burn::{passes_when_burned_covers_*, rejects_when_burned_less_*, rejects_when_last_transition_is_not_burn, rejects_when_burned_asset_metadata_missing}` |
| L-2 (transfer) | `evm_crosscheck::tests::transfer::{passes_when_total_output_*, rejects_when_total_output_less_*, rejects_when_last_transition_is_not_transfer}` |
| L-3 | `evm_crosscheck::tests::{pinned_config_rejects_chain_id_mismatch, _proxy_contract_mismatch, _rgb_asset_mismatch, _partial_pin_missing_asset}` |
| L-5/L-6/L-7 | `spv_crosscheck::tests::*` (coverage, depth, merkle, chain_net, staleness) |
| L-8 | `state::tests::sign_evm_on_initial_errors` |

### Missing tests (negative / edge)

| ID | Test | Covers | Priority |
|---|---|---|---|
| T-01 | `pinned_config_rejects_empty_rgb_asset_id` — pinned `BridgeConfig`, request with `rgb_asset_id = ""` and a consignment whose `contract_id` ≠ pin; assert rejection. (Will fail until TEE-SE-01 is fixed — regression marker.) | TEE-SE-01 / L-4 | must-have |
| T-02 | Real-burn-fixture round-trip: a genuine `TS_BURN` consignment through `validate_consignment` + `validate_funds_out_burn`. | O-5 / L-2 | should-have |
| T-03 | `binds_consignment_contract_id_to_pin` — happy path asserting validated `contract_id == pinned RGB_ASSET_ID`. | TEE-SE-01 / L-4 | should-have |
| T-04 | Recipient-binding test (once TEE-SE-03 has a defined rule). | L-10 | blocked on design |
| T-05 | Contract-derived EIP-712 fixture: derive digest via Solidity `_hashTypedDataV4`, assert byte equality. | L-11 / TEE-SE-05 | should-have |

---

## 9. Status summary

- **Confirmed new finding:** 1 — **TEE-SE-01** (asset-identity bypass via empty
  `rgb_asset_id`), suggested High, code-traced (`evm_crosscheck.rs:212-224`,
  `server.rs:360`). Needs auditor attention + regression test T-01.
- **Carried known findings/design items:** TEE-SE-02 (OpId), TEE-SE-03 (recipient),
  TEE-SE-05 (EIP-712 domain) — all pre-mainnet, consistent with
  `cross-flow-findings.md`.
- **Open design questions:** TEE-SE-04 (`<=` vs `==`), TEE-SE-06 (per-network
  confirmations).
- **Strong / enforced:** in-enclave consignment validation (no boolean trust, L-1),
  consignment-bound amount (L-2), pinned chain/contract (L-3), SPV coverage+depth+
  freshness+network (L-5/6/7), Active-only signing (L-8). The `consignment_valid`
  bypass and the host-supplied amount gap are closed (#47/#44).
- **Missing tests:** T-01 (must-have, also a TEE-SE-01 regression marker), T-02,
  T-03, T-05.
- **Next:** confirm TEE-SE-01 severity and fix direction, then proceed to Step 2
  (attack analysis) for this flow, or run Step 1 on the Cloning flow.

---

### Self-verification checklist (review rules §12)

- [x] Every reject condition written as coded, not inverted (verified vs source lines).
- [x] No CEI claim made (N/A — no Solidity fund-moving fn here; signing path noted instead).
- [x] Every named fn/const exists in loaded code (grepped: `validate_funds_out_*`, `assert_chain_*`, `with_active`, `ifa::*`, `FUNDS_OUT_SELECTOR_*`).
- [x] Diagram order matches `handle_sign_evm` top-to-bottom.
- [x] Design questions (TEE-SE-04/06/08) not labelled findings; severities marked draft.
- [x] Invariants are violable safety properties, each classified + test status.
- [x] No assumptions stated as facts (off-chain assumptions in §3c).
- [x] Scope not exceeded (on-chain MultisigProxy/burnId explicitly deferred).
- [x] Asset wording: USDT0 (EVM) / pinned RGB asset; no non-standard-ERC20 invariants invented.
- [x] Better in-scope option suggested (TEE-SE-01 fix: bind `contract_id` to pin).
