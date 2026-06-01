# Step 2 — Attack Analysis & Implementation Spec — Sign EVM (`fundsOut` unlock)

**Input:** verified `Step 1 - sign_evm.md`. **Code:** `dev` @ `bb2b396`.
**Reviewed:** 2026-05-29. Output is TEXT/specs (Step 3 = code).

---

## Phase 1 — Verification gate

Step 1 passes the gate: diagram matches `handle_sign_evm` top-to-bottom; invariants
L-1…L-11 are violable safety properties with class + test status; trust boundaries
name the controller of every field; items are classified finding/design/test-gap.
Proceeding.

---

# Part A — Attack Analysis

## A.1 Invariant hypotheses (one row per attempted violation)

| Inv | Violation attempt | Verdict | Trace / guard |
|---|---|---|---|
| L-1 | Listener sends `consignment_valid=true` + empty bytes to skip validation | **Dismissed** | `evm_crosscheck.rs:107` rejects empty consignment; `server.rs:395` requires `validated_consignment.is_some()` for any fundsOut selector. |
| L-1 | Listener forges `consignment`+matching `consignment_hash` to fake integrity | **Dismissed (not the gate)** | Both fields are listener-controlled; the hash is transport-integrity only. The real gate is `rgbstd` validation (`rgb.rs:272`) against the SPV-backed chain. Forged bytes that aren't a valid consignment fail `Transfer::load`/`validate`. |
| L-1 | Esplora unavailable at boot → `rgb_validator = None` → sign without validation | **Dismissed (now fail-closed)** | `main.rs:94-97` sets `None` on error; `server.rs:395` then rejects fundsOut. Effect is DoS, not bypass. (Robustness item: prefer panic-at-boot — see TEE-SE-13.) |
| L-2 | Forge a large `burned_asset_amount` / `total_output_amount` | **Dismissed** | Values come from the `rgbstd`-validated transition (`rgb.rs:346`,`:404`); `checked_add` guards overflow (`rgb.rs:350`). You can only burn/transfer units you actually own under the contract. |
| L-2 | Cross-asset: burn a worthless RGB asset to unlock USDT0 | **Already identified — TEE-SE-01** | The amount integrity holds *per asset*; the asset is not bound (L-4). See A.3 AV-1. |
| L-3 | Unpinned/partial config lets listener pick chain/contract | **Dismissed (fail-closed)** | Partial config → `evm_crosscheck.rs:212` "set all three or none", or proxy_contract≠`[0;20]` mismatch. *Fully* unconfigured is a separate operator issue → **TEE-SE-12 (new)**. |
| L-4 | Empty `req.rgb_asset_id` skips asset binding | **Already identified — TEE-SE-01** | `evm_crosscheck.rs:219` and `server.rs:360` both guard on `!req.rgb_asset_id.is_empty()`; pin is never compared to `v.contract_id`. |
| L-5 | Forge a merkle proof / header with a fake root | **Dismissed on PoW nets / Deferred L2 on signet** | Proofs verified against the in-enclave PoW-validated chain (`spv_crosscheck.rs:211-289`). On signet/regtest PoW is skipped → header chain forgeable → SPV backstop weak. Cross-flow (SubmitHeaders + network choice) → **Layer 2**. |
| L-5 | Degenerate consignment with empty witness set → SPV no-op | **Dismissed (unreachable for Transfer)** | A valid `Transfer` has ≥1 witness bundle, each with a `witness_id` (`rgb.rs:207-225`); empty set can't arise from a validated transfer. |
| L-5 | `block_height = u32::MAX` underflows depth | **Dismissed** | `checked_sub` in `verify_one_proof` (`spv_crosscheck.rs:221`). |
| L-6 | Regtest consignment to mainnet enclave | **Dismissed** | Double-enforced: `rgbstd` `chain_net` + `assert_chain_net` (`spv_crosscheck.rs:185`). |
| L-7 | Frozen/old header feed | **Dismissed (logic) but depends on clock** | `assert_chain_not_stale` rejects (`spv_crosscheck.rs:166`). Relies on `SystemTime::now()` (`server.rs:429`); if the host controls the enclave clock the check is defeatable → **TEE-SE-11 (new)**. |
| L-7 | Header `time` far in future | **Dismissed** | Future-skew bound 2h (`spv_crosscheck.rs:151-158`). |
| L-8 | Sign while `Initial`/`Cloning` | **Dismissed** | `with_active` → `KeyNotInitialized` (`state.rs:343-345`). |
| L-9 | Unrelated consignment, no `OpId` link to the EVM payload | **Already identified — TEE-SE-02** | No `op_id` in `SignEvmRequest`; `all_op_ids`/`last_transition.op_id` extracted (`rgb.rs:328-340`) but never compared. Full fix crosses to on-chain lock-record (Sec 11) → also Layer 2. |
| L-10 | Listener sets attacker recipient in `call_data` | **Already identified — TEE-SE-03** | Recipient is unvalidated calldata; never derived from the consignment. |
| L-11 | Wrong EIP-712 domain | **Dismissed to DoS / Already identified — TEE-SE-05** | Wrong `name`/`version` → `ecrecover` wrong addr → contract rejects (DoS, not theft). Cross-protocol collision cryptographically infeasible. Verify-against-contract gap = TEE-SE-05, **expanded** to include the calldata offset assumptions (legacy 68/100, mint/burn 36) which are likewise unverified against the deployed ABI. |
| (cross) | Mint/burn `amount@36` mis-read if deployed ABI differs | **Confirmed latent — merged into TEE-SE-05** | `MINTBURN_AMOUNT_OFFSET=36` (`evm_crosscheck.rs:47`) assumes recipient@slot0, amount@slot1; path inert in prod, asserted only in comments. Same root cause as the EIP-712 fixture gap. |

## A.2 Actor capability matrix

Capabilities w.r.t. this flow. **C**ontrol inputs / **O**bserve / **Re**order / **Rp** Replay / **D**elay / **F**ake.

| Actor | C | O | Re | Rp | D | F | Notes |
|---|---|---|---|---|---|---|---|
| Normal user | partial | – | – | – | – | – | Only supplies their own consignment/burn upstream; not a direct TEE caller. |
| MEV bot / sequencer | – | – | – | – | – | – | **Not involved** (on-chain EVM concern). |
| **Compromised backend (Go Listener)** | **all** req fields | yes | yes | yes | yes | partial | **Primary adversary.** Can't fake an `rgbstd`-valid consignment without owning assets, nor fake PoW headers on mainnet. |
| Compromised TEE signer (seed leaked) | n/a | n/a | n/a | n/a | n/a | **total** | Signs anything offline. Out of this flow → key-mgmt / cloning / attestation. |
| Broken TEE attestation (enclave compromised) | – | – | – | – | – | total | Out of scope → attestation flow. |
| Compromised federation signer | – | – | – | – | – | 1-of-M | One on-chain signature. **Note:** the TEE *cluster* shares one seed → contributes a single logical signature; on-chain quorum security depends on other independent signers → Layer 2. |
| Malicious/unavailable Esplora | content of resolver replies | – | – | – | yes | yes | Mitigated by SPV on PoW nets; unavailability = DoS. |
| Operator/admin mistake | boot env | – | – | – | – | – | Unconfigured `BridgeConfig` → no pinning (TEE-SE-12). |

## A.3 Actor × invariant cross-check (which capability breaks which invariant)

- **Compromised listener × Control** → breaks **L-4** (TEE-SE-01), **L-9** (TEE-SE-02),
  **L-10** (TEE-SE-03). These are the live single-actor breaks. L-1/L-2/L-3/L-5(mainnet)/
  L-6/L-8 hold against it.
- **Compromised listener × Control(clock via host)** → breaks **L-7** *iff* the enclave
  clock is host-controllable (TEE-SE-11).
- **Operator × boot env** → disables **L-3** and **L-4** pinning entirely (TEE-SE-12).
- **Malicious Esplora × Fake** → breaks **L-5/L-1** only on non-PoW networks (Layer 2).
- **Compromised seed/attestation** → breaks all (out-of-flow).

### Headline confirmed attack (combined)

**AV-1 — listener drains USDT0.** A compromised listener submits: `rgb_asset_id=""`
(skips L-4), a genuine, 6-confirmation-deep burn of a *worthless* RGB asset for ≥ the
target amount (satisfies L-1/L-2/L-5/L-6/L-7), `chain_id`/`proxy_contract` = the real
pinned values (satisfies L-3), and `call_data` whose recipient = attacker (L-10 unbound).
The TEE returns a valid `fundsOut` signature. On-chain execution then depends on the
remaining M-1 federation signatures + the Sec 11 lock-record check — so end-to-end
severity is **cross-flow**, but the TEE contributes a fully valid signature it should
have refused. Root: **TEE-SE-01 + TEE-SE-03 (+ TEE-SE-02)**.

## A.4 Summary

**New items (Part A):**
- **TEE-SE-11** (design/platform question) — L-7 staleness + deadline depend on a
  trustworthy enclave wall clock; `server.rs:429`, `evm_crosscheck.rs:228` use
  `SystemTime::now()`. Verify the Nitro enclave clock is not host-settable. Suggested Medium.
- **TEE-SE-12** (design/ops) — fully unconfigured `BridgeConfig` only warns
  (`main.rs:47-53`) and runs in listener-trusting mode (no chain/contract/asset pin).
  Consider fail-closed when `spv`/`rgb-validation` are enabled. Suggested Medium.
- **TEE-SE-13** (robustness) — `rgb_validator=None` (Esplora boot failure) degrades to
  fundsOut-DoS; prefer panic-at-boot so the failure is loud. Suggested Low.

**Expanded:** TEE-SE-05 now also covers the unverified calldata offset assumptions
(legacy 68/100, mint/burn 36), same root cause as the EIP-712 fixture gap.

**Dismissed (one-line each):** L-1 hash-only (rgbstd is the gate); L-2 overflow
(`checked_add`); L-3 partial config (fail-closed); L-5 empty-set (unreachable) /
u32::MAX (`checked_sub`); L-6 (double-enforced); L-7 future-skew (2h bound); L-8
(`with_active`); L-11 cross-protocol (infeasible).

**Linked to existing IDs:** L-4→TEE-SE-01, L-9→TEE-SE-02, L-10→TEE-SE-03, L-11→TEE-SE-05.

**Deferred to Layer 2 (cross-flow):**
- Non-PoW (signet/regtest) header chains weaken the SPV backstop vs malicious Esplora
  (SubmitHeaders + network choice).
- Shared-seed TEE cluster contributes one logical signature; quorum security rests on
  other independent on-chain signers + Sec 11 lock-record (MultisigProxy + cloning).
- Full `OpId` mitigation needs both the TEE binding and the on-chain lock-record check.

**Threat-model notes:** the dominant adversary is the untrusted listener; its `Control`
capability is the through-line for every live break (L-4/9/10). The enclave's defenses
that *do* hold against it (in-enclave RGB validation, consignment-bound amount, pinned
chain/contract, SPV) are exactly the host-trust-removal the spec (Sec 6.2) demands —
the gaps are the semantic fields not yet derived from the consignment (asset, recipient,
OpId).

---

# Part B — Implementation Spec (for Step 3)

Every Step 1 + Part A item is accounted for below or marked docs/design.

## LIST 1 — Missing unit tests

| # | Test | Setup → Action → Assert | Source | Priority |
|---|---|---|---|---|
| U-1 | `pinned_config_rejects_empty_rgb_asset_id` | pinned `BridgeConfig`; request with `rgb_asset_id=""` + `ValidatedConsignment{contract_id != pin}` → `handle_sign_evm`/`validate` path → assert `CrossCheck`. **Regression marker: fails until TEE-SE-01 fixed.** | TEE-SE-01 / L-4 | must-have |
| U-2 | `binds_consignment_contract_id_to_pin` | pinned config; `contract_id == pin`, `rgb_asset_id=""` → assert OK (post-fix). | TEE-SE-01 / L-4 | should-have |
| U-3 | `unconfigured_bridge_config_is_rejected_for_fundsout` (post-fix) or `..._documents_legacy_passthrough` (pre-fix) | `BridgeConfig` all-empty → assert behaviour matches TEE-SE-12 decision. | TEE-SE-12 | should-have |
| U-4 | `mintburn_amount_offset_matches_documented_layout` | synthetic 8-arg calldata; assert `amount@36` extracted == intended; pin offset against the contract ABI fixture. | TEE-SE-05 | should-have |
| U-5 | (exists) selector/consignment/amount/pin tests | — already in `evm_crosscheck::tests` | L-1/2/3 | n/a (mapped) |

## LIST 2 — Fuzz / property tests

| # | Invariant | Target / bounds | Assert | Source |
|---|---|---|---|---|
| F-1 | L-2 (burn) | `validate_funds_out_burn`; burned ∈ [0,2^64), amount@36 ∈ [0,2^64) | OK iff `amount ≤ burned`; type==TS_BURN; meta present | L-2 |
| F-2 | L-2 (transfer) | `validate_funds_out_transfer`; total_output, amount, commission ∈ [0,2^64) | OK iff `amount+commission ≤ total_output` (and no overflow) | L-2 |
| F-3 | L-5 | `validate_spv_proofs`; random txid sets + depths | OK iff proof-set == witness-set ∧ all depth≥6 ∧ merkle valid | L-5 |
| F-4 | L-4 (violated) | asset-id binding; random `req.rgb_asset_id` incl. "" vs `contract_id`/pin | **should FAIL until TEE-SE-01 fixed** (regression) | TEE-SE-01 |
| F-5 | `extract_uint256_as_u64` | random 32-byte words | reject iff any high-24-byte set | TEE-SE-09 |

## LIST 3 — E2E / integration tests

| # | Scenario | Chain / setup | Assert | Source | Note |
|---|---|---|---|---|---|
| E-1 | Happy-path unlock | real `Transfer` consignment + SPV proofs + pinned config; Esplora fixture/mock | `EvmSignatureResponse`; recoverable sig over expected digest | L-1/2/3/5 | needs Esplora mock |
| E-2 | AV-1 regression | compromised-listener: `rgb_asset_id=""` + unrelated valid consignment | `CrossCheck` (post-fix) | TEE-SE-01/03 | regression marker |
| E-3 | Real-burn round-trip | genuine `TS_BURN` consignment → `validate_consignment`+`validate_funds_out_burn` | burned amount bound | TEE-SE-04 / O-5 | cross-repo fixture |
| E-4 | Contract-derived EIP-712 + calldata offsets | digest via Solidity `_hashTypedDataV4`; offsets vs deployed ABI | byte-equality | TEE-SE-05 | cross-repo |

## LIST 4 — Attack vectors (consolidated)

| # | Actor | Scenario | Impact | Current defense | Required fix / risk | Source |
|---|---|---|---|---|---|---|
| AV-1 | Listener | empty `rgb_asset_id` + worthless-asset burn + attacker recipient → valid `fundsOut` sig | Funds theft (cross-flow execution) | amount/SPV/chain/contract bound; **asset+recipient not** | bind `contract_id`==pin (TEE-SE-01), bind recipient (TEE-SE-03), bind OpId (TEE-SE-02) | A.3 |
| AV-2 | Listener + host clock | stale headers + manipulated enclave clock defeat staleness | accept stale Bitcoin state | `assert_chain_not_stale` (clock-dependent) | verify enclave clock trust (TEE-SE-11) | L-7 |
| AV-3 | Operator | deploy without env → no pinning | listener controls chain/contract/asset | warn-only at boot | fail-closed when spv/rgb on (TEE-SE-12) | L-3/4 |
| AV-4 | Malicious Esplora | lie during rgbstd validation | bad consignment accepted | SPV backstop (PoW nets only) | non-PoW net hardening → Layer 2 | L-5 |
| AV-5 | Listener | OpId/recipient substitution within pinned bridge | wrong unlock | none for OpId/recipient | TEE-SE-02 / TEE-SE-03 | L-9/10 |

## LIST 5 — Formal verification

| # | Property | Target | Assumptions | Tool | Expected |
|---|---|---|---|---|---|
| FV-1 | release amount ≤ consignment-derived amount | `validate_funds_out_{burn,transfer}` | validated consignment well-formed | Kani / property test | prove |
| FV-2 | fundsOut ⇒ validated consignment present | `validate_evm_request` + handler | rgb-validation build | Kani | prove |
| FV-3 | asset binding: signed ⇒ `contract_id`==pin | handler+crosscheck | configured | Kani | **counterexample (empty rgb_asset_id) until TEE-SE-01 fix → then prove** |
| FV-4 | SPV: signed ⇒ ∀ witness tx depth≥6 ∧ proof-set==witness-set | `validate_spv_proofs` | honest PoW chain | property test | prove (deferred non-PoW) |

---

## Summary

- **New items from Part A:** TEE-SE-11 (clock trust, Med), TEE-SE-12 (unconfigured =
  no pinning, Med), TEE-SE-13 (validator-None robustness, Low). TEE-SE-05 expanded.
- **Counts:** L1 4 unit · L2 5 fuzz · L3 4 E2E · L4 5 attack vectors · L5 4 FV.
- **Deferred to Layer 2:** non-PoW SPV backstop, shared-seed quorum, full OpId
  (TEE-side + on-chain lock-record).
- **Docs-only / design decisions:** TEE-SE-04 (`<=` vs `==`), TEE-SE-06 (per-net
  depth), TEE-SE-07 (vestigial `consignment_valid`), TEE-SE-08 (on-chain nonce
  semantics — backend question), TEE-SE-09 (u64 amount clamp).
- **Top priority for Step 3:** U-1 + the TEE-SE-01 fix (bind `contract_id` to pinned
  `RGB_ASSET_ID`), then E-2 and the TEE-SE-02/03 bindings.

### Self-verification (review rules §12 + Step 2 Phase 4)
- [x] Every "Confirmed/Already identified" cites code lines; no "probably".
- [x] No invented functions (all symbols verified in Step 1 + grep).
- [x] New findings not duplicating Step 1 — TEE-SE-11/12/13 are genuinely new; cross-asset/OpId/recipient linked to existing IDs.
- [x] Same-root-cause merged (calldata offsets → TEE-SE-05).
- [x] Cross-flow concerns → Layer 2, not single-flow findings.
- [x] Severities marked draft; design questions not labelled findings.
- [x] Part B = specs, not code; violated-invariant fuzz (F-4) marked regression-until-fix.
- [x] Asset wording USDT0/pinned-RGB; no non-standard-ERC20 vectors invented.
