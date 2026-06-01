# Step 2 — Attack Analysis & Implementation Spec — Sign PSBT (EVM → RGB lock)

**Input:** verified `Step 1 - sign_psbt.md`. **Code:** `dev` @ `bb2b396`.
**Reviewed:** 2026-05-29. Output is TEXT/specs (Step 3 = code).

---

## Phase 1 — Verification gate

Step 1 passes: diagram matches `handle_sign_psbt`→`sign_psbt` top-to-bottom; invariants
PS-1…PS-9 are violable properties with class + test status; trust boundaries identify
`witness_utxo.script_pubkey` as the only trusted PSBT field and the listener as the
untrusted source of all enrichment. Proceeding.

---

# Part A — Attack Analysis

## A.1 Invariant hypotheses

| Inv | Violation attempt | Verdict | Trace / guard |
|---|---|---|---|
| PS-1 | Make the enclave sign an input it doesn't co-own (fabricated `witness_script`) | **Dismissed** | `psbt.rs:53-54` `sha256(witness_script)==program` else Skip; test `skips_when_witness_script_does_not_hash_to_script_pubkey`. |
| PS-1 | Hide our key bytes inside a larger push to force a match | **Dismissed** | Exact 33-byte push check (`psbt.rs:58-62`); test `skips_when_pubkey_bytes_only_appear_inside_a_larger_push`. |
| PS-2 | Lie in `tap_key_origins`/`bip32_derivation` to point our fingerprint at a foreign key | **Dismissed** | `taproot.rs:84-105` requires fingerprint match **and** `derived_xonly==claimed`; tests `skips_when_origins_*`. |
| PS-1 | Splice a control block from a different tree | **Dismissed** | `control_block.verify_taproot_commitment` (`taproot.rs:63`); test `skips_when_control_block_does_not_verify`. |
| PS-3 | Induce a second signature on an already-signed input | **Dismissed** | skip-if-present (`taproot.rs:107`, `psbt.rs:45`). |
| PS-4 | Sign while `Initial`/`Cloning` | **Dismissed** | `with_active` (`state.rs:343-345`). |
| PS-9 | Crash/confuse the signer with non-PSBT bytes | **Dismissed** | shape whitelist (`psbt_crosscheck.rs:30-39`). |
| PS-6 | Co-sign a federation spend with **no real EVM deposit** | **Confirmed → TEE-PS-01** | bridge mode trusts `evm_event_valid`/`evm_event_finalized` (`psbt_crosscheck.rs:59-70`); no in-enclave EVM proof. |
| PS-7 | Co-sign a spend whose **outputs go to an attacker** | **Confirmed → TEE-PS-02** | no output inspection anywhere; `psbt_output_amount` declared-vs-declared (`:73-84`). |
| PS-8 | Skip bridge checks entirely | **Confirmed → TEE-PS-03** | `evm_tx_hash==""` ⇒ vanilla, returns `Ok` before any bridge check (`:42-45`); the field is listener-controlled. |

## A.2 Actor capability matrix (C/O/Re/Rp/D/F)

| Actor | C | O | Re | Rp | D | F | Notes |
|---|---|---|---|---|---|---|---|
| Normal user | partial | – | – | – | – | – | Supplies a deposit upstream; not a direct TEE caller. |
| MEV / sequencer | – | – | – | – | – | – | **Not involved**. |
| **Compromised listener/coordinator** | **PSBT bytes + all enrichment + mode** | sigs | yes | n/a (UTXO dedupe) | yes | **partial** | Can set outputs, select vanilla, lie about EVM event. **Cannot** forge an anchored input the enclave doesn't co-own (PS-1/2). |
| Compromised TEE signer (seed leaked) | n/a | n/a | n/a | n/a | n/a | total | Out of flow → key-mgmt. |
| Other federation cosigners | – | – | – | – | – | – | **Out of repo**; their output policy determines end-to-end safety. |
| Operator mistake | dev-mode build | – | – | – | – | – | dev-mode skips `validate_psbt_request` (compile-excluded from release). |

## A.3 Actor × invariant cross-check

- **Compromised listener/coordinator** → breaks **PS-6, PS-7, PS-8** (host-trusted
  policy). It **cannot** break PS-1/PS-2/PS-3/PS-9 (cryptographic anchoring holds).
- Net: the adversary cannot steal a UTXO the enclave doesn't co-own, but **can** get
  the enclave to co-sign a spend of co-owned federation UTXOs to arbitrary outputs
  with no real deposit — execution gated only by the federation threshold (other
  cosigners) → cross-flow.

### Headline confirmed attack
**AV-1 — coordinator drains federation UTXOs.** A compromised coordinator constructs a
PSBT spending federation multisig UTXOs the enclave co-owns, with attacker-controlled
outputs, and sends it in **vanilla mode** (`evm_tx_hash=""`) — or bridge mode with
both booleans `true` and a consistent declared amount. The enclave validates shape,
finds its inputs anchored (PS-1), and **co-signs**. Impact: contributes a valid
federation signature toward an unauthorised spend; end-to-end success depends on the
M-of-N threshold and whether other cosigners enforce output policy. Root: **TEE-PS-02
+ TEE-PS-03 (+ TEE-PS-01)**. This mirrors `Step 2 - sign_evm.md` AV-1: cryptographic
guarantee sound, **bridge policy host-trusted**.

## A.4 Summary

**New items (all Part A, flow-specific):** TEE-PS-01 (EVM-event trust, design),
TEE-PS-02 (no output binding, Med–High), TEE-PS-03 (mode bypass, Med), TEE-PS-04
(unused enrichment fields, Info). Same root cause: **input anchoring enforced, bridge
policy not.**

**Dismissed (one-line):** PS-1 fabricated script / hidden push (hash + exact-push);
PS-2 lying origins (derived==claimed); control-block splice (commitment verify); PS-3
double-sign (skip-if-present); PS-4 (with_active); PS-9 (shape whitelist). All
adversarially tested.

**Deferred to Layer 2 / out-of-flow:**
- Whether other federation cosigners enforce output destination/amount policy, and the
  M-of-N threshold (contracts + federation ops). The shared-seed cluster contributes
  one logical signature (cross-ref `Step 2 - sign_evm.md` A.4 / `Step 1 - cloning.md`).
- In-enclave EVM-event verification feasibility (would need an EVM light-client / log
  proof in the TEE — a large design item, not a quick fix).

**Threat-model note:** the PSBT flow's security is **"anchored signing,"** not
**"policy-validated signing."** The enclave guarantees *"I only co-sign inputs I
legitimately own"* — it does **not** guarantee *"this transaction is a legitimate
bridge operation to the right destination."* The unlock direction closed that gap
(RGB+SPV+amount); the lock direction has not. This is the single most important
architectural finding of the flow and is a **spec/design decision**, not a code bug.

---

# Part B — Implementation Spec (for Step 3)

## LIST 1 — Missing unit tests

| # | Test | Setup → Action → Assert | Source | Priority |
|---|---|---|---|---|
| U-1 | `vanilla_mode_bypasses_bridge_checks` | bridge-shaped request, `evm_tx_hash=""`, `evm_event_valid=false` → still `Ok`. Documents the bypass (regression once mode is fixed). | TEE-PS-03 | must-have |
| U-2 | `amount_check_is_declared_not_psbt_bound` | declared `psbt_output_amount` ≠ actual PSBT output sum → currently `Ok`. Documents TEE-PS-02. | TEE-PS-02 | should-have |
| U-3 | (exists) anchoring + shape suite | mapped in Step 1 §8 | PS-1/2/3/9 | n/a |

## LIST 2 — Fuzz / property tests

| # | Property | Target / bounds | Assert | Source |
|---|---|---|---|---|
| F-1 | Anchoring: a job is emitted **iff** the candidate key is committed under `script_pubkey`. | `find_taproot_sign_jobs` / `should_sign_segwit_input`; random scripts, origins, control blocks | sign ⇒ on-chain commitment contains derived key | PS-1/PS-2 |
| F-2 | No double-sign across arbitrary pre-populated `partial_sigs`/`tap_script_sigs`. | both signers | already-present ⇒ Skip | PS-3 |
| F-3 | Shape whitelist: random byte strings | `validate_psbt_request` | non-PSBT / 0-input ⇒ `CrossCheck` | PS-9 |
| F-4 | (post-fix) output binding: random outputs vs declared destination | once TEE-PS-02 rule exists | mismatch ⇒ reject | TEE-PS-02 |

## LIST 3 — E2E / integration tests

| # | Scenario | Setup | Assert | Source |
|---|---|---|---|---|
| E-1 | Happy-path federation cosign (taproot + P2WSH multisig the enclave is part of) | real PSBT fixture | `inputs_signed` == owned inputs; signatures verify | PS-1 |
| E-2 | AV-1 regression (post-design): coordinator PSBT to attacker outputs, vanilla mode | crafted PSBT | reject (once TEE-PS-02/03 land) | TEE-PS-02/03 |
| E-3 | Multi-input PSBT mixing owned + foreign inputs | mixed PSBT | signs only owned, leaves foreign untouched | PS-1 |

## LIST 4 — Attack vectors (consolidated)

| # | Actor | Scenario | Impact | Current defense | Required fix / risk | Source |
|---|---|---|---|---|---|---|
| AV-1 | Coordinator | Co-sign federation-UTXO spend to attacker outputs (vanilla or lying booleans) | Funds drain (threshold-gated) | input anchoring only; **no output check** | bind outputs to bridge op (TEE-PS-02); make mode non-attacker-selectable (TEE-PS-03) | A.3 |
| AV-2 | Listener | Co-sign a federation spend with **no real EVM deposit** | Unbacked lock/mint | trusted booleans | in-enclave EVM-event proof or explicit accepted-risk (TEE-PS-01) | PS-6 |
| AV-3 | Listener | Downgrade any bridge op to vanilla to skip checks | bypass policy | none (mode = listener field) | derive mode from a trusted signal, not `evm_tx_hash` presence (TEE-PS-03) | PS-8 |

## LIST 5 — Formal verification

| # | Property | Target | Assumptions | Tool | Expected |
|---|---|---|---|---|---|
| FV-1 | sign(input) ⇒ `script_pubkey` commits to a script containing the derived key. | `find_taproot_sign_jobs`, `should_sign_segwit_input` | bitcoin crate hash/commitment correct | Kani / property | prove |
| FV-2 | No signature is added for an already-signed (key, input/leaf). | both signers | — | Kani | prove |
| FV-3 | (post-fix) signed ⇒ outputs match the bound destination/amount. | output-binding logic | TEE-PS-02 rule defined | property | counterexample until fix |

---

## Summary

- **New items:** TEE-PS-01 (EVM-event trust — design), TEE-PS-02 (no output binding —
  Med–High), TEE-PS-03 (mode bypass — Med), TEE-PS-04 (unused fields — Info).
- **Counts:** L1 2 new unit · L2 4 fuzz · L3 3 E2E · L4 3 attack vectors · L5 3 FV.
- **Deferred to Layer 2:** federation threshold / other cosigners' output policy;
  in-enclave EVM-event verification feasibility; shared-seed quorum interaction.
- **Top decision for the team:** TEE-PS-01 — *is the enclave a policy-enforcing signer
  or an anchored-only cosigner?* The answer determines whether TEE-PS-02/03 are bugs
  or accepted risks. Everything else (anchoring) is already strong.

### Self-verification (review rules §12 + Step 2 Phase 4)
- [x] Every Confirmed/Dismissed cites code lines; dismissals name the guard + test.
- [x] No invented symbols; all from Step 1's verified scope.
- [x] New vs design separated; TEE-PS-01 framed as a decision, not a severity-tagged bug.
- [x] Cross-flow (threshold, EVM light-client, quorum) → Layer 2.
- [x] Part B = specs not code; output/EVM-event tests marked blocked-on-design.
- [x] Anchoring strength stated honestly alongside the policy gap.
