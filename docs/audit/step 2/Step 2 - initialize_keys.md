# Step 2 — Attack Analysis & Implementation Spec — Initialize Keys

**Input:** verified `Step 1 - initialize_keys.md`. **Code:** `dev` @ `c51d6fb`.
**Reviewed:** 2026-05-29. Output is TEXT/specs (Step 3 = code).

---

## Phase 1 — Verification gate

Step 1 passes: diagram matches `handle_initialize`→`generate`→`from_seed`; invariants
IK-1…IK-8 are violable properties with class + test status; trust boundaries note the
unauthenticated caller and the feature-gated import paths. Proceeding.

---

# Part A — Attack Analysis

## A.1 Invariant hypotheses

| Inv | Violation attempt | Verdict | Trace / guard |
|---|---|---|---|
| IK-1 | Re-initialize an `Active` enclave to swap the seed | **Dismissed** | `ensure_initial` → `AlreadyInitialized` (`state.rs:350-355`); tests cover double-init + post-cloning. |
| IK-2 | Import a chosen seed/mnemonic in production | **Dismissed (correct build) / Confirmed if mis-built → TEE-IK-01** | `not(allow-seed-import)` → `InvalidRequest` (`server.rs:164-169,190-195`); but no `compile_error!` prevents enabling it (grep). |
| IK-3 | Bias the generated seed | **Dismissed** | 256-bit `getrandom` + BIP-39 (`handle_initialize:172-174`); attacker has no input on the entropy path. |
| IK-4 | Recover the seed from memory/logs | **Dismissed (in-scope)** | `SecretBox` + zeroize of transients (`keys.rs`); response logs only public fields. Mem-dump/side-channel = platform. |
| IK-5 | Make derivation non-deterministic / wrong path | **Dismissed** | fixed BIP-32 paths; `deterministic_derivation`, `from_mnemonic_matches_seed_derivation`. |
| IK-7 | Ship a dev feature in release | **Confirmed gap → TEE-IK-01** | no `compile_error!(... not(debug_assertions))` for `allow-seed-import`/`dev-mode`/`mock-attestation`. |
| IK-1 (timing) | Front-run the operator's init on a fresh enclave | **Confirmed low-impact → TEE-IK-02** | no auth on `InitializeKey`; entropy mode self-generates random seed; attestation verification detects identity. |

## A.2 Actor capability matrix (C/O/Re/Rp/D/F)

| Actor | C | O | Re | Rp | D | F | Notes |
|---|---|---|---|---|---|---|---|
| **Compromised parent** | trigger init / (if mis-built) supply seed | pubkeys | – | re-init → `AlreadyInitialized` | yes (withhold) | **only if `allow-seed-import` shipped** | Otherwise reduces to "trigger a random self-gen" (low) + DoS. |
| Operator mistake | **build flags** (ship `allow-seed-import`/`dev-mode`/`mock`) | – | – | – | – | – | The decisive actor for TEE-IK-01. |
| Normal user / MEV / federation | – | – | – | – | – | – | **Not involved.** |
| NSM RNG | n/a | n/a | n/a | n/a | n/a | total | Entropy trust root (platform). |

## A.3 Actor × invariant cross-check

- **Compromised parent (correct build)** → breaks **nothing**: import rejected (IK-2),
  re-init rejected (IK-1), entropy unbiased (IK-3). Residual: trigger a random self-gen
  (IK-2/TEE-IK-02, low) + withhold (DoS).
- **Operator ships `allow-seed-import`** → breaks **IK-2/IK-7** → parent installs a
  chosen seed on a fresh enclave → **total key compromise** (TEE-IK-01). A *build*
  event, like the mock-attestation gap (TEE-CL-02).
- **NSM RNG compromise** → breaks IK-3 (out of scope — platform).

### Headline conclusion
In a **correct production build** this flow has **no attacker-side break**: one-shot,
entropy-only, deterministic, with strong seed hygiene. The entire risk is the **build
configuration**: three dangerous dev features (`allow-seed-import`, `dev-mode`,
`mock-attestation`) lack a release guard. **TEE-IK-01 + TEE-CL-02 are the same class**
and should be fixed together with one `compile_error!` pattern.

## A.4 Summary

**New items:** TEE-IK-01 (no release guard for dev features — High-if-shipped, the
`allow-seed-import` case catastrophic), TEE-IK-02 (unauthenticated init — Low).

**Carried:** TEE-IK-04 (`expose_seed`), TEE-IK-05 (master vs account fingerprint),
TEE-IK-06 (INFO logging) — all Low/Info.

**Dismissed (one-line):** re-init (`AlreadyInitialized`); entropy bias (no attacker
input); seed recovery (SecretBox/zeroize); non-determinism (fixed paths); import in a
correct build (feature gate).

**Deferred to Layer 2 / out-of-flow:** NSM RNG quality; cloning (additional enclaves,
`Step 2 - cloning.md`).

**Threat-model note:** key-genesis security is a **build-time property** here, not a
runtime one. The defenses are correct; the missing piece is making the unsafe build
*impossible* rather than merely *not-the-default*. This is the third instance of the
"dangerous dev feature, no release guard" pattern (with `mock-attestation` and
`dev-mode`) — a single cross-flow item.

---

# Part B — Implementation Spec (for Step 3)

## LIST 1 — Missing unit tests

| # | Test | Setup → Action → Assert | Source | Priority |
|---|---|---|---|---|
| U-1 | `default_build_rejects_seed_and_mnemonic_import` | default features; `InitializeKey{seed}` and `{mnemonic}` → `InvalidRequest "not allowed"`. | IK-2 / TI-1 | must-have |
| U-2 | `double_init_rejected_from_active_and_cloning` | (exists) keep as regression for IK-1. | IK-1 | n/a |
| U-3 | `entropy_init_yields_wellformed_bundle` | entropy path → evm_address 20B, xpubs parse, fingerprint 4B. | IK-3/IK-5 / TI-3 | should-have |

## LIST 2 — Fuzz / property tests

| # | Property | Target / bounds | Assert | Source |
|---|---|---|---|---|
| F-1 | Derivation determinism: same seed ⇒ identical EVM/BTC/BIP-86 keys; different seeds ⇒ different. | `from_seed`; random seeds | deterministic + injective | IK-5 |
| F-2 | `evm_address == keccak256(uncompressed_pub[1..])[12..]` for random seeds. | `from_seed` | address derivation correct | IK-5 |

## LIST 3 — E2E / integration tests

| # | Scenario | Setup | Assert | Source |
|---|---|---|---|---|
| E-1 | First-enclave init → attested-pubkey verify | entropy init, then `verify_attested_pubkey` | the generated identity attests cleanly | IK-3 + AP-flow |
| E-2 | Re-init attempt after Active rejected over the wire | init, then second `InitializeKey` | `AlreadyInitialized` | IK-1 |

## LIST 4 — Attack vectors (consolidated)

| # | Actor | Scenario | Impact | Current defense | Required fix / risk | Source |
|---|---|---|---|---|---|---|
| AV-1 | Operator(build) + parent | Release ships `allow-seed-import`; parent calls `InitializeKey{seed=attacker}` on a fresh enclave | **Total key compromise** | feature gate (not a release guard) | `compile_error!` for the 3 dev features (TEE-IK-01, + TEE-CL-02) | A.3 |
| AV-2 | Parent | Front-run entropy init / withhold init | Timing control / DoS | self-gen random seed + attestation check; re-init blocked | document reliance on attestation (TEE-IK-02) | IK-2 |

## LIST 5 — Formal verification

| # | Property | Target | Assumptions | Tool | Expected |
|---|---|---|---|---|---|
| FV-1 | `initialize_*` commits `Active` **iff** prior phase was `Initial` (or `Cloning` for cloned-seed); else unchanged. | `state.rs` init fns + `ensure_initial` | single lock | Kani | prove |
| FV-2 | `from_seed` is a deterministic function of (seed, network) for all public outputs. | `from_seed` | bitcoin crate correct | property | prove |
| FV-3 | A build with `allow-seed-import` ∧ release ⇒ does not compile. | feature cfg | TEE-IK-01 landed | compile-time | enforced once guarded |

---

## Summary

- **New items:** TEE-IK-01 (dev-feature release guard — High-if-shipped), TEE-IK-02
  (unauthenticated init — Low).
- **Counts:** L1 3 unit · L2 2 fuzz · L3 2 E2E · L4 2 attack vectors · L5 3 FV.
- **Deferred to Layer 2:** NSM RNG quality; cloning flow.
- **Top priority:** TEE-IK-01 — add `compile_error!(all(feature=<dev-feat>, not(debug_assertions)))`
  for `allow-seed-import`, `dev-mode`, **and** `mock-attestation` (TEE-CL-02) in one
  change; plus U-1 (default-build import rejection).

### Self-verification (review rules §12 + Step 2 Phase 4)
- [x] Every Confirmed/Dismissed cites code lines; dismissals name the guard.
- [x] No invented symbols; TEE-IK-01 grounded in a grep showing no `compile_error!`.
- [x] New vs carried separated; TEE-IK-01 impact conditional-on-build; cross-linked to TEE-CL-02.
- [x] Cross-flow (cloning, RNG) → Layer 2.
- [x] Part B = specs not code; the catastrophic vector (AV-1) flagged as a build event.
