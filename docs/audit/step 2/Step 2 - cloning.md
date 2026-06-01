# Step 2 — Attack Analysis & Implementation Spec — Seed Cloning

**Input:** verified `Step 1 - cloning.md`. **Code:** `dev` @ `bb2b396`.
**Reviewed:** 2026-05-29. Output is TEXT/specs (Step 3 = code).

---

## Phase 1 — Verification gate

Step 1 passes: diagram matches the three handlers; invariants CL-1…CL-12 are violable
properties with class + test status; trust boundaries name the parent as the untrusted
relay and NSM attestation as the root of trust. Proceeding.

---

# Part A — Attack Analysis

## A.1 Invariant hypotheses

| Inv | Violation attempt | Verdict | Trace / guard |
|---|---|---|---|
| CL-1 / CL-9 | Non-same-image enclave receives the seed | **Confirmed only if `mock-attestation` shipped → TEE-CL-02**; otherwise **Dismissed** | `verify_peer_attestation(expected=own_PCRs)` (`server.rs:738-740`). Mock path accepts zero-PCR docs (`attestation.rs:97-101`) with no `compile_error!` guard. |
| CL-2 | Decrypt the sealed seed without the requester ephemeral secret | **Dismissed** | Key = HKDF(X25519(donor_eph, requester_pub)); AEAD auth (`cloning.rs:74-84,197-212`). Secret never leaves the requester TEE. |
| CL-3 | Serve a clone without the operator secret | **Dismissed** | `verify_cloning_digest` under `with_donor_cloning_secret` (`server.rs:768-773`). |
| CL-4 | Parent substitutes `encryption_pubkey`/`cloning_digest` for keys it controls | **Dismissed** | Both are NSM-bound; steps 5-6 reject `verified.{enclave_pubkey,user_data}` ≠ wire (`server.rs:753-764`). Parent can't forge the NSM signature. |
| CL-5 | Replay a captured attestation after enclave restart | **Confirmed low-impact → TEE-CL-01** | `nonce=None` + no timestamp; `replay_guard` resets on restart. But re-seal is to the original requester pubkey → attacker can't decrypt (CL-2). No seed disclosure; hygiene/DoS only. |
| CL-6 | Force a zero shared secret with a small-order point | **Dismissed** | `reject_non_contributory` (`cloning.rs:151-158`). |
| CL-7 | Malicious donor seals a poisoned/foreign seed | **Dismissed** | Requester rejects unless derived `evm_address == cluster_public_key` (`server.rs:840-842`); same-address-different-seed = key collision (infeasible). |
| CL-8 | Extract the seed plaintext from enclave memory/logs | **Dismissed (in-scope)** | `SecretBox`/`Zeroizing`; `with_seed` closure scope (`state.rs:248-250`). Side-channel/mem-dump = platform, out of flow. |
| CL-10 | Route `GetClone` to a non-Active or wrong donor | **Dismissed** | `with_seed→with_active`; `req_cluster_pk == evm_address` (`server.rs:726-733`). Cluster members share the address by design. |
| CL-11 | Exhaust `replay_guard` to deny cloning | **Confirmed → TEE-CL-04** | Capped 10k; full → `Err(Clone "replay guard full")` (`state.rs:75-79`). Parent relays 10k distinct nonces. |
| CL-12 | Ship `mock-attestation` in release | **Confirmed gap → TEE-CL-02** | No `compile_error!(all(feature="mock-attestation", not(debug_assertions)))` anywhere (grep). |
| (cert) | Forge a chain to the AWS root via a non-CA leaf used as intermediate | **Confirmed latent → TEE-CL-03** | `verify_certificate_chain` omits `BasicConstraints/KeyUsage/pathLen` (`attestation-verify/src/lib.rs:297-356`); exploitable only if AWS ever issues a usable non-CA cert. Low likelihood. |

## A.2 Actor capability matrix (C/O/Re/Rp/D/F)

| Actor | C | O | Re | Rp | D | F | Notes |
|---|---|---|---|---|---|---|---|
| Normal user | – | – | – | – | – | – | **Not involved** (operator-driven). |
| MEV / sequencer | – | – | – | – | – | – | **Not involved**. |
| **Compromised parent (relay)** | wire (bound fields rejected) | ciphertext + attestations (not seed) | yes | yes (guard-limited) | yes | **no** (can't forge NSM) | Primary adversary; capabilities reduce to **DoS** (CL-11) + futile replay (CL-5). |
| Broken attestation (`mock` shipped) | – | – | – | – | – | **total** | TEE-CL-02 → seed exfiltration. |
| Operator mistake | build/env | – | – | – | – | – | ship mock, leak/omit secret, point at wrong cluster. |
| Leaked `cloning_secret` holder | digest only | – | – | – | – | partial | Insufficient alone (needs same-PCR attestation); def-in-depth TEE-CL-06. |
| NSM / AWS hardware | n/a | n/a | n/a | n/a | n/a | total | Out of scope (hardware trust root). |
| Compromised federation signer | – | – | – | – | – | – | **Not involved** in cloning. |

## A.3 Actor × invariant cross-check

- **Compromised parent** → breaks only **CL-11** (DoS, TEE-CL-04). It cannot break
  CL-1/2/3/4/6/7/10 (NSM binding + AEAD + address check hold). Replay (CL-5) is futile.
- **Operator ships `mock`** → breaks **CL-1/CL-9/CL-12** → full seed exfiltration
  (TEE-CL-02). This is the single catastrophic path and it is a *build* event, not a
  runtime attack.
- **Leaked secret + control of a genuine enclave** → redundant (that enclave already
  clones legitimately); becomes dangerous only combined with weak attestation
  (mock/cert) → TEE-CL-06 def-in-depth.
- **Cross-deployment** (shared image + secret) → CL-10/identity ambiguity (TEE-CL-10).

### Headline conclusion
Unlike Sign EVM (which had a live single-actor break, TEE-SE-01), **the cloning flow
has no live single-actor seed-exfiltration path** while attestation is sound. The
adversary surface collapses to: (1) a **build/deploy mistake** shipping `mock`
(TEE-CL-02 — the one that must be mechanically prevented), (2) **availability DoS**
(TEE-CL-04), and (3) **defense-in-depth** gaps (cert constraints, AAD, secret-in-PCR2).

## A.4 Summary

**New items (Part A):** TEE-CL-01 (freshness replay-guard-only, Low), TEE-CL-10
(cross-deployment domain separation, Low). All other findings are **carried** from
`cross-flow-findings.md` (TEE-CL-02..09), now framed with cloning-specific impact.

**Dismissed (one-line):** CL-2 (AEAD+ephemeral binding); CL-3 (HMAC secret); CL-4 (NSM
binding); CL-6 (contributory check); CL-7 (address check + collision infeasible);
CL-8 (SecretBox/Zeroizing); CL-10 (Active + address). Parent replay (CL-5) futile.

**Confirmed:** TEE-CL-02 (mock guard absent — catastrophic if shipped), TEE-CL-04
(replay-guard DoS), TEE-CL-03 (cert-constraint latent).

**Deferred to Layer 2 / out-of-flow:** NSM/AWS hardware trust; cross-deployment
operator config (TEE-CL-10); the shared-seed cluster contributing one logical
signature to the on-chain quorum (links to `Step 2 - sign_evm.md` A.4).

**Threat-model note:** cloning confidentiality reduces to **attestation soundness**.
The highest-leverage control is therefore mechanical: a `compile_error!` that makes a
mock-enabled release impossible (TEE-CL-02), plus the cert-chain constraint checks
(TEE-CL-03) that keep the attestation verifier from being one CA-misconfig away from
accepting a forged chain.

---

# Part B — Implementation Spec (for Step 3)

## LIST 1 — Missing unit tests

| # | Test | Setup → Action → Assert | Source | Priority |
|---|---|---|---|---|
| U-1 | `verify_attestation_rejects_pcr_mismatch` | direct `attestation_verify::verify_attestation` with a crafted doc whose PCRs ≠ expected → `PcrMismatch`. | CL-1/TC-1 | must-have |
| U-2 | `get_clone_rejects_substituted_encryption_pubkey` / `..._digest` | mock attestation binding pubkey A / digest A; send wire pubkey B / digest B → `PubkeyMismatch` / `DigestMismatch`. | CL-4/TC-2 | must-have |
| U-3 | `replay_guard_full_rejects_new` | fill `NonceReplayGuard` to `max` → `check_and_record` returns "replay guard full". | CL-11/TC-3 | should-have |
| U-4 | (exists) wrong-secret / wrong-cluster / tampered-ct / small-order / dup-nonce | mapped in Step 1 §8 | CL-2/3/5/6/7/10 | n/a |

## LIST 2 — Fuzz / property tests

| # | Property | Target / bounds | Assert | Source |
|---|---|---|---|---|
| F-1 | Seal/unseal round-trips iff same ephemeral pair | `encrypt_seed_for_peer`/`decrypt_seed_from_peer`; random 32-byte peer keys, 64-byte seeds | OK iff key pair matches; else `Clone` err | CL-2 |
| F-2 | Non-contributory rejection | random low-order + valid points | small-order → `Clone` err | CL-6 |
| F-3 | Digest verify is exact + constant-time-shaped | random secret/pubkey/digest | accept iff `HMAC(secret,pk)==digest` | CL-3 |
| F-4 | HKDF `info` binds both pubkeys | swap donor/requester order | distinct keys ⇒ decrypt fails | CL-2 |

## LIST 3 — E2E / integration tests

| # | Scenario | Setup | Assert | Source |
|---|---|---|---|---|
| E-1 | (exists) happy-path clone copies identity | `test_clone::clone_happy_path...` | requester == donor address | CL-7 |
| E-2 | Replay-guard exhaustion → cloning DoS | relay `max` distinct-nonce attestations, then a genuine clone | last clone rejected "replay guard full" | CL-11/TEE-CL-04 |
| E-3 | Cross-restart replay is futile | capture `GetClone`, restart donor, replay | re-seal to original pubkey; a *second* requester cannot decrypt | CL-5/TEE-CL-01 |

## LIST 4 — Attack vectors (consolidated)

| # | Actor | Scenario | Impact | Current defense | Required fix / risk | Source |
|---|---|---|---|---|---|---|
| AV-1 | Operator/build | `mock-attestation` enabled in a release EIF → zero-PCR docs accepted | **Seed exfiltration** (total) | cfg-gates only; Dockerfile doesn't enable it | `compile_error!` guard (TEE-CL-02) | A.3 |
| AV-2 | Parent | Fill `replay_guard` (10k nonces) | Cloning unavailable until restart | count cap, reject-when-full | time-window / documented restart (TEE-CL-04) | CL-11 |
| AV-3 | CA-misconfig | Non-CA leaf used as intermediate to forge chain to AWS root | Forged attestation → seed exfil | byte-pinned root + signature chain | enforce `BasicConstraints/KeyUsage/pathLen` (TEE-CL-03) | cert |
| AV-4 | Secret leak + weak attestation | Leaked `cloning_secret` combined with mock/cert weakness | Escalation toward seed | PCR attestation (sound path) | bind secret into PCR2 (TEE-CL-06) | A.3 |
| AV-5 | Operator/parent | Point requester at a sibling deployment sharing image+secret | Joins wrong cluster | address check (same → passes) | per-cluster domain separation (TEE-CL-10) | CL-10 |

## LIST 5 — Formal verification

| # | Property | Target | Assumptions | Tool | Expected |
|---|---|---|---|---|---|
| FV-1 | Phase transitions: `Initial→{Active,Cloning}`, `Cloning→Active`, no transition out of `Active`; `enter_cloning` only from `Initial`; `complete_cloning` only from `Cloning`. | `state.rs` `Phase` machine | single state lock | Kani / state-model | prove |
| FV-2 | `complete_cloning` is atomic: on closure error the phase stays `Cloning`. | `state.rs:292-308` | — | Kani | prove |
| FV-3 | Seed seal: derived key depends on the shared secret (no decrypt under a different ephemeral key). | `cloning.rs` derive+AEAD | crate crypto correct | property test (crypto FV out of scope) | prove-by-test |
| FV-4 | `mock-attestation` ⇒ build is non-release. | feature/cfg | — | compile-time (`compile_error!`) | enforced once TEE-CL-02 lands |

---

## Summary

- **New items:** TEE-CL-01 (freshness, Low), TEE-CL-10 (cross-deployment, Low).
- **Counts:** L1 3 unit · L2 4 fuzz · L3 3 E2E · L4 5 attack vectors · L5 4 FV.
- **Top priority for Step 3:** **TEE-CL-02** (`compile_error!` mock guard — mechanical,
  cheap, removes the one catastrophic path) + U-2/U-1 binding tests; then TEE-CL-03
  (cert constraints) and TEE-CL-04 (replay DoS bound).
- **Deferred to Layer 2:** NSM/AWS hardware trust, cross-deployment config (TEE-CL-10),
  shared-seed quorum interaction (cross-ref `Step 2 - sign_evm.md`).
- **Docs-only / def-in-depth:** TEE-CL-05 (AAD), TEE-CL-06 (secret→PCR2), TEE-CL-07
  (constant-time), TEE-CL-08 (`&[u8]` secret), TEE-CL-09 (Cloning→Cloning UX).

### Self-verification (review rules §12 + Step 2 Phase 4)
- [x] Every Confirmed/Dismissed cites code lines; no "probably".
- [x] No invented symbols; carried items cite `cross-flow-findings.md` + file:line.
- [x] New vs carried separated; TEE-CL-02 impact stated as conditional-on-build.
- [x] Cross-flow (quorum, hardware, cross-deployment) → Layer 2, not single-flow findings.
- [x] Part B = specs not code; DoS vs confidentiality distinguished.
- [x] Severities draft; design/hardening not mislabeled as live findings.
