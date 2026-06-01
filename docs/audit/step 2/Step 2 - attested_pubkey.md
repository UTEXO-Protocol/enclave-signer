# Step 2 — Attack Analysis & Implementation Spec — Attested Public Key

**Input:** verified `Step 1 - attested_pubkey.md`. **Code:** `dev` @ `bb2b396`.
**Reviewed:** 2026-05-29. Output is TEXT/specs (Step 3 = code).

---

## Phase 1 — Verification gate

Step 1 passes: diagram matches `handle_get_attested_public_key` → `verify_attested_pubkey`;
invariants AP-1…AP-8 are violable properties with class + test status; the parent is the
untrusted relay and the embedded AWS root + correct expected PCRs are the trust anchors.
Proceeding.

---

# Part A — Attack Analysis

## A.1 Invariant hypotheses

| Inv | Violation attempt | Verdict | Trace / guard |
|---|---|---|---|
| AP-1 | Parent forges an attestation doc | **Dismissed** | Must chain to byte-pinned AWS root + valid COSE sig under leaf (`lib.rs:306-335`); no NSM key ⇒ infeasible. |
| AP-1 | Present a chain where `cabundle[0]==root` but the rest is attacker-made | **Dismissed** | Each link `verify_issuer_signed_subject` (P-384 over TBS) back to root (`lib.rs:326-328`); needs root key. |
| AP-1/AP-7 | Use an AWS-issued non-CA leaf as an intermediate | **Confirmed latent → TEE-AP-01** | `verify_certificate_chain` checks signatures + validity but not `BasicConstraints/KeyUsage/pathLen` (`lib.rs:297-338`); exploitable only if AWS issues a usable non-CA cert. Low likelihood. |
| AP-2 | Pass a doc whose PCRs ≠ the trusted build | **Dismissed** | `verify_pcrs` byte-equality (`lib.rs:178-197`). (Assumes the verifier supplies correct expected PCRs.) |
| AP-3 | Replay an old attested-pubkey doc | **Dismissed** | Verifier sends a fresh nonce; `check_nonce` byte-equality with `Some(nonce)` (`attest_verify.rs:91-96`, `lib.rs:203-206`). |
| AP-4 | Swap the bundle/pubkey under a valid signature | **Dismissed** | `enclave_pubkey == evm_uncompressed_pub` and `user_data == sha256(canonical_bundle)` re-checked on the wire response (`attest_verify.rs:105-125`). |
| AP-1 | A `mock-attestation` enclave fools a Real verifier | **Dismissed** | Real path requires COSE_Sign1 + AWS chain; raw-CBOR mock fails parse/chain. (Mock risk is the Cloning donor path — TEE-CL-02.) |
| AP-6 | Get an attestation before keys exist | **Dismissed** | `get_keys` ⇒ `KeyNotInitialized` outside `Active`. |
| AP-8 | Reuse a doc long after issuance | **Dismissed for this flow** | No timestamp check, but the fresh-nonce challenge already prevents reuse (TEE-AP-03). |
| (verifier) | Verifier accepts an unsigned doc | **Confirmed (verifier misuse) → TEE-AP-05** | `VerifyMode::Mock` accepts zero-PCR docs; only dangerous if a production verifier selects it. |

## A.2 Actor capability matrix (C/O/Re/Rp/D/F)

| Actor | C | O | Re | Rp | D | F | Notes |
|---|---|---|---|---|---|---|---|
| **Compromised parent (relay)** | – (bound fields rejected) | doc + bundle | – | replay → nonce mismatch | yes (drop/delay) | **no** (no NSM key) | Reduces to **DoS**. |
| External verifier (honest) | nonce | – | – | – | – | – | Must supply correct PCRs + use Real. |
| Malicious "verifier" | own checks | – | – | – | – | – | Can fool only itself (no impact on the enclave). |
| NSM / AWS CA | n/a | n/a | n/a | n/a | n/a | total | Trust root (out of scope); TEE-AP-01 is the only place a CA-misconfig could matter. |
| Operator mistake | expected-PCRs / VerifyMode | – | – | – | – | – | wrong PCRs or Mock mode (TEE-AP-05). |

## A.3 Actor × invariant cross-check

- **Compromised parent** → breaks **nothing** beyond availability: every binding
  (root, COSE sig, PCR, nonce, pubkey, commitment) is NSM-signed or verifier-checked.
- **Operator/verifier misuse** → AP-2 (wrong expected PCRs) or AP-8/AP-3 bypass via
  `Mock` mode (TEE-AP-05) — verifier-side, not an enclave defect.
- **CA-misconfig (AWS)** → AP-7 (TEE-AP-01), latent, low likelihood.

### Headline conclusion
**No enclave-side break.** This flow is the strongest of the five reviewed: the parent
is fully neutralised (forgery and replay both fail), and the only residual risks are
(1) the shared cert-chain constraint gap (TEE-AP-01, also in Cloning) and (2)
verifier-side discipline (correct PCRs, Real mode). The challenge-response nonce makes
it strictly stronger than the Cloning attestation usage.

## A.4 Summary

**New items (Part A):** none that are enclave-side defects. TEE-AP-05 (verifier `Mock`
mode discipline, Low) and TEE-AP-06 (test gaps) are the only fresh items; both are
hygiene.

**Carried (shared attestation code):** TEE-AP-01 (= TEE-CL-03, cert constraints, Med),
TEE-AP-02 (= TEE-CL-07, constant-time, Low). **A single fix to
`verify_certificate_chain`/`verify_pcrs` closes the item in both the Cloning and
Attested-pubkey flows.**

**Dismissed (one-line):** forge chain (root key infeasible); replay (fresh nonce);
bundle swap (commitment re-check); mock-vs-real (COSE/chain required); pre-Active
(get_keys); timestamp (nonce-mitigated).

**Deferred to Layer 2 / out-of-flow:** NSM/AWS hardware + CA trust; how the verifier
provisions the correct expected PCRs (operational).

**Threat-model note:** the external attestation surface is **sound against the untrusted
parent**. System trust then reduces to: (a) the AWS Nitro PKI, (b) the verifier holding
the correct PCRs, (c) closing TEE-AP-01 so the chain check is robust to CA edge cases.

---

# Part B — Implementation Spec (for Step 3)

## LIST 1 — Missing unit tests

| # | Test | Setup → Action → Assert | Source | Priority |
|---|---|---|---|---|
| U-1 | `canonical_bundle_enclave_matches_parent` | fixed `KeyInfo`+`BridgeConfig`; assert `canonical_pubkey_bundle` (enclave) == `canonical_bundle` (parent) byte-for-byte, incl. #43 fields. | AP-5 / TEE-AP-06 | must-have |
| U-2 | `replay_doc_with_wrong_nonce_rejected` | doc bound to nonce A, verify with nonce B → nonce-mismatch. | AP-3 / TA-4 | should-have |
| U-3 | (post-fix) `cert_chain_rejects_non_ca_intermediate` | craft a leaf-as-intermediate → reject once constraints enforced. | AP-7 / TEE-AP-01 | should-have |

## LIST 2 — Fuzz / property tests

| # | Property | Target / bounds | Assert | Source |
|---|---|---|---|---|
| F-1 | Any single mutation (cert byte, PCR, nonce, sig, payload) ⇒ verification fails. | `verify_real_document` over a real fixture | mutate-one ⇒ Err | AP-1/2/3 |
| F-2 | `canonical_bundle` is injective over field contents (no two distinct bundles collide pre-hash boundaries). | both builders; random field lengths | length-prefix framing unambiguous | AP-5 |

## LIST 3 — E2E / integration tests

| # | Scenario | Setup | Assert | Source |
|---|---|---|---|---|
| E-1 | (exists, mock) full attest → verify happy path | in-process parent+enclave (mock) | OK; pubkey + commitment match | AP-3/AP-4 |
| E-2 | Real-fixture verify | captured genuine Nitro doc + its real PCRs | OK; tamper ⇒ reject | AP-1/AP-2 |
| E-3 | Mock-enclave doc rejected by Real verifier | mock enclave, `VerifyMode::Real` | reject (COSE/chain parse fail) | A.1 |

## LIST 4 — Attack vectors (consolidated)

| # | Actor | Scenario | Impact | Current defense | Required fix / risk | Source |
|---|---|---|---|---|---|---|
| AV-1 | CA-misconfig | AWS non-CA leaf used as intermediate to forge a chain | Forged attestation accepted | root-pin + sig chain (no constraint check) | enforce `BasicConstraints/KeyUsage/pathLen` (TEE-AP-01) | AP-7 |
| AV-2 | Verifier misuse | Production verifier runs `Mock` mode | Accepts unsigned/zero-PCR docs | doc comment "MUST be Real" | force/feature-gate Real (TEE-AP-05) | A.1 |
| AV-3 | Parent | drop/delay the response | DoS | — | operational (retry/alerting) | A.2 |

## LIST 5 — Formal verification

| # | Property | Target | Assumptions | Tool | Expected |
|---|---|---|---|---|---|
| FV-1 | verified ⇒ doc chains to embedded root ∧ COSE sig valid ∧ PCRs==expected ∧ nonce==challenge ∧ pubkey present. | `verify_real_document` | crypto crates correct | property / Kani | prove |
| FV-2 | `user_data == sha256(canonical_bundle(response))` for any accepted result. | `verify_attested_pubkey` | — | property | prove |
| FV-3 | (post-fix) verified ⇒ every non-leaf cert is a CA with `keyCertSign`. | `verify_certificate_chain` | TEE-AP-01 landed | property | counterexample until fix |

---

## Summary

- **New items:** none enclave-side. TEE-AP-05 (verifier Mock discipline, Low),
  TEE-AP-06 (test gaps).
- **Carried (one fix, two flows):** TEE-AP-01 (= TEE-CL-03, cert constraints, Med),
  TEE-AP-02 (= TEE-CL-07, constant-time, Low).
- **Counts:** L1 3 unit · L2 2 fuzz · L3 3 E2E · L4 3 attack vectors · L5 3 FV.
- **Deferred to Layer 2:** NSM/AWS PKI trust; verifier PCR provisioning (ops).
- **Top priority:** TA-3/U-1 canonical-bundle divergence guard (a silent enclave↔verifier
  mismatch would break every external verification) + the shared TEE-AP-01 fix.

### Self-verification (review rules §12 + Step 2 Phase 4)
- [x] Every Confirmed/Dismissed cites code lines; dismissals name the guard.
- [x] No invented symbols; all from Step 1's verified scope.
- [x] Honestly reports "no enclave-side break"; carried items linked to Cloning IDs.
- [x] Verifier-side misuse (Mock/PCRs) separated from enclave defects.
- [x] Part B = specs not code; bundle-divergence flagged as the highest-value test.
