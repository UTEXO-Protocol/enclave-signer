# Step 1 Flow Review — Attested Public Key (external verifier ↔ enclave)

**Component:** `utexo-bridge-enclave` + `attestation-verify` crate + `parent`
(`attest-verify` CLI), `dev` @ `c51d6fb`.
**Flow:** an external verifier sends a fresh 32-byte nonce; the enclave returns its
public-key bundle plus an NSM attestation document binding `{evm_uncompressed_pub,
sha256(canonical_bundle)}` to its PCRs; the verifier checks the AWS Nitro cert chain,
COSE signature, PCRs, nonce, and bundle commitment.
**Reviewed:** 2026-05-29. Protocol reference: `docs/pubkey-attestation.md`.

> This is the **public trust anchor** for the whole system: it is how an auditor /
> bridge operator confirms "this signing key was generated inside a PCR-pinned TEE."
> It exercises the same `verify_attestation` code as the Cloning donor/requester
> checks, but from the external surface — so it shares the attestation findings
> (TEE-CL-03/07), here re-IDed as TEE-AP-01/02.

---

## 1. Code scope

| File | Symbols |
|---|---|
| `enclave/src/server.rs` | `handle_get_attested_public_key` (:291-328), `build_public_keys_response` (:243-259), `canonical_pubkey_bundle` (:268-289), `handle_get_public_key` (:222-237) |
| `enclave/src/attestation.rs` | `get_attestation` (real NSM vs mock) |
| `attestation-verify/src/lib.rs` | `verify_attestation`→`verify_real_document` (:258-288), `verify_certificate_chain` (:297-338), `verify_cert_validity` (:385-402), `verify_issuer_signed_subject`, `verify_pcrs` (:178-197), `check_nonce` (:199-209), `CoseSign1`/`sig_structure` (:404-467), embedded AWS root (:228-256) |
| `parent/src/attest_verify.rs` | `verify_attested_pubkey` (:70-133), `canonical_bundle` (:40-60) |
| `proto/enclave.proto` | `GetAttestedPublicKeyRequest` (:112-114), `GetAttestedPublicKeyResponse` (:116-119), `PublicKeysResponse` (:81-) |

Production: real NSM path (`mock-attestation` OFF). Skipped: signing, RGB, SPV.

---

## 2. Sequence diagram (verified against handler + verifier)

```mermaid
sequenceDiagram
    autonumber
    actor V as External verifier (auditor)
    participant Cli as attest-verify CLI / verify_attested_pubkey
    participant P as parent (untrusted)
    participant S as handle_get_attested_public_key
    participant St as EnclaveState (Active)
    participant Att as attestation.rs → NSM
    participant Ver as attestation_verify::verify_attestation

    Cli->>Cli: nonce = rand_32()
    Cli->>P: gRPC AttestedPublicKey(nonce)
    P->>S: GetAttestedPublicKeyRequest{nonce}
    S->>S: nonce.len()==32 else InvalidRequest
    S->>St: get_keys() (else KeyNotInitialized — Active only)
    S->>S: public_keys = build_public_keys_response(keys, bridge_config)  %% incl. chain_id/contract/rgb_asset_id (#43)
    S->>S: bundle = canonical_pubkey_bundle(public_keys); commitment = sha256(bundle)
    S->>Att: get_attestation(nonce, public_key=evm_uncompressed_pub, user_data=commitment)
    Att-->>S: COSE_Sign1 doc (NSM-signed over PCRs, ts, nonce, pubkey, user_data)
    S-->>P: {public_keys, attestation_doc}
    P-->>Cli: AttestedPublicKeyResponse

    Cli->>Ver: verify_attestation(doc, expected_pcrs, Some(nonce))
    Ver->>Ver: CoseSign1 (4-elem); parse inner AttestationDocument
    Ver->>Ver: cabundle[0] == embedded AWS Nitro root (byte-equal) else Certificate err
    loop each cert (root..leaf)
        Ver->>Ver: verify_cert_validity (notBefore<=now<=notAfter)
        Ver->>Ver: issuer signed subject (P-384 ECDSA over TBS)
    end
    Ver->>Ver: leaf P-384 pubkey verifies COSE sig over Sig_structure1("Signature1", protected, b"", payload)
    Ver->>Ver: check_nonce: doc.nonce == nonce (byte-equality — FRESH)
    Ver->>Ver: verify_pcrs: PCR0/1/2 == expected
    Ver->>Ver: require public_key present
    Ver-->>Cli: VerifiedAttestation{enclave_pubkey, pcrs, user_data, nonce, timestamp}
    Cli->>Cli: assert verified.enclave_pubkey == response.evm_uncompressed_pub
    Cli->>Cli: rebuild canonical_bundle(response); assert verified.user_data == sha256(bundle)
    Cli-->>V: OK + printed bundle + PCRs
```

Annotations (non-obvious):
- **Freshness is challenge-response**: the verifier passes `Some(&nonce)` and
  `check_nonce` enforces byte-equality (`lib.rs:203-206`). Replay of an old doc fails.
  *(Contrast the Cloning flow, which passes `None` and relies on the replay guard.)*
- The bundle commits **all** pubkey fields **plus** `chain_id`/`bridge_contract`/
  `rgb_asset_id` (#43), so the verifier learns which bridge instance the enclave is
  provisioned for (or that it is unconfigured → zeros).
- The enclave-wire `GetAttestedPublicKeyResponse` nests `PublicKeysResponse`; the parent
  gRPC `AttestedPublicKeyResponse` flattens the same fields — both bundle builders
  mirror the field order exactly.

---

## 3. Trust boundaries

### 3a. Verifier-controlled
| Input | Handling |
|---|---|
| `nonce` (32B) | Length-checked; bound into the NSM doc; byte-equality enforced on return. |
| `expected_pcrs` (CLI `--pcr0/1/2`) | The verifier MUST obtain the correct measurement out-of-band (it's the whole point of attestation). |
| `VerifyMode` | `Real` for production; `Mock` exists (TEE-AP-05). |

### 3b. Internal dependencies
| Dependency | Trust model |
|---|---|
| Embedded AWS Nitro root CA (`lib.rs:228`) | Byte-pinned trust anchor; parsed once. |
| NSM (`get_attestation`) | Signs the doc with a per-instance P-384 key chaining to the root. |
| `KeyManager` (Active) | Source of the attested pubkey bundle. |

### 3c. Off-chain assumptions
- The verifier knows the **correct expected PCRs** for the trusted build, and runs in
  **Real** mode. Getting either wrong is verifier-side misuse, not an enclave bug.
- The parent is untrusted but cannot forge the NSM signature, so it can only drop /
  delay the response (DoS), not fabricate a valid one.

---

## 4. Invariants

| ID | Invariant | Class | Test |
|---|---|---|---|
| AP-1 | The doc chains to the byte-pinned AWS Nitro root via validity-checked, issuer-signed certs, and the COSE signature verifies under the leaf. | enforced (`lib.rs:297-338`) | partial — verify-crate unit tests + parent e2e (mock); **real-AWS-fixture coverage missing** (TEE-AP-06) |
| AP-2 | PCR0/1/2 equal the verifier's expected values. | enforced (`verify_pcrs:178-197`) | existing (mock e2e) |
| AP-3 | The doc is fresh — its nonce equals the verifier's fresh challenge. | enforced (challenge-response, `Some(nonce)`; `check_nonce:203-206`) | existing (`facade_mock_roundtrip`, parent e2e) |
| AP-4 | The attested `public_key` equals the wire `evm_uncompressed_pub`, and `user_data == sha256(canonical_bundle)`. | enforced (`attest_verify.rs:105-125`) | existing (parent e2e) |
| AP-5 | The canonical bundle field order/encoding is identical on enclave and verifier (incl. #43 config fields). | enforced by two mirrored builders | structural — **divergence test missing** (TEE-AP-06) |
| AP-6 | An attested pubkey is produced only in `Phase::Active`. | enforced (`get_keys`) | existing (`get_keys` errors when not Active) |
| AP-7 | The cert chain enforces CA constraints (`BasicConstraints`/`KeyUsage`/`pathLen`). | **violated** — not checked (TEE-AP-01, = TEE-CL-03) | missing |
| AP-8 | The doc is not stale (timestamp bound). | **not checked** but **mitigated here** by AP-3's fresh nonce (TEE-AP-03) | n/a |

---

## 5. Security questions (with answers)

- **Can a malicious parent forge an attested pubkey?** No — it cannot produce a COSE
  doc that chains to the AWS root (no NSM key). It can only drop/delay (DoS).
- **Can an old attestation be replayed?** No — the verifier's fresh nonce is bound into
  the doc and byte-checked (AP-3). This is the key strength vs the Cloning flow.
- **Can a `mock-attestation` enclave fool a real verifier?** No — `verify_attestation`
  (Real) parses the doc as COSE_Sign1 and requires a valid AWS cert chain; a raw-CBOR
  mock doc fails. (The mock danger is confined to the Cloning donor's `verify_mock`
  path — TEE-CL-02 — not this external surface.)
- **What if the verifier runs in `Mock` mode against a real enclave?** It would accept
  zero-PCR/unsigned docs → verifier-side misuse (TEE-AP-05). Production CLI must use
  `Real`.
- **Can a forged cert chain reach the root?** Only with the AWS root's key (infeasible),
  **unless** AWS ever issues a usable non-CA cert and the missing constraint checks
  (AP-7) let it pose as an intermediate — latent, low likelihood (TEE-AP-01).
- **Does the attestation reveal whether the enclave is mis-provisioned?** Yes (positive)
  — the bundle commits chain_id/contract/rgb_asset_id; an unconfigured enclave
  (TEE-SE-12) commits zeros, externally detectable (TEE-AP-04).

---

## 6. Observations (fact → concern → mitigation)

- **O-1.** *Fact:* `verify_certificate_chain` checks root-pin + validity + issuer
  signatures + COSE sig, but **not** `BasicConstraints.cA`/`KeyUsage.keyCertSign`/
  `pathLen` (`lib.rs:297-338`). *Concern:* one CA-misconfig from accepting a leaf as an
  intermediate. *Mitigation:* TEE-AP-01 (= TEE-CL-03; same code, one fix covers both).
- **O-2.** *Fact:* `verify_pcrs`/`check_nonce` use `!=` (`lib.rs:183,204`). *Concern:*
  timing; values public. *Mitigation:* TEE-AP-02 (= TEE-CL-07), Low.
- **O-3.** *Fact:* `attestation.timestamp` is never checked. *Concern:* staleness.
  *Mitigation:* **already mitigated here** by the fresh-nonce challenge (AP-3); note for
  symmetry with TEE-CL-01 (where it is *not* mitigated) → TEE-AP-03, Low.
- **O-4 (positive).** The bundle commitment binds the pinned bridge config (#43); an
  unconfigured/mis-pinned enclave is externally observable → TEE-AP-04.
- **O-5.** *Fact:* `VerifyMode::Mock` is a caller-selectable mode in the shipped parent
  library. *Concern:* a verifier in Mock mode accepts unsigned docs. *Mitigation:*
  default/force `Real` in production; consider gating `Mock` behind a feature →
  TEE-AP-05, Low.

---

## 7. Items

> Severities draft; human sets final. Carried items share code with the Cloning flow.

| ID | Type | Item | Suggested sev | Status |
|---|---|---|---|---|
| TEE-AP-01 | Finding (carried = TEE-CL-03) | `verify_certificate_chain` omits `BasicConstraints`/`KeyUsage`/`pathLen` (`attestation-verify/src/lib.rs:297-338`). Affects both the external verifier and the cloning peer checks. | Medium | open |
| TEE-AP-02 | Hardening (carried = TEE-CL-07) | Non-constant-time PCR/nonce comparison (`lib.rs:183,204`). | Low | open |
| TEE-AP-03 | Observation | No `attestation.timestamp` check; **mitigated for this flow** by the fresh-nonce challenge. Worth a one-line comment so the contrast with cloning (TEE-CL-01) is explicit. | Low | open |
| TEE-AP-04 | Observation (positive) | Bundle commits chain_id/bridge_contract/rgb_asset_id (#43) → unconfigured/mis-pinned enclave externally detectable. Document so ops verifies these in the attestation. | Info | — |
| TEE-AP-05 | Observation | `VerifyMode::Mock` is caller-selectable in the parent lib; ensure production CLI forces `Real`, consider feature-gating `Mock`. | Low | open |
| TEE-AP-06 | Test gap | No real-AWS-fixture test of the COSE/cert-chain path; no canonical-bundle divergence test (enclave vs verifier). | — | open |

---

## 8. Tests

### Existing coverage mapped
| Inv | Test |
|---|---|
| AP-1 (mock) / AP-3 / AP-4 | `attestation::tests::facade_mock_roundtrip`; `parent/tests/test_attest_verify_e2e.rs` (mock e2e — nonce, pubkey, commitment) |
| AP-2 | mock e2e PCR check (zero PCRs) |
| AP-6 | `state` get_keys errors when not Active |
| COSE / sig-structure correctness | `attestation-verify` unit tests |

### Missing tests
| ID | Test | Covers | Priority |
|---|---|---|---|
| TA-1 | Real-AWS-fixture: a captured genuine Nitro doc verifies; a tampered cert/PCR/nonce/sig is rejected. | AP-1/AP-2/AP-3 | should-have |
| TA-2 | Cert-constraint negative (once TEE-AP-01 lands): a leaf cert presented as an intermediate is rejected. | AP-7 / TEE-AP-01 | should-have |
| TA-3 | Canonical-bundle divergence guard: a unit test asserting the enclave bundle == parent bundle byte-for-byte for a fixed `KeyInfo`+`BridgeConfig`. | AP-5 | must-have |
| TA-4 | Replay rejection: a doc bound to nonce A fails verification against nonce B. | AP-3 | should-have |

---

## 9. Status summary

- **Strong flow.** The external attestation surface is well-built: byte-pinned AWS root,
  full cert chain + COSE signature, PCR equality, **challenge-response nonce freshness**
  (AP-3 — the key strength over Cloning), pubkey + full-bundle commitment, Active-only.
  A malicious parent cannot forge or replay; a mock enclave is rejected by a Real
  verifier.
- **Carried items (shared attestation code):** TEE-AP-01 (cert constraints, = TEE-CL-03,
  Med), TEE-AP-02 (constant-time, = TEE-CL-07, Low). Fixing once benefits both flows.
- **Flow-specific:** TEE-AP-03 (timestamp — mitigated here), TEE-AP-04 (positive: config
  externally detectable), TEE-AP-05 (verifier-mode discipline).
- **Missing tests:** TA-3 (bundle divergence — must-have), TA-1/TA-2/TA-4.
- **Next:** Step 2 attack analysis for this flow.

### Self-verification (review rules §12)
- [x] Every check written as coded (`cabundle[0] != root → err`, `nonce != exp → err`, `user_data != commitment → bail`).
- [x] Every named symbol verified in source (enclave handler, verify crate, parent lib).
- [x] Diagram matches `handle_get_attested_public_key` then `verify_attested_pubkey` order.
- [x] Carried vs flow-specific separated; TEE-AP-03 honestly marked mitigated; positive O-4 not inflated.
- [x] Invariants are violable safety properties + test status (AP-7 violated, AP-8 mitigated).
- [x] No invented checks; cert-constraint omission and Mock mode both verified by reading the code.
- [x] Scope: NSM hardware trust and BIP-325/SPV out of scope.
