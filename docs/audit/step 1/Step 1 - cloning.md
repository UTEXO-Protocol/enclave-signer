# Step 1 Flow Review — Enclave-to-Enclave Seed Cloning

**Component:** `utexo-bridge-enclave`, `dev` @ `bb2b396`.
**Flow:** a new enclave (`Phase::Initial`) obtains the cluster's HD seed from an
existing enclave (`Phase::Active`) via a three-message handshake relayed by the
untrusted parent: `InitiateCloning` (requester) → `GetClone` (donor) → `SetClone`
(requester). **Crown jewel: the 64-byte BIP-39 seed.**
**Reviewed:** 2026-05-29. Methodology: `internal_audit/release 1.0/prompts/`.

> Purely TEE↔TEE; no on-chain backstop. Confidentiality of the seed rests entirely
> on (a) NSM attestation soundness and (b) X25519/AEAD. Carried hardening items
> from `cross-flow-findings.md` (Cloning + Attestation sections) are referenced
> rather than re-derived.

---

## 1. Code scope

| File | Symbols |
|---|---|
| `enclave/src/server.rs` | `handle_initiate_cloning` (:654-696), `handle_get_clone` (:702-797), `handle_set_clone` (:802-855), `fresh_nonce` (:643-648) |
| `enclave/src/cloning.rs` | `CloneSession::{new,public_key,decrypt_seed_from_peer}`, `make_cloning_digest` (:108), `verify_cloning_digest` (:116), `encrypt_seed_for_peer` (:132), `derive_symmetric_key` (:164), `reject_non_contributory` (:151), `ZERO_NONCE` (:184) |
| `enclave/src/state.rs` | `Phase`, `CloningSession`, `NonceReplayGuard` (:48-88), `enter_cloning` (:223), `complete_cloning` (:292), `with_seed` (:248), `evm_address` (:254), `with_donor_cloning_secret` (:170), `set_donor_cloning_secret` (:158) |
| `enclave/src/attestation.rs` | `get_attestation`, `get_own_pcrs`, `verify_peer_attestation` (mock vs real cfg-split) |
| `attestation-verify/src/lib.rs` | `verify_attestation` (:137), `check_nonce` (:204), PCR check (:179-186), `verify_certificate_chain` (:297-356) |
| `proto/enclave.proto` | `InitiateCloning*` (:252-261), `GetClone*` (:263-273), `SetClone*` (:276-285) |

Production: `--features spv,rgb-validation`, **`mock-attestation` OFF**,
`allow-seed-import` OFF. Cloning is the only non-`allow-seed-import` path to load a
seed in production. Skipped: signing, SPV, SubmitHeaders.

---

## 2. Sequence diagram (verified against the three handlers, in code order)

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator
    participant P as parent (untrusted relay)
    participant Req as REQUESTER (Phase::Initial)
    participant RN as Req NSM
    participant Don as DONOR (Phase::Active)
    participant DN as Don NSM

    Note over Req,Don: both must run the SAME enclave image (PCR0/1/2 equal)

    Op->>P: Initialize(cloning_secret)
    P->>Req: InitiateCloningRequest{cloning_secret, cluster_public_key(20B)}
    Req->>Req: cloning_secret empty → Err(InvalidRequest); cluster_pk != 20B → Err
    Req->>Req: CloneSession::new() (ephemeral X25519); nonce = getrandom(32)
    Req->>Req: cloning_digest = HMAC-SHA256(secret, encryption_pubkey)
    Req->>RN: get_attestation(nonce, pubkey=encryption_pubkey, user_data=cloning_digest)
    RN-->>Req: requester_attestation (COSE_Sign1)
    Req->>Req: enter_cloning() — ensure Phase::Initial else AlreadyInitialized
    Req-->>P: {requester_attestation, encryption_pubkey, cloning_digest}

    P->>Don: GetCloneRequest{cluster_public_key, cloning_digest, encryption_pubkey, requester_attestation}
    Don->>Don: (1) cluster_pk/encryption_pk/digest length checks
    Don->>Don: (2) req_cluster_pk == state.evm_address() else Err(Clone)  %% donor must be Active
    Don->>DN: (3) get_own_pcrs()
    Don->>Don: (3) verify_peer_attestation(requester_attestation, expected=own_PCRs, nonce=None)
    Don->>Don: (4) replay_guard.check_and_record(verified.nonce) else NonceReplay
    Don->>Don: (5) verified.enclave_pubkey == req_encryption_pk else PubkeyMismatch
    Don->>Don: (6) verified.user_data == req_digest else DigestMismatch
    Don->>Don: (7) with_donor_cloning_secret: verify_cloning_digest(secret, pk, digest) else DigestMismatch
    Don->>Don: (8) with_seed → encrypt_seed_for_peer(req_encryption_pk, seed) [fresh eph, contributory, HKDF, ChaCha20Poly1305 zero-nonce]
    Don->>DN: (9) get_attestation(donor_nonce, pubkey=donor_pubkey, user_data=None)
    Don-->>P: {encrypted_seed, donor_pubkey, donor_attestation}

    P->>Req: SetCloneRequest{encrypted_seed, donor_pubkey, donor_attestation}
    Req->>Req: donor_pubkey != 32B → Err
    Req->>RN: get_own_pcrs()
    Req->>Req: verify_peer_attestation(donor_attestation, expected=own_PCRs, nonce=None)
    Req->>Req: replay_guard.check_and_record(verified.nonce) else NonceReplay
    Req->>Req: verified.enclave_pubkey == donor_pubkey else PubkeyMismatch
    Req->>Req: complete_cloning: decrypt_seed_from_peer → KeyManager::from_seed → km.evm_address()==cluster_public_key else IdentityMismatch → atomic Cloning→Active
    Req-->>P: SetCloneResponse{}
    P-->>Op: Initialize OK
```

Annotations (non-obvious):
- Both `verify_peer_attestation` calls pass **`expected_nonce = None`** (`server.rs:740`,
  `:814`). Freshness is enforced only by `replay_guard` (in-memory, reset on restart).
- The X25519 secret is `StaticSecret` (not `EphemeralSecret`) so it survives across
  the two requester messages; zeroized on drop.
- `ZERO_NONCE` for ChaCha20Poly1305 is safe **because** the derived key is single-use
  per handshake (fresh ephemeral keypair).

---

## 3. Trust boundaries

### 3a. Parent-controlled (untrusted relay)
Relays all three messages; can **reorder, replay, drop, or substitute** any wire field.
It cannot forge an NSM signature, so it cannot rewrite `encryption_pubkey`/`cloning_digest`
(bound into the requester attestation, checked at GetClone steps 5-6) or `donor_pubkey`
(bound into donor attestation, checked at SetClone). Dropping/reordering = DoS only.

### 3b. Internal dependencies
| Dependency | Trust model |
|---|---|
| NSM attestation (`get_attestation`/`verify_peer_attestation`) | **The root of cloning security.** Real path → NSM + AWS Nitro cert chain + PCR equality. Mock path accepts zero-PCR docs (must not ship — CL-12). |
| `cloning_secret` (`UTEXO_CLONING_SECRET`) | Pre-shared operator secret; HMAC-authorises the request. Defense-in-depth on top of PCR attestation. |
| `replay_guard` | In-memory, per-uptime, capped 10k. Freshness store. |
| X25519/HKDF/ChaCha20Poly1305 (`cloning.rs`) | Single-use derived key per handshake; small-order points rejected. |

### 3c. Off-chain / platform assumptions
- The enclave image is PCR-pinned and `mock-attestation` is compiled out in release.
- `attestation.timestamp` is **not** checked; freshness depends on `replay_guard`
  surviving (resets on restart) — see CL-5 / TEE-CL-01.
- All cluster members (and any deployment sharing the same image + `cloning_secret`)
  share one seed → one EVM address; `cluster_public_key` cannot distinguish them
  (TEE-CL-10).

---

## 4. Invariants

| ID | Invariant | Class | Test |
|---|---|---|---|
| CL-1 | The seed is sealed only to a peer whose NSM attestation proves a PCR-equal enclave image. | enforced (`server.rs:738-740`) | partial — happy path exists; **PCR-mismatch rejection not testable under mock (zero PCRs)** → missing |
| CL-2 | The seed ciphertext is decryptable only by the holder of the requester's ephemeral X25519 secret. | enforced (`cloning.rs:74-84,132-145`) | existing (`cloning::tests` tampered/wrong-key; `test_clone::clone_rejects_tampered_ciphertext`) |
| CL-3 | A clone is served only if the request carries `HMAC(cloning_secret, encryption_pubkey)`. | enforced (`server.rs:768-773`) | existing (`clone_rejects_wrong_cloning_secret`) |
| CL-4 | `encryption_pubkey` and `cloning_digest` are NSM-bound; a parent cannot substitute them. | enforced (`server.rs:753-764`) | partial — wire-vs-attestation substitution not explicitly tested → missing |
| CL-5 | A replayed/stale attestation cannot be reused. | **violated/weak** — `expected_nonce=None`, no timestamp; `replay_guard` resets on restart (TEE-CL-01) | existing within-uptime (`clone_rejects_duplicate_requester_attestation_nonce_on_donor`); cross-restart missing |
| CL-6 | Small-order / non-contributory X25519 points are rejected. | enforced (`cloning.rs:151-158`) | existing (`encrypt/decrypt_rejects_small_order_peer_pubkey`) |
| CL-7 | The requester installs the seed only if the derived EVM address == `cluster_public_key`. | enforced (`server.rs:840-842`) | existing (`clone_happy_path...`, `clone_rejects_wrong_cluster_public_key`) |
| CL-8 | The seed plaintext never leaves the TEE and is zeroized. | enforced (`SecretBox`/`Zeroizing`/`with_seed`) | structural (not directly testable) |
| CL-9 | Cloning is recovery, not upgrade — only the same image (PCRs) can clone. | enforced (= CL-1) | as CL-1 |
| CL-10 | The donor serves `GetClone` only in `Active`, addressed to its own EVM address. | enforced (`server.rs:726-733`, `with_seed→with_active`) | existing (`clone_rejects_wrong_cluster_public_key`) |
| CL-11 | The replay guard cannot be exhausted to deny cloning. | **violated** — capped 10k; full → all cloning rejected (TEE-CL-04) | missing |
| CL-12 | `mock-attestation` never ships in release. | **assumed** — no `compile_error!` guard (TEE-CL-02) | n/a (build) |

---

## 5. Security questions (with answers)

- **Can a non-TEE attacker obtain the seed?** Only by holding the requester's
  ephemeral X25519 secret (lives inside the requester TEE) → requires a valid
  same-PCR NSM attestation binding an attacker-controlled pubkey. Infeasible unless
  (a) `mock-attestation` shipped (CL-12/TEE-CL-02), (b) NSM key compromise, or
  (c) cert-chain constraint forgery (TEE-CL-03). **Cloning confidentiality ≡ attestation
  soundness.**
- **Does a leaked `cloning_secret` alone leak the seed?** **No.** The attacker still
  needs a same-PCR attestation binding their pubkey (steps 3-5). The secret is
  defense-in-depth → strengthen by binding it into PCR2 (TEE-CL-06).
- **Can the parent replay `GetClone` to re-extract the seed?** Within one uptime →
  `replay_guard` rejects (step 4). Across restart → re-seals to the original
  requester's pubkey, which the attacker cannot decrypt → **no disclosure** (CL-2).
  Low impact (TEE-CL-01).
- **Can the parent substitute its own `encryption_pubkey`?** No — bound into the
  NSM-signed attestation; steps 5-6 reject mismatches (CL-4).
- **Can a malicious donor seal a poisoned seed?** The requester rejects unless the
  derived address == `cluster_public_key` (CL-7); a second seed with the same EVM
  address is a key collision → infeasible.
- **Can the parent DoS cloning?** Yes — relay 10k distinct-nonce attestations to fill
  `replay_guard` → all subsequent cloning rejected until restart (CL-11/TEE-CL-04).
- **Can the requester be tricked into joining the wrong cluster?** If a second
  deployment shares the image **and** `cloning_secret`, the parent could point the
  requester at it; the address check passes (same seed) (TEE-CL-10).

---

## 6. Observations (fact → concern → mitigation)

- **O-1.** *Fact:* both attestation verifications pass `nonce=None`; no challenge-response,
  no timestamp check. *Concern:* freshness is replay-guard-only and per-uptime.
  *Mitigation:* low impact for confidentiality (ephemeral binding); open as TEE-CL-01.
- **O-2.** *Fact:* no `compile_error!` prevents `mock-attestation` in a release build
  (`attestation.rs` cfg-gates only). *Concern:* an accidental release with the feature
  accepts zero-PCR docs → seed exfiltration. *Mitigation:* open → TEE-CL-02.
- **O-3.** *Fact:* `replay_guard` is count-bounded (10k) and rejects when full
  (`state.rs:75-79`). *Concern:* cloning-availability DoS. *Mitigation:* time-window
  or document restart-as-reset → TEE-CL-04.
- **O-4.** *Fact:* AEAD AAD is empty (`cloning.rs:191-200`); pubkeys are bound via HKDF
  `info` instead. *Concern:* defense-in-depth only; a future key-reuse bug wouldn't be
  caught by AAD. *Mitigation:* set AAD = context → TEE-CL-05.
- **O-5.** *Fact:* `cluster_public_key` is the shared cluster EVM address. *Concern:*
  cannot distinguish cluster members or sibling deployments sharing image+secret.
  *Mitigation:* operator/ops + TEE-CL-10.

---

## 7. Items

> Severity drafts; human sets final. Carried items cite `cross-flow-findings.md`.

| ID | Type | Item | Suggested sev | Status |
|---|---|---|---|---|
| TEE-CL-01 | Finding (new framing) | Attestation freshness is `replay_guard`-only: both `verify_peer_attestation` calls pass `nonce=None` (`server.rs:740,814`) and `verify_attestation` ignores `timestamp`. Within-uptime replay blocked; cross-restart replay possible but **low-impact** (ciphertext bound to requester ephemeral key, CL-2). Consolidates the prior code-review "no timestamp" + "replay across restart" notes. | Low | open |
| TEE-CL-02 | Finding (carried) | No `compile_error!(all(feature="mock-attestation", not(debug_assertions)))`. If shipped, `verify_peer_attestation` accepts zero-PCR CBOR → any caller poses as a same-image TEE → **seed exfiltration**. | High-if-shipped (Critical impact) | open |
| TEE-CL-03 | Finding (carried) | `verify_certificate_chain` omits `BasicConstraints.cA`/`KeyUsage.keyCertSign`/`pathLen` (`attestation-verify/src/lib.rs:297-356`). | Medium | open |
| TEE-CL-04 | Finding (carried) | `replay_guard` capped at 10k and rejects when full (`state.rs:75-79`) → cloning-availability DoS by the parent. | Medium | open |
| TEE-CL-05 | Hardening (carried) | ChaCha20Poly1305 AAD empty; set AAD = `"utexo-cloning-v1"‖donor_pub‖requester_pub` (`cloning.rs:191-200`). | Low–Med (def-in-depth) | open |
| TEE-CL-06 | Hardening (carried) | Bind `cloning_secret` into PCR2 so a leaked secret + substituted image still fails PCR equality (`main.rs:58`). | Medium (def-in-depth) | open |
| TEE-CL-07 | Hardening (carried) | PCR/nonce comparison not constant-time (`attestation-verify/src/lib.rs:183,204`); values public so low risk. | Low | open |
| TEE-CL-08 | Hardening (carried) | `make_cloning_digest` takes `secret: &str` (`cloning.rs:108`); take `&[u8]` so high-entropy binary secrets work without UTF-8 wrapping. | Low | open |
| TEE-CL-09 | Design/UX (carried) | `Cloning → Cloning` re-initiation rejected with misleading `AlreadyInitialized` (`state.rs:223-228`); allow restart-in-place or rename error. | Low | open |
| TEE-CL-10 | Design/ops (new) | `cluster_public_key` binds the shared cluster identity; a sibling deployment sharing image + `cloning_secret` is indistinguishable. Per-cluster domain separation (e.g. cluster id in HKDF info / digest). | Low (config-gated) | open |

---

## 8. Tests

### Existing coverage mapped
| Inv / question | Test |
|---|---|
| CL-2 | `cloning::tests::{seed_decrypt_tampered_*, decrypt_with_wrong_*}`, `test_clone::clone_rejects_tampered_ciphertext` |
| CL-3 | `test_clone::clone_rejects_wrong_cloning_secret` |
| CL-5 (within-uptime) | `test_clone::clone_rejects_duplicate_requester_attestation_nonce_on_donor` |
| CL-6 | `cloning::tests::{encrypt,decrypt}_rejects_small_order_peer_pubkey` |
| CL-7, CL-10 | `test_clone::{clone_happy_path..., clone_rejects_wrong_cluster_public_key}` |
| Phase guard | `test_clone::cannot_initialize_after_entering_cloning` |

### Missing tests
| ID | Test | Covers | Priority |
|---|---|---|---|
| TC-1 | Donor rejects a requester attestation with mismatched PCRs (needs a verify path that exercises non-zero expected PCRs — see note). | CL-1/CL-9 | must-have |
| TC-2 | Substituted wire `encryption_pubkey` ≠ attestation `public_key` → `PubkeyMismatch`; substituted `cloning_digest` ≠ `user_data` → `DigestMismatch`. | CL-4 | must-have |
| TC-3 | Fill `replay_guard` to capacity → next clone rejected with "replay guard full". | CL-11 / TEE-CL-04 | should-have |
| TC-4 | `mock-attestation` build guard: a release-profile compile fails (once TEE-CL-02 `compile_error!` lands). | TEE-CL-02 | should-have |
| TC-5 | Cert-chain negative: a leaf cert presented as intermediate is rejected (once TEE-CL-03 constraints land). | TEE-CL-03 | should-have |

> Note for TC-1: mock attestation uses all-zero PCRs and `get_own_pcrs`→zero, so a
> PCR-mismatch path can't be exercised under the mock feature today. Needs either a
> mock that supports configurable PCRs or a unit test directly against
> `attestation_verify::verify_attestation` with crafted PCRs.

---

## 9. Status summary

- **No live single-actor seed-exfiltration path** given attestation soundness: the
  parent cannot substitute keys (CL-4), a leaked `cloning_secret` alone is
  insufficient (needs same-PCR attestation), and ciphertext is bound to the
  requester's ephemeral key (CL-2). The flow is **strong and substantially
  spec-conformant (Sec 16.4)**.
- **New items:** TEE-CL-01 (freshness replay-guard-only, Low), TEE-CL-10 (cluster
  domain separation, Low).
- **Carried (prior code review) — pre-mainnet priority:** TEE-CL-02 (mock guard,
  High-if-shipped → add `compile_error!`), TEE-CL-03 (cert constraints, Med),
  TEE-CL-04 (replay DoS, Med); plus hardening TEE-CL-05/06/07/08/09.
- **Missing tests:** TC-1 (PCR mismatch), TC-2 (wire-vs-attestation binding), TC-3
  (replay-guard-full).
- **Next:** Step 2 attack analysis for this flow (below).

### Self-verification (review rules §12)
- [x] Every reject condition written as coded (e.g. `verified.enclave_pubkey == req_encryption_pk else PubkeyMismatch`).
- [x] Every named symbol verified in source (handlers, `cloning.rs`, `state.rs`, `attestation.rs`).
- [x] Diagram order matches the three handlers top-to-bottom.
- [x] Findings vs hardening vs design separated; severities draft; mock-guard impact stated as conditional.
- [x] Invariants are violable safety properties + test status.
- [x] No invented checks; carried items cite `cross-flow-findings.md` + file:line.
- [x] Scope: signing/SPV excluded; cross-deployment deferred (TEE-CL-10).
