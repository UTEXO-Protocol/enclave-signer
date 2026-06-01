# Step 1 Flow Review — Initialize Keys (first-enclave key generation)

**Component:** `utexo-bridge-enclave`, `dev` @ `bb2b396`.
**Flow:** the first enclave in a cluster generates the HD seed from OS entropy
(`InitializeKey` with empty seed/mnemonic), deriving the EVM + BTC + BIP-86 keys. The
**seed is born here** — this is the genesis of the cluster's signing identity.
**Reviewed:** 2026-05-29. Methodology: `internal_audit/release 1.0/prompts/`.

> Seed/mnemonic *import* paths exist but are gated behind the `allow-seed-import`
> feature (testing only). Cloning is the production path for *additional* enclaves
> (`Step 1 - cloning.md`); this flow is the *first* one.

---

## 1. Code scope

| File | Symbols |
|---|---|
| `enclave/src/server.rs` | `dispatch` (InitializeKey arm :71-81), `handle_initialize` (:155-219) |
| `enclave/src/state.rs` | `initialize_from_entropy` (:195-201), `initialize_from_{mnemonic,seed}` (:203-219), `ensure_initial` (:350-355) |
| `enclave/src/keys.rs` | `KeyManager::generate` (:61-69), `from_seed` (:84-181), `from_mnemonic` (:72-77), derivation paths, `evm_address`, `expose_seed` (:211-213) |
| `enclave/Cargo.toml` | `[features]` `allow-seed-import` (:88), `dev-mode` (:90), `mock-attestation` (:101) |
| `proto/enclave.proto` | `InitializeKeyRequest` (:48-55), `InitializeKeyResponse` (:57-) |

Production: `allow-seed-import` **OFF** → only the OS-entropy path compiles.

---

## 2. Sequence diagram (verified against `handle_initialize` → `generate` → `from_seed`)

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator
    participant P as parent
    participant S as handle_initialize
    participant St as EnclaveState
    participant K as KeyManager
    participant R as getrandom (OS/NSM)

    Op->>P: InitializeKey (seed="", mnemonic="")
    P->>S: InitializeKeyRequest
    alt mnemonic non-empty
        S->>S: cfg(allow-seed-import) → initialize_from_mnemonic; else InvalidRequest "not allowed"
    else seed empty (PRODUCTION)
        S->>R: getrandom::fill(entropy[32]) else Internal err
        S->>St: initialize_from_entropy(&mut entropy)
        St->>St: lock; ensure_initial else AlreadyInitialized
        St->>K: KeyManager::generate(entropy)
        K->>K: Mnemonic::from_entropy(entropy); entropy.zeroize()
        K->>K: seed = mnemonic.to_seed(""); from_seed(seed)
        K->>K: seed_box = SecretBox(seed); seed.zeroize()
        K->>K: master = Xpriv::new_master(network, seed); master_fingerprint
        K->>K: EVM m/44'/60'/0'/0/0 → evm_secret(box); evm_address = keccak256(uncompressed_pub)[12..]
        K->>K: BTC m/84'/0'/0'/0/0 → btc_secret(box), btc_xpub
        K->>K: BIP-86 vanilla m/86'/<coin>'/0'; colored m/86'/827167'/0'
        K-->>St: (KeyManager, Mnemonic)
        St->>St: *phase = Active(km)
    else seed non-empty
        S->>S: cfg(allow-seed-import) → 64B seed → initialize_from_seed; else InvalidRequest "not allowed"
    end
    S->>St: get_keys()
    S-->>P: InitializeKeyResponse{evm_address, btc_pub, xpubs, master_fingerprint, evm_uncompressed_pub, chain_id, bridge_contract, rgb_asset_id}
```

Annotations (non-obvious):
- **Production path is the empty-seed branch** → self-generated 256-bit entropy. Import
  branches are `InvalidRequest` unless `allow-seed-import` is compiled in.
- Seed hygiene: `SecretBox::new(seed)` **before** `seed.zeroize()` (the explicit comment
  at `keys.rs:81-83` warns that zeroizing first would store all-zeros).
- The returned mnemonic is logged once and dropped; only the `SecretBox` seed persists.

---

## 3. Trust boundaries

### 3a. Caller-controlled (parent/operator; untrusted transport)
| Field | Handling |
|---|---|
| `seed` | Empty → entropy path. Non-empty → import (only if `allow-seed-import`); must be 64B. |
| `mnemonic` | Non-empty → import (only if `allow-seed-import`); takes precedence over seed. |

There is **no authentication** on who may call `InitializeKey` (TEE-IK-02).

### 3b. Internal dependencies
| Dependency | Trust model |
|---|---|
| `getrandom` | Trusted OS/NSM RNG inside the enclave (platform assumption, IK-8). |
| `bip39`/`bitcoin` bip32 | Standard BIP-39/32 derivation. |
| `ensure_initial` | One-shot: only `Phase::Initial` may initialize. |

### 3c. Off-chain / platform assumptions
- In-enclave `getrandom` yields cryptographically strong entropy (Nitro NSM RNG).
- Operators verify the resulting identity out-of-band via the **attested-pubkey** flow
  (`Step 1 - attested_pubkey.md`) — that's how front-running/identity is checked.

---

## 4. Invariants

| ID | Invariant | Class | Test |
|---|---|---|---|
| IK-1 | Keys are generated at most once; re-init from `Active`/`Cloning` is rejected. | enforced (`ensure_initial` → `AlreadyInitialized`) | existing (`*_then_double_init_fails`, `cannot_initialize_after_entering_cloning`) |
| IK-2 | Production builds accept **only** OS-entropy generation (no seed/mnemonic import). | enforced **by feature gate** (`server.rs:164-169,190-195`) | partial — import tests are `allow-seed-import`-gated; **default-build rejection test missing** |
| IK-3 | The seed comes from 256 bits of OS entropy. | enforced (`handle_initialize:172-174`, `generate:62-66`) | structural (`generate_different_keys`) |
| IK-4 | Secrets are held in `SecretBox` and transient entropy/seed/secret bytes are zeroized. | enforced (`keys.rs:64,86-87,107-109,127-129`) | structural |
| IK-5 | Derivation is deterministic, standard BIP-39/32 (EVM 44'/60', BTC 84', BIP-86 vanilla/colored 86'). | enforced (`from_seed:100-164`) | existing (`deterministic_derivation`, `from_mnemonic_matches_seed_derivation`) |
| IK-6 | The mnemonic is returned once for logging then dropped; only the `SecretBox` seed persists. | enforced (`generate` returns it; handler logs+drops) | structural |
| IK-7 | Dangerous dev features cannot ship in a release build. | **violated** — no `compile_error!` guard for `allow-seed-import`/`dev-mode`/`mock-attestation` (TEE-IK-01) | missing |
| IK-8 | In-enclave entropy is strong. | assumed (platform) | n/a |

---

## 5. Security questions (with answers)

- **Can an attacker make the enclave adopt a chosen seed?** **Only if `allow-seed-import`
  is compiled into the release build.** Then a compromised parent can call
  `InitializeKey{seed/mnemonic}` on a *fresh* (`Initial`) enclave before the operator,
  installing an attacker-controlled seed → **total key compromise**. There is **no
  `compile_error!`** preventing that build (confirmed by grep). → **TEE-IK-01.** In a
  correct production build, import is rejected (`InvalidRequest`).
- **Can the parent front-run entropy-mode init?** Yes (no auth, TEE-IK-02), but the seed
  is self-generated randomly → the resulting key is still genuinely enclave-born; the
  operator confirms it via the attested-pubkey flow. Low impact in entropy mode.
- **Can init happen twice?** No — `ensure_initial` rejects any non-`Initial` phase
  (IK-1).
- **Is the seed exposed?** Held in `SecretBox`; transient copies zeroized (IK-4). The
  `expose_seed()` accessor returns an unwrapped `&[u8;64]` (only caller: cloning
  `with_seed`) — a footgun, not a current leak (TEE-IK-04, carried).
- **Is the master fingerprint standard?** It's the **master** xpriv fingerprint, not the
  account-level one (TEE-IK-05, carried) — harmless today because taproot signing
  re-derives and anchors, but non-standard for external descriptor construction.
- **Does the response leak secrets?** No — only public addresses/xpubs/fingerprint,
  logged at INFO (TEE-IK-06, carried; all log-safe).

---

## 6. Observations (fact → concern → mitigation)

- **O-1.** *Fact:* no `compile_error!` gates `allow-seed-import` (nor `dev-mode`,
  `mock-attestation`) on `not(debug_assertions)` (grep: none in `enclave/src`).
  *Concern:* an accidental release with `allow-seed-import` lets a parent install a
  chosen seed on a fresh enclave (catastrophic); `dev-mode` disables all cross-checks;
  `mock-attestation` accepts zero-PCR docs. *Mitigation:* open → TEE-IK-01 (a single
  guard pattern fixes all three; pairs with TEE-CL-02).
- **O-2.** *Fact:* `InitializeKey` is unauthenticated. *Concern:* timing/front-running.
  *Mitigation:* entropy-mode self-generation + attested-pubkey verification make it low
  impact in production → TEE-IK-02.
- **O-3.** *Fact:* BIP-39 passphrase is empty (`to_seed("")`). *Concern:* none — the TEE
  is the seed's protection, not a passphrase. *Mitigation:* info only → TEE-IK-03.
- **O-4 (positive).** Seed hygiene (box-then-zeroize ordering, `SecretBox`, per-secret
  zeroize) and the one-shot `Phase::Initial` guard are correct and well-commented.

---

## 7. Items

> Severities draft; human sets final.

| ID | Type | Item | Suggested sev | Status |
|---|---|---|---|---|
| TEE-IK-01 | Finding (new) | No `compile_error!(all(feature="allow-seed-import", not(debug_assertions)))` — nor for `dev-mode`/`mock-attestation`. A release shipping `allow-seed-import` lets a compromised parent install a chosen seed on a fresh enclave → total key compromise. Add the guard (and symmetric guards for the other two dev features). Pairs with TEE-CL-02. | High-if-shipped | open |
| TEE-IK-02 | Observation | `InitializeKey` is unauthenticated; front-running is low-impact in entropy mode (random seed + attestation verification), but document the reliance on the attested-pubkey check. | Low | open |
| TEE-IK-03 | Observation | Empty BIP-39 passphrase; fine (TEE is the protection). Document. | Info | — |
| TEE-IK-04 | Hardening (carried) | `expose_seed()` returns `&[u8;64]` (`keys.rs:211`); prefer a closure form (`with_seed`-style) so the seed reference can't escape. | Low | open |
| TEE-IK-05 | Observation (carried) | `master_fingerprint` is the master xpriv's, not account-level; non-standard for external descriptors (harmless today). | Low | open |
| TEE-IK-06 | Observation (carried) | Public addresses/xpubs/fingerprint logged at INFO on init (`server.rs:199-205`); all log-safe. | Info | — |

---

## 8. Tests

### Existing coverage mapped
| Inv | Test |
|---|---|
| IK-1 | `state::tests::*_then_double_init_fails`; `test_clone::cannot_initialize_after_entering_cloning` |
| IK-3 | `keys::tests::generate_different_keys` |
| IK-5 | `keys::tests::{deterministic_derivation, from_mnemonic_deterministic, from_mnemonic_matches_seed_derivation}` |
| IK-2 (import-on) | `test_keygen.rs` / `test_signing.rs` (`allow-seed-import`-gated init helpers) |

### Missing tests
| ID | Test | Covers | Priority |
|---|---|---|---|
| TI-1 | Default-build: `InitializeKey{seed}` and `{mnemonic}` both return `InvalidRequest "not allowed"`. | IK-2 | must-have |
| TI-2 | (post-fix) a release-profile build with `allow-seed-import` fails to compile (`compile_error!`). | IK-7 / TEE-IK-01 | should-have |
| TI-3 | Entropy-path init produces a valid, attestable bundle (evm_address derivable, xpubs well-formed). | IK-3/IK-5 | should-have |

---

## 9. Status summary

- **Well-built, small surface:** one-shot generation (IK-1), OS-entropy-only in
  production (IK-2), deterministic standard derivation (IK-5), strong seed hygiene
  (IK-4). The seed is born and confined correctly.
- **One real finding — TEE-IK-01 (High-if-shipped):** no `compile_error!` guard against
  shipping `allow-seed-import`/`dev-mode`/`mock-attestation` in release. The
  `allow-seed-import` case is catastrophic (parent installs a chosen seed). This
  generalises the same gap as TEE-CL-02 (mock) into a **single cross-flow hardening
  item**: add release guards for all three dev features.
- **Carried hygiene:** TEE-IK-04 (`expose_seed`), TEE-IK-05 (master vs account
  fingerprint), TEE-IK-06 (INFO logging).
- **Missing tests:** TI-1 (default-build import rejection — must-have), TI-2/TI-3.
- **Next:** Step 2 attack analysis for this flow. With this, all 6 enclave flows are
  reviewed.

### Self-verification (review rules §12)
- [x] Every condition written as coded (`!req.mnemonic.is_empty()`, `ensure_initial → AlreadyInitialized`, `seed must be 64 bytes`).
- [x] Every named symbol verified in source.
- [x] Diagram matches `handle_initialize` branch order + `from_seed` derivation order.
- [x] TEE-IK-01 confirmed by grep (no `compile_error!` in `enclave/src`); not invented.
- [x] Invariants are violable safety properties + test status (IK-7 violated).
- [x] Findings vs observations separated; TEE-IK-01 impact stated as conditional-on-build.
- [x] Scope: cloning (additional enclaves) and platform RNG trust noted, not analysed here.
