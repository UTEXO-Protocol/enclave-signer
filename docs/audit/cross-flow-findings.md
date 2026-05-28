# UTEXO Enclave-Signer — Cross-Flow Findings Tracker, Coverage Map & Audit Package

**Component:** `utexo-bridge-enclave` (the TEE), `dev` @ `c51d6fb`.
**Compiled:** 2026-05-29 from the six Step 1/2 flow reviews in `docs/audit/`.
**Methodology:** `internal_audit/release 1.0/prompts/` (Cross-Flow Documents).

> **Severities are DRAFT** (suggested by the review). Per the methodology, final
> severity + owner are set by a human/auditor. "High-if-shipped" = catastrophic impact
> but gated on a build/deploy mistake, not a runtime attack.

Flows covered (all six): `sign_evm`, `cloning`, `sign_psbt`, `submit_headers`,
`attested_pubkey`, `initialize_keys`. Item ID prefixes: `TEE-SE / CL / PS / SH / AP / IK`.

---

## Part 1 — Findings tracker (all flows, ranked by draft severity)

### Tier H — pre-mainnet blockers

| ID | Flow | Item (one line) | Draft sev | Owner | Status |
|---|---|---|---|---|---|
| TEE-SH-01 | submit_headers | Signet/regtest header validation is **linkage-only** (no PoW, no BIP-325) → listener can forge the chain and defeat the Sign EVM SPV gate on the production signet. Needs proto `coinbase_txs` + BIP-325 verify. | High (signet) | Eng + Proto | open (known/deferred) |
| TEE-SE-01 | sign_evm | Asset-identity bypass: empty `req.rgb_asset_id` skips both the pin match and the consignment `contract_id` check → a valid foreign-asset burn can authorise a USDT0 unlock. Bind `validated.contract_id == pinned RGB_ASSET_ID`. | High | Eng | open |
| TEE-SE-02 | sign_evm | RGB `OpId` not bound (no `op_id` in `SignEvmRequest`, never checked or signed). Spec core cross-domain primitive. | High | Eng + Auditor | open |
| TEE-SH-03 | submit_headers | All SPV checkpoints are placeholders (`is_real=false`); release-blocker (release panics via `assert_real_in_release`). | High | Ops/Deploy | open |
| TEE-IK-01 + TEE-CL-02 | initialize_keys / cloning | **No `compile_error!` release guard** for `allow-seed-import` (→ parent installs chosen seed on fresh enclave) / `mock-attestation` (→ zero-PCR docs accepted) / `dev-mode` (→ all cross-checks skipped). One guard pattern fixes all three. | High-if-shipped | Eng | open |

### Tier M

| ID | Flow | Item (one line) | Draft sev | Owner | Status |
|---|---|---|---|---|---|
| TEE-SE-05 | sign_evm | EIP-712 domain `name`/`version` hardcoded `"Tricorn"/"1"` **and** calldata offsets (68/100, mint-burn 36) unverified vs deployed ABI. Needs a contract-derived fixture. | Med | Eng + Contract | open |
| TEE-SE-03 | sign_evm | EVM recipient not derived from / bound to the RGB payload (Sec 13). | Med–High | Eng + Auditor | open |
| TEE-PS-01 | sign_psbt | Bridge-mode trusts listener `evm_event_valid/finalized` with no in-enclave EVM-event proof (asymmetric vs unlock RGB+SPV). Design decision: policy signer vs anchored-only. | Med (design) | Auditor + Contract | open |
| TEE-PS-02 | sign_psbt | No PSBT **output** validation; `psbt_output_amount` declared-vs-declared, never tied to actual outputs → co-signs spends to any destination. | Med–High | Eng + Auditor | open |
| TEE-PS-03 | sign_psbt | Bridge cross-checks bypassable: listener selects **vanilla mode** via empty `evm_tx_hash`. | Med | Eng | open |
| TEE-SH-02 | submit_headers | Non-boundary checkpoint wedges the chain at the first retarget boundary (`epoch_start_time`→`HeaderNotFound`). ~17h on signet, ~2wk on mainnet. | Med–High | Eng + Ops | open |
| TEE-CL-03 = TEE-AP-01 | cloning / attested_pubkey | `verify_certificate_chain` omits `BasicConstraints`/`KeyUsage`/`pathLen` (shared code — one fix, two flows). | Med | Eng | open |
| TEE-CL-04 | cloning | `replay_guard` count-capped (10k) + reject-when-full → cloning-availability DoS by the parent. | Med | Eng | open |
| TEE-CL-06 | cloning | Bind `cloning_secret` into PCR2 (leaked-secret + substituted-image defence in depth). | Med | Eng | open |
| TEE-SE-11 | sign_evm | Staleness + deadline rely on `SystemTime::now()`; verify the Nitro enclave clock is not host-settable. | Med (platform) | Eng + Platform | open |
| TEE-SE-12 | sign_evm | Unconfigured `BridgeConfig` only warns and runs in listener-trusting mode (no chain/contract/asset pin). Consider fail-closed when spv/rgb on. | Med | Eng + Ops | open |

### Tier L

| ID | Flow | Item | Draft sev | Owner | Status |
|---|---|---|---|---|---|
| TEE-SE-04 | sign_evm | Amount bind is `<=`, not the spec's strict `==`. | Low–Med (design) | Auditor | open |
| TEE-SE-06 | sign_evm | `SPV_MIN_CONFIRMATIONS=6` for all networks (signet 30s blocks ≈ 3 min). | Low–Med (design) | Auditor + Ops | open |
| TEE-SE-13 | sign_evm | `rgb_validator=None` (Esplora boot fail) → fundsOut DoS; prefer panic-at-boot. | Low | Eng | open |
| TEE-CL-01 | cloning | Freshness replay-guard-only (`nonce=None`, no timestamp); cross-restart replay possible but low-impact (ephemeral binding). | Low | Eng | open |
| TEE-CL-05 | cloning | Empty AEAD AAD; set AAD = handshake context (def-in-depth). | Low–Med | Eng | open |
| TEE-CL-07 = TEE-AP-02 | cloning / attested_pubkey | Non-constant-time PCR/nonce comparison (shared code). | Low | Eng | open |
| TEE-CL-08 | cloning | `cloning_secret` is `&str`; take `&[u8]` for binary secrets. | Low | Eng | open |
| TEE-CL-09 | cloning | `Cloning→Cloning` re-init gives misleading `AlreadyInitialized`. | Low | Eng | open |
| TEE-CL-10 | cloning | `cluster_public_key` doesn't distinguish sibling deployments sharing image+secret. | Low (config) | Ops | open |
| TEE-AP-03 | attested_pubkey | No `attestation.timestamp` check — **mitigated here** by fresh-nonce challenge (note the contrast with TEE-CL-01). | Low | Eng | open |
| TEE-AP-05 | attested_pubkey | `VerifyMode::Mock` caller-selectable; force/feature-gate `Real` in production. | Low | Eng + Ops | open |
| TEE-SH-04 | submit_headers | Assert the implicit `MAX_REORG_DEPTH(100) < RETARGET_INTERVAL(2016)` invariant. | Low | Eng | open |
| TEE-IK-02 | initialize_keys | `InitializeKey` unauthenticated; low-impact in entropy mode (random seed + attestation check). | Low | Auditor | open |
| TEE-IK-04 | initialize_keys | `expose_seed()` returns `&[u8;64]`; prefer closure form. | Low | Eng | open |
| TEE-IK-05 | initialize_keys | `master_fingerprint` is master-level, not account-level (non-standard for external descriptors). | Low | Eng + Auditor | open |

### Tier Info / questions / positive

| ID | Flow | Item | Type |
|---|---|---|---|
| TEE-SE-07 | sign_evm | `consignment_valid` (proto #4) vestigial — mark deprecated. | Doc |
| TEE-SE-08 | sign_evm | Confirm on-chain `MultisigProxy` nonce/`burnId` semantics match listener nonce. | Backend question |
| TEE-SE-09 | sign_evm | `uint256` calldata amount clamped to `u64`; document assumption. | Info |
| TEE-PS-04 | sign_psbt | `evm_token`/`evm_recipient`/`rgb_asset_id`/`operation_idx` unused in enclave. | Doc |
| TEE-PS-05 | sign_psbt | Input-anchoring suite is the strongest adversarial coverage — keep as regression gate. | Positive |
| TEE-SH-05 | submit_headers | No per-batch header cap beyond 4 MB framing (minor CPU DoS). | Info |
| TEE-SH-06 | submit_headers | Testnet3 min-difficulty exception not implemented (not a target). | Info |
| TEE-AP-04 | attested_pubkey | Bundle commits config (#43) → mis-provisioned enclave externally detectable. | Positive |
| TEE-AP-06 | attested_pubkey | Test gaps: no real-AWS fixture; no bundle-divergence guard. | Test gap |
| TEE-IK-03 | initialize_keys | Empty BIP-39 passphrase (TEE is the protection). | Info |
| TEE-IK-06 | initialize_keys | Public addresses/xpubs/fingerprint logged at INFO (log-safe). | Info |

**Counts:** 5 Tier-H groups · 12 Tier-M · ~17 Tier-L · ~11 Info/question/positive.
Two ID pairs are the **same code** (TEE-CL-03≡AP-01, TEE-CL-07≡AP-02); one group spans
three features (TEE-IK-01+CL-02+dev-mode).

---

## Part 2 — Cross-flow themes (merged root causes)

1. **Dangerous dev features have no release guard.** `allow-seed-import` (TEE-IK-01),
   `mock-attestation` (TEE-CL-02), `dev-mode` (cross-check skip) — none has
   `compile_error!(all(feature=…, not(debug_assertions)))`. Each is catastrophic if it
   ships. **One change** adds all three guards. *Highest leverage-to-cost fix.*

2. **Anchored crypto, host-trusted bridge policy.** Both signing flows enforce
   *cryptographic* correctness rigorously (Sign EVM: in-enclave RGB+SPV+amount; Sign
   PSBT: input anchoring to `script_pubkey`, adversarially tested) but leave *semantic*
   bridge policy host-trusted: unlock side — asset (TEE-SE-01), recipient (TEE-SE-03),
   OpId (TEE-SE-02); lock side — EVM-event truth (TEE-PS-01), output destination/amount
   (TEE-PS-02), mode selection (TEE-PS-03). This is the spec's central trust-removal
   goal (Sec 6.2) and the bulk of the funds-risk surface.

3. **SPV is only as strong as the network's PoW.** TEE-SH-01: on the production signet
   the header chain is unauthenticated (no PoW, no BIP-325), so the Sign EVM SPV gate
   (TEE-SE predicates 7/8) provides no protection against the listener. Mainnet is sound.

4. **Shared attestation verifier.** Cloning and Attested-pubkey use the same
   `verify_attestation`; the cert-constraint (TEE-CL-03≡AP-01) and constant-time
   (TEE-CL-07≡AP-02) items are single fixes benefiting both. The Attested-pubkey flow is
   the strongest reviewed (challenge-response freshness); Cloning is weaker only on
   freshness (TEE-CL-01), mitigated by ephemeral-key binding.

---

## Part 3 — Coverage map (risk × existing test × missing test × owner)

| Risk / invariant | Flow | Existing test | Missing test (ID) | Owner |
|---|---|---|---|---|
| Consignment validated in-enclave (no boolean trust) | sign_evm L-1 | `rejects_empty_consignment_even_with_valid_flag` | — | — |
| Amount bound to consignment | sign_evm L-2 | burn/transfer submodules | E-3 real-burn fixture | Eng |
| **Asset identity bound to pin** | sign_evm L-4 | — | **U-1/T-01 (must), T-03** | Eng |
| Pinned chain/contract | sign_evm L-3 | `pinned_config_rejects_*` | — | — |
| OpId bound | sign_evm L-9 | — | (post-design) | Eng |
| Recipient bound | sign_evm L-10 | — | (post-design) TP-style | Eng |
| EIP-712 digest matches contract | sign_evm L-11 | — | T-05 contract fixture | Eng+Contract |
| Enclave clock trust | sign_evm | — | (platform verify) | Platform |
| SPV coverage/depth/freshness/net | sign_evm L-5/6/7 | `spv_crosscheck::*` | — | — |
| Seal only to PCR-equal peer | cloning CL-1 | happy-path (mock) | **TC-1 PCR-mismatch (must)** | Eng |
| Wire↔attestation pubkey/digest binding | cloning CL-4 | — | **TC-2 (must)** | Eng |
| Replay-guard exhaustion | cloning CL-11 | — | TC-3 | Eng |
| mock-attestation never ships | cloning CL-12 | — | TC-4 (compile-fail) | Eng |
| Cert-chain CA constraints | cloning/attested AP-7 | — | TC-5 / TA-2 | Eng |
| Input anchoring (P2WSH+taproot) | sign_psbt PS-1/2/3 | extensive adversarial suite | TP-4 multi-input | Eng |
| **Bridge-mode not bypassable** | sign_psbt PS-8 | vanilla tests show bypass | **TP-1 (must)** | Eng |
| PSBT output binding | sign_psbt PS-7 | — | TP-2 (post-design) | Eng |
| Header contiguity/linkage/PoW/reorg | submit_headers SH-1..5 | full chain+validation suite | TH-4 mainnet retarget | Eng |
| **Retarget-boundary checkpoint** | submit_headers SH-7 | — | **TH-1/TH-2 (must)** | Eng |
| Signet header authentication | submit_headers SH-6 | — | TH-3 (post-proto) | Eng+Proto |
| Attestation chain/PCR/nonce/pubkey | attested_pubkey AP-1..4 | mock e2e + verify-crate units | TA-1 real fixture, TA-4 replay | Eng |
| **Canonical-bundle enclave↔verifier parity** | attested_pubkey AP-5 | — | **TA-3 / U-1 (must)** | Eng |
| One-shot init / re-init rejected | initialize_keys IK-1 | double-init tests | — | — |
| **Production rejects seed/mnemonic import** | initialize_keys IK-2 | import-on tests only | **TI-1 (must)** | Eng |
| Dev-feature release guard | initialize_keys IK-7 | — | TI-2 (compile-fail) | Eng |
| Deterministic derivation | initialize_keys IK-5 | `deterministic_derivation` etc. | — | — |

**Must-have missing tests (8):** U-1/T-01 (asset bind), TC-1 (PCR mismatch), TC-2
(wire↔attestation), TP-1 (vanilla bypass), TH-1/TH-2 (retarget wedge), TA-3 (bundle
parity), TI-1 (import rejection). Each doubles as a regression marker for its finding.

---

## Part 4 — Pre-mainnet priority list

In order, the smallest set that closes the most risk:

1. **Dev-feature release guards** (TEE-IK-01 + TEE-CL-02 + dev-mode) — one `compile_error!`
   change; removes three catastrophic-if-shipped paths. *Cheapest high-value fix.*
2. **TEE-SE-01 asset bind** — bind validated `contract_id` to the pinned `RGB_ASSET_ID`;
   add U-1. Closes a listener-triggerable funds-theft path.
3. **TEE-SH-01 signet authentication** — decide the BIP-325 timeline; until then, any
   signet-backed value flow is SPV-unprotected. Needs a proto extension.
4. **TEE-SH-03 + TEE-SH-02 checkpoints** — pin **real, retarget-boundary-aligned**
   mainnet/signet checkpoints (one decision closes both).
5. **TEE-SE-02 OpId + TEE-SE-03 recipient** — the remaining unlock-side semantic
   bindings (spec Sec 13 / Sec 6/7).
6. **TEE-PS-01 decision** — is the enclave a policy-enforcing signer or anchored-only
   cosigner? Determines whether TEE-PS-02/03 are bugs or accepted risks.
7. **TEE-SE-05** — pin the EIP-712 domain + calldata offsets with a contract-derived
   fixture.

Items 2/5/6/7 are facets of theme #2 (host-trusted bridge policy); 1 is theme #1; 3 is
theme #3.

---

## Part 5 — What's genuinely solid (regression-protect these)

- **PSBT input anchoring** (TEE-PS-05): the strongest adversarial suite in the codebase
  — fabricated witness_script, sliding-window pubkey, lying tap_key_origins/bip32, wrong
  control block all closed and tested.
- **External attestation** (attested_pubkey): byte-pinned AWS root, full cert chain +
  COSE sig, PCR equality, **challenge-response nonce freshness**, bundle commitment. No
  enclave-side break; parent fully neutralised.
- **Cloning confidentiality**: no single-actor seed-exfiltration path while attestation
  is sound (key-substitution + leaked-secret-alone both fail; ciphertext bound to the
  requester ephemeral key).
- **Header chain on PoW networks**: contiguity/anchor, linkage, PoW+retarget nBits,
  bounded strictly-heavier reorgs, atomic batches — all tested.
- **Consignment-bound amount + closed `consignment_valid` bypass** (#44/#47), **config
  pinning bound into attestation** (#43), **EIP-191 raw-message envelope** (#42), **PSBT
  shape whitelist** (#40).

---

---

## Part 6 — Cross-cutting / infrastructure items (folded from the code review)

These are not scoped to one of the six flows (transport, build, key-handling,
`SignRawMessage`); preserved here from the former `docs/project-review.md`.

| ID | Area | Item | Draft sev | Owner | Status |
|---|---|---|---|---|---|
| TEE-XC-01 | SignRawMessage | EIP-191 prefix (#42) closed the tx-collision; **remaining**: no length cap, no `fundsIn`-shape allowlist — the RPC EIP-191-signs arbitrary bytes (`server.rs:483-515`). | Med | Eng | open |
| TEE-XC-02 | sign_evm key | `sign_evm` relies on k256's default low-S; not asserted (`keys.rs:267-279`). A k256 default change could emit high-S that EVM verifiers reject. Add `normalize_s()` + test. | Low | Eng | open |
| TEE-XC-03 | framing | `read_message` allocates up to 4 MB before decode (`framing.rs:25`) → ~4 MB transient heap per malicious connection. Chunked read or tighter cap. | Med | Eng | open |
| TEE-XC-04 | error taxonomy | `EnclaveError::error_code` collapses all but CrossCheck/Spv/NotReady to code 1 (`error.rs:78-86`) — Listener can't alarm on PCR/identity/nonce-replay. Assign distinct codes for security-relevant errors. | Med (operability) | Eng | open |
| TEE-XC-05 | dispatch robustness | A handler panic aborts the whole enclave (`panic=abort`, single-thread accept); `handle_connection` lacks `catch_unwind` (`server.rs:52-56`). | Low–Med | Eng | open |
| TEE-XC-06 | vsock_forwarder | TCP listener on `127.0.0.1:3443` forwards any in-enclave traffic to the host vsock-proxy → covert-channel risk if another component is buggy. Prefer a Unix socket / document trusted-only. | Low | Eng | open |
| TEE-XC-07 | build / PCR reproducibility | RGB deps `[patch.crates-io]` pinned to branch `master` not a commit; `rgb-consignment` fetched over SSH from a private repo (PCR0 not independently re-derivable → team-attested); `Dockerfile.enclave` floating `rust:1.89-slim`. Pin commits/digests + document PCR0 provenance. | Med (release) | Eng + Ops | open |
| TEE-XC-08 | error taxonomy | Esplora/network errors during RGB validation surface as `CrossCheck` (`rgb.rs`) — conflates bad-consignment (terminal) with infra-down (transient). Split `Spv`/transient vs `CrossCheck`/terminal. | Low | Eng | open |

**Minor / maintainability (folded, no separate ID):** `assert_chain_not_stale`
future-skew branch is structurally asymmetric; `verify_one_proof` has a redundant
`checked_sub` guard; `CloneSession` is `StaticSecret` (add a `!Clone` note); error
messages embed adversary-controlled hex (bounded, hygiene); a requester attestation can
fan out to multiple donors (harmless — same cluster seed).

---

## Part 7 — Spec-conformance summary (folded from the spec review)

Maps the implementation to the *RGB↔EVM Bridge Technical Spec* predicates. Detail +
predicate-by-predicate tables previously lived in `docs/spec-conformance.md`; the
authoritative per-predicate analysis is now in the per-flow docs cross-referenced below.

| Spec section | Verdict | Notes / cross-ref |
|---|---|---|
| Sec 10 — TEE validation predicates (1–11) | **Partial** | 1/7/8/11 ✅; 9 n/a (on-chain); **6 ❌** OpId (TEE-SE-02); 2/3 substantially closed post #44/#47 (burn amount consignment-bound); 5 chain/contract pinned (#43) but **recipient unbound** (TEE-SE-03). → `Step 1/2 - sign_evm`. |
| Sec 9 — RGB burn semantics | **Validated** | #41 extract + #44 enforce (TS_BURN ∧ amount ≤ burned); `<=` not strict `==` (TEE-SE-04); mint/burn path inert until the listener migrates. → `sign_evm`. |
| Sec 12 — RGB/Bitcoin/SPV | **Strong on PoW; gap on signet** | coverage + depth + chain-net + staleness all enforced; **TEE-SH-01** signet is linkage-only; checkpoints placeholder **TEE-SH-03**. → `submit_headers` / `sign_evm`. |
| Sec 13 — Destination binding | **NOT conformant** | recipient/OpId not derived from the RGB payload (TEE-SE-02/03); lock-side outputs unbound (TEE-PS-02). → `sign_evm` / `sign_psbt`. |
| Sec 16 — TEE federation / cloning / signer attestation | **Mostly conformant** | PCR-equal cloning, mutual attestation, challenge-response attested-pubkey; carried hardening TEE-CL-03/04/06. Quorum is on-chain (out of repo). → `cloning` / `attested_pubkey`. |
| Sec 14/15 — Security invariants & failure conditions | **Partial** | compromised-backend: amount + chain/contract now bound; recipient/OpId still host-supplied; fail-closed posture correct. → `sign_evm`. |

The spec's "priority gaps to close (pre-mainnet)" correspond to **Part 4** above.

---

### Provenance
Each row traces to a per-flow doc under `docs/audit/step 1/` and `docs/audit/step 2/`
(`Step 1 - <flow>.md` / `Step 2 - <flow>.md`). System/trust context: `ENCLAVE_SIGNER_CONTEXT.md`.
Severities are draft; this tracker is the consolidation layer (findings tracker +
coverage map + audit package + cross-cutting + spec summary), not a re-derivation — see
the per-flow docs for code traces and self-verification checklists. Folded from the
former `docs/project-review.md` (Part 1 → `ENCLAVE_SIGNER_CONTEXT.md`; findings → Parts
1/6) and `docs/spec-conformance.md` (→ Part 7) on 2026-05-29.
