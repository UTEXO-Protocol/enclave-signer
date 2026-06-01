# Step 1 Flow Review — SubmitHeaders (SPV header-chain sync)

**Component:** `utexo-bridge-enclave`, `dev` @ `bb2b396`.
**Flow:** the (untrusted) Listener pushes batches of contiguous 80-byte Bitcoin
headers via `SubmitHeaders`; the enclave validates and appends them to its in-memory
`HeaderChain`, anchored at a compile-time checkpoint. This chain is the backing store
for the **Sign EVM SPV gate** (inclusion + confirmation-depth proofs).
**Reviewed:** 2026-05-29; **refreshed 2026-06-01** against PR #48 (`bd4158a`).
Methodology: `internal_audit/release 1.0/prompts/`.

> This closes the Layer-2 item deferred in `Step 1 - sign_evm.md` (L-5): *"is the header
> chain the SPV gate trusts actually authenticated?"* Answer below — **on signet, no.**

> **Refresh (2026-06-01, PR #48):** real checkpoints landed for **mainnet**
> (`h=950_000`, `is_real=true`) and **signet** (`h=311_000`, `is_real=true`) → TEE-SH-03
> **partial-close** (testnet3/regtest still placeholder). `chain.rs:236-240` now
> short-circuits `epoch_start_time` on non-PoW networks → TEE-SH-02 closed for
> signet/regtest. **BUT** the new mainnet checkpoint at `h=950_000` is **not**
> retarget-boundary-aligned (`950_000 mod 2016 = 464`), so TEE-SH-02 will trigger
> at `h=951_552` once the listener syncs that far — pick a boundary-aligned
> checkpoint before then. TEE-SH-01 (signet linkage-only, BIP-325 pending) is
> unchanged. See `cross-flow-findings.md` Parts 1/4 for current item status.

---

## 1. Code scope

| File | Symbols |
|---|---|
| `enclave/src/server.rs` | `handle_submit_headers` (:580-605), `handle_get_last_saved_block` (:607-631) |
| `enclave/src/spv/chain.rs` | `HeaderChain::submit_headers` (:168-283), `epoch_start_time` (:292-332), `sum_work` (:337-341), `MAX_REORG_DEPTH=100` |
| `enclave/src/spv/validation.rs` | `validate_header_full` (:107-129), `check_linkage`, `check_pow`, `expected_bits` (:79-103), `is_retarget_height`, `RETARGET_INTERVAL=2016` |
| `enclave/src/spv/types.rs` | `Network::enforces_pow` (:51-53), `SpvError` |
| `enclave/src/spv/checkpoint.rs` | `Checkpoint`, `assert_real_in_release` (:88-99), `checkpoint_for`, all `*_CHECKPOINT` (placeholders) |
| `proto/enclave.proto` | `SubmitHeadersRequest` (:299-307), `SubmitHeadersResponse` (:309-312), `GetLastSavedBlock*` (:315-318) |

Boot wiring (`main.rs:104-130`): `checkpoint_for(network)`, `assert_real_in_release()`
panics in release on a placeholder, `HeaderChain::new`. Skipped: signing, RGB, merkle
verification (consumed by Sign EVM, not here).

---

## 2. Sequence diagram (verified against `submit_headers` top-to-bottom)

```mermaid
sequenceDiagram
    autonumber
    participant L as Go Listener (untrusted)
    participant P as parent (untrusted)
    participant S as handle_submit_headers
    participant C as HeaderChain
    participant V as spv::validation

    L->>P: GetLastSavedBlock → tip N
    L->>P: SubmitHeaders{start_height, headers[80B...]}
    P->>S: SubmitHeadersRequest
    S->>C: lock(header_chain); submit_headers(start_height, headers)
    C->>C: start_height <= checkpoint.height → BelowCheckpoint
    C->>C: start_height > tip+1 → NonContiguous
    C->>C: reorg_depth = (tip+1)-start_height; > MAX_REORG_DEPTH(100) → ReorgTooDeep
    C->>C: predecessor at start_height-1 (checkpoint or stored)
    loop each raw header (staged, not committed)
        C->>C: deserialize 80B → HeaderParse on fail
        C->>C: epoch_start_time(height) → HeaderNotFound if epoch-start < checkpoint  %% see TEE-SH-02
        C->>V: expected_bits(height, prev_bits, prev_time, epoch_start, network)
        V-->>C: Some(bits) on mainnet/testnet3, None on signet/regtest
        C->>V: validate_header_full(header, height, prev_hash, expected_bits, network)
        V->>V: check_linkage(prev_blockhash == expected) else ChainLinkage
        V->>V: if Some(bits): header.bits == bits else BitsMismatch
        V->>V: check_pow IF network.enforces_pow() (Mainnet|Testnet3 ONLY) else skip  %% see TEE-SH-01
    end
    alt reorg_depth > 0
        C->>C: existing_work vs new_work (sum of header.work()); new <= existing → WeakerChain
        C->>C: truncate displaced tail
    end
    C->>C: append all staged (all-or-nothing)
    C-->>S: SubmitOutcome{last_height, last_hash, headers_accepted, reorg_depth}
    S-->>P: SubmitHeadersResponse
```

Annotations (non-obvious):
- **PoW + nBits are enforced only on Mainnet/Testnet3** (`types.rs:51-53`). On **signet
  and regtest** validation is **chain-linkage only** — see TEE-SH-01.
- `epoch_start_time` runs at every retarget-boundary height **regardless of network**
  and errors `HeaderNotFound` if the epoch-start block predates the checkpoint — see
  TEE-SH-02.

---

## 3. Trust boundaries

### 3a. Listener-controlled (untrusted)
| Field | TEE handling |
|---|---|
| `headers[]` | Parsed (80B); linkage always checked; PoW + nBits checked **only on PoW networks**; reorg work-checked. |
| `start_height` | Bounds-checked (contiguity, ≤ checkpoint rejected, reorg depth ≤ 100). |

### 3b. Internal dependencies
| Dependency | Trust model |
|---|---|
| `Checkpoint` (compile-time, in PCR0) | The trust anchor: chain must extend from it; never rewritten below it. **All placeholders today** (TEE-SH-03). |
| `Network` (from `BITCOIN_NETWORK` env, in PCR0) | Decides whether PoW/nBits are enforced. |
| `bitcoin` crate | Header parse, `validate_pow`, `from_next_work_required`. |

### 3c. Off-chain / platform assumptions
- **On a PoW network**, real cumulative work makes the chain self-authenticating — a
  forged chain needs real hashpower. **On signet/regtest, this assumption does not
  hold** (PoW trivial + BIP-325 signature not verified) → TEE-SH-01.
- The chosen mainnet/signet checkpoint is placed at a **retarget boundary** (else the
  chain wedges) — TEE-SH-02.

---

## 4. Invariants

| ID | Invariant | Class | Test |
|---|---|---|---|
| SH-1 | Headers extend contiguously from the checkpoint; no gaps, no rewriting at/below the checkpoint. | enforced (`chain.rs:175-186`) | existing (`rejects_non_contiguous_batch`, `rejects_at_or_below_checkpoint`) |
| SH-2 | Each header links to its predecessor (`prev_blockhash`). | enforced (`validation.rs:43-53`) | existing (`rejects_broken_linkage`, `linkage_rejects_wrong_prev_hash`) |
| SH-3 | On a PoW network, each header meets its target and carries the retarget-correct `nBits`. | enforced **Mainnet/Testnet3 only** (`validation.rs:57-66,79-103`) | existing (`mainnet_block_1_pow_passes`, `signet_skips_pow_check`) |
| SH-4 | Reorgs are bounded (≤ 100) and require strictly greater cumulative work. | enforced (`chain.rs:191-264`) | existing (reorg suite: accepted-longer, rejected-equal/shorter, too-deep, at-max) |
| SH-5 | A batch is all-or-nothing (no partial accept). | enforced (`chain.rs:217-275`) | existing (`batch_is_atomic_on_failure`, `reorg_atomic_on_validation_failure`) |
| SH-6 | The stored chain reflects **real, authenticated** Bitcoin headers. | **violated on signet/regtest** — linkage-only; no PoW, no BIP-325 (TEE-SH-01) | n/a (by design today) |
| SH-7 | The chain can advance across retarget boundaries. | **violated unless checkpoint is boundary-aligned** (TEE-SH-02) | **missing** |
| SH-8 | The checkpoint is a real (non-placeholder) anchor. | assumed — placeholders today; release panics (TEE-SH-03) | n/a (build) |

---

## 5. Security questions (with answers)

- **Can a malicious listener forge the header chain the SPV gate trusts?**
  **On signet/regtest: yes.** `enforces_pow()` is false for both (`types.rs:51-53`), so
  `check_pow` is skipped and `expected_bits` returns `None` (no nBits check). BIP-325
  signature verification is not implemented (the proto carries no coinbase witness).
  Validation reduces to **chain linkage**, which the listener trivially satisfies for a
  fabricated chain. Since the **UTEXO custom signet is the production target**, the SPV
  inclusion/confirmation gate in Sign EVM provides **no protection against a malicious
  listener on the deployed network**. → **TEE-SH-01.** On mainnet/testnet3 the chain is
  self-authenticating (real PoW) and this attack is infeasible.
- **Can the listener rewrite confirmed history?** Not below the checkpoint (SH-1); not
  deeper than 100 blocks (SH-4); and (on PoW nets) only with strictly more work.
- **Can the chain get stuck?** **Yes** — if the checkpoint height is not a multiple of
  `RETARGET_INTERVAL` (2016), `epoch_start_time` returns `HeaderNotFound` at the first
  retarget boundary above the checkpoint (epoch-start < checkpoint), aborting every
  batch that reaches it. On signet (30s blocks) that's ~17h; on mainnet ~2 weeks. →
  **TEE-SH-02.**
- **Can a huge batch DoS the enclave?** Bounded by the 4 MB framing cap (~50k headers);
  single-threaded CPU only. Minor (TEE-SH-05).
- **Is `GetLastSavedBlock` sensitive?** No — returns public tip height/hash.

---

## 6. Observations (fact → concern → mitigation)

- **O-1.** *Fact:* signet/regtest do linkage-only header validation (`types.rs:51-53`,
  `validation.rs:57-66`). *Concern:* the SPV gate is unauthenticated on the production
  signet. *Mitigation:* open, **needs proto + BIP-325** → TEE-SH-01.
- **O-2.** *Fact:* `epoch_start_time` errors when the epoch-start predates the
  checkpoint, at any retarget boundary, on any network (`chain.rs:304-331`). *Concern:*
  liveness wedge if the checkpoint isn't boundary-aligned. *Mitigation:* → TEE-SH-02
  (cheap: boundary checkpoint, or short-circuit non-PoW networks).
- **O-3.** *Fact:* all checkpoints `is_real=false` (`checkpoint.rs:48-83`); release
  panics via `assert_real_in_release`. *Concern:* known release-blocker. *Mitigation:*
  TEE-SH-03 (carried — `cross-flow-findings.md`, `cross-flow-findings.md`).
- **O-4.** *Fact:* `MAX_REORG_DEPTH(100) < RETARGET_INTERVAL(2016)` makes reorg work a
  pure block-count comparison and forbids cross-retarget reorgs — but the invariant is
  implicit (`chain.rs`). *Mitigation:* assert it → TEE-SH-04 (carried).

---

## 7. Items

> Severities draft; human sets final.

| ID | Type | Item | Suggested sev | Status |
|---|---|---|---|---|
| TEE-SH-01 | Finding (known/deferred) | On signet/regtest, header validation is **linkage-only** (no PoW: `enforces_pow` false; no nBits; no BIP-325 — proto lacks coinbase witness). The production UTEXO signet is therefore SPV-unauthenticated: a malicious listener forges the chain and defeats the Sign EVM SPV gate (L-5). Fix needs a proto extension (`repeated bytes coinbase_txs`) + BIP-325 signature verification against `UTEXO_SIGNET_CHALLENGE`. | High (on signet) | open |
| TEE-SH-02 | Finding (new) | If the checkpoint height is not a multiple of `RETARGET_INTERVAL` (2016), `epoch_start_time` returns `HeaderNotFound` at the first retarget boundary above it (`chain.rs:304-331`) → chain wedges → eventually staleness halts signing. Affects mainnet (~2 weeks) and signet (~17h at 30s blocks). | Med–High (liveness, prod) | open |
| TEE-SH-03 | Finding (carried) | All checkpoints are placeholders (`is_real=false`); release-blocker (release panics via `assert_real_in_release`). | High (release-blocker) | open |
| TEE-SH-04 | Hardening (carried) | Assert the implicit `MAX_REORG_DEPTH < RETARGET_INTERVAL` invariant so a future operator bumping `MAX_REORG_DEPTH > 2016` is forced to handle cross-retarget reorg work. | Low | open |
| TEE-SH-05 | Observation | No explicit per-batch header cap beyond the 4 MB framing limit; large batches = minor single-threaded CPU DoS. | Info | open |
| TEE-SH-06 | Observation | Testnet3 min-difficulty (20-min) exception not implemented (`validation.rs` docs); testnet3 not a target — fine, documented. | Info | — |

---

## 8. Tests

### Existing coverage mapped
| Inv | Test |
|---|---|
| SH-1 | `chain::tests::{rejects_non_contiguous_batch, rejects_at_or_below_checkpoint}` |
| SH-2 | `chain::rejects_broken_linkage`, `validation::linkage_rejects_wrong_prev_hash` |
| SH-3 | `validation::{mainnet_block_1_pow_passes, signet_skips_pow_check, expected_bits_*}`, `chain::mainnet_block_1_appends_after_genesis_checkpoint` |
| SH-4 | `chain::{reorg_accepted_when_alt_chain_is_strictly_longer, reorg_rejected_when_alt_chain_is_equal_length, ..._shorter, reorg_too_deep_rejected, reorg_at_max_depth_is_allowed, reorg_uses_correct_predecessor_not_tip}` |
| SH-5 | `chain::{batch_is_atomic_on_failure, reorg_atomic_on_validation_failure}` |

### Missing tests
| ID | Test | Covers | Priority |
|---|---|---|---|
| TH-1 | `retarget_boundary_with_non_boundary_checkpoint_wedges` — checkpoint at a non-2016 height; submit across the next boundary → `HeaderNotFound` (regression marker for TEE-SH-02). | SH-7 / TEE-SH-02 | must-have |
| TH-2 | `retarget_boundary_with_boundary_checkpoint_succeeds` — checkpoint at a 2016-multiple; crossing the boundary derives bits from the checkpoint time. | SH-7 / TEE-SH-02 | must-have |
| TH-3 | (post-fix) signet header authentication: a forged signet chain is rejected once BIP-325 lands. | SH-6 / TEE-SH-01 | blocked on proto |
| TH-4 | A mainnet retarget that actually changes `nBits` (timespan clamp) validates correctly. | SH-3 | should-have |

---

## 9. Status summary

- **Strong on PoW networks:** contiguity/anchor (SH-1), linkage (SH-2), PoW+nBits
  retarget (SH-3), bounded strictly-heavier reorgs (SH-4), atomic batches (SH-5) — all
  well-tested. On **mainnet/testnet3** the chain is self-authenticating.
- **TEE-SH-01 (High, signet):** the production network does **linkage-only** validation
  — the SPV gate Sign EVM relies on is forgeable by the listener until BIP-325 lands
  (needs a proto change). This concretely resolves the Layer-2 deferral from
  `Step 1 - sign_evm.md` L-5.
- **TEE-SH-02 (new, Med–High):** non-boundary checkpoint wedges the chain at the first
  retarget boundary — a deployment constraint with a cheap fix.
- **TEE-SH-03 (release-blocker, carried):** placeholder checkpoints.
- **Missing tests:** TH-1/TH-2 (retarget wedge), TH-3 (blocked on proto).
- **Next:** Step 2 attack analysis for this flow.

### Self-verification (review rules §12)
- [x] Every reject condition written as coded (`start_height <= checkpoint.height → BelowCheckpoint`, `new_work <= existing_work → WeakerChain`, etc.).
- [x] Every named symbol verified in source.
- [x] Diagram matches `submit_headers` order (bounds → stage/validate loop → reorg-work → append).
- [x] Findings vs observations separated; TEE-SH-01 marked known/deferred, TEE-SH-02 marked new with code trace.
- [x] Invariants are violable safety properties + test status (SH-6/7 violated).
- [x] No invented checks — `enforces_pow` (Mainnet|Testnet3) and the `epoch_start_time` wedge both verified by reading the code.
- [x] Scope: merkle verification (Sign EVM) and BIP-325 implementation (deferred) noted, not analysed here.
