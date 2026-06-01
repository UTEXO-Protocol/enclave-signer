# Step 2 — Attack Analysis & Implementation Spec — SubmitHeaders

**Input:** verified `Step 1 - submit_headers.md`. **Code:** `dev` @ `bb2b396`.
**Reviewed:** 2026-05-29. Output is TEXT/specs (Step 3 = code).

---

## Phase 1 — Verification gate

Step 1 passes: diagram matches `submit_headers` top-to-bottom; invariants SH-1…SH-8 are
violable properties with class + test status; the listener is the untrusted source and
the checkpoint/network are the PCR0-pinned anchors. Proceeding.

---

# Part A — Attack Analysis

## A.1 Invariant hypotheses

| Inv | Violation attempt | Verdict | Trace / guard |
|---|---|---|---|
| SH-1 | Rewrite history below the checkpoint / leave a gap | **Dismissed** | `BelowCheckpoint`/`NonContiguous` (`chain.rs:175-186`). |
| SH-2 | Append a header that doesn't link to its predecessor | **Dismissed** | `check_linkage` (`validation.rs:43-53`); test `rejects_broken_linkage`. |
| SH-3 | Submit a low-difficulty / wrong-`nBits` chain on **mainnet** | **Dismissed (mainnet)** | `check_pow` + `expected_bits` retarget re-derivation (`validation.rs:57-103`). |
| SH-3 | Submit a forged chain on **signet/regtest** | **Confirmed → TEE-SH-01** | `enforces_pow()` false (`types.rs:51-53`) ⇒ no PoW, `expected_bits`→`None` ⇒ no nBits; BIP-325 not implemented (no coinbase witness in proto). Linkage-only. |
| SH-4 | Equal-work or shorter reorg to flip the tip | **Dismissed** | strict `new_work > existing_work` (`chain.rs:262`); tests `reorg_rejected_when_*`. |
| SH-4 | Reorg deeper than 100 to rewrite deep history | **Dismissed** | `ReorgTooDeep` (`chain.rs:191-196`). |
| SH-4 | Win a reorg on signet by submitting more (fake) blocks | **Confirmed (subsumed by TEE-SH-01)** | `header.work()` is constant on signet ⇒ "more work" == "more blocks" ⇒ listener always wins. Only matters because headers are unauthenticated there. |
| SH-5 | Leave the chain half-mutated via a mid-batch failure | **Dismissed** | stage-then-commit; `batch_is_atomic_on_failure`, `reorg_atomic_on_validation_failure`. |
| SH-7 | Wedge the chain at a retarget boundary | **Confirmed → TEE-SH-02** | `epoch_start_time` → `HeaderNotFound` when epoch-start < checkpoint (`chain.rs:304-331`), any network. |
| SH-8 | Operate on a placeholder checkpoint | **Dismissed in release / Confirmed gap** | `assert_real_in_release` panics in release (`checkpoint.rs:88-99`); all checkpoints placeholder today → TEE-SH-03. |

## A.2 Actor capability matrix (C/O/Re/Rp/D/F)

| Actor | C | O | Re | Rp | D | F | Notes |
|---|---|---|---|---|---|---|---|
| **Compromised listener** | header bytes + start_height | tip (via GetLastSavedBlock) | yes (≤100, work-gated on PoW nets) | n/a | yes (withhold = freeze, caught by staleness) | **signet: total; mainnet: none** | Primary adversary. |
| Normal user / MEV / federation signer | – | – | – | – | – | – | **Not involved** in header sync. |
| Operator mistake | checkpoint choice / `BITCOIN_NETWORK` env | – | – | – | – | – | non-boundary checkpoint (TEE-SH-02); wrong network. |
| Bitcoin network (real reorgs) | – | – | natural | – | – | – | ≤100, work-gated → handled (SH-4). |

## A.3 Actor × invariant cross-check

- **Compromised listener × Fake (signet)** → breaks **SH-6** (and trivially SH-3/SH-4),
  because signet headers are linkage-only. This **defeats the Sign EVM SPV gate**
  (inclusion + depth proofs are verified against a chain the attacker authored).
- **Compromised listener × Control (mainnet)** → breaks **nothing**: real PoW + retarget
  enforcement make a forged chain infeasible; reorgs are bounded + strictly-heavier.
- **Operator × checkpoint choice** → triggers **SH-7** wedge (TEE-SH-02) and the
  placeholder release-blocker (TEE-SH-03).
- **Listener × Delay (withhold headers)** → freezes the tip, but the Sign EVM staleness
  check (`assert_chain_not_stale`, ≤2h) converts this to a signing halt, not a stale
  acceptance. Cross-ref `Step 1 - sign_evm.md` L-7.

### Headline conclusion
The chain logic is **sound on PoW networks** and **unauthenticated on signet** —
the network the bridge actually deploys on. **TEE-SH-01 is therefore the most
consequential finding across all flows reviewed so far**: it removes the
cryptographic backstop the entire unlock-direction security argument leans on
(`Step 1 - sign_evm.md` L-5/L-7, predicates 7/8). It is a known/deferred gap (BIP-325
needs a proto change), so it is *acknowledged-incomplete*, not silent — but it must
be closed before any signet-backed mainnet-value flow.

## A.4 Summary

**New items (Part A):** TEE-SH-02 (retarget-boundary wedge — confirmed by trace, Med–High).
TEE-SH-01 confirmed and elevated (the signet SPV-authentication gap, already noted in
code/`cross-flow-findings.md` but now tied to a concrete attack on the production network).

**Dismissed (one-line):** SH-1 (anchor/contiguity); SH-2 (linkage); SH-3 mainnet (PoW +
retarget); SH-4 equal/short/deep reorg (strict work + depth bound); SH-5 (atomic).

**Deferred to Layer 2 / out-of-flow:**
- BIP-325 signature verification design (proto extension + coinbase witness) — large,
  cross-component (listener must supply coinbase txs).
- The downstream impact on Sign EVM (SPV gate) is tracked there; this flow supplies the
  root cause.

**Threat-model note:** "real PoW = self-authenticating chain" is the assumption the SPV
design rests on. It holds on mainnet and **fails on signet**, where security would come
from the BIP-325 block-signature — which is not verified. Until then, the in-enclave
header chain on signet is **only as trustworthy as the listener**, which the whole
architecture treats as untrusted.

---

# Part B — Implementation Spec (for Step 3)

## LIST 1 — Missing unit tests

| # | Test | Setup → Action → Assert | Source | Priority |
|---|---|---|---|---|
| U-1 | `non_boundary_checkpoint_wedges_at_retarget` | checkpoint height not %2016; submit headers crossing the next boundary → `HeaderNotFound`. Regression marker for TEE-SH-02. | TEE-SH-02 | must-have |
| U-2 | `boundary_checkpoint_crosses_retarget_ok` | checkpoint at a 2016-multiple; crossing derives bits from checkpoint time. | TEE-SH-02 | must-have |
| U-3 | `mainnet_retarget_adjusts_nbits` | a boundary block whose timespan changes difficulty; assert `expected_bits` clamp + `BitsMismatch` on a wrong value. | SH-3 | should-have |
| U-4 | (post-fix) `signet_rejects_forged_header` | once BIP-325 lands. | TEE-SH-01 | blocked on proto |

## LIST 2 — Fuzz / property tests

| # | Property | Target / bounds | Assert | Source |
|---|---|---|---|---|
| F-1 | Append ⇒ contiguous & linked to checkpoint-rooted chain. | `submit_headers`; random start_heights/lengths | accepted ⇒ tip advanced by batch len & linkage holds | SH-1/SH-2 |
| F-2 | Reorg accepted **iff** depth≤100 ∧ strictly heavier. | random fork lengths/depths (regtest = block-count proxy) | monotonic best-chain | SH-4 |
| F-3 | Atomicity: a corrupted element anywhere ⇒ chain unchanged. | random corrupt index | pre==post state | SH-5 |
| F-4 | (mainnet) PoW: a sub-target hash is always rejected. | mutate nonce | `PowFailed` | SH-3 |

## LIST 3 — E2E / integration tests

| # | Scenario | Setup | Assert | Source |
|---|---|---|---|---|
| E-1 | Listener bootstrap + sync loop | `GetLastSavedBlock` → batched `SubmitHeaders` | tip tracks; outcome fields correct | SH-1 |
| E-2 | Cross-flow: forged signet chain + fake merkle proof passes Sign EVM SPV | signet build; forged chain; fake proof | **today: signs (vuln); post-fix: rejects** | TEE-SH-01 |
| E-3 | Freeze attack: stop pushing headers → Sign EVM staleness halts signing | stale tip | `Spv` "too stale" | cross-ref sign_evm L-7 |

## LIST 4 — Attack vectors (consolidated)

| # | Actor | Scenario | Impact | Current defense | Required fix / risk | Source |
|---|---|---|---|---|---|---|
| AV-1 | Listener (signet) | Forge the header chain (linkage-only) + fake merkle proofs → defeat Sign EVM SPV gate | Unauthorised unlock backing | none on signet (PoW skipped, BIP-325 absent) | proto `coinbase_txs` + BIP-325 verify (TEE-SH-01) | A.3 |
| AV-2 | Operator | Non-boundary checkpoint → chain wedges at first retarget | Signing halts (liveness) | none | boundary checkpoint or short-circuit non-PoW `epoch_start_time` (TEE-SH-02) | SH-7 |
| AV-3 | Listener (mainnet) | Submit forged / low-difficulty / deep-reorg chain | — | PoW + nBits + depth/work bounds | none needed (dismissed) | SH-3/4 |

## LIST 5 — Formal verification

| # | Property | Target | Assumptions | Tool | Expected |
|---|---|---|---|---|---|
| FV-1 | Post-`submit_headers`, the stored chain is linkage-consistent from the checkpoint to the tip. | `HeaderChain` | — | Kani / model | prove |
| FV-2 | A reorg commits **iff** `depth ≤ 100 ∧ new_work > existing_work`; else state unchanged. | `submit_headers` reorg branch | — | Kani | prove |
| FV-3 | (mainnet) accepted ⇒ every header meets target ∧ retarget-correct nBits. | `validate_header_full` | bitcoin crate PoW correct | property | prove |
| FV-4 | No retarget-boundary height yields `HeaderNotFound` given a boundary-aligned checkpoint. | `epoch_start_time` | checkpoint %2016==0 | Kani | prove (counterexample for non-aligned ⇒ TEE-SH-02) |

---

## Summary

- **New items:** TEE-SH-02 (retarget-boundary wedge — Med–High, cheap fix).
- **Confirmed/elevated:** TEE-SH-01 (signet header authentication — High; the root cause
  behind Sign EVM's SPV Layer-2 deferral). TEE-SH-03 placeholder checkpoints (carried,
  release-blocker).
- **Counts:** L1 4 unit · L2 4 fuzz · L3 3 E2E · L4 3 attack vectors · L5 4 FV.
- **Deferred to Layer 2:** BIP-325 design (proto + coinbase witness); the Sign EVM
  downstream impact (tracked in `Step 2 - sign_evm.md`).
- **Top priority:** decide BIP-325 timeline (TEE-SH-01 gates any signet-backed value)
  and pick a **boundary-aligned** real checkpoint (TEE-SH-02 + TEE-SH-03 together).

### Self-verification (review rules §12 + Step 2 Phase 4)
- [x] Every Confirmed/Dismissed cites code lines; dismissals name the guard + test.
- [x] No invented symbols; all from Step 1's verified scope.
- [x] New (TEE-SH-02) vs known/deferred (TEE-SH-01) clearly separated.
- [x] Cross-flow (Sign EVM SPV, BIP-325 proto) → Layer 2 with explicit cross-refs.
- [x] Part B = specs not code; signet auth test marked blocked-on-proto.
- [x] Mainnet soundness stated honestly alongside the signet gap.
