# Spec Conformance Review -- Enclave-Signer vs. RGB <-> EVM Bridge Technical Specification

**Spec:** *RGB <-> EVM Bridge Technical Specification* -- Draft, last update 06/05/2026
**Code:** `enclave-signer` @ branch `dev`, HEAD `c51d6fb` (#43) (this repo)
**Reviewed:** 2026-05-25, refreshed 2026-05-28 after #44 / #47 / #43 landed

## Scope note

The spec describes the **whole system**: EVM contracts (`BridgeBase`, `Bridge`,
`MultisigProxy`, `BtcRelay`), the RGB mint smart contract, the orchestration
backend, the Bitcoin data providers, **and** the Nitro Enclave validator/signer.

**This repo is only the TEE validator/signer + its parent adapter.** So large
parts of the spec are *out of this repo's scope* and can only be validated
against their own repos:

| Spec section                                                            | Component            | In this repo?      |
|-------------------------------------------------------------------------|----------------------|--------------------|
| Sec 5.1-5.4 BridgeBase / Bridge / MultisigProxy / BtcRelay              | Solidity             | [NO] separate repo |
| Sec 4.8 RGB Mint Smart Contract                                         | RGB contract         | [NO] separate repo |
| Sec 5.5 Bridge Backend                                                  | Go listener          | [NO] separate repo |
| Sec 8 replay (`burnId` consumption), Sec 11 on-chain checks             | Solidity             | [NO] separate repo |
| Sec 16.5 admin federation / timelock / upgrades                         | Solidity + ops       | [NO] separate repo |
| **Sec 5.6 / Sec 10 TEE validation predicates**                          | **enclave**          | [OK]               |
| **Sec 12 RGB / Bitcoin / SPV verification**                             | **enclave**          | [OK]               |
| **Sec 13 Destination binding (TEE derivation)**                         | **enclave**          | [OK]               |
| **Sec 16.3 attestation, Sec 16.4 cloning, Sec 16.6 signer attestation** | **enclave + parent** | [OK]               |

Everything below judges only the in-repo sections.

---

## Verdict

The **SPV / Bitcoin verification stack (Sec 12) and the attestation + cloning model
(Sec 16) are strong and substantially conformant.** As of #44 / #47 the **burn
amount is now bound to the validated consignment** (Sec 9) and the **`consignment_valid`
bypass is closed** (Sec 10.1) -- the two changes that moved the burn-amount finding
from "host-supplied" to "consignment-derived". The **core unlock-authorization
predicate set (Sec 10) and destination binding (Sec 13) are still NOT fully
conformant**: the single most important cross-domain primitive the spec defines, the
**RGB `OpId` binding, is entirely absent**, and the **EVM recipient is still not
cross-checked**. The amount binding is `>=` / `<=` (release ≤ what RGB destroyed),
not the spec's strict `==`, and the mint/burn selector path is **inert in production**
until the listener migrates off the legacy 6-arg `fundsOut`.

These remaining items are pre-mainnet blockers. They are acknowledged in code
comments as "follow-up PR" work, so this is a known-incomplete state, not a silent gap.

---

## Sec 10 TEE Validation Predicates -- the central checklist

The spec lists 11 predicates the TEE MUST verify before signing, and says
"if any predicate fails, the TEE MUST refuse to sign." Mapping each to code
(`enclave/src/server.rs::handle_sign_evm`, `validation/evm_crosscheck.rs`,
`validation/rgb.rs`, `validation/spv_crosscheck.rs`):

| #  | Predicate                                                          | Status     | Where / why                                                                                                                                                                                                                                                                                                                                                                     |
|----|--------------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | submitted RGB consignment is valid                                 | [OK]       | `rgb.rs` runs full `rgbstd` validation against an Esplora resolver -- no longer trusts the listener boolean.                                                                                                                                                                                                                                                                    |
| 2  | consignment proves the **expected burn transition**                | [~]        | (#44) `validate_funds_out_burn` now **gates the mint/burn selector (`0x179bef59`) on `transition_type == ifa::TS_BURN`** (`evm_crosscheck.rs:276`) -- a non-burn consignment on that path is rejected. The legacy pools selector (`0x1ad880b2`) gates on `TS_TRANSFER` instead (`validate_funds_out_transfer`), which is the pools-release model, not a burn. So the burn-transition gate exists for the burn path, but that path is **inert in production** until the listener emits the new selector.                                                                                                                                                                                                                                                   |
| 3  | burn amount **equals** amount requested for unlock                 | [~]        | (#44 / #47) the amount is now **bound to the consignment**, not the listener: mint/burn requires `calldata_amount <= burned_asset_amount` from `MS_BURNED_ASSET` metadata (`evm_crosscheck.rs:289`); legacy pools requires `calldata_amount + commission <= last_transition.total_output_amount` (`evm_crosscheck.rs:357`). The host-supplied `req.rgb_amount` is no longer the sole gate. Still `<=`, not the spec's strict `==`. |
| 4  | bridge metadata in RGB payload is well-formed                      | [~]        | Only selector/amount/chain/contract presence is checked. No structured bridge-metadata parse from the consignment.                                                                                                                                                                                                                                                              |
| 5  | payload binds correct destination chain / contract / **recipient** | [~]        | (#43) `chain_id` and `proxy_contract` (and `rgb_asset_id`) are now **pinned at boot from env and cross-checked** when configured (`evm_crosscheck.rs:192-225`), and the same values are folded into the attestation `user_data`. **Recipient is still never cross-checked** -- it is just whatever bytes the listener put in calldata.                                                                                                                                                                                                                     |
| 6  | payload binds correct **`OpId`**                                   | [NO]       | **Not checked anywhere.** There is no `op_id` field in `SignEvmRequest` (proto) and no comparison of consignment `op_id` against the EVM payload. This is the spec's primary cross-domain identifier (Sec 7).                                                                                                                                                                   |
| 7  | referenced Bitcoin txs included in accepted chain history          | [OK]       | `spv_crosscheck::validate_spv_proofs` -- set-equality coverage of every witness txid.                                                                                                                                                                                                                                                                                           |
| 8  | inclusion proofs valid against supplied headers                    | [OK]       | Merkle reconstruction vs. stored header root, correct byte-order handling.                                                                                                                                                                                                                                                                                                      |
| 9  | corresponding EVM-side lock record exists for same `OpId`          | [n/a]      | Intentionally delegated **on-chain** per Sec 11 (`Bridge.fundsOut` checks the lock record). Acceptable to be out of TEE -- *but* it relies on the `OpId` binding that predicate 6 does not yet provide.                                                                                                                                                                         |
| 10 | EVM execution payload **exactly matches** validated unlock intent  | [~]        | The enclave signs the listener's `call_data` verbatim. Because amount/recipient/`OpId` are not independently derived from the consignment, "exactly matches the *validated* intent" cannot currently be claimed -- there is no independently-derived intent to match against.                                                                                                   |
| 11 | (fail-closed)                                                      | [OK]       | All checks return `Err(CrossCheck/Spv)` -> no signature. Fail-closed is correctly implemented.                                                                                                                                                                                                                                                                                  |

**Net:** predicates 1, 7, 8, 11 [OK]; 9 [n/a] (on-chain by design); **6 [NO]; 2, 3, 4, 5, 10 [~].**

> **Change since last review (#44 / #47 / #43):** the burn-amount finding is
> substantially closed. #47 drops the `consignment_valid` carve-out -- fundsOut
> now *requires* validated consignment bytes (default builds refuse fundsOut
> outright) and binds the legacy-pools amount to `last_transition.total_output_amount`.
> #44 wires the second half of the burn check: `validate_funds_out_burn` gates the
> mint/burn selector on `TS_BURN` and on `calldata_amount <= burned_asset_amount`.
> #43 pins chain_id / bridge contract / rgb_asset_id from env, cross-checks them,
> and binds them into the attestation `user_data`. **Net effect on funds-theft
> posture:** the amount and the chain/contract are no longer host-supplied. What
> remains: the bind is `<=` not `==`; **recipient and `OpId` are still unbound**;
> and the mint/burn path is inert until the listener migrates off the 6-arg
> `fundsOut`. So a compromised listener can no longer over-withdraw or redirect to
> another chain/contract, but recipient/`OpId` substitution within the pinned
> bridge is not yet caught (see Root cause).

### Root cause

The whole spec hangs on the **`OpId` as cross-domain identifier** (Sec 7, Sec 13,
Sec 14, Sec 15 all reference it). In the current wire format the `OpId` is not
transmitted, not extracted from the consignment for a decision, and not bound
into the signed EIP-712 payload:

- `proto/enclave.proto::SignEvmRequest` still has **no `op_id` field**.
- `signing/evm.rs` signs `SignRequest(bytes callData, uint256 nonce, uint256 deadline)`
  -- the `OpId` is at best buried inside `callData` as the `transactionId` string
  arg, but the enclave never parses or cross-checks it against the consignment.
- `rgb.rs` *does* extract `all_op_ids` and `last_transition.op_id` (and, since
  #41, classifies the burn and extracts `burned_asset_amount`), but the mint/burn
  `OpId` cross-check is still not written. So the data is on hand; the binding
  logic is not.

After #44 / #47 the **amount** half of this attack is closed: a valid-but-unrelated
consignment can no longer authorise a *larger* withdrawal, because the release is
bound to `burned_asset_amount` / `total_output_amount` rather than the listener's
`rgb_amount`. What remains: a compromised listener that supplies a **valid but
unrelated** consignment together with calldata for a *different recipient* (at an
amount ≤ what that consignment destroyed) still passes every in-enclave check --
recipient and `OpId` are not bound to the consignment. This is the residual of the
attack Sec 8.1 / Sec 14 ("an EVM unlock payload not bound to the RGB `OpId` MUST
NOT be accepted") is meant to stop.

---

## Sec 9 RGB Burn Semantics -- [~] validated (#41 extract, #44 enforce)

Spec: a valid burn proof MUST establish the consumed allocation existed, the
burned amount is unspendable, and the amount is unambiguous; **"the burned
amount MUST be derived from the burn transition's `burnedAsset` metadata."**

Code (after #41): `rgb.rs` reads the `burnedAsset` (`MS_BURNED_ASSET = 1001`)
metadata and decodes the strict-encoded `u64` into
`TransitionSummary.burned_asset_amount`, populated only when
`transition_type == ifa::TS_BURN (8010)`.

Code (after #44): `validate_funds_out_burn` (`evm_crosscheck.rs:262-297`) now
**consumes** that value. For the mint/burn selector it asserts (a) the last
transition is a `TS_BURN`, (b) it carries `MS_BURNED_ASSET` metadata, and (c)
`calldata_amount <= burned_asset_amount`. It is called from `handle_sign_evm`
(`server.rs:402`) and fail-closes when a mint/burn selector arrives without a
validated consignment. So the spec's "derive the amount from `burnedAsset`
metadata and act on it" is now done.

**Remaining gaps:** (1) the check is `<=`, not the spec's strict `==` -- the
intent ("release at most what was destroyed") is enforced, but exact-equality is
not; (2) the burn path is **inert in production** until the listener emits the
new 8-arg selector (`0x179bef59`); today's traffic uses the legacy 6-arg pools
`fundsOut`, which binds against `total_output_amount` of a `TS_TRANSFER`, not a
burn. A real-burn-fixture round-trip test is still pending (synthetic
`ValidatedConsignment` only).

---

## Sec 12 RGB / Bitcoin / SPV Verification -- [OK] strong

This is the best-conformed section.

| Spec requirement | Status | Evidence |
|---|---|---|
| Full header chain present in TEE before tx validation | [OK] | `header_at()` returns `None` below checkpoint / above tip; staleness gate rejects a frozen feed. |
| Header validity / PoW / best-chain by cumulative work | [OK] | `spv/validation.rs` (linkage + nBits + PoW), `spv/chain.rs` (cumulative-work reorg, `MAX_REORG_DEPTH=100`, weaker-chain rejection). |
| Inclusion proof correctness (reconstruct root, compare) | [OK] | `spv/merkle.rs` + `verify_one_proof`; careful display<->internal byte-order conversion. |
| Sufficient confirmation depth | [OK] | `SPV_MIN_CONFIRMATIONS = 6`, compile-time (not env-overridable -- good: an operator can't set it to 0). |
| **"MUST NOT rely only on the most recent anchoring tx; full relevant history MUST satisfy the threshold"** | [OK] | `validate_spv_proofs` enforces depth on **every** witness txid via set-equality, not just the burn tx. Explicitly matches the spec sentence. |
| Cross-network replay defense | [OK] (beyond spec) | `assert_chain_net` rejects e.g. a regtest consignment at a mainnet enclave. |

**One blocker, not a logic gap:** `spv/checkpoint.rs` ships **placeholder
checkpoints (`is_real = false`)** for mainnet/signet/testnet3. There is a
release-build assert (`assert_real_in_release()`) so this fails closed, but real
checkpoints MUST be pinned before mainnet. (Already flagged in
`docs/project-review.md`.)

---

## Sec 13 Destination Binding Rules -- [NO] not conformant

Spec: for every burn the bridge metadata MUST bind {EVM contract address, EVM
recipient, RGB `OpId`}; **"the TEE MUST derive the EVM-side unlock destination
deterministically from the validated RGB payload"**; ambiguous/missing/mismatched
binding MUST be rejected.

Code: the enclave does **not derive** the destination from the RGB payload. It
accepts contract + recipient from listener-provided calldata and only checks the
proxy contract is 20 bytes. There is no derivation, and no mismatch check against
consignment-carried destination metadata. Non-conformant.

---

## Sec 16 TEE Federation -- mostly conformant

| Spec requirement                                                                                              | Status          | Notes                                                                                                                                                                                                                                                                                                        |
|---------------------------------------------------------------------------------------------------------------|-----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Sec 16.3 keys generated in enclave, bound to attestation, publicly verifiable                                 | [OK]            | `handle_get_attested_public_key` -> NSM COSE_Sign1 over pubkey + bundle commitment; `attest-verify` CLI verifies cert chain to embedded AWS Nitro root + PCRs + nonce.                                                                                                                                       |
| Sec 16.3 PCR0/PCR1 mandatory checked; PCR2 optional                                                           | [OK] (stricter) | `attestation-verify` asserts PCR0/1/2 all equal expected. Stricter than spec (PCR2 MAY) -- fine, but means PCR2 must be pinned by verifiers.                                                                                                                                                                 |
| Sec 16.4 cloning valid only if same cluster pubkey + same snapshot + same cloning secret + mutual attestation | [OK]            | `cloning.rs` + `server.rs`: cluster pubkey equality, PCR equality (same snapshot), `HMAC(cloning_secret, enc_pubkey)` digest, mutual `verify_peer_attestation`, X25519 contributory check, HKDF-bound ciphertext, requester asserts derived `evm_address == cluster_public_key`. Matches Sec 16.4 closely.   |
| Sec 16.4 keys enclave-confined, never plaintext to parent/operator                                            | [OK]            | `SecretBox`/`Zeroizing`; only HKDF-sealed ciphertext crosses the wire.                                                                                                                                                                                                                                       |
| Sec 16.4 cloning is recovery, not upgrade                                                                     | [OK]            | Enforced by PCR equality -- a new image (different PCRs) cannot clone.                                                                                                                                                                                                                                       |
| **Sec 16.2 / Sec 16.8 M-of-N quorum**, "one signer MUST NOT authorize `fundsOut` alone"                       | [n/a]           | Quorum is enforced on-chain by `MultisigProxy` (out of repo). Each enclave signs **independently**; the spec's "signed payload MUST be identical across quorum members" is satisfied because the EIP-712 digest is a pure function of `callData`+`nonce`+`deadline`. No quorum logic in this repo by design. |
| Sec 16.8 replay protection at federation execution layer                                                      | [n/a]           | Real replay guard is on-chain `burnId` consumption (Sec 8.2, out of repo). In-repo: EIP-712 `nonce` is bound; `NonceReplayGuard` covers cloning attestations.                                                                                                                                                |

---

## Sec 14 / Sec 15 Security Invariants & Failure Conditions -- TEE-enforced subset

| Invariant / failure                                                  | Status                                                                                                                                                                                                                                    |
|----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| compromised backend alone MUST NOT unlock                            | [~] partial -- after #44/#47/#43 the **amount** is bound to the consignment and **chain/contract** are pinned, so a compromised backend can no longer over-withdraw or redirect to another chain/contract. **Recipient and `OpId` still flow from backend-controlled listener fields**, so a compromised backend can still redirect an unlock to a different recipient (≤ the burned amount) until Sec 10.6/Sec 13 land. |
| forged/malformed consignment MUST NOT trigger unlock                 | [OK] -- `rgbstd` validation + deserialization gate.                                                                                                                                                                                       |
| Bitcoin proof inconsistent with chain state MUST NOT unlock          | [OK] -- SPV crosscheck.                                                                                                                                                                                                                   |
| EVM payload not bound to `OpId` MUST NOT be accepted                 | [NO] -- no `OpId` binding (see Sec 10/#6).                                                                                                                                                                                                |
| user exit MUST NOT depend on discretionary post-burn operator action | [n/a] out of repo (liveness/atomic-swap, Sec 17).                                                                                                                                                                                         |
| on failure, unlock path MUST fail closed                             | [OK] -- all validation errors abort signing.                                                                                                                                                                                              |

---

## Priority gaps to close (in-repo, pre-mainnet)

1. **Bind the RGB `OpId` end-to-end (Sec 6, Sec 7, Sec 10.6, Sec 13, Sec 14).** Add `op_id`
   to `SignEvmRequest`, extract the mint/burn `OpId` from the validated
   consignment, require it to equal the `OpId` committed in the EVM payload,
   and include it in the signed EIP-712 struct so the on-chain side can bind
   the same identifier. *Highest priority -- it is the spec's core primitive,
   and now the only remaining unbound semantic field alongside recipient.*
2. **Bind the EVM recipient to the validated RGB payload and reject mismatch
   (Sec 13).** The amount and chain/contract are now consignment-/config-bound
   (#44/#47/#43), but the recipient is still taken from calldata unverified.
3. ~~**Validate burn semantics + derive amount from `burnedAsset` (Sec 9, Sec 10.2/3).**~~
   **DONE in #44/#47.** `validate_funds_out_burn` gates the mint/burn selector on
   `TS_BURN` and `calldata_amount <= burned_asset_amount`; `validate_funds_out_transfer`
   binds the legacy-pools amount to `total_output_amount`. _Follow-ups:_ tighten
   `<=` to `==` per the spec, and add a real-burn-fixture round-trip test (current
   coverage is synthetic). The mint/burn path is inert until the listener migrates
   off the 6-arg `fundsOut`.
4. **Pin real SPV checkpoints (Sec 12).** Replace `is_real=false` placeholders for
   mainnet/signet/testnet3. (Unchanged by the recent commits.)
5. **Pin the EIP-712 domain (`name`/`version`) with a contract-derived fixture
   test.** Still `"Tricorn"`/`"1"` hardcoded in `build_evm_domain` (`server.rs:552`)
   with a `TODO: confirm with contract team`. #43 pinned chain_id / contract /
   asset but **not** the domain name/version.

Items 1-2 are now the residual of one finding: **the enclave still trusts the
listener-supplied recipient and the (implied) `OpId` instead of deriving them
from the consignment it validates.** The amount used to be on that list -- after
#44/#47 it is derived from the consignment, and after #43 chain/contract are
pinned -- so the gap has narrowed to recipient + `OpId`. The spec's entire trust
model (Sec 6.2 "moves trust away from the host operator") depends on the enclave
deriving the remaining two itself.

## What's genuinely solid

- SPV verification incl. the "all anchors, not just the burn tx" depth rule (Sec 12).
- Cloning/attestation handshake vs. Sec 16.4 (PCR equality, mutual attestation,
  contributory DH, HKDF binding, cluster-pubkey self-check).
- Fail-closed posture and the feature-flag guards (`spv`/`rgb-validation`
  mismatch refuses to sign rather than signing blind).
- Cross-network replay defense -- stronger than the spec asks for.
- **(#44/#47/#43) Unlock amount bound to the validated consignment**
  (`burned_asset_amount` for mint/burn, `total_output_amount` for legacy pools),
  the `consignment_valid` bypass closed, and chain/contract/asset pinned from env
  and committed into the attestation.
