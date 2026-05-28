# Nitro Enclave Signer -- Technical Specification

**Component:** `enclave-signer` (TEE validator / signer + parent adapter)
**Status:** Draft for internal review
**Date:** 2026-05-25 (code @ HEAD `5148f0c`, #41)
**Parent spec:** *RGB <-> EVM Bridge Technical Specification* (Draft 06/05/2026) -- Sec 5.6, Sec 10, Sec 12, Sec 13, Sec 16
**Companion docs:** [`audit/ENCLAVE_SIGNER_CONTEXT.md`](audit/ENCLAVE_SIGNER_CONTEXT.md) | [`audit/cross-flow-findings.md`](audit/cross-flow-findings.md) | [`diagrams/`](diagrams/)

Normative keywords (MUST / MUST NOT / SHOULD / MAY) follow RFC 2119. Where the
current implementation diverges from a normative requirement, it is flagged
inline as **`[GAP]`** with a pointer to `audit/cross-flow-findings.md`.

---

## 1. Purpose

The enclave signer is the trust-minimised authorization component of the bridge.
It runs inside an **AWS Nitro Enclave (TEE)** and is the only component permitted
to produce the signatures that release EVM-side liquidity (`fundsOut`) and that
sign Bitcoin PSBTs for the RGB-side flows.

Its job is to **move trust away from the host operator**: even a fully
compromised parent host, listener, or backend MUST NOT be able to extract a
signature unless every protocol predicate holds. The enclave validates RGB
consignments, Bitcoin SPV inclusion, and cross-domain bindings *itself*, rather
than trusting any value asserted by the host.

## 2. Trust boundary and threat model

```
Internet -- orchestrator -- EC2 parent (UNTRUSTED) -- vsock -- Nitro Enclave (TRUSTED)
                                  |                                    |
                              listener,                          key material,
                              backend, NSM proxy,                validation, signing
                              Esplora proxy                       (this spec)
```

| Actor                            | Trusted for                                      | NOT trusted for                                                                       |
|----------------------------------|--------------------------------------------------|---------------------------------------------------------------------------------------|
| Nitro hardware + NSM             | measurement (PCRs), attestation signing, entropy | --                                                                                     |
| Enclave code (this repo)         | validation, key custody, signing                 | -- (the thing being attested)                                                          |
| Parent host / listener / backend | liveness, transport, data *delivery*             | **any semantic claim** -- every value is re-derived or re-validated inside the enclave |
| Esplora / Bitcoin data providers | availability                                     | correctness -- outputs are checked against in-enclave PoW header chain + SPV           |
| Operator                         | deployment, the pre-shared cloning secret        | seed access (never leaves the TEE in plaintext)                                       |

**Trust anchors (residual):** TEE manufacturer (AWS), the Nitro attestation
root CA, the correctness of *this* enclave code, and the correctness of the RGB
/ SPV validation libraries. (Parent spec Sec 6.2, Sec 6.3.)

## 3. Architecture

The signer is three crates plus the external infrastructure it touches.

![Component structure](diagrams/components.svg)
*Source: [`diagrams/01-components.puml`](diagrams/01-components.puml)*

- **`enclave`** -- runs inside the TEE. Listener loop (vsock in prod, TCP in dev)
  -> `server.rs` handler dispatch -> `KeyManager`, `validation/*`, `spv/*`,
  `signing/*`, `cloning.rs`, `attestation.rs`.
- **`attestation-verify`** -- shared, no-std-friendly library that verifies a
  COSE_Sign1 Nitro attestation document against the embedded AWS Nitro root CA
  (cert-chain + PCR equality + nonce). Used by both the parent CLI and, for
  peer attestation, inside the enclave.
- **`parent`** -- untrusted EC2-side adapter: tonic gRPC server (`grpc_server.rs`)
  bridging the bridge backend to the enclave's length-prefixed wire protocol,
  plus the `attest-verify` CLI.

### Deployment

![Deployment](diagrams/deployment.svg)
*Source: [`diagrams/02-deployment.puml`](diagrams/02-deployment.puml)*

Wire protocol enclave<->parent is a **4-byte little-endian length prefix + prost
protobuf** (`framing.rs`, 4 MB cap). Esplora and NSM are reached through
host-side proxies over vsock so the enclave has no direct network stack.

## 4. Key management

- Keys are **generated inside the enclave** from OS entropy (BIP-39 mnemonic ->
  BIP-32 seed) and are **enclave-confined**: the 64-byte seed lives only in a
  `SecretBox` / `Zeroizing` buffer and MUST NOT be exported in plaintext to the
  parent, backend, or operator (parent spec Sec 16.4).
- Derivation paths:
  - EVM signing key: `m/44'/60'/0'/0/0`; `evm_address = keccak256(uncompressed_pub[1..])[12..]`.
  - BTC SegWit: `m/84'/0'/0'/0/0`.
  - BIP-86 taproot: vanilla `m/86'/<coin>'/0'`, colored `m/86'/827167'/0'`.
- The **EVM address is the cluster identity**: a cloned enclave installs the
  same seed and therefore signs as the same address; `complete_cloning` asserts
  `km.evm_address() == session.cluster_public_key` before going `Active`.

![Initialize keys](diagrams/seq-initialize-keys.svg)
*Source: [`diagrams/07-seq-initialize-keys.puml`](diagrams/07-seq-initialize-keys.puml)*

## 5. State machine

The enclave is a three-phase machine. **Signing is enabled only in `Active`**,
and `Active` is terminal -- there is no in-place rotation or re-init.

![Phase state machine](diagrams/state-phase.svg)
*Source: [`diagrams/09-state-phase.puml`](diagrams/09-state-phase.puml)*

| Phase     | Holds                                                       | Signing | Entry                                            |
|-----------|-------------------------------------------------------------|---------|--------------------------------------------------|
| `Initial` | nothing                                                     | [NO]      | boot                                             |
| `Cloning` | `CloningSession` (ephemeral X25519 + target cluster pubkey) | [NO]      | `begin_cloning` (requester)                      |
| `Active`  | `Box<KeyManager>` (seed in `SecretBox`)                     | [OK]      | `initialize_from_entropy`, or `complete_cloning` |

A second initialize attempt MUST fail with `AlreadyInitialized` (`ensure_initial`).
Upgrades/rotation MUST be done by standing up a **new cluster with new PCRs**,
not by mutating an `Active` enclave (parent spec Sec 16.5).

## 6. Protocol flows

### 6.1 RGB burn -> EVM unlock (the protected path)

The enclave signs `fundsOut` only after all validation predicates (Sec 8) hold.

![Sign EVM](diagrams/seq-sign-evm.svg)
*Source: [`diagrams/03-seq-sign-evm.puml`](diagrams/03-seq-sign-evm.puml)*

### 6.2 EVM lock -> RGB (PSBT signing)

Taproot script-path (BIP-340 Schnorr) + SegWit v0 P2WSH (ECDSA), each anchored
to the input's `witness_utxo.script_pubkey` so the enclave signs only the
intended UTXO.

![Sign PSBT](diagrams/seq-sign-psbt.svg)
*Source: [`diagrams/04-seq-sign-psbt.puml`](diagrams/04-seq-sign-psbt.puml)*

### 6.3 SPV header sync

The host feeds Bitcoin headers; the enclave builds its own PoW-validated chain
with bounded reorgs. The full chain MUST be present before any tx validation.

![SPV submit headers](diagrams/seq-submit-headers.svg)
*Source: [`diagrams/08-seq-spv-submit-headers.puml`](diagrams/08-seq-spv-submit-headers.puml)*

### 6.4 Attested public key (public verifiability)

Any external verifier can confirm a signer pubkey belongs to attested enclave
code (parent spec Sec 16.3, Sec 16.6).

![Attested pubkey](diagrams/seq-attested-pubkey.svg)
*Source: [`diagrams/05-seq-attested-pubkey.puml`](diagrams/05-seq-attested-pubkey.puml)*

### 6.5 Cloning (recovery / federation membership)

Three-message handshake; valid only between enclaves with identical PCRs, the
same cluster pubkey, and the shared cloning secret (parent spec Sec 16.4).

![Cloning](diagrams/seq-cloning.svg)
*Source: [`diagrams/06-seq-cloning.puml`](diagrams/06-seq-cloning.puml)*

## 7. RGB / Bitcoin / SPV verification (parent spec Sec 12)

The enclave runs full `rgbstd` consignment validation against an Esplora-backed
resolver, then independently verifies Bitcoin anchoring via its own header chain.

The enclave MUST:
1. hold the full header chain before accepting tx validation (`header_at` returns
   `None` below checkpoint / above tip);
2. validate header linkage, PoW, and nBits, and track the best chain by
   cumulative work with bounded reorgs (`MAX_REORG_DEPTH = 100`);
3. for **every** witness tx referenced by the consignment -- not only the most
   recent burn anchor -- verify Merkle inclusion against the stored header root
   and require `>= SPV_MIN_CONFIRMATIONS (6)` depth;
4. reject a stale or future-dated chain tip (`SPV_MAX_TIP_AGE_SECS`,
   `SPV_MAX_TIP_FUTURE_SECS` = 2 h) to defeat a frozen-feed attack;
5. reject a consignment whose `chain_net` differs from the enclave's compiled
   network (cross-network replay defense).

`SPV_MIN_CONFIRMATIONS` MUST be a compile-time constant, not host-configurable --
otherwise an operator could set it to 0 while attestation still passed.

**`[GAP]`** Production checkpoints are placeholders (`is_real = false`); a
release-build assert fails closed, but real checkpoints MUST be pinned before
mainnet.

## 8. Unlock authorization predicates (parent spec Sec 10) -- NORMATIVE

Before signing `fundsOut`, the enclave MUST verify **all** of the following and
MUST refuse to sign (fail closed) if any fails. This is the heart of the spec.

![Signing gate](diagrams/signing-gate.svg)
*Source: [`diagrams/10-signing-gate.puml`](diagrams/10-signing-gate.puml)*

| #   | Predicate                                                                               | Implemented                                                        |
|-----|-----------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| P1  | submitted RGB consignment is valid (`rgbstd` full validation)                           | [OK]                                                               |
| P2  | consignment proves the **expected burn transition**                                     | **`[GAP/partial]`** (#41) classified via `TS_BURN`, but signing not gated on it |
| P3  | burn amount **equals** amount requested for unlock, derived from `burnedAsset` metadata | **`[GAP/partial]`** (#41) amount extracted (`burned_asset_amount`), but decision still uses host `rgb_amount`, `>=` not `=` |
| P4  | bridge metadata is well-formed                                                          | [~] partial                                                        |
| P5  | payload binds correct destination chain / contract / **recipient**                      | **`[GAP]`** recipient not cross-checked                            |
| P6  | payload binds correct **RGB `OpId`** (the cross-domain identifier, Sec 7)               | **`[GAP]`** no `OpId` in wire format or signed payload             |
| P7  | referenced Bitcoin txs are in accepted chain history                                    | [OK]                                                               |
| P8  | Bitcoin inclusion proofs valid against supplied headers                                 | [OK]                                                               |
| P9  | corresponding EVM lock record exists for same `OpId`                                    | on-chain (Sec 11), depends on P6                                   |
| P10 | EVM execution payload **exactly matches** the validated unlock intent                   | **`[GAP]`** intent not independently derived                       |
| P11 | on any failure, refuse to sign                                                          | [OK] fail-closed                                                   |

The signed digest is `EIP-712( SignRequest(bytes callData, uint256 nonce,
uint256 deadline) )` over domain `(name, version, chainId, verifyingContract)`.
The domain `name`/`version` MUST match the deployed `MultisigProxy` and SHOULD
be pinned by a contract-derived fixture test. **`[GAP]`** currently `"Tricorn"`/`"1"`
with a `TODO`.

> The four `[GAP]`s above are one root cause: **the enclave currently trusts
> host-supplied semantic fields (`rgb_amount`, recipient, implied `OpId`)
> instead of deriving them from the consignment it validates.** Closing them is
> the pre-mainnet blocker -- see `audit/cross-flow-findings.md` Sec "Priority gaps".

## 9. Attestation & federation (parent spec Sec 16)

- **Public verifiability:** each signer pubkey is generated in-enclave and bound
  to a Nitro attestation; the COSE_Sign1 document chains to the embedded AWS
  Nitro root CA and commits to the canonical pubkey bundle + verifier nonce.
- **PCR policy:** PCR0 and PCR1 MUST be checked by frontend, backend, and fellow
  signers; PCR2 MAY be checked for stronger app-state binding. The verifier
  asserts all of PCR0/1/2 equal expected (stricter than the spec's minimum).
- **Cloning** is valid only if source and destination enclaves: target the same
  cluster pubkey, run the same accepted code snapshot (PCR equality), share the
  same cloning secret, and complete **mutual** attestation. The DH exchange MUST
  reject non-contributory (small-order) points; the seed ciphertext is bound to
  the per-handshake key via HKDF `info = donor_pub || requester_pub`.
- **Federation / quorum:** unlock SHOULD require an M-of-N enclave-signer quorum.
  Quorum enforcement is on-chain in `MultisigProxy` (out of this repo); the
  enclave guarantees the spec's "signed payload identical across quorum members"
  because the EIP-712 digest is a pure function of `callData`/`nonce`/`deadline`.
- **Replay:** the in-enclave `NonceReplayGuard` covers cloning attestation
  nonces; the authoritative unlock replay guard is on-chain `burnId` consumption
  (Sec 8.2, out of repo). The EIP-712 `nonce` is bound into the signed payload.

## 10. Security invariants -- NORMATIVE

The enclave MUST uphold the following. Each maps to parent spec Sec 14/Sec 15.

| ID        | Invariant                                                                                                                                               |
|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| **SI-1**  | A compromised parent/listener/backend alone MUST NOT yield a `fundsOut` signature. (Depends on P2/P3/P5/P6 -- see `[GAP]`s.)                            |
| **SI-2**  | A forged or malformed RGB consignment MUST NOT trigger signing. [OK]                                                                                    |
| **SI-3**  | A Bitcoin inclusion proof inconsistent with the in-enclave PoW chain MUST NOT trigger signing. [OK]                                                     |
| **SI-4**  | An EVM unlock payload not bound to the RGB `OpId` MUST NOT be accepted. **`[GAP]` P6.**                                                                 |
| **SI-5**  | The signing seed MUST NOT leave the enclave in plaintext; only HKDF-sealed ciphertext crosses the wire, and only during a mutually-attested clone. [OK] |
| **SI-6**  | Cloning MUST require identical PCRs (same code), same cluster pubkey, and the shared cloning secret -- i.e. cloning MUST NOT be an upgrade path. [OK]   |
| **SI-7**  | Confirmation depth and chain-freshness thresholds MUST NOT be host-configurable. [OK]                                                                   |
| **SI-8**  | The enclave MUST verify SPV depth on **every** anchoring tx in the relevant RGB history, not only the most recent burn tx. [OK]                         |
| **SI-9**  | Signing MUST be possible only in `Active`; `Initial`/`Cloning` MUST reject all signing and key-export RPCs (except the donor's sealed export). [OK]     |
| **SI-10** | On any validation failure the unlock path MUST fail closed (no partial signature, no fallback). [OK]                                                    |
| **SI-11** | A feature/build mismatch (e.g. request carries `merkle_proofs` but the binary lacks `spv`) MUST cause refusal, never a sign-without-verification. [OK]  |
| **SI-12** | Cross-network consignments (e.g. regtest replayed at a mainnet enclave) MUST be rejected. [OK]                                                          |

## 11. Failure conditions

On any of the following the enclave MUST return an error and MUST NOT sign:
invalid RGB consignment; invalid/missing burn transition; amount mismatch;
malformed bridge metadata; `OpId` mismatch across domains; invalid Bitcoin
inclusion proof; inconsistent or stale Bitcoin headers; missing/insufficient
SPV confirmations; cross-network consignment; wrong phase; deadline expired;
replayed cloning nonce.

## 12. Implementation status & blockers

Conformant and solid: Sec 7 SPV stack (incl. SI-8), Sec 9 attestation + cloning
(Sec 16.4), fail-closed posture (SI-10/11), cross-network defense (SI-12).

**Pre-mainnet blockers** (detail in [`audit/cross-flow-findings.md`](audit/cross-flow-findings.md)):

1. Bind the RGB `OpId` end-to-end (P6 / SI-4) -- add to wire format, derive from
   consignment, require equality, include in the signed EIP-712 struct.
2. Validate burn semantics and derive the amount from `burnedAsset` (P2/P3).
   _#41 did the extraction half_ (`TS_BURN` classification + `burned_asset_amount`);
   remaining: gate signing on `TS_BURN` and use `burned_asset_amount` (== not `>=`)
   in place of host `rgb_amount`.
3. Derive destination (contract + recipient) from the validated RGB payload (P5).
4. Pin real SPV checkpoints for mainnet/signet/testnet3 (Sec 7).
5. Pin the EIP-712 domain with a contract-derived fixture test (Sec 8).

---

## Appendix A -- Diagram index

| Diagram                       | Source                                    | Rendered                      |
|-------------------------------|-------------------------------------------|-------------------------------|
| Component structure           | `diagrams/01-components.puml`             | `components.svg/png`          |
| Deployment / trust zones      | `diagrams/02-deployment.puml`             | `deployment.svg/png`          |
| Sign EVM (unlock)             | `diagrams/03-seq-sign-evm.puml`           | `seq-sign-evm.svg/png`        |
| Sign PSBT                     | `diagrams/04-seq-sign-psbt.puml`          | `seq-sign-psbt.svg/png`       |
| Attested pubkey               | `diagrams/05-seq-attested-pubkey.puml`    | `seq-attested-pubkey.svg/png` |
| Cloning handshake             | `diagrams/06-seq-cloning.puml`            | `seq-cloning.svg/png`         |
| Initialize keys               | `diagrams/07-seq-initialize-keys.puml`    | `seq-initialize-keys.svg/png` |
| SPV submit headers            | `diagrams/08-seq-spv-submit-headers.puml` | `seq-submit-headers.svg/png`  |
| **Phase state machine**       | `diagrams/09-state-phase.puml`            | `state-phase.svg/png`         |
| **Signing gate / predicates** | `diagrams/10-signing-gate.puml`           | `signing-gate.svg/png`        |
