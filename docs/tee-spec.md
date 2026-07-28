# Nitro Enclave Signer -- Technical Specification

**Component:** `enclave-signer` (TEE validator / signer + parent adapter)
**Status:** Current -- describes the audit-fix line (`dev-ng`, including PR #169) that is being ported to `dev`
**Date:** 2026-07-28 (supersedes the 2026-06-01 draft)
**Parent spec:** *RGB <-> EVM Bridge Technical Specification* -- Sec 5.6, Sec 10, Sec 12, Sec 13, Sec 16
**Audit:** Oxorio final report, 22 Jun 2026 ([hosted](https://audits.oxor.io/reports/-OvekSN6D3fiqnoGqrq3)) | status board: issue #91

Normative keywords (MUST / MUST NOT / SHOULD / MAY) follow RFC 2119. Where the
implementation still diverges from a requirement, it is flagged **`[OPEN]`**
with the audit finding ID (Oxorio final numbering) and GitHub issue.

---

## 1. Purpose

The enclave signer is the authorization component of the bridge. It runs inside
an **AWS Nitro Enclave (TEE)** and is the only component that can produce the
signatures that release EVM-side liquidity (`fundsOut`) and that sign Bitcoin
PSBTs for the RGB-side flows.

Its job is to move trust away from the host operator: even a fully compromised
parent host, listener, or backend MUST NOT be able to obtain a signature unless
every protocol predicate holds. The enclave validates RGB consignments, Bitcoin
SPV inclusion, EVM deposit events, and cross-domain bindings itself; it does
not trust semantic claims made by the host.

## 2. Trust boundary and threat model

```
Internet -- orchestrator -- EC2 parent (UNTRUSTED) -- vsock -- Nitro Enclave (TRUSTED)
                                  |                                    |
                              listener, backend,                 key material,
                              Esplora / EVM-RPC / Helios         validation, signing
                              vsock proxies                       (this spec)
```

| Actor                            | Trusted for                                      | NOT trusted for                                                                        |
|----------------------------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| Nitro hardware + NSM             | measurement (PCRs), attestation signing, entropy | --                                                                                     |
| Enclave code (this repo)         | validation, key custody, signing                 | -- (the thing being attested)                                                          |
| Parent host / listener / backend | liveness, transport, data *delivery*             | **any semantic claim** -- every value is re-derived or re-validated inside the enclave |
| Esplora / Bitcoin data providers | availability                                     | correctness -- checked against the in-enclave PoW header chain + SPV                   |
| EVM RPC provider                 | availability                                     | correctness -- Helios-verified when enabled; otherwise fail-closed evidence (Sec 7.2)  |
| Operator                         | deployment, env pins, the cloning secret         | seed access (never leaves the TEE in plaintext)                                        |

**Residual trust anchors:** AWS (Nitro isolation + attestation root CA), the
correctness of this enclave code, and the RGB / SPV validation libraries.

**Wall clock (W-11):** the deadline check, the SPV tip-staleness check, and the
header-submission rate limit read `SystemTime::now()`. Inside Nitro this clock
is hypervisor-provided (kvm-clock); there is no NSM-attested time source. The
accepted assumption: the AWS hypervisor is trusted for *coarse* time --
consistent with already trusting it for isolation and attestation. The parent
cannot skew the enclave clock through any interface this code exposes. If
host-time independence is ever required, the remediation is NSM-attested time
(tracked under #123 / W-11).

**No batch signing (W-03):** the enclave builds exactly one digest shape -- the
single-call `BridgeOperation` EIP-712 struct. There is no batch digest builder,
and the typehash separation means a signature produced here can never authorize
a batch execution. Aligning or removing `executeBatch` on the contract side is
tracked with the contracts team (#123 / W-03).

## 3. Architecture

Three crates plus the infrastructure they touch:

- **`enclave`** -- runs inside the TEE. Connection loop (`main.rs`, vsock in
  prod / TCP in dev; hardening in `conn.rs`) -> `server.rs` dispatch -> `policy.rs` (security policy),
  `keys.rs` / `state.rs` (key custody, phases), `cloning.rs`, `attestation.rs`,
  and the network validators under `networks/`:
  - `networks/rgb/` -- consignment validation, PSBT validation and signing,
    the SPV header chain (`spv/`), plain-BTC crosschecks;
  - `networks/evm/` -- `fundsOut` calldata validation and crosschecks, EIP-712
    signing, `FundsIn` event verification (`evm_event.rs`, optional Helios),
    gas-tx validation.
- **`attestation-verify`** -- shared library that verifies COSE_Sign1 Nitro
  attestation documents against the embedded AWS root CA, and defines the
  canonical **security-policy commitment encoding** (Sec 4) used identically by
  the enclave and every verifier.
- **`parent`** -- untrusted EC2-side adapter: tonic gRPC server bridging the
  backend to the enclave's wire protocol, plus the `attest-verify` CLI.

**Wire protocol** enclave<->parent: 4-byte little-endian length prefix + prost
protobuf, 4 MiB frame cap (`framing.rs`). Esplora, EVM RPC, and Helios are
reached through in-enclave loopback forwarders (ports 3443, 3444, 18545/18550)
that bridge over vsock to host-side `vsock-proxy` instances (vsock ports
8001-8004); the enclave has no direct network stack.

**Connection hardening (M-07 / #117):** fixed pool of 4 worker threads, bounded
queue of 16 connections, 10 s per-syscall idle timeout, 30 s total per-request
deadline. One request per connection. All limits are compile-time constants.

Diagrams: [components](diagrams/01-components.md) |
[deployment](diagrams/02-deployment.md) (see Appendix A for freshness).

## 4. Security policy (audit C-01, PR #169)

The enclave's whole security posture is one explicit value, resolved once at
boot and attested as a single commitment -- a verifier no longer has to infer
the posture from build flags and config guesses.

```
SecurityPolicy = Production {
    chain_id, bridge_contract, rgb_asset_id,   -- operator pins
    allow_vanilla_psbt,                        -- plain-BTC signing on/off
    attestation: Real,                         -- always, in production
    evm_source:  Disabled | RawRpc | HeliosVerified,
    btc_source:  SpvVerified,                  -- always, in production
} | Development { reason }
```

- **Resolution** (`policy.rs`): any dev feature (`dev-mode`,
  `mock-attestation`, `allow-seed-import`), a debug/test build, a non-bridge
  build, or a missing pin resolves to `Development`. Only a release
  `rgb-validation` build with `EVM_CHAIN_ID`, `BRIDGE_CONTRACT`, and
  `RGB_ASSET_ID` all set resolves to `Production`.
- **Boot gate:** a release `rgb-validation` build that does not resolve to a
  valid `Production` policy MUST refuse to boot (panic). Independently, each
  dev feature is a `compile_error!` in any shipped release binary (non-test
  build with debug assertions off), and `rgb-validation` without `spv` is a
  `compile_error!` in every profile (M-01 / #61).
- **Attestation:** `user_data = sha256(canonical_pubkey_bundle ||
  policy_commitment)`. The commitment encoding is versioned and shared
  (`attestation-verify/src/policy.rs`), so the enclave and every verifier
  produce identical bytes. See [`pubkey-attestation.md`](pubkey-attestation.md).
- **Verification:** `attest-verify` reconstructs the *expected* policy
  (`--expect-vanilla-psbt`, `--expect-evm-source raw|helios|disabled`) and
  fails if the commitment differs -- a downgraded posture (vanilla signing on,
  raw RPC instead of Helios, a dev build) fails verification instead of being
  silently trusted.

Not yet inside the commitment: `GAS_TX_ALLOWED_TO`, `FUNDS_IN_CONTRACT`, and
the concrete `BTC_ALLOWED_SCRIPTS` / `BTC_MAX_TOTAL_SATS` values (only the
on/off boolean is attested). Follow-up work; no tracking issue yet.

## 5. Key management

- Keys are **generated inside the enclave** from OS entropy (BIP-39 mnemonic
  -> BIP-32 seed). The 64-byte seed lives in a `SecretBox` and MUST NOT leave
  the TEE in plaintext (parent spec Sec 16.4). Intermediate buffers are
  zeroized; the BIP-86 account xprivs are wiped on drop (I-07 / #151).
- Derivation paths:
  - EVM bridge key (authorization): `m/44'/60'/0'/0/0`;
    `evm_address = keccak256(uncompressed_pub[1..])[12..]`.
  - EVM gas-tx key (outer tx signing, `SignRawDigest`): `m/44'/60'/0'/0/1`.
  - BTC SegWit v0 (legacy P2WSH): `m/84'/0'/0'/0/0`.
  - BIP-86 taproot: vanilla `m/86'/<coin>'/0'`, colored (RGB) `m/86'/827167'/0'`.
- The **EVM address is the cluster identity**: a cloned enclave installs the
  same seed and signs as the same address; `complete_cloning` asserts the
  derived address equals the target cluster key before going `Active`.

[Initialize keys](diagrams/07-seq-initialize-keys.md)

## 6. State machine

Three phases; **signing works only in `Active`**, and `Active` is terminal --
no in-place rotation or re-init.

| Phase     | Holds                                    | Signing | Entry                                            |
|-----------|------------------------------------------|---------|--------------------------------------------------|
| `Initial` | nothing                                  | no      | boot                                             |
| `Cloning` | ephemeral X25519 + target cluster pubkey | no      | `enter_cloning` (requester)                      |
| `Active`  | `KeyManager` (seed in `SecretBox`)       | yes     | `initialize_from_entropy`, or `complete_cloning` |

A second initialize attempt MUST fail (`AlreadyInitialized`). Upgrades MUST be
done by standing up a new cluster with new PCRs, not by mutating an `Active`
enclave (parent spec Sec 16.5). Mnemonic/seed import is rejected unless the
dev-only `allow-seed-import` feature is compiled in (release: `compile_error!`).

[Phase state machine](diagrams/09-state-phase.md)

## 7. Protocol flows

All bridge signing goes through one `Sign` request carrying a source network
and a destination network. Plain-BTC signing is a separate `SignBtc` request
(Sec 7.3). The old standalone SignEvm/SignPsbt request shapes no longer exist.

### 7.1 RGB burn -> EVM unlock (`fundsOut`)

The enclave signs `fundsOut` only after the full predicate set of Sec 9 holds:
validated consignment, SPV-confirmed anchors, canonical calldata, pinned
chain/contract, amount coverage, future deadline.

The signed digest is `EIP-712( BridgeOperation(bytes4 selector, bytes callData,
uint256 nonce, uint256 deadline) )` over domain `("MultisigProxy", "1",
chainId, verifyingContract)`. The domain separator is pinned by a regression
test against the deployed `MultisigProxy`, and a second test reproduces the
backend's digest -- domain drift breaks the build.

The current rollout signs the **swap flow** (`TS_TRANSFER` consignments) only.
The mint/burn unlock flow is deliberately not wired yet: the enclave preserves
the backend-provided `burnId` / `fundsInIds` (#168), and the in-enclave OpId
rewrite stays dormant until flows are routed by network id (Sec 9, P6).

[Sign EVM](diagrams/03-seq-sign-evm.md)

### 7.2 EVM lock -> RGB (bridge PSBT)

A bridge PSBT request MUST carry the EVM deposit tx hash **and** the RGB
consignment; there is no consignment-less bridge mode. Listener-supplied
`event_valid` / `event_finalized` booleans are ignored (M-06 / #51). The
enclave establishes validity and finality itself, fail-closed
(`evm_event::verify_funds_in_event`):

- a **successful receipt** must exist for `evm_tx_hash`, at depth >=
  `EVM_MIN_CONFIRMATIONS` (pinned config, default 12);
- it must carry a **unique** deposit event from the pinned
  `FUNDS_IN_CONTRACT` (falls back to `BRIDGE_CONTRACT`; #152). `BridgeFundsIn`
  is preferred; a same-tx `FundsIn` + `BridgeFundsIn` pair counts as one
  deposit (#150);
- the event MUST bind the on-chain `operationId` to the request's
  `funds_in_operation_id` -- not the hub's `operation_idx` (#153). A
  `BridgeFundsIn` event additionally binds gross amount and commission
  (`net == gross - commission`); the plain `FundsIn` fallback binds only
  `operationId` and the net amount, leaving the commission split
  listener-supplied.

The PSBT itself is bound to the validated consignment: unsigned txid ==
witness txid, input prevouts == witness prevouts, `SIGHASH_ALL` / taproot
`DEFAULT` only, and the consignment's asset outputs must cover the credited
amount. `TS_TRANSFER` and `TS_INFLATION` (mint-RGB) transitions are accepted
(#146 / #54). A fee sanity check rejects a PSBT whose fee rate exceeds 3x the
enclave's own Esplora estimate, fail-closed on a missing estimate (#147; a
compile-time floor applies only on non-mainnet chains, #149).

**EVM data source:** a build without `evm-rpc` refuses bridge PSBTs outright.
With `evm-rpc`, receipts are host-relayed evidence -- verified fail-closed, but
not trustless. With `helios` and `HELIOS_EXECUTION_RPC` set, receipts are
verified by an in-enclave light client against an operator-pinned checkpoint
(trustless; #60/#136); a Helios sync failure fails closed rather than
downgrading to raw RPC. The chosen source is part of the attested policy
(Sec 4).

A soft in-memory replay guard (24 h TTL) dedups deposit-keyed requests; the
durable double-spend guard is on-chain.

[Sign PSBT](diagrams/04-seq-sign-psbt.md)

### 7.3 Plain-BTC PSBT (`SignBtc`, M-05 / #102)

Vanilla (non-bridge) BTC signing is its own request and can no longer be
reached by omitting bridge fields. It is gated by the attested policy
(`allow_vanilla_psbt`, default **off**), and each request must satisfy the
operator pins: every output script in `BTC_ALLOWED_SCRIPTS`, total input value
<= `BTC_MAX_TOTAL_SATS`. Signing is scoped to the **vanilla** BIP-86 account
only -- it can structurally never co-sign a colored (RGB-allocated) input.

### 7.4 Gas transaction (`SignRawDigest`, C-02 / #68)

The enclave no longer signs an opaque digest. The request MUST carry the
unsigned transaction preimage; the enclave strictly RLP-decodes it (EIP-1559 or
legacy EIP-155), requires `chain_id` == pinned `EVM_CHAIN_ID`, `to` == pinned
`GAS_TX_ALLOWED_TO` (fail-closed when unset), `value == 0`, no contract
creation -- and computes the digest itself. Deliberate follow-ups: no fee/gas
caps yet, calldata to the pinned destination is not inspected (so the pin
should be an EOA), and the `to` pin is not yet attested.

### 7.5 Raw message (`SignRawMessage`)

Wraps the message in the EIP-191 `personal_sign` envelope and signs with the
main bridge key. **`[OPEN]`** I-01 (#124): the handler is not gated by any
feature or policy; decision pending (remove vs. add domain/nonce).

### 7.6 SPV header sync

The host feeds Bitcoin headers; the enclave builds its own PoW-validated chain
(Sec 8). The chain MUST cover every consignment anchor before any tx
validation. [SPV submit headers](diagrams/08-seq-spv-submit-headers.md)

### 7.7 Attested public key

Any external verifier can confirm the signer pubkey belongs to attested
enclave code *and* that the enclave runs the expected security posture (Sec 4).
[Attested pubkey](diagrams/05-seq-attested-pubkey.md)

### 7.8 Cloning (recovery / federation membership)

Three-message handshake, valid only between enclaves with identical PCRs, the
same cluster pubkey, and the shared cloning secret (Sec 10).
[Cloning](diagrams/06-seq-cloning.md)

## 8. RGB / Bitcoin / SPV verification (parent spec Sec 12)

The consignment pipeline (cheap checks first, W-04): non-empty payload,
`keccak256(consignment) == consignment_hash` (integrity only, I-09), asset id
declared; then full `rgbstd` validation with the trusted typesystem pinned per
schema id (unknown schemas rejected, W-09 / #92) against an Esplora resolver
with a 30 s timeout (I-03 / #87); the validated contract id must then equal
the declared asset id and the pinned `RGB_ASSET_ID`; then SPV verification of
every witness tx.

The SPV layer MUST:

1. validate header linkage, PoW, and nBits, and track the best chain by
   cumulative work with bounded reorgs (`MAX_REORG_DEPTH = 100`; an equal-work
   alternative is rejected);
2. retain **all** headers from the checkpoint (no pruning -- deep RGB anchors
   stay verifiable, #130), with a fail-closed cap `MAX_STORED_HEADERS =
   1,000,000` that rejects rather than prunes;
3. bound submission: max 10,000 headers per call, max 100,000 headers per
   60 s window;
4. for **every** witness tx referenced by the consignment: require exact
   set-equality with the supplied Merkle proofs, verify inclusion against the
   stored header (path depth <= 32), and require depth >=
   `SPV_MIN_CONFIRMATIONS = 6`;
5. reject a stale or future-dated tip (both bounds 2 h) to defeat frozen-feed
   attacks;
6. reject a consignment whose `chain_net` differs from the enclave's network
   (boot-selected via `BITCOIN_NETWORK`, baked into the image and therefore
   PCR0-attested; cross-network replay defense).

All thresholds are compile-time constants -- a host-tunable threshold would let
an operator weaken the gate while attestation still passed.

**Checkpoints:** mainnet block 951,552 (retarget-aligned, W-14) and UTEXO
signet block 334,000 are real pinned checkpoints; regtest uses genesis.
Testnet3 remains a placeholder -- a release build refuses to boot on any
placeholder checkpoint. **Signet caveat:** the enclave does not validate PoW or
nBits on signet, and the BIP-325 challenge signature is not verified (the wire
format carries no coinbase witness), so signet header integrity rests on chain
linkage, the reorg/work rules, the submission caps, and the 2 h freshness
gate.

## 9. Unlock authorization predicates (parent spec Sec 10) -- NORMATIVE

Before signing `fundsOut`, the enclave MUST verify **all** of the following and
MUST refuse to sign (fail closed) if any fails.

| #   | Predicate                                                   | Status                                                                                                                                                            |
|-----|-------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| P1  | submitted RGB consignment is valid (`rgbstd` full validation) | OK                                                                                                                                                               |
| P2  | consignment proves the expected transition                  | OK for the live swap flow: last transition MUST be `TS_TRANSFER`. `TS_BURN` is classified and amount-extracted, but mint/burn unlock is not wired yet (#168)       |
| P3  | unlock amount is covered by the consignment-derived amount  | OK -- the amount comes from the consignment (host `rgb_amount` is ignored); comparison is coverage (`>=`), strict `==` pending per-output binding (**`[OPEN]`** I-06 / #124, #58) |
| P4  | calldata is well-formed                                     | OK -- single pinned selector, 64 KiB cap, canonical ABI decode + re-encode byte-equality (closes W-01)                                                            |
| P5  | payload binds destination chain / contract / **recipient**  | chain + contract pinned; **`[OPEN]`** recipient not bound (C-04 / #66) -- blocked on an EVM-destination commitment in the RGB burn schema (cross-repo)             |
| P6  | payload binds the RGB `OpId` (cross-domain identifier)      | **`[OPEN -- dormant]`** M-02: the in-enclave `burnId` / `fundsInIds` derivation exists (#93/#97) but is disabled for the swap rollout (#168); backend ids are signed as received |
| P7  | referenced Bitcoin txs are in accepted chain history        | OK                                                                                                                                                               |
| P8  | Bitcoin inclusion proofs valid against the in-enclave chain | OK; plus, when populated, the calldata `(blockHeight, commitmentHash)` proof must match the enclave's own header (#57/#122 -- inert until the listener sends it)   |
| P9  | corresponding EVM lock record exists for the same operation | on-chain for this direction; for EVM->RGB the enclave verifies `FundsIn` itself (Sec 7.2)                                                                         |
| P10 | EVM execution payload matches the validated unlock intent   | selector, calldata layout, amount, chain, contract: OK; recipient and operation id: see P5 / P6                                                                   |
| P11 | on any failure, refuse to sign                              | OK -- fail-closed                                                                                                                                                |

> The two remaining `[OPEN]`s share one root cause: the recipient and the
> operation id inside `fundsOut` calldata are not yet derived from the
> validated consignment. C-04 needs a schema change (cross-repo); P6 activation
> needs network-id-routed flows. Until then, those two fields rest on the
> backend plus the on-chain quorum and replay controls.

[Signing gate](diagrams/10-signing-gate.md)

## 10. Attestation & federation (parent spec Sec 16)

- **Public verifiability:** each signer pubkey is generated in-enclave and
  bound to a Nitro attestation. The verifier enforces: cert chain to the
  embedded AWS root with `BasicConstraints`, `keyCertSign`, path-length, and
  leaf `digitalSignature` checks (W-10 / #126); COSE `alg == ES384` with the
  raw 96-byte signature form only (I-05); PCR0/1/2 equality; nonce equality;
  and the `user_data` commitment over pubkey bundle + security policy (Sec 4).
- **PCR policy:** verifiers assert PCR0/1/2 (stricter than the parent spec's
  minimum of PCR0/1).
- **Cloning** is valid only between enclaves that target the same cluster
  pubkey, run the same code (PCR equality), and share the cloning secret, with
  mutual attestation. The DH exchange rejects small-order points; the seed
  ciphertext is bound to both handshake keys via HKDF; replay-guard nonces are
  recorded only **after** authentication succeeds (W-13 / #129), and the guard
  is TTL-bounded (1 h) with oldest-first eviction so it cannot be wedged
  (W-12 / #80). **`[OPEN]`** M-08 (#73): authorization still rests on a static
  cluster-wide secret, not bound into PCRs or the attested commitment.
  **`[OPEN]`** I-13 (#124): the master seed stays resident for the enclave's
  lifetime (the donor re-seals it per clone); fix requires a cloning redesign
  or threshold keys.
- **Federation / quorum:** unlock SHOULD require M-of-N enclave signatures;
  quorum is enforced on-chain in `MultisigProxy`. The EIP-712 digest is a pure
  function of `callData` / `nonce` / `deadline`, so quorum members sign
  identical payloads.
- **Replay:** `fundsOut` replay protection is the on-chain proxy nonce, which
  is committed into the signed digest; the enclave keeps no fundsOut nonce
  state. EVM->RGB requests get the soft in-enclave dedup guard (Sec 7.2);
  cloning nonces get their own guard.

## 11. Security invariants -- NORMATIVE

| ID        | Invariant                                                                                                                                                |
|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| **SI-1**  | A compromised parent/listener/backend alone MUST NOT yield a `fundsOut` signature. (Holds except the unbound recipient / operation id -- P5/P6 `[OPEN]`.) |
| **SI-2**  | A forged or malformed RGB consignment MUST NOT trigger signing. OK                                                                                       |
| **SI-3**  | A Bitcoin inclusion proof inconsistent with the in-enclave PoW chain MUST NOT trigger signing. OK                                                        |
| **SI-4**  | An EVM unlock payload not bound to the RGB `OpId` MUST NOT be accepted. **`[OPEN]` P6 (dormant binding).**                                                |
| **SI-5**  | The seed MUST NOT leave the enclave in plaintext; only HKDF-sealed ciphertext crosses the wire, and only during a mutually-attested clone. OK             |
| **SI-6**  | Cloning MUST require identical PCRs, same cluster pubkey, and the cloning secret -- cloning MUST NOT be an upgrade path. OK                               |
| **SI-7**  | Confirmation depth, freshness, and size thresholds MUST NOT be host-configurable. OK (compile-time constants)                                            |
| **SI-8**  | SPV depth MUST be verified for **every** anchoring tx in the consignment history, with no header pruning below it. OK (#130)                             |
| **SI-9**  | Signing MUST be possible only in `Active`; other phases MUST reject signing and key-export RPCs (except the donor's sealed export). OK                    |
| **SI-10** | On any validation failure the path MUST fail closed -- no partial signature, no fallback, no silent downgrade (including Helios -> raw RPC). OK           |
| **SI-11** | A feature/build mismatch MUST cause refusal, never sign-without-verification (no `evm-rpc` => no bridge PSBTs; `rgb-validation` without `spv` does not compile). OK |
| **SI-12** | Cross-network consignments MUST be rejected. OK                                                                                                          |
| **SI-13** | Bridge PSBT signing MUST independently verify the EVM deposit (receipt success, pinned contract, unique event, on-chain `operationId` + amount + commission binding, depth >= `EVM_MIN_CONFIRMATIONS`); listener flags MUST NOT authorize. OK (#51/#60, #150/#152/#153) |
| **SI-14** | A release bridge build MUST refuse to boot unless it resolves to a valid `Production` security policy. OK (C-01)                                         |
| **SI-15** | The full security posture MUST be verifiable as one attested value; a downgraded posture MUST fail pubkey verification. OK (C-01)                        |
| **SI-16** | Plain-BTC signing MUST be off unless enabled in the attested policy, MUST respect the output allowlist and value cap, and MUST NOT touch colored keys. OK (#102) |
| **SI-17** | A signing that produced zero input signatures MUST NOT be reported as success. OK (W-07 / #85)                                                            |

## 12. Failure conditions

On any of the following the enclave MUST return an error and MUST NOT sign:
invalid consignment; unsupported or unclassified transition; amount not
covered; malformed or non-canonical calldata; unpinned or mismatched
chain/contract/asset; invalid or missing SPV proof; stale, future-dated, or
incomplete header chain; cross-network consignment; missing/failed/shallow
`FundsIn` verification; `operationId` mismatch; excessive fee rate; PSBT not
anchored to the consignment; disallowed output script or value cap exceeded
(plain BTC); non-allowlisted gas tx; wrong phase; expired deadline; replayed
nonce or duplicate operation; oversized frame, field, or header batch.

## 13. Implementation status

**Landed on the `dev-ng` line** (Oxorio final IDs): C-01 unified attested
policy (#148/#169) · C-02 gas-tx allowlist (#81) · C-03 asset pin (#75) · M-05
plain-BTC split (#102) · M-06 in-enclave `FundsIn` + Helios (#60/#136,
#150/#152/#153) · M-07 connection limits (#117) · M-09 config AND-logic (#98)
· W-01 canonical ABI · W-04 hash-first ordering · W-07 zero-signature guard ·
W-08 bounded full retention (#130) · W-09 typesystem pin · W-10 cert-chain
hardening (#126) · W-12/W-13 replay-guard fixes (#80/#129) · W-14 + real
mainnet/signet checkpoints · I-02 fallible digest · I-03 Esplora timeout ·
I-04 size caps + I-15 validate()-status handling (#118) · I-05 COSE pinning · I-07 xpriv zeroization (#151)
· EIP-712 domain pinned to the deployed contract · fee sanity (#147, #149) ·
mint-PSBT binding (#146) · swap op-id preservation (#168) · audit regression +
`audit:test` suites in CI (#144/#167).

**Open -- pre-mainnet:**

1. **C-04 recipient binding** (P5): needs the EVM-destination commitment in
   the RGB burn-transition schema first (cross-repo), then the enclave reads
   and binds it.
2. **M-02 operation-id activation** (P6): enable the in-enclave
   `burnId` / `fundsInIds` derivation once flows are routed by network id;
   durable cluster-wide dedup stays on-chain.
3. **M-03 signer-set rotation** (cross-repo): no enclave membership gate for
   co-signers; needs contracts (`btcDescriptorHash`) + listener support.
4. **M-08 / I-13 cloning hardening**: bind the cloning secret / operator
   identity into the attested measurement; redesign so the seed need not stay
   resident.
5. **W-06** (#52): derive `psbt_output_amount` from the PSBT instead of the
   listener; identify the recipient leg (#58).
6. **Helios by default**: raw RPC remains host-relayed evidence; decide
   Helios-on for production images and require `--expect-evm-source helios`.
7. **Listener migration** (deploy ordering): a production enclave rejects the
   old gas-tx digest and consignment-less request shapes -- migrate
   proto/listener/backend before deploying, otherwise availability (never
   safety) suffers.
8. Smaller: attest `GAS_TX_ALLOWED_TO` / `FUNDS_IN_CONTRACT` / BTC pin values;
   gas-tx fee caps; I-01 `SignRawMessage` decision; I-14 u64 amount ceiling;
   I-16 reproducible-build determinism; testnet3 checkpoint.

---

## Appendix A -- Diagram index

Mermaid in Markdown -- rendered inline on GitHub.

| Diagram                   | File                                    |
|---------------------------|-----------------------------------------|
| Component structure       | `diagrams/01-components.md`             |
| Deployment / trust zones  | `diagrams/02-deployment.md`             |
| Sign fundsOut (unlock)    | `diagrams/03-seq-sign-evm.md`           |
| Sign bridge PSBT          | `diagrams/04-seq-sign-psbt.md`          |
| Attested pubkey           | `diagrams/05-seq-attested-pubkey.md`    |
| Cloning handshake         | `diagrams/06-seq-cloning.md`            |
| Initialize keys           | `diagrams/07-seq-initialize-keys.md`    |
| SPV submit headers        | `diagrams/08-seq-spv-submit-headers.md` |
| Phase state machine       | `diagrams/09-state-phase.md`            |
| Signing gate / predicates | `diagrams/10-signing-gate.md`           |

All diagrams refreshed 2026-07-28 to match this spec; where a diagram and this
spec disagree, this spec is authoritative.
