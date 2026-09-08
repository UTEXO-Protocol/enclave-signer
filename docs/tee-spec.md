# Nitro Enclave Signer -- Technical Specification

**Component:** `enclave-signer` (TEE validator / signer + parent adapter)
**Reviewed:** 2026-09-08 against this repository.

This document describes implemented behavior and its limits. It is not a
security audit or a statement about the currently deployed listener/contracts.
MUST/MUST NOT describe enforced rules within the stated build and trust
assumptions. Known gaps are collected in Sec 13.

---

## 1. Purpose

The enclave signer is the authorization component of the bridge. It runs inside
an **AWS Nitro Enclave (TEE)** and is the only component that can produce the
signatures that release EVM-side liquidity (`fundsOut`) and that sign Bitcoin
PSBTs for the RGB-side flows.

Its job is to move trust away from the host operator: requests from a compromised parent, listener, or backend must pass
the checks implemented for the selected route. The enclave validates RGB consignments, Bitcoin
SPV inclusion, EVM deposit events, and cross-domain bindings itself; it does
not treat request flags as evidence. Raw EVM RPC and CCD retain the trust
exceptions described below.

## 2. Trust boundary and threat model

```
Internet -- orchestrator -- EC2 parent (UNTRUSTED) -- vsock -- Nitro Enclave (TRUSTED)
                                  |                                    |
                              listener, backend,                 key material,
                              Esplora / EVM-RPC                  validation, signing
                              vsock proxies                       (this spec)
```

| Actor                            | Trusted for                                      | NOT trusted for                                                                        |
|----------------------------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| Nitro hardware + NSM             | measurement (PCRs), attestation signing, entropy | --                                                                                     |
| Enclave code (this repo)         | validation, key custody, signing                 | -- (the thing being attested)                                                          |
| Parent host / listener / backend | liveness, transport, data *delivery*             | request claims are checked, but raw EVM RPC and CCD have explicit trust exceptions |
| Esplora / Bitcoin data providers | availability                                     | correctness -- checked against the in-enclave PoW header chain + SPV                   |
| Raw EVM RPC and its host relay | receipt/head correctness and availability | no cryptographic consensus verification on this path (Sec 7.2) |
| Operator                         | deployment, env pins, the cloning secret         | seed access (never leaves the TEE in plaintext)                                        |

**Residual trust anchors:** AWS (Nitro isolation + attestation root CA), the
correctness of this enclave code and its validation libraries, the Bitcoin
checkpoint, and the selected EVM provider. Raw RPC and CCD rely on external
validation/data; Helios adds an operator-pinned beacon checkpoint.

**Wall clock:** the deadline check, the SPV tip-staleness check, and the
header-submission rate limit read `SystemTime::now()`. Inside Nitro this clock
is hypervisor-provided (kvm-clock); there is no NSM-attested time source. The
accepted assumption: the AWS hypervisor is trusted for *coarse* time --
consistent with already trusting it for isolation and attestation. The parent
cannot skew the enclave clock through any interface this code exposes.

**No batch signing:** the enclave builds exactly two digest shapes -- the
typed `TeeFundsOut` and `TeeLzFundsOut` EIP-712 structs over decoded calldata
fields (Sec 7.1). There is no batch or opaque-calldata digest builder, so a
signature produced here can never authorize a batch execution. This statement applies to the typed bridge authorization path; gas transaction
and Concordium signing have separate rules.

**Concordium exception:** the CCD source is the one input the enclave does not
re-validate (Sec 7.9). The listener's finality check is trusted there by
design; the enclave binds only the amount.

## 3. Architecture

Four crates plus the infrastructure they touch:

- **`enclave`** -- runs inside the TEE. Connection loop (`main.rs`, vsock in
  prod / TCP in dev; hardening in `conn.rs`) -> `server.rs` dispatch -> `policy.rs` (security policy),
  `keys.rs` / `state.rs` (key custody, phases), `cloning.rs`, `attestation.rs`,
  and the network validators under `networks/`:
  - `networks/rgb/` -- consignment validation, PSBT binding (`psbt_validation.rs`),
    invoice recipient bind (`invoice.rs`), taproot signing, the SPV header
    chain (`spv/`), plain-BTC ownership and sats gates, and the per-build flow
    rules in `flow/{swap,mint_burn}.rs`;
  - `networks/evm/` -- `fundsOut` / `lzFundsOut` calldata validation and
    crosschecks, EIP-712 signing, `FundsIn` event verification
    (`evm_event.rs`), gas-tx validation;
  - `networks/ccd.rs` -- Concordium source (amount bind only, Sec 7.9).
- **`enclave-proto`** -- the vendored `enclave` protobuf package, committed as
  pre-generated Rust so no codegen toolchain enters PCR0.
- **`attestation-verify`** -- shared library that verifies COSE_Sign1 Nitro
  attestation documents against the embedded AWS root CA, and defines the
  canonical **security-policy commitment encoding** (Sec 4) used identically by
  the enclave and every verifier.
- **`parent`** -- untrusted EC2-side adapter: tonic gRPC server
  (`parent.ParentService`) bridging the listener to the enclave's wire
  protocol, the operator CLI, and the `attest-verify` CLI.

**Cargo features.** `rgb` (implies `spv`, which implies `rgb-validation`),
`ccd`, exactly one of `rgb-swap` / `rgb-mint-burn`, `evm-rpc`, `bfa-mint`,
`vsock`. Production images are built with `--no-default-features` and an
explicit set (README, Building). Dev-only features (`dev-mode`,
`mock-attestation`, `allow-seed-import`) are `compile_error!` in release.

**Wire protocol** enclave<->parent: 4-byte little-endian length prefix + prost
protobuf, 4 MiB frame cap, no version field (`framing.rs`). The consignment
resolver and the EVM RPC are reached through in-enclave loopback forwarders
that bridge over vsock to host-side `vsock-proxy` instances (vsock ports 8001
and 8002); the enclave has no direct network stack. With an
`ELECTRUM_URL` of the form `ssl://host:port` the forwarder listens on that
port and pins `host` to loopback in `/etc/hosts`, so TLS terminates inside the
enclave against the real certificate. Esplora REST uses loopback 3443, EVM RPC
3444.

**Connection hardening:** fixed pool of 4 worker threads, bounded
queue of 16 connections, 10 s per-syscall idle timeout, 30 s total per-request
deadline. One request per connection. All limits are compile-time constants.

Diagrams: [components](diagrams/01-components.md) |
[deployment](diagrams/02-deployment.md).

## 4. Security policy

The enclave resolves a security policy once at boot and commits it alongside
the public-key bundle. This policy covers the fields below, not all configuration.

```
SecurityPolicy = Production {
    chain_id, bridge_contract, rgb_asset_id,   -- operator pins
    allow_vanilla_psbt,                        -- plain-BTC signing on/off
    attestation: Real,                         -- always, in production
    evm_source:  Disabled | RawRpc | HeliosVerified,
    evm_checkpoint, gas_tx_rule,
    btc_source:  SpvVerified,                  -- always, in production
} | Development { reason }
```

- **Resolution** (`policy.rs`): any dev feature (`dev-mode`,
  `mock-attestation`, `allow-seed-import`), a debug/test build, a non-bridge
  build, or a missing pin resolves to `Development`. Only a release
  `rgb-validation` build with `EVM_CHAIN_ID`, `EVM_PROXY_CONTRACT_ADDRESS`, and
  `RGB_ASSET_ID` all set resolves to `Production`. `evm_source` is
  `Disabled` without `evm-rpc`, otherwise `RawRpc` unless a `helios`
  build selects Helios through `HELIOS_EXECUTION_RPC`. Helios requires a
  valid checkpoint; the verifier pins both source and checkpoint.
- **Boot gate:** a release `rgb-validation` build that does not resolve to a
  valid `Production` policy MUST refuse to boot (panic). Independently, each
  dev feature is a `compile_error!` in any shipped release binary (non-test
  build with debug assertions off); `rgb-validation` without `spv` is a
  `compile_error!` in every profile, as is `rgb-validation` with both RGB flows
  (`rgb-swap` + `rgb-mint-burn`) or with neither.
- **Attestation:** `user_data = sha256(canonical_pubkey_bundle ||
  policy_commitment)`. The commitment encoding is versioned and shared
  (`attestation-verify/src/policy.rs`), so the enclave and every verifier
  produce identical bytes. See [`pubkey-attestation.md`](pubkey-attestation.md).
- **Verification:** `attest-verify` reconstructs the *expected* policy
  (`--expect-vanilla-psbt`, `--expect-evm-source raw|helios|disabled`,
  `--expect-helios-checkpoint` and the gas-rule flags) and
  fails if the commitment differs -- a downgraded posture (vanilla signing on,
  a different EVM source, a dev build) fails verification instead of being
  silently trusted.

Inside the commitment: the whole gas-tx rule -- `GAS_TX_ALLOWED_TO`,
`GAS_TX_MAX_GAS_LIMIT`, `GAS_TX_MAX_FEE_PER_GAS`, `GAS_TX_MAX_VALUE_WEI`, and
`GAS_TX_ALLOWED_SELECTORS` -- so a verifier confirms the `SignRawDigest` policy
instead of trusting the operator's configuration. An unset pin commits as its zero value, which is the posture it enforces, so
"unpinned" is attested too.

Not inside the policy commitment: `FUNDS_IN_CONTRACT`,
`EVM_MIN_CONFIRMATIONS`, `BITCOIN_NETWORK`, resolver endpoints,
`HELIOS_STRICT_CHECKPOINT_AGE`, request-size caps, and the concrete
`BTC_MAX_TOTAL_SATS`, `BTC_MAX_UNOWNED_SATS` and `RGB_MAX_UNOWNED_SATS` values
(only the `BTC_MAX_TOTAL_SATS` on/off boolean is attested).
Image-baked configuration is still covered by image measurement; runtime
configuration is not automatically added to the policy commitment. The plain-BTC *destination* rule needs no
commitment: it is not configuration but a property the enclave derives from its
own keys.

## 5. Key management

- Keys are **generated inside the enclave** from OS entropy (BIP-39 mnemonic
  -> BIP-32 seed). The 64-byte seed lives in a `SecretBox` and MUST NOT leave
  the TEE in plaintext . Intermediate buffers are
  zeroized; the BIP-86 account xprivs are wiped on drop.
- Derivation paths:
  - EVM bridge key (authorization): `m/44'/60'/0'/0/0`;
    `evm_address = keccak256(uncompressed_pub[1..])[12..]`.
  - EVM gas-tx key (outer tx signing, `SignRawDigest`): `m/44'/60'/0'/0/1`.
  - BTC SegWit v0 (legacy P2WSH): `m/84'/0'/0'/0/0`. Used only by the
    unscoped library signing path; both bridge paths are account-scoped and skip it.
  - BIP-86 taproot: vanilla `m/86'/<coin>'/0'` (0 mainnet, 1 otherwise), colored
    (RGB) `m/86'/<rgb_coin>'/0'` (827166 mainnet, 827167 otherwise -- the split
    `rgb-lib` uses, so the host's colored addresses resolve).
  - Concordium governance key: Ed25519 via SLIP-0010, all-hardened
    `m/44'/919'/0'/0'/0'`. Always derived, so the attested key bundle has the
    same shape in every build.
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
enclave. Mnemonic/seed import is rejected unless the
dev-only `allow-seed-import` feature is compiled in (release: `compile_error!`).

[Phase state machine](diagrams/09-state-phase.md)

## 7. Protocol flows

All bridge signing goes through one `Sign` request carrying a source network
(EVM, RGB, or CCD) and a destination network (EVM or RGB). Accepted routes are
RGB -> EVM, EVM -> RGB, and CCD -> EVM; any other pair is refused. Plain-BTC
signing is a separate `SignBtc` request (Sec 7.3), Concordium hash signing a
separate `SignCcd` (Sec 7.9). The old standalone SignEvm/SignPsbt request
shapes no longer exist.

### 7.1 RGB burn -> EVM unlock (`fundsOut`)

For an RGB source, `fundsOut` signing runs the checks in Sec 9:
validated consignment, SPV-confirmed anchors, canonical calldata, pinned
chain/contract, amount coverage, future deadline.

The calldata MUST lead with one of two selectors: the pools `fundsOut`
(`0xdc771390`) or `lzFundsOut` (LayerZero release). The enclave decodes it
canonically (re-encoding must byte-equal the input) and signs a typed digest
over the **decoded** fields, never over opaque bytes: `EIP-712( TeeFundsOut(
recipient, amount, ...) )` for the pools route, `EIP-712( TeeLzFundsOut(...) )`
for the LayerZero route, over domain `("MultisigProxy", "1", chainId,
verifyingContract)`. On the LayerZero route the request's `lz_release`
(`dst_eid`, `min_amount_ld`, `recipient`) MUST match the decoded calldata. The
calldata `destinationChainId` MUST equal the pinned `EVM_CHAIN_ID` on the pools
route and MUST differ from it (and be non-zero) on the LayerZero route. The
domain separator is pinned by a regression test against the deployed
`MultisigProxy`, and a second test reproduces the backend's digest -- domain
drift breaks the build. The response echoes the calldata unchanged; nothing in
the enclave rewrites it.

**Settlement bind (`bfa-mint`).** `settlementData` is
`abi.encode(bytes32[] operationIds, uint256[] netAmounts)`, the deposits the
release settles. The enclave verifies every `FundsIn` lock behind the burn's
mint ancestry itself (receipt, pinned emitter, RGB OpId, depth) and reads the
`BridgeFundsIn` record from the same receipt. It then requires the cited
pairs to equal those records exactly: set equality, no duplicates, canonical
encoding, and at least one verified lock. This validates settlement references
but does not establish a unique release identifier (Sec 9, P6).

Which consignment shape a build signs is chosen at compile time by its RGB
flow feature (`rgb-swap` or `rgb-mint-burn`, exactly one). A **swap** enclave
signs `TS_TRANSFER` unlocks; a **mint/burn** enclave signs `TS_BURN` unlocks and
nothing else, binding the release to the payout target the burn transition
commits to (`MS_BURN_RECIPIENT`). The BFA line is a mint/burn build
(`bfa-mint`), where a deposit is a bridge mint against a verified `FundsIn`
lock. The two flows are separate instances with separate PCR0s -- neither
binary contains the other's rules. Independently of the flow, the enclave
signs the backend-provided `burnId` / `settlementData` as received; no
in-enclave derivation from the RGB OpId exists yet (Sec 9, P6).

[Sign EVM](diagrams/03-seq-sign-evm.md)

### 7.2 EVM lock -> RGB (bridge PSBT)

A bridge PSBT request MUST carry the EVM deposit tx hash **and** the RGB
consignment; there is no consignment-less bridge mode. Listener-supplied
`event_valid` / `event_finalized` booleans are ignored. The
enclave establishes validity and finality itself, fail-closed
(`evm_event::verify_funds_in_event`):

- a **successful receipt** must exist for `evm_tx_hash`, at depth >=
  `EVM_MIN_CONFIRMATIONS` (pinned config, default 12);
- it must carry exactly **one** `BridgeFundsIn` event from the pinned
  `FUNDS_IN_CONTRACT` (falls back to `EVM_PROXY_CONTRACT_ADDRESS`). Zero or two
  such events refuse. There is no fallback to the plain `FundsIn` event: it
  carries an RGB OpId, a different id space;
- the event MUST bind the on-chain `operationId` (the full 32-byte word,
  indexed topic 1) to the request's 32-byte `funds_in_operation_id` -- not the
  hub's `operation_idx` -- plus the gross `amount` and `tokenCommission`;
  `netAmount` MUST NOT exceed `gross - commission` (a lower value is accepted
  with a warning for fee-on-transfer tokens);
- the event's `destinationAddress` string is the depositor's RGB invoice. The
  enclave parses it (`rgb-invoicing`), accepts only a blinded-seal
  beneficiary, and requires the consignment's single confidential recipient
  leg to equal that seal. Zero or two confidential legs refuse.

The PSBT itself is bound to the validated consignment: unsigned txid ==
witness txid, input prevouts == witness prevouts, `SIGHASH_ALL` / taproot
`DEFAULT` only, every transition the PSBT commits to must be a shape the
build's flow accepts, and the group's asset outputs are checked against the
credited amount. Which transition is accepted is the build's RGB flow:
`TS_TRANSFER` under `rgb-swap` (coverage `>=`, since the surplus is bridge
change), `TS_INFLATION` under `rgb-mint-burn` -- joined by `TS_BRIDGE` in a
`bfa-mint` build -- with a strict `==`, since any surplus is an over-mint.
Independently, every `OS_ASSET` output is split into legs: a confidential
(blinded) leg is the recipient, a revealed leg MUST be proven self-owned
(script equality with an input the enclave co-signs, at most 4 off-PSBT change
outpoints), and the recipient legs MUST sum exactly to `amount - commission`.
The destination amount the route check uses is this enclave-derived recipient
total, not the wire `psbt_output_amount`. A fee sanity check rejects a PSBT
whose fee rate exceeds 3x the enclave's own estimate (Electrum or Esplora),
fail-closed on a missing estimate (a compile-time floor applies only on
non-mainnet chains).

**EVM data source:** a build without `evm-rpc` refuses bridge PSBTs outright.
With the default raw `evm-rpc` provider, receipts are host-relayed evidence -- verified fail-closed, but
not trustless: a host that controls the RPC can withhold a receipt (liveness)
or present a fabricated one that passes every structural check. The chosen
source is part of the attested policy (Sec 4). The optional `helios` feature supplies a checkpoint-verified provider.
It is selected only when `HELIOS_EXECUTION_RPC` is set; otherwise even a
Helios-capable build uses raw RPC. Helios requires `HELIOS_CHECKPOINT` and a
network matching `EVM_CHAIN_ID`. A selected provider that fails initialization
or bounded sync remains unavailable; there is no fallback to raw RPC. The
supplied Dockerfiles do not enable `helios`.

A soft in-memory replay guard (24 h TTL) dedups requests keyed by
`(chain_id, bridge_contract, evm_tx_hash, funds_in_operation_id, rgb_asset_id)`
and is committed only after signing succeeds; it is not durable or shared across clones. Bitcoin prevents spending the
same UTXO twice, but this cache alone does not prevent issuing another PSBT
for the same deposit after restart/expiry or on another enclave.

**Bitcoin value.** Every bind above is denominated in RGB asset units, so a
witness transaction can satisfy the RGB ledger exactly and still route the
bridge's Bitcoin backing to an attacker output that carries no RGB assignment.
The fee-rate cap does not catch it -- a diverted sat is an output, not a fee, so
diversion *lowers* the implied rate. Outputs that do not pay back into the
custody their inputs were in are therefore bounded by `RGB_MAX_UNOWNED_SATS`,
fail-closed while unset. The budget is a bound rather than an identity check
because the recipient's seal is blinded: the enclave cannot tell which output is
the payout, only how much may leave. Signing is scoped to the **colored** BIP-86
account.

[Sign PSBT](diagrams/04-seq-sign-psbt.md)

### 7.3 Plain-BTC PSBT (`SignBtc`)

Vanilla (non-bridge) BTC signing is its own request and can no longer be
reached by omitting bridge fields. It is gated by the attested policy
(`allow_vanilla_psbt`, default **off**), and each request must satisfy the
authorization rules: every output must pay back into the custody its inputs were
already in, except a budget of `BTC_MAX_UNOWNED_SATS` for those that do not, and
total input value <= `BTC_MAX_TOTAL_SATS`. Signing is scoped to
the **vanilla** BIP-86 account only -- it can structurally never co-sign a
colored (RGB-allocated) input.

The destination rule is self-proving, not pinned. An output is accepted when its
`script_pubkey` equals that of an input the enclave co-signs -- control-block and
derivation anchored, and committed to by the segwit sighash. That proves custody
is unchanged, not that only the enclave can spend: the bridge is a multisig and
the other signers can move funds regardless. It holds for change because the
wallet reuses addresses.

Outputs outside the proved input scripts may consume the configured unowned
sats budget. A matching key in one taproot leaf alone is not treated as proof
that the enclave controls an output.

### 7.4 Gas transaction (`SignRawDigest`)

The enclave no longer signs an opaque digest. The request MUST carry the
unsigned transaction preimage; the enclave strictly RLP-decodes it (EIP-1559 or
legacy EIP-155), requires `chain_id` == pinned `EVM_CHAIN_ID`, `to` == pinned
`GAS_TX_ALLOWED_TO` (fail-closed when unset), `value == 0`, no contract
creation -- and computes the digest itself.

Two further bounds, each fail-closed when unset:

- **Fee/gas ceilings.** `gasLimit` <= `GAS_TX_MAX_GAS_LIMIT`, and the per-gas
  fee fields (`maxFeePerGas` / `maxPriorityFeePerGas`, or legacy `gasPrice`) <=
  `GAS_TX_MAX_FEE_PER_GAS`. Together they bound the most ETH a *single* signed
  gas tx can burn as fees.
- **Calldata selector allowlist.** The calldata MUST lead with a 4-byte selector
  in `GAS_TX_ALLOWED_SELECTORS`; empty calldata is refused, because a bare call
  still invokes the destination's `fallback`/`receive`. This replaces the old
  unverifiable "the pin is an EOA, so calldata is inert" assumption with an
  in-enclave, attested control.

One carve-out to `value == 0`: the payable `lzFundsOutCall`, which forwards
native value as the LayerZero messaging fee. Admitted only when all three hold
-- the on-chain `lzFundsOutCall` selector, `to` == pinned `EVM_PROXY_CONTRACT_ADDRESS`
(the proxy itself, not merely `GAS_TX_ALLOWED_TO`, which may be an EOA), and
`value` <= pinned `GAS_TX_MAX_VALUE_WEI`. That ceiling is fail-closed when
unset, so a deployment not using the path keeps the strict posture. The
carve-out widens the *value* rule only: `lzFundsOutCall` must still appear in
`GAS_TX_ALLOWED_SELECTORS` like any other call.

The whole rule -- destination, both fee/gas ceilings, the value ceiling, and the
selector allowlist -- is folded into the attested `SecurityPolicy` (Sec 4), so a
verifier confirms the gas policy rather than trusting configuration.

Deliberate follow-ups: the ceilings are per-transaction, not aggregate, so a
compromised listener can still burn the gas EOA's balance over a long sequence
of within-cap txs (bounded griefing -- fees go to the base fee / block builder,
never to an attacker; rate limiting belongs out-of-enclave). And the fee is not
a field of the `TeeLzFundsOut` payload, so nothing binds a fee to its release --
the ceiling bounds the blast radius until a contract change adds that binding.

### 7.5 Raw message (`SignRawMessage`) -- REMOVED

Signed the message under the EIP-191 `personal_sign` envelope with the main
bridge key, gated by no feature and no policy. Removed. The proto
variant is kept for wire compatibility and the enclave refuses the request.

### 7.6 SPV header sync

The host feeds Bitcoin headers (`SubmitHeaders`, `spv` builds only); the
enclave builds its own PoW-validated chain (Sec 8). The chain MUST cover every
consignment anchor before any tx validation.
[SPV submit headers](diagrams/08-seq-spv-submit-headers.md)

### 7.7 Attested public key

Any external verifier can confirm the signer pubkey belongs to attested
enclave code *and* that the enclave runs the expected security posture (Sec 4).
[Attested pubkey](diagrams/05-seq-attested-pubkey.md)

### 7.8 Cloning (recovery / federation membership)

Three-message handshake, valid only between enclaves with identical PCRs, the
same cluster pubkey, and the shared cloning secret (Sec 10). The donor learns
the secret at runtime (`InitializeKey.cloning_secret`, or the legacy
`UTEXO_CLONING_SECRET` env), never from the image. The CLI `clone` command
drives it: `InitiateCloning` on the new enclave, the parent `Clone` RPC on the
donor, `SetClone` on the new enclave. [Cloning](diagrams/06-seq-cloning.md)

### 7.9 Concordium (`CcdSource`, `SignCcd`)

`ccd` builds add two paths that follow the Concordium hash-signing model, where
the node derives what is signed:

- **CCD -> EVM release.** A `Sign` request with a `CcdSource` MUST carry a
  32-byte source tx hash. The enclave does **not** re-validate the Concordium
  transaction; the listener's finality and structure check is trusted. The
  enclave binds `SignRequest.amount` into the route proof, so the EVM
  destination amount check (Sec 7.1) still applies, and signs the same typed
  `fundsOut` digest.
- **`SignCcd`.** Ed25519 signature over a caller-supplied 32-byte hash with the
  governance key (Sec 5), returned with the 32-byte public key. No structural
  validation inside the enclave.

Both are trust exceptions to Sec 2, summarized in Sec 13.

## 8. RGB / Bitcoin / SPV verification

The consignment pipeline (cheap checks first): non-empty payload within
`MAX_CONSIGNMENT_BYTES`, proof count and bytes within `MAX_MERKLE_PROOFS` /
`MAX_TOTAL_PROOF_BYTES`, `keccak256(consignment) == consignment_hash`
(integrity only), asset id declared; then full `rgb-ops` validation with the
trusted typesystem pinned per schema id (unknown schemas rejected) against the
resolver (Electrum, 15 s timeout, or Esplora REST, 30 s); the validated
contract id must then equal the declared asset id and the pinned `RGB_ASSET_ID`
(on the `fundsOut` path this last leg applies once the bridge is configured;
on the PSBT path it is unconditional). The RGB-source path then checks SPV
proofs for every witness transaction. The PSBT destination path instead binds
the transaction being signed to the consignment; that transaction need not
already be mined. A `bfa-mint` build validates the bridged schema with an extension that
checks every `Bridge` transition against the enclave's own verified `FundsIn`
lock, and refuses a mint with no verified lock behind it.

The SPV layer MUST:

1. validate header linkage, PoW and nBits on mainnet/testnet3 (network
   exceptions below), and track the best submitted chain by
   cumulative work with bounded reorgs (`MAX_REORG_DEPTH = 100`; an equal-work
   alternative is rejected);
2. retain **all** headers from the checkpoint (no pruning -- deep RGB anchors
   stay verifiable), with a fail-closed cap `MAX_STORED_HEADERS =
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
   (boot-selected via `BITCOIN_NETWORK`, measured when baked into the image; cross-network replay defense).

The SPV thresholds above are compile-time constants. EVM receipt depth is
separately configured through `EVM_MIN_CONFIRMATIONS`. The
three request-size caps above are env-tunable because they only bound
resource use; they never relax a verification step.

**Checkpoints:** mainnet block 951,552 (retarget-aligned) and UTEXO
signet block 334,000 are real pinned checkpoints; regtest uses genesis. Local/dev
builds (debug, `cfg(test)`, or `allow-seed-import`) may move the anchor forward
at boot with `SPV_CHECKPOINT=height:block_hash[:bits:time]` to skip a long
initial sync; a production-shaped build refuses to start if that variable is
set, so the host can never choose the trust anchor.
Testnet3 remains a placeholder -- a release build refuses to boot on any
placeholder checkpoint. **Signet caveat:** the enclave does not validate PoW or
nBits on signet, and the BIP-325 challenge signature is not verified (the wire
format carries no coinbase witness), so signet header integrity rests on chain
linkage, the reorg/work rules, the submission caps, and the 2 h freshness
gate.

## 9. Unlock authorization predicates

For RGB→EVM, the following table separates enforced checks from bindings
delegated to the receiving contract and known gaps. Enforced checks fail closed.

| #   | Predicate                                                   | Status                                                                                                                                                            |
|-----|-------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| P1  | submitted RGB consignment is valid (`rgbstd` full validation) | OK                                                                                                                                                               |
| P2  | consignment proves the expected transition                  | OK -- the last transition MUST be the one this build's RGB flow unlocks with: `TS_TRANSFER` under `rgb-swap`, `TS_BURN` (amount from `MS_BURNED_ASSET`) under `rgb-mint-burn`, where a `bfa-mint` build also validates every `TS_BRIDGE` the burn descends from against its own verified `FundsIn` lock. Any other shape is refused |
| P3  | unlock amount equals the consignment-derived amount         | OK -- the amount is the burn's `MS_BURNED_ASSET` (host `rgb_amount` is ignored) and MUST equal `fundsOut.amount` exactly (`flow::assert_funds_out_amount`; `fundsOut.amount` is gross, commission is taken on-chain). Swap: coverage (`>=`), since a transfer's `total_output_amount` includes the sender's change leg |
| P4  | calldata is well-formed                                     | OK -- two allowlisted selectors (`fundsOut`, `lzFundsOut`), 64 KiB cap, canonical ABI decode + re-encode byte-equality, `destinationChainId` rule per route |
| P5  | payload binds destination chain / contract / **recipient**  | OK -- chain + contract pinned; the BFA burn carries `MS_BURN_RECIPIENT` and the enclave refuses a release whose calldata names a different address. Swap gap: this burn-recipient check does not apply to transfers |
| P6 | release identifiers and settlement | BFA checks canonical ABI and exact set equality of `(operationId, netAmount)` ancestry locks, with no duplicates and at least one lock. It does not derive `burnId` or `sourceAddress` from the RGB OpId. Plain IFA mint/burn does not run the settlement check. |
| P7  | referenced Bitcoin txs are in accepted chain history        | OK                                                                                                                                                               |
| P8  | Bitcoin inclusion proofs valid against the in-enclave chain | OK; plus the calldata `proof` is required (fail-closed): `source.height` is pinned to the block anchoring the consignment's last witness tx (re-verified under one lock guard), the enclave must hold a header at `latest.height`, and `latest` must be within `MAX_RELAY_TIP_LAG_BLOCKS = 100` of the enclave tip. The two `commitmentHash` words are **not** checked in-enclave: they are BtcRelay's `keccak256(StoredBlockHeader)` over relay-internal state (chainWork, lastDiffAdjustment, last ten timestamps), which the enclave cannot compute; `RGBVerifier` verifies each against the relay itself, so a manipulated commitment reverts on-chain (#57/#122) |
| P9  | corresponding EVM lock record exists for the same operation | on-chain for this direction; for EVM->RGB the enclave verifies `FundsIn` itself (Sec 7.2)                                                                         |
| P10 | EVM execution payload matches the validated unlock intent   | selector, calldata layout, amount, chain, contract: OK; recipient and operation id: see P5 / P6                                                                   |
| P11 | on any failure, refuse to sign                              | OK -- fail-closed                                                                                                                                                |

The enclave signs `burnId`, `sourceAddress`, and other decoded fields into the
typed digest; a signature binding is not itself validation of their meaning.
Settlement set equality does not require a unique ordering of deposit pairs.
End-to-end release uniqueness also depends on contract checks outside this repo.

[Signing gate](diagrams/10-signing-gate.md)

## 10. Attestation & federation

- **Public verifiability:** each signer pubkey is generated in-enclave and
  bound to a Nitro attestation. The verifier enforces: cert chain to the
  embedded AWS root with `BasicConstraints`, `keyCertSign`, path-length, and
  leaf `digitalSignature` checks; COSE `alg == ES384` with the
  raw 96-byte signature form only; PCR0/1/2 equality; nonce equality;
  and the `user_data` commitment over pubkey bundle + security policy (Sec 4).
- **PCR policy:** verifiers assert PCR0/1/2.
- **Cloning** is valid only between enclaves that target the same cluster
  pubkey, run the same code (PCR equality), and share the cloning secret, with
  mutual attestation. The DH exchange rejects small-order points; the seed
  ciphertext is bound to both handshake keys via HKDF; replay-guard nonces are
  recorded only **after** authentication succeeds, and the guard
  is TTL-bounded (1 h) with oldest-first eviction so it cannot be wedged.
  By design: authorization rests on the operator's cluster-wide secret
  delivered at runtime (not in PCRs), and the master seed stays resident so
  the donor can re-seal it per clone. Both are accepted; no change planned.
- **Federation / quorum:** unlock SHOULD require M-of-N enclave signatures;
  quorum is enforced on-chain in `MultisigProxy`. The EIP-712 digest is a pure
  function of `callData` / `nonce` / `deadline`, so quorum members sign
  identical payloads.
- **Replay:** `fundsOut` replay protection is the on-chain proxy nonce, which
  is committed into the signed digest; the enclave keeps no fundsOut nonce
  state. EVM->RGB requests get the soft in-enclave dedup guard (Sec 7.2);
  cloning nonces get their own guard.

## 11. Enforcement boundaries

- Key access and signing require `Active`; initialization cannot overwrite keys.
- Validation errors return no signature. A PSBT with zero new signatures is an error.
- Production bridge policy requires real attestation and bridge pins. This
  does not imply every runtime setting is in the policy commitment (Sec 4).
- Mainnet Bitcoin anchors use the pinned checkpoint and PoW/SPV checks.
  Signet/regtest have different validation rules (Sec 8).
- EVM deposit checks use the selected provider's receipt/head. Raw RPC is a
  trust dependency; CCD source validity is delegated to the listener.
- Plain-BTC and bridge PSBTs sign only vanilla and colored accounts respectively.
  Unowned output budgets permit bounded outputs outside proved custody scripts.
- Cloning transfers an encrypted seed between PCR-matched enclaves. Clones
  share one signing identity; they are not independent quorum members.

## 12. Failure conditions

On any of the following the enclave MUST return an error and MUST NOT sign:
invalid consignment; unsupported or unclassified transition; amount not
covered; malformed or non-canonical calldata; unpinned or mismatched
chain/contract/asset; invalid or missing SPV proof; stale, future-dated, or
incomplete header chain; cross-network consignment; missing/failed/shallow
`FundsIn` verification; `operationId` mismatch; excessive fee rate; PSBT not
anchored to the consignment; disallowed output script or value cap exceeded
(plain BTC); non-allowlisted gas tx; wrong phase; expired deadline; duplicate bridge operation within the local cache window; oversized frame, field, or header batch.

## 13. Implementation status

The repository supports swap, mint/burn, BFA mint/burn and CCD builds. Defaults
include `rgb-swap` and `ccd`; the BFA Dockerfile selects `bfa-mint`. These are
build choices, not evidence of which image is deployed.

Known limits to account for before deployment:

- **Release binding:** `sourceAddress` and `burnId` are signed as supplied;
  the enclave does not derive a canonical release identifier from the RGB OpId.
  BFA settlement validation binds the set of ancestry deposits, not every
  release field or its unique encoding/order. See Sec 9.
- **Swap authorization:** the amount floor includes transfer change, and the
  burn-recipient check does not apply to swaps. Plain IFA mint/burn does not
  perform the BFA settlement check.
- **EVM/CCD trust:** supplied images use raw EVM RPC; CCD source validation
  trusts the listener. Optional Helios is implemented but absent from those
  images and the CI production feature matrix.
- **Replay:** the EVM→RGB cache is per-instance, volatile and expires after
  24 hours. `fundsOut` nonce enforcement belongs to the receiving contract.
- **Policy coverage:** the commitment omits several enforced settings (Sec 4).
  The attestation CLI authenticates the returned chain/contract/asset pins;
  callers must compare them with their intended deployment.
- **Build reproducibility:** private RGB mirrors require credentials. Rust CI, CD and
  EIF workflows use per-repository deploy keys; Docker builds mount credentials
  as BuildKit secrets. Local builds can also use a read-access token. OS package versions float. Supplied images leave gas
  fee/gas ceilings and RGB unowned-sats budgets unset, so the corresponding
  signing paths refuse until configured in a rebuilt image.
- **Protocol integration:** BFA burns and chained mints require
  `mint_ancestors`. The enclave and parent pin the same vendored schema;
  downstream clients must send its required fields. Deployment versions are
  outside this repository's evidence.
- **Network limits:** testnet3 has a placeholder checkpoint rejected in release;
  signet does not verify PoW/nBits or its challenge signature (Sec 8).
- **Value limits:** gas ceilings apply per transaction, not across transactions;
  wire asset amounts are `u64` and larger values are refused.

## Diagram index

See the [diagram index](diagrams/README.md) for component, deployment, sequence,
state and signing-gate views. Keep diagrams and this specification aligned with
the referenced Rust handlers when behavior changes.
