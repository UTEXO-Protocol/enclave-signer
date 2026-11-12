# Nitro Enclave Signer: technical specification

- **Component:** `enclave-signer` (the enclave validator and signer, and its
  parent adapter).
- **Reviewed:** 2026-11-10 against repository code. Deployment was not
  checked.

This document states what the enclave trusts, what it checks and what it
signs. It describes implemented behavior and its limits. It is not a security
audit, and it says nothing about the deployed listener or contracts. MUST and
MUST NOT name rules that the code enforces under the stated build and trust
assumptions. [Known limits](#10-known-limits) lists what the rules do not
cover.

The bridge has two flows. Each flow has its own signer image:

| Flow | Direction | Image | Ordered checks |
|------|-----------|-------|----------------|
| Mint | EVM -> RGB | `mint-signer` | [mint-flow.md](mint-flow.md) |
| Burn | RGB -> EVM | `burn-signer` | [burn-flow.md](burn-flow.md) |

The flow documents give the checks of one request, in order. This document
gives the rules that the flows share. The [documentation index](README.md)
lists the other documents.

## 1. Purpose

The enclave signer authorizes bridge operations. It runs inside an AWS Nitro
Enclave. It makes EVM release signatures and Bitcoin PSBT signatures with its
own keys. The receiving contracts and wallets must accept the intended signing
identities.

Its job is to move trust away from the host operator. A request from a
compromised parent, listener or backend must pass the checks of its route. The
enclave derives the evidence itself: RGB consensus over a consignment (burn),
the RGB data that a mint transaction commits (mint), Bitcoin SPV inclusion,
EVM deposit events, and the bindings between the chains. A flag in a request
is never evidence. The EVM RPC is a trust exception (section 2).

A failed check returns an error and no signature. In a release image a
missing pin, proof, receipt or feature refuses the request; it never selects
a weaker path.

## 2. Trust model

```
Internet -- orchestrator -- EC2 parent (UNTRUSTED) -- vsock -- Nitro Enclave (TRUSTED)
                                  |                                    |
                              listener, backend,                 keys, validation,
                              vsock proxies                      signing
```

| Actor | Trusted for | Not trusted for |
|-------|-------------|-----------------|
| Nitro hardware and NSM | Isolation, measurement (PCRs), attestation signing, entropy | - |
| Enclave code (this repository) | Validation, key custody, signing | - (the attestation measures it) |
| Parent, listener, backend | Liveness and delivery of data | Every claim in a request. The enclave checks each one. |
| EVM RPC (pinned host and CA) | Mint signer: receipts, canonical blocks and the selected finality head. Burn signer: only the content of an asset's reject list. | TLS authenticates the endpoint. It does not prove EVM history or the answer of an `eth_call`. |
| Bitcoin indexer (pinned URL) | Nothing on an `spv` signing path. A burn signer built without `spv` trusts it for witness status and depth. | TLS authenticates the indexer. It proves no Bitcoin consensus. |
| Bridge contracts and their governance | Honest deposit events. The on-chain release rules and the signature quorum. | - |
| Operator | Deployment, launch values, the cloning secret | Export of the plaintext seed |
| AWS KMS (mint only) | Seed generation, encryption and decryption, under the configured key policy | - |

**Residual trust.** AWS (Nitro isolation and the attestation root CA), this
code and its validation libraries, the compiled-in Bitcoin checkpoint, the
pinned EVM RPC, and the Bridge contract with its governance. The enclave pins
the Bridge address, not its code: an upgraded Bridge could emit false
`FundsIn` events and so back mints that have no deposit. Mint seed recovery
also trusts AWS KMS and its key policy.

**EVM RPC (accepted by design).** TLS ends inside the enclave and
authenticates the configured host against the pinned CA. The host relay can
block or delay traffic. It cannot change an answer without detection. A TLS or
RPC failure refuses the request.

The mint signer checks that a deposit receipt succeeded, that it holds
exactly the expected events from the pinned contract, that the operation id
and the amounts match the request, that the head selected by
`EVM_FINALITY_TAG` covers the receipt, and that the block hash at its height
is the canonical one. The receipt, the blocks and the head come from the same
provider. So these are consistency checks, not a proof of EVM consensus: an
approved provider that is faulty or compromised can return a false history
that is consistent with itself. A production policy refuses the `latest`
tag.

The burn signer reads no deposit. It derives each deposit id, and it reads
the RPC only for a reject list.

**Clock.** The deadline check, the SPV tip-age check, the header time rule,
the header rate limit and the certificate checks read the system clock.
Inside Nitro this is the hypervisor clock, and the enclave uses no attested
time. So the AWS hypervisor is trusted for coarse time, as it is for
isolation. No request sets the clock. On Linux the enclave copies the
hypervisor PTP clock into `CLOCK_REALTIME` at a fixed interval
(`enclave/src/clocksync.rs`). A failed copy leaves the clock unchanged.

## 3. Architecture

Four crates:

- **`enclave`** runs inside the enclave: boot, the connection loop, request
  dispatch, the security policy, key custody, cloning, attestation, and the
  validators under `networks/rgb/` and `networks/evm/`.
- **`enclave-proto`** is the vendored `enclave` protobuf package. Its Rust is
  committed, so no code generator enters the measured build.
- **`attestation-verify`** verifies Nitro attestation documents and defines
  the encoding of the security-policy commitment. The enclave and every
  verifier use the same code.
- **`parent`** is the untrusted adapter on the EC2 host: the gRPC server, the
  operator CLI and the `attest-verify` CLI.

Diagrams: [components](diagrams/01-components.md),
[deployment](diagrams/02-deployment.md).

### Request path

The listener calls the parent over gRPC with mTLS. The parent sends one
`EnclaveRequest` to the enclave over vsock and reads one `EnclaveResponse`.
The frame is a 4-byte little-endian length and a protobuf message, with no
version field. Each connection carries one request.

- Before it decodes a frame, the enclave refuses one above
  `max_message_bytes`, and one with more field occurrences than
  `max_wire_elements`.
- 4 worker threads (`WORKER_THREADS`) serve a queue of 16 connections
  (`MAX_QUEUED_CONNECTIONS`).
- Each socket read or write can block for `io_idle_timeout_secs`. The socket
  deadline `total_request_timeout_secs` starts when the connection is
  accepted, time in the queue included.
- The socket deadline does not cancel the work of a handler. A handler can
  finish its validation after the deadline; its reply is then lost.

### Outbound connections

The enclave has no network stack of its own. It reaches the EVM RPC, the
Bitcoin indexer and KMS through loopback forwarders that bridge to
`vsock-proxy` processes on the host. TLS ends inside the enclave, so a proxy
relays bytes only. A forwarder of a TLS endpoint passes only a connection
that starts with a TLS handshake, so no client in the enclave can send
plaintext to the host for that endpoint. The EVM RPC client follows no
redirect. The indexer client can follow one, but a redirect to another host
or port has no route out of the enclave. A mint signer also connects to the
seed broker of the parent over vsock, for the AWS credentials and the stored
ciphertext of the seed.

### The parent

The parent decides who may call the enclave. It checks nothing that a
signature depends on.

- It implements `parent.ParentService`. mTLS and a client ACL give each caller
  a role ([parent-mtls.md](parent-mtls.md)).
- `Sign` routes by `data_type`: `TRANSACTION` to `Sign`, `EVM_GAS_TX` to
  `SignRawDigest`, `BTC_UTXO` to `SignBtc`, `RGB_RIGHTS_REFILL` to
  `SignRightsRefill`. It refuses a Concordium source or payload, which the
  proto still defines.
- It refuses `SubmitHeaders` from every client. Its own header sync reads
  headers from `HEADER_ELECTRUM_URL` and writes them to the enclave.
- It waits longer for a reply than the request deadline of the enclave, so
  the enclave gives up first ([runtime-limits.md](runtime-limits.md#the-parent)).
- It keeps the reply of each EVM -> RGB sign and answers a retry of the same
  request from it ([mint-flow.md](mint-flow.md), section 6).

Any process on the parent instance can also reach the enclave directly over
vsock. So every signing check runs inside the enclave.

### Launch values

The operator sends the chain endpoints once after launch, in `SetEndpoints`:
the indexer URL, the EVM RPC host, CA, port and optional path, and on a mint
signer the KMS values ([configuration.md](configuration.md#launch-values)).

- Until the set, the enclave refuses `Sign`, `SignBtc`, `SignRightsRefill`,
  `SignRawDigest`, `GetAttestedPublicKey`, `GetClone`, `SetClone` and, on the
  mint signer, `InitializeKey`. It opens no chain connection, and `Health`
  reports not ready.
- The enclave refuses a second set. A refused set leaves the enclave unset, so
  a retry works. New values need a restart, which clears the keys in memory.
- The values, and any digest of them, are outside the image. Members with the
  same role, release and build profile run one EIF with different endpoints.
  A mint image also holds `KMS_ALLOWED_ACCOUNT_IDS`, so members share it only
  if the list has the account of each member's key.
- A release image accepts only a TLS indexer URL (`ssl://` or `https://`).
- A `Production` policy commits the indexer host, the EVM RPC host, the CA
  hash and the KMS values (section 4). A `Development` policy commits none of
  them.

Endpoint approval is a deployment duty. The enclave checks no operator
signature on these values. TLS authenticates the endpoint that the launch
selected; it does not show that the operator approved it.

### Runtime limits and memory

The operator can change the time, memory and size limits of a running
enclave. Each limit only sets when the enclave refuses a request or how long
it waits, so the attestation does not cover them. The safety rules stay in the
image. [runtime-limits.md](runtime-limits.md) lists the limits and their
image values.

The enclave has a fixed amount of memory and no swap. So the heap that one
request can use has a bound that does not depend on the content of the
request: `REQUEST_MEMORY_FACTOR` times the frame, plus a term for the decoded
protobuf elements. A parser that can take more has its own size limit. The
answers of the EVM RPC and the indexer are outside the model, except a reject
list, whose entry limit the model counts. A release build refuses to start
with less usable memory than the model needs for all its workers.
`enclave/src/memory.rs` holds the model and its measured factors; the tests
are next to the parsers that they measure.
[operations.md](operations.md#memory) gives the launch value.

## 4. Security policy

The enclave resolves one security policy when the launch values are set. It
commits the policy next to the public-key bundle in the attestation. The
policy covers the fields below, not all configuration.

```
SecurityPolicy = Production {
    chain_id, bridge_contract, rgb_asset_id,     -- bridge pins
    bitcoin_network,                             -- BITCOIN_NETWORK
    funds_in_contract, token_contract,           -- deposit and burnId pins
    evm_finality_tag: Latest | Safe | Finalized, -- required receipt head
    spv_min_confirmations,                       -- Bitcoin witness depth
    allow_vanilla_psbt,                          -- plain-BTC signing on or off
    signer_role: Mint | Burn | Combined,
    attestation: Real,
    evm_source:  Disabled | PinnedTlsRpc,
    electrum_host, evm_rpc_tls, gas_tx_rule,
    btc_source:  SpvVerified,
    kms,                                         -- mint signer only
    clone_peer_pcr3,                             -- cloning roles only
} | Development { reason }
```

**Resolution** (`enclave/src/policy.rs`). Only a release `spv` build with
`EVM_CHAIN_ID`, `EVM_PROXY_CONTRACT_ADDRESS` and `RGB_ASSET_ID` set resolves
to `Production`. A debug or test build, a build with a dev feature, a build
without `spv` and a build with a missing pin resolve to `Development`.

**Boot gate.** A release `spv` build that does not resolve to a valid
`Production` policy refuses to boot. `SetEndpoints` runs the gate again with
the launch values and refuses the set on an error. The gate requires:

- a non-zero FundsIn contract (`FUNDS_IN_CONTRACT`, or its default, the
  proxy address) and a non-zero `TOKEN_CONTRACT`;
- `BTC_RELAY_MODE=required`;
- `BITCOIN_NETWORK=bitcoin` when `EVM_CHAIN_ID` is 1 or 42161;
- an `EVM_FINALITY_TAG` of `safe` or `finalized`;
- `SPV_MIN_CONFIRMATIONS` of at least 1;
- at `SetEndpoints`: an indexer host, and a host and CA pin for the
  pinned-TLS source;
- at `SetEndpoints`, for a cloning role: a PCR3 that is not all zero.

A build with a signer role and without `spv` needs real attestation,
`BITCOIN_NETWORK=signet`, `BTC_RELAY_MODE=none` and the bridge pins, in a
debug and in a release profile. It boots and signs on
`Development { IndexerTrusted }` and on no other policy. Each dev feature
(`mock-attestation`, `allow-seed-import`, `allow-debug-pcrs`) fails to
compile in a release build. A build with both signer roles, or with
`rgb-validation` and no role, fails to compile.

**Commitment.** The attestation carries
`user_data = sha256(canonical_pubkey_bundle || policy_commitment)`. The
encoding is versioned and shared (`attestation-verify/src/policy.rs`), so the
enclave and every verifier produce the same bytes
([pubkey-attestation.md](pubkey-attestation.md#security-policy-commitment)).
An unset gas pin commits as its zero value, which is the rule it enforces. So
"unpinned" is attested too.

**Verification.** A verifier builds the policy it expects from independently
approved values and fails on any difference. A weaker posture (plain-BTC
signing on, another EVM source, a dev build) then fails verification. Values
copied from the signer under check prove nothing. Attestation shows which
endpoint is configured; it does not show that the provider is honest.

**Not in the commitment.**

- Launch values that nothing attests or measures: the scheme and port of the
  indexer URL, and the port and path of the EVM RPC. A release image accepts
  only TLS for the indexer; PCR0 measures that rule, not the value.
- Image settings that PCR0 measures and the policy does not commit: the
  values of `BTC_MAX_TOTAL_SATS` and `BTC_MAX_UNOWNED_SATS` (only "plain BTC
  on or off" is committed), `MINT_WITNESS_SAT` and `KMS_ALLOWED_ACCOUNT_IDS`.
- The runtime limits in force, which nothing attests. PCR0 measures only
  their image values.

On a build without `spv` the `Development` policy commits no field. Its gas
rule and `SPV_MIN_CONFIRMATIONS` are measured, not attested.

## 5. Keys and lifecycle

**Seed.** A burn signer makes its seed inside the enclave from OS entropy
(BIP-39 mnemonic, BIP-32 seed). A mint signer gets its 64-byte seed from AWS
KMS through recipient attestation ([kms-persistence.md](kms-persistence.md)).
The seed stays in a `SecretBox`. The enclave MUST NOT export it in plaintext.
Mnemonic and seed import need `allow-seed-import`, which a release build
refuses.

| Key | Path | Use |
|-----|------|-----|
| EVM bridge key | `m/44'/60'/0'/0/0` | Signs the release (burn). Its address is the cluster identity. |
| EVM gas key | `m/44'/60'/0'/0/1` | Signs the outer gas transaction (burn). |
| Vanilla Taproot account | `m/86'/<coin>'/0'`, coin 0 on mainnet and 1 elsewhere | Plain-BTC `SignBtc` only. |
| Colored Taproot account | `m/86'/<rgb_coin>'/0'`, 827166 on mainnet and 827167 elsewhere | Mint and refill PSBTs only. |

Key derivation and the shape of the attested key bundle are the same in every
build. The role gates the request path, not the keys.

**Phases.** Signing requires `Active`. `Active` is terminal: a process cannot
replace or rotate its keys.

| Phase | Holds | Entry |
|-------|-------|-------|
| `Initial` | Nothing | Boot |
| `Initializing` | A KMS initialization in progress (mint only) | `InitializeKey` |
| `Cloning` | A requester session: an ephemeral key, the target cluster key, the pending secret | `InitiateCloning` |
| `Active` | The keys | `InitializeKey`, or `SetClone` on a requester |

`InitializeKey` from `Active` or `Cloning` fails. A failed KMS recovery
returns to `Initial`. A new `InitiateCloning` can replace an expired `Cloning`
session. See the [phase diagram](diagrams/09-state-phase.md).

**Upgrade.** A new image runs as a new enclave process, with measurements that
must be approved before use. A mint signer recovers its seed through KMS when
the key policy permits the new image. A burn signer on a new image cannot
take the seed of an old image, because cloning needs equal PCR0, PCR1 and
PCR2 ([cloning.md](cloning.md)). It makes a new seed, or it clones from
another enclave of the new image.

**Clones are one identity.** A cloned enclave signs as the same EVM address.
Replicas of one seed are not independent quorum members.

## 6. Requests

| Request | Phase | Signer | What it does |
|---------|-------|--------|--------------|
| `SetEndpoints` | any | all | Sets the launch values. Once per boot. |
| `SetLimits`, `GetLimits` | any | all | Change or read the runtime limits. |
| `InitializeKey` | `Initial` | all | Mint: recover or create the KMS seed. Burn: make a seed from OS entropy. |
| `GetPublicKey` | `Active` | all | The public-key bundle and the boot pins. |
| `GetAttestedPublicKey` | any, after `SetEndpoints` | all | The bundle and an attestation document for a nonce. Before keys exist it attests the policy only. |
| `Sign` | `Active` | mint, burn | Bridge signing. Mint signer: EVM -> RGB. Burn signer: RGB -> EVM. |
| `SignBtc` | `Active` | mint | A plain-BTC PSBT on the vanilla account. |
| `SignRightsRefill` | `Active` | mint | A send of one mint right to new rights of the mint wallet. |
| `SignRawDigest` | `Active` | burn | A gas transaction under the attested allowlist. |
| `SignRawMessage` | - | none | Refused in every build. |
| `SubmitHeaders` | any | mint, burn, built with `spv` | Bitcoin headers for the header chain. |
| `GetLastSavedBlock` | any | mint, burn, built with `spv` | The tip of the header chain, or the checkpoint when the chain is empty. |
| `InitiateCloning`, `GetClone`, `SetClone` | see [cloning.md](cloning.md) | burn | The seed cloning handshake. |
| `Health` | any | all | Readiness: launch values set, keys loaded and, where a release needs it, a ready header chain. |

### 6.1 `Sign`

One request carries a source network and a destination network. The accepted
routes are RGB -> EVM and EVM -> RGB. Any other pair is refused. A signer
compiles one direction only and refuses the other.

**RGB -> EVM (burn signer).** The enclave validates the consignment with
full RGB consensus, proves every witness transaction in its own header chain,
and binds the release to the burn. It signs an EIP-712 digest over the
decoded calldata fields: `TeeFundsOut` on the direct route, `TeeLzFundsOut`
on the LayerZero route. It builds no batch digest and signs no opaque
calldata. Section 8 lists the predicates. [burn-flow.md](burn-flow.md) gives
the checks in order.

**EVM -> RGB (mint signer).** The enclave reads the mint from the fascia that
rgb-lib wrote for the PSBT's transaction, and it validates no consignment. It
proves that the transaction commits exactly one mint of the pinned asset, that
the mint issues exactly the deposited amount less the commission, that the
deposit names this mint and this transaction, and that the PSBT spends the
one output that holds the mint right. It then signs with the colored account.
[mint-flow.md](mint-flow.md) gives the checks in order.

### 6.2 Other signing requests

- **`SignBtc`** signs a plain-BTC PSBT with the vanilla account only. It is
  off unless the image sets `BTC_MAX_TOTAL_SATS`; a `Production` policy
  attests that switch. Each request must pay its
  outputs back into the custody of its inputs, within a value cap, an
  unowned-sats budget and the fee policy
  ([mint-flow.md](mint-flow.md#7-plain-btc-signbtc)).
- **`SignRightsRefill`** signs the mint wallet's own send of one mint right
  to new rights. No deposit backs it, so its rule checks shape only: every
  new right and every sat stays on the enclave's outputs, and no units move
  ([mint-flow.md](mint-flow.md#8-rights-refill-signrightsrefill)).
- **`SignRawDigest`** signs the gas transaction that sends a release. The
  request carries the unsigned transaction; the enclave decodes it, checks it
  against the attested gas rule and computes the digest itself. It never
  signs a digest that a caller supplies
  ([burn-flow.md](burn-flow.md#6-the-gas-transaction-signrawdigest)).
- **`SignRawMessage`** asks for an EIP-191 signature over caller bytes with
  the bridge key. No rule could limit such a signature, so the enclave refuses
  the request in every build.

### 6.3 Errors

A refused request gets an `ErrorResponse` with a code. The parent maps the
code to a gRPC status. A direct caller identifies a retryable state by the
code, not by the text. The parent gives codes 3 and 8 the same gRPC status,
so a gRPC caller identifies the finality wait by its fixed prefix.

| Code | Meaning | gRPC status |
|------|---------|-------------|
| 1 | Any other error. A request that needs keys before they exist gets this code. | `INTERNAL` |
| 2 | Not ready: the launch values are not set, or the enclave is not in the phase that the request needs. On a mint signer also an unavailable KMS or seed store. | `UNAVAILABLE` |
| 3 | A failed cross-check or SPV check. On `GetClone` also a donor without keys. | `FAILED_PRECONDITION` |
| 4 | `GetClone`: invalid input | `INVALID_ARGUMENT` |
| 5 | `GetClone`: refused credential, attestation, PCR or public key | `PERMISSION_DENIED` |
| 6 | `GetClone`: replayed attestation nonce | `ALREADY_EXISTS` |
| 7 | `GetClone`: seed-export cap reached | `RESOURCE_EXHAUSTED` |
| 8 | The deposit receipt is above the `safe` or `finalized` head. The caller waits and retries. | `FAILED_PRECONDITION`, with the fixed prefix `evm event pending finality:` |

## 7. Bitcoin header chain (SPV)

An `spv` build keeps its own Bitcoin header chain. The parent feeds it with
`SubmitHeaders`, and the enclave validates every header
([sequence](diagrams/08-seq-spv-submit-headers.md)). An RGB -> EVM release
needs a proof in this chain for every witness transaction of its consignment.
The mint signer checks no witness.

1. **Header validity.** On mainnet and the testnets the enclave checks
   linkage, proof of work and `nBits`. The testnets apply the 20-minute
   minimum-difficulty rule. Testnet4 adds BIP94: the retarget starts from the
   first block of the period, and that block may be at most 600 s older than
   its parent.
2. **Header time.** On every network a header may be at most
   `MAX_FUTURE_BLOCK_TIME_SECS` (two hours) ahead of the enclave clock, and it
   must be newer than the median time of the eleven blocks below it. These
   are Bitcoin Core's `time-too-new` and `time-too-old` rules. A chain from
   genesis takes the median of the blocks it has. Above any other checkpoint
   the median rule starts at the eleventh block above the checkpoint. Without
   these rules a host could date min-difficulty blocks to lower the
   difficulty of its own fork.
3. **Reorganization.** The enclave accepts a replacement chain only when it
   has more cumulative work and replaces at most `MAX_REORG_DEPTH` (100)
   blocks.
4. **Retention.** The enclave keeps every header above the checkpoint, so old
   RGB anchors stay verifiable. It refuses a submission that would pass
   `MAX_STORED_HEADERS` (1,000,000).
5. **Rate.** At most `max_headers_per_submit` headers per call and
   `max_headers_per_minute` per fixed 60-second window. Submitted headers
   count before validation, invalid ones included.
6. **Inclusion.** A request carries one Merkle proof for each witness
   transaction of its consignment: none missing, none extra, no duplicate.
   The path has at most `MAX_MERKLE_PATH_DEPTH` (32) levels and uses up the
   transaction position, one bit per level. A path on which a hashed node is
   a 64-byte transaction is refused (CVE-2017-12842). The block must be at
   least `SPV_MIN_CONFIRMATIONS` deep.
7. **Freshness.** The chain tip must be at most `SPV_MAX_TIP_AGE_SECS` old
   and at most `SPV_MAX_TIP_FUTURE_SECS` in the future (two hours each). This
   checks timestamps. It does not prove that the parent sent the network tip.
8. **Network.** The consignment's `chain_net` must be the enclave's
   `BITCOIN_NETWORK`.
9. **Pins until the key is used.** The enclave records the hash and the
   required depth of each block that a check used. It checks both again while
   it holds the lock of the header chain, and keeps the lock until it has
   signed. A changed hash, or a block shallower than its check required,
   refuses the signature. The caller sends the request again when
   the block is deep enough.

`SPV_MIN_CONFIRMATIONS` and `BITCOIN_NETWORK` come from the image env, so
PCR0 measures them, and a `Production` policy commits them. A Nitro enclave
takes no env from the host. The limits of rule 5 are runtime limits. The
other SPV thresholds are compile-time constants.

**Checkpoints.** The checkpoint is the trust anchor of the chain. A release
build uses only the compiled-in value. `SPV_CHECKPOINT` can move the anchor
on a dev build; a production-shaped build refuses to start when it is set.

| Network | Checkpoint | Header checks |
|---------|------------|---------------|
| `bitcoin` | Block 951,552 | Full: linkage, proof of work, `nBits`, time. |
| `testnet4` | Block 155,232, without chainwork | Full, with the testnet rules. Test-grade: min-difficulty blocks count for depth and freshness. |
| `testnet3` | Placeholder. A release build refuses to boot. | Full, with the 20-minute rule. |
| `signet`, `signetcustom` | Block 334,000 of the UTEXO signet, without chainwork | No proof of work, `nBits` or signet challenge signature. Linkage, time, reorganization, rate and freshness rules only. |
| `regtest` | Genesis | No proof of work or `nBits`. |

An RGB -> EVM release under `BTC_RELAY_MODE=required` needs the chainwork of
the checkpoint. So it fails on `testnet4` and the signets, unless a dev build
sets `SPV_CHECKPOINT` with chainwork.

## 8. Release authorization (burn)

The table lists what an RGB -> EVM release must pass. The enclave enforces
each row before it signs. [burn-flow.md](burn-flow.md) gives the checks in
order; the [signing gate diagram](diagrams/10-signing-gate.md) shows them as
decisions.

| # | Required | Enforcement |
|---|----------|-------------|
| P1 | Valid RGB consignment | Full RGB consensus validation by rgb-lib, under the pinned schema. |
| P2 | Expected transition | The settling transition must be a `TS_BURN`: the one burn of the last witness bundle. Two burns there are refused. |
| P3 | Exact amount | `burnedAsset` must equal the calldata `amount`. The host's `rgb_amount` is not evidence. |
| P4 | Valid calldata | An allowed selector, a size limit, canonical ABI encoding, the destination-chain rule of the route, and a bounded deadline. |
| P5 | Correct destination | The pinned chain and contract. The payee, `destinationChainId` and LayerZero `dstEid` must match the burn destination (`burnReason`). |
| P6 | Release identity | Source chain 827166, an empty source address, the recomputed `burnId`, `sourceBurnTxId` equal to the burn OpId, and settlement ids equal to the derived deposits. |
| P7 | Accepted Bitcoin history | With `spv`: every witness is in the enclave's header chain. Without `spv`: the indexer gives the chain view. |
| P8 | Inclusion and relay agreement | With `spv`: Merkle inclusion, depth, tip freshness and the BtcRelay proof. Without `spv`: the indexer gives the depth. |
| P9 | Backed mints | The enclave derives the deposit id of every mint in the consignment. It reads nothing from the chain. |
| P10 | Signed payload matches the checks | The typed digest commits to the decoded fields that the checks read. |
| P11 | No signature on failure | A failed check returns an error. |

The contracts complete two of these rows. `RgbSettlementModule.beforeFundsOut`
checks that each cited deposit exists (P9). The Bridge refuses a `burnId` or a
`sourceBurnTxId` that it already used (P6). A signature from the enclave does
not prove that a release will succeed on chain.

## 9. Quorum and replay

- **Quorum.** `MultisigProxy` enforces M of N enclave signatures on chain. The
  EIP-712 digest is a function of the calldata, the nonce and the deadline, so
  quorum members sign the same payload.
- **Release replay.** The burn signer keeps no release state. The
  `MultisigProxy` nonce is in the signed digest, and the Bridge refuses a
  used `burnId`. A signature expires at its deadline.
- **Mint replay.** Every signature for one mint spends the same output, so
  Bitcoin confirms at most one. An in-memory guard also refuses a second
  request for a deposit for a time. It is not the safety control
  ([mint-flow.md](mint-flow.md), section 6).
- **Clone replay.** Each donor records the attestation nonces that it
  accepted ([cloning.md](cloning.md)).

## 10. Known limits

Read these before a deployment. The production images are the mint signer
(`build/Dockerfile.enclave.mint`) and the burn signer
(`build/Dockerfile.enclave.burn`). A build recipe is not evidence of what is
deployed.

**Burn**

- **Stuck burns.** A V1 burn whose destination record is lost, or whose route
  is later disabled, cannot be released. The units are already burned, and
  the backing stays in the Bridge. The backend must keep the record
  ([burn-destination.md](burn-destination.md)).
- **Settlement ancestry.** `settlementData` must cite the deposit of every
  `TS_MINT` in the consignment, not only of the mints that fed the burned
  units.
- **Release route (contracts).** The Bridge release route for source chain
  827166 must use `RgbSettlementModule`. Only its `beforeFundsOut` checks that
  each cited deposit exists.
- **Reject list.** For an asset whose genesis names a reject list, the burn
  signer reads the whole list over the pinned EVM RPC on each request and
  trusts the RPC for its content. A provider that hides an entry lets a
  rejected lineage release. A failed read, or a list above
  `max_reject_list_entries`, refuses every burn of the asset. Whoever can
  append to the list can stop every release. A burn of rejected units stays
  refused until an allow for them is finalized, and its units are already
  burned ([burn-flow.md](burn-flow.md), Stage 3b).
- **Validation time.** Work caps and a modeled time budget bound the work of
  rgb-lib on a consignment. The model is fitted to measurements, not proved:
  a shape that costs more than the measured ones runs longer than its budget.
  The caps can also refuse an honest burn with a very long history, until the
  operator raises them ([validation-cost-model.md](validation-cost-model.md)).
- **Gas transactions.** The gas limits apply to one transaction, not to a
  sum. A gas transaction is not linked to one checked release, and the
  LayerZero fee is not bound to its release. A compromised listener can ask
  for many transactions within the limits and drain the gas account. The
  production recipe sets no gas limits, so its gas path refuses every request
  until an image sets them.

**Mint**

- **EVM RPC trust.** A false history that is consistent with itself, from the
  approved provider, passes the deposit checks of the mint signer. This is
  accepted by design (section 2).
- **No history check.** The mint signer validates no RGB history: no
  consensus, genesis, ancestor, witness depth or reject list. A host that
  controls the bridge can make a mint that no wallet accepts, after the user
  locked. It cannot mint units that no deposit backs, and it cannot spend
  other state of the wallet. The mint wallet must hold no right whose parent
  is a mint or the genesis ([mint-flow.md](mint-flow.md), section 11).
- **Witness mint recipient.** The deposit's lockId commits the mint
  transaction, and so the script that the user's output pays. The user locks
  the lockId that the bridge hands out, so the bridge must name the
  transaction that pays the user.
- **Fee after the lock.** The mint transaction cannot change after the lock,
  and no fee bump is implemented. It must confirm at its original fee.
- **Refill fee input.** A host that pays for a junk parent transaction can
  make a refill destroy one right on its fee input. It cannot take a right.
  The hourly refill limit bounds it ([mint-flow.md](mint-flow.md), section 8).
- **Replay guard.** The EVM -> RGB guard is in memory and per enclave. A
  restart, its expiry or another replica lets a second request through. The
  parent proof is the bound: Bitcoin confirms at most one spend of the right.

**Both**

- **Policy coverage.** The commitment does not hold every enforced setting
  (section 4). A verifier must compare the attested chain, contract and asset
  pins with the intended deployment.
- **Builds without `spv`.** A build with a signer role and without `spv` runs
  on public Signet only and attests `Development`, which commits no endpoint
  and no KMS value. A compromised host can launch it with its own TLS
  endpoints: its own indexer for a burn signer, its own EVM RPC for a mint
  signer. A burn signer built this way trusts the indexer for witness status
  and depth, and checks no request-supplied Merkle proof or BtcRelay proof.
  rgb-lib checks the network, transaction IDs and confirmation depth against
  that trusted chain view ([burn flow](burn-flow.md#2-who-does-what)). These
  checks do not independently verify Bitcoin inclusion or headers.
  `attest-verify` and `verify-launch` refuse this policy.
- **Test networks.** Testnet4 SPV is test-grade: a host can make
  min-difficulty blocks at almost no cost, and they count for depth and
  freshness. Run it with `BTC_RELAY_MODE=required` and a relay that applies
  the same rule. The signets and regtest check no proof of work (section 7).
- **Request deadline.** The socket deadline does not cancel a handler. A
  handler with slow indexer or RPC calls can run past it.
- **Build reproducibility.** Reproducing PCR0 needs read access to a private
  rgb-lib mirror, and CI does not pin the Docker and BuildKit versions
  ([building.md](building.md#reproducibility)).
- **Contract integration.** The Bridge must derive RGB deposit ids as the
  enclave does. Tests compare the EIP-712 domain and digests with stored
  contract fixtures; they do not read the deployed contracts.
- **Amounts.** Asset amounts on the wire are `u64`. The enclave refuses a
  larger value.
