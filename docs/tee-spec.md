# Nitro Enclave Signer -- Technical Specification

**Component:** `enclave-signer` (TEE validator / signer + parent adapter)
**Reviewed:** 2026-11-02 against repository code. Deployment was not checked.

The production bridge has two flows. Each flow has its own signer image:

- **Mint** (EVM -> RGB), `mint-signer`: [mint-flow.md](mint-flow.md).
- **Burn** (RGB -> EVM), `burn-signer`: [burn-flow.md](burn-flow.md).

Read those two documents first. This specification gives the full rules.

This document describes implemented behavior and its limits. It is not a
security audit or a statement about the currently deployed listener/contracts.
MUST/MUST NOT describe enforced rules within the stated build and trust
assumptions. Known gaps are collected in Sec 13.

---

`mint-signer` enables `kms-persistence`: initialization uses attested KMS seed
generation/recovery and encrypted S3 storage; peer cloning is disabled. Burn
signers and other builds without this capability use the entropy/cloning
lifecycle below. See [KMS seed persistence](kms-persistence.md).

## 1. Purpose

The enclave signer authorizes bridge operations. It runs inside an
**AWS Nitro Enclave (TEE)**. It produces EVM release signatures and Bitcoin
PSBT signatures with its own keys. The receiving contracts and wallets must
accept the intended signing identities.

Its job is to move trust away from the host operator: requests from a compromised parent, listener, or backend must pass
the checks implemented for the selected route. The enclave validates RGB consignments (burn),
the RGB data a mint or refill tx commits, from its rgb-lib fascia (mint), Bitcoin SPV inclusion, EVM
deposit events, and cross-domain bindings itself; it does not treat request
flags as evidence. The EVM RPC and CCD are trust
exceptions, described below.

## 2. Trust boundary and threat model

```
Internet -- orchestrator -- EC2 parent (UNTRUSTED) -- vsock -- Nitro Enclave (TRUSTED)
                                  |                                    |
                              listener, backend,                 key material,
                              Electrum / EVM-RPC                 validation, signing
                              vsock proxies                       (this spec)
```

| Actor                            | Trusted for                                      | NOT trusted for                                                                        |
|----------------------------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| Nitro hardware + NSM             | measurement (PCRs), attestation signing, entropy | --                                                                                     |
| Enclave code (this repo)         | validation, key custody, signing                 | -- (the thing being attested)                                                          |
| Parent host / listener / backend | liveness, transport, data *delivery*             | request claims are checked; the EVM RPC is TLS to a pinned CA; CCD has an explicit trust exception |
| Electrum / Esplora indexer (pinned URL, TLS in the enclave) | nothing on the production signing paths. A burn signer built without `spv` (public Signet, `Development` policy) trusts it for witness status and confirmation depth (Known limits) | the mint signer reads its RGB data from the rgb-lib fascia of the PSBT's tx (Sec 7.2); an `spv` burn counts a witness as mined only through an SPV proof against the enclave header chain. TLS authenticates the indexer; it proves no Bitcoin consensus. The mint and burn launches pin the URL even where no signing path reads it. |
| EVM RPC endpoint (pinned TLS) | receipt, canonical block and selected finality head correctness and availability, as an explicit design assumption. On the burn signer also the reject-list reads: `length()` and `entries()` of an asset's `IRgbRejectList` (Known limits). A hidden entry lets a rejected lineage release. An invented entry or a failed read refuses releases. | TLS authenticates the endpoint; it does not prove canonical EVM history or the answer of an `eth_call` (Sec 7.1-7.2) |
| Operator | deployment, configuration pins, the cloning secret | plaintext seed export from the enclave |
| AWS KMS (mint only) | seed generation, encryption, and decryption | host access to plaintext, subject to the configured KMS policies |

**Residual trust anchors:** AWS (Nitro isolation + attestation root CA), the
correctness of this enclave code and its validation libraries, the Bitcoin
checkpoint, and the pinned EVM RPC endpoint. Mint seed recovery also trusts
AWS KMS and its access policies. The Bridge contract and its governance are
trusted: the enclave pins the Bridge address, not its code, so an upgraded
Bridge could emit fake `FundsIn` events and back unbacked mints. EVM deposits,
the BFA mint lock included, must be covered by the RPC head selected by
`EVM_FINALITY_TAG` (`finalized` in every image, and the default), and match the
canonical block hash at their height; the RPC is trusted for that tag.
On Arbitrum, `latest` accepts the current L2 tip with sequencer and L1 reorg
risk; `safe` waits for the batch to be posted and covered by L1's safe head,
with residual L1 reorg risk; `finalized` waits for L1 finalized coverage.
A production policy refuses `latest` at boot.
The mint signer validates no RGB history: a bad history makes the mint
invalid for every receiver, so it is liveness only (Sec 7.2). CCD source
checks trust the listener.

**Pinned EVM RPC trust (accepted by design, F05-NEW-AF-07):** the production
mint and burn images use `PinnedTlsRpc`. TLS ends inside the enclave and
authenticates the configured hostname against the pinned CA. The host relay
can block or delay traffic, but cannot alter authenticated responses without
detection. A TLS or RPC failure refuses the signing request.

The enclave checks successful receipts, unique expected events from the pinned
`FUNDS_IN_CONTRACT`, the operation-ID and amount bindings for the selected
flow, coverage by the selected finality head and a matching canonical block
hash at the receipt height. Receipts, blocks and the head come from the same provider.
These are consistency checks, not EVM consensus proofs. A faulty, malicious
or compromised approved provider can return a self-consistent false deposit
history that passes them.

For the burn flow, RGB consensus, Bitcoin SPV and burn/settlement bindings
still apply. The receiving contracts must also enforce their on-chain
settlement rules and signature quorum (Secs 9-10). Those checks constrain
release execution; they do not authenticate the provider's historical receipts
inside the enclave. Passing the enclave checks alone does not prove that a
release will succeed on-chain.

**Wall clock:** the deadline check, the SPV tip-staleness check, and the
header-submission rate limit read `SystemTime::now()`. Inside Nitro this clock
is hypervisor-provided (kvm-clock); there is no NSM-attested time source. The
accepted assumption: the AWS hypervisor is trusted for *coarse* time --
consistent with already trusting it for isolation and attestation. The code exposes no request that sets the clock. On Linux, `clocksync.rs`
copies the hypervisor PTP clock into `CLOCK_REALTIME` every five minutes.
A synchronization failure leaves the current clock unchanged.

**No batch signing:** the enclave builds exactly two digest shapes -- the
typed `TeeFundsOut` and `TeeLzFundsOut` EIP-712 structs over decoded calldata
fields (Sec 7.1). This path has no batch or opaque-calldata digest builder. The receiving
contract must use the same signature format. Gas transaction and Concordium
signing have separate rules.

**Concordium exception:** the CCD source is the one input the enclave does not
re-validate (Sec 7.9). The listener's finality check is trusted there by
design; the enclave binds only the amount.

## 3. Architecture

Four crates plus the infrastructure they touch:

- **`enclave`** -- runs inside the TEE. Boot sequence (`main.rs` + `bootstrap.rs`), connection loop (vsock in
  prod / TCP in dev; hardening in `conn.rs`) -> `server/dispatch.rs` -> `policy.rs` (security policy),
  `keys.rs` / `state/` (key custody, phases), `cloning.rs`, `attestation.rs`,
  and the network validators under `networks/`:
  - `networks/rgb/` -- consignment validation, PSBT binding (`psbt_validation.rs`),
    the mint signer's PSBT core (`psbt_commit.rs`) and parent proof
    (`parent_proof.rs`),
    invoice recipient bind (`invoice.rs`), taproot signing, the SPV header
    chain (`spv/`), plain-BTC ownership and sats gates, and the flow rules in
    `flow.rs`;
  - `networks/evm/` -- `fundsOut` / `lzFundsOut` calldata validation and
    crosschecks, EIP-712 signing, `FundsIn` event verification
    (`events.rs`), gas-tx validation;
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

**Cargo features.** `spv` (implies `rgb-validation`),
`ccd`,
`vsock`, and for mint/burn exactly one signer role: `mint-signer` (EVM -> RGB)
or `burn-signer` (RGB -> EVM), each implying `rgb-validation`. `mint-signer` also
enables `kms-persistence`. Production images are built with
`--no-default-features` and an explicit set (README, Building). Dev-only features
(`mock-attestation`, `allow-seed-import`, `allow-debug-pcrs`) are
`compile_error!` in release. So is `ccd` with a signer role (Sec 7.9).

**Wire protocol** enclave<->parent: 4-byte little-endian length prefix + prost
protobuf, 24 MiB frame limit, no version field (`framing.rs`). Before the
decode, `check_request_shape` counts the field occurrences on the wire and
refuses a request with more than 2^19 (`max_wire_elements`). The walk enters
only the messages that `framing::Schema` names. A test reads `enclave.proto`
and fails when a request message gets a repeated field outside them. The
Bitcoin indexer and the EVM RPC are reached through in-enclave loopback
forwarders. They bridge over vsock to host-side `vsock-proxy` instances
(vsock ports 8001 and 8002). The enclave has no direct network stack.

**Runtime limits** (`limits.rs`). The operator can change the time, memory and
size limits of a running enclave. A change needs no new image, so the PCR values
do not change. The attestation does not cover these values. Each limit only sets
when the enclave refuses a request or how long it waits. Safety rules stay in the
image. `docs/runtime-limits.md` has the list. The numbers in this document are the
image values.

**Request memory model** (`memory.rs`). The enclave has a fixed amount of
memory and no swap. So the heap one request can use has a bound that depends
only on its size. The bound is `REQUEST_MEMORY_FACTOR` (24) times the frame,
plus 64 MiB for the decoded protobuf elements. Most parsers that grow with
their input stay within the factor. Reading a frame takes 3 times the frame.
Consignment validation of a long history takes about 21 times the
consignment, because rgb-lib decodes a second copy while the enclave keeps its
own. A fascia of many rights takes about 11 times its bytes. The gas
transaction parser stays under 0.1, and a PSBT whose bytes sit in large
records takes about 1.5. A whole burn request through `dispatch` holds the
decoded request during validation. It peaks at about 20 times its frame beyond
the element term.

Some parsers take more on the densest inputs measured, and each has a size
limit:

- a PSBT of one input and outputs with two empty records each: about 102
  times, 1 MiB limit
- an attestation document of CBOR nulls: about 48 times, 64 KiB limit
- a consignment of transfers that turn one mint right into tens of
  thousands: about 53 times, 10 MiB limit

At those limits each fits the bound of the largest frame, 640 MiB, which each
worker holds. A request holds one parsed PSBT at a time, and a fascia has the
PSBT limit. A burn request with the densest consignment measured takes about
632 MiB at the limit by the test's count. The real peak is lower, because the
cost gate of validation refuses a chain this dense above about 2 MiB. The
sender sets part of the rate through the order of the OpIds, which sets how
full RGB validation keeps its B-trees. Validation clones the decoded
consignment, so each decoded list keeps only its length.
`MAX_CONSIGNMENT_BYTES` can lower that limit in the image, and the enclave
refuses to start with a larger value. A runtime change (`SetLimits`) can raise
it only with a frame whose memory holds the densest consignment
(`docs/runtime-limits.md`).

The tests measure the frame, consignment, PSBT, fascia, gas transaction and
attestation document parsers on the densest shapes measured. The other parsers
have small size limits and refusal tests. The remaining request fields are
fixed-size, refused before use, never read, or only compared, hashed or read
once. `memory.rs` names the ones with no upper limit. Four workers, the bound
for a 24 MiB frame and a 512 MiB baseline give the minimum usable memory
(3072 MiB). A release build reads `MemTotal` from `/proc/meminfo` at boot. It
refuses to start with less, or with no readable total. `MemTotal` leaves out
the memory the kernel keeps for itself, so `run-enclave --memory` must give
at least 4096 MiB, a whole number of GiB. The deploy scripts use that value
and refuse a smaller `ENCLAVE_MEMORY`. `deploy-host.sh` and
`utexo-enclave-ctl.sh check` also refuse a hugepage pool smaller than the
launch value of the one enclave they check.

**Launch endpoints.** The operator sends these once after launch in
`SetEndpoints`: the Electrum URL, the EVM RPC host, the EVM RPC CA (DER), the
EVM RPC TLS port, an optional private RPC path and, in a mint build, the KMS
key ARN, region, seed id and expected EVM address. Every build keeps these
values and any endpoint-derived digest outside the image. SPV and no-SPV members with the same role, release
and build profile can use the same EIF with different endpoints. Image PCR
reproduction and comparison do not require endpoint information. A mint image
also carries `KMS_ALLOWED_ACCOUNT_IDS`, so members can share one mint image only
if this list has the AWS account of the key of each member.
A Production policy separately commits the endpoint and KMS fields listed in
Sec 4 in attestation `user_data`; the Development policy does not.
Endpoint approval is external deployment configuration, not an approval
signature checked by the enclave. In no-SPV / IndexerTrusted mode a host can
choose a different well-formed TLS endpoint at launch, and the Development
attestation does not reveal or approve that choice. TLS authenticates that
selected endpoint; it does not establish that the operator approved it.
The burn signer requires the indexer URL; without SPV, it queries the indexer
for confirmations.
The enclave refuses a second set; changing launch values needs a restart,
which clears the in-memory keys. Mint recovers its saved KMS identity; burn
recovery requires a live approved donor with matching PCRs and policy. Changing
an attested host or CA can therefore prevent cloning from an old-policy donor,
even when the image PCRs are unchanged. Until the set, the
enclave refuses `Sign`,
`SignBtc`, `SignRightsRefill`, `SignRawDigest`, `SignCcd`,
`GetAttestedPublicKey`, `GetClone`, `SetClone` and, on the mint signer,
`InitializeKey`. It starts no Electrum or
EVM RPC forwarder and opens no chain connection, and `Health` reports not
ready. A refused set leaves the enclave
unset, so a retry works.

With an Electrum URL `ssl://host:port` the forwarder listens on that port and
pins `host` to loopback in `/etc/hosts`, so TLS terminates inside the enclave
against the real certificate. An `https://host[:port]` URL selects Esplora
instead, with the same forwarder and pin. Dev uses it on the custom signet.
The plaintext forms `tcp://` and
`http://` let the host read and change every answer; only a test, debug,
`mock-attestation` or `allow-seed-import` build accepts them. A release image
refuses them in `SetEndpoints`.

Each loopback forwarder of a TLS endpoint (an `ssl://` or `https://` indexer,
the EVM RPC, KMS) sends on only a connection that starts with a TLS handshake
record (`enclave/src/egress.rs`). The enclave has no other network path, so no
client can send plaintext to the host for such an endpoint, not even after an
HTTPS -> HTTP redirect. The EVM RPC client (`reqwest`) disables redirects.
`esplora-client` (`minreq`) can follow redirects; a redirect to a port with no
forwarder, or to another host, has no route out.
The parent -> enclave channel (vsock port 5000) is a separate inbound listener
and is not affected. The EVM RPC forwarder listens on the
EVM RPC TLS port, and the client connects to `https://<host>:<port><path>`
through it. TLS ends inside the enclave, which trusts only the configured CA
in every build. The host runs `vsock-proxy 8002 <EVM_RPC_HOST> <EVM_RPC_TLS_PORT>`.
An empty wire `evm_rpc_path` uses `/`. The CLI reads a nonempty private path from
`EVM_RPC_PATH_FILE`; a supplied empty file is rejected. Both parsers require an
absolute ASCII path of at most 2048 bytes. They reject authorities, queries,
fragments, percent escapes and dot segments without echoing the value. Only
ASCII letters, digits and `/-._~` are accepted. RPC transport errors and endpoint
debug output omit the path. The dev images use
`RUST_LOG=debug,alloy_transport_http=off` to disable Alloy HTTP logs, which can
include the full URL and provider responses. Custom debug or trace filters
must keep `alloy_transport_http=off`. The client does not override the log filter.
Builds without `rgb-validation` reject a nonempty path.

A provider key in the path is runtime-only. Neither attestation policy nor KMS
context includes it, so rotating it on restart does not change image PCRs,
public policy or the recovery context. The attested host/CA in Production
covers accepted paths at that endpoint, not a particular provider account.
No-SPV Development commits no endpoint fields.

**Connection limits:** 4 worker threads and a queue of 16 connections.
Each socket read or write has a 10-second idle timeout. A 90-second socket
deadline starts when the connection is accepted, including time in the queue.
Each connection carries one request. The workers and the queue are compile-time
constants. The operator can change the two timeouts (`docs/runtime-limits.md`).

The socket deadline does not cancel validation or network work inside a
handler. KMS initialization checks the shared deadline before it activates
keys. Other handlers can continue work after the response deadline.

Diagrams: [components](diagrams/01-components.md) |
[deployment](diagrams/02-deployment.md).

## 4. Security policy

The enclave resolves a security policy once, when the endpoints are set at
launch, and commits it alongside
the public-key bundle. This policy covers the fields below, not all configuration.

```
SecurityPolicy = Production {
    chain_id, bridge_contract, rgb_asset_id,   -- operator pins
    bitcoin_network,                           -- BITCOIN_NETWORK
    funds_in_contract, token_contract,         -- deposit and burnId pins
    evm_finality_tag: Latest | Safe | Finalized, -- required receipt head
    spv_min_confirmations,                     -- Bitcoin witness depth
    allow_vanilla_psbt,                        -- plain-BTC signing on/off
    signer_role: Mint | Burn | Combined,
    attestation: Real,                         -- always, in production
    evm_source:  Disabled | RawRpc | PinnedTlsRpc,
    electrum_host, evm_rpc_tls, gas_tx_rule,
    btc_source:  SpvVerified,                  -- always, in production
    kms,                                       -- KMS pin, mint signer only
    clone_peer_pcr3,                           -- own PCR3, cloning roles only
} | Development { reason }
```

- **Resolution** (`policy.rs`): `mock-attestation`, `allow-seed-import`, a
  debug/test build, a build without `spv`, a non-bridge
  build, or a missing pin resolves to `Development`. Only a release
  `spv` build with `EVM_CHAIN_ID`, `EVM_PROXY_CONTRACT_ADDRESS`, and
  `RGB_ASSET_ID` all set resolves to `Production`. `evm_source` is
  `Disabled` without `rgb-validation`. Otherwise it is `PinnedTlsRpc` with the host
  and the CA SHA-256 of the launch set. The verifier pins both.
- **Boot gate:** a release `spv` build that does not resolve to a
  valid `Production` policy MUST refuse to boot (panic). The FundsIn contract
  and `TOKEN_CONTRACT` must be non-zero, and `BTC_RELAY_MODE` must be `required`.
  A mainnet EVM chain (`EVM_CHAIN_ID` 1 or 42161) requires
  `BITCOIN_NETWORK=bitcoin`.
  `EVM_FINALITY_TAG` accepts exactly `latest`, `safe`, or `finalized` (default
  `finalized`); an invalid value rejects startup, and a production policy refuses
  `latest`.
  `SetEndpoints` runs the gate again with the endpoints and refuses the set on
  an error: `RawRpc`, and `PinnedTlsRpc` without a valid host and CA.
  Independently, each
  dev feature is a `compile_error!` in any shipped release binary (non-test
  build with debug assertions off); `rgb-validation` without `spv` requires
  a mint/burn role, real attestation, `BITCOIN_NETWORK=signet` and
  `BTC_RELAY_MODE=none`. Such a build boots and signs on
  `Development { IndexerTrusted }`, and on no other policy. The gas rule and
  `SPV_MIN_CONFIRMATIONS` are measured there, not attested. Its Development
  policy does not commit launch fields. Both profiles validate runtime endpoint
  syntax and enforce TLS in release; neither embeds endpoint settings or their
  digest in the EIF. Operators approve launch endpoints and KMS inputs
  separately. The enclave does not verify an operator signature on those inputs.
  A build fails with both signer roles or with neither.
- **Attestation:** `user_data = sha256(canonical_pubkey_bundle ||
  policy_commitment)`. The commitment encoding is versioned and shared
  (`attestation-verify/src/policy.rs`), so the enclave and every verifier
  produce identical bytes. Version 1 commits to the selected EVM finality tag
  (`evm_finality_tag`) and the Bitcoin witness depth (`spv_min_confirmations`).
  Receipt verification requires coverage by that head and canonical block-hash
  matching. Use the EIF and verifiers from the same release with approved PCRs. See
  [`pubkey-attestation.md`](pubkey-attestation.md).
- **Verification:** `attest-verify` reconstructs the *expected* policy
  (`--expect-signer-role mint|burn|combined`, `--expect-vanilla-psbt`,
  `--expect-evm-source tls|raw|disabled`, `--expect-electrum-host`,
  `--expect-evm-rpc-host`,
  `--expect-evm-rpc-ca-sha256`,
  `--expect-funds-in-contract`, `--expect-evm-finality-tag`,
  `--expect-spv-min-confirmations`, `--expect-bitcoin-network`, and the
  gas-rule flags) and
  fails if the commitment differs -- a downgraded posture (vanilla signing on,
  a different EVM source, a dev build) fails verification instead of being
  silently trusted.
  `--expect-evm-finality-tag` is required for production verification.

Provider approval is a deployment responsibility. For `PinnedTlsRpc`, supply
`--expect-evm-source tls` and the RPC hostname and CA SHA-256 from an
independently approved configuration. Copying expected values from the
deployment being verified does not establish approval. Attestation confirms
the configured endpoint identity; it does not prove that the provider is
honest or that its data is genuine.

Inside the commitment: the whole gas-tx rule -- `GAS_TX_ALLOWED_TO`,
`GAS_TX_MAX_GAS_LIMIT`, `GAS_TX_MAX_FEE_PER_GAS`, `GAS_TX_MAX_VALUE_WEI`, and
`GAS_TX_ALLOWED_SELECTORS` -- so a verifier confirms the `SignRawDigest` policy
instead of trusting the operator's configuration. An unset pin commits as its zero value, which is the posture it enforces, so
"unpinned" is attested too.

Also inside: `BITCOIN_NETWORK` (`bitcoin_network`).

Not inside the policy commitment: the Electrum/Esplora URL
scheme and port, the EVM RPC TLS port, request-size caps, and the concrete
`BTC_MAX_TOTAL_SATS` and `BTC_MAX_UNOWNED_SATS` values
(only the `BTC_MAX_TOTAL_SATS` on/off boolean is attested), and the mint
signer's `MINT_WITNESS_SAT`.

The scheme needs no commitment: a release image accepts only TLS
(`ssl://` or `https://`) for the Electrum/Esplora URL, so the rule is in the
code and PCR0 measures it (F05-RR-AF-24). The ports are not committed, and
matching policies do not prove compliance with a specific port requirement. EVM RPC still requires TLS with the pinned host
and CA on every accepted port. Bitcoin SPV checks for RGB-source requests
still apply.

Image-baked configuration is still covered by image measurement; runtime
configuration is not automatically added to the policy commitment. The plain-BTC *destination* rule needs no
commitment: it is not configuration but a property the enclave derives from its
own keys.

## 5. Key management

- Burn signer: keys are **generated inside the enclave** from OS entropy
  (BIP-39 mnemonic -> BIP-32 seed). Mint signer: the 64-byte seed comes from
  KMS `GenerateDataKey` through recipient attestation
  ([KMS seed persistence](kms-persistence.md)). The seed lives in a
  `SecretBox`. The enclave MUST NOT export it in plaintext. KMS also handles
  the mint seed during generation and decryption. Intermediate buffers
  are zeroized; the BIP-86 account xprivs are wiped on drop.
- Derivation paths:
  - EVM bridge key (authorization): `m/44'/60'/0'/0/0`;
    `evm_address = keccak256(uncompressed_pub[1..])[12..]`.
  - EVM gas-tx key (outer tx signing, `SignRawDigest`): `m/44'/60'/0'/0/1`.
  - BTC BIP-84 key: `m/84'/0'/0'/0/0`. Only its public key is published; the
    enclave signs nothing with it.
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

**Signing requires `Active`.** This phase is terminal. The process cannot
rotate or replace keys after activation. KMS builds add an `Initializing`
phase to the three phases used by other builds.

| Phase     | Holds                                    | Signing | Entry                                            |
|-----------|------------------------------------------|---------|--------------------------------------------------|
| `Initial` | nothing                                  | no      | boot                                             |
| `Initializing` | KMS initialization reservation | no | `initialize_from_persistence_until` (mint only) |
| `Cloning` | ephemeral X25519 + target cluster pubkey + pending secret in `SecretBox` | no | `enter_cloning` (requester) |
| `Active`  | `KeyManager` (seed in `SecretBox`)       | yes     | `initialize_from_entropy`, `initialize_from_persistence` (mint), or `complete_cloning` |

Initialization from `Active` or `Cloning` fails with `AlreadyInitialized`.
A concurrent KMS initialization fails with `NotReady`. Failed KMS recovery
returns to `Initial`. A new clone request can replace an expired `Cloning`
session.

Start a new enclave process to upgrade the image. Approve its measurements
before use. Mint signers can recover the existing seed through KMS when the
KMS policy permits the new image. Peer cloning requires matching PCRs.
Mnemonic and seed import require `allow-seed-import`, which release builds reject.

[Phase state machine](diagrams/09-state-phase.md)

## 7. Protocol flows

All bridge signing goes through one `Sign` request carrying a source network
(EVM, RGB, or CCD) and a destination network (EVM or RGB). Accepted routes are
RGB -> EVM, EVM -> RGB, and CCD -> EVM; any other pair is refused. Plain-BTC
signing is a separate `SignBtc` request (Sec 7.3), Concordium hash signing a
separate `SignCcd` (Sec 7.9).

### 7.1 RGB burn -> EVM unlock (`fundsOut`)

For an RGB source, `fundsOut` signing runs the checks in Sec 9:
validated consignment, anchors confirmed by SPV (by the indexer on a no-SPV
build, Sec 8), canonical calldata, pinned
chain/contract, amount coverage, a deadline at most 1 day ahead. On the
LayerZero route also: `minAmountLD` in `(0, amount]`, and `extraOptions`
empty or one gas-only executor `lzReceive` option.

The calldata MUST lead with one of two selectors: the pools `fundsOut`
(`0x340276aa`) or `lzFundsOut` (LayerZero release). The enclave decodes it
canonically (re-encoding must byte-equal the input) and signs a typed digest
over the **decoded** fields, never over opaque bytes: `EIP-712( TeeFundsOut(
recipient, amount, ...) )` for the pools route, `EIP-712( TeeLzFundsOut(...) )`
for the LayerZero route, over domain `("MultisigProxy", "1", chainId,
verifyingContract)`. On the LayerZero route the request's `lz_release`
(`dst_eid`, `min_amount_ld`, `recipient`) MUST match the decoded calldata. The
calldata `destinationChainId` MUST equal the pinned `EVM_CHAIN_ID` on the pools
route. On the LayerZero route, it MUST differ from that pin and be non-zero.
Regression tests compare the domain separator and digest with stored
contract/backend fixtures. These tests do not inspect the deployed contract.
The response returns the calldata unchanged.

**Settlement bind.** `settlementData` is
`abi.encode(bytes32[] operationIds)`, the deposits the release settles. Each
id hashes its deposit's netAmount, so no amounts are cited. For each mint in
the burn's ancestry, the enclave derives the `operationId` of the one deposit
that can back it (burn-flow B2.4). It reads nothing from the chain. It then
requires the cited ids to equal those derived locks exactly: set equality, canonical encoding,
strictly ascending `operationId` order (so no duplicates), and at least one
verified lock. `burnId` does not hash `settlementData`, so these rules decide
what backs a release, not its replay key (F05-NEW-AF-04).

**Burn identity bind.** The release carries
`sourceBurnTxId`, the RGB OpId of the burn being settled, and `Bridge.fundsOut`
folds it into `burnId` under the `BURN_TYPEHASH` it shares with
`rebalanceLiquidity` (`bridge, chainId, token, amount, sourceChainId,
keccak(sourceAddress), sourceBurnTxId`; `settlementData`, the moving
finality `proof`, the `recipient` and
`destinationChainId` are out, so one burn cannot settle once per
destination). The
contract rejects a zero id but cannot check its meaning, so the enclave MUST:
`sourceBurnTxId` equals the OpId of the consignment's settling transition (the
same transition the amount is read from), and `sourceAddress` is empty
(`RGBVerifier` reverts otherwise; RGB has no source-address concept). Together
with the exact amount this gives one validated burn exactly one `burnId`
on both routes (Sec 9, P6).

**Source chain bind.** The Router and CommissionManager key the verifier, the
settlement module and the commission rate on the `(sourceChainId,
destinationChainId)` pair, so `sourceChainId` decides which contracts judge a
release. An RGB-sourced release (direct `fundsOut` and LayerZero `lzFundsOut`
alike) MUST carry `sourceChainId == 827166`, the bridge's RGB network id, pinned as
a compile-time constant (`RGB_CHAIN_ID`) and so measured into PCR0. The
`sourceAddress` rule above applies to both routes the same way
(`validate_rgb_source_identity`). A CCD-sourced release is not subject to it.

**`burnId` recompute.** `burnId` is also recomputed in-enclave, exactly as
`Bridge._deriveBurnIdFromFields` does, from the pinned `FUNDS_IN_CONTRACT`
(the Bridge), `EVM_CHAIN_ID` and `TOKEN_CONTRACT` plus the bound calldata
fields, and a mismatch refuses (`validate_burn_id`, both routes). The contract
derives and checks it again and reverts on a mismatch (`InvalidBurnId`); the
in-enclave check fails earlier and names the expected value.

A mint/burn enclave signs `TS_BURN` unlocks and nothing else, binding the
release to the payout target the burn transition commits to (`burnReason`).
The BFA line is a mint/burn build, where a deposit is a BFA
`mint` against a verified `FundsIn` lock. A mint/burn build is further split by
signer role: the **mint signer** compiles only the EVM -> RGB direction (mint
PSBT, `SignBtc`, `SignRightsRefill`), the **burn signer** only the RGB -> EVM direction
(`fundsOut`, gas tx). Each refuses the other direction, runs on its own seed,
and attests its role in the policy commitment (`signer_role`). Independently of the flow, the enclave
recomputes `burnId` and refuses a mismatch. On both routes it also binds
each enclave-checkable `burnId` input: `sourceBurnTxId` to the RGB OpId,
`sourceAddress` to empty, `amount` to the burned units (Sec 9, P6). It binds
`settlementData` (BFA) to the ancestry locks.

**LayerZero route.** `lzFundsOut` runs the same binds as `fundsOut`:
the exact amount (`burnedAsset == amount`), the destination,
`sourceBurnTxId == OpId`, the `settlementData` bind, and the BtcRelay proof.

**Burn destination.** `burnReason` (`GS_BURN_REASON`) is either a V0 EVM
address (left-padded) or the hash of a versioned destination record
([burn-destination.md](burn-destination.md)). For V1 the request carries the
record (`EvmDestination.burn_destination`). The enclave hashes it, compares the
hash with the burn, and then requires the calldata `destinationChainId`,
`dstEid` (LayerZero) and `recipient` to equal the record. A V0 burn names no
chain, so it is released on the direct route only. `min_amount_ld` is checked
against the request only.

[Sign EVM](diagrams/03-seq-sign-evm.md)

### 7.2 EVM lock -> RGB (bridge PSBT)

A bridge PSBT request MUST carry the EVM deposit tx hash. The mint signer
reads the mint from the fascia of the PSBT's tx (`RgbDestination.fascia`, 9)
and needs the parent fascia (`parent_fascia`, 10). It reads no consignment.
Listener-supplied
`event_valid` / `event_finalized` booleans are ignored. The
enclave checks the deposit against the approved provider's receipt, blocks
and selected finality head, subject to the trust assumption in Sec 2. These checks fail closed
(`events::verify_funds_in_event`):

- a **successful receipt** must exist for `evm_tx_hash`;
- its block number MUST be at or below
  `eth_getBlockByNumber(EVM_FINALITY_TAG, false).number`. The receipt's
  `blockHash` MUST match the canonical block fetched at that height. The
  selected head snapshot is revalidated to detect a reorg during verification;
- it must carry exactly **one** `BridgeFundsIn` event from the pinned
  `FUNDS_IN_CONTRACT` (falls back to `EVM_PROXY_CONTRACT_ADDRESS`) whose
  `operationId` (topic 1) is the request's. Zero or two such events refuse.
  Other deposits in the tx are ignored. There is no fallback to the plain
  `FundsIn` event: it carries an RGB lockId, a different id space;
- the event MUST bind the on-chain `operationId` (the full 32-byte word,
  indexed topic 1) to the request's 32-byte `funds_in_operation_id` -- not
  `RgbDestination.operation_idx`, which the enclave does not read -- plus the
  gross `amount` and `tokenCommission`;
  `netAmount` MUST NOT exceed `gross - commission` (a lower value is accepted
  with a warning for fee-on-transfer tokens);
- when the event's `destinationAddress` string is not empty, it is the
  depositor's RGB invoice. The enclave parses it (`rgb-invoicing`), accepts
  only a blinded-seal beneficiary, and requires the single confidential
  recipient leg to equal that seal. Zero or two confidential legs refuse.
  The v2 Bridge sends an empty `destinationAddress` for RGB.
  Then the recipient is bound through the mint's lockId: the `FundsIn`
  `lockId` must be `LockId(opid, txid)` of the mint transition being signed
  and the PSBT's tx (Sec 8). The transition commits to its seals, and the tx
  to the script on a witness seal's output. A witness mint has no
  confidential leg, so a deposit with an invoice refuses it.

**Mint signer.** The mint signer validates no consignment.
rgb-lib (pin: rgb-lib-bfa 5010eefa, RGB-Tools bfa 66bae096)
strips the RGB, MPC, OPRET and TAPRET proprietary keys from
the PSBT it returns and keeps the tx, its bundles and the MPC entropy in the
tx's strict-encoded fascia. The enclave decodes that fascia as rgb-lib reads
it, checks it as rgb-lib's `inspect_rgb_transfer` does without the wallet
checks and with its own opret proof in place of the fascia's DBC proof, reads
no RGB key of the PSBT, and proves that the txid commits exactly
one transition
of the pinned contract ([mint-flow.md](mint-flow.md) Stage 3): every input a
native SegWit output with `SIGHASH_ALL` / taproot `DEFAULT` only (F2); the
first `OP_RETURN` or P2TR output an `OP_RETURN` (F3), so consensus reads the
opret commitment the enclave checks; a fascia of that txid with exactly one
bundle, of the pinned contract (F4); the MPC tree rebuilt from every fascia
bundle and the fascia's entropy matches that commitment (F5), so no bundle
hides and none is added or swapped; one disclosed
transition whose id is recomputed and whose inputs are exactly the input map
(F6); one Colored key-path input (F7). The transition must be one `TS_MINT`
that consumes one `mintRight`, assigns asset units only, carries exactly
`issuedSupply` (> 0) and `beforeBlock` as 8-byte little-endian values, pays
`issuedSupply` to one seal, blinded or a witness seal on an output of its own
tx, and issues exactly `amount - commission` (M1 - M5, M7). The deposit must
name this mint's lockId, `LockId(opid, txid)` of the PSBT's tx, and carry the
deposit id it derives (M6). After the lock the mint tx must never change (no
RBF, rebuild or batching): another txid names another lock. Its fee stays the
one `mint_begin` set, and the only fee bump left is a CPFP child that spends an
output of the mint tx. None is implemented, so an operator must plan for it to
confirm at its original fee. rgb-lib puts the mint's change on the Colored
account (M8 would also take Vanilla), and `SignBtc` never signs a Colored input,
so on a mint rgb-lib built the one enclave path that could fund a child is a
`SignRightsRefill` whose fee input spends that change. A witness mint's user
output is the seal holding the units: a child of it must close that seal or it
destroys them (mint-flow section 1). A
blinded mint pays no sat out of the enclave's outputs. A witness mint pays exactly
`MINT_WITNESS_SAT` (image env, default 1500, 546 to 10 000) to its seal's
output, which must not be the enclave's, and no sat elsewhere (M8).

The parent fascia, of the tx that made the spent right, passes the same core
on the tx it carries and must show a `TS_PROPAGATE` of one right that put
that right alone on a witness seal of its own tx; the PSBT must spend that
output (PP1 - PP7). This pins the one
UTXO every signature for the mint spends, so replays conflict and no other
state of ours is spent. The enclave checks no history, genesis, ancestor
anchor, reject list or witness depth: a bad history makes the mint invalid
for every receiver, so each is liveness only. The rights refill
(`SignRightsRefill`) uses the same core and parent proof
([mint-flow.md](mint-flow.md) section 8), with its own fascia in
`SignRightsRefillRequest.fascia` (6) and the parent's in `parent_fascia` (7).
Accepted residual: a host that pays
for a junk parent tx can make a refill destroy one right on its fee input, at
most 12 per enclave hour; it cannot take a right.

The destination amount the route check uses is `mint.issued` from the fascia,
not the wire `psbt_output_amount`.

**Fee policy.** A pinned fee policy, shared with the
plain-BTC `SignBtc` path, rejects a PSBT whose miner fee exceeds a compile-time
maximum fee rate (over the unsigned size, which the host cannot pad) or a
compile-time maximum absolute fee, and one that does not fund 1 sat/vB over its
estimated signed size. The enclave fetches no fee estimate: a dynamic bound
could strand a mint whose EVM lock already settled when the fee market moved,
so the operational fee check belongs to the bridge, before the lock. Raising a
ceiling ships a new enclave image, so it needs federation agreement.

**EVM data source:** a build without `rgb-validation` refuses bridge PSBTs outright.
Deposits above the selected head refuse signing and can be retried once that
head covers them. A missing, malformed or unsupported tag response refuses signing.
With `PinnedTlsRpc`, TLS ends inside the enclave and authenticates the pinned
host against the configured CA. The host can withhold a response, but cannot
alter it without detection. The endpoint remains trusted for receipt, block
and head correctness: the checks above cannot reject a self-consistent false
history solely because the approved provider invented it (Sec 2). The source, hostname
and CA SHA-256 are committed into the attested policy (Sec 4).

An in-memory replay cache (by default a 1-hour TTL and a 100,000-entry cap) checks requests keyed by
`(chain_id, bridge_contract, evm_tx_hash, funds_in_operation_id, rgb_asset_id)`
and is committed only after the enclave writes the response; a failed write
releases it. A successful write does not prove receipt by the caller. A lost
response can therefore leave a committed entry. The parent keeps the reply of
an EVM -> RGB sign for an hour and answers a retry of the same request itself
(parent `signed_responses`). An identical retry still reaches the enclave, and
is refused, when the parent has no reply for it: the parent did not read the
reply, the reply was above `SIGNED_RESPONSE_MAX_BYTES`, the parent dropped it
at `SIGNED_RESPONSE_MAX_ENTRIES` or `SIGNED_RESPONSE_MAX_BYTES`, or the parent
restarted. The cache is not durable or shared across replicas. Capacity pressure
removes the oldest entries.
Bitcoin prevents a double spend of the same UTXO. The cache does not prevent
another PSBT for the deposit after restart, expiry, eviction, or on another enclave.

**Bitcoin value.** Every bind above is denominated in RGB asset units, so a
witness transaction can satisfy the RGB ledger exactly and still route the
bridge's Bitcoin backing to an attacker output that carries no RGB assignment.
The fee-rate cap does not catch it -- a diverted sat is an output, not a fee, so
diversion *lowers* the implied rate. A mint PSBT is therefore held to M8: a blinded mint
pays no sat out, a witness mint exactly `MINT_WITNESS_SAT` to its seal's output.
Signing is scoped to the **colored** BIP-86
account, key-path spends only: the bridge wallet is singlesig, and a script-path
input is never signed.

[Sign PSBT](diagrams/04-seq-sign-psbt.md)

### 7.3 Plain-BTC PSBT (`SignBtc`)

Vanilla (non-bridge) BTC signing is its own request; a `Sign` request without
bridge fields does not reach it. It is gated by the attested policy
(`allow_vanilla_psbt`, default **off**), and each request must satisfy the
authorization rules: every output must pay back into the custody its inputs were
already in, except a budget of `BTC_MAX_UNOWNED_SATS` for those that do not,
total input value <= `BTC_MAX_TOTAL_SATS`, and the miner fee within the pinned
fee policy of Sec 7.2 (compile-time maximum fee rate and absolute fee, 1 sat/vB
relay floor; needs no configuration, so it holds in every build). Self-owned
outputs, the value cap and the fee policy each bound **one** transaction: the
fee policy caps what a single request can burn as miner fees, not what a host
can burn across many requests. The enclave does not rate-limit `SignBtc`, so a
compromised host can still burn up to the per-transaction fee cap of every UTXO
it submits; the aggregate bound belongs out-of-enclave (host rate limiting,
`BTC_MAX_TOTAL_SATS` sizing). The fee floor also needs every input to be
sizeable (see Sec 7.2): an input the size estimator cannot classify refuses the
whole request. Signing is scoped to the **vanilla** BIP-86 account only -- it
can structurally never sign a colored (RGB-allocated) input.

The enclave derives output ownership from its keys. There is no configured
list of allowed scripts. An output is exempt from the unowned-sats budget in
either of these cases:

- Its script matches an input that the enclave can sign. The enclave checks
  the fingerprint, BIP-86 key derivation, and Taproot tweak. A script tree can
  contain foreign spend paths. For such inputs, the exemption is limited to
  the input value on that script.
- Its script is a BIP-86 output from an enclave account, with no script tree,
  at a wallet child path `[k, i]`, both steps non-hardened, `k` = 0 on Colored,
  0 or 1 on Vanilla. The enclave derives the key and reconstructs the output
  script. An enclave key at any other path counts as unowned.

Other outputs must fit the configured unowned-sats budget. An enclave key in
one Taproot leaf does not prove control of the whole output.

### 7.4 Gas transaction (`SignRawDigest`)

The enclave does not sign an opaque digest. The request MUST carry the
unsigned transaction preimage; the enclave strictly RLP-decodes it (EIP-1559 or
legacy EIP-155), requires `chain_id` == pinned `EVM_CHAIN_ID`, `to` == pinned
`GAS_TX_ALLOWED_TO` (fail-closed when unset), `value == 0`, no contract
creation -- and computes the digest itself. The preimage is at most 1 MiB
(`max_gas_tx_bytes`). It decodes to at most 1024 RLP items (`max_rlp_items`)
with a nesting depth of at most 8. So the input bounds the decoder's heap.

Two further bounds, each fail-closed when unset:

- **Fee/gas ceilings.** `gasLimit` <= `GAS_TX_MAX_GAS_LIMIT`, and the per-gas
  fee fields (`maxFeePerGas` / `maxPriorityFeePerGas`, or legacy `gasPrice`) <=
  `GAS_TX_MAX_FEE_PER_GAS`. Together they bound the most ETH a *single* signed
  gas tx can burn as fees.
- **Calldata selector allowlist.** The calldata MUST lead with a 4-byte selector
  in `GAS_TX_ALLOWED_SELECTORS`; empty calldata is refused, because a bare call
  still invokes the destination's `fallback`/`receive`. This is an in-enclave,
  attested control; it does not assume that the pinned `to` is an EOA whose
  calldata is inert.

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

The limits apply to each transaction, not to total spending. A compromised
listener can request many transactions within those limits and exhaust the
gas account. The enclave does not establish who receives priority fees or
other permitted payments. Aggregate limits need controls outside this signer.

The LayerZero fee is not a field of `TeeLzFundsOut`. The gas transaction is
not linked to a previously checked release. The configured value ceiling
limits the payment but does not establish that link.

### 7.5 Raw message (`SignRawMessage`)

The request asks for an EIP-191 `personal_sign` signature of caller bytes with
the main bridge key. No feature or policy could limit such a signature, so the
enclave refuses every `SignRawMessage` request, in every build. The proto keeps
the variant, so the request decodes and gets a refusal.

### 7.6 SPV header sync

The host feeds Bitcoin headers (`SubmitHeaders`, `spv` builds only); the
enclave maintains its own header chain. Mainnet uses PoW validation (Sec 8).
For an RGB-source release, the chain MUST cover every
consignment witness: RGB consensus counts a witness as mined only through its
SPV proof. The mint signer validates no witness: it reads its RGB data from
the rgb-lib fascia of its tx (Sec 7.2).
[SPV submit headers](diagrams/08-seq-spv-submit-headers.md)

### 7.7 Attested public key

Any external verifier can confirm the signer pubkey belongs to attested
enclave code *and* that the enclave runs the expected security posture (Sec 4).
[Attested pubkey](diagrams/05-seq-attested-pubkey.md)

### 7.8 Cloning (recovery / federation membership)

Three-message handshake, valid only between enclaves with identical PCR0/1/2,
the same PCR3 (the parent instance IAM role), the same cluster pubkey, and the
shared cloning secret (Sec 10). The donor learns
the secret at runtime (`InitializeKey.cloning_secret`, a completed clone, or
the dev-only `UTEXO_CLONING_SECRET` env), never from the image. The CLI `clone` command
drives it: `InitiateCloning` on the new enclave, the parent `Clone` RPC on the
donor, `SetClone` on the new enclave. [Cloning](diagrams/06-seq-cloning.md)

The requester retains the supplied secret in its pending session. Only after
`SetClone` verifies the donor, seed, identity, policy and transcript does it
install that session's secret and keys together. This secret replaces any
donor secret loaded at boot. A failed completion leaves both the pending session and
any existing donor secret unchanged. Session replacement or drop zeroizes the
pending secret; the expiry deadline alone does not erase it.

The activated replica can then donate to another replica using the same
operator secret, even when its original donor is unavailable. Each replica
enforces its own export cap; this is not a cluster-wide replica limit or
revocation mechanism. The cap is `CLONE_EXPORT_HARD_CAP`. Unset or zero means
no cap, and no supplied image sets it. Blocking the original donor does not revoke its clones.
Each `EnclaveState` also owns its nonce replay guard. A successful export on
one donor does not prevent another donor from accepting the same otherwise-valid
requester attestation, subject to its own export cap. Each donor refuses a
replay only while its nonce entry remains recorded; expiry or eviction can
permit another acceptance.

After SetClone, the CLI performs a bounded read-only identity check, including
when the response was lost. Automation must use the versioned
[CLI completion results](clone-cli-results.md); an error or timeout alone does
not establish whether keys were installed.

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

The only release image permitted to carry these paths is
`build/Dockerfile.enclave.ccd`, built with
`--no-default-features --features vsock,ccd`. It has no signer role. A release
build with `ccd` and `mint-signer` or `burn-signer` does not compile
(`enclave/src/lib.rs`). Without that guard, such an image would attest Mint or
Burn and also sign these requests.
`build/Dockerfile.enclave-dev.bfa` enables `ccd` with a signer role in a debug
build, which resolves to `Development` (Sec 4).

## 8. RGB / Bitcoin / SPV verification

The consignment pipeline runs on the burn path; the mint
signer runs none (Sec 7.2). Cheap checks first: non-empty payload within
`MAX_CONSIGNMENT_BYTES`, proof count and bytes within `MAX_MERKLE_PROOFS` /
`MAX_TOTAL_PROOF_BYTES`, `keccak256(consignment) == consignment_hash`
(integrity only), asset id declared; then full validation of a V1 transfer
file by one call of rgb-lib's `validate_consignment_with_resolver` (rgb-ops
0.11.2). A V1 consignment carries no schema, types or scripts: the BFA rules
come from `rgb-schemas`, and any other schema id, or a reject list that is
not an EVM contract, is refused before rgb-lib runs. So is a transfer whose
work in rgb-lib would pass one of three caps (`validation/cost.rs`, burn-flow
B2.2 and section 10): the checks of each transition against its bundle's
whole witness tx, anchor and input map, which rgb-lib runs for every BFA
before it checks any witness, and, for a listed asset, a count of its reject
walk with each origin walking alone (rgb-lib shares the walk); or
whose modeled rgb-lib time would pass 30 s (`max_rgb_lib_ms`): for
validation its file bytes, opouts, genesis hashes (every genesis global and
assignment, once per operation) and those three costs, and for the
inspection that reads the summary after it its file bytes, opouts,
operations and witness checks. The rest of rgb-lib's work is linear in the
file (Known limits). The
asset bind also runs before rgb-lib, so a foreign genesis never reaches it
and only the pinned asset's list is ever read. rgb-lib runs two phases. Phase 1 (`validate_deterministic`) checks everything that depends on
the consignment only. It leaves open each witness and each BFA mint claim
(`Claim::Lock`: the mint's OpId, its witness txid, `issuedSupply` and
`beforeBlock`). Phase 2 asks the
enclave's three resolvers, and no `safe_height` is passed: every refusal of
the resolvers is a refusal of the request, and so is any rgb-lib warning. It
resolves every witness on chain:
the transaction comes from the consignment, its status from a source the
enclave trusts, and it must be mined at least `SPV_MIN_CONFIRMATIONS` deep.
In an `spv` build that source is the request's Merkle proofs, verified against
the enclave header chain (rule 4 below) before consensus runs. A burn signer
built without `spv` uses the pinned indexer instead, through non-verbose calls
only, and the depth counts every block from the indexer's tip. That build runs
on public Signet only, and it trusts the indexer (Known limits). An unmined, unknown
or shallow witness fails consensus, so single-use seals hold: of two
conflicting transfers of the same units, only the mined one validates. A proof
the consignment carries is never used: the
resolver offers no block headers, so rgb-ops asks the resolver instead. Phase 2 also
confirms each claim only
against a lock bound to its exact `(lockId, amount)`, lockId being
`LockId(opid, witness txid)`, through rgb-lib's checked
resolver, which compares the bound chain id with the genesis `bridgeLocation`;
rgb-lib makes no RPC for a claim.
`LockId(opid, txid)` is `SHA256(t || t || opid || txid)` with
`t = SHA256("urn:lnp-bp:rgb:lock#2026-11-04")`, each id as its 32 bytes and
the txid in internal byte order. Test vector: opid bytes 0x00 to 0x1f and txid
bytes 0x20 to 0x3f give
`1ce683c92fdfb3ef54e39c7b461e731dad02cd240b366441f34a2c2e849a9876`.
The binder first requires `bridgeLocation` to name the pinned
`FUNDS_IN_CONTRACT` on `EVM_CHAIN_ID`, and binds every claim to the deposit id
its lockId derives. The mint signer binds its mint the same way from the fascia (M6):
the node must report `EVM_CHAIN_ID`, and the receipt of `evm_tx_hash` must
hold its `FundsIn` (the `lockId` word equals the 32 raw `LockId` bytes, as a
big-endian `uint256`) and the derived `BridgeFundsIn`, with
`destinationChainId == RGB_CHAIN_ID` (827166), in a block before `beforeBlock`
and covered by the `EVM_FINALITY_TAG` head, with the canonical block hash at
its height. The enclave never calls
`Consignment::validate` or the unchecked `PendingValidation::resolve_claim`;
`clippy.toml` refuses both. Last, for an asset whose genesis names a reject
list, rgb-lib checks the inputs and outputs of every terminal operation
against the list the enclave's reader returns (Known limits). rgb-lib's
validation returns no amounts or burn facts, so the enclave reads them from
the same bytes once they pass: the burn facts from the validated rgbstd
transfer, and the flat summary of every transition from rgb-lib's
`inspect_consignment` over every bundle, on the file rgb-lib just validated.
The two readings must name the same settling transition. The validated
contract id must then equal the
declared asset id and the pinned `RGB_ASSET_ID` (on the `fundsOut` path this
last leg applies once the bridge is configured; on the PSBT paths it is
unconditional). In an `spv` build the RGB-source path then checks the SPV
proofs again, with freshness, exact coverage and block pins.

For an RGB-source request, the SPV layer enforces these rules:

1. On mainnet and the testnets, validate header linkage, PoW, and `nBits`.
   The testnets apply the 20-minute minimum-difficulty rule. Testnet4 adds
   BIP94: the retarget starts from the first block of the period, and that
   block may not be more than 600 s older than its parent. On every network a
   header may be at most two hours ahead of the enclave clock (Bitcoin Core
   `time-too-new`). Without it a host could date free min-difficulty blocks
   ahead and lower its fork's difficulty 4x per period for the work of one
   block. A header must also be newer than the median time past of the eleven
   blocks below it (Bitcoin Core `time-too-old`). A chain from genesis takes
   the median of the blocks it has, as Core does. Above any other checkpoint,
   the rule starts at the eleventh block above the checkpoint, where the chain
   holds all eleven times. Without the rule the enclave accepts headers that
   Core refuses: a host could date the blocks of a fork back without bound. On
   the testnets that yields free min-difficulty blocks in bulk, each more than
   twenty minutes after its parent and all in the past.
   Accept a replacement chain only when its cumulative work is greater.
   Limit reorganization depth to `MAX_REORG_DEPTH = 100`.
2. Retain all headers above the checkpoint. Do not prune old headers.
   Reject submissions that exceed `MAX_STORED_HEADERS = 1,000,000`.
3. Accept at most 10,000 headers per call and 100,000 per fixed 60-second window.
   Count submitted headers before validation, including invalid headers.
4. Require one Merkle proof for each consignment witness transaction.
   Reject missing, extra, or duplicate proofs.
   Check inclusion against the stored header with a path of at most 32 levels.
   Require the transaction position to be consumed by the path, one bit per
   level. Refuse a path on which a hashed node is a 64-byte transaction
   (CVE-2017-12842).
   Require at least `SPV_MIN_CONFIRMATIONS` confirmations (default 3). On the
   testnets min-difficulty blocks count, for testing convenience: testnets
   carry no production value.
   Record the hash and the required depth of each block a check used. Check
   both again under the signing lock. A changed hash, or a block shallower
   than the depth its check required, refuses the signature. This is a
   signing rule, not a consensus rule. The request fails like a proof below
   `SPV_MIN_CONFIRMATIONS`, and the caller sends it again when the block is
   deep enough.
5. Reject a chain whose tip (on the testnets, min-difficulty blocks included)
   is more than two hours old or more than two hours in the future. This checks timestamps. It does not prove that the
   provider sent the network tip.
6. Require the consignment's `chain_net` to match the enclave's Bitcoin network.
   `BITCOIN_NETWORK` selects that network at boot.
   The image measurement covers the value when it is part of the image.
   The attested policy commits it.

`SPV_MIN_CONFIRMATIONS` is read from the image env at boot, so PCR0 measures
it, and a `Production` attested policy commits it. The mint and burn images bake
3. The host cannot set it: a Nitro enclave takes no env from the host, and a
value of zero or a non-number stops the boot. The other SPV thresholds above
are compile-time constants. EVM receipts always require coverage by the
selected finality head (`EVM_FINALITY_TAG`) and a matching canonical block
hash. The three request-size caps above are env-tunable because they only bound
resource use; they never relax a verification step.

**Checkpoints:** mainnet block 951,552 (retarget-aligned), testnet4 block
155,232 (retarget-aligned) and UTEXO signet block 334,000 are real pinned
checkpoints. Regtest uses genesis. The testnet4 and signet checkpoints have no
chainwork yet. So their `fundsOut` fails under `BTC_RELAY_MODE=required`,
unless a dev build sets `SPV_CHECKPOINT` with chainwork. `signetcustom` uses the signet checkpoint
with the RGB chain-network `sbc`. Local/dev builds (debug, `cfg(test)`, or
`allow-seed-import`) may move the anchor forward at boot with
`SPV_CHECKPOINT=height:block_hash:bits:time[:chainwork]` to skip a long
initial sync. `bits` and `time` are those of that block. The median-time-past
rule reads `time`, and on mainnet and the testnets the `nBits` checks read
both. A production-shaped build refuses to start if that variable is set, so
the host can never choose the trust anchor.
Testnet3 has a placeholder checkpoint -- a release build refuses to boot on any
placeholder checkpoint. **Signet caveat:** the enclave does not check PoW or
nBits on signet. It does not check the BIP-325 challenge signature either,
because the wire format carries no coinbase witness. Signet header integrity
rests on chain linkage, the clock bound, the median-time-past rule, the
reorg/work rules, the submission caps and the 2 h freshness gate.

## 9. Unlock authorization predicates

For RGB→EVM, the following table separates enforced checks from bindings
delegated to the receiving contract and known gaps. Enforced checks fail closed.

| # | Required check | Enforcement |
| --- | --- | --- |
| P1 | Valid RGB consignment | Full RGB consensus validation. |
| P2 | Expected transition | The settling transition (the one burn of the last witness bundle, else its last transition) must be `TS_BURN`. Two burns in that bundle refuse. Each ancestry mint needs a verified deposit. |
| P3 | Exact amount | `burnedAsset` must equal calldata `amount`. The host's `rgb_amount` is not evidence. |
| P4 | Valid calldata | Allowed selector, 96 KiB cap, canonical ABI encoding, and route-specific destination-chain check. |
| P5 | Correct destination | Pinned chain and contract. The payee, `destinationChainId` and LayerZero `dstEid` must match the burn destination (`burnReason`, V1 record). A V0 burn: direct route only. |
| P6 | Release identity | RGB source chain 827166, empty source address, recomputed `burnId`, matching burn OpId, and exact settlement ids. |
| P7 | Accepted Bitcoin history | With `spv` enabled, each witness must belong to the retained chain. Without `spv`, the indexer supplies the trusted chain view. |
| P8 | Inclusion and relay agreement | With `spv` enabled, Merkle inclusion, confirmation depth, tip freshness, and the BtcRelay checks below. Without `spv`, confirmation depth comes from the indexer. |
| P9 | Ancestry deposits | Derive each deposit id from its mint; no chain read. `RgbSettlementModule.beforeFundsOut` enforces that each cited deposit exists. |
| P10 | Payload matches intent | The typed digest commits to the decoded fields checked above. |
| P11 | Reject failed checks | Return an error without a signature. |

P6 applies to both release routes. `sourceBurnTxId` must equal the non-zero
OpId of the settling burn. Settlement data must contain the exact verified
`operationId`s. The list must be non-empty and canonically
encoded. Operation IDs must be strictly ascending, without duplicates.

With `spv` enabled, P8 requires a 128-byte proof with source and latest
height/commitment pairs.
The source height must hold the last consignment witness transaction.
The enclave verifies that anchor again while it holds the chain lock.
The latest height must exist in the retained chain. It must be at most
`MAX_RELAY_TIP_LAG_BLOCKS = 100` blocks below the enclave tip.

With `spv` enabled and `BTC_RELAY_MODE=required`, each commitment must match
the enclave's reconstructed BtcRelay record. The commitment is `keccak256` of the 160-byte
`StoredBlockHeader`, using cumulative work from the checkpoint. Zero commitments
are rejected. Records that need data below the checkpoint are also rejected.
Production policy permits only this mode.

With `spv` enabled and `BTC_RELAY_MODE=none`, both commitments must be zero.
The enclave still checks heights, the source anchor, and freshness. This mode
supports local systems without BtcRelay. It is not a production policy.

With `spv` disabled, the signer requires empty RGB `merkle_proofs` and an
empty release `proof`. It does not run the header, Merkle inclusion or
BtcRelay checks above.

The enclave signs `burnId` and the other decoded fields into the typed digest.
A signature is not a check of their meaning. So `sourceBurnTxId`,
`sourceAddress` and `settlementData` each have their own bind above.
`burnId` does not hash `settlementData`, so citing other deposits or another
order cannot make a new `burnId`.
"Ancestry" is every `TS_MINT` in the consignment, not only the mints that
fed the burned allocation.
End-to-end release uniqueness also depends on contract checks outside this repo
(`consumedBurnIds` and `consumedSourceBurnTxIds` of the Bridge).

[Signing gate](diagrams/10-signing-gate.md)

## 10. Attestation & federation

- **Public verifiability:** trusted Real verification binds the public-key
  bundle and policy to code with independently approved PCRs. It does not
  prove the key's original generation or exclusive custody; key-handling
  rules depend on the measured code (Sec 5). The verifier enforces: cert chain
  to the embedded AWS root with `BasicConstraints`, `keyCertSign`, path-length,
  and leaf `digitalSignature` checks; COSE `alg == ES384` with the
  raw 96-byte signature form only; PCR0/1/2 equality; nonce equality;
  and the `user_data` commitment over pubkey bundle + security policy (Sec 4).
- **PCR policy:** verifiers assert PCR0/1/2. Clone peers also assert PCR3.
- **Cloning** is valid only between enclaves that target the same cluster
  pubkey, run the same code (PCR0/1/2 equality), run under the same parent
  instance IAM role (PCR3 equality), and share the cloning secret, with mutual
  attestation. PCR0/1/2 are the same for each instance of the published image,
  in any AWS account; PCR3 binds the peer to the operator's role. Each
  side compares the peer's PCR3 with its own (`GetClone` and `SetClone`) and
  refuses a missing or different PCR3, and refuses to clone at all when its own
  PCR3 is all zero (no IAM role). A Production policy for a role that clones
  (burn, combined) commits its PCR3 (`clone_peer_pcr3`) and refuses
  `SetEndpoints` when it is all zero. The handshake enforces nonzero, matching
  PCR3 regardless of policy. Recovery onto an instance with another role
  fails by design. The mint signer does not clone and does not read PCR3. The DH exchange rejects small-order points; the seed
  ciphertext is bound to both handshake keys via HKDF; replay-guard nonces are
  recorded only **after** authentication succeeds, and the guard
  is TTL-bounded (1 h) with oldest-first eviction so it cannot be wedged.
  By design: authorization rests on the operator's cluster-wide secret
  delivered at runtime (not in PCRs), and the master seed stays resident so
  the donor can re-seal it per clone. Every completed clone retains the secret
  and can become a donor; blocking the original donor does not revoke its
  descendants. These properties are accepted; no change planned.
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
- EVM deposit checks use the selected provider's receipt, canonical block and
  selected finality head. `PinnedTlsRpc` retains trust in the approved provider's
  data (Sec 2); CCD source validity is delegated to the listener.
- Plain-BTC and bridge PSBTs sign only vanilla and colored accounts respectively.
  The plain-BTC unowned budget permits bounded outputs outside proved custody
  scripts.
- Cloning transfers an encrypted seed between enclaves with matching
  PCR0/1/2 and PCR3 (same image, same IAM role). Clones share one signing
  identity; they are not independent quorum members.

## 12. Failure conditions

On any of the following the enclave MUST return an error and MUST NOT sign:
invalid consignment; unsupported or unclassified transition; amount not
covered; malformed or non-canonical calldata; unpinned or mismatched
chain/contract/asset; invalid or missing SPV proof; stale, future-dated, or
incomplete header chain; cross-network consignment; missing/failed/unconfirmed
`FundsIn` verification; unavailable finality head or mismatched receipt block hash;
`operationId` mismatch; fee over the pinned fee rate or
absolute maximum, or under the relay floor (both PSBT paths); PSBT not
committing exactly one mint or
refill of the asset, or without its rgb-lib fascia or a parent fascia that
pins the spent right (mint signer); disallowed output script or value cap exceeded
(plain BTC); non-allowlisted gas tx; wrong phase; expired deadline; duplicate bridge operation within the local cache window; oversized frame, field, or header batch.

## 13. Implementation status

The production images are the mint signer (`Dockerfile.enclave.mint`) and the
burn signer (`Dockerfile.enclave.burn`). The tree also has a CCD build. The default feature set is `ccd`. A build choice is not evidence of the deployed image.
`Dockerfile.enclave.ccd` sets no EVM pins, so its release image refuses every
EVM signature and every plain-BTC PSBT. CI does not build or publish it.

Known limits. Read them before deployment.

- **Stuck burns.** A V1 burn whose record is lost, or whose route is later
  disabled, cannot be released. A refund path is planned for record V2.
- **Release replay.** The burn signer keeps no release state. Replay
  protection is the `MultisigProxy` nonce and the Bridge `burnId` check. The
  enclave refuses an EIP-712 deadline more than 1 day after signing.
- **Settlement ancestry.** `settlementData` must cite every `TS_MINT` in the
  consignment, not only the mints that fed the burned units.
- **Release route invariant.** The Bridge release route for source chain
  827166 must use `RgbSettlementModule`. Only its `beforeFundsOut` checks that
  each derived ancestry deposit exists.
- **History on the mint path.** The mint signer reads the mint from the fascia
  and validates no history: no consensus, genesis, `bridgeLocation`, ancestor
  anchor, witness depth or reject list. A host that controls the bridge can
  make a mint no receiving wallet accepts, after the user locked. It cannot
  mint unbacked units, and the parent proof keeps it from spending any other
  state of ours. The mint wallet must hold no right whose parent is a mint or
  the genesis.
- **Refill fee input.** A host that pays for a junk parent tx can make a
  refill destroy one right on its fee input, at most 12 per enclave hour (a
  restart resets the count). It cannot take a right. Accepted until rgb-lib
  can take a refill's fee from the vanilla key.
- **Reject list.** A genesis may name an `IRgbRejectList` contract on
  `EVM_CHAIN_ID`. The burn signer reads it over the pinned EVM RPC, with the
  rules of rgb-lib-bfa 5010eefa (RGB-Tools bfa 66bae096): a pending reject
  counts at once, an allow only once
  `finalized`. rgb-lib then refuses a release when an input or output of a
  terminal operation descends from a rejected opout: the burn's inputs, and
  also a companion transfer in the burn's bundle, so a rejected line there
  refuses a burn whose own units are clean. The change on rgb-lib's split is
  not checked: the burn spends the split. The mint signer reads no list: the connector's rgb-lib
  checks it before `mint_begin`. Any read failure
  refuses, so the burn signer depends on the EVM RPC for such an asset.
  The reads are `eth_call` answers over TLS. The enclave has no EVM light
  client, so it cannot check them against a block hash: the pinned RPC is
  trusted for the list contents, as the trust table states. A provider that
  hides a reject entry lets a rejected lineage release. A provider that
  invents entries or fails refuses releases. A
  rejected release stays refused until an allow is finalized, and its units
  are already burned. The list appender can halt every release; the owner
  rotates it. The list is read in full on each request, at most
  `max_reject_list_entries` entries, by default 20,000 (about 25 RPC calls). The
  list is append-only, so a list over that value refuses every release until the
  operator raises it. The read also stops before the request
  deadline; a list the RPC cannot serve in time refuses every request of the
  asset with "exceeded the request budget".
- **Linear work in rgb-lib.** The witness and bundle id caps bound only the
  parts of rgb-lib's work that grow faster than the file; the walk cap bounds a
  per-origin count of a walk that is linear on this pin (burn-flow section
  10). The rest is
  bounded by `MAX_CONSIGNMENT_BYTES` and the time budget. Measured on rgb-lib
  1ae1c160, not on this pin, validation costs
  about 1.1 us per byte plus 35 to 55 us per opout on an M1 Pro, plus 13.7 us
  per genesis global or assignment for each operation (rgb-consensus hashes
  the whole genesis once per operation). The inspection that reads the
  summary once validation passed costs about as much again per opout: about
  0.5 us per byte, 46 to 60 us per opout and up to about 130 us per
  operation. So a file alone models at 1.75 us per byte, and the budget
  refuses any file past about 17 MB, above the 10 MiB limit. On the
  pinned asset's genesis of 10 mint rights an honest 2810-mint burn takes
  2.7 to 2.8 s to validate and 1.9 to 2.2 s to inspect, 5.0 to 6.3 s end to
  end; with 3 transfers a line it takes 15.9 to 16.2 s end to end and models
  at 17.9 s. A history of 10,000 transfers with an SPV proof on each models at
  19.95 s. The budget refuses a history past about 10 MB of plain transfers,
  about the size limit. The
  genesis part depends on the
  pinned asset: on a genesis of 255 mint rights an operation costs rgb-lib
  3.6 ms, so the budget admits about 5,900 operations; the 2810-mint burn
  there models at 16.5 s and takes 15.3 to 16.2 s end to end. A forged
  chain of propagates, 14 bytes an opout, at the size cap took 44 s to
  validate and 51 s to inspect: the budget counts its opouts and refuses it.
  The caps' parts add up with it, so `max_rgb_lib_ms` holds the modeled sum
  to 30 s, against a 90 s deadline that does not stop a worker (4 workers).
  `docs/runtime-limits.md` has the times measured on a real enclave.
  The budget is rgb-lib's alone: the enclave's own parse, gate and reads of
  the validated transfer take the rest of the deadline, 1.1 to 1.6 s more end
  to end on the 2810-mint burn with 3 transfers a line (2.3 s at a load of 5.6).
  The model's rates are rounded-up Mac timings, not a proof: their margin is
  about the spread between runs (8 percent on the honest 2810-mint burn's
  inspection, the closest), and a shape slower per byte, per opout, per
  operation or per genesis leaf would run past it. The enclave CPU may be
  slower. rgb-lib reads a consignment only from a path, so the request bytes
  are written to a scratch file in the enclave's temp dir, which is RAM, up
  to `MAX_CONSIGNMENT_BYTES` per request, and removed once rgb-lib
  validated and inspected it, or refused it.
- **Mint replay.** The EVM -> RGB cache is per enclave, in memory, and expires
  after one hour by default. The 100,000-entry cap can remove entries earlier.
  The operator can change both values, because the cache is not the safety
  control (`docs/runtime-limits.md`). A successful
  response write can commit an entry even when the caller receives no response;
  the parent's kept reply answers a retry of the same request.
  The parent proof is the real bound: signatures for one mint that share a
  supplied parent spend the same UTXO, so Bitcoin confirms at most one. A
  different parent conflicts with the real one on Bitcoin.
- **Witness mint recipient (bound by the lockId).** A witness mint's seal names
  a vout of the mint tx, and the OpId commits that vout, not the script on it.
  The lockId the deposit names also commits the mint txid, so the same mint in
  a tx paying another script names another lock and M6 refuses it. The user
  still locks the lockId the bridge hands out, so the bridge must name the tx
  that pays the user. M8 keeps the units off the enclave's outputs and bounds
  the sats that leave to `MINT_WITNESS_SAT`. A witness mint has no amount cap
  yet.
- **EVM and CCD trust.** The images trust the pinned EVM RPC endpoint for
  receipts, canonical blocks and the selected finality head. TLS authenticates the
  endpoint, not its EVM history. A self-consistent false history from an
  approved provider can pass the deposit checks; this risk is accepted by
  design (Sec 2). CCD source
  validation trusts the listener.
- **Gas transactions.** The gas limits apply to one transaction, not to a
  sum. A gas transaction is not linked to one checked release. The LayerZero
  fee is not bound to its release.
- **Policy coverage.** The commitment does not hold all enforced settings
  (Sec 4). The attestation CLI authenticates the chain, contract and asset
  pins. The caller must compare them with the intended deployment.
  No-SPV / IndexerTrusted uses the generic Development commitment, which
  contains no endpoint or KMS settings. Its image PCRs prove code identity,
  not approval of its runtime providers. A compromised host can substitute
  its own valid TLS endpoint at launch; no in-enclave operator approval gate
  prevents that. Treat the approved launch configuration and provider data
  as additional trust assumptions for this profile.
- **Build reproducibility.** rgb-lib comes from the private
  `UTEXO-Protocol/rgb-lib-bfa` mirror at a pinned rev, and the RGB protocol
  crates it pins from the root `[patch.crates-io]`: public `rgb-protocol`
  repos at the full revs of rgb-lib's own `[patch]`. An EIF build needs the
  deploy key of the first (`lib_key`); the build scripts also require
  `rgb_deps_token`, which maps no URL. Both are BuildKit secrets: never in a
  layer, the image or PCR0. Until the RGB-Tools release is public, only a
  holder of that access can reproduce PCR0. All three EIF recipes pin both base images
  by digest and install packages from the signed Debian snapshot
  `20261007T000000Z` over HTTPS. The parent and dev image recipes use live APT
  repositories. EIF CI pins `nitro-cli` and its kernel/init blobs to `1.4.5`,
  but Docker, Buildx and BuildKit versions are not pinned.
  The supplied images leave the gas limits unset, so the gas path refuses
  until a rebuilt image sets them. The mint image bakes
  `MINT_WITNESS_SAT=1500`.
- **Protocol integration.** The enclave derives each mint's deposit id. The
  Bridge must derive RGB deposit ids the same way. The enclave and the parent pin the same vendored schema.
  Clients must send its required fields.
- **Network limits.** Testnet3 has a placeholder checkpoint. A release build
  refuses it. Testnet4 SPV is test-grade: depth counts min-difficulty
  blocks, which a host can make for free, and a host that feeds a
  fork from the checkpoint can lower its difficulty as fast as real time
  lets the testnet retarget (about 2x per 4 weeks); run it with
  `BTC_RELAY_MODE=required` and a relay that applies the same rule. Signet
  does not check PoW, `nBits` or its challenge signature (Sec 8). Regtest also
  skips PoW and `nBits` checks. The mint path reads no witness status.
- **Builds without SPV.** A burn signer built without `spv` trusts the pinned
  indexer for witness status and confirmation depth. TLS authenticates that
  endpoint; it proves no Bitcoin consensus. So the indexer can report a witness
  as mined or deep when it is not, and a release can then be signed. The build
  checks no Merkle proof and no BtcRelay commit: it requires both to be empty.
  It runs on public Signet only and attests `Development`, so `attest-verify`
  and `verify-launch` refuse it.
- **Request deadlines.** The socket deadline does not cancel handler work.
  Multiple indexer or RPC calls can take longer than the response budget.
- **Value limits.** Wire asset amounts are `u64`. The enclave refuses larger
  values.

## Diagram index

See the [diagram index](diagrams/README.md) for component, deployment, sequence,
state and signing-gate views. Keep diagrams and this specification aligned with
the referenced Rust handlers when behavior changes.
