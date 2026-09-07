# enclave-signer

Signing service for the UTEXO bridge, running inside an
[AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/). The
enclave generates the HD wallet keys, validates every bridge operation itself
(RGB consignments, Bitcoin SPV inclusion, EVM `FundsIn` receipts), and only
then signs: EIP-712 `fundsOut` releases for the EVM side, taproot PSBTs for the
RGB/Bitcoin side, Ed25519 hashes for the Concordium side. Private keys never
leave the TEE. The security posture is resolved once at boot and committed into
the attestation document, so a verifier checks it instead of trusting config.

Deeper material:

- [`docs/tee-spec.md`](docs/tee-spec.md) - normative technical specification
  (trust model, predicates, invariants, open items).
- [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md) - how to prove a
  signing key belongs to attested enclave code, and the `attest-verify` CLI.
- [`docs/diagrams/`](docs/diagrams/README.md) - Mermaid component, deployment,
  sequence and state diagrams.
- [`enclave-proto/README.md`](enclave-proto/README.md) - provenance of the
  vendored wire schema and the re-sync procedure.

## Architecture

```
+------------------------------------------------------------------+
|  Go Listener (federated-signer-node)                             |
|  Receives signing intents from the orchestrator, enriches them   |
|  with the EVM event / RGB consignment / SPV proofs, calls gRPC   |
+---------------------------+--------------------------------------+
                            | gRPC parent.ParentService
                            | (upstream federated-signer-proto, proto/enclave/parent.proto)
                            v
+------------------------------------------------------------------+
|  EC2 host (UNTRUSTED)                                            |
|                                                                  |
|  utexo-bridge-parent      gRPC -> enclave wire protocol          |
|  utexo-bridge-parent-cli  direct enclave RPCs (init, clone, ops) |
|  attest-verify            external attestation verifier          |
|                                                                  |
|  vsock-proxy 8001 -> Electrum (ssl://) or Esplora    RGB/SPV     |
|  vsock-proxy 8002 -> EVM JSON-RPC                    evm-rpc     |
|                                                                  |
|  +------------------------------------------------------------+  |
|  |  Nitro Enclave (TRUSTED, PCR-pinned)                        |  |
|  |  utexo-bridge-enclave                                       |  |
|  |  - BIP-39 seed; EVM bridge + gas-tx keys, BTC BIP-84/86,    |  |
|  |    Concordium Ed25519 (SLIP-0010)                           |  |
|  |  - SecurityPolicy resolved at boot, attested in user_data   |  |
|  |  - RGB consignment validation (rgb-ops + Electrum/Esplora)  |  |
|  |  - In-enclave Bitcoin SPV header chain                      |  |
|  |  - In-enclave EVM FundsIn receipt verification              |  |
|  |  - EIP-712 fundsOut / lzFundsOut, taproot PSBT, gas-tx,     |  |
|  |    plain-BTC, Concordium signing                            |  |
|  |  - Seed cloning between attested enclaves                   |  |
|  |  - Wire server: vsock port 5000 (prod) / TCP 5000 (dev)     |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

## Crates and binaries

| Crate | Binary | Description |
|-------|--------|-------------|
| `enclave/` | `utexo-bridge-enclave` | Runs inside the Nitro Enclave. Keys, validation, signing, SPV chain, cloning, attestation. |
| `enclave-proto/` | - | Vendored `enclave` protobuf package (pre-generated Rust, no `build.rs`). |
| `attestation-verify/` | - | Nitro attestation verifier (COSE_Sign1, cert chain to the AWS root, PCRs) plus the canonical security-policy commitment encoding. Shared by enclave and parent. |
| `parent/` | `utexo-bridge-parent` | gRPC server on the EC2 host. Translates `ParentService` RPCs to the enclave wire protocol. |
| `parent/` | `utexo-bridge-parent-cli` | Direct enclave client: key init, cloning, keys, header sync, manual signing, REPL. |
| `parent/` | `attest-verify` | Fetches an attested pubkey through the parent and verifies it end to end. |

`parent/` is a **separate cargo workspace** (own `Cargo.lock`). See
[Proto source](#proto-source) for why.

## What it does

### Key management

- Generates a BIP-39 mnemonic from OS entropy, derives the 64-byte seed and
  keeps it in a `SecretBox` (zeroize on drop). Mnemonic or raw-seed import
  exists only behind `allow-seed-import` (dev builds).
- EVM bridge key `m/44'/60'/0'/0/0` (signs `fundsOut`); EVM gas-tx key
  `m/44'/60'/0'/0/1` (signs the outer relay transaction).
- BTC legacy key `m/84'/0'/0'/0/0` (P2WSH ECDSA, unscoped CLI signing only).
- BIP-86 taproot accounts: vanilla `m/86'/<coin>'/0'` (coin 0 mainnet, 1
  otherwise) and colored `m/86'/<rgb_coin>'/0'` (827166 mainnet, 827167
  otherwise). Plain-BTC signing is scoped to vanilla, bridge PSBTs to colored.
- Concordium governance key: Ed25519, SLIP-0010, `m/44'/919'/0'/0'/0'`.
- Returns the master fingerprint and both account xpubs for multisig
  descriptors.
- The EVM address is the cluster identity. A cloned enclave installs the same
  seed and must derive the same address before it goes `Active`.

### Signing

All bridge signing goes through one `Sign` request with a source network and a
destination network. Accepted routes: RGB -> EVM, EVM -> RGB, CCD -> EVM.

- **RGB -> EVM (`fundsOut`)** - EIP-712 `TeeFundsOut` (pools route, selector
  `0xdc771390`) or `TeeLzFundsOut` (LayerZero route) over the decoded calldata
  fields, domain `MultisigProxy` / `1` / pinned chain id / pinned proxy. 65-byte
  recoverable ECDSA signature.
- **EVM -> RGB (bridge PSBT)** - taproot script-path Schnorr signatures on the
  colored account, only after the EVM deposit and the RGB consignment are
  verified and bound to the PSBT.
- **CCD -> EVM** - same `fundsOut` digest, with a Concordium source the
  listener has already validated (the enclave binds only the amount).
- **`SignBtc`** - plain-BTC PSBT on the vanilla account. Off unless the
  attested policy enables it.
- **`SignRawDigest`** - EVM gas transaction. The enclave RLP-decodes the
  unsigned tx, applies the attested allowlist (chain, `to`, fee caps, value
  cap, calldata selectors) and computes the digest itself.
- **`SignCcd`** - Ed25519 signature over a 32-byte Concordium hash.
- **`SignRawMessage`** - removed. The wire variant stays for compatibility and
  the enclave refuses it.

### Validation before signing

- **RGB consignment** - `rgb-ops` full validation inside the TEE with the
  trusted type system pinned per schema id, against an Electrum or Esplora
  resolver reached through the vsock forwarder. Contract id must equal the
  declared asset id and the pinned `RGB_ASSET_ID`.
- **Bitcoin SPV** - the enclave keeps its own PoW-validated header chain fed by
  `SubmitHeaders`. Every consignment witness tx needs a Merkle proof against a
  stored header at depth >= 6. Chain tip must be fresh (2 h).
- **EVM `FundsIn`** - the enclave fetches the receipt itself (`evm-rpc`),
  requires success, a unique event from the
  pinned `FUNDS_IN_CONTRACT`, matching `operationId` / amount / commission,
  and depth >= `EVM_MIN_CONFIRMATIONS`. Listener flags are ignored.
- **PSBT bind** - PSBT txid == consignment witness txid, prevouts match,
  sighash `ALL` / taproot `DEFAULT` only, per-output recipient legs, recipient
  seal == the invoice in the `FundsIn` event, fee rate <= 3x the enclave's own
  estimate, unowned sats <= `RGB_MAX_UNOWNED_SATS`.
- **`fundsOut` calldata** - allowlisted selector, canonical ABI (decode and
  re-encode must byte-match), amount == declared, chain / contract pins,
  `destinationChainId` rule per route, deadline in the future, BtcRelay
  finality proof anchored to the consignment's block.
- **Flow shape** - a `rgb-swap` build accepts IFA `Transfer` only; a
  `rgb-mint-burn` build accepts `Inflation` / `Burn` (and BFA `Bridge` with
  `bfa-mint`). Separate images, separate PCR0.
- **Replay** - `fundsOut` replay is the on-chain nonce in the digest. EVM -> RGB
  requests get a soft in-memory dedup (24 h) keyed by the deposit.

### Attested security policy

`SecurityPolicy` is resolved once at boot from build flags and env pins and is
`Production { pins, allow_vanilla_psbt, evm_source, gas-tx rule }` or
`Development { reason }`. A release `rgb-validation` build refuses
to boot unless it resolves to a valid `Production` policy. The policy is
committed into the attestation `user_data`; `attest-verify` rebuilds the
expected policy and fails on any downgrade. Details in
[`docs/pubkey-attestation.md`](docs/pubkey-attestation.md).

### gRPC bridge (parent)

- Implements `parent.ParentService` from `federated-signer-proto`
  (`proto/enclave/parent.proto`): `Sign`, `PublicKey`, `Initialize`, `Clone`,
  `GetLastSavedBlock`, `SubmitHeaders`, `AttestedPublicKey`.
- `Sign` routes by `data_type`: `TRANSACTION` -> enclave `Sign` (EVM / RGB /
  CCD payload), `EVM_GAS_TX` -> `SignRawDigest`, `BTC_UTXO` -> `SignBtc`.
  EVM destinations must be listed in `EVM_NETWORK_IDS`.
- One new TCP or vsock connection per RPC, 30 s timeout. No TLS, no health
  service. Readiness is checked with a port probe or a `get-keys` call.

## Enclave requests

Wire format: `[4-byte little-endian length][protobuf EnclaveRequest]`, one
request per connection, 4 MiB frame cap. Schema:
[`enclave-proto/proto/enclave.proto`](enclave-proto/proto/enclave.proto).

| Request | Phase | Feature | Description |
|---------|-------|---------|-------------|
| `InitializeKey` | Initial | - | Generate keys from OS entropy. Optional donor `cloning_secret`. Mnemonic / seed import needs `allow-seed-import`. |
| `GetPublicKey` | Active | - | EVM address + pubkeys, gas-tx key, BTC pubkey / xpub, fingerprint, account xpubs, CCD pubkey, boot pins. |
| `GetAttestedPublicKey` | Active | - | Same bundle plus an NSM attestation document bound to nonce, pubkey and the policy commitment. |
| `Sign` | Active | `rgb` / `ccd` | Bridge signing: RGB -> EVM, EVM -> RGB, CCD -> EVM. |
| `SignBtc` | Active | - | Plain-BTC PSBT, vanilla account, policy-gated. |
| `SignRawDigest` | Active | - | Gas-tx signing under the attested allowlist. |
| `SignCcd` | Active | `ccd` | Ed25519 over a 32-byte hash. |
| `SubmitHeaders` | any | `spv` | Feed Bitcoin headers (<= 10 000 per call, <= 100 000 per 60 s). |
| `GetLastSavedBlock` | any | `spv` | Header-chain tip (checkpoint when empty). |
| `InitiateCloning` | Initial | - | Requester side of the seed-cloning handshake. |
| `GetClone` | Active | - | Donor side: verifies the requester attestation and seals the seed. |
| `SetClone` | Cloning | - | Requester installs the sealed seed and goes `Active`. |
| `SignRawMessage` | - | - | Removed. Always refused. |
| `ProxyFederation` | - | - | Stub. Returns `NOT_READY`. |

Error codes in `ErrorResponse`: `3` cross-check / SPV failure (the parent maps
it to `FAILED_PRECONDITION`), `2` not ready, `1` everything else.

## Prerequisites

- **Rust 1.96.1** - pinned in `rust-toolchain.toml`. The exact patch version
  matters for reproducible PCR0.
- **SSH deploy keys** - the workspace currently pins the RGB crates to private
  BFA mirrors (`rgb-consensus-s-bfa`, `rgb-ops-s-bfa`, `rgb-schemas-s-bfa`,
  `consignment-utils`) through the `github-rgb-*` SSH host aliases in
  `Cargo.toml`. Every build, including the enclave, needs read access to them.
  The parent additionally needs `federated-signer-proto`. CI wires the aliases
  in `.github/workflows/ci.yml`; copy that `~/.ssh/config` shape locally.
  Until the mirrors are public again, PCR0 is reproducible only by key holders.
- **Docker + `nitro-cli`** for the EIF. Any x86_64 Linux host with Docker can
  build an EIF and read its PCRs; Nitro hardware is needed only to run it.

```bash
git clone git@github.com:UTEXO-Protocol/enclave-signer
cargo build                                   # enclave workspace
cargo build --manifest-path parent/Cargo.toml # parent workspace
```

## Building

### Feature sets

The production feature sets are below. Single-network images use
`--no-default-features`:

```bash
# Combined (what build/Dockerfile.enclave ships)
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,rgb,rgb-swap,ccd,evm-rpc

# RGB send/receive only
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,rgb,rgb-swap,evm-rpc

# RGB mint/burn only (separate instance, separate PCR0)
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,rgb,rgb-mint-burn,evm-rpc

# Concordium only
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,ccd

# Local TCP dev build (debug profile, seed import allowed)
cargo build -p utexo-bridge-enclave --no-default-features --features allow-seed-import,spv,rgb-swap,ccd,evm-rpc
```

Compile-time guards in `enclave/src/lib.rs`: `rgb-validation` requires `spv`;
exactly one of `rgb-swap` / `rgb-mint-burn` whenever `rgb-validation` is on;
`allow-seed-import`, `mock-attestation`, `dev-mode` do not compile in a release
profile. CI asserts every guard fires.

### Enclave image (EIF)

```bash
./build/build-enclave.sh                                  # Dockerfile.enclave (combined)
DOCKERFILE=Dockerfile.enclave.rgb       ./build/build-enclave.sh
DOCKERFILE=Dockerfile.enclave.mint-burn ./build/build-enclave.sh
DOCKERFILE=Dockerfile.enclave.ccd       ./build/build-enclave.sh
DOCKERFILE=Dockerfile.enclave.bfa GITHUB_TOKEN=... ./build/build-enclave.sh
```

The script builds the Docker image with `SOURCE_DATE_EPOCH` set to the commit
time, converts it with `nitro-cli build-enclave`, and writes the EIF,
`PCR.json` and `SHA256SUMS` to `build/`. Reproducibility inputs: pinned
toolchain, digest-pinned base images, `--locked`, `CARGO_INCREMENTAL=0`,
path-prefix remapping, pre-generated proto code. Known drift: apt / dnf
package versions still float.

`.github/workflows/build-eif.yml` builds the `combined`, `rgb`,
`rgb-mint-burn` and `ccd` variants on a plain runner with `nitro-cli 1.4.5`
and uploads EIF + PCRs + host binaries to `s3://<bucket>/eif/<git_sha>/`.
`release-eif.yml` deploys one of those to the stage hosts over SSM using
`deploy/deploy-host.sh`. The `cd-*.yml` workflows push container images for
the parent and the **dev** enclave image only.

The production Dockerfiles bake the bridge pins as `ENV` (`EVM_CHAIN_ID`,
`EVM_PROXY_CONTRACT_ADDRESS`, `RGB_ASSET_ID`, `FUNDS_IN_CONTRACT`,
`GAS_TX_ALLOWED_TO`, `BTC_MAX_TOTAL_SATS`, `ELECTRUM_URL`, ...), so they are
measured into PCR0. The cloning secret is never baked.

## Running

### Local development (TCP)

```bash
# Enclave on 127.0.0.1:5000
RUST_LOG=debug cargo run -p utexo-bridge-enclave

# Parent gRPC server (GRPC_PORT defaults to 5000; pick another port when both run on one host)
RUST_LOG=debug GRPC_PORT=50051 cargo run --manifest-path parent/Cargo.toml

# CLI
CLI="cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent-cli --"
$CLI init                                   # keys from OS entropy
$CLI init --cloning-secret <secret>         # same, and arm this enclave as a clone donor
$CLI init-mnemonic "word1 ... word12"       # needs an allow-seed-import enclave
$CLI get-keys
$CLI get-last-saved-block
$CLI submit-headers --start-height <h> --headers-file headers.hex
$CLI sign-evm --call-data <hex> --nonce 1 --deadline 9999999999 --chain-id 1 --proxy-contract <hex>
$CLI sign-psbt --psbt <hex> --evm-tx-hash <hex> --evm-funds-in-operation-id <hex32> --consignment <hex> ...
$CLI clone --cloning-secret <secret> --donor-grpc http://donor:50051 --donor-evm <hex20>
$CLI interactive
```

`--addr host:port` or `--addr vsock://<cid>:<port>` selects the enclave.

### Production (Nitro)

```bash
nitro-cli run-enclave --cpu-count 2 --memory 3072 --enclave-cid 16 \
  --eif-path build/utexo-bridge-enclave.eif

# Host-side proxies (allowlist each upstream)
vsock-proxy 8001 <electrum-host> 50002          # ELECTRUM_URL upstream
vsock-proxy 8002 127.0.0.1 8547                 # EVM JSON-RPC (nginx adds TLS + key, see deploy/host-prep-evmrpc.sh)

GRPC_HOST=0.0.0.0 GRPC_PORT=50051 USE_VSOCK=true ENCLAVE_VSOCK_CID=16 ./utexo-bridge-parent
```

`deploy/deploy-host.sh` installs the systemd units for a three-enclave host:
CIDs 16 / 18 / 20 with parents on ports 50051 / 50052 / 50053. It verifies the
EIF checksum and PCR0 against the S3 manifest before and after start. Keys
live only in enclave memory; a restart wipes them and the enclave must be
initialised or cloned again.

### Debug mode

`nitro-cli run-enclave ... --debug-mode` zeroes PCR0/1/2, so attestation
against pinned PCRs fails. Use it only to read logs:

```bash
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
nitro-cli describe-enclaves
nitro-cli terminate-enclave --enclave-id <id>
```

## Environment variables

### Enclave

Bridge pins (all three required for a `Production` policy):

| Variable | Default | Description |
|----------|---------|-------------|
| `EVM_CHAIN_ID` | `0` | Pinned chain id. Must match the destination chain and the direct-route `destinationChainId`. |
| `EVM_PROXY_CONTRACT_ADDRESS` | zero | MultisigProxy address: EIP-712 `verifyingContract` and the `to` of the payable `lzFundsOutCall` carve-out. Attested as `bridge_contract`. |
| `RGB_ASSET_ID` | empty | Pinned RGB contract id. Enforced on every bridge PSBT, and on `fundsOut` when the bridge is configured. |
| `FUNDS_IN_CONTRACT` | falls back to the proxy | Emitter of `FundsIn` / `BridgeFundsIn`. Set it explicitly when the two contracts differ. Not yet in the attested commitment. |

Value bounds (fail closed while unset in a production build):

| Variable | Default | Description |
|----------|---------|-------------|
| `BTC_MAX_TOTAL_SATS` | `0` | Cap on total input value of one plain-BTC (`SignBtc`) transaction. Non-zero also flips `allow_vanilla_psbt` in the attested policy. |
| `BTC_MAX_UNOWNED_SATS` | `0` | Plain-BTC output budget for scripts the enclave does not prove it controls (allocation dust, fresh change). |
| `RGB_MAX_UNOWNED_SATS` | `0` | Bridge-PSBT output budget for sats the enclave cannot prove it controls. Size it from the bridge's witnessed satoshi amount. |
| `GAS_TX_ALLOWED_TO` | unset | Only `to` a gas tx may target. |
| `GAS_TX_MAX_GAS_LIMIT` | `0` | Ceiling on `gasLimit`. |
| `GAS_TX_MAX_FEE_PER_GAS` | `0` | Ceiling (wei) on `maxFeePerGas` / `maxPriorityFeePerGas` / legacy `gasPrice`. |
| `GAS_TX_ALLOWED_SELECTORS` | empty | Comma-separated 4-byte selectors a gas tx may call. Empty calldata is refused. Malformed entries are dropped with a warning. |
| `GAS_TX_MAX_VALUE_WEI` | unset | Ceiling on native `value`; only `lzFundsOutCall` to the pinned proxy may carry value. |

The gas-tx rule is part of the attested policy. Unset pins commit as zero.

Data sources and transport:

| Variable | Default | Description |
|----------|---------|-------------|
| `BITCOIN_NETWORK` | `bitcoin` | `bitcoin`, `testnet`, `signet`, `regtest`. Selects the SPV checkpoint, coin types and xpub prefix. Baked into the image. |
| `ELECTRUM_URL` / `ESPLORA_URL` | `http://127.0.0.1:3443` | Consignment resolver. `ssl://host:port` or `tcp://host:port` selects Electrum: the forwarder listens on that port and pins `host` to loopback in `/etc/hosts` so TLS terminates inside the enclave. Anything else is Esplora REST on loopback 3443. |
| `ESPLORA_VSOCK_PORT` | `8001` | Host vsock-proxy port for the resolver. |
| `EVM_RPC_URL` | `http://127.0.0.1:3444` | Loopback EVM JSON-RPC (`evm-rpc`). A non-loopback value is replaced by the default. |
| `EVM_RPC_VSOCK_PORT` | `8002` | Host vsock-proxy port for the EVM RPC. |
| `EVM_MIN_CONFIRMATIONS` | `12` | Minimum depth of a `FundsIn` receipt. |
| `ENCLAVE_LISTEN_ADDR` | `127.0.0.1:5000` | TCP listen address, non-vsock builds only. |
| `RUST_LOG` | unset | Log filter. |

Limits and dev knobs:

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONSIGNMENT_BYTES` | 1 MiB | Consignment size cap. |
| `MAX_MERKLE_PROOFS` | `256` | Proof-count cap per request. |
| `MAX_TOTAL_PROOF_BYTES` | 128 KiB | Aggregate proof-bytes cap per request. |
| `SPV_CHECKPOINT` | unset | Dev builds only: `height:hash[:bits:time]` moves the SPV anchor forward. A production-shaped build refuses to boot when set. |
| `UTEXO_CLONING_SECRET` | unset | Legacy donor secret. Prefer `init --cloning-secret` at runtime. |

### Parent

| Variable | Default | Description |
|----------|---------|-------------|
| `GRPC_HOST` | `127.0.0.1` | Bind address. Deployments use `0.0.0.0`. |
| `GRPC_PORT` | `5000` | gRPC port. Deployments use 50051-50053. |
| `ENCLAVE_ADDR` | `127.0.0.1:5000` | Enclave TCP address (dev). |
| `USE_VSOCK` | `false` | `true` / `1` selects vsock (Linux only). |
| `ENCLAVE_VSOCK_CID` | `16` | Enclave CID. |
| `ENCLAVE_VSOCK_PORT` | `5000` | Enclave vsock port. |
| `EVM_NETWORK_IDS` | empty | Comma-separated network ids that count as EVM destinations for `Sign`. Empty rejects every EVM-destination transaction. |
| `RUST_LOG` | unset | Log filter. |

## Testing

```bash
cargo test                                                              # enclave workspace, default features
cargo test -p utexo-bridge-enclave --features spv,rgb-swap              # full RGB sign-path gate
cargo test -p utexo-bridge-enclave --no-default-features --features rgb,rgb-mint-burn
cargo test -p utexo-bridge-enclave --features evm-rpc
cargo test -p utexo-bridge-enclave --features mock-attestation,allow-seed-import
cargo test --manifest-path parent/Cargo.toml                            # gRPC bridge + attest-verify e2e
```

Coverage: key derivation and fingerprints, framing, EIP-712 digests pinned to
the deployed contract, calldata canonicalisation, gas-tx allowlist, consignment
fixtures per flow, PSBT binding and fee gate, SPV chain / reorg / Merkle,
attestation verification incl. crafted cert chains, cloning handshake, wire
roundtrips over TCP, gRPC translation with a mock enclave, vendored-proto
provenance. `build/smoke-test.sh` drives a live enclave through the CLI.

## Feature flags

| Feature | Implies | Description |
|---------|---------|-------------|
| `rgb` | `spv` | RGB / Bitcoin bridge stack. |
| `ccd` | - | Concordium stack (Ed25519 is always compiled; this gates the handlers). |
| `rgb-swap` | `rgb` | RGB flow: send/receive with IFA `Transfer`. In the default set. |
| `rgb-mint-burn` | `rgb` | RGB flow: deposits mint with IFA `Inflation`, withdrawals `Burn`. Needs `--no-default-features`. |
| `bfa-mint` | `rgb-mint-burn`, `evm-rpc` | Bridged Fungible Asset schema: `Bridge` transitions verified against the enclave's own `FundsIn` reads. |
| `spv` | `rgb-validation` | In-enclave Bitcoin header chain and witness inclusion proofs. |
| `rgb-validation` | rgb crates | In-enclave consignment validation. Requires `spv`. |
| `evm-rpc` | `rgb-validation` | In-enclave `FundsIn` verification over host-relayed JSON-RPC. Without it the enclave refuses every bridge PSBT. |
| `vsock` | - | vsock listener and forwarders (Linux). |
| `allow-seed-import` | - | Mnemonic / raw-seed import. Dev only, does not compile in release. |
| `dev-mode` | - | Skips cross-check validation. Dev only, does not compile in release. |
| `mock-attestation` | - | Raw-CBOR attestation with zero PCRs. Dev only, does not compile in release. |

## Protocol

### Enclave wire protocol

`[4-byte LE length][protobuf]`, one `EnclaveRequest` -> one `EnclaveResponse`
per connection, 4 MiB cap, no version field. Connection limits are compiled
in: 4 worker threads, queue of 16, 10 s idle and 30 s total per request.

### Proto source

| | Enclave | Parent |
|---|---|---|
| Schema | `enclave-proto/`, vendored in-tree | `federated-signer-proto`, git dep over SSH |
| Packages | `enclave` only | `bridge` / `node` / `orchestrator` / `parent` / `signer` |
| Workspace | repo root | `parent/` (own root + lockfile) |

Cargo materialises every git source in a workspace before it knows which
crates a `-p` build compiles. Keeping `parent/` out of the root workspace is
what keeps its private proto dep out of the enclave dependency graph. Build
the parent with `--manifest-path parent/Cargo.toml`, never `-p`.

The generated Rust is committed because `protoc` / prost-build versions change
the output and would otherwise enter PCR0. Both sides pin the same upstream
commit; `enclave-proto/tests/vendored_provenance.rs` fails when they drift.
Re-syncing changes PCR0. Procedure in
[`enclave-proto/README.md`](enclave-proto/README.md).

## Security model

- **Untrusted host.** Every value from the parent, listener or backend is
  re-derived or re-validated inside the enclave. Esplora / Electrum and the
  EVM RPC are trusted for availability only.
- **Attested posture.** Build flags and pins resolve to one `SecurityPolicy`
  committed into the attestation. A downgraded posture fails verification.
- **Fail closed.** Missing feature, missing pin, missing receipt, missing
  proof, zero inputs signed: refuse, never sign with less verification.
- **Compile-time thresholds.** Confirmation depths, freshness windows, reorg
  and retention caps, connection limits are constants measured into PCR0.
- **Key custody.** Seed and keys in `SecretBox`, zeroized on drop.
  `#![deny(unsafe_code)]`. No persistence: keys exist only in enclave memory.
- **Cloning.** X25519 + HKDF-SHA256 + ChaCha20-Poly1305, mutual attestation
  with PCR equality, shared secret, replay guard recorded only after
  authentication.
- **Release hardening.** `opt-level = "z"`, LTO, stripped, `panic = "abort"`,
  single codegen unit. Dev features are `compile_error!` in release.

Known open items are tracked in
[`docs/tee-spec.md`](docs/tee-spec.md#13-implementation-status).

## Project structure

```
.
|-- Cargo.toml                   # enclave workspace + [patch.crates-io] RGB pins
|-- rust-toolchain.toml          # 1.96.1
|-- enclave-proto/               # vendored `enclave` schema slice (see its README)
|-- attestation-verify/          # Nitro attestation verifier + policy commitment encoding
|-- enclave/src/
|   |-- main.rs                  # boot: policy, forwarders, SPV checkpoint, listener
|   |-- server.rs                # dispatch + handlers, attested pubkey bundle
|   |-- conn.rs                  # worker pool, deadlines
|   |-- policy.rs                # SecurityPolicy resolution
|   |-- config.rs                # env pins and caps
|   |-- state.rs                 # Phase machine, replay guards
|   |-- keys.rs                  # BIP-39/32/44/84/86 + SLIP-0010 keys, signing
|   |-- cloning.rs               # seed cloning crypto
|   |-- attestation.rs           # NSM facade
|   |-- framing.rs               # length-prefixed protobuf
|   |-- vsock_forwarder.rs       # loopback -> vsock egress
|   `-- networks/
|       |-- mod.rs               # route validation
|       |-- ccd.rs               # Concordium source
|       |-- evm/                 # calldata validation, crosscheck, FundsIn, gas tx, EIP-712
|       `-- rgb/                 # consignment, PSBT bind, invoice, ownership, SPV, flow/{swap,mint_burn}
|-- parent/                      # separate workspace: gRPC server, CLI, attest-verify
|-- build/                       # Dockerfiles, build-enclave.sh, smoke tests
|-- deploy/                      # deploy-host.sh, systemd units, EVM-RPC host prep
|-- docs/                        # tee-spec, pubkey-attestation, diagrams
`-- .github/workflows/           # ci, build-eif, release-eif, cd-*
```

## License

TBD
