# utexo-bridge-signer

Cryptographic signing service for the UTEXO RGB-EVM bridge, running inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/). The enclave generates HD wallet keys, signs EVM (EIP-712) and BTC (PSBT) transactions, and validates RGB consignments against an Esplora indexer — all within the TEE so private keys never leave the enclave.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Go Listener (federated-signer-node)                             │
│  Receives signing requests from Orchestrator, enriches with      │
│  EVM event data + RGB consignment, forwards via gRPC             │
└───────────────────────┬──────────────────────────────────────────┘
                        │ gRPC (upstream federated-signer-proto: proto/listener/listener.proto)
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│  EC2 Host                                                        │
│                                                                  │
│  utexo-bridge-parent (gRPC server + CLI)                         │
│  ├── Translates gRPC → enclave wire protocol                     │
│  ├── PSBTSigningFlow / EVMSigningFlow → SignPsbtRequest /        │
│  │   SignEvmRequest (including consignment bytes)                 │
│  └── TCP / vsock to enclave                                      │
│                                                                  │
│  vsock-proxy 8001 → Esplora API  (for RGB validation)            │
│  vsock-proxy 8002 → EVM RPC      (for FundsIn verify, evm-rpc)   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Nitro Enclave                                              │  │
│  │                                                             │  │
│  │  utexo-bridge-enclave                                       │  │
│  │  ├── BIP-39 key gen (EVM m/44'/60', BTC m/84' + m/86')     │  │
│  │  ├── EIP-712 signing (EVM → RGB direction)                  │  │
│  │  ├── PSBT signing (RGB → EVM direction)                     │  │
│  │  ├── RGB consignment validation (rgbstd + Esplora)          │  │
│  │  ├── Cross-check validation (amounts, deadlines, calldata)  │  │
│  │  ├── vsock forwarder (localhost → vsock → Esplora)          │  │
│  │  └── Protobuf RPC server (vsock:5000 / TCP:5000)            │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Workspace crates

| Crate | Binary | Description |
|-------|--------|-------------|
| **`enclave/`** | `utexo-bridge-enclave` | Runs inside the Nitro Enclave. Key management, signing, RGB validation. |
| **`parent/`** | `utexo-bridge-parent` | gRPC server (Parent Adapter) — translates Go Listener RPCs to enclave wire protocol. |
| **`parent/`** | `utexo-bridge-parent-cli` | CLI tool for direct enclave interaction (testing, key init, manual signing). |

## What it does

### Key management

- Generates a BIP-39 mnemonic from OS entropy (or imports a mnemonic phrase in test mode), derives a 64-byte seed, stores it in `SecretBox` (zeroize-on-drop)
- EVM: derives `m/44'/60'/0'/0/0`, computes 20-byte address via `keccak256(uncompressed_pubkey[1..])[12..]`
- BTC (legacy): derives `m/84'/0'/0'/0/0`, produces 33-byte compressed pubkey and BIP-32 xpub
- BTC (BIP-86 taproot): derives two account-level xprivs for multisig descriptors:
  - Vanilla: `m/86'/<coin>'/0'` (coin type 0 mainnet, 1 testnet)
  - Colored (RGB): `m/86'/<rgb_coin>'/0'` (coin type 827166 mainnet, 827167 testnet)
- Returns master fingerprint (4 bytes) for cosigner identification in multisig descriptors

### Signing

- **EVM (EIP-712)** — Signs typed data for the MultisigProxy contract (fundsOut). Builds EIP-712 domain from chain_id + proxy_contract, computes struct hash from calldata/nonce/deadline, signs with recoverable ECDSA (65 bytes: r+s+v).
- **PSBT (SegWit v0 P2WSH + Taproot)** — Signs matching inputs in a partially signed Bitcoin transaction. Auto-detects input type:
  - **Taproot script-path** (BIP-341/BIP-340): Matches via `tap_key_origins` fingerprint, derives child keys per-input, signs with Schnorr into `tap_script_sigs`. Supports `multi_a()` tapscripts.
  - **SegWit v0 P2WSH** (legacy): Matches by BIP-32 derivation path or witness script pubkey, signs with ECDSA into `partial_sigs`.
- **Raw message** — Signs arbitrary bytes (keccak256-hashed) for fundsIn authorization (1-of-n).

### Validation (before signing)

- **RGB consignment validation** (feature `rgb-validation`) — Deserializes the RGB `Transfer` consignment, creates an Esplora-backed resolver, runs rgbstd's full validation pipeline inside the TEE. Replaces trusting the Go Listener's boolean.
- **Consignment hash integrity** — Verifies `keccak256(consignment) == consignment_hash` to catch tampering.
- **Amount cross-checks** — Verifies `rgb_amount >= calldata_amount + commission`, extracts and compares amounts from raw calldata bytes.
- **Calldata extraction** — Reads uint256 values at ABI offsets to verify declared amounts match actual calldata.
- **Deadline check** — Rejects expired signing requests.
- **Chain/domain validation** — Requires valid `chain_id` and 20-byte `proxy_contract` for EIP-712 domain.

### gRPC bridge (Parent Adapter)

- Implements `FederatedSignerNode` from the upstream federated-signer-proto repo (`proto/listener/listener.proto`) (the Go Listener's gRPC interface)
- Translates `PSBTSigningFlow` / `EVMSigningFlow` into enclave-native `SignPsbtRequest` / `SignEvmRequest`
- Passes consignment bytes through for in-enclave validation
- 30-second timeout on enclave requests, binds to localhost only

## Enclave operations

| Operation | Description |
|-----------|-------------|
| `InitializeKey` | Generate keys from OS entropy (or import raw seed / BIP-39 mnemonic in test mode) |
| `GetPublicKey` | Retrieve EVM address, BTC pubkeys, master fingerprint, and BIP-86 account xpubs (vanilla + colored) |
| `SignEvm` | EIP-712 typed data signing with cross-check validation |
| `SignPsbt` | Taproot (Schnorr) + SegWit v0 P2WSH (ECDSA) PSBT signing with cross-check validation |
| `ProxyFederation` | Federation signature proxy (stub, not yet wired) |

## Prerequisites

- **Rust 1.91+** (stable) — `alloy` 2.1.x sets the floor; the enclave image
  builds on 1.96.
- **No credentials.** Every enclave dependency resolves over public HTTPS.
  Building the **parent** additionally needs a deploy key for
  `UTEXO-Protocol/federated-signer-proto`, the last private dep in the repo.

```bash
git clone https://github.com/UTEXO-Protocol/enclave-signer
cargo build
```

No submodules. The enclave's slice of the proto schema is vendored in-tree at
[`enclave-proto/`](enclave-proto/), and `parent/` is a separate cargo workspace
so its private dep never enters an enclave build.

For building the Nitro Enclave image: Docker + `nitro-cli`. A Nitro-capable EC2
instance is **not** required to produce an EIF and read its PCRs — any x86_64
Linux host with Docker works (CI does this on a plain GitHub runner). You only
need Nitro hardware to *run* the enclave.

## Building

### Local development (TCP mode)

```bash
# Build everything
cargo build

# Build with RGB validation support. `rgb-swap` picks the send/receive RGB
# flow; every rgb-validation build must name exactly one flow (see below).
cargo build -p utexo-bridge-enclave --features rgb-validation,rgb-swap

# Build with SPV verification (implies rgb-validation). With --features spv,
# the enclave refuses to sign EVM transactions unless the request carries
# valid Bitcoin SPV proofs for every consignment-anchor witness tx.
# Without the feature, the enclave fails-closed if the request supplies
# merkle_proofs at all (catches build mismatches against the listener).
cargo build -p utexo-bridge-enclave --features spv,rgb-swap

# Build only the gRPC server (Parent Adapter)
cargo build --manifest-path parent/Cargo.toml
```

### Production (Nitro Enclave)

```bash
# Build the enclave binary with vsock + RGB validation + SPV, send/receive flow
cargo build --release -p utexo-bridge-enclave --features vsock,rgb-validation,spv,rgb-swap

# The mint/burn enclave is the same stack with the other flow. It is a separate
# instance with its own PCR0, never a runtime switch. `--no-default-features` is
# required: the default set carries `rgb-swap`.
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,rgb,rgb-mint-burn

# Or build the full Enclave Image Format (EIF). No credentials needed --
# this is the command a third party runs to reproduce PCR0.
./build/build-enclave.sh
```

The build script builds a Docker image, converts it to an EIF via `nitro-cli build-enclave`, and outputs PCR measurements (PCR0/1/2) for KMS attestation policies.

## Running

### Local development

Start the enclave server (TCP on `127.0.0.1:5000`):

```bash
RUST_LOG=debug cargo run -p utexo-bridge-enclave
```

Start the gRPC server (Parent Adapter on `127.0.0.1:5000`):

```bash
RUST_LOG=debug cargo run --manifest-path parent/Cargo.toml
```

Use the CLI tool directly:

```bash
# Initialize keys (generate new mnemonic)
cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent-cli -- init

# Initialize keys from a known mnemonic (requires allow-seed-import feature)
cargo run --manifest-path parent/Cargo.toml --features allow-seed-import --bin utexo-bridge-parent-cli -- \
  init-mnemonic "word1 word2 word3 ... word12"

# Get public keys
cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent-cli -- get-keys

# Sign an EVM transaction
cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent-cli -- sign-evm \
  --call-data <hex> --nonce 1 --deadline 9999999999 \
  --chain-id 1 --proxy-contract <hex>

# Interactive REPL
cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent-cli -- interactive
```

### Production (Nitro Enclave)

```bash
# Start the enclave
nitro-cli run-enclave \
  --cpu-count 2 --memory 512 --enclave-cid 16 \
  --eif-path build/utexo-bridge-enclave.eif

# Start vsock-proxy for Esplora access (on the host)
vsock-proxy 8001 <esplora-host> <esplora-port>

# Start vsock-proxy for the EVM RPC (on the host) — only for `evm-rpc` builds,
# used by in-enclave FundsIn verification. Allowlist to the RPC endpoint.
vsock-proxy 8002 <evm-rpc-host> <evm-rpc-port>

# Trustless (Helios) variant — only for `helios` builds (experimental).
# Two upstreams Helios verifies against a pinned checkpoint:
vsock-proxy 8003 <evm-execution-rpc-host> <port>   # HELIOS_EXECUTION_RPC
vsock-proxy 8004 <beacon-consensus-rpc-host> <port> # HELIOS_CONSENSUS_RPC

# Start the gRPC server (Parent Adapter)
GRPC_PORT=5000 USE_VSOCK=true cargo run --release --manifest-path parent/Cargo.toml
```

### Debug mode (Nitro Enclave)

By default, a running enclave has no console output — `RUST_LOG` output is siloed inside the TEE. To see logs, run the enclave with `--debug-mode`:

```bash
nitro-cli run-enclave \
  --cpu-count 2 --memory 512 --enclave-cid 16 \
  --eif-path build/utexo-bridge-enclave.eif \
  --debug-mode
```

> **Note:** In debug mode, PCR0/PCR1/PCR2 are all zeroed. KMS attestation policies that check PCR values will reject the enclave. Use debug mode only for development/testing — never in production.

Once the enclave is running, attach to its console:

```bash
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

This streams the enclave's stdout/stderr (i.e. `RUST_LOG` output) to your terminal. `Ctrl+C` detaches without stopping the enclave.

To list running enclaves and their IDs:

```bash
nitro-cli describe-enclaves
```

To terminate an enclave:

```bash
nitro-cli terminate-enclave --enclave-id <enclave-id>
```

### Environment variables

#### Enclave

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | (none) | Log level (e.g., `info`, `debug`) |
| `ESPLORA_URL` | `http://127.0.0.1:3443` | Esplora API endpoint for RGB validation |
| `BITCOIN_NETWORK` | `bitcoin` | One of: `bitcoin`, `testnet`, `signet`, `regtest`. Affects BIP-86 coin type (0 vs 1) and xpub prefix (xpub vs tpub). |
| `SPV_CHECKPOINT` | (unset) | **Local/dev builds only** (debug, `cfg(test)`, or `allow-seed-import` — i.e. what `build/Dockerfile.enclave-dev` produces). Moves the SPV boot checkpoint forward so the initial header sync doesn't replay every block since the compiled-in anchor. Format `height:block_hash` or `height:block_hash:bits:time`, where `block_hash` is 64 hex chars in explorer (display) order, `bits` is hex and **must** carry a `0x` prefix, and `time` is a Unix timestamp. The two-field form inherits `bits`/`time` from the compiled checkpoint and is rejected on PoW networks (mainnet/testnet3), which consume both. A production-shaped build **refuses to boot** when this is set: the checkpoint is the SPV trust anchor and must come from the constant PCR0 commits to. Example: `SPV_CHECKPOINT=430000:000000ac5fccb8a26d3bf859952e164b4fb65190c8f29c8339c6a2c39f3aeb66`. |
| `BTC_MAX_TOTAL_SATS` | (unset) | Cap on the total input value a single plain-BTC (`SignBtc`) transaction may spend. An `rgb-validation` build refuses plain-BTC signing while unset. |
| `BTC_MAX_UNOWNED_SATS` | (unset) | Budget (sats) for plain-BTC outputs that do **not** pay back into the same custody — i.e. whose `script_pubkey` is not that of an input the enclave co-signs. Sized for `create_utxo` allocation dust (1000 sats each, 5 by default), so `5000` is the floor and `20000` leaves headroom. An `rgb-validation` build refuses plain-BTC signing while unset. Replaces the removed "a tap leaf mentions one of our keys" rule, which a host could forge (see `networks/rgb/btc_ownership.rs`). |
| `RGB_MAX_UNOWNED_SATS` | (unset) | Budget (sats) for send-RGB (`SignPsbt`) outputs the enclave cannot prove it controls. The recipient's witness output is blinded, so the enclave bounds what leaves rather than identifying the payout — size it from the bridge's `WITNESSED_SATOSHI_AMOUNT` (`1000` → `10000` leaves headroom). An `rgb-validation` build refuses send-RGB signing while unset. Without it, every send-RGB bind is denominated in RGB asset units and nothing bounds the Bitcoin value the transaction moves. |
| `GAS_TX_ALLOWED_TO` | (unset) | 0x-hex destination a gas-key transaction (`SignRawDigest`) may target. Unset refuses all gas-tx signing in a release build. Together with the three pins below this forms the gas-tx rule, which is folded into the attested `SecurityPolicy`, so a verifier confirms it rather than trusting configuration (see `networks/evm/gas_tx.rs`). |
| `GAS_TX_MAX_GAS_LIMIT` | (unset) | Ceiling on a gas tx's `gasLimit`. `0`/unset refuses all gas-tx signing. With `GAS_TX_MAX_FEE_PER_GAS` this bounds the most ETH a *single* signed gas tx can burn as fees (`gasLimit * maxFeePerGas`). Not an aggregate cap — rate limiting belongs outside the enclave. |
| `GAS_TX_MAX_FEE_PER_GAS` | (unset) | Ceiling (wei) on a gas tx's per-gas fee: `maxFeePerGas` and `maxPriorityFeePerGas` for EIP-1559, `gasPrice` for legacy. `0`/unset refuses all gas-tx signing. |
| `GAS_TX_ALLOWED_SELECTORS` | (unset) | Comma-separated 4-byte hex function selectors (e.g. `0xdeadbeef,0x7ae8f736`) a gas tx's calldata may invoke. Every signed gas tx must lead with a selector in this set; empty calldata is refused (a bare call still invokes the destination's `fallback`/`receive`). Empty/unset refuses all gas-tx signing. A malformed entry is dropped with a boot warning rather than poisoning the list. This replaces the old unverifiable "the destination is an EOA so calldata is inert" assumption. |
| `GAS_TX_MAX_VALUE_WEI` | (unset) | Ceiling (wei) on the native `value` a gas-key transaction (`SignRawDigest`) may carry. Only the payable `lzFundsOutCall` may carry value, and only when `to` is also the pinned `BRIDGE_CONTRACT`; every other selector still requires `value == 0`. The carve-out widens the *value* rule only — `lzFundsOutCall` must still appear in `GAS_TX_ALLOWED_SELECTORS`. Unset or unparseable refuses any non-zero value, so deployments not using the LayerZero release path need no configuration. The fee is not bound into the `TeeLzFundsOut` payload, so this ceiling bounds the blast radius (see `networks/evm/gas_tx.rs`). |
| `ESPLORA_VSOCK_PORT` | `8001` | vsock port for the host's vsock-proxy |
| `EVM_RPC_URL` | `http://127.0.0.1:3444` | Loopback EVM JSON-RPC endpoint for in-enclave FundsIn verification (`evm-rpc` builds). MUST be loopback — reached via the vsock forwarder. Responses are relayed by the untrusted host (evidence verified fail-closed; trustless only once Helios lands). |
| `EVM_RPC_VSOCK_PORT` | `8002` | vsock port for the host's EVM-RPC vsock-proxy (`evm-rpc` builds) |
| `EVM_MIN_CONFIRMATIONS` | `12` | Minimum confirmation depth a FundsIn receipt must have (`evm-rpc` / `helios` builds) |
| `HELIOS_EXECUTION_RPC` | (unset) | **`helios` builds (experimental).** Loopback execution RPC Helios verifies. **Setting this selects the trustless Helios path** over the raw path. |
| `HELIOS_CONSENSUS_RPC` | `http://127.0.0.1:18550` | Loopback beacon (consensus) RPC for Helios light-client sync (`helios` builds) |
| `HELIOS_CHECKPOINT` | (unset; **required once `HELIOS_EXECUTION_RPC` selects the Helios path**) | 0x 32-byte weak-subjectivity beacon block root, refreshed < ~2 weeks old. Without it Helios init fails closed (no untrusted community fallback). |
| `HELIOS_STRICT_CHECKPOINT_AGE` | `true` | Refuse a `HELIOS_CHECKPOINT` older than the safe weak-subjectivity window (~2 weeks) — Helios init fails closed instead of syncing from a stale trust root. Only the literal `false` or `0` disable it; any other value leaves it on. Disable for local/dev replay only. |
| `HELIOS_NETWORK` | `mainnet` | `mainnet` \| `sepolia` \| `holesky` (`helios` builds). Must be consistent with the pinned `EVM_CHAIN_ID` (mainnet=1 / sepolia=11155111 / holesky=17000) or Helios init fails closed. |
| `HELIOS_EXECUTION_VSOCK_PORT` / `HELIOS_CONSENSUS_VSOCK_PORT` | `8003` / `8004` | vsock ports for the host's Helios exec/consensus proxies |
| `HELIOS_EXECUTION_LOCAL_PORT` / `HELIOS_CONSENSUS_LOCAL_PORT` | `18545` / `18550` | Loopback ports the enclave exposes those upstreams on |

#### Parent Adapter

| Variable | Default | Description |
|----------|---------|-------------|
| `GRPC_PORT` | `5000` | Port for the gRPC server |
| `ENCLAVE_ADDR` | `127.0.0.1:5000` | Enclave TCP address (dev mode) |
| `USE_VSOCK` | `false` | Use vsock instead of TCP |
| `ENCLAVE_VSOCK_CID` | `16` | Enclave vsock CID (production) |
| `ENCLAVE_VSOCK_PORT` | `5000` | Enclave vsock port |

## Testing

```bash
# Run all tests
cargo test

# Run with RGB validation tests (send/receive flow)
cargo test -p utexo-bridge-enclave --features rgb-validation,rgb-swap

# Same, for the mint/burn flow
cargo test -p utexo-bridge-enclave --no-default-features --features rgb,rgb-mint-burn

# Run with SPV tests (implies rgb-validation; covers the full sign-path gate)
cargo test -p utexo-bridge-enclave --features spv,rgb-swap

# Run with seed import tests
cargo test -p utexo-bridge-enclave --features allow-seed-import

# Run gRPC bridge integration tests
cargo test --manifest-path parent/Cargo.toml
```

### Test coverage (96 tests)

| Category | Count | What it covers |
|----------|-------|----------------|
| Enclave unit tests | 62 | Key derivation (BIP-84 + BIP-86), mnemonic import, master fingerprint, taproot Schnorr signing, framing, EIP-712 digest, cross-checks, consignment hash integrity, RGB deserialization |
| Enclave integration tests | 20 | Full wire-protocol: keygen, signing roundtrips, cross-check rejections, consignment hash via real TCP |
| gRPC bridge tests | 7 | Full gRPC → Parent Adapter → mock enclave roundtrips, error paths, consignment passthrough verification |
| RGB validator unit tests | 2 | Bad bytes rejection, unknown network rejection |

## Feature flags

| Feature | Description |
|---------|-------------|
| `vsock` | Enable vsock transport (production, Linux only) |
| `rgb-validation` | In-enclave RGB consignment validation via rgbstd + Esplora |
| `spv` | Bitcoin SPV verification of consignment witness txids before signing EVM transactions. Implies `rgb-validation` (needed to extract witness txids). When OFF, `handle_sign_evm` additionally **rejects** any request that carries a non-empty `merkle_proofs` field — fail-closed against build mismatches between listener and enclave. |
| `rgb-swap` | **RGB flow selection** — send/receive (pools): the bridge holds an allocation and moves it with IFA `Transfer` in both directions. In the default feature set. |
| `rgb-mint-burn` | **RGB flow selection** — the bridge owns the contract's inflation rights: deposits mint with IFA `Inflation`, withdrawals destroy with IFA `Burn`. Needs `--no-default-features`. |
| `allow-seed-import` | Allow raw 64-byte seed or BIP-39 mnemonic import (testing only, never enable in production) |
| `dev-mode` | Skip cross-check validation on signing requests (development only) |

**Exactly one RGB flow.** An `rgb-validation` build must enable `rgb-swap` or
`rgb-mint-burn`, never both and never neither — a `compile_error!` pair in
`enclave/src/lib.rs` enforces it, and CI asserts both guards fire. The two flows
differ only in which RGB transition types they accept and how the amounts bind,
but those are the checks that authorize value to move, so they are split per
file (`enclave/src/networks/rgb/flow/`) and per image rather than branched at
runtime: a send/receive enclave carries no mint rule to reach. Everything else
about consignment validation — parsing, SPV anchoring, the PSBT txid bind,
sighash guard, leg split and fee bound — is shared.

## Protocol

### Enclave wire protocol

Wire format: `[4-byte LE length][protobuf payload]`

All messages are defined in
[`enclave-proto/proto/enclave.proto`](enclave-proto/proto/enclave.proto), the
vendored copy this repo actually compiles.
The enclave accepts one `EnclaveRequest` per connection and returns one
`EnclaveResponse`.

### gRPC interface (Parent Adapter)

Defined in `proto/enclave/parent.proto` in the upstream
[federated-signer-proto](https://github.com/UTEXO-Protocol/federated-signer-proto)
repo, which the parent consumes as a git dependency (not vendored here).
The Go Listener connects to the parent gRPC service, which transforms requests
before forwarding them to the enclave.

### Enriched payloads

`proto/enriched/payload.proto` in the upstream
[federated-signer-proto](https://github.com/UTEXO-Protocol/federated-signer-proto)
repo defines `EnrichedPsbtPayload` and `EnrichedEvmPayload` for the enriched
data format. Parent-side only; not vendored here.

### Proto source

The schema is split deliberately, and so are the cargo workspaces:

| | Enclave | Parent |
|---|---|---|
| Schema | [`enclave-proto/`](enclave-proto/), vendored in-tree | `federated-signer-proto`, git dep over SSH |
| Packages | `enclave` only | `bridge` / `node` / `orchestrator` / `parent` / `signer` |
| Workspace | repo root | `parent/` (its own root + lockfile) |
| Credentials to build | none for the proto | deploy key required |

```toml
# enclave/Cargo.toml
enclave-proto = { path = "../enclave-proto" }

# parent/Cargo.toml
federated-signer-proto = { git = "ssh://git@github.com/UTEXO-Protocol/federated-signer-proto.git", rev = "..." }
```

**Why the workspaces are split.** Cargo materialises every git source declared
anywhere in a workspace during resolution, before it knows which crates a `-p`
build actually compiles. While `parent` was a member, its private proto dep made
even `cargo build -p utexo-bridge-enclave --no-default-features` demand that
credential — which would have defeated the point of vendoring. Splitting them is
what makes the enclave, and therefore PCR0, reproducible by anyone. Build the
parent from its own directory:

```bash
cargo build --manifest-path parent/Cargo.toml     # not `-p utexo-bridge-parent`
```

**Why the generated code is committed.** `protoc` / buf plugin versions affect
the generated Rust, and no crate in either workspace has a `build.rs`. Shipping
pre-generated code keeps the codegen toolchain out of the inputs that determine
the enclave binary — and therefore out of PCR0.

Provenance, verification against upstream, and the re-sync procedure are in
[`enclave-proto/README.md`](enclave-proto/README.md). The two sides are pinned
to the same upstream commit and must be re-synced together; re-syncing changes
PCR0, so treat it as a measurement-affecting change.

## Security model

- **No unsafe code** — `#![deny(unsafe_code)]` enforced in the enclave crate.
- **Zeroize-on-drop** — All seeds and private keys wrapped in `SecretBox`. Memory zeroed on drop.
- **In-enclave RGB validation** — Consignments validated inside the TEE via rgbstd, not trusted from external sources.
- **In-enclave EVM FundsIn verification** (`evm-rpc`) — bridge-mode `signPsbt` confirms the EVM deposit itself via `eth_getTransactionReceipt`, instead of trusting the listener's `evm_event_valid`/`evm_event_finalized` flags. The RPC is reached through the untrusted host, so responses are treated as evidence (verified fail-closed) and this becomes trustless only once Helios verifies them. A build **without** this feature refuses bridge-mode `signPsbt` outright (the deposit cannot be verified), so production EIFs MUST enable `evm-rpc` (or `helios`).
- **Trustless EVM verification via Helios** (`helios` — EXPERIMENTAL, default-OFF, not in the shipped EIF) — embeds the a16z Helios light client so the enclave cryptographically verifies the execution/consensus RPCs against a pinned weak-subjectivity checkpoint before accepting a FundsIn receipt. Runtime-selectable (`HELIOS_EXECUTION_RPC` set → verified path, else the raw path) and fail-closed (an unsynced/errored Helios refuses signing, never downgrades). Heavy build (a second alloy major, revm, BLS, vendored OpenSSL); no production experience yet.
- **Cross-check validation** — Amount consistency, calldata extraction, deadline, and chain/domain checks before any signature is produced.
- **Seed import gated** — Raw seed import requires `allow-seed-import` feature, never enabled in production.
- **Nitro Enclave isolation** — No persistent storage, no network access (only vsock), no shell.
- **vsock-proxy allowlist** — Enclave can only reach Esplora (and, for `evm-rpc` builds, the EVM RPC) through the host's vsock-proxy with explicit allowlist.
- **Release hardening** — `opt-level = "z"`, LTO, symbol stripping, `panic = "abort"`, single codegen unit.
- **gRPC localhost-only** — Parent Adapter binds to `127.0.0.1`, not `0.0.0.0`.

## Project structure

```
.
├── Cargo.toml                        # Workspace root + [patch.crates-io] for RGB deps
├── enclave-proto/                    # Vendored `enclave` schema slice (see its README)
│   ├── proto/enclave.proto           # Enclave wire protocol, source of truth
│   └── src/enclave.rs                # Pre-generated Rust, verbatim (no build.rs)
├── enclave/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                    # Library root + proto modules
│       ├── main.rs                   # Entry point (vsock forwarder, RGB validator, listener)
│       ├── server.rs                 # ServerContext, request dispatch, all handlers
│       ├── keys.rs                   # BIP-39/BIP-32 key management (EnclaveState)
│       ├── framing.rs                # Length-prefixed protobuf wire format
│       ├── error.rs                  # Error types with gRPC code mapping
│       ├── vsock_forwarder.rs        # TCP→vsock forwarder for Esplora access
│       ├── signing/
│       │   ├── evm.rs                # EIP-712 domain/digest construction
│       │   └── psbt.rs               # SegWit v0 P2WSH PSBT signing
│       └── validation/
│           ├── evm_crosscheck.rs     # EVM request cross-checks (amounts, calldata, hash)
│           ├── psbt_crosscheck.rs    # PSBT request cross-checks
│           └── rgb.rs                # RGB consignment validation (rgbstd + Esplora)
├── parent/                           # SEPARATE cargo workspace (own Cargo.lock)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                    # Library root + grpc_proto + enclave_proto modules
│       ├── main.rs                   # gRPC server startup (tonic)
│       ├── grpc_server.rs            # EnclaveService implementation (translation layer)
│       ├── config.rs                 # Environment-based configuration
│       ├── client.rs                 # Enclave TCP/vsock RPC client
│       ├── framing.rs                # Wire format (shared with enclave)
│       ├── error.rs                  # Error types
│       └── bin/
│           └── cli.rs                # CLI tool (init, get-keys, sign-evm, sign-psbt, REPL)
├── build/
│   ├── Dockerfile.enclave            # Multi-stage Docker build
│   ├── build-enclave.sh              # EIF build + PCR extraction
│   ├── deploy-to-ec2.sh             # rsync to Nitro EC2 instance
│   ├── entrypoint.sh                 # Enclave runtime init (loopback + exec)
│   └── smoke-test.sh                 # Comprehensive RPC smoke tests
└── .vscode/
    └── settings.json                 # Rust Analyzer: enables rgb-validation + allow-seed-import
```

## License

TBD
