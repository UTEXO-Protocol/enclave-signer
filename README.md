# utexo-bridge-signer

Cryptographic signing service for the UTEXO RGB-EVM bridge, running inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/). The enclave generates HD wallet keys, signs EVM (EIP-712) and BTC (PSBT) transactions, and validates RGB consignments against an Esplora indexer — all within the TEE so private keys never leave the enclave.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Go Listener (federated-signer-node)                             │
│  Receives signing requests from Orchestrator, enriches with      │
│  EVM event data + RGB consignment, forwards via gRPC             │
└───────────────────────┬──────────────────────────────────────────┘
                        │ gRPC (parentadapter.proto)
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
  - Colored (RGB): `m/86'/827167'/0'`
- Returns master fingerprint (4 bytes) for cosigner identification in multisig descriptors

### Signing

- **EVM (EIP-712)** — Signs typed data for the MultisigProxy contract (fundsOut). Builds EIP-712 domain from chain_id + proxy_contract, computes struct hash from calldata/nonce/deadline, signs with recoverable ECDSA (65 bytes: r+s+v).
- **PSBT (SegWit v0 P2WSH)** — Signs matching inputs in a partially signed Bitcoin transaction. Matches inputs by BIP-32 derivation path or witness script pubkey match.
- **Raw message** — Signs arbitrary bytes (keccak256-hashed) for fundsIn authorization (1-of-n).

### Validation (before signing)

- **RGB consignment validation** (feature `rgb-validation`) — Deserializes the RGB `Transfer` consignment, creates an Esplora-backed resolver, runs rgbstd's full validation pipeline inside the TEE. Replaces trusting the Go Listener's boolean.
- **Consignment hash integrity** — Verifies `keccak256(consignment) == consignment_hash` to catch tampering.
- **Amount cross-checks** — Verifies `rgb_amount >= calldata_amount + commission`, extracts and compares amounts from raw calldata bytes.
- **Calldata extraction** — Reads uint256 values at ABI offsets to verify declared amounts match actual calldata.
- **Deadline check** — Rejects expired signing requests.
- **Chain/domain validation** — Requires valid `chain_id` and 20-byte `proxy_contract` for EIP-712 domain.

### gRPC bridge (Parent Adapter)

- Implements `EnclaveService` from `parentadapter.proto` (the Go Listener's gRPC interface)
- Translates `PSBTSigningFlow` / `EVMSigningFlow` into enclave-native `SignPsbtRequest` / `SignEvmRequest`
- Passes consignment bytes through for in-enclave validation
- 30-second timeout on enclave requests, binds to localhost only

## Enclave operations

| Operation | Description |
|-----------|-------------|
| `InitializeKey` | Generate keys from OS entropy (or import raw seed / BIP-39 mnemonic in test mode) |
| `GetPublicKey` | Retrieve EVM address, BTC pubkeys, master fingerprint, and BIP-86 account xpubs (vanilla + colored) |
| `SignEvm` | EIP-712 typed data signing with cross-check validation |
| `SignPsbt` | SegWit v0 P2WSH PSBT signing with cross-check validation |
| `SignRawMessage` | Keccak256-hash-then-sign for fundsIn authorization |
| `ProxyFederation` | Federation signature proxy (stub, not yet wired) |

## Prerequisites

- **Rust 1.85+** (stable)
- **protobuf compiler** (`protoc`)

```bash
# macOS
brew install protobuf

# Ubuntu / Amazon Linux
sudo apt-get install -y protobuf-compiler   # Debian/Ubuntu
sudo dnf install -y protobuf-compiler       # Amazon Linux 2023
```

For building the Nitro Enclave image (on EC2 only): Docker + `nitro-cli`.

## Building

### Local development (TCP mode)

```bash
# Build everything
cargo build

# Build with RGB validation support
cargo build -p utexo-bridge-enclave --features rgb-validation

# Build only the gRPC server (Parent Adapter)
cargo build -p utexo-bridge-parent
```

### Production (Nitro Enclave)

```bash
# Build the enclave binary with vsock + RGB validation
cargo build --release -p utexo-bridge-enclave --features vsock,rgb-validation

# Or build the full Enclave Image Format (EIF)
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
RUST_LOG=debug cargo run -p utexo-bridge-parent
```

Use the CLI tool directly:

```bash
# Initialize keys (generate new mnemonic)
cargo run --bin utexo-bridge-parent-cli -- init

# Initialize keys from a known mnemonic (requires allow-seed-import feature)
cargo run --features allow-seed-import --bin utexo-bridge-parent-cli -- \
  init-mnemonic "word1 word2 word3 ... word12"

# Get public keys
cargo run --bin utexo-bridge-parent-cli -- get-keys

# Sign an EVM transaction
cargo run --bin utexo-bridge-parent-cli -- sign-evm \
  --call-data <hex> --nonce 1 --deadline 9999999999 \
  --chain-id 1 --proxy-contract <hex>

# Interactive REPL
cargo run --bin utexo-bridge-parent-cli -- interactive
```

### Production (Nitro Enclave)

```bash
# Start the enclave
nitro-cli run-enclave \
  --cpu-count 2 --memory 512 --enclave-cid 16 \
  --eif-path build/utexo-bridge-enclave.eif

# Start vsock-proxy for Esplora access (on the host)
vsock-proxy 8001 <esplora-host> <esplora-port>

# Start the gRPC server (Parent Adapter)
GRPC_PORT=5000 USE_VSOCK=true cargo run --release -p utexo-bridge-parent
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
| `ESPLORA_VSOCK_PORT` | `8001` | vsock port for the host's vsock-proxy |

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

# Run with RGB validation tests
cargo test -p utexo-bridge-enclave --features rgb-validation

# Run with seed import tests
cargo test -p utexo-bridge-enclave --features allow-seed-import

# Run gRPC bridge integration tests
cargo test -p utexo-bridge-parent
```

### Test coverage (92 tests)

| Category | Count | What it covers |
|----------|-------|----------------|
| Enclave unit tests | 58 | Key derivation (BIP-84 + BIP-86), mnemonic import, master fingerprint, framing, EIP-712 digest, cross-checks, consignment hash integrity, RGB deserialization |
| Enclave integration tests | 20 | Full wire-protocol: keygen, signing roundtrips, cross-check rejections, consignment hash via real TCP |
| gRPC bridge tests | 7 | Full gRPC → Parent Adapter → mock enclave roundtrips, error paths, consignment passthrough verification |
| RGB validator unit tests | 2 | Bad bytes rejection, unknown network rejection |

## Feature flags

| Feature | Description |
|---------|-------------|
| `vsock` | Enable vsock transport (production, Linux only) |
| `rgb-validation` | In-enclave RGB consignment validation via rgbstd + Esplora |
| `allow-seed-import` | Allow raw 64-byte seed or BIP-39 mnemonic import (testing only, never enable in production) |
| `dev-mode` | Skip cross-check validation on signing requests (development only) |

## Protocol

### Enclave wire protocol

Wire format: `[4-byte LE length][protobuf payload]`

All messages are defined in [`proto/enclave.proto`](proto/enclave.proto). The enclave accepts one `EnclaveRequest` per connection and returns one `EnclaveResponse`.

### gRPC interface (Parent Adapter)

Defined in [`proto/parentadapter.proto`](proto/parentadapter.proto) (copied from the Go `federated-signer-node` repo). The Go Listener connects to `EnclaveService.Sign()` and `EnclaveService.GetPublicKeys()`.

### Enriched payloads

[`proto/enriched-payload.proto`](proto/enriched-payload.proto) defines `EnrichedPsbtPayload` and `EnrichedEvmPayload` for the enriched data format.

## Security model

- **No unsafe code** — `#![deny(unsafe_code)]` enforced in the enclave crate.
- **Zeroize-on-drop** — All seeds and private keys wrapped in `SecretBox`. Memory zeroed on drop.
- **In-enclave RGB validation** — Consignments validated inside the TEE via rgbstd, not trusted from external sources.
- **Cross-check validation** — Amount consistency, calldata extraction, deadline, and chain/domain checks before any signature is produced.
- **Seed import gated** — Raw seed import requires `allow-seed-import` feature, never enabled in production.
- **Nitro Enclave isolation** — No persistent storage, no network access (only vsock), no shell.
- **vsock-proxy allowlist** — Enclave can only reach Esplora through the host's vsock-proxy with explicit allowlist.
- **Release hardening** — `opt-level = "z"`, LTO, symbol stripping, `panic = "abort"`, single codegen unit.
- **gRPC localhost-only** — Parent Adapter binds to `127.0.0.1`, not `0.0.0.0`.

## Project structure

```
.
├── Cargo.toml                        # Workspace root + [patch.crates-io] for RGB deps
├── proto/
│   ├── enclave.proto                 # Enclave wire protocol (all request/response types)
│   ├── parentadapter.proto           # gRPC service (Go Listener interface)
│   └── enriched-payload.proto        # Enriched payload definitions
├── enclave/
│   ├── Cargo.toml
│   ├── build.rs                      # Protobuf codegen (prost)
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
├── parent/
│   ├── Cargo.toml
│   ├── build.rs                      # tonic-build (gRPC) + prost-build (enclave proto)
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
