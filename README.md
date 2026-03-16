# utexo-bridge-signer

Cryptographic key management service running inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) for the UTEXO bridge. The enclave generates and holds BIP-39 HD wallet keys, derives EVM and BTC public keys, and exposes them over a protobuf-based RPC protocol. A host-side CLI client communicates with the enclave over vsock (production) or TCP (development).

## Architecture

```
┌──────────────────────────────────────────────┐
│  EC2 Host (Parent)                           │
│                                              │
│  utexo-bridge-parent ──vsock:5000──┐         │
│  (CLI client)                      │         │
│                                    ▼         │
│  ┌──────────────────────────────────────┐    │
│  │  Nitro Enclave                       │    │
│  │                                      │    │
│  │  utexo-bridge-enclave                │    │
│  │  ├── BIP-39 mnemonic generation      │    │
│  │  ├── EVM key derivation (m/44'/60')  │    │
│  │  ├── BTC key derivation (m/84'/0')   │    │
│  │  └── Protobuf RPC server             │    │
│  └──────────────────────────────────────┘    │
└──────────────────────────────────────────────┘
```

The project is a Cargo workspace with two crates:

| Crate | Description |
|-------|-------------|
| **`enclave/`** | Runs inside the Nitro Enclave. Generates keys, derives addresses, serves RPC requests. |
| **`parent/`** | Runs on the EC2 host. CLI client that talks to the enclave over vsock or TCP. |

## What it does

- **Key generation** — Generates a BIP-39 mnemonic from OS entropy (`getrandom`), derives a 64-byte seed, and stores it in memory wrapped in `SecretBox` (zeroize-on-drop).
- **EVM address derivation** — Derives `m/44'/60'/0'/0/0` (standard Ethereum path), computes the 20-byte address via `keccak256(uncompressed_pubkey[1..])[12..]`.
- **BTC public key derivation** — Derives `m/84'/0'/0'/0/0` (SegWit v0 path), produces a 33-byte compressed secp256k1 public key and a BIP-32 xpub.
- **Protobuf RPC** — Length-prefixed protobuf messages over vsock (production) or TCP (development). One request/response per connection, 4 MB message size limit.

### Current operations

| Operation | Description |
|-----------|-------------|
| `InitializeKey` | Generate new keys from OS entropy (or import a raw seed in test mode) |
| `GetPublicKey` | Retrieve the EVM address, BTC compressed pubkey, and xpub |

### Planned operations (reserved in proto)

- `SignEvm` — EIP-712 typed data signing with ECDSA
- `SignPsbt` — SegWit v0 PSBT signing
- `GetAttestation` — Nitro attestation document
- `Clone` — Key cloning between enclaves
- `HealthCheck` — Liveness probe

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

For building the Nitro Enclave image (on EC2 only):

- Docker
- `nitro-cli` (AWS Nitro Enclaves CLI)

## Building

### Local development (TCP mode)

```bash
# Build both crates
cargo build

# Build only the enclave
cargo build -p utexo-bridge-enclave

# Build only the parent CLI
cargo build -p utexo-bridge-parent
```

### Production (vsock mode for Nitro Enclave)

```bash
# Build the enclave binary with vsock support
cargo build --release -p utexo-bridge-enclave --features vsock

# Or build the full Enclave Image Format (EIF) on a Nitro-enabled EC2 instance
./build/build-enclave.sh
```

The build script will:
1. Build a Docker image with the enclave binary
2. Convert it to an EIF via `nitro-cli build-enclave`
3. Output PCR measurements (PCR0/1/2) for KMS attestation policies
4. Save the EIF to `build/utexo-bridge-enclave.eif`

## Running

### Local development

Start the enclave server (TCP on `127.0.0.1:5000`):

```bash
RUST_LOG=debug cargo run -p utexo-bridge-enclave
```

In another terminal, use the parent CLI:

```bash
# Initialize keys (generates new mnemonic)
cargo run -p utexo-bridge-parent -- init

# Retrieve public keys
cargo run -p utexo-bridge-parent -- get-keys

# Interactive REPL mode
cargo run -p utexo-bridge-parent -- interactive
```

REPL commands: `init`, `init-seed <hex>`, `get-keys`, `help`, `quit`.

### Production (Nitro Enclave)

```bash
# Start the enclave (production — KMS attestation works)
nitro-cli run-enclave \
  --cpu-count 2 --memory 512 --enclave-cid 16 \
  --eif-path build/utexo-bridge-enclave.eif

# Start the enclave (debug — console output, PCRs zeroed)
nitro-cli run-enclave \
  --cpu-count 2 --memory 512 --enclave-cid 16 \
  --eif-path build/utexo-bridge-enclave.eif --debug-mode

# Read enclave console (debug mode only)
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# Use the parent CLI (auto-connects to vsock CID 16, port 5000)
cargo run --release -p utexo-bridge-parent --features vsock -- init
```

## Testing

```bash
# Run all tests
cargo test

# Run with output (see key values printed during tests)
cargo test -- --nocapture

# Run deterministic seed import test (requires feature flag)
cargo test -p utexo-bridge-enclave --features allow-seed-import

# Run a specific test
cargo test -p utexo-bridge-enclave initialize_and_get_keys
```

### Test coverage

| Test | What it verifies |
|------|-----------------|
| `roundtrip_encode_decode` | Protobuf framing round-trip (encode → decode) |
| `reject_oversized_message` | Messages > 4 MB are rejected |
| `reject_zero_length_message` | Zero-length messages are rejected |
| `initialize_and_get_keys` | Full lifecycle: init → get keys → values match |
| `double_initialize_returns_error` | Re-initialization is blocked |
| `get_keys_before_init_returns_error` | Accessing keys before init returns error |
| `deterministic_seed_import` | Same seed produces identical keys across instances |

Plus unit tests in `keys.rs` for derivation consistency, key format validation, and secret handling.

## Protocol

Wire format: `[4-byte LE length][protobuf payload]`

All messages are defined in [`proto/enclave.proto`](proto/enclave.proto). The enclave accepts one `EnclaveRequest` per connection and returns one `EnclaveResponse`.

## Security model

- **No unsafe code** — `#![deny(unsafe_code)]` enforced in the enclave crate.
- **Zeroize-on-drop** — All seeds and private keys are wrapped in `SecretBox` from the `secrecy` crate. Memory is zeroed when values go out of scope.
- **Seed import gated** — Raw seed import requires the `allow-seed-import` Cargo feature, which must never be enabled in production builds.
- **Nitro Enclave isolation** — In production, the enclave runs in a Nitro Enclave VM with no persistent storage, no network access, and no shell. Communication is restricted to vsock.
- **Release binary hardening** — Release builds use `opt-level = "z"`, LTO, symbol stripping, `panic = "abort"`, and single codegen unit.

## Project structure

```
.
├── Cargo.toml                  # Workspace root
├── Cargo.lock
├── proto/
│   └── enclave.proto           # Protobuf service definitions
├── enclave/
│   ├── Cargo.toml
│   ├── build.rs                # Protobuf codegen
│   ├── src/
│   │   ├── lib.rs              # Library root + proto module
│   │   ├── main.rs             # Enclave binary entry point
│   │   ├── keys.rs             # Key generation, derivation, state management
│   │   ├── server.rs           # Request dispatcher and handlers
│   │   ├── framing.rs          # Length-prefixed protobuf wire format
│   │   ├── error.rs            # Error types
│   │   └── signing/
│   │       └── mod.rs          # (placeholder for EVM + PSBT signing)
│   └── tests/
│       ├── common/mod.rs       # Test server harness
│       ├── test_framing.rs     # Framing protocol tests
│       └── test_keygen.rs      # Key lifecycle integration tests
├── parent/
│   ├── Cargo.toml
│   ├── build.rs                # Protobuf codegen
│   └── src/
│       ├── lib.rs              # Library root + proto module
│       ├── main.rs             # Host-side CLI (clap)
│       ├── client.rs           # Enclave RPC client
│       ├── framing.rs          # Wire format (shared logic)
│       └── error.rs            # Error types
└── build/
    ├── Dockerfile.enclave      # Multi-stage Docker build
    ├── build-enclave.sh        # EIF build + PCR extraction script
    └── entrypoint.sh           # Enclave runtime init (loopback + exec)
```

## License

TBD
