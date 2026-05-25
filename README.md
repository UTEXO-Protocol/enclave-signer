# utexo-bridge-signer

Cryptographic signing service for the UTEXO RGB-EVM bridge, running inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/). The enclave generates HD wallet keys, signs EVM (EIP-712) and BTC (PSBT) transactions, and validates RGB consignments + Bitcoin SPV proofs against an Esplora indexer — all within the TEE so private keys never leave the enclave. Operators can prove the running keys belong to a specific code measurement via NSM attestation, and stand up replicas via an enclave-to-enclave cloning handshake.

## Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│  Go Listener (federated-signer-node)                             │
│  Receives signing requests from Orchestrator, enriches with      │
│  EVM event data + RGB consignment + Bitcoin Merkle proofs,       │
│  pushes block headers, forwards via gRPC                         │
└───────────────────────┬──────────────────────────────────────────┘
                        │ gRPC (parentadapter.proto)
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│  EC2 Host                                                        │
│                                                                  │
│  utexo-bridge-parent (gRPC server + CLI + attest-verify)         │
│  ├── Translates gRPC → enclave wire protocol                     │
│  ├── PSBTSigningFlow / EVMSigningFlow → SignPsbtRequest /        │
│  │   SignEvmRequest (with consignment + merkle proofs)           │
│  ├── Drives cloning handshake (Initialize / Clone)               │
│  ├── Forwards SubmitHeaders / GetLastSavedBlock for SPV sync     │
│  └── TCP / vsock to enclave                                      │
│                                                                  │
│  vsock-proxy 8001 → Esplora API  (for RGB validation only)       │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Nitro Enclave                                              │  │
│  │                                                             │  │
│  │  utexo-bridge-enclave                                       │  │
│  │  ├── BIP-39 key gen (EVM m/44'/60', BTC m/84' + m/86')     │  │
│  │  ├── EIP-712 signing (EVM → RGB direction)                  │  │
│  │  ├── PSBT signing — taproot (Schnorr) + P2WSH (ECDSA)       │  │
│  │  ├── RGB consignment validation (rgbstd + Esplora)          │  │
│  │  ├── Bitcoin SPV header chain + Merkle inclusion verifier   │  │
│  │  ├── Cross-checks: selector whitelist, amounts, deadlines,  │  │
│  │  │   PSBT shape, EIP-712 domain, consignment hash           │  │
│  │  ├── NSM attestation (cloning + GetAttestedPublicKey)       │  │
│  │  ├── X25519 + HKDF + ChaCha20Poly1305 cloning handshake     │  │
│  │  ├── vsock forwarder (localhost → vsock → Esplora)          │  │
│  │  └── Protobuf RPC server (vsock:5000 / TCP:5000)            │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Documentation

In-tree design docs live under [`docs/`](docs/):

- [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md) — verifying that the bridge's EVM signing key belongs to a specific Nitro Enclave PCR measurement, with the canonical bundle encoding and full verification recipe.

The wire protocol is documented inline in the `.proto` files under [`proto/`](proto/).

## Workspace crates

| Crate | Binary | Description |
|-------|--------|-------------|
| [`enclave/`](enclave/) | `utexo-bridge-enclave` | Runs inside the Nitro Enclave. Key management, signing, RGB validation, SPV verification, attestation, cloning. |
| [`parent/`](parent/) | `utexo-bridge-parent` | gRPC server (Parent Adapter) — translates Go Listener RPCs to the enclave wire protocol. |
| [`parent/`](parent/) | `utexo-bridge-parent-cli` | CLI tool for direct enclave interaction (testing, key init, manual signing, header sync). |
| [`parent/`](parent/) | `attest-verify` | Standalone CLI that verifies an enclave attestation document end-to-end against expected PCRs (see [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md)). |
| [`attestation-verify/`](attestation-verify/) | (library only) | Shared AWS Nitro attestation verifier (COSE_Sign1 + cert chain). Used by both the enclave (for peer attestation in cloning) and the `attest-verify` CLI. |

## What it does

### Key management

- Generates a BIP-39 mnemonic from OS entropy (or imports a mnemonic phrase in test mode), derives a 64-byte seed, stores it in `SecretBox` (zeroize-on-drop).
- EVM: derives `m/44'/60'/0'/0/0`, computes 20-byte address via `keccak256(uncompressed_pubkey[1..])[12..]`.
- BTC (legacy): derives `m/84'/0'/0'/0/0`, produces 33-byte compressed pubkey and BIP-32 xpub.
- BTC (BIP-86 taproot): derives two account-level xprivs for multisig descriptors:
  - Vanilla: `m/86'/<coin>'/0'` (coin type 0 mainnet, 1 testnet).
  - Colored (RGB): `m/86'/827167'/0'`.
- Returns master fingerprint (4 bytes) for cosigner identification in multisig descriptors.

### Signing

- **EVM (EIP-712)** — Signs typed data for the MultisigProxy contract (`fundsOut`). Builds EIP-712 domain from chain_id + proxy_contract, computes struct hash from calldata/nonce/deadline, signs with recoverable ECDSA (65 bytes: r+s+v).
- **PSBT (SegWit v0 P2WSH + Taproot)** — Signs matching inputs in a partially signed Bitcoin transaction. Auto-detects input type:
  - **Taproot script-path** (BIP-341/BIP-340): matches via `tap_key_origins` fingerprint, derives child keys per-input, signs with Schnorr into `tap_script_sigs`. Supports `multi_a()` tapscripts. Cosigner identity is anchored to `witness_utxo.script_pubkey` (not to `tap_key_origins` alone) so a malicious coordinator cannot trick the enclave into signing for a different output.
  - **SegWit v0 P2WSH** (legacy): cosigner identity anchored to `witness_utxo.script_pubkey`; `sha256(witness_script)` must match the witness program in the script_pubkey, and our pubkey must appear as a literal `OP_PUSHBYTES_33` push in the script.
- **Raw message** — Signs arbitrary bytes (keccak256-hashed) for fundsIn authorization (1-of-n).

### Validation (before signing)

The enclave applies the checks below before producing any signature. What the enclave **trusts** (the AWS Nitro hardware, the compiled-in checkpoints, the BIP-39 seed it generated or imported, the operator-pinned bridge config) is fixed at build/boot. Everything that crosses the wire from the host or the Listener is verified.

#### `signEvm` pipeline

When `--features spv` (the production combination) is enabled, `handle_sign_evm` runs the following gates in order, fail-closed on any:

1. **Bridge-config gate** (when configured via env) — `chain_id`, `proxy_contract`, and `rgb_asset_id` from the request must equal the enclave's boot-time `BridgeConfig`. A compromised Listener cannot redirect a signature to a different chain, contract, or asset.
2. **Selector whitelist** — `call_data[..4]` must be one of:
   - `0x1ad880b2` — legacy pools `fundsOut(address,address,uint256,uint256,string,string)`.
   - `0x179bef59` — mint/burn `fundsOut(address,uint256,uint256,uint256,uint256,uint256,string,bytes,bytes)`.

   Any other selector is rejected before any byte-level offset extraction runs.
3. **Consignment hash integrity** — `keccak256(consignment) == consignment_hash`. Catches tampering between the Listener computing the hash and the enclave signing.
4. **In-enclave RGB validation** (`rgb-validation`) — deserializes the consignment via `rgbstd::Transfer::load`, builds an Esplora-backed resolver (over the host's vsock-proxy), runs the full rgbstd validation pipeline, extracts:
   - `contract_id` (cross-checked against `rgb_asset_id`),
   - `chain_net` (cross-checked against the enclave's compiled Bitcoin network — rejects e.g. a regtest consignment against a mainnet enclave),
   - the deduplicated set of `witness_txids` (used by SPV below),
   - the last transition (op_id + transition type) and, for IFA burns, the `burnedAsset` metadata amount.

   The Listener's `consignment_valid` boolean is **not** authoritative when raw consignment bytes are present; the in-enclave validator is.
5. **SPV gate** (`spv`) — `handle_sign_evm` refuses to sign unless every consignment-anchor Bitcoin tx is independently confirmed on the chain the enclave has stored:
   - **Coverage** — the set of `merkle_proofs[].txid` must equal the set of witness txids extracted from the consignment (both directions; no extras, no missing).
   - **Inclusion** — every Merkle proof must reconstruct to the `merkle_root` committed in the header at `block_height` stored in the in-enclave chain.
   - **Confirmation depth** — every witness tx (not just the burn) must be ≥ `SPV_MIN_CONFIRMATIONS = 6` deep.
   - **Header validation** — headers submitted via `SubmitHeaders` are PoW-checked (mainnet retarget enforced via `bitcoin::CompactTarget::from_next_work_required`), chain-linked to the previous header, and rooted at the compiled-in checkpoint. Reorgs are accepted up to depth 100 only if the alternate chain has **strictly greater** cumulative work.
   - **Tip staleness** — refuse to sign if the in-enclave chain tip's `time` is more than 2 h behind wall clock, or more than 2 h ahead. Defends against a hostile Listener replaying old headers to freeze the enclave's view of the chain.

   When `spv` is **disabled** at build time, `handle_sign_evm` still rejects any request carrying a non-empty `merkle_proofs` field — fail-closed against build mismatches between Listener and enclave.
6. **Per-selector amount cross-checks** — for the legacy pools selector, `rgb_amount ≥ calldata_amount + calldata_commission`, plus byte-level `extract_uint256_as_u64(call_data, 68)` (amount) and `(call_data, 100)` (commission) must match the listener-declared values. For the mint/burn selector, the calldata `amount` at offset 36 must be ≤ the consignment's IFA burn-asset amount (spec §8 invariant: an unlock cannot release more EVM units than were destroyed on the RGB side).
7. **EIP-712 domain check** — `chain_id > 0` and `proxy_contract` is exactly 20 bytes.
8. **Deadline check** — `request.deadline > SystemTime::now()`.

If everything passes, the enclave builds the EIP-712 domain + struct hash and produces a 65-byte recoverable ECDSA signature.

#### `signPsbt` pipeline

The PSBT handler runs in one of two modes based on whether the request carries an EVM bridge context:

- **Bridge mode** (`evm_tx_hash` is 32 bytes): the Listener's `evm_event_valid` and `evm_event_finalized` booleans are required, `evm_amount ≥ psbt_output_amount + evm_commission`, and `evm_tx_hash` must be exactly 32 bytes. Independent in-enclave EVM event verification is on the roadmap (see [`docs/`](docs/)); today the enclave trusts the Listener's attestation for these two booleans.
- **Vanilla mode** (`evm_tx_hash` empty): only `psbt_bytes` non-empty is required. Used for `create_utxo` and other plain BTC operations.

Regardless of mode, every PSBT input is **independently authorized** at signing time by anchoring to `witness_utxo.script_pubkey`:

- **P2WSH input**: `script_pubkey` must be P2WSH; `sha256(witness_script)` must equal the witness program; our pubkey must appear as a literal `OP_PUSHBYTES_33` push inside the witness script. Closes both the "fabricated witness_script" and the "key bytes hidden inside a larger script" holes.
- **Taproot input**: `script_pubkey` must be P2TR; our key must appear in a tapscript leaf in `tap_scripts`; the `tap_key_origins` entry whose fingerprint matches ours must derive to that exact x-only key. Closes the gap where a coordinator could forge `tap_key_origins` to make the enclave sign for a different output.

PSBT shape validation against a strict whitelist of legitimate operation shapes is in flight (PR #40, [`feat/psbt-shape-validation`](https://github.com/UTEXO-Protocol/utexo-bridge-enclave-signer/pulls)).

### Attestation

The enclave exposes `GetAttestedPublicKey(nonce)` (over the wire protocol and the parent's gRPC). The response bundles:

- The full `PublicKeysResponse` (EVM address, BTC pubkeys, xpubs, master fingerprint, plus bridge-config fields when set).
- An NSM-produced COSE_Sign1 attestation document whose `public_key` field commits to the 64-byte uncompressed EVM signing key, `user_data` commits to `sha256(canonical_bundle)`, and `nonce` echoes the verifier's challenge.

A verifier that trusts only the AWS Nitro root CA and a known PCR0/1/2 can then prove: "the EVM address signing my bridge transactions was produced by code with PCR0=X, running on AWS Nitro hardware, at time T". The full recipe — chain validation, COSE signature shape, PCR/nonce/pubkey/commitment checks — is documented in [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md). The reference verifier is the `attest-verify` CLI; the same code path is used by the cloning handshake to verify peer attestations.

### Cloning (enclave-to-enclave seed transfer)

A fresh enclave can clone the HD seed from an already-provisioned peer of the same code measurement (same PCRs). The handshake is a three-message protocol authenticated by NSM attestation and a pre-shared operator secret:

1. **Parent → requester**: `InitiateCloning { cloning_secret, cluster_public_key }`. Requester generates an X25519 ephemeral keypair, asks NSM to attest the pubkey (in `public_key`) and an HMAC digest `HMAC-SHA256(cloning_secret, pubkey)` (in `user_data`), and returns `(attestation, pubkey, digest)`.
2. **Parent → donor (relayed)**: `GetClone { cluster_public_key, cloning_digest, encryption_pubkey, requester_attestation }`. Donor verifies the AWS Nitro cert chain, the COSE signature, the requester's PCRs (must match its own), the digest (must verify against its own `cloning_secret`), and that `cluster_public_key` matches its own EVM address. It then does X25519 DH against the requester's ephemeral pubkey, derives a symmetric key via HKDF-SHA256 (salt `utexo-cloning-v1`), seals the seed with ChaCha20Poly1305, and replies with `(ciphertext, donor_pubkey, donor_attestation)`.
3. **Parent → requester (relayed)**: `SetClone { encrypted_seed, donor_pubkey, donor_attestation }`. Requester verifies the donor attestation, unseals the ciphertext, derives a `KeyManager` from the seed, and checks the derived EVM address matches `cluster_public_key`. Transitions the enclave state machine to `Active`.

At the gRPC boundary the surface is simpler: `Initialize(cloning_secret)` (= `InitiateCloning` on the wire) and `Clone(attestation, encryption_pubkey)` (= `GetClone`). The parent drives `SetClone` over vsock internally. The `cloning_digest` never crosses the gRPC boundary — it is bound into the attestation's `user_data` and extracted by the donor post-verify. The replay guard caps nonces at 10 000 entries and rejects on overflow (rather than silently rolling the window).

### gRPC bridge (Parent Adapter)

- Implements `EnclaveService` from [`proto/parentadapter.proto`](proto/parentadapter.proto) (the Go Listener's gRPC interface).
- Translates `PSBTSigningFlow` / `EVMSigningFlow` into enclave-native `SignPsbtRequest` / `SignEvmRequest`.
- Passes consignment bytes + merkle proofs through for in-enclave validation.
- Forwards `SubmitHeaders` / `GetLastSavedBlock` to drive SPV sync.
- Drives the cloning handshake (`Initialize` / `Clone`) and the `AttestedPublicKey` RPC.
- 30-second timeout on enclave requests, binds to localhost only.

## Enclave operations

| Operation | Description |
|-----------|-------------|
| `InitializeKey` | Generate keys from OS entropy (or import raw seed / BIP-39 mnemonic in test mode). |
| `GetPublicKey` | Retrieve EVM address, BTC pubkeys, master fingerprint, BIP-86 account xpubs (vanilla + colored), and the operator-pinned bridge config (chain_id, bridge_contract, rgb_asset_id). |
| `GetAttestedPublicKey` | Same bundle as `GetPublicKey` plus an NSM attestation document binding it to the running enclave's PCRs. Verifier-supplied 32-byte nonce defends against replay. |
| `SignEvm` | EIP-712 typed data signing with the full cross-check + SPV pipeline above. |
| `SignPsbt` | Taproot (Schnorr) + SegWit v0 P2WSH (ECDSA) PSBT signing with per-input authorization anchored to `witness_utxo.script_pubkey`. |
| `SignRawMessage` | Keccak256-hash-then-sign for fundsIn authorization. |
| `SubmitHeaders` | Push a batch of raw 80-byte Bitcoin headers into the in-enclave chain. Validates PoW + retarget + chain linkage; supports bounded reorgs (≤100 deep, strictly greater cumulative work). |
| `GetLastSavedBlock` | Return the enclave's current tip (height + hash) so the Listener knows where to resume header sync. |
| `InitiateCloning` / `GetClone` / `SetClone` | Three-message X25519+HKDF+ChaCha20Poly1305 handshake for enclave-to-enclave seed transfer. |
| `ProxyFederation` | Federation signature proxy (stub, not yet wired). |

## Prerequisites

- **Rust 1.85+** (stable).
- **protobuf compiler** (`protoc`).

```bash
# macOS
brew install protobuf

# Ubuntu / Amazon Linux
sudo apt-get install -y protobuf-compiler   # Debian/Ubuntu
sudo dnf install -y protobuf-compiler       # Amazon Linux 2023
```

For building the Nitro Enclave image (on EC2 only): Docker + `nitro-cli`.

The RGB validation feature pulls `rgb-consignment-parser` via an SSH-style git URL, so CI / local builds need SSH access to `github.com/UTEXO-Protocol/rgb-consignment-parser` (deploy key or SSH agent forwarded into Docker).

## Building

### Local development (TCP mode)

```bash
# Build everything
cargo build

# Build with RGB validation support
cargo build -p utexo-bridge-enclave --features rgb-validation

# Build with SPV verification (implies rgb-validation). With --features spv,
# the enclave refuses to sign EVM transactions unless the request carries
# valid Bitcoin SPV proofs for every consignment-anchor witness tx.
# Without the feature, the enclave fails-closed if the request supplies
# merkle_proofs at all (catches build mismatches against the listener).
cargo build -p utexo-bridge-enclave --features spv

# Build only the gRPC server (Parent Adapter)
cargo build -p utexo-bridge-parent
```

### Production (Nitro Enclave)

```bash
# Build the enclave binary with vsock + RGB validation + SPV
cargo build --release -p utexo-bridge-enclave --features vsock,rgb-validation,spv

# Or build the full Enclave Image Format (EIF)
./build/build-enclave.sh
```

The build script builds a Docker image, converts it to an EIF via `nitro-cli build-enclave`, and outputs PCR measurements (PCR0/1/2) for KMS attestation policies and for distributing to external verifiers (see [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md)).

## Running

### Local development

Start the enclave server (TCP on `127.0.0.1:5000`):

```bash
RUST_LOG=debug cargo run -p utexo-bridge-enclave
```

> macOS note: port 5000 is occupied by AirPlay Receiver. Use `ENCLAVE_LISTEN_ADDR=127.0.0.1:5050` and point the parent / CLI at the same address.

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

# Drive SPV header sync from the CLI (testing only — production sync is
# driven by the Go Listener)
cargo run --bin utexo-bridge-parent-cli -- submit-headers \
  --start-height <h> --headers-file <path-to-binary-headers>
cargo run --bin utexo-bridge-parent-cli -- get-last-saved-block

# Interactive REPL
cargo run --bin utexo-bridge-parent-cli -- interactive
```

Verify the enclave attestation end-to-end:

```bash
# Production: against a real Nitro enclave, with PCRs from the release notes
attest-verify --endpoint http://parent.example:50051 \
    --pcr0 <96-hex-chars> --pcr1 <96-hex-chars> --pcr2 <96-hex-chars>

# Dev / CI: against an enclave built with --features mock-attestation
cargo run --bin attest-verify -- --endpoint http://127.0.0.1:50051 --mock
```

Exit codes: `0` = all eight checks pass, `1` = verification failed (stderr explains why), `2` = usage / IO / connection error. Full recipe in [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md).

### Running in production (Nitro Enclave)

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

> **Note:** In debug mode, PCR0/PCR1/PCR2 are all zeroed. KMS attestation policies that check PCR values will reject the enclave, and `attest-verify` will fail the PCR check. Use debug mode only for development/testing — never in production.

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
| `RUST_LOG` | (none) | Log level (e.g., `info`, `debug`). |
| `ENCLAVE_LISTEN_ADDR` | `127.0.0.1:5000` | Listen address when not built with `vsock`. Use `127.0.0.1:5050` on macOS to avoid AirPlay. |
| `ESPLORA_URL` | `http://127.0.0.1:3443` | Esplora API endpoint for RGB validation. |
| `BITCOIN_NETWORK` | `bitcoin` | One of: `bitcoin`, `testnet`, `signet`, `regtest`. Affects BIP-86 coin type (0 vs 1), xpub prefix (xpub vs tpub), and the SPV header-chain network constants. |
| `ESPLORA_VSOCK_PORT` | `8001` | vsock port for the host's vsock-proxy. |
| `UTEXO_CLONING_SECRET` | (none) | Pre-shared operator secret. When set, the enclave will participate in the cloning handshake as a donor. |
| `EVM_CHAIN_ID` | (unset) | If set, the enclave pins to this chain id and refuses to sign EVM requests for any other chain. Folded into the attestation `user_data` commitment so external verifiers can prove which chain the enclave is provisioned for. |
| `BRIDGE_CONTRACT` | (unset) | 0x-prefixed or bare 40-hex 20-byte EVM address. Same pinning + commitment behaviour as `EVM_CHAIN_ID`. |
| `RGB_ASSET_ID` | (unset) | Operator-pinned RGB contract id. Same pinning + commitment behaviour. |

When all three bridge-config vars are unset, the enclave runs in "unconfigured" mode: the strict cross-check is skipped, and the attestation commitment binds to zeros / the empty string — externally observable. Production deployments **must** set all three.

#### Parent Adapter

| Variable | Default | Description |
|----------|---------|-------------|
| `GRPC_PORT` | `5000` | Port for the gRPC server. |
| `ENCLAVE_ADDR` | `127.0.0.1:5000` | Enclave TCP address (dev mode). |
| `USE_VSOCK` | `false` | Use vsock instead of TCP. |
| `ENCLAVE_VSOCK_CID` | `16` | Enclave vsock CID (production). |
| `ENCLAVE_VSOCK_PORT` | `5000` | Enclave vsock port. |

## Testing

```bash
# Run the default-features test suite (small)
cargo test

# Run with RGB validation tests
cargo test -p utexo-bridge-enclave --features rgb-validation

# Run with SPV tests (implies rgb-validation; covers the full sign-path gate)
cargo test -p utexo-bridge-enclave --features spv

# Run with seed import tests
cargo test -p utexo-bridge-enclave --features allow-seed-import

# Run the full workspace under the production-shaped feature combo
cargo test --workspace \
    --features utexo-bridge-enclave/spv \
    --features utexo-bridge-enclave/allow-seed-import \
    --features utexo-bridge-enclave/mock-attestation

# Run gRPC bridge integration tests
cargo test -p utexo-bridge-parent
```

### Test coverage

Roughly 250 tests across the workspace under the full feature combo. The bulk lives in the enclave crate (~190 covering key derivation, mnemonic import, taproot Schnorr signing, EIP-712 digest, all cross-checks, RGB consignment validation, SPV header chain + reorg + Merkle inclusion, NSM attestation parsing, cloning crypto, framing, and end-to-end wire-protocol tests), with the rest split across the `attestation-verify` library, the gRPC bridge integration tests, and `attest-verify` end-to-end tests against a live mock-attestation enclave.

## Feature flags

| Feature | Description |
|---------|-------------|
| `vsock` | Enable vsock transport (production, Linux only). |
| `rgb-validation` | In-enclave RGB consignment validation via rgbstd + `rgb-consignment-parser` + Esplora. |
| `spv` | Bitcoin SPV verification of consignment witness txids before signing EVM transactions. Implies `rgb-validation` (needed to extract witness txids). When OFF, `handle_sign_evm` additionally **rejects** any request that carries a non-empty `merkle_proofs` field — fail-closed against build mismatches between listener and enclave. |
| `allow-seed-import` | Allow raw 64-byte seed or BIP-39 mnemonic import (testing only, never enable in production). |
| `dev-mode` | Skip cross-check validation on signing requests (development only). |
| `mock-attestation` | Use raw-CBOR attestation documents with all-zero PCRs instead of the NSM device. Testing only — `attest-verify --mock` is the matching verifier flag. |

## Protocol

### Enclave wire protocol

Wire format: `[4-byte LE length][protobuf payload]`.

All messages are defined in [`proto/enclave.proto`](proto/enclave.proto). The enclave accepts one `EnclaveRequest` per connection and returns one `EnclaveResponse`.

### gRPC interface (Parent Adapter)

Defined in [`proto/parentadapter.proto`](proto/parentadapter.proto) (mirrors the Go `federated-signer-node` repo). The Go Listener connects to `EnclaveService.Sign()`, `EnclaveService.PublicKey()`, `EnclaveService.Initialize()` / `Clone()` (cloning), `EnclaveService.SubmitHeaders()` / `GetLastSavedBlock()` (SPV sync), and `EnclaveService.AttestedPublicKey()` (attestation).

### Enriched payloads

[`proto/enriched-payload.proto`](proto/enriched-payload.proto) defines `EnrichedPsbtPayload` and `EnrichedEvmPayload` for the enriched data format, including `MerkleProofEntry` for SPV proofs.

## Security model

- **No unsafe code** — `#![deny(unsafe_code)]` enforced in the enclave crate.
- **Zeroize-on-drop** — all seeds and private keys wrapped in `SecretBox`; the X25519 cloning secret is `StaticSecret` with the `zeroize` feature; the decrypted seed during cloning is wrapped in `Zeroizing<[u8; 64]>`.
- **In-enclave RGB validation** — consignments validated inside the TEE via rgbstd + Esplora (over vsock-proxy), not trusted from the Listener.
- **In-enclave SPV verification** — Merkle inclusion + confirmation depth + tip-staleness verified against an in-enclave Bitcoin header chain bootstrapped from a compile-time checkpoint. Mainnet PoW retargets enforced; reorgs accepted only if strictly more cumulative work.
- **Cross-check pipeline** — selector whitelist, consignment hash integrity, amount consistency, calldata extraction at fixed offsets, EIP-712 domain, deadline, optional bridge-config pinning. Detailed above.
- **PSBT cosigner authorization anchored to `script_pubkey`** — neither `witness_script` nor `tap_key_origins` is trusted on its own; both must be consistent with the `witness_utxo.script_pubkey` we're signing into.
- **Operator-pinned bridge config** — when set, the enclave refuses to sign for any other (chain_id, bridge_contract, rgb_asset_id) tuple, and the tuple is committed in the attestation `user_data` so external verifiers can prove what the enclave was provisioned for.
- **NSM attestation** — `GetAttestedPublicKey` lets external verifiers cryptographically bind the EVM signing pubkey + full key bundle to specific PCR0/1/2 values. Peer attestations during cloning go through the same verifier (`attestation-verify` crate), with a 10 000-entry nonce replay guard.
- **Seed import gated** — raw seed / BIP-39 mnemonic import requires the `allow-seed-import` feature, never enabled in production builds.
- **Nitro Enclave isolation** — no persistent storage, no inbound network access (only vsock), no shell. Outbound Esplora access only via the host's explicitly allowlisted vsock-proxy.
- **Release hardening** — `opt-level = "z"`, LTO, symbol stripping, `panic = "abort"`, single codegen unit.
- **gRPC localhost-only** — Parent Adapter binds to `127.0.0.1`, not `0.0.0.0`.

## Project structure

```text
.
├── Cargo.toml                        # Workspace root + [patch.crates-io] for RGB deps
├── proto/
│   ├── enclave.proto                 # Enclave wire protocol (all request/response types)
│   ├── parentadapter.proto           # gRPC service (Go Listener interface)
│   ├── enriched-payload.proto        # Enriched payload definitions (+ MerkleProofEntry)
│   └── signer/signer.proto           # Shared message types used by parentadapter.proto
├── attestation-verify/               # Library crate — shared AWS Nitro attestation verifier
│   ├── Cargo.toml
│   └── src/lib.rs                    # COSE_Sign1 parse + cert chain + mock path
├── enclave/
│   ├── Cargo.toml
│   ├── build.rs                      # Protobuf codegen (prost)
│   └── src/
│       ├── lib.rs                    # Library root + proto modules
│       ├── main.rs                   # Entry point (vsock forwarder, RGB validator, listener)
│       ├── server.rs                 # ServerContext, request dispatch, all handlers
│       ├── config.rs                 # BridgeConfig — env-pinned (chain_id, contract, asset)
│       ├── state.rs                  # EnclaveState (phase state machine + CloningSession + nonce replay guard)
│       ├── keys.rs                   # BIP-39/BIP-32 key management (KeyManager)
│       ├── attestation.rs            # NSM facade (real + mock paths) and own-PCR readout
│       ├── cloning.rs                # X25519 + HKDF + ChaCha20Poly1305 cloning crypto
│       ├── framing.rs                # Length-prefixed protobuf wire format
│       ├── error.rs                  # Error types with gRPC code mapping
│       ├── vsock_forwarder.rs        # TCP→vsock forwarder for Esplora access
│       ├── signing/
│       │   ├── mod.rs
│       │   ├── evm.rs                # EIP-712 domain/digest construction
│       │   ├── psbt.rs               # SegWit v0 P2WSH PSBT signing (script_pubkey-anchored)
│       │   └── taproot.rs            # Taproot script-path Schnorr PSBT signing (script_pubkey-anchored)
│       ├── spv/
│       │   ├── mod.rs
│       │   ├── chain.rs              # In-enclave header chain + reorg + PoW + retarget
│       │   ├── checkpoint.rs         # Compile-time chain checkpoints (mainnet / signet)
│       │   ├── merkle.rs             # Merkle inclusion verifier
│       │   ├── types.rs              # Network, header helpers
│       │   └── validation.rs         # Header validation (PoW, retarget, linkage)
│       └── validation/
│           ├── mod.rs
│           ├── evm_crosscheck.rs     # EVM request cross-checks (selector whitelist, amounts, calldata, hash, deadline, bridge-config)
│           ├── psbt_crosscheck.rs    # PSBT request cross-checks (bridge vs vanilla mode)
│           ├── spv_crosscheck.rs     # SPV gate (coverage, inclusion, depth, staleness, chain_net)
│           └── rgb.rs                # RGB consignment validation (rgbstd + Esplora) → ValidatedConsignment
├── parent/
│   ├── Cargo.toml
│   ├── build.rs                      # tonic-build (gRPC) + prost-build (enclave proto)
│   └── src/
│       ├── lib.rs                    # Library root + grpc_proto + enclave_proto modules
│       ├── main.rs                   # gRPC server startup (tonic)
│       ├── grpc_server.rs            # EnclaveService implementation (translation layer + cloning driver)
│       ├── attest_verify.rs          # attest-verify CLI library entry points
│       ├── config.rs                 # Environment-based configuration
│       ├── client.rs                 # Enclave TCP/vsock RPC client
│       ├── framing.rs                # Wire format (shared with enclave)
│       ├── error.rs                  # Error types
│       └── bin/
│           ├── cli.rs                # CLI tool (init, get-keys, sign-evm, sign-psbt, submit-headers, REPL)
│           └── attest_verify.rs      # attest-verify binary — end-to-end attestation verifier CLI
├── docs/
│   └── pubkey-attestation.md         # Attestation verification recipe + canonical bundle encoding
├── build/
│   ├── Dockerfile.enclave            # Multi-stage Docker build (production: vsock,rgb-validation,spv)
│   ├── Dockerfile.enclave-dev        # Dev build (allow-seed-import,spv)
│   ├── build-enclave.sh              # EIF build + PCR extraction
│   ├── deploy-to-ec2.sh              # rsync to Nitro EC2 instance
│   ├── entrypoint.sh                 # Enclave runtime init (loopback + exec)
│   └── smoke-test.sh                 # Comprehensive RPC smoke tests
└── .vscode/
    └── settings.json                 # Rust Analyzer: enables rgb-validation + allow-seed-import + spv + mock-attestation
```

## License

TBD
