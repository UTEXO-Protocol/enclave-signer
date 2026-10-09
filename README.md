# enclave-signer

This service signs for the UTEXO bridge. It runs inside an
[AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/).

The enclave makes its own keys. It checks each bridge operation itself. It
signs only when all checks pass. The host is not trusted.

The bridge has two primary flows:

| Flow | Direction | User does | Enclave signs | Signer image |
|------|-----------|-----------|---------------|--------------|
| **Mint** | EVM -> RGB | Locks ERC-20 tokens on EVM | A Bitcoin PSBT that mints RGB units | `mint-signer` |
| **Burn** | RGB -> EVM | Burns RGB units on Bitcoin | An EIP-712 `fundsOut` release, and its gas transaction | `burn-signer` |

Each flow has its own enclave image, its own seed and its own PCR0. A mint
signer refuses burn requests. A burn signer refuses mint requests.

Read these first:

- [`docs/mint-flow.md`](docs/mint-flow.md) - the mint flow, step by step.
- [`docs/burn-flow.md`](docs/burn-flow.md) - the burn flow, step by step.

Reference material:

- [`docs/tee-spec.md`](docs/tee-spec.md) - the full specification: trust
  model, signing rules, limits.
- [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md) - how to prove
  that a signing key belongs to attested enclave code. The `attest-verify` CLI.
- [`docs/verify-a-signer.md`](docs/verify-a-signer.md) - how anyone checks a
  published burn-signer attestation bundle and the on-chain signer list.
- [`docs/kms-persistence.md`](docs/kms-persistence.md) - how the mint signer
  keeps its seed with AWS KMS and S3.
- [`docs/parent-mtls.md`](docs/parent-mtls.md) - the required mTLS between
  the parent and its clients. RPC roles. Host rollout.
- [`docs/clone-cli-results.md`](docs/clone-cli-results.md) - result codes of
  the `clone` CLI command.
- [`docs/diagrams/`](docs/diagrams/README.md) - Mermaid diagrams.
- [`enclave-proto/README.md`](enclave-proto/README.md) - where the wire
  schema comes from, and how to sync it.

## Architecture

1. The listener (`federated-signer-node`) sends a signing request to the
   parent over gRPC with mTLS.
2. The parent runs on the EC2 host. It is not trusted. It sends the request
   to the enclave over vsock.
3. The enclave holds the keys. It checks the request and signs, or refuses.
4. The enclave reads Bitcoin data (Electrum) and EVM data (JSON-RPC) through
   host vsock proxies. EVM TLS ends inside the enclave. Electrum uses TLS
   only when the configured URL uses `ssl://`.
5. The parent sends Bitcoin block headers to the enclave. On mainnet, the
   enclave checks proof of work and maintains its own header chain.
   Signet and regtest use weaker checks. See the specification.

See the [component diagram](docs/diagrams/01-components.md) and the
[deployment diagram](docs/diagrams/02-deployment.md).

## Crates and binaries

| Crate | Binary | Description |
|-------|--------|-------------|
| `enclave/` | `utexo-bridge-enclave` | Runs inside the Nitro Enclave. Keys, checks, signing, SPV chain, cloning, attestation. |
| `enclave-proto/` | - | Vendored `enclave` protobuf package. Pre-generated Rust, no `build.rs`. |
| `attestation-verify/` | - | Nitro attestation verifier (COSE_Sign1, cert chain to the AWS root, PCRs). Also the encoding of the security-policy commitment. The enclave and the parent both use it. |
| `parent/` | `utexo-bridge-parent` | gRPC server on the EC2 host. Translates `ParentService` RPCs to the enclave wire protocol. Syncs Bitcoin headers. |
| `parent/` | `utexo-bridge-parent-cli` | Direct enclave client: endpoints, key init, cloning, keys, header sync, manual signing, health. |
| `parent/` | `attest-verify` | Gets an attested public key through the parent and verifies it end to end. |

`parent/` is a **separate cargo workspace** with its own `Cargo.lock`. See
[Proto source](#proto-source) for the reason.

## Mint flow (EVM -> RGB)

The user locks tokens on EVM. The bridge mints the same value of RGB units to
the user. The mint signer signs the Bitcoin transaction that does the mint.

Before it signs, the mint signer:

1. Gets the EVM deposit receipt itself. The receipt must be a success and at
   least `EVM_MIN_CONFIRMATIONS` blocks deep (default 12).
2. Finds exactly one `BridgeFundsIn` event from the pinned `FUNDS_IN_CONTRACT`.
   The `operationId`, amount and commission must match the request.
3. Validates the RGB consignment (full RGB consensus). The asset must be the
   pinned `RGB_ASSET_ID`. Each BFA `Bridge` (mint) transition must have a
   verified `FundsIn` lock behind it.
4. Binds the PSBT to the consignment. The txid, the inputs and the sighash
   types must match. The minted units must equal `amount - commission`
   exactly.
5. Binds the recipient. The v2 Bridge deposit names the mint OpId, and the
   mint commits to the user's seal. A legacy deposit has an RGB invoice. Then
   the one blinded seal in the consignment must equal that invoice.
6. Checks the Bitcoin fee and the sats that leave the bridge.
7. Signs Taproot key-path inputs with keys from the colored BIP-86 account.
   A Tapret or script-tree root can be part of the output-key tweak.

Full detail: [`docs/mint-flow.md`](docs/mint-flow.md).

## Burn flow (RGB -> EVM)

The user burns RGB units on Bitcoin. The bridge releases the locked tokens on
EVM. The burn signer signs the `fundsOut` release. `MultisigProxy` needs M of
N signatures.

Before it signs, the burn signer:

1. Verifies each EVM deposit behind the burned units (the mint ancestry).
2. Validates the RGB consignment. The last transition must be a BFA `Burn`.
3. Checks that each Bitcoin transaction of the consignment is in its own
   header chain, at least 6 blocks deep. The chain tip must be less than
   2 hours old.
4. Decodes the `fundsOut` calldata. The encoding must be canonical. Chain,
   contract and deadline must be correct.
5. Checks `sourceChainId`, `sourceAddress` and `burnId`.
6. Checks the BtcRelay finality proof against its own header chain.
7. Binds the release to the burn: amount, `sourceBurnTxId`, recipient and
   `settlementData`.
8. Signs the EIP-712 `TeeFundsOut` (or `TeeLzFundsOut`) digest over the
   decoded fields.

The burn signer also signs the gas transaction that sends the release to EVM
(`SignRawDigest`). An attested allowlist limits that transaction.

Full detail: [`docs/burn-flow.md`](docs/burn-flow.md).

## Keys

The mint signer and the burn signer get their seed in different ways:

- **Mint signer** (`kms-persistence`): the enclave makes or recovers its seed
  through attested AWS KMS. It keeps the encrypted seed in S3. Mint replicas
  recover the same seed. Peer cloning is off. See
  [`docs/kms-persistence.md`](docs/kms-persistence.md).
- **Burn signer**: the enclave makes a BIP-39 mnemonic from OS entropy.
  Replicas get the seed through the attested cloning handshake.

Both keep the 64-byte seed in a `SecretBox` (zeroized on drop). The enclave
never exports the plaintext seed. For mint signers, KMS also handles the
plaintext seed during generation and decryption. Mnemonic or raw-seed import
exists only with
`allow-seed-import` (dev builds).

Key paths:

| Key | Path | Use |
|-----|------|-----|
| EVM bridge key | `m/44'/60'/0'/0/0` | Signs `fundsOut` (burn). Its address is the cluster identity. |
| EVM gas-tx key | `m/44'/60'/0'/0/1` | Signs the outer gas transaction (burn). |
| BTC legacy key | `m/84'/0'/0'/0/0` | Public key only. Signs nothing. |
| Vanilla taproot account | `m/86'/<coin>'/0'` (coin 0 mainnet, 1 other) | Plain-BTC `SignBtc` only. |
| Colored taproot account | `m/86'/<rgb_coin>'/0'` (827166 mainnet, 827167 other) | Mint PSBTs only. |
| Concordium key | `m/44'/919'/0'/0'/0'` (Ed25519, SLIP-0010) | `SignCcd`. |

The enclave returns the master fingerprint and both account xpubs. The bridge
wallet uses them for its watch-only descriptors. A cloned enclave must derive
the same EVM address before it goes `Active`.

## Attested security policy

The enclave resolves one `SecurityPolicy` when the operator sets the
endpoints at launch. The policy comes from build flags, image pins and the
endpoints. It is `Production { ... }` or `Development { reason }`.

- A release bridge build refuses to boot if its pins do not make a valid
  `Production` policy.
- It also refuses endpoints that do not make a valid `Production` policy.
- The policy goes into the attestation `user_data`, with the signer role.
- `attest-verify` builds the expected policy and fails on any difference.

See [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md).

## gRPC bridge (parent)

- The parent implements `parent.ParentService` from `federated-signer-proto`
  (`proto/enclave/parent.proto`): `Sign`, `PublicKey`, `Initialize`, `Clone`,
  `GetLastSavedBlock`, `SubmitHeaders`, `AttestedPublicKey`.
- mTLS is required. A client certificate ACL gives each caller a role
  (`listener`, `clone-operator`, `observer`). See
  [`docs/parent-mtls.md`](docs/parent-mtls.md).
- `Sign` routes by `data_type`: `TRANSACTION` -> enclave `Sign`,
  `EVM_GAS_TX` -> `SignRawDigest`, `BTC_UTXO` -> `SignBtc`.
- `SubmitHeaders` answers `PERMISSION_DENIED` to every caller. The parent's
  header sync writes headers through the direct enclave protocol. Other direct
  enclave clients can also submit headers. The sync reads headers from
  `HEADER_ELECTRUM_URL` and sends them to its enclave.
- The parent opens one new TCP or vsock connection per enclave RPC, with a
  30 s timeout.
- `GET /health` on a loopback port tells if the enclave can sign now. See
  [Readiness endpoint](#readiness-endpoint).

## Enclave requests

Wire format: `[4-byte little-endian length][protobuf EnclaveRequest]`. One
request per connection. Frame cap 24 MiB. Schema:
[`enclave-proto/proto/enclave.proto`](enclave-proto/proto/enclave.proto).

| Request | Phase | Signer | Description |
|---------|-------|--------|-------------|
| `SetEndpoints` | any | all | Sets the chain endpoints (and the KMS values on mint). Once per boot. |
| `InitializeKey` | Initial | all | Mint: recover or create the KMS seed. Burn: make a seed from OS entropy, with an optional donor `cloning_secret`. |
| `GetPublicKey` | Active | all | EVM address and keys, gas-tx key, BTC key and xpubs, fingerprint, CCD key, boot pins. |
| `GetAttestedPublicKey` | Active | all | The same bundle, plus an NSM attestation document bound to the nonce, the bundle and the policy. |
| `Sign` | Active | mint, burn | Bridge signing. Mint signer: EVM -> RGB only. Burn signer: RGB -> EVM only. |
| `SignBtc` | Active | mint | Plain-BTC PSBT on the vanilla account. Off unless the attested policy turns it on. |
| `SignRawDigest` | Active | burn | Gas transaction under the attested allowlist. |
| `SignCcd` | Active | `ccd` builds | Ed25519 over a 32-byte hash. |
| `SubmitHeaders` | any | RGB builds | Bitcoin headers (<= 10 000 per call, <= 100 000 per 60 s). The parent denies this gRPC method to clients. Direct enclave callers can still submit headers. |
| `GetLastSavedBlock` | any | RGB builds | Header-chain tip (the checkpoint when empty). |
| `InitiateCloning` | Initial or expired Cloning | burn | Starts a requester session or replaces an expired session. |
| `GetClone` | Active | burn | Donor side. Verifies the requester attestation and seals the seed. |
| `SetClone` | Cloning | burn | Requester installs the sealed seed and goes `Active`. |
| `SignRawMessage` | - | - | Removed. Always refused. |
| `Health` | any | all | Readiness: endpoints set and key loaded. Builds with the RGB -> EVM path also require a ready header chain. |
| `ProxyFederation` | - | - | Not implemented. Always refused (code `1`). |

The "Signer" column is for the mint/burn images. Other builds (combined,
CCD) keep both directions where their features allow it.

Error codes in `ErrorResponse`: `3` cross-check or SPV failure (the parent
maps it to `FAILED_PRECONDITION`), `2` not ready, `1` all other errors.

## Prerequisites

- **Rust 1.96.1** - pinned in `rust-toolchain.toml`. The exact patch version
  matters for reproducible PCR0.
- **SSH deploy keys** - the workspace currently pins the RGB crates to private
  BFA mirrors (`rgb-consensus-s-bfa`, `rgb-ops-s-bfa`, `rgb-schemas-s-bfa`)
  through the `github-rgb-*` SSH host aliases in `Cargo.toml`. Every build,
  including the enclave, needs read access to them. `consignment-utils` is
  public and is fetched over HTTPS without a key.
  The parent additionally needs `federated-signer-proto`. CI wires the aliases
  in `.github/workflows/ci.yml`; copy that `~/.ssh/config` shape locally.
  External users cannot build without read access to all three private repos.
  Public source builds require public access to their pinned revisions.
  Access alone does not prove that a build reproduces the approved PCR0.
- **Docker + `nitro-cli`** for the EIF. Any x86_64 Linux host with Docker can
  build an EIF and read its PCRs; Nitro hardware is needed only to run it.

```bash
git clone git@github.com:UTEXO-Protocol/enclave-signer
cd enclave-signer
cargo build                                   # enclave workspace
cargo build --manifest-path parent/Cargo.toml # parent workspace
```

## Building

### Feature sets

The production images are the mint signer and the burn signer. Each image
has one role, its own PCR0 and its own seed. Use `--no-default-features`:

```bash
# Mint signer (EVM -> RGB)
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,rgb,mint-signer

# Burn signer (RGB -> EVM)
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,rgb,burn-signer
```

Other builds stay in the tree. They are not the production bridge:

```bash
# Combined (what build/Dockerfile.enclave ships). Uses the retired swap flow.
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,rgb,rgb-swap,ccd,bfa-validation

# RGB send/receive (swap) only. Retired flow.
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,rgb,rgb-swap,bfa-validation

# Concordium only
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,ccd

# Local TCP dev build (debug profile, seed import allowed)
cargo build -p utexo-bridge-enclave --no-default-features --features allow-seed-import,spv,rgb-swap,ccd,evm-rpc
```

Compile-time guards in `enclave/src/lib.rs`: `rgb-validation` requires `spv`;
exactly one of `rgb-swap` / `rgb-mint-burn` whenever `rgb-validation` is on;
exactly one of `mint-signer` / `burn-signer` whenever `rgb-mint-burn` is on;
`kms-persistence` requires `mint-signer`;
`allow-seed-import` and `mock-attestation` do not compile in a release
profile. CI asserts every guard fires.

### Enclave image (EIF)

No image takes a KMS value: the mint enclave gets them at launch. See
[mint KMS setup](docs/kms-persistence.md) for the parent and policy requirements.

```bash
RGB_ASSET_ID="rgb:<approved-bfa-contract-id>" DOCKERFILE=Dockerfile.enclave.mint ./build/build-enclave.sh   # mint signer
RGB_ASSET_ID="rgb:<approved-bfa-contract-id>" DOCKERFILE=Dockerfile.enclave.burn ./build/build-enclave.sh   # burn signer
RGB_ASSET_ID="rgb:<approved-swap-contract-id>" ./build/build-enclave.sh # combined
RGB_ASSET_ID="rgb:<approved-swap-contract-id>" DOCKERFILE=Dockerfile.enclave.rgb ./build/build-enclave.sh   # swap (retired)
DOCKERFILE=Dockerfile.enclave.ccd       ./build/build-enclave.sh
```

`Dockerfile.enclave.mint` and `Dockerfile.enclave.burn` build the BFA signer images.
Each signer role enables `bfa-mint`. This enables `rgb-mint-burn` and
`bfa-validation`. BFA validation also enables `evm-rpc`.

Run the two roles as separate enclaves with independent seeds. Mint signers use
KMS persistence. Burn signers use OS entropy or peer cloning with matching PCRs.

Set `RGB_ASSET_ID` when you use the build helper. For a direct Docker build,
pass `--build-arg RGB_ASSET_ID=rgb:<contract-id>`. Use the approved BFA contract
id for mint and burn images. There is no default asset id.

The helper and Dockerfile reject an empty value. They do not validate the id
or reject a value that contains only spaces. The image contains the asset pin.
A runtime environment override is not the provisioning procedure.

The EIF workflow gets this value from the repository variable `BFA_RGB_ASSET_ID`.
It records the asset pin from the built image as `rgb_asset_id` in `metadata.json`.
This file accompanies the EIF in the Actions artifact and S3 bundle. CCD images
have no asset pin and record `null`.

To reproduce a published EIF, use its recorded asset id, not the current
repository variable. Older bundles may lack this field; obtain the original
build value from the release owner. Include `metadata.json` when distributing
a release. An internal S3 upload alone does not make these inputs public.

Before deploying, record the image/EIF checksum, approved asset, measured PCRs,
registered key, and Parent endpoint together. Verify a genuine BFA request
succeeds and an opposite-flow request is rejected.

All Dockerfiles resolve private dependencies. Supply either a GitHub token
with read access to those repositories, or the same per-repository deploy keys
used by Rust CI. Credentials are mounted as BuildKit secrets during Cargo's
build step; they are not copied into image layers.

```bash
# GITHUB_TOKEN must already be exported; the value is not a build argument.
docker build --secret id=github_token,env=GITHUB_TOKEN \
  -f build/Dockerfile.enclave-dev -t utexo-bridge-enclave-dev .

# EIF: uses GITHUB_TOKEN, or PRIVATE_DEPS_DIR if no token is set.
RGB_ASSET_ID="rgb:<approved-swap-contract-id>" \
  PRIVATE_DEPS_DIR=/absolute/path/to/private-deps ./build/build-enclave.sh
```

The key directory contains `consensus_key`, `ops_key`, and `schemas_key`;
parent builds also need `federated_key`. Keep it outside the
checkout, with directory mode `700` and key files `600`. For a direct Docker
build with keys, pass each file as `--secret id=<name>,src=<absolute-path>`.
`make build_*` uses the token option by default; `DOCKER_AUTH_ARGS` can override
it with those key-file arguments.

CD and EIF workflows reuse the four deploy-key secrets configured for Rust CI:
`RGB_CONSENSUS_BFA_DEPLOY_KEY`,
`RGB_OPS_BFA_DEPLOY_KEY`, `RGB_SCHEMAS_BFA_DEPLOY_KEY`, and
`FEDERATED_SIGNER_PROTO_DEPLOY_KEY`. The workflow's automatic `GITHUB_TOKEN`
is used for image publishing, not cross-repository dependency access.

The script builds the Docker image with `SOURCE_DATE_EPOCH` set to the commit
time, converts it with `nitro-cli build-enclave`, and writes the EIF,
`PCR.json` and `SHA256SUMS` to `build/`. Reproducibility inputs: pinned
toolchain, digest-pinned base images, `--locked`, `CARGO_INCREMENTAL=0`,
path-prefix remapping, pre-generated proto code. All five EIF recipes use
digest-pinned Debian 13 Trixie images for both build and runtime stages.
The builder uses Rust `1.96.1`, matching `rust-toolchain.toml`.
Both stages install packages from the signed Debian snapshot
`20261007T000000Z` over HTTPS. APT checks repository signatures.
The expiry check is disabled because a fixed snapshot must remain usable after
its Release metadata expires. CMake comes from this snapshot instead of PyPI.
Only the parent and dev image recipes still use live APT repositories.
CI pins `nitro-cli` and its kernel/init blobs to `1.4.5`. Docker, Buildx and
BuildKit versions are not pinned in CI, so PCR reproducibility still requires
verification.

Each runtime checks the binary with its dynamic loader before EIF conversion.
This rejects missing libraries and incompatible symbol versions.
The base-image update changes enclave measurements. Build new EIFs and approve
their PCRs before updating attestation allowlists or KMS policies. Existing
measurements do not apply to these images.

`.github/workflows/build-eif.yml` builds the `combined`, `rgb`,
`rgb-mint`, `rgb-burn` and `ccd` variants on a plain runner with `nitro-cli 1.4.5`
and uploads EIF + PCRs + host binaries to `s3://<bucket>/eif/<git_sha>/`.
`release-eif.yml` deploys the `combined` EIF only: `deploy/deploy-host.sh`
fetches `eif/<git_sha>/utexo-bridge-enclave.eif` and runs it on every CID.
The `rgb-mint` and `rgb-burn` EIFs have no release path yet. The `cd-*.yml` workflows push container images for
the parent and the **dev** enclave images only (`utexo-bridge-enclave-mint`
and `utexo-bridge-enclave-burn`, both from `Dockerfile.enclave-dev.bfa` with a
`SIGNER_ROLE` build arg).

The production Dockerfiles bake the bridge pins as `ENV` (`EVM_CHAIN_ID`,
`EVM_PROXY_CONTRACT_ADDRESS`, `RGB_ASSET_ID`, `FUNDS_IN_CONTRACT`,
`TOKEN_CONTRACT`, `GAS_TX_ALLOWED_TO`, `BTC_MAX_TOTAL_SATS`, ...), so they are
measured into PCR0. The cloning secret is never baked. The chain endpoints and
the KMS values are not in the image: anyone can rebuild the EIF and get the
same PCR0 without knowing them.

## Running

### Local development (TCP)

```bash
# Enclave on 127.0.0.1:5000
RUST_LOG=debug cargo run -p utexo-bridge-enclave

# Parent gRPC server (GRPC_PORT defaults to 5000; pick another port when both run on one host)
RUST_LOG=debug GRPC_PORT=50051 GRPC_ALLOW_INSECURE_LOOPBACK=true cargo run --manifest-path parent/Cargo.toml

# Or: parent reachable from other hosts, plaintext, no mTLS (see "insecure-dev" below)
RUST_LOG=debug GRPC_HOST=0.0.0.0 GRPC_PORT=50051 \
  cargo run --manifest-path parent/Cargo.toml --features insecure-dev

# CLI (shell function works in bash and zsh)
cli() { cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent-cli -- "$@"; }
cli set-endpoints --electrum-url tcp://<host>:<port>   # once, before any signature (debug build; release needs ssl://)
cli init
cli get-keys
cli get-last-saved-block
cli --help
```

`--addr host:port` or `--addr vsock://<cid>:<port>` selects the enclave.

`insecure-dev` (parent cargo feature, dev only): the parent serves plaintext gRPC
with no client auth on any `GRPC_HOST`, and `clone` / `attest-verify` accept
`http://` to any host. Any `GRPC_TLS_*` setting is an error. A release build with
this feature does not compile. Dev image: `make build_parent_dev`.
Initialize once: use `cli init --cloning-secret-file <file>` instead of
`cli init` to configure a donor. Use a fresh requester for `cli clone`; initialization
and cloning are alternative ways to enter `Active`. Signing subcommands require
complete proofs and configured pins; see their `--help` and the spec.

### Production (Nitro)

```bash
nitro-cli run-enclave --cpu-count 2 --memory 3072 --enclave-cid 16 \
  --eif-path build/utexo-bridge-enclave.eif

# Host-side proxies (allowlist each upstream)
vsock-proxy 8001 <electrum-host> 50002          # ELECTRUM_URL upstream
vsock-proxy 8002 <EVM_RPC_HOST> 443             # EVM JSON-RPC over TLS to the pinned host (see deploy/host-prep-evmrpc.sh)

# Set the endpoints once. The enclave refuses a second set, and signs nothing
# and opens no chain connection before it. A restart needs a new set.
cli --addr vsock://16:5000 set-endpoints --electrum-url ssl://<electrum-host>:50002 \
  --evm-rpc-host <EVM_RPC_HOST> --evm-rpc-tls-port 443 --evm-rpc-ca-der-file ca.der \
  --kms-key-arn <KMS_KEY_ARN> --kms-region <KMS_REGION> --kms-seed-id <KMS_SEED_ID>   # mint only

GRPC_HOST=0.0.0.0 GRPC_PORT=50051 USE_VSOCK=true ENCLAVE_VSOCK_CID=16 \
  GRPC_TLS_CERT_FILE=server.pem GRPC_TLS_KEY_FILE=server.key \
  GRPC_TLS_CLIENT_CA_FILE=client-ca.pem GRPC_TLS_ACL_FILE=clients.acl \
  ./utexo-bridge-parent
```

`deploy/deploy-host.sh` installs the systemd units for a three-enclave host:
CIDs 16 / 18 / 20 with parents on ports 50051 / 50052 / 50053. It verifies the
EIF checksum and PCR0 against the S3 manifest before and after start.
A restart removes the in-memory keys. Initialize or clone each enclave again.
Mint signers recover their saved KMS seed through `InitializeKey`. They require
the verified address pin and do not support peer cloning.

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
| `FUNDS_IN_CONTRACT` | falls back to the proxy | Attested emitter of `FundsIn` / `BridgeFundsIn`. It must resolve to a non-zero address in production. |
| `TOKEN_CONTRACT` | zero | The ERC-20 the Bridge releases (`Bridge.TOKEN`). A `burnId` preimage input: the enclave recomputes `burnId` from it and refuses a mismatch. Attested; must be non-zero in production. |
| `BTC_RELAY_MODE` | `required` | `required`: every `fundsOut` proof must carry the two BtcRelay commitment words, and each must equal the relay record the enclave rebuilds from its own chain; a zero word is refused. `none`: the stand has no BtcRelay (route verifier `NullVerifier`), the bridge sends both words as zero and the enclave requires exactly that, still binding heights, anchor and freshness. A production policy refuses to boot on `none`. Any other value is treated as `required` with a boot warning. |

Value bounds (fail closed while unset in a production build):

| Variable | Default | Description |
|----------|---------|-------------|
| `BTC_MAX_TOTAL_SATS` | `0` | Cap on total input value of one plain-BTC (`SignBtc`) transaction. Non-zero also flips `allow_vanilla_psbt` in the attested policy. |
| `BTC_MAX_UNOWNED_SATS` | `0` | Plain-BTC output budget for scripts the enclave does not prove it controls. Outputs repaying a signed input or landing on the enclave's own BIP-86 key-path addresses (singlesig change, `create_utxo` allocations) are proven and do not count. |
| `RGB_MAX_UNOWNED_SATS` | `0` | Bridge-PSBT output budget for sats the enclave cannot prove it controls. Size it from the bridge's witnessed satoshi amount. |
| `GAS_TX_ALLOWED_TO` | unset | Only `to` a gas tx may target. |
| `GAS_TX_MAX_GAS_LIMIT` | `0` | Ceiling on `gasLimit`. |
| `GAS_TX_MAX_FEE_PER_GAS` | `0` | Ceiling (wei) on `maxFeePerGas` / `maxPriorityFeePerGas` / legacy `gasPrice`. |
| `GAS_TX_ALLOWED_SELECTORS` | empty | Comma-separated 4-byte selectors a gas tx may call. Empty calldata is refused. Malformed entries are dropped with a warning. |
| `GAS_TX_MAX_VALUE_WEI` | unset | Ceiling on native `value`; only `lzFundsOutCall` to the pinned proxy may carry value. |

The gas-tx rule is part of the attested policy. Unset pins commit as zero.

Mint signer KMS custody is set at launch (see the launch table below).
With `KMS_EXPECTED_EVM_ADDRESS` set, initialization recovers the saved ciphertext
and checks the derived address. Without the pin, initialization creates a seed
only when storage reports no saved object. It rejects an existing object.
There is no separate creation-mode setting. See the [deployment and recovery
procedure](docs/kms-persistence.md) for parent storage and relay configuration.

Data sources and transport:

| Variable | Default | Description |
|----------|---------|-------------|
| `BITCOIN_NETWORK` | `bitcoin` | `bitcoin`, `testnet`, `signet`, `regtest`. Selects the SPV checkpoint, coin types and xpub prefix. Baked into the image. |
| `ESPLORA_VSOCK_PORT` | `8001` | Host vsock-proxy port for the Electrum resolver. |
| `EVM_RPC_VSOCK_PORT` | `8002` | Host vsock-proxy port for the EVM RPC. |
| `EVM_MIN_CONFIRMATIONS` | `12` | Attested minimum depth of a `FundsIn` receipt; zero is rejected at production boot. |
| `ENCLAVE_LISTEN_ADDR` | `127.0.0.1:5000` | TCP listen address, non-vsock builds only. |
| `RUST_LOG` | unset | Log filter. |

Chain endpoints and KMS values, set once at launch with `cli set-endpoints`
(`SetEndpoints`), never in the image. The attested policy commits the Electrum
host, the EVM RPC host, the SHA-256 of the CA and the four KMS values. A build
requires the values it uses and refuses the others:

| Value (CLI flag / env) | Build | Description |
|------------------------|-------|-------------|
| `--electrum-url` / `ELECTRUM_URL` | `rgb-validation` | `ssl://host:port` (Electrum) or `https://host[:port]` (Esplora, for the custom dev signet). TLS terminates inside the enclave. The forwarder listens on that port and pins `host` to loopback in `/etc/hosts`. A test, debug, `mock-attestation` or `allow-seed-import` build also accepts plaintext `tcp://host:port` and `http://host[:port]`; a release image refuses them. |
| `--evm-rpc-host` / `EVM_RPC_HOST` | `evm-rpc` | TLS host name of the EVM RPC. No scheme, path, port or IP literal. The JSON-RPC is served at `/`. |
| `--evm-rpc-tls-port` / `EVM_RPC_TLS_PORT` | `evm-rpc` | TLS port, 1-65535, not the Electrum port. The forwarder listens on it. |
| `--evm-rpc-ca-der-file` / `EVM_RPC_TLS_CA_DER_FILE` | `evm-rpc` | DER of the only CA the EVM RPC TLS trusts. |
| `--kms-key-arn` / `KMS_KEY_ARN` | `kms-persistence` | Full symmetric KMS key ARN; aliases are rejected. |
| `--kms-region` / `KMS_REGION` | `kms-persistence` | Commercial AWS region matching the key ARN. The KMS forwarder listens on `127.0.0.2:443`. |
| `--kms-seed-id` / `KMS_SEED_ID` | `kms-persistence` | Stable signer identity used in the KMS encryption context and storage namespace. |
| `--kms-expected-evm-address` / `KMS_EXPECTED_EVM_ADDRESS` | `kms-persistence`, optional | Identity pin: 40 hex digits with optional `0x`. Pin the verified signer before funding; missing ciphertext then fails without replacement. |

Limits and dev knobs:

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONSIGNMENT_BYTES` | 8 MiB | Consignment size cap. Sized for a history of 10,000 transitions. |
| `MAX_MERKLE_PROOFS` | `16384` | Proof-count cap per request. A burn needs one proof for each witness tx in its history. |
| `MAX_TOTAL_PROOF_BYTES` | 8 MiB | Aggregate proof-bytes cap per request. |
| `SPV_CHECKPOINT` | unset | Dev builds only: `height:hash[:bits:time[:chainwork]]` moves the SPV anchor forward. Without `chainwork` (Core's `getblockheader` value) every `fundsOut` is refused under `BTC_RELAY_MODE=required`; `none` needs no chainwork. A production-shaped build refuses to boot when set. |
| `UTEXO_CLONING_SECRET` | unset | Legacy donor secret; ignored with `kms-persistence`, which rejects cloning. Otherwise prefer `init --cloning-secret-file` at runtime. |

### Parent

| Variable | Default | Description |
|----------|---------|-------------|
| `GRPC_HOST` | `127.0.0.1` | Bind address. The deploy script defaults to the private EC2 address. |
| `GRPC_PORT` | `5000` | gRPC port. Deployments use 50051-50053. |
| `ENCLAVE_ADDR` | `127.0.0.1:5000` | Enclave TCP address (dev). |
| `USE_VSOCK` | `false` | `true` / `1` selects vsock (Linux only). |
| `ENCLAVE_VSOCK_CID` | `16` | Enclave CID. |
| `ENCLAVE_VSOCK_PORT` | `5000` | Enclave vsock port. |
| `HEALTH_HOST` | `127.0.0.1` | Bind host for `GET /health`. Keep on loopback - unlike `GRPC_HOST`, do not set to `0.0.0.0` |
| `HEALTH_PORT` | `5001` | Port for `GET /health` |
| `HEADER_ELECTRUM_URL` | unset | `ssl://host:port` (WebPKI roots, host name checked), or `tcp://` to a loopback IP. The parent's header sync reads Bitcoin headers here. Unset: `header_sync.state` is `unconfigured`. Malformed: the parent still serves, `header_sync.state` is `unconfigured` and `last_error` says why. Deploy passes it through; it does not copy `ELECTRUM_URL`, whose enclave-side rules differ. |
| `HEADER_SYNC_INTERVAL_SECS` | `10` | Seconds between header sync steps, `1..=600`. A malformed value stops the parent at boot. |
| `RUST_LOG` | unset | Log filter. |

#### Readiness endpoint

Use `GET /health` to check readiness before you continue a rollout.
`deploy/deploy-host.sh` performs a cold deployment. It does not initialize keys
or implement a rolling restart.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5001/health
```

- `200` - endpoints are set and the signing key is loaded. Builds with the
  RGB -> EVM path also require a fresh header chain with at least six headers
  above the checkpoint (`assert_chain_ready`). Mint signers do
  not require SPV readiness, although they report `spv_synced`.
- `503` - the enclave is not ready, cannot be reached, or does not answer
  within the five-second probe timeout.

A `200` response does not prove that a signing request will succeed. The
request must still pass its policy, data-source, and validation checks.

The body includes readiness, key, phase, and SPV diagnostic fields.
Use them to investigate a failed deployment. It also includes the parent's
header-sync status. Example fragment:

```json
{"header_sync": {"state": "synced", "source_tip": 412345, "enclave_tip": 412345, "lag_blocks": 0, "tip_age_secs": 41, "last_ok_unix": 1790000000, "last_error": null}}
```

`state` is `synced`, `syncing`, `stalled` (three failed steps in a row), `off`
(a build with no header chain) or `unconfigured` (no `HEADER_ELECTRUM_URL`).
The header-sync state does not change the HTTP code. A rollout can check it
separately when the selected signer needs Bitcoin headers. The deploy script
sets ports `50061`, `50062`, and `50063` for the three parents. The parent
Docker image uses the same probe in its `HEALTHCHECK`.

This operations probe binds to loopback by default. `HEALTH_HOST` can change
the address. Keep the endpoint inaccessible from other hosts.

The same answer is available from the CLI, for debugging from the host shell:

```bash
utexo-bridge-parent-cli --addr vsock://16 health
```

## Testing

```bash
cargo test                                                              # enclave workspace, default features
cargo test -p utexo-bridge-enclave --no-default-features --features rgb,mint-signer,mock-attestation,allow-seed-import
cargo test -p utexo-bridge-enclave --no-default-features --features rgb,burn-signer,mock-attestation,allow-seed-import
cargo test -p utexo-bridge-enclave --features evm-rpc
cargo test -p utexo-bridge-enclave --features mock-attestation,allow-seed-import
cargo test --manifest-path parent/Cargo.toml                            # gRPC bridge + attest-verify e2e
```

Coverage: key derivation and fingerprints, framing, EIP-712 digests checked against
contract fixtures, calldata canonicalisation, gas-tx allowlist, consignment
fixtures per flow, PSBT binding and fee gate, SPV chain / reorg / Merkle,
attestation verification incl. crafted cert chains, cloning handshake, wire
roundtrips over TCP, gRPC translation with a mock enclave, vendored-proto
provenance. `build/smoke-test.sh` drives a live enclave through the CLI.

## Feature flags

| Feature | Implies | Description |
|---------|---------|-------------|
| `rgb` | `spv` | RGB / Bitcoin bridge stack. |
| `ccd` | - | Concordium stack (Ed25519 is always compiled; this gates the handlers). |
| `rgb-swap` | `rgb` | Retired RGB flow: send/receive with BFA `Transfer`. In the default set. Not in production. |
| `kms-persistence` | - | Attested KMS seed generation/recovery with encrypted S3 persistence. Requires `mint-signer`; custody context is `rgb-mint`. |
| `rgb-mint-burn` | `rgb` | RGB flow: deposits mint with BFA `Bridge`, withdrawals `Burn`. Needs `--no-default-features`. |
| `bfa-mint` | `rgb-mint-burn`, `bfa-validation` | Mint/burn flow with BFA consensus and settlement checks against verified `FundsIn` locks. |
| `mint-signer` | `bfa-mint`, `kms-persistence` | Mint/burn signer role: EVM -> RGB only (mint PSBT, `SignBtc`). Exactly one role per mint/burn build. |
| `burn-signer` | `bfa-mint` | Mint/burn signer role: RGB -> EVM only (`fundsOut`, gas tx). Exactly one role per mint/burn build. |
| `bfa-validation` | `evm-rpc` | Runs BFA consensus with verified mint ancestry. Implied by `bfa-mint`. |
| `spv` | `rgb-validation` | In-enclave Bitcoin header chain and witness inclusion proofs. |
| `rgb-validation` | rgb crates | In-enclave consignment validation. Requires `spv`. |
| `evm-rpc` | `rgb-validation` | In-enclave `FundsIn` verification over JSON-RPC, TLS to a pinned host and CA. Without it the enclave refuses every bridge PSBT. |
| `vsock` | - | vsock listener and forwarders (Linux). |
| `allow-seed-import` | - | Mnemonic / raw-seed import. Dev only, does not compile in release. |
| `mock-attestation` | - | Raw-CBOR attestation with zero PCRs. Dev only, does not compile in release. |

## Proto source

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

- **Untrusted host.** Requests from the parent, listener and backend are checked
  inside the enclave. For RGB-source requests, Bitcoin witness inclusion is
  checked against its header chain. Concordium source validation still trusts
  the listener; see the spec for network-specific limits.
- **Pinned EVM RPC trust (accepted by design).** TLS ends inside the enclave and
  authenticates the configured RPC hostname against the pinned CA. The host
  relay cannot alter authenticated responses without detection. The enclave
  checks successful receipts, unique expected events from the pinned contract,
  operation IDs, amounts and depth relative to the provider-reported chain head.
  These checks do not prove EVM consensus: an approved provider can return a
  self-consistent false deposit history. Trust in the provider's data is an
  explicit design assumption. Verifiers must compare the attested host and CA
  SHA-256 with independently approved values. See the
  [EVM RPC trust boundary](docs/tee-spec.md#2-trust-boundary-and-threat-model).
- **Attested posture.** Build flags and pins resolve to one `SecurityPolicy`
  committed into the attestation. Policy matching checks only the committed fields.
  The Electrum/Esplora scheme is not committed: a release image accepts only
  TLS (`ssl://`, `https://`), so PCR0 covers it. Endpoint ports are not
  committed. See the [policy scope](docs/tee-spec.md#4-security-policy).
- **Fail closed.** Missing feature, missing pin, missing receipt, missing
  proof, zero inputs signed: refuse, never sign with less verification.
- **Limits.** Bitcoin confirmation depth, freshness, reorg/retention caps and
  connection limits are compiled in. `EVM_MIN_CONFIRMATIONS` and request-size
  caps are read from environment; image-baked values are measured with the EIF.
- **Key custody.** Seed and keys in `SecretBox`, zeroized on drop.
  `#![deny(unsafe_code)]`. With `kms-persistence`, seeds persist as KMS ciphertext
  in S3. The parent receives no plaintext seed. KMS handles the seed during
  generation and decryption. Derived signing keys stay in enclave memory.
- **Cloning (without KMS persistence).** X25519 + HKDF-SHA256 + ChaCha20-Poly1305, mutual attestation
  with PCR equality, shared secret, replay guard recorded only after
  authentication.
- **Release hardening.** `opt-level = "z"`, LTO, stripped, `panic = "abort"`,
  single codegen unit. Dev features are `compile_error!` in release.

Known limitations are listed in
[`docs/tee-spec.md`](docs/tee-spec.md#13-implementation-status).
