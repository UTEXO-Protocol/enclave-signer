# enclave-signer

This service signs for the UTEXO bridge. It runs inside an
[AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/).

The enclave makes its own keys. It checks each bridge operation itself. It
signs only when all checks pass. The host is not trusted.

The bridge has two flows:

| Flow | Direction | User does | Enclave signs | Signer image |
|------|-----------|-----------|---------------|--------------|
| **Mint** | EVM -> RGB | Locks ERC-20 tokens on EVM | A Bitcoin PSBT that mints RGB units | `mint-signer` |
| **Burn** | RGB -> EVM | Burns RGB units on Bitcoin | An EIP-712 `fundsOut` release, and its gas transaction | `burn-signer` |

Each flow has its own enclave image, its own seed and its own PCR0. A mint
signer refuses burn requests. A burn signer refuses mint requests.

## Documentation

Read the flow that you work on first:

- [`docs/mint-flow.md`](docs/mint-flow.md) - the mint flow, check by check.
- [`docs/burn-flow.md`](docs/burn-flow.md) - the burn flow, check by check.

Then:

- [`docs/tee-spec.md`](docs/tee-spec.md) - the specification: trust model,
  security policy, keys, requests, SPV rules, known limits.
- [`docs/verify-a-signer.md`](docs/verify-a-signer.md) - how anyone verifies
  a signer.
- [`docs/building.md`](docs/building.md),
  [`docs/configuration.md`](docs/configuration.md) and
  [`docs/operations.md`](docs/operations.md) - build, configure and run.

The [documentation index](docs/README.md) lists every document.

## How it works

1. The listener (`federated-signer-node`) sends a signing request to the
   parent over gRPC with mTLS.
2. The parent runs on the EC2 host. It is not trusted. It sends the request
   to the enclave over vsock.
3. The enclave holds the keys. It checks the request and signs, or refuses.
4. The enclave reaches the EVM JSON-RPC and the Bitcoin indexer through
   vsock proxies on the host. TLS ends inside the enclave.
5. The parent sends Bitcoin block headers to the enclave. The enclave
   validates them and keeps its own header chain.

**Mint.** The user locks tokens on EVM. The mint signer gets the deposit
receipt itself from the pinned EVM RPC. It reads the mint from the data that
rgb-lib wrote for the Bitcoin transaction. It checks that the transaction
commits exactly one mint of the pinned asset, for exactly the deposited
amount less the commission, and that the deposit names this mint and this
transaction. Then it signs the PSBT.

**Burn.** The user burns RGB units on Bitcoin. The burn signer runs full RGB
consensus over the history of the burn, proves every Bitcoin transaction of
that history in its own header chain, and binds the amount, the destination
and the deposits of the release to the burn. Then it signs the EIP-712
release. `MultisigProxy` needs M of N such signatures.

See the [component diagram](docs/diagrams/01-components.md) and the
[deployment diagram](docs/diagrams/02-deployment.md).

## Crates and binaries

| Crate | Binary | Description |
|-------|--------|-------------|
| `enclave/` | `utexo-bridge-enclave` | Runs inside the Nitro Enclave. Keys, checks, signing, SPV chain, cloning, attestation. |
| `enclave-proto/` | - | Vendored `enclave` protobuf package. Pre-generated Rust, no `build.rs`. |
| `attestation-verify/` | - | Nitro attestation verifier, and the encoding of the security-policy commitment. The enclave and the parent both use it. |
| `parent/` | `utexo-bridge-parent` | gRPC server on the EC2 host. Translates `ParentService` RPCs to the enclave wire protocol. Syncs Bitcoin headers. |
| `parent/` | `utexo-bridge-parent-cli` | Direct enclave client for the operator: launch values, limits, key init, cloning, health. |
| `parent/` | `attest-verify` | Gets an attested public key through the parent and verifies it. |

`parent/` is a separate cargo workspace with its own `Cargo.lock`
([`docs/building.md`](docs/building.md#workspaces)).

## Quick start

### Build

The build needs the Rust version of `rust-toolchain.toml` and read access to
the private repositories ([`docs/building.md`](docs/building.md#requirements)).

```bash
git clone git@github.com:UTEXO-Protocol/enclave-signer
cd enclave-signer
cargo build                                   # enclave workspace
cargo build --manifest-path parent/Cargo.toml # parent workspace
```

[`docs/building.md`](docs/building.md) has the feature sets, the enclave
image and its reproducibility.

### Run locally

```bash
# Enclave on 127.0.0.1:5000
RUST_LOG=debug,alloy_transport_http=off cargo run -p utexo-bridge-enclave

# Parent gRPC server (GRPC_PORT defaults to 5000; pick another port when both run on one host)
RUST_LOG=debug GRPC_PORT=50051 GRPC_ALLOW_INSECURE_LOOPBACK=true \
  cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent

# CLI (shell function works in bash and zsh)
cli() { cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent-cli -- "$@"; }
cli set-endpoints   # once, before any signature
cli init
cli get-keys
cli --help
```

- The default enclave build has no features. It takes no chain endpoints. A
  build with a signer role needs the launch values in `set-endpoints`
  ([`docs/configuration.md`](docs/configuration.md#launch-values)).
- `--addr host:port` or `--addr vsock://<cid>:<port>` selects the enclave.
- To make a clone donor, use `cli init --cloning-secret-file <file>`
  ([`docs/cloning.md`](docs/cloning.md)).
- The parent cargo feature `insecure-dev` serves plaintext gRPC with no
  client check on any `GRPC_HOST`. It is for dev only, and a release build
  with it does not compile.

[`docs/operations.md`](docs/operations.md) has the launch on Nitro.

### Test

```bash
cargo test                                                              # enclave workspace, default features
cargo test -p attestation-verify --features mock                          # dependency tests need their own invocation
cargo test -p utexo-bridge-enclave --no-default-features --features spv,mint-signer,mock-attestation,allow-seed-import
cargo test -p utexo-bridge-enclave --no-default-features --features spv,burn-signer,mock-attestation,allow-seed-import
cargo test --manifest-path parent/Cargo.toml                            # gRPC bridge + attest-verify e2e
python3 -m unittest discover -s build/tests -v
python3 -m unittest discover -s deploy/lambda/sns-to-slack -v
```

Default-feature tests alone are not enough for role-specific work: run the
mint and burn sets too. `.github/workflows/ci.yml` has the full matrix.

- The large-history tests are ignored by default. The burn-signer CI job
  runs them on every PR.
- The release-mode timing tests are ignored. Run them with **Actions → CI →
  Run workflow → run_stress**, or with the command in
  [`docs/validation-cost-model.md`](docs/validation-cost-model.md#measurements).
- The live EVM event tests need an RPC and a known deposit. Set the variables
  that `enclave/tests/test_evm_event_live.rs` documents, and run its command
  with `-- --ignored`. An ordinary CI run reports them as ignored, not as
  passed.
- The parent CLI timeout test needs Linux `vsock_loopback`:

  ```bash
  sudo modprobe vsock_loopback
  cargo test --manifest-path parent/Cargo.toml --features vsock --test test_cli_vsock_timeout
  ```

- `build/smoke-test.sh` checks the lifecycle and the public identity of a
  live enclave. `build/grpc-smoke-test.sh` checks the transport and the role
  refusals of the burn parent. Neither replaces a signing test.

## Security model

- **Untrusted host.** The enclave checks every claim of the parent, the
  listener and the backend itself.
- **Fail closed.** A missing feature, pin, receipt or proof refuses the
  request. The enclave never signs with less verification.
- **Trusted EVM RPC (accepted by design).** TLS to a pinned host and CA ends
  inside the enclave. The deposit checks are consistency checks, not a proof
  of EVM consensus: the approved provider is trusted for its data.
- **Attested posture.** The build flags, the pins and the launch values
  resolve to one security policy, committed into the attestation. A verifier
  compares it with independently approved values.
- **Key custody.** The seed never leaves the enclave in plaintext. A mint
  signer keeps it as KMS ciphertext in S3. A burn signer keeps it in memory
  and clones it only to an enclave with the same measurements.

The [specification](docs/tee-spec.md#2-trust-model) has the trust model, and
its [known limits](docs/tee-spec.md#10-known-limits) say what the checks do
not cover.
