# Building

How to build the binaries and the enclave image (EIF), and what makes the
image measurements reproducible. Launching an image is in
[operations.md](operations.md).

## Requirements

- **Rust.** The exact version in `rust-toolchain.toml`. The patch version
  matters: another compiler gives another PCR0.
- **Access to the private repository, for the parent only.**
  - The enclave workspace needs no credential. rgb-lib comes from the public
    `RGB-Tools/rgb-lib` repository, at the revision in `enclave/Cargo.toml`,
    and the RGB protocol crates from crates.io.
  - The parent needs `federated-signer-proto`, through the
    `github-federated-signer` SSH alias (deploy key `federated_key`).
  - CI wires it in `.github/workflows/ci.yml` (secret
    `FEDERATED_SIGNER_PROTO_DEPLOY_KEY`). `build/with-private-deps.sh` runs
    cargo with that access and keeps the credential out of the build layers.
- **Docker with Buildx, `nitro-cli` and `jq`** for an EIF. Any x86_64 Linux
  host with Docker can build an EIF and read its PCRs. Nitro hardware is
  needed only to run it.

## Workspaces

The root workspace has the enclave, the vendored enclave protocol and the
attestation verifier. `parent/` is a separate workspace with its own
`Cargo.lock`. Cargo fetches every git source of a workspace before it knows
which crates a build compiles. Keeping the parent out of the root workspace
keeps its private proto dependency out of the enclave's dependency graph.
Build the parent with `--manifest-path parent/Cargo.toml`, never with `-p`.

```bash
cargo build                                   # enclave workspace
cargo build --manifest-path parent/Cargo.toml # parent workspace
```

The parent and its CLI reach a Nitro enclave over vsock only when they are
built with the parent feature `vsock` (Linux):
`cargo build --release --locked --manifest-path parent/Cargo.toml --features vsock`.

The enclave's wire schema is vendored in `enclave-proto/`, with its generated
Rust committed, so that no code generator enters the measured build. Both
workspaces pin the same upstream commit, and a test fails when they differ.
[`enclave-proto/README.md`](../enclave-proto/README.md) has the sync
procedure. A sync changes PCR0.

## Features

The default feature set is empty. A production image has one signer role:

```bash
# Mint signer (EVM -> RGB)
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,spv,mint-signer

# Burn signer (RGB -> EVM)
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,spv,burn-signer

# Local TCP dev build (debug profile, seed import allowed)
cargo build -p utexo-bridge-enclave --no-default-features --features allow-seed-import,spv,mint-signer
```

| Feature | Implies | Description |
|---------|---------|-------------|
| `mint-signer` | `rgb-validation`, `kms-persistence` | Signer role: EVM -> RGB only (mint PSBT, `SignBtc`, `SignRightsRefill`). |
| `burn-signer` | `rgb-validation` | Signer role: RGB -> EVM only (`fundsOut`, gas transaction). |
| `spv` | `rgb-validation` | The Bitcoin header chain in the enclave and the witness inclusion proofs. |
| `rgb-validation` | The RGB crates and the EVM client | Consignment validation, the BFA checks and the EVM RPC client. Without it the enclave refuses every bridge request. |
| `kms-persistence` | - | KMS seed generation and recovery with an encrypted copy in S3. Requires `mint-signer`. |
| `vsock` | - | The vsock listener and forwarders (Linux). |
| `allow-seed-import` | - | Mnemonic and raw-seed import. Dev only. |
| `mock-attestation` | - | Raw-CBOR attestation with zero PCRs. Dev only. |
| `allow-debug-pcrs` | - | Removes the all-zero PCR rejection from the attestation verifier. Dev only. |

Compile-time guards in `enclave/src/lib.rs`, each checked in CI:

- `rgb-validation` needs exactly one of `mint-signer` and `burn-signer`.
- `kms-persistence` needs `mint-signer`.
- `rgb-validation` without `spv` needs a signer role and no dev feature.
  The limit of such a build to public Signet is a boot check.
- The three dev features do not compile in a release profile.

Do not combine mutually exclusive features with `--all-features`.

The release profile builds for size with LTO, one codegen unit,
`panic = "abort"` and a stripped binary.

## Enclave image (EIF)

```bash
RGB_ASSET_ID="rgb:<approved-bfa-contract-id>" KMS_ALLOWED_ACCOUNT_IDS="<12-digit AWS account id>" \
  DOCKERFILE=Dockerfile.enclave.mint ./build/build-enclave.sh   # mint signer
RGB_ASSET_ID="rgb:<approved-bfa-contract-id>" DOCKERFILE=Dockerfile.enclave.burn ./build/build-enclave.sh   # burn signer
```

The script builds the Docker image, converts it with
`nitro-cli build-enclave`, and writes the EIF, `PCR.json`, `SHA256SUMS` and
`IMAGE-ENV.json` to `build/`. Each recipe checks the binary with the dynamic
loader of its runtime image before the conversion, so a missing library
fails the build, not the launch.

**Inputs.**

- `RGB_ASSET_ID`: the id of the approved BFA contract. There is no default.
  The helper refuses an empty value; it does not validate the id.
- `KMS_ALLOWED_ACCOUNT_IDS` (mint only): the 12-digit AWS account ids of the
  seed KMS key, comma-separated. The helper refuses a missing or malformed
  list.
- Optional measured overrides. When `ENCLAVE_FEATURES`, `BITCOIN_NETWORK`,
  `BTC_RELAY_MODE`, a bridge pin, a `GAS_TX_*` setting or `RUST_LOG` is set
  in the environment, the helper passes it to the recipe, and PCR0 changes.
  Unset them to get the values of the recipe.

**What the image holds.** The recipes set the bridge pins and the acceptance
rules as `ENV` ([configuration.md](configuration.md#image-settings)), so PCR0
measures them. The image holds no cloning secret, no endpoint and no KMS key
ARN: a rebuild reproduces PCR0 without knowing them.

**The asset and its schema.** The BFA schema id is
`rgb:sch:3I0xZVEQnQxYVk7vDnh5uNtQyUfsmThw6dX9n_Gvb5o#mama-swing-album`. The
enclave refuses any other schema, so an asset issued on another schema does
not validate. Use the id of a BFA contract issued on this schema, for the
mint image and the burn image.

**Stage profiles.** `BUILD_PROFILE=stage-signet` builds both roles without
`spv` for public Signet. `BUILD_PROFILE=stage-mainnet` builds both roles with
`spv`, required relay checks and the new Stage mainnet contracts. Each profile
uses dedicated release inputs and its own S3 subdirectory; see
[build/profiles/README.md](../build/profiles/README.md).

**CI.** `.github/workflows/build-eif.yml` builds the `rgb-mint` and
`rgb-burn` variants and uploads each EIF with its PCRs, checksums,
`IMAGE-ENV.json`, `metadata.json` and host binaries to
`s3://<bucket>/eif/<git_sha>/rgb-<role>/`. It takes the asset from the
repository variable `BFA_RGB_ASSET_ID` and the account list from
`KMS_ALLOWED_ACCOUNT_IDS`, and records the asset pin of the built image in
`metadata.json`. `release-eif.yml` runs `deploy/deploy-host.sh` for one role
and one CID: its `enclave_cid` input is 16, 18 or 20, and 16 by default. It
passes no launch value, and `set-endpoints` of a role image refuses blank
values. The `cd-*.yml` workflows push container images
of the parent and of the dev enclave images only.

## Reproducibility

The recipes pin the inputs below, so that a rebuild of the same commit with
the same inputs gives the same PCR0, PCR1 and PCR2. Every source of the
enclave workspace is public, so a rebuild needs no credential. No CI job
compares two builds.

- the Rust toolchain, and the dependencies through `--locked`;
- both base images, by digest, in both EIF recipes;
- the OS packages, from a signed Debian snapshot named in each recipe. APT
  checks the repository signatures; its expiry check is off, because a fixed
  snapshot stays in use after its metadata expires;
- the build timestamps, through `SOURCE_DATE_EPOCH` (the commit time);
- the build paths, through path-prefix remapping, with `CARGO_INCREMENTAL=0`;
- the generated proto code, which is committed;
- `nitro-cli` and its kernel and init blobs, in the EIF workflow. PCR0 and
  PCR1 depend on them, so a local rebuild must use the same version and
  blobs.

Limits:

- The rgb-lib revision is not on a release tag yet, so a rebuild depends on
  RGB-Tools keeping that commit reachable.
- CI does not pin the Docker, Buildx and BuildKit versions.
- The parent image and the dev images use live APT repositories. They are
  not measured.

To reproduce a published EIF, use the values recorded with it
(`metadata.json`, `IMAGE-ENV.json`): the asset id, the account list and every
setting that differs from the recipe. Do not use the current repository
variables.
A change of a base image, the toolchain or a measured input changes the
measurements: build new EIFs and approve their PCRs before you update an
attestation allowlist or a KMS policy.

Record with each release: the source commit, the role and profile, the asset
and the other measured inputs, the tool versions, the checksums and the PCRs.
An upload to S3 is not a public release, and it is not proof of a
deployment.

To publish a Stage Signet or Stage mainnet build and its measurements for cosigners, use
[Publish EIF Release](github-releases.md). It promotes existing build artifacts
without rebuilding or deploying them.

## Parent image

```bash
docker build --secret id=federated_key,src=<absolute-path> \
  -f build/Dockerfile.parent -t utexo-bridge-parent .
```

`make build_parent*` passes `DOCKER_AUTH_ARGS` to `docker build`: set it to
the `--secret` argument above. `make build_enclave*` takes no secret. The
`insecure-dev` parent feature (plaintext gRPC with no client check) is for
dev images only (`make build_parent_dev`); a release build with it does not
compile.
