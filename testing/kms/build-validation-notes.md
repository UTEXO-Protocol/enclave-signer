# Local Linux release and EIF build validation

On 2026-09-14, both RGB-swap and mint/burn ARM64 release binaries were built
from production commit `484fe4dc2d0bbafb9bf41638527c1a89d587c05f`, with their
production feature sets and no mock/import/dev features. Both passed the
dynamic loader checks in the pinned AL2023 runtime. The swap binary required
at most GLIBC 2.34. A real unsigned ARM64 EIF was packaged using Nitro CLI
1.4.5 and its ARM64 blobs; `describe-eif` returned `CheckCRC: true`.

| Artifact | SHA-256 |
| --- | --- |
| Swap release binary | `4d31e565f7104e014fac727dda154f7c01b8de23db1465d0113892ebea78b926` |
| Mint/burn release binary | `3dfdf1a8835636aa9ba3beb8b150f8782983279502806690ff70b39773677e58` |
| Swap validation EIF | `88219fd3ff32d1aa6e20190ad60a98c6398eb8dbc467877b756b12a0126bc090` |

The EIF used a fixture KMS ARN and seed ID, so it is a build-validation
artifact. No Nitro hardware execution or real AWS call was performed. The
repository's Bullseye builder encountered Debian security-package HTTP 404s;
the successful build used the pinned Bookworm builder below and checked
AL2023 compatibility explicitly. Local Docker lacked buildx, so the runtime
image used the legacy builder. Cargo release defaults were used, without the
production Dockerfile's path-remapping/stripping flags. These results do not
assert production PCR reproducibility or provide deployable measurements.

## Reusable commands

Run from the repository root with Docker, Python 3, Git, and the repository's
private dependencies already fetched into the host Cargo cache. Keep generated
files in the ignored `.artifacts` directory. These commands reproduce the
validation procedure; timestamps, source changes, and build paths can change
artifact hashes and PCRs.

```bash
KMS_REPO_ROOT="$(pwd)"
KMS_BUILD_DIR="$KMS_REPO_ROOT/.artifacts/kms-build-validation"
KMS_CARGO_CACHE="${CARGO_HOME:-$HOME/.cargo}"
KMS_RUST_IMAGE=rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663
KMS_RUNTIME_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:2023-minimal@sha256:8073d921f4ac1bf17fca94e16b0bc575e3fc17e4ccbe53b563160f02f0c7ccfc
mkdir -p "$KMS_BUILD_DIR/target" "$KMS_BUILD_DIR/out"

docker run --rm --cpus 3 \
  -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS=3 -e CARGO_INCREMENTAL=0 \
  -v "$KMS_REPO_ROOT:/build:ro" \
  -v "$KMS_CARGO_CACHE/registry:/usr/local/cargo/registry:ro" \
  -v "$KMS_CARGO_CACHE/git:/usr/local/cargo/git:ro" \
  -v "$KMS_BUILD_DIR/target:/target" -v "$KMS_BUILD_DIR/out:/out" \
  -w /build "$KMS_RUST_IMAGE" sh -ec '
    apt-get update
    apt-get install -y --no-install-recommends cmake
    for flow in rgb-swap rgb-mint-burn; do
      cargo build --offline --locked --release -p utexo-bridge-enclave \
        --bin utexo-bridge-enclave --no-default-features \
        --features "vsock,$flow,evm-rpc"
      cp /target/release/utexo-bridge-enclave "/out/utexo-bridge-enclave-$flow-aarch64-linux"
    done
  '

docker run --rm -v "$KMS_BUILD_DIR/out:/out:ro" "$KMS_RUNTIME_IMAGE" sh -ec '
  for flow in rgb-swap rgb-mint-burn; do
    /lib/ld-linux-aarch64.so.1 --verify "/out/utexo-bridge-enclave-$flow-aarch64-linux"
    /lib/ld-linux-aarch64.so.1 --list "/out/utexo-bridge-enclave-$flow-aarch64-linux"
  done
'
```

Build the exact public Nitro CLI tool used by the repository, with an isolated
Cargo cache. The source revision checked below is the inspected v1.4.5 tag.

```bash
git clone --depth 1 --branch v1.4.5 \
  https://github.com/aws/aws-nitro-enclaves-cli.git "$KMS_BUILD_DIR/nitro-src"
test "$(git -C "$KMS_BUILD_DIR/nitro-src" rev-parse HEAD)" = \
  18a5f6f35f110c0f235f193ae3caff9434d64ee1
mkdir -p "$KMS_BUILD_DIR/nitro-cargo" "$KMS_BUILD_DIR/nitro-target"
docker run --rm --cpus 2 -e CARGO_HOME=/nitro-cargo \
  -e CARGO_TARGET_DIR=/nitro-target -e CARGO_BUILD_JOBS=2 \
  -v "$KMS_BUILD_DIR/nitro-src:/nitro-src:ro" \
  -v "$KMS_BUILD_DIR/nitro-cargo:/nitro-cargo" \
  -v "$KMS_BUILD_DIR/nitro-target:/nitro-target" \
  -v "$KMS_BUILD_DIR/out:/out" -w /nitro-src "$KMS_RUST_IMAGE" sh -ec '
    apt-get update
    apt-get install -y --no-install-recommends cmake
    cargo build --locked --release -p nitro-cli
    cp /nitro-target/release/nitro-cli /out/nitro-cli
    /out/nitro-cli --version
  '
```

Reuse the production runtime stage, substituting only the separately compiled
binary's source path. Fixture KMS settings are explicit build arguments.

```bash
python3 - "$KMS_REPO_ROOT" "$KMS_BUILD_DIR/out" <<'PY'
from pathlib import Path
import shutil, sys
repo, out = map(Path, sys.argv[1:])
runtime = (repo / 'build/Dockerfile.enclave.rgb').read_text().split('# --- Runtime ---', 1)[1]
runtime = runtime.replace(
    'COPY --from=builder /build/target/release/utexo-bridge-enclave /app/utexo-bridge-enclave',
    'COPY utexo-bridge-enclave-rgb-swap-aarch64-linux /app/utexo-bridge-enclave')
runtime = runtime.replace('COPY build/entrypoint.sh /app/entrypoint.sh',
                          'COPY entrypoint.sh /app/entrypoint.sh')
(out / 'Dockerfile.swap-validation').write_text(runtime)
shutil.copy2(repo / 'build/entrypoint.sh', out / 'entrypoint.sh')
PY
DOCKER_BUILDKIT=0 docker build \
  --build-arg SWAP_KMS_KEY_ARN=arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
  --build-arg SWAP_KMS_REGION=eu-west-1 \
  --build-arg SWAP_KMS_SEED_ID=local-build-validation-only \
  --build-arg SWAP_KMS_ALLOW_CREATE=1 \
  --build-arg SWAP_KMS_EXPECTED_EVM_ADDRESS= \
  -f "$KMS_BUILD_DIR/out/Dockerfile.swap-validation" \
  -t codex-kms-swap-build-validation:local "$KMS_BUILD_DIR/out"

docker run --rm -e NITRO_CLI_BLOBS=/blobs \
  -e NITRO_CLI_ARTIFACTS=/tmp/nitro-artifacts -e DOCKER_API_VERSION=1.44 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$KMS_BUILD_DIR/nitro-src/blobs/aarch64:/blobs:ro" \
  -v "$KMS_BUILD_DIR/out:/out" "$KMS_RUST_IMAGE" sh -ec '
    mkdir -p /tmp/nitro-artifacts /var/log/nitro_enclaves /run/nitro_enclaves
    /out/nitro-cli build-enclave \
      --docker-uri codex-kms-swap-build-validation:local \
      --output-file /out/rgb-swap-validation-arm64.eif
    /out/nitro-cli describe-eif --eif-path /out/rgb-swap-validation-arm64.eif \
      > /out/rgb-swap-validation-arm64.describe.json
    cd /out
    sha256sum rgb-swap-validation-arm64.eif > rgb-swap-validation-arm64.eif.sha256
  '
```

The Docker socket mount above lets Nitro CLI read the local validation image
and package its filesystem. It does not run an enclave or change the existing
application containers. This procedure was exercised on an ARM64 Docker host.
Use matching builder, binary, and Nitro blobs for another architecture.
