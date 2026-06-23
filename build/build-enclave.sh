#!/usr/bin/env bash
# Build the production enclave image (vsock + rgb-validation + spv), convert it
# to an EIF, and emit the artifacts a deployment needs:
#   - utexo-bridge-enclave.eif   the enclave image
#   - PCR.json                   PCR0/1/2 measurements (from `nitro-cli describe-eif`)
#   - SHA256SUMS                 sha256 of the EIF (integrity check before run-enclave)
#
# Environment-agnostic: runs the same on a Nitro EC2 build host and on a CI
# runner. It does NOT touch S3 — uploading/publishing is the caller's job
# (the build-eif workflow handles AWS auth + S3). This keeps the script a pure,
# reproducible build step.
#
# Private dep: the `rgb-validation`/`spv` features pull `rgb-consignment` over
# SSH. BuildKit `--ssh default` forwards the host's ssh-agent into the build for
# the duration of the cargo fetch only (no key in image layers). Make sure a
# read-only deploy key is loaded into the agent before running:
#   eval "$(ssh-agent -s)" && ssh-add <deploy-key>
#
# Reproducible PCRs: PCR0/PCR1 depend on the nitro-cli version + its blobs
# (kernel/init), NOT just our code. Pin nitro-cli to the SAME version that runs
# on the target hosts (stage hosts are on 1.4.5) or PCRs will not match.
#
# Usage:
#   ./build/build-enclave.sh
# Tunables (env):
#   OUT_DIR                output directory for artifacts (default: build/)
#   IMAGE_TAG              docker tag for the builder image (default: utexo-bridge-enclave:latest)
#   NITRO_CLI_BLOBS        override blobs dir for `nitro-cli build-enclave`
# NOTE: the donor cloning secret is NOT baked into the EIF. It is delivered at
# runtime via the InitializeKey message (CLI: `init --cloning-secret <secret>`),
# keeping the build secret-free and the PCRs reproducible.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUT_DIR="${OUT_DIR:-$SCRIPT_DIR}"
IMAGE_TAG="${IMAGE_TAG:-utexo-bridge-enclave:latest}"
EIF_PATH="$OUT_DIR/utexo-bridge-enclave.eif"

echo "=== Building UTEXO Bridge Enclave ==="
echo "    project root : $PROJECT_ROOT"
echo "    output dir   : $OUT_DIR"
echo "    image tag    : $IMAGE_TAG"

command -v docker   &>/dev/null || { echo "Error: docker not found"; exit 1; }
command -v nitro-cli &>/dev/null || { echo "Error: nitro-cli not found (install + pin to the host version)"; exit 1; }
command -v jq       &>/dev/null || { echo "Error: jq not found"; exit 1; }

mkdir -p "$OUT_DIR"

# --- 1. Build the docker image (BuildKit + ssh-agent forwarding) ------------
# The Dockerfile's `RUN --mount=type=ssh` consumes `--ssh default`.
echo "Building Docker image (BuildKit, --ssh default)..."
DOCKER_BUILDKIT=1 docker build \
    --ssh default \
    -f "$SCRIPT_DIR/Dockerfile.enclave" \
    -t "$IMAGE_TAG" \
    "$PROJECT_ROOT"

# --- 2. Convert to EIF ------------------------------------------------------
# nitro-cli picks up an alternate blobs dir from the NITRO_CLI_BLOBS env var
# (no dedicated flag); export it if the caller provided one.
echo "Building EIF..."
[ -n "${NITRO_CLI_BLOBS:-}" ] && export NITRO_CLI_BLOBS
nitro-cli build-enclave \
    --docker-uri "$IMAGE_TAG" \
    --output-file "$EIF_PATH"

# --- 3. Emit measurements + checksums --------------------------------------
echo "Extracting PCRs..."
nitro-cli describe-eif --eif-path "$EIF_PATH" \
    | jq '.Measurements' > "$OUT_DIR/PCR.json"

echo "Writing SHA256SUMS..."
( cd "$OUT_DIR" && sha256sum "$(basename "$EIF_PATH")" > SHA256SUMS )

echo ""
echo "=== Build Complete ==="
echo "EIF       : $EIF_PATH"
echo "PCR.json  : $OUT_DIR/PCR.json"
echo "SHA256SUMS: $OUT_DIR/SHA256SUMS"
echo ""
echo "PCRs:"
cat "$OUT_DIR/PCR.json"
echo ""
