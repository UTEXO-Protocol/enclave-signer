#!/usr/bin/env bash
# Build the production enclave image (vsock + rgb-validation + spv), convert it
# to an EIF, and emit the artifacts a deployment needs:
#   - utexo-bridge-enclave.eif   the enclave image
#   - PCR.json                   PCR0/1/2 measurements (from `nitro-cli describe-eif`)
#   - SHA256SUMS                 sha256 of the EIF (integrity check before run-enclave)
#
# Environment-agnostic: runs the same on a Nitro EC2 build host and on a CI
# runner. It does not touch S3 - uploading is the caller's job (the build-eif
# workflow handles AWS auth + S3).
#
# NO CREDENTIALS REQUIRED. Every enclave dependency resolves over public HTTPS,
# so a third party can run this and reproduce the PCRs it prints. `parent/`,
# which does need a private crate, is a separate workspace this never touches.
#
# Reproducible PCRs: PCR0/PCR1 depend on the nitro-cli version and its blobs
# (kernel/init), not just our code. Pin nitro-cli to the same version the target
# hosts run (stage is on 1.4.5) or the PCRs will not match.
#
# On the build side the EIF packs the runtime-stage rootfs, so the image build
# must be deterministic: both base images are digest-pinned in
# Dockerfile.enclave, and layer timestamps are normalised via SOURCE_DATE_EPOCH
# plus BuildKit's `rewrite-timestamp` exporter (needs `docker buildx` with a
# container/containerd builder). SOURCE_DATE_EPOCH defaults to the commit time.
# OS package versions (apt/dnf) still float.
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
# Which enclave image to build. Defaults to the combined (rgb+ccd) image; set
# DOCKERFILE=Dockerfile.enclave.rgb (send/receive RGB flow),
# Dockerfile.enclave.mint-burn (mint/burn RGB flow) or Dockerfile.enclave.ccd for a lean
# single-network EIF. EIF_NAME names the output .eif (and thus the SHA256SUMS
# entry); default keeps the historical artifact name.
DOCKERFILE="${DOCKERFILE:-Dockerfile.enclave}"
EIF_NAME="${EIF_NAME:-utexo-bridge-enclave.eif}"
EIF_PATH="$OUT_DIR/$EIF_NAME"

echo "=== Building UTEXO Bridge Enclave ==="
echo "    project root : $PROJECT_ROOT"
echo "    output dir   : $OUT_DIR"
echo "    image tag    : $IMAGE_TAG"
echo "    dockerfile   : $DOCKERFILE"
echo "    eif name     : $EIF_NAME"

command -v docker   &>/dev/null || { echo "Error: docker not found"; exit 1; }
command -v nitro-cli &>/dev/null || { echo "Error: nitro-cli not found (install + pin to the host version)"; exit 1; }
command -v jq       &>/dev/null || { echo "Error: jq not found"; exit 1; }

mkdir -p "$OUT_DIR"

# --- 1. Build the docker image ---------------------------------------------
# Deterministic timestamps: SOURCE_DATE_EPOCH (commit time, stable per git_sha)
# + `rewrite-timestamp=true` make BuildKit normalise file mtimes in the exported
# layers, so two builds of the same commit yield the same rootfs -> same PCR0.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$PROJECT_ROOT" log -1 --format=%ct 2>/dev/null || echo 1700000000)}"
export SOURCE_DATE_EPOCH

echo "Building Docker image (buildx, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)..."
DOCKER_BUILDKIT=1 docker buildx build \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -f "$SCRIPT_DIR/$DOCKERFILE" \
    -t "$IMAGE_TAG" \
    --output "type=docker,rewrite-timestamp=true" \
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
