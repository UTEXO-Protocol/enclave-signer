#!/usr/bin/env bash
# Build an enclave image and convert it to an EIF.
# Write the EIF, PCR.json, and SHA256SUMS to OUT_DIR.
# The caller uploads these files to S3.
#
# Usage: ./build/build-enclave.sh
# Environment:
#   OUT_DIR          output directory (default: build/)
#   IMAGE_TAG        image tag (default: utexo-bridge-enclave:latest)
#   DOCKERFILE       recipe name (default: Dockerfile.enclave)
#   EIF_NAME         output name (default: utexo-bridge-enclave.eif)
#   NITRO_CLI_BLOBS   optional Nitro kernel/init directory
#   GITHUB_TOKEN     private dependency token
#   PRIVATE_DEPS_DIR alternative directory for per-repository deploy keys
#   RGB_ASSET_ID     required when the recipe declares ARG RGB_ASSET_ID
#   ENCLAVE_DEBUG_FEATURES optional test features; leave empty for production
#   SOURCE_DATE_EPOCH build timestamp (default: commit time)
#
# BuildKit mounts credentials as secrets.
# Supply the cloning secret at runtime through InitializeKey.
# Use the target host's nitro-cli version to keep measurements consistent.
# Normalize timestamps with buildx rewrite-timestamp for reproducible images.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUT_DIR="${OUT_DIR:-$SCRIPT_DIR}"
IMAGE_TAG="${IMAGE_TAG:-utexo-bridge-enclave:latest}"
# Which enclave image to build. Defaults to the combined (rgb+ccd) image; set
# DOCKERFILE=Dockerfile.enclave.rgb (send/receive RGB flow),
# Dockerfile.enclave.mint-burn (mint/burn RGB flow), Dockerfile.enclave.ccd for a
# lean single-network EIF, or Dockerfile.enclave.bfa for the BFA mint EIF - which
# is the mint/burn flow on the bridged schema. Every variant
# needs private dependency credentials. EIF_NAME names the output .eif (and thus the SHA256SUMS
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

# The same credential setup applies to every enclave Dockerfile.
SECRET_ARGS=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
    SECRET_ARGS=(--secret "id=github_token,env=GITHUB_TOKEN")
elif [ -n "${PRIVATE_DEPS_DIR:-}" ]; then
    for key in consignment_key consensus_key ops_key schemas_key; do
        [ -s "$PRIVATE_DEPS_DIR/$key" ] || {
            echo "Error: missing private dependency key file: $key" >&2
            exit 1
        }
        SECRET_ARGS+=(--secret "id=$key,src=$PRIVATE_DEPS_DIR/$key")
    done
else
    echo "Error: set GITHUB_TOKEN or PRIVATE_DEPS_DIR for the private RGB dependencies" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# Require an asset when the selected Dockerfile declares RGB_ASSET_ID.
# Reject a missing asset before the build starts. (F06-AF-38)
# A fixed ENV asset does not need a build argument.
BUILD_ARGS=()
if grep -qE '^ARG[[:space:]]+RGB_ASSET_ID' "$SCRIPT_DIR/$DOCKERFILE"; then
    if [ -z "${RGB_ASSET_ID:-}" ]; then
        echo "Error: $DOCKERFILE requires RGB_ASSET_ID (the issued BFA contract id, e.g. rgb:<...>)." >&2
        echo "       Set RGB_ASSET_ID=rgb:<contract-id> and re-run; an empty pin leaves the" >&2
        echo "       enclave config partially set and policy.rs refuses to boot." >&2
        exit 1
    fi
    BUILD_ARGS+=(--build-arg "RGB_ASSET_ID=$RGB_ASSET_ID")
    echo "    rgb asset id : $RGB_ASSET_ID"
fi

# Forward debug features only when set. (F03-AF-12)
# Do not set ENCLAVE_DEBUG_FEATURES for production builds.
if [ -n "${ENCLAVE_DEBUG_FEATURES:-}" ]; then
    BUILD_ARGS+=(--build-arg "ENCLAVE_DEBUG_FEATURES=$ENCLAVE_DEBUG_FEATURES")
    echo "    DEBUG feats  : $ENCLAVE_DEBUG_FEATURES  (⚠ NON-PRODUCTION EIF)"
fi

# --- 1. Build the docker image ---------------------------------------------
# Deterministic timestamps: SOURCE_DATE_EPOCH (commit time, stable per git_sha)
# + `rewrite-timestamp=true` make BuildKit normalise file mtimes in the exported
# layers, so two builds of the same commit yield the same rootfs -> same PCR0.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$PROJECT_ROOT" log -1 --format=%ct 2>/dev/null || echo 1700000000)}"
export SOURCE_DATE_EPOCH

echo "Building Docker image (buildx, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)..."
# `${a[@]+...}`: bash 3.2 treats an empty array as unset under `set -u`.
DOCKER_BUILDKIT=1 docker buildx build \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} \
    ${SECRET_ARGS[@]+"${SECRET_ARGS[@]}"} \
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
