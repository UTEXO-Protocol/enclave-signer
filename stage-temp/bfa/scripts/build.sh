#!/usr/bin/env bash
# Build only the temporary BFA recipe. Read public mode and asset from config.json.
# Supply private dependency credentials through BuildKit secret mounts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/stage-temp/bfa/artifacts}"
mapfile -t CONFIG < <(python3 "$SCRIPT_DIR/config.py" "$PROJECT_ROOT/stage-temp/bfa/config.json")
[ "${#CONFIG[@]}" -eq 2 ] || { echo "invalid temporary build config" >&2; exit 1; }
STAGE_BFA_MODE="${CONFIG[0]}"
RGB_ASSET_ID="${CONFIG[1]}"
IMAGE_TAG="stage-bfa-temp:${STAGE_BFA_MODE}"
DOCKERFILE="$PROJECT_ROOT/stage-temp/bfa/Dockerfile"
EIF_NAME="stage-bfa-temp.eif"
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

BUILD_ARGS=(--build-arg "STAGE_BFA_MODE=$STAGE_BFA_MODE" --build-arg "RGB_ASSET_ID=$RGB_ASSET_ID")

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
    -f "$DOCKERFILE" \
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
