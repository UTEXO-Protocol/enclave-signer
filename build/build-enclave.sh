#!/usr/bin/env bash
# Build an enclave image and convert it to an EIF.
# IMAGE-ENV.json is the env of the measured image. The deploy launch check
# reads the expected policy pins from it.
# The caller uploads these files to S3.
#
# Usage: ./build/build-enclave.sh
# Environment:
#   OUT_DIR          output directory (default: build/)
#   IMAGE_TAG        image tag (default: utexo-bridge-enclave:latest)
#   DOCKERFILE       recipe name (required)
#   EIF_NAME         output name (default: utexo-bridge-enclave.eif)
#   NITRO_CLI_BLOBS  optional Nitro kernel/init directory
#   RGB_ASSET_ID     required when the recipe declares ARG RGB_ASSET_ID
#                    (mint, burn)
#   KMS_ALLOWED_ACCOUNT_IDS  mint only: AWS accounts of the seed KMS key; the
#                    recipe fails the build without it
#   ENCLAVE_DEBUG_FEATURES optional test features; leave empty for production
#   SOURCE_DATE_EPOCH build timestamp (default: commit time)
#   RGB_LIB_BFA_DEPLOY_KEY  deploy key with read access to UTEXO-Protocol/rgb-lib-bfa
#   RGB_PRIVATE_DEPS_TOKEN  token with read access to the UTEXO-Protocol/<repo>-s-bfa
#                           mirrors of the RGB protocol crates
#   PRIVATE_DEPS_DIR        or a directory with those in lib_key and rgb_deps_token files
#
# rgb-lib and the RGB protocol crates it pins come from private mirrors. The
# key and the token go in BuildKit secrets: never in a build arg, a layer, the
# image or PCR0.
#
# Reproducible PCRs: PCR0/PCR1 depend on the nitro-cli version and its blobs
# (kernel/init), not just our code. Pin nitro-cli to the same version the target
# hosts run (stage is on 1.4.5) or the PCRs will not match.
#
# On the build side the EIF packs the runtime-stage rootfs, so the image build
# must be deterministic: both base images are digest-pinned in each enclave
# Dockerfile, and layer timestamps are normalised via SOURCE_DATE_EPOCH
# plus BuildKit's `rewrite-timestamp` exporter (needs `docker buildx` with a
# container/containerd builder). SOURCE_DATE_EPOCH defaults to the commit time.
# EIF recipes pin OS packages to a signed Debian snapshot.
#
# Usage:
#   ./build/build-enclave.sh
# Tunables (env):
#   OUT_DIR                output directory for artifacts (default: build/)
#   IMAGE_TAG              docker tag for the builder image (default: utexo-bridge-enclave:latest)
#   RGB_ASSET_ID           required approved asset pin for every Dockerfile that
#                          declares ARG RGB_ASSET_ID (mint, burn)
#   NITRO_CLI_BLOBS        override blobs dir for `nitro-cli build-enclave`
# NOTE: the donor cloning secret is NOT baked into the EIF. It is delivered at
# runtime via the InitializeKey message (CLI: `init --cloning-secret <secret>`),
# keeping it out of the image and the PCRs reproducible.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUT_DIR="${OUT_DIR:-$SCRIPT_DIR}"
IMAGE_TAG="${IMAGE_TAG:-utexo-bridge-enclave:latest}"
# Which enclave image to build. Required. Production is
# DOCKERFILE=Dockerfile.enclave.mint / Dockerfile.enclave.burn (the two BFA
# signer EIFs). The other one is Dockerfile.enclave.ccd. EIF_NAME names the
# output .eif and its SHA256SUMS entry; the default keeps the historical
# artifact name.
DOCKERFILE="${DOCKERFILE:?DOCKERFILE required (Dockerfile.enclave.mint, .burn or .ccd)}"
BUILD_PROFILE="${BUILD_PROFILE:-default}"
case "$BUILD_PROFILE" in
    default) ;;
    stage-signet) source "$SCRIPT_DIR/profiles/stage-signet.sh" ;;
    *) echo "Error: unknown BUILD_PROFILE: $BUILD_PROFILE" >&2; exit 1 ;;
esac
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

# Require an asset when the selected Dockerfile declares RGB_ASSET_ID.
# Reject a missing asset before the build starts. (F06-AF-38)
# A fixed ENV asset does not need a build argument.
BUILD_ARGS=()
declares_build_arg() {
    grep -qE "^[[:space:]]*ARG[[:space:]]+$1([=[:space:]]|$)" "$SCRIPT_DIR/$DOCKERFILE"
}
if declares_build_arg RGB_ASSET_ID; then
    if [ -z "${RGB_ASSET_ID:-}" ]; then
        echo "Error: $DOCKERFILE requires RGB_ASSET_ID (the issued BFA contract id, e.g. rgb:<...>)." >&2
        echo "       Set RGB_ASSET_ID=rgb:<contract-id> and re-run; the image build fails without it." >&2
        exit 1
    fi
    BUILD_ARGS+=(--build-arg "RGB_ASSET_ID=$RGB_ASSET_ID")
    echo "    rgb asset id : $RGB_ASSET_ID"
fi

# The mint recipe pins the AWS accounts of the seed KMS key. Refuse a missing
# or malformed list here, before the long build: the recipe's own check only
# tests that it is not empty.
if declares_build_arg KMS_ALLOWED_ACCOUNT_IDS; then
    if [ -z "${KMS_ALLOWED_ACCOUNT_IDS:-}" ]; then
        echo "Error: $DOCKERFILE requires KMS_ALLOWED_ACCOUNT_IDS (the AWS account id of the seed KMS key)." >&2
        echo "       Set KMS_ALLOWED_ACCOUNT_IDS=<12-digit id>[,<12-digit id>...] and re-run." >&2
        exit 1
    fi
    if ! [[ "$KMS_ALLOWED_ACCOUNT_IDS" =~ ^[0-9]{12}(,[0-9]{12})*$ ]]; then
        echo "Error: KMS_ALLOWED_ACCOUNT_IDS must be comma-separated 12-digit AWS account ids, got '$KMS_ALLOWED_ACCOUNT_IDS'." >&2
        exit 1
    fi
    BUILD_ARGS+=(--build-arg "KMS_ALLOWED_ACCOUNT_IDS=$KMS_ALLOWED_ACCOUNT_IDS")
    echo "    kms accounts : $KMS_ALLOWED_ACCOUNT_IDS"
fi

# Optional measured configuration for the mint/burn recipes. Unset values
# retain each Dockerfile's production defaults.
if declares_build_arg ENCLAVE_FEATURES; then
    # Match Docker's effective defaults when an override is unset or empty.
    build_features="${ENCLAVE_FEATURES:-$(sed -n 's/^ARG ENCLAVE_FEATURES=//p' "$SCRIPT_DIR/$DOCKERFILE")}"
    bitcoin_network="${BITCOIN_NETWORK:-$(sed -n 's/^ARG BITCOIN_NETWORK=//p' "$SCRIPT_DIR/$DOCKERFILE")}"
    if [ "$bitcoin_network" != signet ] && \
        ! grep -qE '(^|[[:space:],])rgb([[:space:],]|$)' <<< "$build_features"; then
        echo "Error: $DOCKERFILE requires the rgb feature when BITCOIN_NETWORK=$bitcoin_network." >&2
        echo "       Include rgb in ENCLAVE_FEATURES; omitting it is supported only on signet." >&2
        exit 1
    fi
    for arg in ENCLAVE_FEATURES BITCOIN_NETWORK BTC_RELAY_MODE EVM_CHAIN_ID \
        EVM_PROXY_CONTRACT_ADDRESS FUNDS_IN_CONTRACT TOKEN_CONTRACT ENDPOINTS_SHA256 \
        GAS_TX_ALLOWED_TO GAS_TX_MAX_GAS_LIMIT GAS_TX_MAX_FEE_PER_GAS GAS_TX_MAX_VALUE_WEI \
        GAS_TX_ALLOWED_SELECTORS RUST_LOG; do
        if [ -n "${!arg:-}" ] && declares_build_arg "$arg"; then
            BUILD_ARGS+=(--build-arg "$arg=${!arg}")
            echo "    build override: $arg=${!arg}"
        fi
    done
fi

if [ -n "${PRIVATE_DEPS_DIR:-}" ]; then
    for secret in lib_key rgb_deps_token; do
        [ -s "$PRIVATE_DEPS_DIR/$secret" ] || {
            echo "Error: $PRIVATE_DEPS_DIR/$secret is missing or empty." >&2
            exit 1
        }
    done
    SECRET_ARGS=(
        --secret "id=lib_key,src=$PRIVATE_DEPS_DIR/lib_key"
        --secret "id=rgb_deps_token,src=$PRIVATE_DEPS_DIR/rgb_deps_token"
    )
elif [ -n "${RGB_LIB_BFA_DEPLOY_KEY:-}" ] && [ -n "${RGB_PRIVATE_DEPS_TOKEN:-}" ]; then
    SECRET_ARGS=(
        --secret id=lib_key,env=RGB_LIB_BFA_DEPLOY_KEY
        --secret id=rgb_deps_token,env=RGB_PRIVATE_DEPS_TOKEN
    )
else
    echo "Error: the enclave build needs a deploy key with read access to UTEXO-Protocol/rgb-lib-bfa" >&2
    echo "       and a token with read access to the UTEXO-Protocol/<repo>-s-bfa RGB crate mirrors." >&2
    echo "       Set RGB_LIB_BFA_DEPLOY_KEY and RGB_PRIVATE_DEPS_TOKEN, or PRIVATE_DEPS_DIR with" >&2
    echo "       lib_key and rgb_deps_token files." >&2
    exit 1
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
    "${SECRET_ARGS[@]}" \
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
docker image inspect --format '{{json .Config.Env}}' "$IMAGE_TAG" > "$OUT_DIR/IMAGE-ENV.json"

echo "Writing SHA256SUMS..."
( cd "$OUT_DIR" && sha256sum "$(basename "$EIF_PATH")" > SHA256SUMS )

echo ""
echo "=== Build Complete ==="
echo "EIF       : $EIF_PATH"
echo "PCR.json  : $OUT_DIR/PCR.json"
echo "IMAGE-ENV : $OUT_DIR/IMAGE-ENV.json"
echo "SHA256SUMS: $OUT_DIR/SHA256SUMS"
echo ""
echo "PCRs:"
cat "$OUT_DIR/PCR.json"
echo ""
