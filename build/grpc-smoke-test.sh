#!/bin/bash
# =============================================================================
# gRPC Smoke Test Suite (via grpcurl)
# =============================================================================
# Tests the parent's gRPC service `parent.ParentService`
# (`proto/enclave/parent.proto` of federated-signer-proto).
#
# Setup: grpcurl installed; a burn-signer parent in plaintext loopback mode
# (USE_VSOCK=true GRPC_ALLOW_INSECURE_LOOPBACK=true ./parent/target/release/utexo-bridge-parent)
# with its enclave keyed and endpoints set; PROTO_DIR is the `proto/` dir of
# federated-signer-proto at the rev that parent/Cargo.toml pins.
# Usage: ./grpc-smoke-test.sh [--addr=HOST:PORT]
# Each negative case sends its own payload and passes only on the expected gRPC code and message.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

ADDR="127.0.0.1:5000"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="${PROTO_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/federated-signer-proto/proto}"

while [ $# -gt 0 ]; do
    case $1 in
        --addr=*) ADDR="${1#*=}" ;;
        --addr)
            [ $# -ge 2 ] || { echo "--addr needs a value" >&2; exit 2; }
            shift; ADDR="$1" ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

log()  { echo -e "${YELLOW}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1: $2"; FAIL=$((FAIL + 1)); }

command -v grpcurl &>/dev/null || {
    echo -e "${RED}Error: grpcurl not found. Install with: brew install grpcurl${NC}"
    exit 1
}

[ -f "$PROTO_DIR/enclave/parent.proto" ] || {
    echo -e "${RED}Error: parent.proto not found in: $PROTO_DIR${NC}"
    echo "The parent gRPC schema is not vendored in this repo. Clone"
    echo "  https://github.com/UTEXO-Protocol/federated-signer-proto"
    echo "and re-run with PROTO_DIR=/path/to/that/checkout/proto"
    exit 1
}

echo "============================================="
echo "  gRPC Smoke Tests (parent.ParentService)"
echo "  Target: $ADDR"
echo "  Proto:  $PROTO_DIR"
echo "============================================="
echo ""

GRPCURL=(grpcurl -plaintext -import-path "$PROTO_DIR" -proto enclave/parent.proto)

# call METHOD PAYLOAD: sets OUT and RC.
call() {
    OUT=$("${GRPCURL[@]}" -d "$2" "$ADDR" "parent.ParentService/$1" 2>&1) && RC=0 || RC=$?
}

# expect_ok NAME METHOD PAYLOAD FIELD
expect_ok() {
    log "$1"
    call "$2" "$3"
    if [ "$RC" -eq 0 ] && grep -q "\"$4\"" <<<"$OUT"; then
        pass "$1"
    else
        fail "$1" "$OUT"
    fi
}

# expect_error NAME METHOD PAYLOAD CODE MESSAGE
expect_error() {
    log "$1"
    call "$2" "$3"
    if [ "$RC" -ne 0 ] && grep -qx "  Code: $4" <<<"$OUT" \
        && grep '^  Message: ' <<<"$OUT" | grep -qF -- "$5"; then
        pass "$1"
    else
        fail "$1" "expected $4 / $5, got: $OUT"
    fi
}

# Zero bytes in base64, for bytes fields in grpcurl JSON.
zeros() { head -c "$1" /dev/zero | base64 | tr -d '\n'; }
NONCE_32=$(zeros 32)
NONCE_31=$(zeros 31)
COMMON='"common":{"srcNetworkId":84,"dataType":"TRANSACTION","dstNetworkId":1}'

expect_ok "PublicKey" PublicKey '{"networkId":1,"dataType":"TRANSACTION"}' publicKey
expect_ok "AttestedPublicKey (32-byte nonce)" AttestedPublicKey "{\"nonce\":\"$NONCE_32\"}" evmAddress

expect_error "Sign without common" Sign '{}' \
    InvalidArgument "SignRequest.common is missing"
expect_error "AttestedPublicKey (31-byte nonce)" AttestedPublicKey "{\"nonce\":\"$NONCE_31\"}" \
    InvalidArgument "nonce must be 32 bytes, got 31"
expect_error "SubmitHeaders" SubmitHeaders '{"startHeight":1}' \
    PermissionDenied "SubmitHeaders is closed"

# The other signer role's direction. It reaches the enclave, which refuses it.
expect_error "Sign EVM -> RGB on the burn signer" Sign \
    "{$COMMON,\"source\":{\"amount\":1000,\"evm\":{\"txHash\":\"$NONCE_32\",\"fundsInOperationId\":\"$NONCE_32\"}},\"rgbData\":{\"psbtBytes\":\"AA==\"}}" \
    Internal "it does not sign EVM -> RGB bridge PSBTs"

# ---------------------------------------------
# Summary
# ---------------------------------------------
echo ""
echo "============================================="
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "============================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
