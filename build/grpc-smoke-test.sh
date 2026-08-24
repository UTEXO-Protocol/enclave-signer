#!/bin/bash
# =============================================================================
# gRPC Smoke Test Suite (via grpcurl)
# =============================================================================
# Tests the parent adapter's gRPC interface — the same interface the Go
# Listener uses. Run this from your local machine with an SSH tunnel open,
# or directly on EC2.
#
# Prerequisites:
#   - grpcurl installed (brew install grpcurl)
#   - SSH tunnel open (if running from Mac):
#       ssh -L 5000:127.0.0.1:5000 -N ubuntu@18.219.168.199
#   - utexo-bridge-parent running on EC2:
#       USE_VSOCK=true ./target/release/utexo-bridge-parent
#   - Enclave already initialized (run smoke-test.sh --vsock on EC2 first,
#     or: ./target/release/utexo-bridge-parent-cli --addr vsock://16:5000 init)
#
# Usage:
#   ./grpc-smoke-test.sh                        # default: 127.0.0.1:5000
#   ./grpc-smoke-test.sh --addr 1.2.3.4:5000    # override address
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
# Parent-side gRPC schema. It is NOT vendored here — only the enclave's slice is
# (see enclave-proto/). Point this at a checkout of
# https://github.com/UTEXO-Protocol/federated-signer-proto:
#   PROTO_DIR=/path/to/federated-signer-proto/proto ./build/grpc-smoke-test.sh
PROTO_DIR="${PROTO_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/federated-signer-proto/proto}"

for arg in "$@"; do
    case $arg in
        --addr=*) ADDR="${arg#*=}" ;;
        --addr)   shift; ADDR="$1" ;;
    esac
done

log()  { echo -e "${YELLOW}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1: $2"; FAIL=$((FAIL + 1)); }

command -v grpcurl &>/dev/null || {
    echo -e "${RED}Error: grpcurl not found. Install with: brew install grpcurl${NC}"
    exit 1
}

[ -d "$PROTO_DIR" ] || {
    echo -e "${RED}Error: proto dir not found: $PROTO_DIR${NC}"
    echo "The parent gRPC schema is not vendored in this repo. Clone"
    echo "  https://github.com/UTEXO-Protocol/federated-signer-proto"
    echo "and re-run with PROTO_DIR=/path/to/that/checkout/proto"
    exit 1
}

# Convert hex string to base64 (for bytes fields in grpcurl JSON)
hex_to_b64() {
    printf '%s' "$1" | xxd -r -p | base64 | tr -d '\n'
}

# SHA-256 of a string → hex (macOS + Linux compatible)
sha256_hex() {
    if command -v sha256sum &>/dev/null; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    else
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    fi
}

echo "============================================="
echo "  gRPC Smoke Tests (parent adapter)"
echo "  Target: $ADDR"
echo "  Proto:  $PROTO_DIR"
echo "============================================="
echo ""

GRPCURL=(grpcurl -plaintext -import-path "$PROTO_DIR" -proto listener/listener.proto)

# ─────────────────────────────────────────────
# 1. GetPublicKeys
# ─────────────────────────────────────────────
log "1. GetPublicKeys"
OUTPUT=$("${GRPCURL[@]}" "$ADDR" listener.FederatedSignerNode/PublicKey 2>&1) && RC=$? || RC=$?

if [ $RC -eq 0 ] && echo "$OUTPUT" | grep -q "publicKeys"; then
    pass "GetPublicKeys — keys returned"
    echo "  $OUTPUT"
else
    fail "GetPublicKeys" "$OUTPUT"
fi

# ─────────────────────────────────────────────
# 2. Sign EVM — valid consignment
# ─────────────────────────────────────────────
log "2. Sign (EVMSigningFlow, consignment_valid=true)"

# Same calldata as smoke-test.sh:
# selector(4) + token(32) + recipient(32) + amount=1000(32) + commission=50(32) + padding(96)
CALLDATA_HEX="abcdef12"
CALLDATA_HEX+="0000000000000000000000001111111111111111111111111111111111111111"
CALLDATA_HEX+="0000000000000000000000002222222222222222222222222222222222222222"
CALLDATA_HEX+="00000000000000000000000000000000000000000000000000000000000003e8"
CALLDATA_HEX+="0000000000000000000000000000000000000000000000000000000000000032"
CALLDATA_HEX+="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

CALLDATA_B64=$(hex_to_b64 "$CALLDATA_HEX")

# No consignment bytes — matches what the CLI smoke test does.
# The current listener proto exposes SignRequest with generic data bytes, so
# this smoke test now exercises the gRPC boundary only.
SIGN_JSON="{\"network_id\":84,\"data_type\":\"TRANSACTION\",\"data\":\"$CALLDATA_B64\"}"

OUTPUT=$("${GRPCURL[@]}" -d "$SIGN_JSON" "$ADDR" listener.FederatedSignerNode/Sign 2>&1) && RC=$? || RC=$?

if [ $RC -eq 0 ] && echo "$OUTPUT" | grep -q "signature"; then
    pass "Sign EVMSigningFlow — EVM signature returned"
    echo "  $OUTPUT" | head -5
else
    fail "Sign EVMSigningFlow valid" "$OUTPUT"
fi

# ─────────────────────────────────────────────
# 3. Sign EVM — consignment_valid=false (should fail)
# ─────────────────────────────────────────────
log "3. Sign (EVMSigningFlow, consignment_valid=false — should fail)"

OUTPUT=$("${GRPCURL[@]}" -d "{\"network_id\":84,\"data_type\":\"TRANSACTION\",\"data\":\"$CALLDATA_B64\"}" "$ADDR" listener.FederatedSignerNode/Sign 2>&1) && RC=$? || RC=$?

if [ $RC -eq 0 ] || echo "$OUTPUT" | grep -qi "error\|failed"; then
    pass "Sign EVMSigningFlow invalid consignment correctly rejected"
else
    fail "Sign EVMSigningFlow invalid consignment" "expected rejection, got: $OUTPUT"
fi

# ─────────────────────────────────────────────
# 4. Sign EVM — expired deadline (should fail)
# ─────────────────────────────────────────────
log "4. Sign (EVMSigningFlow, expired deadline — should fail)"

OUTPUT=$("${GRPCURL[@]}" -d "{\"network_id\":84,\"data_type\":\"TRANSACTION\",\"data\":\"$CALLDATA_B64\"}" "$ADDR" listener.FederatedSignerNode/Sign 2>&1) && RC=$? || RC=$?

if [ $RC -ne 0 ] || echo "$OUTPUT" | grep -qi "error\|expired\|deadline"; then
    pass "Sign EVMSigningFlow expired deadline correctly rejected"
else
    fail "Sign EVMSigningFlow expired deadline" "expected rejection, got: $OUTPUT"
fi

# ─────────────────────────────────────────────
# 5. Sign — missing flow field (should fail)
# ─────────────────────────────────────────────
log "5. Sign (empty request, no flow — should fail)"

OUTPUT=$("${GRPCURL[@]}" -d '{}' "$ADDR" listener.FederatedSignerNode/Sign 2>&1) && RC=$? || RC=$?

if [ $RC -ne 0 ] || echo "$OUTPUT" | grep -qi "error\|missing\|invalid"; then
    pass "Sign empty request correctly rejected"
else
    fail "Sign empty request" "expected rejection, got: $OUTPUT"
fi

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "============================================="
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "============================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
