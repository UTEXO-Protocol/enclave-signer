#!/bin/bash
# =============================================================================
# Enclave Smoke Test Suite
# =============================================================================
# Run this from the EC2 parent instance after the enclave is running.
# It exercises every RPC endpoint via the parent CLI binary.
#
# Usage:
#   ./smoke-test.sh                     # TCP mode (dev, enclave on localhost:5000)
#   ./smoke-test.sh --vsock             # vsock mode (production, CID 16 port 5000)
#
# Prerequisites:
#   - utexo-bridge-parent binary on PATH or in current directory
#   - Enclave running (either TCP dev mode or Nitro vsock)
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

ADDR="127.0.0.1:5000"

# Parse args
for arg in "$@"; do
    case $arg in
        --vsock) ADDR="vsock://16:5000" ;;
        --addr=*) ADDR="${arg#*=}" ;;
    esac
done

# Find parent binary: explicit env var > release build > debug build
if [ -n "${PARENT_BIN:-}" ]; then
    :
elif [ -f "./target/release/utexo-bridge-parent" ]; then
    PARENT_BIN="./target/release/utexo-bridge-parent"
elif [ -f "./target/debug/utexo-bridge-parent" ]; then
    PARENT_BIN="./target/debug/utexo-bridge-parent"
else
    PARENT_BIN="utexo-bridge-parent"
fi

log()  { echo -e "${YELLOW}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1: $2"; FAIL=$((FAIL + 1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1: $2"; SKIP=$((SKIP + 1)); }

# Run parent CLI, capture stdout+stderr, return exit code
run_parent() {
    "$PARENT_BIN" --addr "$ADDR" "$@" 2>&1
}

echo "============================================="
echo "  Enclave Smoke Tests"
echo "  Target: $ADDR"
echo "  Parent: $PARENT_BIN"
echo "============================================="
echo ""

# Check binary exists
if ! command -v "$PARENT_BIN" &>/dev/null && [ ! -f "$PARENT_BIN" ]; then
    echo -e "${RED}Error: parent binary not found at '$PARENT_BIN'${NC}"
    echo "Set PARENT_BIN env var or place utexo-bridge-parent in current directory."
    exit 1
fi

# ─────────────────────────────────────────────
# 1. Initialize keys
# ─────────────────────────────────────────────
log "1. InitializeKey (generate new mnemonic)"
INIT_OUTPUT=$(run_parent init) && RC=$? || RC=$?

if [ $RC -eq 0 ] && echo "$INIT_OUTPUT" | grep -q "EVM address"; then
    EVM_ADDR=$(echo "$INIT_OUTPUT" | grep "EVM address" | awk '{print $NF}')
    BTC_PUB=$(echo "$INIT_OUTPUT" | grep "BTC pubkey" | awk '{print $NF}')
    BTC_XPUB=$(echo "$INIT_OUTPUT" | grep "BTC xpub" | awk '{print $NF}')
    pass "InitializeKey — EVM: $EVM_ADDR"
else
    # May fail if already initialized — that's OK, try get-keys instead
    if echo "$INIT_OUTPUT" | grep -qi "already initialized"; then
        skip "InitializeKey" "already initialized (expected on re-run)"
    else
        fail "InitializeKey" "$INIT_OUTPUT"
    fi
fi

# ─────────────────────────────────────────────
# 2. Get public keys
# ─────────────────────────────────────────────
log "2. GetPublicKey"
KEYS_OUTPUT=$(run_parent get-keys) && RC=$? || RC=$?

if [ $RC -eq 0 ] && echo "$KEYS_OUTPUT" | grep -q "EVM address"; then
    EVM_ADDR=$(echo "$KEYS_OUTPUT" | grep "EVM address" | awk '{print $NF}')
    BTC_PUB=$(echo "$KEYS_OUTPUT" | grep "BTC pubkey" | awk '{print $NF}')
    BTC_XPUB=$(echo "$KEYS_OUTPUT" | grep "BTC xpub" | awk '{print $NF}')
    pass "GetPublicKey — EVM: $EVM_ADDR, xpub: ${BTC_XPUB:0:20}..."
else
    fail "GetPublicKey" "$KEYS_OUTPUT"
fi

# ─────────────────────────────────────────────
# 3. Double-init should fail
# ─────────────────────────────────────────────
log "3. Double InitializeKey (should fail)"
DOUBLE_INIT=$(run_parent init) && RC=$? || RC=$?

if [ $RC -ne 0 ] || echo "$DOUBLE_INIT" | grep -qi "already initialized\|error"; then
    pass "Double init correctly rejected"
else
    fail "Double init" "expected error, got: $DOUBLE_INIT"
fi

# ─────────────────────────────────────────────
# 4. SignRawMessage
# ─────────────────────────────────────────────
log "4. SignRawMessage (fundsIn authorization)"
# "hello from smoke test" in hex
RAW_MSG_HEX="68656c6c6f2066726f6d20736d6f6b652074657374"
RAW_SIG_OUTPUT=$(run_parent sign-raw-message --message "$RAW_MSG_HEX") && RC=$? || RC=$?

if [ $RC -eq 0 ] && echo "$RAW_SIG_OUTPUT" | grep -q "Signature"; then
    SIG=$(echo "$RAW_SIG_OUTPUT" | grep "Signature" | awk '{print $NF}')
    SIG_LEN=$((${#SIG} / 2))
    if [ "$SIG_LEN" -eq 65 ]; then
        pass "SignRawMessage — 65-byte signature returned"
    else
        fail "SignRawMessage" "expected 65 bytes, got $SIG_LEN"
    fi
else
    fail "SignRawMessage" "$RAW_SIG_OUTPUT"
fi

# ─────────────────────────────────────────────
# 5. SignRawMessage determinism (same message → same sig)
# ─────────────────────────────────────────────
log "5. SignRawMessage determinism"
RAW_SIG_OUTPUT2=$(run_parent sign-raw-message --message "$RAW_MSG_HEX") && RC=$? || RC=$?

if [ $RC -eq 0 ]; then
    SIG2=$(echo "$RAW_SIG_OUTPUT2" | grep "Signature" | awk '{print $NF}')
    if [ "$SIG" = "$SIG2" ]; then
        pass "SignRawMessage deterministic (RFC 6979)"
    else
        fail "SignRawMessage determinism" "signatures differ"
    fi
else
    fail "SignRawMessage determinism" "$RAW_SIG_OUTPUT2"
fi

# ─────────────────────────────────────────────
# 6. SignRawMessage empty (should fail)
# ─────────────────────────────────────────────
log "6. SignRawMessage empty message (should fail)"
EMPTY_SIG=$(run_parent sign-raw-message --message "") && RC=$? || RC=$?

if [ $RC -ne 0 ] || echo "$EMPTY_SIG" | grep -qi "error\|empty"; then
    pass "Empty SignRawMessage correctly rejected"
else
    fail "Empty SignRawMessage" "expected error, got: $EMPTY_SIG"
fi

# ─────────────────────────────────────────────
# 7. SignEvm (with valid enriched payload)
# ─────────────────────────────────────────────
log "7. SignEvm (enriched payload, valid)"

# Build a mock fundsOut calldata:
#   selector(4) + token(32) + recipient(32) + amount(32) + commission(32) + padding(96)
# amount=1000 (0x3E8), commission=50 (0x32)
CALLDATA="abcdef12"                                            # selector
CALLDATA+="0000000000000000000000001111111111111111111111111111111111111111"  # token
CALLDATA+="0000000000000000000000002222222222222222222222222222222222222222"  # recipient
CALLDATA+="00000000000000000000000000000000000000000000000000000000000003e8"  # amount=1000
CALLDATA+="0000000000000000000000000000000000000000000000000000000000000032"  # commission=50
CALLDATA+="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"  # 3x32 zero padding

EVM_SIG_OUTPUT=$(run_parent sign-evm \
    --call-data "$CALLDATA" \
    --nonce 1 \
    --deadline 9999999999 \
    --chain-id 1 \
    --proxy-contract "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    --rgb-amount 1200 \
    --rgb-asset-id "rgb:test" \
    --calldata-amount 1000 \
    --calldata-commission 50 \
    --consignment-valid) && RC=$? || RC=$?

if [ $RC -eq 0 ] && echo "$EVM_SIG_OUTPUT" | grep -q "signature"; then
    SIG=$(echo "$EVM_SIG_OUTPUT" | grep "signature" | awk '{print $NF}')
    SIG_LEN=$((${#SIG} / 2))
    if [ "$SIG_LEN" -eq 65 ]; then
        pass "SignEvm — 65-byte EIP-712 signature returned"
    else
        fail "SignEvm" "expected 65 bytes, got $SIG_LEN"
    fi
else
    fail "SignEvm" "$EVM_SIG_OUTPUT"
fi

# ─────────────────────────────────────────────
# 8. SignEvm rejects invalid consignment
# ─────────────────────────────────────────────
log "8. SignEvm rejects invalid consignment"

BAD_CONSIGN_OUTPUT=$(run_parent sign-evm \
    --call-data "$CALLDATA" \
    --nonce 2 \
    --deadline 9999999999 \
    --chain-id 1 \
    --proxy-contract "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    --rgb-amount 1200 \
    --rgb-asset-id "rgb:test" \
    --calldata-amount 1000 \
    --calldata-commission 50) && RC=$? || RC=$?
    # Note: --consignment-valid flag NOT passed → consignment_valid = false

if [ $RC -ne 0 ] || echo "$BAD_CONSIGN_OUTPUT" | grep -qi "consignment\|error"; then
    pass "SignEvm correctly rejected invalid consignment"
else
    fail "SignEvm invalid consignment" "expected rejection, got: $BAD_CONSIGN_OUTPUT"
fi

# ─────────────────────────────────────────────
# 9. SignEvm rejects amount mismatch
# ─────────────────────────────────────────────
log "9. SignEvm rejects amount mismatch"

BAD_AMOUNT_OUTPUT=$(run_parent sign-evm \
    --call-data "$CALLDATA" \
    --nonce 3 \
    --deadline 9999999999 \
    --chain-id 1 \
    --proxy-contract "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    --rgb-amount 500 \
    --rgb-asset-id "rgb:test" \
    --calldata-amount 1000 \
    --calldata-commission 50 \
    --consignment-valid) && RC=$? || RC=$?

if [ $RC -ne 0 ] || echo "$BAD_AMOUNT_OUTPUT" | grep -qi "amount mismatch\|error"; then
    pass "SignEvm correctly rejected amount mismatch"
else
    fail "SignEvm amount mismatch" "expected rejection, got: $BAD_AMOUNT_OUTPUT"
fi

# ─────────────────────────────────────────────
# 10. ProxyFederation (should return NOT_READY)
# ─────────────────────────────────────────────
log "10. ProxyFederation (stub — should return NOT_READY)"
# No CLI subcommand for federation yet, so we skip if not available
skip "ProxyFederation" "no CLI subcommand yet — test via integration tests"

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "============================================="
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}"
echo "============================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
