#!/bin/bash
# =============================================================================
# Enclave Smoke Test Suite
# =============================================================================
# Run this from the EC2 parent instance after the enclave is running.
# It exercises every RPC endpoint via the parent CLI binary.
#
# A fresh enclave gets its endpoints from step 0. A running one is only checked.
#
# Usage:
#   ./smoke-test.sh                     # TCP mode (dev, enclave on localhost:5000)
#   ./smoke-test.sh --vsock             # vsock mode (production, CID 16 port 5000)
#
# Prerequisites:
#   - utexo-bridge-parent-cli binary on PATH or in current directory
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

# Find parent CLI binary: explicit env var > release build > debug build.
# NOTE: the binary is utexo-bridge-parent-CLI, not utexo-bridge-parent (the
# latter is the gRPC server and ignores subcommands). Earlier revisions of
# this script pointed at the wrong binary.
if [ -n "${PARENT_BIN:-}" ]; then
    :
elif [ -f "./target/release/utexo-bridge-parent-cli" ]; then
    PARENT_BIN="./target/release/utexo-bridge-parent-cli"
elif [ -f "./target/debug/utexo-bridge-parent-cli" ]; then
    PARENT_BIN="./target/debug/utexo-bridge-parent-cli"
else
    PARENT_BIN="utexo-bridge-parent-cli"
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
    echo -e "${RED}Error: CLI binary not found at '$PARENT_BIN'${NC}"
    echo "Run 'cargo build --bin utexo-bridge-parent-cli' or set PARENT_BIN env var."
    exit 1
fi

# Preflight: prove the peer at $ADDR speaks our wire protocol, not just
# "something accepts TCP here". A naive `nc -z` is insufficient on macOS
# because port 5000 is hijacked by AirPlay Receiver - nc happily connects,
# we then write our length-prefixed protobuf into AirPlay's mouth, and the
# CLI hangs forever waiting for a response that will never come.
#
# Strategy: run `get-keys` once. The enclave responds with one of two
# stable patterns:
#   - "EVM address ..."  (initialised - typical re-run state)
#   - "key not initialized" (fresh enclave - typical first-run state)
# Any other output (or a timeout from EnclaveClient's READ_TIMEOUT) means
# we're talking to something that isn't our enclave. Bail with hints.
preflight_handshake() {
    local addr="$1"
    local out
    out=$("$PARENT_BIN" --addr "$addr" get-keys 2>&1) || true
    if echo "$out" | grep -qiE "EVM address|key not initialized|not initialized"; then
        return 0
    fi
    echo "$out" >&2
    return 1
}

# Friendly diagnostic for the macOS-on-port-5000 case. Detects the
# AirPlay Receiver process holding port 5000 and tells the user where to
# turn it off.
print_airplay_hint_if_relevant() {
    local addr="$1"
    case "$(uname -s)" in
        Darwin) ;;  # continue
        *) return 0 ;;
    esac
    case "$addr" in
        *:5000) ;;
        *) return 0 ;;
    esac
    if command -v lsof &>/dev/null && lsof -nP -iTCP:5000 -sTCP:LISTEN 2>/dev/null | grep -q "ControlCe"; then
        echo ""
        echo -e "${YELLOW}macOS AirPlay Receiver is holding port 5000.${NC}"
        echo "Either:"
        echo "  1. Disable AirPlay Receiver:"
        echo "     System Settings → General → AirDrop & Handoff → AirPlay Receiver → Off"
        echo "  2. Use a different port (recommended for dev):"
        echo "     ENCLAVE_LISTEN_ADDR=127.0.0.1:5050 cargo run --bin utexo-bridge-enclave"
        echo "     ./build/smoke-test.sh --addr=127.0.0.1:5050"
    fi
}

case "$ADDR" in
    vsock://*)
        # vsock preflight needs nitro-cli describe-enclaves; left to the host.
        if ! command -v nitro-cli &>/dev/null; then
            echo -e "${YELLOW}Warning: nitro-cli not in PATH; cannot verify enclave is running${NC}"
        fi
        ;;
    *)
        echo "Preflight: handshake against $ADDR..."
        if ! preflight_handshake "$ADDR"; then
            echo -e "${RED}Error: $ADDR is not responding with our enclave wire protocol.${NC}"
            echo ""
            echo "Start the enclave first, then re-run this script:"
            echo ""
            echo "  RUST_LOG=info cargo run --bin utexo-bridge-enclave"
            echo ""
            echo "(in a separate terminal). For Nitro Enclave / vsock mode use --vsock."
            print_airplay_hint_if_relevant "$ADDR"
            exit 1
        fi
        echo -e "${GREEN}Preflight OK — peer speaks the enclave wire protocol${NC}"
        echo ""
        ;;
esac

# ---------------------------------------------
# 0. Endpoints: set once on a fresh enclave, else only check
# ---------------------------------------------
# The enclave refuses a second set. The CLI reads ELECTRUM_URL, EVM_RPC_HOST,
# EVM_RPC_TLS_PORT and EVM_RPC_TLS_CA_DER_FILE.
log "0. SetEndpoints (only when the enclave has none)"
HEALTH_OUTPUT=$(run_parent health) || true
if echo "$HEALTH_OUTPUT" | grep -q "Endpoints set: *true"; then
    skip "SetEndpoints" "already set"
elif echo "$HEALTH_OUTPUT" | grep -q "Endpoints set: *false"; then
    SET_OUTPUT=$(run_parent set-endpoints) || true
    HEALTH_OUTPUT=$(run_parent health) || true
    if echo "$HEALTH_OUTPUT" | grep -q "Endpoints set: *true"; then
        pass "SetEndpoints"
    else
        fail "SetEndpoints" "$SET_OUTPUT"
    fi
else
    fail "SetEndpoints" "$HEALTH_OUTPUT"
fi

# ---------------------------------------------
# 1. Initialize keys
# ---------------------------------------------
log "1. InitializeKey (generate new mnemonic)"
INIT_OUTPUT=$(run_parent init) && RC=$? || RC=$?

if [ $RC -eq 0 ] && echo "$INIT_OUTPUT" | grep -q "EVM address"; then
    EVM_ADDR=$(echo "$INIT_OUTPUT" | grep "EVM address" | awk '{print $NF}')
    BTC_PUB=$(echo "$INIT_OUTPUT" | grep "BTC pubkey" | awk '{print $NF}')
    BTC_XPUB=$(echo "$INIT_OUTPUT" | grep "BTC xpub" | awk '{print $NF}')
    pass "InitializeKey — EVM: $EVM_ADDR"
else
    # May fail if already initialized - that's OK, try get-keys instead
    if echo "$INIT_OUTPUT" | grep -qi "already initialized"; then
        skip "InitializeKey" "already initialized (expected on re-run)"
    else
        fail "InitializeKey" "$INIT_OUTPUT"
    fi
fi

# ---------------------------------------------
# 2. Get public keys
# ---------------------------------------------
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

# ---------------------------------------------
# 3. Double-init should fail
# ---------------------------------------------
log "3. Double InitializeKey (should fail)"
DOUBLE_INIT=$(run_parent init) && RC=$? || RC=$?

if [ $RC -ne 0 ] || echo "$DOUBLE_INIT" | grep -qi "already initialized\|error"; then
    pass "Double init correctly rejected"
else
    fail "Double init" "expected error, got: $DOUBLE_INIT"
fi

# ---------------------------------------------
# 4. SignEvm (with valid enriched payload)
# ---------------------------------------------
log "4. SignEvm (enriched payload, valid)"

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
        pass "SignEvm — 65-byte EIP-712 signature returned (non-SPV build)"
    else
        fail "SignEvm" "expected 65 bytes, got $SIG_LEN"
    fi
elif echo "$EVM_SIG_OUTPUT" | grep -qi "spv:.*signEVM requires"; then
    # SPV-enabled build: this request has no consignment bytes, so the SPV
    # path correctly rejects. That's the right behaviour, not a failure -
    # full SPV happy-path coverage requires fixture data and lives in the
    # spv_crosscheck unit tests + test_spv_handlers integration tests.
    pass "SignEvm — correctly rejected by SPV (build has --features spv)"
else
    fail "SignEvm" "$EVM_SIG_OUTPUT"
fi

# ---------------------------------------------
# 5. SignEvm rejects invalid consignment
# ---------------------------------------------
log "5. SignEvm rejects invalid consignment"

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
    # Note: --consignment-valid flag NOT passed -> consignment_valid = false

if [ $RC -ne 0 ] || echo "$BAD_CONSIGN_OUTPUT" | grep -qi "consignment\|error"; then
    pass "SignEvm correctly rejected invalid consignment"
else
    fail "SignEvm invalid consignment" "expected rejection, got: $BAD_CONSIGN_OUTPUT"
fi

# ---------------------------------------------
# 6. SignEvm rejects amount mismatch
# ---------------------------------------------
log "6. SignEvm rejects amount mismatch"

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

# ---------------------------------------------
# 7. ProxyFederation (should return NOT_READY)
# ---------------------------------------------
log "7. ProxyFederation (stub — should return NOT_READY)"
# No CLI subcommand for federation yet, so we skip if not available
skip "ProxyFederation" "no CLI subcommand yet — test via integration tests"

# =============================================================================
# SPV header chain read.
# =============================================================================
# The parent's header sync is the one writer, so the CLI only reads the tip.

# ---------------------------------------------
# 8. GetLastSavedBlock baseline
# ---------------------------------------------
log "8. GetLastSavedBlock — chain initialised at boot"
LAST_BLOCK_OUTPUT=$(run_parent get-last-saved-block) && RC=$? || RC=$?

if [ $RC -eq 0 ] && echo "$LAST_BLOCK_OUTPUT" | grep -q "Block hash"; then
    BLOCK_HEIGHT=$(echo "$LAST_BLOCK_OUTPUT" | grep "Block height" | awk '{print $NF}')
    BLOCK_HASH=$(echo "$LAST_BLOCK_OUTPUT" | grep "Block hash" | awk '{print $NF}')
    BLOCK_HASH_LEN=$((${#BLOCK_HASH} / 2))
    if [ "$BLOCK_HASH_LEN" -eq 32 ]; then
        pass "GetLastSavedBlock — height=$BLOCK_HEIGHT, 32-byte hash"
    else
        fail "GetLastSavedBlock" "expected 32-byte hash, got $BLOCK_HASH_LEN bytes"
    fi
else
    fail "GetLastSavedBlock" "$LAST_BLOCK_OUTPUT"
fi

# ---------------------------------------------
# Summary
# ---------------------------------------------
echo ""
echo "============================================="
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}"
echo "============================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
