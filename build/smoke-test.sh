#!/bin/bash
# Lifecycle/readiness smoke test for either signer role, with or without SPV.
# Run on the parent instance against a running enclave. A fresh enclave gets
# its endpoints and keys initialized; an initialized enclave keeps its identity.
# Mint KMS configuration and burn header sync must be available as applicable.
#
# Usage: ./build/smoke-test.sh [--vsock | --addr=HOST:PORT]
# Set PARENT_BIN to override the parent CLI. SetEndpoints reads its usual
# endpoint/KMS environment variables. No signing request is sent: successful
# mint and burn signing is covered by the Rust fixture integration suites.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASS=0
FAIL=0
SKIP=0
ADDR="127.0.0.1:5000"

for arg in "$@"; do
    case $arg in
        --vsock) ADDR="vsock://16:5000" ;;
        --addr=*) ADDR="${arg#*=}" ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

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

call() {
    OUT=$("$PARENT_BIN" --addr "$ADDR" "$@" 2>&1) && RC=0 || RC=$?
}

# Health exits 1 for a valid not-ready response. A transport failure is not
# such a response: require its fields and the matching exit status.
read_health() {
    call health
    READY=$(sed -n 's/^Ready: *//p' <<<"$OUT")
    ENDPOINTS_SET=$(sed -n 's/^Endpoints set: *//p' <<<"$OUT")
    KEY_LOADED=$(sed -n 's/^Key loaded: *//p' <<<"$OUT")
    [[ "$READY" =~ ^(true|false)$ ]] \
        && [[ "$ENDPOINTS_SET" =~ ^(true|false)$ ]] \
        && [[ "$KEY_LOADED" =~ ^(true|false)$ ]] \
        && { { [ "$READY" = true ] && [ "$RC" -eq 0 ]; } \
            || { [ "$READY" = false ] && [ "$RC" -eq 1 ]; }; }
}

# Validate the core identity fields, then retain every printed public key for
# the before/after comparison. Init and GetPublicKey print the same fields.
identity() {
    local evm xpub
    evm=$(sed -n 's/^  EVM address: *//p' <<<"$1")
    xpub=$(sed -n 's/^  Account xpub vanilla: *//p' <<<"$1")
    [[ "$evm" =~ ^0x[[:xdigit:]]{40}$ ]] \
        && [[ "$xpub" =~ ^[xt]pub[1-9A-HJ-NP-Za-km-z]{107}$ ]] || return 1
    grep -E '^  (EVM address|Master fingerprint|Account xpub vanilla|Account xpub colored|EVM gas TX address|EVM gas TX pubkey):' <<<"$1"
}

echo "============================================="
echo "  Enclave Lifecycle Smoke Tests"
echo "  Target: $ADDR"
echo "  Parent: $PARENT_BIN"
echo "============================================="

if ! command -v "$PARENT_BIN" &>/dev/null && [ ! -f "$PARENT_BIN" ]; then
    echo "Error: parent CLI not found; set PARENT_BIN or build it with cargo build --manifest-path parent/Cargo.toml --bin utexo-bridge-parent-cli" >&2
    exit 1
fi

log "Health handshake"
if ! read_health; then
    fail "Health handshake" "expected an enclave health response, got: $OUT"
    exit 1
fi
pass "Health handshake"

log "SetEndpoints (only when absent)"
if [ "$ENDPOINTS_SET" = true ]; then
    skip "SetEndpoints" "already set; preserving the launch configuration"
else
    call set-endpoints
    if [ "$RC" -ne 0 ] || ! grep -qx 'Endpoints set' <<<"$OUT"; then
        fail "SetEndpoints" "$OUT"
        exit 1
    fi
    if ! read_health || [ "$ENDPOINTS_SET" != true ]; then
        fail "SetEndpoints" "health did not confirm the installed endpoints: $OUT"
        exit 1
    fi
    pass "SetEndpoints"
fi

INIT_IDENTITY=""
log "InitializeKey (only when absent)"
if [ "$KEY_LOADED" = true ]; then
    skip "InitializeKey" "key already loaded; preserving its identity"
else
    call init
    if [ "$RC" -ne 0 ] || ! INIT_IDENTITY=$(identity "$OUT"); then
        fail "InitializeKey" "$OUT"
        exit 1
    fi
    pass "InitializeKey"
fi

log "GetPublicKey"
call get-keys
if [ "$RC" -ne 0 ] || ! BEFORE_IDENTITY=$(identity "$OUT"); then
    fail "GetPublicKey" "$OUT"
    exit 1
fi
if [ -n "$INIT_IDENTITY" ] && [ "$INIT_IDENTITY" != "$BEFORE_IDENTITY" ]; then
    fail "GetPublicKey" "identity differs from the InitializeKey response"
    exit 1
fi
pass "GetPublicKey"

log "Double InitializeKey"
call init
if [ "$RC" -eq 1 ] && grep -qxF 'Error: enclave returned error (code 1): already initialized' <<<"$OUT"; then
    pass "Double init correctly rejected"
else
    fail "Double init" "expected AlreadyInitialized (code 1), got exit $RC: $OUT"
fi

log "Identity after refused initialization"
call get-keys
if [ "$RC" -eq 0 ] && AFTER_IDENTITY=$(identity "$OUT") \
    && [ "$BEFORE_IDENTITY" = "$AFTER_IDENTITY" ]; then
    pass "Identity unchanged after refused initialization"
else
    fail "Identity after refused initialization" "public keys changed or could not be read: $OUT"
fi

log "Final health/readiness"
if read_health && [ "$READY" = true ] && [ "$ENDPOINTS_SET" = true ] && [ "$KEY_LOADED" = true ]; then
    pass "Enclave ready"
else
    fail "Final health/readiness" "$OUT"
fi

echo ""
echo "Signing coverage: Rust mint/burn fixture suites; this smoke test checks lifecycle and readiness."
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}"
[ "$FAIL" -eq 0 ]
