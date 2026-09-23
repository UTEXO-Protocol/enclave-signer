#!/usr/bin/env bash
# Check the stage profile and keep the ordinary release and feature guards closed.
set -euo pipefail
export STAGE_BFA_MODE=bootstrap
cargo check --locked -p utexo-bridge-enclave --profile stage-bfa-temp --no-default-features --features stage-bfa-temp
cargo test --locked -p utexo-bridge-enclave --no-default-features --features stage-bfa-temp --lib stage_bfa_temp::tests
log=$(mktemp)
trap 'rm -f "$log"' EXIT
expect_guard() {
    local expected="$1"
    shift
    if cargo check --locked -p utexo-bridge-enclave --no-default-features "$@" > "$log" 2>&1; then
        echo 'ERROR: forbidden feature combination compiled' >&2
        exit 1
    fi
    if ! grep -Fq "$expected" "$log"; then
        cat "$log" >&2
        echo 'ERROR: build failed for a reason other than the expected guard' >&2
        exit 1
    fi
}
expect_guard 'allow-seed-import` must not be enabled in a release build' --release --features stage-bfa-temp
expect_guard 'stage-bfa-temp requires real validation and NSM attestation' --features stage-bfa-temp,dev-mode
expect_guard 'stage-bfa-temp requires real validation and NSM attestation' --features stage-bfa-temp,mock-attestation
echo 'PASS: stage profile and all forbidden-feature guards'
