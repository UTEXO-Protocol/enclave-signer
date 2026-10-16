#!/usr/bin/env bash
# verify-identity.sh — post-init / post-restart signing-identity gate (F09-AF-13).
#
# WHY (audit F09-AF-13): a restart puts an enclave back in Initial (EMPTY) until it
# is re-cloned, and a fresh re-init can mint a VALID-BUT-UNREGISTERED key. Process/
# PCR/port health does NOT prove the node holds the APPROVED registered signing key.
# If traffic is routed too early the node returns KeyNotInitialized, or a new
# unregistered key trips quorum/consumer rejection. This gate must PASS before a
# node is put back into rotation.
#
# What it asserts on THIS host, for every expected CID:
#   1. the enclave is RUNNING (empty/partial enclave set is a FAIL);
#   2. get-keys returns an INITIALIZED key (a "key not initialized" enclave that was
#      restarted but never re-cloned is a FAIL, not "healthy");
#   3. the live EVM address EQUALS the approved registered identity for that CID.
#      For SIGNER_ROLE burn or combined, export-attestation attests the address
#      and writes $CLUSTER_DIR/attestation-<CID>.json; see docs/verify-a-signer.md.
#
# For SIGNER_ROLE=mint or ENCLAVE_DEBUG_MODE=1 (zero PCRs) step 3 reads get-keys:
# a fast STRUCTURAL check, NOT an attestation.
#
# Launch values (PCR_FILE, IMAGE_ENV, SIGNER_ROLE, ELECTRUM_URL, ...) come from
# ENCLAVE_ENV for a single-role deployment, or ENCLAVE_ENV_DIR/enclave-<CID>.env
# for a mixed Mint/Burn host. No shared RPC file overrides per-CID settings.
#
# Runs ON a node (as root, e.g. via SSM — same model as deploy-host.sh).
# Self-contained; no infra identifiers baked in — pass them via env.
#
# Usage (run as root):
#   CLUSTER_DIR=<dir-with-utexo-bridge-parent-cli> \
#   EXPECTED_EVM="16=0x.. 18=0x.. 20=0x.." \
#   [CIDS="16 18 20"] [ENCLAVE_ENV=/etc/utexo/enclave.env] bash verify-identity.sh
#
# EXPECTED_EVM must contain exactly one approved CID=0x<40 hex digits> entry
# per CIDS member. Obtain it from the approved deployment record, not live keys.
# For diagnostics only: bash verify-identity.sh --liveness (no map required).
# Liveness success NEVER approves a signer for routing and exports no bundles.
#
# Exit: 0 = identity approved, or liveness only when explicitly requested.
#       1 = at least one CID empty / diverged / unregistered / export failed
#           -> do NOT route traffic.
#       2 = misconfiguration (missing CLI / bad args / missing launch values).
set -uo pipefail

log(){ printf '[verify-identity] %s\n' "$*"; }
fatal(){ log "FATAL: $*"; exit 2; }
mode=identity
case "$#:$*" in
  0:) ;;
  1:--liveness) mode=liveness ;;
  *) fatal "usage: verify-identity.sh [--liveness]" ;;
esac

if [ -z "${ENCLAVE_ENV_DIR:-}" ] && [ -r "${ENCLAVE_ENV:-/etc/utexo/enclave.env}" ]; then
  set -a; . "${ENCLAVE_ENV:-/etc/utexo/enclave.env}"; set +a
fi
[ -z "${ENCLAVE_ENV_DIR:-}" ] || [ -n "${CIDS:-}" ] || fatal "explicit CIDS required with ENCLAVE_ENV_DIR"

# An explicitly empty list is an error; only an unset CIDS gets the default.
CIDS="${CIDS-16 18 20}"
read -ra CID_ARR <<< "${CIDS//$'\n'/ }"
[ "${#CID_ARR[@]}" -gt 0 ] || fatal "CIDS must not be empty"
valid_cid(){ [[ "$1" =~ ^[1-9][0-9]{0,9}$ ]] && (( $1 >= 4 && $1 < 4294967295 )); }
declare -A TARGETS=() EXP_EVM=()
for CID in "${CID_ARR[@]}"; do
  valid_cid "$CID" || fatal "invalid CID: $CID"
  [ -z "${TARGETS[$CID]:-}" ] || fatal "duplicate CID: $CID"
  TARGETS[$CID]=1
done

# Validate the entire approved map before probing nodes or exporting bundles.
if [ "$mode" = identity ]; then
  expected="${EXPECTED_EVM:-}"
  read -ra PAIRS <<< "${expected//$'\n'/ }"
  for kv in "${PAIRS[@]}"; do
    [[ "$kv" =~ ^([1-9][0-9]{0,9})=(0x[0-9a-fA-F]{40})$ ]] || fatal "invalid EXPECTED_EVM entry: $kv"
    CID="${BASH_REMATCH[1]}"
    address="${BASH_REMATCH[2]}"
    [ -n "${TARGETS[$CID]:-}" ] || fatal "unexpected CID in EXPECTED_EVM: $CID"
    [ -z "${EXP_EVM[$CID]:-}" ] || fatal "duplicate CID in EXPECTED_EVM: $CID"
    EXP_EVM[$CID]="$address"
  done
  for CID in "${CID_ARR[@]}"; do
    [ -n "${EXP_EVM[$CID]:-}" ] || fatal "missing EXPECTED_EVM entry for CID $CID"
  done
fi

# Validate the full map and every launch file before checking individual roles.
# Each child gets an isolated environment, so Mint KMS values cannot leak to Burn.
if [ -n "${ENCLAVE_ENV_DIR:-}" ]; then
  for CID in "${CID_ARR[@]}"; do
    f="$ENCLAVE_ENV_DIR/enclave-$CID.env"
    [ -r "$f" ] || fatal "missing launch file for CID $CID"
    (set -a; . "$f"; set +a
     [ -x "${CLI:-}" ] && [ -n "${PCR_FILE:-}" ] && [ -n "${IMAGE_ENV:-}" ] &&
     [[ "${SIGNER_ROLE:-}" = mint || "${SIGNER_ROLE:-}" = burn ]]) || fatal "invalid launch configuration for CID $CID"
  done
  fail=0
  for CID in "${CID_ARR[@]}"; do
    if out="$(
      for key in ${!KMS_@}; do unset "$key"; done
      set -a; . "$ENCLAVE_ENV_DIR/enclave-$CID.env"; set +a
      export ENCLAVE_ENV="$ENCLAVE_ENV_DIR/enclave-$CID.env"
      unset ENCLAVE_ENV_DIR
      export CLUSTER_DIR="$(dirname -- "$CLI")" CIDS="$CID" EXPECTED_EVM="$CID=${EXP_EVM[$CID]:-}"
      args=(); [ "$mode" = liveness ] && args=(--liveness)
      bash "$0" "${args[@]}"
    )"; then
      # Do not expose a partial PASS as host-wide approval.
      printf '%s\n' "$out" | sed '/\[verify-identity\] PASS:/d'
    else
      printf '%s\n' "$out" | sed '/\[verify-identity\] PASS:/d'
      fail=1
    fi
  done
  [ "$fail" = 0 ] || { log 'FAILED: one or more CIDs failed; do NOT route traffic'; exit 1; }
  if [ "$mode" = identity ]; then
    log "PASS: all CIDs [$CIDS] match the complete approved identity map (Mint uses structural verification)"
  else
    log "LIVE: all configured CIDs initialized; identity NOT approved"
  fi
  exit 0
fi

[ -n "${CLUSTER_DIR:-}" ] || fatal "CLUSTER_DIR required (dir containing utexo-bridge-parent-cli)"
CLI="$CLUSTER_DIR/utexo-bridge-parent-cli"
[ -x "$CLI" ] || fatal "CLI not found/executable at $CLI"

# Liveness never exports an attestation or claims identity approval.
attested=0
if [ "$mode" = identity ] && [ "${ENCLAVE_DEBUG_MODE:-0}" != 1 ]; then
  case "${SIGNER_ROLE:-}" in
    mint) ;;
    burn|combined)
      [ -n "${PCR_FILE:-}" ] && [ -n "${IMAGE_ENV:-}" ] || fatal "PCR_FILE and IMAGE_ENV required (set in ENCLAVE_ENV)"
      attested=1 ;;
    *) fatal "SIGNER_ROLE must be mint, burn or combined (set in ENCLAVE_ENV)" ;;
  esac
fi
fail=0

# --- 1. every configured enclave must be RUNNING ----------------------------
if ! running="$(nitro-cli describe-enclaves 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    d = []
print("\n".join(str(e["EnclaveCID"]) for e in d if e.get("State") == "RUNNING"))
' 2>/dev/null)"; then
  log "FAIL: cannot read running enclave inventory"; exit 1
fi
for CID in "${CID_ARR[@]}"; do
  printf '%s\n' "$running" | grep -qx "$CID" || { log "FAIL: CID $CID not RUNNING"; fail=1; }
done

# Accept exactly one main EVM address; never fall back to gas/contract addresses.
extract_evm() {
  local blob="$1" line hit="" count=0
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*EVM[[:space:]]address:[[:space:]]*(0x[0-9a-fA-F]{40})[[:space:]]*$ ]]; then
      hit="${BASH_REMATCH[1]}"
      count=$((count + 1))
    fi
  done <<< "$blob"
  [ "$count" = 1 ] || return 1
  printf '%s' "$hit"
}

# --- 2. per CID: key initialized AND == registered identity -------------------
for CID in "${CID_ARR[@]}"; do
  exp="${EXP_EVM[$CID]:-}"
  if [ "$attested" = 1 ]; then
    bundle="$CLUSTER_DIR/attestation-$CID.json"
    rm -f "$bundle"
    args=(--pcr-file "$PCR_FILE" --image-env "$IMAGE_ENV" --signer-role "$SIGNER_ROLE" --out "$bundle")
    args+=(--expect-evm-address "$exp")
    if ! out="$(timeout 45 "$CLI" --addr "vsock://$CID:5000" export-attestation "${args[@]}" 2>&1)"; then
      log "FAIL: CID $CID attested export failed: $(printf '%s\n' "$out" | tail -1)"; fail=1; continue
    fi
    evm="$(extract_evm "$out")"
    if [ -z "$evm" ] || [ "${evm,,}" != "${exp,,}" ] || [ ! -s "$bundle" ]; then
      log "FAIL: CID $CID missing bundle or unexpected attested EVM address"
      rm -f "$bundle"
      fail=1; continue
    fi
    log "OK:   CID $CID attested EVM $evm == registered identity; bundle $bundle"
    continue
  fi
  [ "${ENCLAVE_DEBUG_MODE:-0}" = "1" ] && log "CID $CID bundle skipped: debug PCRs are zero"
  if ! out="$(timeout 20 "$CLI" --addr "vsock://$CID:5000" get-keys 2>&1)"; then
    log "FAIL: CID $CID get-keys failed"; fail=1; continue
  fi
  if printf '%s\n' "$out" | grep -qiE 'not initialized|key not'; then
    log "FAIL: CID $CID is EMPTY (key not initialized — restarted and not re-cloned)"; fail=1; continue
  fi
  evm="$(extract_evm "$out")"
  if [ -z "$evm" ]; then
    log "FAIL: CID $CID no EVM address read (uninitialized / get-keys error)"; fail=1; continue
  fi
  if [ "$mode" = identity ]; then
    if [ "${evm,,}" = "${exp,,}" ]; then
      log "OK:   CID $CID live EVM $evm == registered identity"
    else
      log "FAIL: CID $CID live EVM $evm != registered identity $exp (unregistered/re-inited key)"; fail=1
    fi
  else
    log "LIVE: CID $CID initialized; identity NOT approved"
  fi
done

# --- verdict ------------------------------------------------------------------
if [ "$fail" = 0 ]; then
  if [ "$mode" = identity ]; then
    log "PASS: all CIDs [$CIDS] RUNNING + keys match the registered identity"
  else
    log "LIVE: all configured CIDs RUNNING with initialized keys; identity NOT approved; do NOT enable routing from this result"
  fi
  exit 0
fi
log "FAILED — do NOT route traffic to this node until resolved"
exit 1
