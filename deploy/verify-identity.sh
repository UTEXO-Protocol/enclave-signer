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
#
# This is a fast STRUCTURAL gate, NOT a full attestation. The supervisor still owns
# attestation-doc verification + a safe test signature before routing; this only
# catches a wrong / unregistered / empty key early and cheaply.
#
# Runs ON a node (as root, e.g. via SSM — same model as deploy-host.sh).
# Self-contained; no infra identifiers baked in — pass them via env.
#
# Usage (run as root):
#   CLUSTER_DIR=<dir-with-utexo-bridge-parent-cli> \
#   EXPECTED_EVM="16=0x.. 18=0x.. 20=0x.." \
#   [CIDS="16 18 20"] bash verify-identity.sh
#
# Exit: 0 = all expected CIDs RUNNING + initialized + match registered identity.
#       1 = at least one CID empty / diverged / unregistered  -> do NOT route traffic.
#       2 = misconfiguration (missing CLI / bad args).
set -uo pipefail

CIDS="${CIDS:-16 18 20}"
CLUSTER_DIR="${CLUSTER_DIR:?CLUSTER_DIR required (dir containing utexo-bridge-parent-cli)}"
read -ra CID_ARR <<< "$CIDS"

CLI="$CLUSTER_DIR/utexo-bridge-parent-cli"
[ -x "$CLI" ] || { echo "[verify-identity] FATAL: CLI not found/executable at $CLI"; exit 2; }

# Registered / approved signing identity per CID, from EXPECTED_EVM="CID=0x.. ...".
declare -A EXP_EVM
if [ -n "${EXPECTED_EVM:-}" ]; then
  for kv in $EXPECTED_EVM; do EXP_EVM[${kv%%=*}]="${kv#*=}"; done
fi

log(){ printf '[verify-identity] %s\n' "$*"; }
fail=0

# --- 1. exact enclave set RUNNING (host-local; mirrors F09-AF-07) -------------
running="$(nitro-cli describe-enclaves 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    d = []
print("\n".join(str(e["EnclaveCID"]) for e in d if e.get("State") == "RUNNING"))
' 2>/dev/null)"
for CID in "${CID_ARR[@]}"; do
  printf '%s\n' "$running" | grep -qx "$CID" || { log "FAIL: CID $CID not RUNNING"; fail=1; }
done

# pull the first EVM-looking address out of a get-keys blob.
extract_evm() {
  local blob="$1" hit
  hit="$(printf '%s\n' "$blob" | grep -iE 'evm|eth' | grep -oiE '0x[0-9a-f]{40}' | head -1)"
  [ -n "$hit" ] || hit="$(printf '%s\n' "$blob" | grep -oiE '0x[0-9a-f]{40}' | head -1)"
  printf '%s' "$hit"
}

# --- 2. per CID: key initialized AND == registered identity -------------------
for CID in "${CID_ARR[@]}"; do
  out="$(timeout 20 "$CLI" --addr "vsock://$CID:5000" get-keys 2>&1)"
  if printf '%s\n' "$out" | grep -qiE 'not initialized|key not'; then
    log "FAIL: CID $CID is EMPTY (key not initialized — restarted and not re-cloned)"; fail=1; continue
  fi
  evm="$(extract_evm "$out")"
  if [ -z "$evm" ]; then
    log "FAIL: CID $CID no EVM address read (uninitialized / get-keys error)"; fail=1; continue
  fi
  exp="${EXP_EVM[$CID]:-}"
  if [ -n "$exp" ]; then
    if [ "${evm,,}" = "${exp,,}" ]; then
      log "OK:   CID $CID live EVM $evm == registered identity"
    else
      log "FAIL: CID $CID live EVM $evm != registered identity $exp (unregistered/re-inited key)"; fail=1
    fi
  else
    log "warn: CID $CID live EVM $evm — no EXPECTED_EVM entry, registration NOT verified"
  fi
done

# --- verdict ------------------------------------------------------------------
if [ "$fail" = 0 ]; then
  if [ -n "${EXPECTED_EVM:-}" ]; then
    log "PASS: all CIDs [$CIDS] RUNNING + keys match the registered identity"
  else
    log "PASS (liveness only): all CIDs [$CIDS] RUNNING with initialized keys — set EXPECTED_EVM to verify registration"
  fi
  exit 0
fi
log "FAILED — do NOT route traffic to this node until resolved"
exit 1
