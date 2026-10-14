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
# For SIGNER_ROLE=mint and ENCLAVE_DEBUG_MODE=1 (zero PCRs) step 3 reads get-keys:
# a fast STRUCTURAL check, NOT an attestation.
#
# Launch values (PCR_FILE, IMAGE_ENV, SIGNER_ROLE, ELECTRUM_URL, ...) come from
# ENCLAVE_ENV (default /etc/utexo/enclave.env) and
# /etc/nitro_enclaves/vsock-proxy-evmrpc.env, as utexo-enclave-ctl.sh reads them.
#
# Runs ON a node (as root, e.g. via SSM — same model as deploy-host.sh).
# Self-contained; no infra identifiers baked in — pass them via env.
#
# Usage (run as root):
#   CLUSTER_DIR=<dir-with-utexo-bridge-parent-cli> \
#   EXPECTED_EVM="16=0x.. 18=0x.. 20=0x.." \
#   [CIDS="16 18 20"] [ENCLAVE_ENV=/etc/utexo/enclave.env] bash verify-identity.sh
#
# Exit: 0 = all expected CIDs RUNNING + initialized + match registered identity.
#       1 = at least one CID empty / diverged / unregistered / export failed
#           -> do NOT route traffic.
#       2 = misconfiguration (missing CLI / bad args / missing launch values).
set -uo pipefail

CIDS="${CIDS:-16 18 20}"
CLUSTER_DIR="${CLUSTER_DIR:?CLUSTER_DIR required (dir containing utexo-bridge-parent-cli)}"
read -ra CID_ARR <<< "$CIDS"

for f in "${ENCLAVE_ENV:-/etc/utexo/enclave.env}" /etc/nitro_enclaves/vsock-proxy-evmrpc.env; do
  if [ -r "$f" ]; then set -a; . "$f"; set +a; fi
done

CLI="$CLUSTER_DIR/utexo-bridge-parent-cli"
[ -x "$CLI" ] || { echo "[verify-identity] FATAL: CLI not found/executable at $CLI"; exit 2; }

# Burn and combined signers prove the address with an attested export.
attested=1
if [ "${SIGNER_ROLE:-}" = "mint" ] || [ "${ENCLAVE_DEBUG_MODE:-0}" = "1" ]; then
  attested=0
elif [ -z "${PCR_FILE:-}" ] || [ -z "${IMAGE_ENV:-}" ] || [ -z "${SIGNER_ROLE:-}" ]; then
  echo "[verify-identity] FATAL: PCR_FILE, IMAGE_ENV and SIGNER_ROLE required (set in ENCLAVE_ENV)"
  exit 2
fi

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
  exp="${EXP_EVM[$CID]:-}"
  if [ "$attested" = 1 ]; then
    bundle="$CLUSTER_DIR/attestation-$CID.json"
    rm -f "$bundle"
    args=(--pcr-file "$PCR_FILE" --image-env "$IMAGE_ENV" --signer-role "$SIGNER_ROLE" --out "$bundle")
    [ -n "$exp" ] && args+=(--expect-evm-address "$exp")
    if ! out="$(timeout 45 "$CLI" --addr "vsock://$CID:5000" export-attestation "${args[@]}" 2>&1)"; then
      log "FAIL: CID $CID attested export failed: $(printf '%s\n' "$out" | tail -1)"; fail=1; continue
    fi
    evm="$(printf '%s\n' "$out" | grep -oiE 'EVM address: 0x[0-9a-f]{40}' | grep -oiE '0x[0-9a-f]{40}')"
    if [ -n "$exp" ]; then
      log "OK:   CID $CID attested EVM $evm == registered identity; bundle $bundle"
    else
      log "warn: CID $CID attested EVM $evm — no EXPECTED_EVM entry, registration NOT verified; bundle $bundle"
    fi
    continue
  fi
  [ "${ENCLAVE_DEBUG_MODE:-0}" = "1" ] && log "CID $CID bundle skipped: debug PCRs are zero"
  out="$(timeout 20 "$CLI" --addr "vsock://$CID:5000" get-keys 2>&1)"
  if printf '%s\n' "$out" | grep -qiE 'not initialized|key not'; then
    log "FAIL: CID $CID is EMPTY (key not initialized — restarted and not re-cloned)"; fail=1; continue
  fi
  evm="$(extract_evm "$out")"
  if [ -z "$evm" ]; then
    log "FAIL: CID $CID no EVM address read (uninitialized / get-keys error)"; fail=1; continue
  fi
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
