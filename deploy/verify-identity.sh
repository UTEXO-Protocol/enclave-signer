#!/usr/bin/env bash
# verify-identity.sh — post-init / post-restart signing-identity gate.
#
# WHY: a restart puts an enclave back in Initial (EMPTY) until it
# is re-cloned, and a fresh re-init can mint a VALID-BUT-UNREGISTERED key. Process/
# PCR/port health does NOT prove the node holds the APPROVED registered signing key.
# If traffic is routed too early the node returns KeyNotInitialized, or a new
# unregistered key trips quorum/consumer rejection. This gate must PASS before a
# node is put back into rotation.
#
# Each selected enclave must be RUNNING without debug mode. A fresh real NSM
# attestation must match the approved PCRs, complete launch policy and EVM
# identity. Mint also compares both approved account xpubs and the master
# fingerprint. No structural get-keys response can approve an identity.
# This checks supplied identity pins; it does not prove backend or on-chain
# registration, readiness, or successful signing.
#
# Launch values (PCR_FILE, IMAGE_ENV, SIGNER_ROLE, EVM_RPC_HOST, ...) come from
# ENCLAVE_ENV and EVM_RPC_ENV (defaulting to
# /etc/nitro_enclaves/vsock-proxy-evmrpc.env), as
# utexo-enclave-ctl.sh reads them. deploy-host.sh writes one env per CID
# (/etc/utexo/enclave-<CID>.env), so check one CID per run.
#
# Runs ON a node (as root, e.g. via SSM — same model as deploy-host.sh).
# Self-contained; no infra identifiers baked in — pass them via env.
#
# Usage (run as root):
#   CLUSTER_DIR=<dir-with-utexo-bridge-parent-cli> \
#   EXPECTED_EVM="16=0x.. 18=0x.. 20=0x.." \
#   CIDS=<cid> ENCLAVE_ENV=/etc/utexo/enclave-<cid>.env bash verify-identity.sh
#
# EXPECTED_EVM must contain exactly one approved CID=0x<40 hex digits> entry
# per CIDS member. Mint also requires complete CID=value maps in
# EXPECTED_XPUB_VANILLA, EXPECTED_XPUB_COLORED and EXPECTED_MASTER_FINGERPRINT
# (eight hex characters). EXPECTED_EVM_RPC_HOST and
# EXPECTED_EVM_RPC_CA_SHA256 (64 hex characters) independently approve the
# launch endpoint. Obtain every pin from the approved deployment record,
# never from the live keys or policy of the enclave under check.
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
readonly approved_rpc_host="${EXPECTED_EVM_RPC_HOST:-}"
readonly approved_rpc_ca="${EXPECTED_EVM_RPC_CA_SHA256:-}"
readonly approved_evm="${EXPECTED_EVM:-}"
readonly approved_vanilla="${EXPECTED_XPUB_VANILLA:-}"
readonly approved_colored="${EXPECTED_XPUB_COLORED:-}"
readonly approved_fingerprint="${EXPECTED_MASTER_FINGERPRINT:-}"
readonly requested_cids="${CIDS-16 18 20}"
case "$#:$*" in
  0:) ;;
  1:--liveness) mode=liveness ;;
  *) fatal "usage: verify-identity.sh [--liveness]" ;;
esac

if [ "$mode" = identity ] && ! [ -r "${ENCLAVE_ENV:-}" ]; then
  fatal "ENCLAVE_ENV must name a readable launch env (/etc/utexo/enclave-<CID>.env)"
fi
# A launch env is shell code. When root sources it, every path component must
# be controlled by root; a protected final file under a writable parent is not
# sufficient. Service-user artifacts and test configs are read without root.
check_root_env() {
  [ "$(id -u)" = 0 ] || return 0
  python3 -I - "$1" <<'PY_ROOT_ENV'
import os, stat, sys
path = sys.argv[1]
try:
    if not path.startswith('/') or '..' in path.split('/'):
        raise ValueError()
    current = '/'
    parts = [part for part in path.split('/') if part]
    for index, part in enumerate([''] + parts):
        current = os.path.join(current, part)
        info = os.lstat(current)
        last = index == len(parts)
        if (info.st_uid != 0 or info.st_mode & 0o022 or
                (not stat.S_ISREG(info.st_mode) if last else not stat.S_ISDIR(info.st_mode))):
            raise ValueError()
except (OSError, ValueError):
    sys.exit(1)
PY_ROOT_ENV
}
for f in "${ENCLAVE_ENV:-}" "${EVM_RPC_ENV-/etc/nitro_enclaves/vsock-proxy-evmrpc.env}"; do
  if [ -n "$f" ] && [ -r "$f" ]; then
    check_root_env "$f" || fatal "launch env paths must be root-owned, not writable by others, and contain no symlinks"
    set -a; . "$f"; set +a
  fi
done

# An explicitly empty list is an error; only an unset CIDS gets the default.
CIDS="$requested_cids"
read -ra CID_ARR <<< "${CIDS//$'\n'/ }"
[ "${#CID_ARR[@]}" -gt 0 ] || fatal "CIDS must not be empty"
valid_cid(){ [[ "$1" =~ ^[1-9][0-9]{0,9}$ ]] && (( $1 >= 4 && $1 < 4294967295 )); }
declare -A TARGETS=() EXP_EVM=() EXP_VANILLA=() EXP_COLORED=() EXP_FINGERPRINT=()
for CID in "${CID_ARR[@]}"; do
  valid_cid "$CID" || fatal "invalid CID: $CID"
  [ -z "${TARGETS[$CID]:-}" ] || fatal "duplicate CID: $CID"
  TARGETS[$CID]=1
done

# Validate the entire approved map before probing nodes or exporting bundles.
if [ "$mode" = identity ]; then
  expected="$approved_evm"
  read -ra PAIRS <<< "${expected//$'\n'/ }"
  for kv in "${PAIRS[@]}"; do
    [[ "$kv" =~ ^([1-9][0-9]{0,9})=(0x[0-9a-fA-F]{40})$ ]] || fatal "invalid EXPECTED_EVM entry: $kv"
    CID="${BASH_REMATCH[1]}"
    address="${BASH_REMATCH[2]}"
    [ "$address" != 0x0000000000000000000000000000000000000000 ] || fatal "EXPECTED_EVM must not contain the zero address"
    [ -n "${TARGETS[$CID]:-}" ] || fatal "unexpected CID in EXPECTED_EVM: $CID"
    [ -z "${EXP_EVM[$CID]:-}" ] || fatal "duplicate CID in EXPECTED_EVM: $CID"
    EXP_EVM[$CID]="$address"
  done
  for CID in "${CID_ARR[@]}"; do
    [ -n "${EXP_EVM[$CID]:-}" ] || fatal "missing EXPECTED_EVM entry for CID $CID"
  done
fi

# Every Mint signing-account pin is required before querying any enclave.
if [ "$mode" = identity ]; then
  [ "${ENCLAVE_DEBUG_MODE:-0}" = 0 ] || fatal "debug mode cannot approve an identity; use --liveness for diagnostics"
  case "${SIGNER_ROLE:-}" in
    mint|burn) ;;
    *) fatal "SIGNER_ROLE must be mint or burn (set in ENCLAVE_ENV)" ;;
  esac
  [ -n "${PCR_FILE:-}" ] && [ -n "${IMAGE_ENV:-}" ] || fatal "PCR_FILE and IMAGE_ENV required (set in ENCLAVE_ENV)"
  [[ "$approved_rpc_host" =~ ^[a-zA-Z0-9.-]+$ ]] || fatal "EXPECTED_EVM_RPC_HOST must name the approved TLS host"
  [[ "$approved_rpc_ca" =~ ^[0-9a-fA-F]{64}$ ]] || fatal "EXPECTED_EVM_RPC_CA_SHA256 must be the approved 64-hex CA hash"
  launch_rpc_host="${EVM_RPC_HOST:-}"
  [ "${launch_rpc_host,,}" = "${approved_rpc_host,,}" ] || fatal "EVM_RPC_HOST differs from the approved endpoint"
  [ -n "${EVM_RPC_TLS_CA_DER_FILE:-}" ] || fatal "EVM_RPC_TLS_CA_DER_FILE required"
  if [ "$SIGNER_ROLE" = mint ]; then
    for field in VANILLA COLORED FINGERPRINT; do
      case "$field" in
        VANILLA) name=EXPECTED_XPUB_VANILLA; expected="$approved_vanilla" ;;
        COLORED) name=EXPECTED_XPUB_COLORED; expected="$approved_colored" ;;
        FINGERPRINT) name=EXPECTED_MASTER_FINGERPRINT; expected="$approved_fingerprint" ;;
      esac
      read -ra PAIRS <<< "${expected//$'\n'/ }"
      for kv in "${PAIRS[@]}"; do
        [[ "$kv" =~ ^([1-9][0-9]{0,9})=(.+)$ ]] || fatal "invalid $name entry"
        CID="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
        [ -n "${TARGETS[$CID]:-}" ] || fatal "unexpected CID in $name: $CID"
        case "$field" in
          VANILLA|COLORED)
            [[ "$value" =~ ^[xt]pub[1-9A-HJ-NP-Za-km-z]{107}$ ]] || fatal "$name must contain account xpubs"
            if [ "$field" = VANILLA ]; then
              [ -z "${EXP_VANILLA[$CID]:-}" ] || fatal "duplicate CID in $name: $CID"
              EXP_VANILLA[$CID]="$value"
            else
              [ -z "${EXP_COLORED[$CID]:-}" ] || fatal "duplicate CID in $name: $CID"
              EXP_COLORED[$CID]="$value"
            fi ;;
          FINGERPRINT)
            [[ "$value" =~ ^[0-9a-fA-F]{8}$ ]] || fatal "$name must contain eight-hex fingerprints"
            [ -z "${EXP_FINGERPRINT[$CID]:-}" ] || fatal "duplicate CID in $name: $CID"
            EXP_FINGERPRINT[$CID]="${value,,}" ;;
        esac
      done
    done
    for CID in "${CID_ARR[@]}"; do
      [ -n "${EXP_VANILLA[$CID]:-}" ] || fatal "missing EXPECTED_XPUB_VANILLA entry for CID $CID"
      [ -n "${EXP_COLORED[$CID]:-}" ] || fatal "missing EXPECTED_XPUB_COLORED entry for CID $CID"
      [ -n "${EXP_FINGERPRINT[$CID]:-}" ] || fatal "missing EXPECTED_MASTER_FINGERPRINT entry for CID $CID"
    done
  fi
fi

[ -n "${CLUSTER_DIR:-}" ] || fatal "CLUSTER_DIR required (dir containing utexo-bridge-parent-cli)"
CLI="$CLUSTER_DIR/utexo-bridge-parent-cli"
[ -x "$CLI" ] || fatal "CLI not found/executable at $CLI"
# The CLI and its output directory are service-user controlled. Root runs no
# artifact code and performs no bundle-file operations with its own privileges.
RUN_AS=()
[ "$(id -u)" = 0 ] && RUN_AS=(runuser -u ubuntu --)
RUN_CLI=("${RUN_AS[@]}" "$CLI")
if [ "$mode" = identity ]; then
  actual_ca="$("${RUN_AS[@]}" python3 -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$EVM_RPC_TLS_CA_DER_FILE" 2>/dev/null)" || fatal "cannot read EVM_RPC_TLS_CA_DER_FILE as the service user"
  [ "$actual_ca" = "${approved_rpc_ca,,}" ] || fatal "EVM RPC CA differs from the approved endpoint"
fi
fail=0

# --- 1. every configured enclave must be RUNNING ----------------------------
if ! running="$(nitro-cli describe-enclaves 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    d = []
print("\n".join(str(e["EnclaveCID"]) for e in d if e.get("State") == "RUNNING" and (sys.argv[1] == "liveness" or e.get("Flags") == "NONE")))
' "$mode" 2>/dev/null)"; then
  log "FAIL: cannot read running enclave inventory"; exit 1
fi
for CID in "${CID_ARR[@]}"; do
  printf '%s\n' "$running" | grep -qx "$CID" || { log "FAIL: CID $CID not RUNNING in the required mode"; fail=1; }
done
[ "$fail" = 0 ] || exit 1

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
  if [ "$mode" = identity ]; then
    bundle="$CLUSTER_DIR/attestation-$CID.json"
    "${RUN_AS[@]}" rm -f "$bundle" || { log "FAIL: cannot remove stale bundle for CID $CID"; fail=1; continue; }
    args=(--pcr-file "$PCR_FILE" --image-env "$IMAGE_ENV" --signer-role "$SIGNER_ROLE" --out "$bundle")
    args+=(--expect-evm-address "$exp")
    if [ "$SIGNER_ROLE" = mint ]; then
      args+=(--expect-account-xpub-vanilla "${EXP_VANILLA[$CID]}"
             --expect-account-xpub-colored "${EXP_COLORED[$CID]}"
             --expect-master-fingerprint "${EXP_FINGERPRINT[$CID]}")
    fi
    if ! out="$(timeout 45 "${RUN_CLI[@]}" --addr "vsock://$CID:5000" export-attestation "${args[@]}" 2>&1)"; then
      "${RUN_AS[@]}" rm -f "$bundle"
      log "FAIL: CID $CID attested export failed: $(printf '%s\n' "$out" | tail -1)"; fail=1; continue
    fi
    evm="$(extract_evm "$out")"
    if [ -z "$evm" ] || [ "${evm,,}" != "${exp,,}" ] || ! "${RUN_AS[@]}" test -s "$bundle"; then
      log "FAIL: CID $CID missing bundle or unexpected attested EVM address"
      "${RUN_AS[@]}" rm -f "$bundle"
      fail=1; continue
    fi
    log "OK:   CID $CID attested EVM $evm == approved identity; bundle $bundle"
    continue
  fi
  if ! out="$(timeout 20 "${RUN_CLI[@]}" --addr "vsock://$CID:5000" get-keys 2>&1)"; then
    log "FAIL: CID $CID get-keys failed"; fail=1; continue
  fi
  if printf '%s\n' "$out" | grep -qiE 'not initialized|key not'; then
    log "FAIL: CID $CID is EMPTY (key not initialized — restarted and not re-cloned)"; fail=1; continue
  fi
  evm="$(extract_evm "$out")"
  if [ -z "$evm" ]; then
    log "FAIL: CID $CID no EVM address read (uninitialized / get-keys error)"; fail=1; continue
  fi
  log "LIVE: CID $CID initialized; identity NOT approved"
done

# --- verdict ------------------------------------------------------------------
if [ "$fail" = 0 ]; then
  if [ "$mode" = identity ]; then
    log "PASS: all CIDs [$CIDS] RUNNING + attested keys and policy match the approved identity"
  else
    log "LIVE: all configured CIDs RUNNING with initialized keys; identity NOT approved; do NOT enable routing from this result"
  fi
  exit 0
fi
log "FAILED — do NOT route traffic to this node until resolved"
exit 1
