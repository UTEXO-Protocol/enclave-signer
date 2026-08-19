#!/usr/bin/env bash
# start|stop a single Nitro enclave by CID, used by utexo-enclave@.service.
# Identity is NOT bootstrapped here — a freshly (re)started enclave is empty;
# run `init`/`clone` separately (keys live only in enclave memory).
#
# At boot systemd starts all per-CID enclave units in parallel, but concurrent
# `nitro-cli run-enclave` calls race on the shared CPU/memory pool and fail with
# E36/E39. We therefore serialize starts host-wide with flock and retry the
# transient pool failures.
set -uo pipefail

ACTION="${1:?usage: utexo-enclave-ctl.sh start|stop <cid>}"
CID="${2:?cid required}"
NAME="enclave-${CID}"
CPU="${ENCLAVE_CPU_COUNT:-2}"
MEM="${ENCLAVE_MEMORY:-3072}"
LOCK="/tmp/utexo-enclave-start.lock"

# Resolve the running enclave-id for our name (empty if not running).
enc_id() {
  nitro-cli describe-enclaves 2>/dev/null \
    | python3 -c "import json,sys; print(next((e['EnclaveID'] for e in json.load(sys.stdin) if e.get('EnclaveName')=='$NAME'), ''))"
}

case "$ACTION" in
  start)
    : "${EIF:?EIF env required (set in /etc/utexo/enclave.env)}"
    # Hold a host-wide lock so only one run-enclave runs at a time (anti-race).
    # `nitro-cli` children are spawned with fd 9 closed (9>&-) so an occasionally
    # orphaned/lingering run-enclave can never keep holding the lock and deadlock
    # the next CID; the lock is released the moment this shell exits.
    exec 9>"$LOCK"
    flock -w 180 9 || { echo "could not acquire enclave start lock for CID $CID" >&2; exit 1; }
    # DEBUG-MODE (op13 crash hunt): when ENCLAVE_DEBUG_MODE=1 in the unit env,
    # run the enclave with --debug-mode so `nitro-cli console` can attach and
    # surface the in-enclave panic/backtrace. NOTE: debug-mode ZEROES PCR0/1/2 —
    # attestation is insecure and the clone flow only passes because both peers
    # report zeroed PCRs. Never leave this enabled on a real production host.
    DEBUG_ARG=()
    [ "${ENCLAVE_DEBUG_MODE:-0}" = "1" ] && DEBUG_ARG=(--debug-mode)
    # Clear a stale instance of THIS enclave so the CPU pool is free (anti-E39).
    old="$(enc_id)"; [ -n "$old" ] && nitro-cli terminate-enclave --enclave-id "$old" 9>&- || true
    for attempt in 1 2 3 4 5; do
      if nitro-cli run-enclave \
        --eif-path "$EIF" --cpu-count "$CPU" --memory "$MEM" \
        --enclave-cid "$CID" --enclave-name "$NAME" "${DEBUG_ARG[@]}" 9>&-; then
        exit 0
      fi
      echo "run-enclave CID $CID attempt $attempt failed; cleaning up and retrying" >&2
      bad="$(enc_id)"; [ -n "$bad" ] && nitro-cli terminate-enclave --enclave-id "$bad" 9>&- || true
      sleep 3
    done
    echo "run-enclave CID $CID failed after retries" >&2
    exit 1
    ;;
  stop)
    id="$(enc_id)"; [ -n "$id" ] && nitro-cli terminate-enclave --enclave-id "$id" || true
    ;;
  *)
    echo "usage: utexo-enclave-ctl.sh start|stop <cid>" >&2
    exit 2
    ;;
esac
