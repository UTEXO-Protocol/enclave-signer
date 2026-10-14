#!/usr/bin/env bash
# start|stop a single Nitro enclave by CID, used by utexo-enclave@.service.
# `start` sets the chain endpoints on the fresh enclave. Identity is NOT
# bootstrapped here - a freshly (re)started enclave is empty; run `init`/`clone`
# separately (keys live only in enclave memory).
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
LOCK="${UTEXO_ENCLAVE_LOCK:-/tmp/utexo-enclave-start.lock}"

# Resolve the running enclave-id for our name (empty if not running).
enc_id() {
  nitro-cli describe-enclaves 2>/dev/null \
    | python3 -c "import json,sys; print(next((e['EnclaveID'] for e in json.load(sys.stdin) if e.get('EnclaveName')=='$NAME'), ''))"
}

# Set endpoints and KMS values once from the unit env.
set_endpoints() {
  : "${CLI:?CLI env required (set in /etc/utexo/enclave.env)}"
  # systemd sources this via EnvironmentFile; a manual `start` does not, so
  # source it here too (idempotent: harmless if already in the environment).
  if [ -r /etc/nitro_enclaves/vsock-proxy-evmrpc.env ]; then
    set -a; . /etc/nitro_enclaves/vsock-proxy-evmrpc.env; set +a
  fi
  for _ in $(seq 30); do
    # `health` exits 1 until the enclave is ready. Any answer will do.
    case "$("$CLI" --addr "vsock://$CID:5000" health 2>/dev/null)" in
      *"Endpoints set:"*) "$CLI" --addr "vsock://$CID:5000" set-endpoints; return ;;
    esac
    sleep 2
  done
  echo "enclave CID $CID did not answer health" >&2
  return 1
}

# Terminate this enclave if it runs. Fail if it still runs after.
terminate() {
  id="$(enc_id)"; [ -n "$id" ] && nitro-cli terminate-enclave --enclave-id "$id"
  [ -z "$(enc_id)" ] && return 0
  echo "FATAL: enclave CID $CID still running after terminate" >&2
  return 1
}
# Compare the attested launch policy with the deploy inputs. Debug mode
# zeroes the PCRs, so it skips the check.
verify_launch() {
  if [ "${ENCLAVE_DEBUG_MODE:-0}" = "1" ]; then
    echo "debug mode: PCRs are zero, launch attestation check skipped"
    return 0
  fi
  timeout --kill-after=5 "${VERIFY_LAUNCH_TIMEOUT:-45}" \
    "$CLI" --addr "vsock://$CID:5000" verify-launch \
    --pcr-file "$PCR_FILE" --image-env "$IMAGE_ENV" --signer-role "$SIGNER_ROLE"
}
case "$ACTION" in
  start)
    : "${EIF:?EIF env required (set in /etc/utexo/enclave.env)}"
    : "${PCR_FILE:?PCR_FILE env required}" "${IMAGE_ENV:?IMAGE_ENV env required}" "${SIGNER_ROLE:?SIGNER_ROLE env required}"
    # Hold a host-wide lock so only one run-enclave runs at a time (anti-race).
    # `nitro-cli` children are spawned with fd 9 closed (9>&-) so an occasionally
    # orphaned/lingering run-enclave can never keep holding the lock and deadlock
    # the next CID; the lock is released the moment this shell exits.
    exec 9>"$LOCK"
    flock -w 180 9 || { echo "could not acquire enclave start lock for CID $CID" >&2; exit 1; }
    # DEBUG-MODE: ENCLAVE_DEBUG_MODE=1 (unit env) -> run with --debug-mode so
    # `nitro-cli console` can attach. This zeroes PCR0/1/2, so attestation is
    # insecure. Never enable it on a production host.
    DEBUG_ARG=()
    [ "${ENCLAVE_DEBUG_MODE:-0}" = "1" ] && DEBUG_ARG=(--debug-mode)
    # Clear a stale instance of THIS enclave so the CPU pool is free (anti-E39).
    old="$(enc_id)"; [ -n "$old" ] && nitro-cli terminate-enclave --enclave-id "$old" 9>&- || true
    for attempt in 1 2 3 4 5; do
      if nitro-cli run-enclave \
        --eif-path "$EIF" --cpu-count "$CPU" --memory "$MEM" \
        --enclave-cid "$CID" --enclave-name "$NAME" "${DEBUG_ARG[@]}" 9>&-; then
        exec 9>&-
        set_endpoints && verify_launch && exit 0
        echo "set-endpoints or launch check CID $CID failed; terminating the enclave" >&2
        terminate
        exit 1
      fi
      echo "run-enclave CID $CID attempt $attempt failed; cleaning up and retrying" >&2
      bad="$(enc_id)"; [ -n "$bad" ] && nitro-cli terminate-enclave --enclave-id "$bad" 9>&- || true
      sleep 3
    done
    echo "run-enclave CID $CID failed after retries" >&2
    exit 1
    ;;
  stop)
    terminate
    ;;
  *)
    echo "usage: utexo-enclave-ctl.sh start|stop <cid>" >&2
    exit 2
    ;;
esac
