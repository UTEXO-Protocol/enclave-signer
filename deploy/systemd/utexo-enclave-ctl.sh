#!/usr/bin/env bash
# start|check|stop a single Nitro enclave by CID, used by utexo-enclave@.service.
# `check` refuses a launch value or a hugepage pool that cannot hold every
# enclave of the host, and changes nothing. Run it before a rolling restart:
# under `systemctl restart` the old enclave stops before `start` runs.
# `start` sets the chain endpoints on the fresh enclave. Identity is NOT
# bootstrapped here - a freshly (re)started enclave is empty; run `init`/`clone`
# separately (keys live only in enclave memory).
#
# At boot systemd starts all per-CID enclave units in parallel, but concurrent
# `nitro-cli run-enclave` calls race on the shared CPU/memory pool and fail with
# E36/E39. We therefore serialize starts host-wide with flock and retry the
# transient pool failures.
set -uo pipefail

ACTION="${1:?usage: utexo-enclave-ctl.sh start|check|stop <cid>}"
CID="${2:?cid required}"
# systemd gives `start` the values in /etc/utexo/enclave.env. `check` takes
# the four keys below from this file only, and a key that is not in the file
# gets its default. A drop-in or the systemd manager can still give `start` a
# value for such a key, but deploy-host.sh writes all four keys. `check`
# refuses a file that it cannot read. It reads only these plain lines:
# - KEY=value. The key has only ASCII letters, digits and `_`, and its first
#   character is not a digit. The key and the `=` can have blanks around
#   them. The value has no backslash. A value can have one pair of the same
#   quotes around it, and no other quote.
# - A comment line. Its first character that is not a blank is `#` or `;`.
# - A blank line.
# A plain line can end with a carriage return. It has no other carriage
# return, no backslash at its end, and only tabs and printable ASCII.
# A plain line has at most 4096 bytes, and the file has at most 65536
# bytes. systemd does not start the unit with some much larger values and
# files.
#
# On plain lines, `check` reads the values as systemd reads them. The last
# line of a key wins. `check` removes the blanks around the key and the value,
# and one pair of quotes around the whole value. A comment after a value stays
# in the value. systemd joins, splits, changes or ignores some other lines, or
# refuses the file, so `check` refuses a file with them. An empty ENCLAVE_ENV
# makes `check` use the environment.
ENV_FILE="${ENCLAVE_ENV-/etc/utexo/enclave.env}"
if [ "$ACTION" = check ] && [ -n "$ENV_FILE" ]; then
  # The number of the first line that is not plain, or 0. awk can miss a NUL
  # byte, so tr changes it to a byte that is not plain.
  bad=
  if [ -f "$ENV_FILE" ] && [ -r "$ENV_FILE" ]; then
    bad="$(LC_ALL=C tr '\000' '\001' < "$ENV_FILE" | LC_ALL=C awk -v q="'" '
      bad { next }
      { size += length($0) + 1; sub(/\r$/, "") }
      /[^\t -~]/ || /\\$/ || length($0) > 4096 || size > 65536 { bad = NR; next }
      /^[ \t]*[#;]/ || /^[ \t]*$/ { next }
      {
        n = index($0, "="); v = substr($0, n + 1); sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
        f = substr(v, 1, 1); w = substr(v, 2, length(v) - 2)
        if (!n || substr($0, 1, n - 1) !~ /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*$/ || /\\/)
          bad = NR
        else if ((index(v, "\"") || index(v, q)) && (length(v) < 2 || (f != "\"" && f != q) ||
                 substr(v, length(v)) != f || index(w, "\"") || index(w, q)))
          bad = NR
      }
      END { print bad + 0 }')" || bad=
  fi
  case "$bad" in
    0) ;;
    '') echo "cannot read $ENV_FILE. systemd gives start the values in this file. Run check as root or as a user that can read the file." >&2; exit 1 ;;
    *) echo "line $bad of $ENV_FILE is not a plain line. Write the file again with plain KEY=value lines, comment lines and blank lines only (README)." >&2; exit 1 ;;
  esac
  for key in ENCLAVE_MEMORY ENCLAVE_COUNT NITRO_ALLOCATOR_CONFIG NITRO_HUGEPAGES_DIR; do
    value="$(awk -v k="$key" -v q="'" '
      { l = $0; sub(/^[ \t\r]+/, "", l); n = index(l, "=") }
      n > 0 && substr(l, 1, n - 1) ~ ("^" k "[ \t]*$") {
        v = substr(l, n + 1); sub(/^[ \t\r]+/, "", v); sub(/[ \t\r]+$/, "", v)
        f = substr(v, 1, 1)
        if (length(v) > 1 && (f == "\"" || f == q) && substr(v, length(v)) == f)
          v = substr(v, 2, length(v) - 2)
        out = "=" v
      }
      END { printf "%s", out }' "$ENV_FILE")" || { echo "cannot read $ENV_FILE." >&2; exit 1; }
    if [ -n "$value" ]; then export "$key=${value#=}"; else unset "$key"; fi
  done
else
  ENV_FILE="the environment"
fi
NAME="enclave-${CID}"
CPU="${ENCLAVE_CPU_COUNT:-2}"
MEM="${ENCLAVE_MEMORY:-4096}"
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
# The Nitro allocator reserves hugepages for the enclaves of the host.
# nitro-cli gives an enclave whole pages, 1 GiB pages first.
POOL_FILE="${NITRO_ALLOCATOR_CONFIG:-/etc/nitro_enclaves/allocator.yaml}"
PAGES_DIR="${NITRO_HUGEPAGES_DIR:-/sys/kernel/mm/hugepages}"
# memory_mib in the allocator file, read with the loop of the allocator. It
# reads each line with `read`, so it ignores a last line with no newline. It
# reads only the lines after "---". It edits the value with the same sed
# commands, so a comment after the value stays in the value. The allocator
# also refuses other errors in the file, which this function does not check.
file_pool_mib() {
  local line value='' data=''
  while read line; do
    [[ $line =~ ^[[:space:]]*# ]] && continue
    [ "$line" = --- ] && { data=1; continue; }
    [ -n "$data" ] || continue
    [[ ${line%%:*} =~ ^[-_a-zA-Z0-9]+ ]] && [ "${BASH_REMATCH[0]}" = memory_mib ] || continue
    value="$(printf '%s\n' "$line" | sed -E 's/^.+://; s/[[:space:]]+"?//; s/"?$//')"
  done 2>/dev/null < "$POOL_FILE"
  printf '%s\n' "$value"
}
# The MiB in hugepages of all sizes: the kernel holds nr_hugepages, and no
# enclave uses free_hugepages.
pages_mib() {
  total=0
  for dir in "$PAGES_DIR"/hugepages-*kB; do
    n="$(cat "$dir/$1" 2>/dev/null)"
    kb="${dir##*/hugepages-}"
    kb="${kb%kB}"
    case "$n" in ''|*[!0-9]*) continue ;; esac
    case "$kb" in ''|*[!0-9]*) continue ;; esac
    total=$((total + n * kb / 1024))
  done
  echo "$total"
}

case "$ACTION" in
  start|check)
    # The enclave refuses to start below 2688 MiB of usable memory
    # (enclave/src/memory.rs), and the kernel keeps part of the launch value.
    # Refuse a value under 4096 MiB here, where the message is read.
    case "$MEM" in
      ''|0?*|*[!0-9]*|????????*) echo "ENCLAVE_MEMORY must be a whole number of MiB with at most 7 digits and no leading zero, got '$MEM'" >&2; exit 1 ;;
    esac
    if [ "$MEM" -lt 4096 ]; then
      echo "ENCLAVE_MEMORY=$MEM MiB is below the 4096 MiB minimum (enclave/src/memory.rs)" >&2
      exit 1
    fi
    # A value that is not a whole number of GiB can take a further 1 GiB page.
    if [ $((MEM % 1024)) -ne 0 ]; then
      echo "ENCLAVE_MEMORY=$MEM MiB is not a whole number of GiB (enclave/src/memory.rs)" >&2
      exit 1
    fi
    COUNT="${ENCLAVE_COUNT:-3}"
    case "$COUNT" in
      ''|0*|*[!0-9]*|???*) echo "ENCLAVE_COUNT must be a whole number from 1 to 99, got '$COUNT'" >&2; exit 1 ;;
    esac
    if [ "$ACTION" = check ]; then
      # The pool must hold every enclave of the host at this value. The
      # allocator applies the file at its next start, and the kernel holds
      # the pages now.
      need=$((COUNT * MEM))
      file="$(file_pool_mib)"
      # The allocator refuses a value that is not a number, and it reads a
      # leading zero as an octal number.
      case "$file" in
        ''|0*|*[!0-9]*|????????*) echo "cannot read memory_mib from $POOL_FILE, got '$file'" >&2; exit 1 ;;
      esac
      if [ "$file" -lt "$need" ]; then
        echo "memory_mib in $POOL_FILE is $file MiB, and $COUNT enclaves (ENCLAVE_COUNT) of $MEM MiB need $need MiB. Set it to at least $need. The allocator applies it when its service starts, and a restart of that service restarts every enclave of this host (README)." >&2
        exit 1
      fi
      held="$(pages_mib nr_hugepages)"
      if [ "$held" -lt "$need" ]; then
        echo "the kernel holds $held MiB of hugepages in $PAGES_DIR, and $COUNT enclaves (ENCLAVE_COUNT) of $MEM MiB need $need MiB. The allocator applies memory_mib when its service starts, and a restart of that service restarts every enclave of this host (README)." >&2
        exit 1
      fi
      echo "CID $CID: $COUNT enclaves of $MEM MiB fit: memory_mib $file MiB, hugepages $held MiB, values from $ENV_FILE"
      exit 0
    fi
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
    # Refuse with one clear message, not five failed attempts, when the free
    # hugepages cannot hold this enclave. A stopped enclave frees its pages.
    free=0
    for _ in 1 2 3 4 5; do
      free="$(pages_mib free_hugepages)"
      [ "$free" -ge "$MEM" ] && break
      sleep 1
    done
    if [ "$free" -lt "$MEM" ]; then
      echo "only $free MiB of hugepages are free in $PAGES_DIR, and CID $CID needs $MEM MiB" >&2
      exit 1
    fi
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
    echo "usage: utexo-enclave-ctl.sh start|check|stop <cid>" >&2
    exit 2
    ;;
esac
