#!/usr/bin/env bash
# Deploy the enclave-signer cluster on THIS host from S3 by git_sha.
#
# Pulls the matching {EIF, parent, cli} set (published by the build-eif CI
# workflow under eif/<git_sha>/), verifies checksums and PCRs, installs systemd
# units + Nitro udev/tmpfiles rules, then runs 3 enclaves (CID 16/18/20) + 3
# parents (gRPC 50051/52/53) as systemd services so the cluster survives a reboot.
# Artifact-only: the host never builds or clones the repo.
#
# It does NOT bootstrap identity. A fresh/restarted enclave has no key; after this
# run `utexo-bridge-parent-cli init --cloning-secret ...` on a donor, or
# `... clone ...` on a requester. (Identity lives in enclave memory and is lost
# on restart/reboot — see TODO #5 for KMS-sealed DR. #7 only makes the PROCESSES
# come back automatically; the enclaves come up empty.)
#
# The systemd units / ctl scripts / udev / tmpfiles installed here are embedded
# below as heredocs so this script is self-contained over SSM. They are the same
# files kept (canonical, reviewable) under deploy/systemd/ in the repo — keep both
# in sync.
#
# Usage (run as root, e.g. via SSM):
#   GIT_SHA=<40-hex> BUCKET=<s3-bucket> AWS_REGION=<region> CLUSTER_DIR=<path> bash deploy-host.sh
# No infra identifiers or paths are baked in (public repo) — pass them via env.
set -euo pipefail

GIT_SHA="${GIT_SHA:?GIT_SHA required (40-hex commit)}"
BUCKET="${BUCKET:?BUCKET required (S3 artifact bucket)}"
REGION="${AWS_REGION:?AWS_REGION required (e.g. eu-central-1)}"
DIR="${CLUSTER_DIR:?CLUSTER_DIR required (cluster working dir, e.g. /home/<user>/<dir>)}"
EIF="$DIR/utexo-bridge-enclave.eif"
SRC="s3://$BUCKET/eif/$GIT_SHA"
ENCLAVE_CPU_COUNT="${ENCLAVE_CPU_COUNT:-2}"
ENCLAVE_MEMORY="${ENCLAVE_MEMORY:-3072}"
# DEBUG-MODE (op13 crash hunt): when set to 1, enclaves run with --debug-mode so
# `nitro-cli console` can attach. This ZEROES runtime PCR0/1/2, so the step-6
# runtime-PCR check is skipped (the static describe-eif measurement in step 3
# still verifies the EIF file). Default 0 keeps the normal production path.
ENCLAVE_DEBUG_MODE="${ENCLAVE_DEBUG_MODE:-0}"
CIDS=(16 18 20)
declare -A PORT=([16]=50051 [18]=50052 [20]=50053)

log(){ echo "[deploy $(date -u +%H:%M:%S)] $*"; }
asubuntu(){ su - ubuntu -c "$1"; }

# Ensure the `ne` group exists + ubuntu is a member (idempotent; the udev rule
# below relies on the group). Group membership is persistent across reboots.
getent group ne >/dev/null || groupadd -g 986 ne
id -nG ubuntu | grep -qw ne || usermod -aG ne ubuntu
mkdir -p "$DIR"

# --- 1. fetch artifacts ----------------------------------------------------
log "pulling artifacts from $SRC"
asubuntu "aws s3 cp $SRC/utexo-bridge-enclave.eif $EIF                 --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/PCR.json                 $DIR/PCR.json         --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/SHA256SUMS               $DIR/SHA256SUMS.eif   --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/utexo-bridge-parent      $DIR/utexo-bridge-parent     --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/utexo-bridge-parent-cli  $DIR/utexo-bridge-parent-cli --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/HOST-SHA256SUMS          $DIR/HOST-SHA256SUMS  --region $REGION --no-progress"
chmod +x "$DIR/utexo-bridge-parent" "$DIR/utexo-bridge-parent-cli"
chown ubuntu:ubuntu "$DIR/utexo-bridge-parent" "$DIR/utexo-bridge-parent-cli"

# --- 2. verify checksums ---------------------------------------------------
EXP=$(awk '{print $1}' "$DIR/SHA256SUMS.eif")
ACT=$(sha256sum "$EIF" | awk '{print $1}')
[ "$EXP" = "$ACT" ] || { log "EIF sha mismatch ($ACT != $EXP)"; exit 1; }
( cd "$DIR" && sha256sum -c HOST-SHA256SUMS ) || { log "host binary sha mismatch"; exit 1; }
log "checksums OK"

# --- 3. pre-flight PCR (static EIF measurement vs manifest) ----------------
EIF_PCR=$(asubuntu "nitro-cli describe-eif --eif-path $EIF" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["Measurements"]["PCR0"])')
MAN_PCR=$(python3 -c 'import json;print(json.load(open("'"$DIR"'/PCR.json"))["PCR0"])')
[ "$EIF_PCR" = "$MAN_PCR" ] || { log "PCR0 manifest mismatch ($EIF_PCR != $MAN_PCR)"; exit 1; }
log "PCR0 (manifest) = $MAN_PCR"

# --- 4. install host services (udev + tmpfiles + systemd units + env) ------
log "installing systemd units + udev/tmpfiles"
install -d /etc/utexo

# udev: give the `ne` group the Nitro device on every boot.
cat > /etc/udev/rules.d/99-nitro-enclaves.rules <<'EOF'
# Give the `ne` group access to the Nitro device on every boot, so enclaves can
# be run by the (non-root) ubuntu user without re-chmod'ing after a reboot.
KERNEL=="nitro_enclaves", GROUP="ne", MODE="0660"
EOF

# tmpfiles: recreate /run/nitro_enclaves on boot (tmpfs is wiped each boot).
cat > /etc/tmpfiles.d/10-nitro-enclaves.conf <<'EOF'
# Recreate the Nitro runtime dir on boot (tmpfs /run is wiped each boot).
# nitro-cli writes here; without it run/terminate-enclave fail (E19).
d /run/nitro_enclaves 0770 root ne -
EOF

# enclave control wrapper (serialized + retried: at boot all enclave units start
# in parallel and concurrent run-enclave calls race on the pool -> E36/E39).
cat > /usr/local/bin/utexo-enclave-ctl.sh <<'EOF'
#!/usr/bin/env bash
# start|stop a single Nitro enclave by CID, used by utexo-enclave@.service.
set -uo pipefail
ACTION="${1:?usage: utexo-enclave-ctl.sh start|stop <cid>}"
CID="${2:?cid required}"
NAME="enclave-${CID}"
CPU="${ENCLAVE_CPU_COUNT:-2}"
MEM="${ENCLAVE_MEMORY:-3072}"
LOCK="/tmp/utexo-enclave-start.lock"
enc_id() {
  nitro-cli describe-enclaves 2>/dev/null \
    | python3 -c "import json,sys; print(next((e['EnclaveID'] for e in json.load(sys.stdin) if e.get('EnclaveName')=='$NAME'), ''))"
}
case "$ACTION" in
  start)
    : "${EIF:?EIF env required (set in /etc/utexo/enclave.env)}"
    # fd 9 closed in nitro-cli children (9>&-) so an orphaned run-enclave can't
    # keep holding the lock and deadlock the next CID.
    exec 9>"$LOCK"
    flock -w 180 9 || { echo "could not acquire enclave start lock for CID $CID" >&2; exit 1; }
    # DEBUG-MODE: ENCLAVE_DEBUG_MODE=1 (unit env) -> run with --debug-mode so
    # `nitro-cli console` can attach. Zeroes PCR0/1/2; never on real production.
    DEBUG_ARG=()
    [ "${ENCLAVE_DEBUG_MODE:-0}" = "1" ] && DEBUG_ARG=(--debug-mode)
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
  *) echo "usage: utexo-enclave-ctl.sh start|stop <cid>" >&2; exit 2 ;;
esac
EOF
chmod 0755 /usr/local/bin/utexo-enclave-ctl.sh

# parent launcher wrapper.
cat > /usr/local/bin/utexo-parent-ctl.sh <<'EOF'
#!/usr/bin/env bash
# Launch the parent gRPC adapter from the cluster dir, used by utexo-parent@.service.
set -uo pipefail
cd "${CLUSTER_DIR:?CLUSTER_DIR env required (set in /etc/utexo/parent-<cid>.env)}"
exec ./utexo-bridge-parent
EOF
chmod 0755 /usr/local/bin/utexo-parent-ctl.sh

# templated units.
cat > /etc/systemd/system/utexo-enclave@.service <<'EOF'
[Unit]
Description=UTEXO Nitro enclave (CID %i)
After=nitro-enclaves-allocator.service
Requires=nitro-enclaves-allocator.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=ubuntu
TimeoutStartSec=300
EnvironmentFile=/etc/utexo/enclave.env
ExecStart=/usr/local/bin/utexo-enclave-ctl.sh start %i
ExecStop=/usr/local/bin/utexo-enclave-ctl.sh stop %i

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/utexo-parent@.service <<'EOF'
[Unit]
Description=UTEXO parent gRPC adapter (CID %i)
After=utexo-enclave@%i.service
Requires=utexo-enclave@%i.service

[Service]
Type=simple
User=ubuntu
EnvironmentFile=/etc/utexo/parent-%i.env
ExecStart=/usr/local/bin/utexo-parent-ctl.sh
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# env files (host-specific values; not in the repo).
cat > /etc/utexo/enclave.env <<EOF
EIF=$EIF
ENCLAVE_CPU_COUNT=$ENCLAVE_CPU_COUNT
ENCLAVE_MEMORY=$ENCLAVE_MEMORY
ENCLAVE_DEBUG_MODE=$ENCLAVE_DEBUG_MODE
EOF
for CID in "${CIDS[@]}"; do
  cat > "/etc/utexo/parent-$CID.env" <<EOF
CLUSTER_DIR=$DIR
GRPC_HOST=0.0.0.0
GRPC_PORT=${PORT[$CID]}
USE_VSOCK=true
ENCLAVE_VSOCK_CID=$CID
ENCLAVE_VSOCK_PORT=5000
EOF
done

# apply udev + tmpfiles now (so this run doesn't depend on a reboot).
udevadm control --reload && udevadm trigger --subsystem-match=misc 2>/dev/null || true
systemd-tmpfiles --create /etc/tmpfiles.d/10-nitro-enclaves.conf || true
systemctl daemon-reload

# --- 5. (re)start enclaves via systemd -------------------------------------
# Stop any prior unit instances, and kill stray setsid parents from pre-systemd
# deploys (they would hold the gRPC ports). Enclave ctl `start` also terminates a
# stale same-named enclave (anti-E39), so a leftover enclave is replaced cleanly.
for CID in "${CIDS[@]}"; do
  systemctl stop "utexo-parent@$CID" "utexo-enclave@$CID" 2>/dev/null || true
done
pkill -f utexo-bridge-parent 2>/dev/null || true
sleep 2

for CID in "${CIDS[@]}"; do
  systemctl enable "utexo-enclave@$CID" "utexo-parent@$CID" >/dev/null 2>&1 || true
  systemctl restart "utexo-enclave@$CID"
  sleep 2
done

# --- 6. verify runtime PCR matches the manifest ----------------------------
# In debug-mode the running enclave reports zeroed PCR0, so a manifest match is
# impossible by design — skip the runtime check (the static EIF measurement in
# step 3 already verified the artifact). Only meaningful for a production EIF.
if [ "$ENCLAVE_DEBUG_MODE" = "1" ]; then
  log "ENCLAVE_DEBUG_MODE=1 — skipping runtime PCR0 check (PCRs zeroed under --debug-mode)"
  asubuntu 'nitro-cli describe-enclaves' | python3 -c 'import json,sys; print("running CIDs:", sorted(e["EnclaveCID"] for e in json.load(sys.stdin)))'
else
asubuntu 'nitro-cli describe-enclaves' > /tmp/desc.json
python3 - "$MAN_PCR" <<'PY'
import json, sys
man = sys.argv[1]
d = json.load(open("/tmp/desc.json"))
bad = [e["EnclaveCID"] for e in d if e.get("Measurements", {}).get("PCR0") != man]
print("running CIDs:", sorted(e["EnclaveCID"] for e in d))
if bad:
    sys.exit(f"runtime PCR0 mismatch on CID {bad}")
print("runtime PCR0 == manifest on all enclaves")
PY
fi

# --- 7. start parents via systemd ------------------------------------------
for CID in "${CIDS[@]}"; do
  systemctl restart "utexo-parent@$CID"
done
sleep 4
ss -ltnp | grep -E '5005[123]' || { log "parents not listening"; exit 1; }

log "deploy OK (git_sha $GIT_SHA) — systemd-managed; run init/clone to bootstrap identity"
