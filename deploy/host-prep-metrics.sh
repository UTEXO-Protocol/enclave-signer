#!/usr/bin/env bash
# Host-prep for enclave-host LIVENESS METRICS (run as root, e.g. via SSM).
#
# TODO §7a Track 2. Track 1 (host-prep-observability.sh) ships journald logs;
# this ships the "is it alive?" SIGNAL that actually drives alarms. A systemd
# timer runs a tiny reporter every 60s and publishes 3 custom CloudWatch metrics
# per CID (namespace `Utexo/EnclaveHost`, dims Host=<instance-id>, Cid=<16|18|20>):
#
#   EnclaveRunning     nitro-cli describe-enclaves has this CID in State=RUNNING   (1/0)
#   ParentListening    the parent gRPC port (16->50051,18->50052,20->50053) listens (1/0)
#   EnclaveResponsive  cli `get-keys` over vsock returns OK = enclave initialized  (1/0)
#                      + not wedged (catches "process up but empty" — a port check
#                      alone would miss this).
#
# All HOST-SIDE (describe-enclaves + a port check + a read-only get-keys over
# vsock straight to the enclave — does NOT touch the parent or the EIF). PCR0
# unchanged, no rebuild. Reboot-safe (systemd timer enabled).
#
# ── IAM (attach ONCE to the hosts' instance role `ec2-ssm-role`) ──────────────
# Least-privilege policy `utexo-stage-enclave-metrics-put` (PutMetricData cannot
# be resource-scoped, so it is constrained by the metric namespace condition):
#   {
#     "Version": "2012-10-17",
#     "Statement": [{
#       "Sid": "EnclaveHostMetricsPut",
#       "Effect": "Allow",
#       "Action": "cloudwatch:PutMetricData",
#       "Resource": "*",
#       "Condition": { "StringEquals": { "cloudwatch:namespace": "Utexo/EnclaveHost" } }
#     }]
#   }
#
# Usage (root):  AWS_REGION=eu-central-1 bash host-prep-metrics.sh
set -euo pipefail

REGION="${AWS_REGION:-eu-central-1}"
NS="${METRIC_NAMESPACE:-Utexo/EnclaveHost}"
INTERVAL_SEC="${INTERVAL_SEC:-60}"
REPORTER=/usr/local/bin/utexo-enclave-metrics.sh

log(){ echo "[host-prep-metrics $(date -u +%H:%M:%S)] $*"; }

# --- 1. install the reporter script ----------------------------------------
log "writing $REPORTER"
cat > "$REPORTER" <<'REPORTER_EOF'
#!/usr/bin/env bash
# Emit enclave/parent liveness metrics to CloudWatch. Installed by
# deploy/host-prep-metrics.sh; run by utexo-enclave-metrics.timer every 60s.
set -uo pipefail
REGION="${AWS_REGION:-eu-central-1}"
NS="${METRIC_NAMESPACE:-Utexo/EnclaveHost}"
CIDS=(16 18 20)
declare -A PORT=([16]=50051 [18]=50052 [20]=50053)

# instance-id via IMDSv2 (dimension Host)
TOK=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 120" 2>/dev/null || true)
IID=$(curl -sS -H "X-aws-ec2-metadata-token: $TOK" \
        "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || true)
IID="${IID:-unknown}"

# cluster dir holds the cli binary (read from a parent env, fallback to default)
CLUSTER_DIR=$(sed -n 's/^CLUSTER_DIR=//p' /etc/utexo/parent-16.env 2>/dev/null | head -1)
CLUSTER_DIR="${CLUSTER_DIR:-/home/ubuntu/clone-stage}"
CLI="$CLUSTER_DIR/utexo-bridge-parent-cli"

DESC=$(nitro-cli describe-enclaves 2>/dev/null || echo '[]')
SS=$(ss -ltnH 2>/dev/null || true)

METRICS=()
for CID in "${CIDS[@]}"; do
  RUN=$(printf '%s' "$DESC" | jq -r --argjson c "$CID" \
        'if any(.[]?; .EnclaveCID==$c and .State=="RUNNING") then 1 else 0 end' 2>/dev/null)
  [ "$RUN" = "1" ] || RUN=0

  P=${PORT[$CID]}
  if printf '%s' "$SS" | grep -qE ":${P}([^0-9]|$)"; then LIS=1; else LIS=0; fi

  RESP=0
  if [ "$RUN" = "1" ] && [ -x "$CLI" ]; then
    if "$CLI" --addr "vsock://${CID}:5000" get-keys >/dev/null 2>&1; then RESP=1; fi
  fi

  D="Dimensions=[{Name=Host,Value=${IID}},{Name=Cid,Value=${CID}}]"
  METRICS+=( "MetricName=EnclaveRunning,${D},Value=${RUN},Unit=Count" )
  METRICS+=( "MetricName=ParentListening,${D},Value=${LIS},Unit=Count" )
  METRICS+=( "MetricName=EnclaveResponsive,${D},Value=${RESP},Unit=Count" )
done

# vsock-proxy liveness (egress: electrs 8001, evm-rpc 8002). vsock ports are NOT
# TCP so `ss -ltn` can't see them — use systemctl. Dimension Proxy=electrs|evmrpc.
declare -A PROXY=([electrs]=vsock-proxy-electrs [evmrpc]=vsock-proxy-evmrpc)
for PNAME in "${!PROXY[@]}"; do
  if systemctl is-active --quiet "${PROXY[$PNAME]}"; then UP=1; else UP=0; fi
  DP="Dimensions=[{Name=Host,Value=${IID}},{Name=Proxy,Value=${PNAME}}]"
  METRICS+=( "MetricName=VsockProxyUp,${DP},Value=${UP},Unit=Count" )
done

aws cloudwatch put-metric-data --namespace "$NS" --region "$REGION" \
  --metric-data "${METRICS[@]}"
REPORTER_EOF
chmod 755 "$REPORTER"

# --- 2. systemd service + timer --------------------------------------------
log "writing utexo-enclave-metrics.service + .timer (every ${INTERVAL_SEC}s)"
cat > /etc/systemd/system/utexo-enclave-metrics.service <<EOF
[Unit]
Description=Publish enclave/parent liveness metrics to CloudWatch (Utexo/EnclaveHost)
After=network-online.target nitro-enclaves-allocator.service
Wants=network-online.target

[Service]
Type=oneshot
Environment=AWS_REGION=${REGION}
Environment=METRIC_NAMESPACE=${NS}
ExecStart=${REPORTER}
EOF

cat > /etc/systemd/system/utexo-enclave-metrics.timer <<EOF
[Unit]
Description=Run utexo-enclave-metrics every ${INTERVAL_SEC}s

[Timer]
OnBootSec=${INTERVAL_SEC}
OnUnitActiveSec=${INTERVAL_SEC}
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now utexo-enclave-metrics.timer >/dev/null 2>&1 || true

# --- 3. run once now + show what would be published ------------------------
log "running the reporter once (foreground)"
if AWS_REGION="$REGION" METRIC_NAMESPACE="$NS" "$REPORTER"; then
  log "put-metric-data OK"
else
  log "NOTE: reporter run failed — if it is 'AccessDenied', attach utexo-stage-enclave-metrics-put to the instance role, then: systemctl start utexo-enclave-metrics.service"
fi

log "timer status:"
systemctl --no-pager --lines=0 status utexo-enclave-metrics.timer 2>/dev/null | grep -E 'Active:|Trigger:' || true
log "host-prep-metrics DONE — metrics -> namespace $NS (Host/Cid dims)"
