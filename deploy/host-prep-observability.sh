#!/usr/bin/env bash
# Host-prep for enclave-host observability (run as root, e.g. via SSM).
#
# PROBLEM (2026-08-27): today there is NO signal when a `parent` or `enclave`
# process dies. Parents log only to journald (local, invisible off-host); the
# enclave itself is opaque in prod (no `nitro-cli console` under non-debug = TEE
# isolation). Listeners already ship to CloudWatch (`/utexo/stage/listeners`, via
# the docker `awslogs` driver) — parents/enclaves have nothing.
#
# This stands up, idempotently and reboot-safe, the host side of LOG collection
# (TODO §7a Track 1). It installs the amazon-cloudwatch-agent and ships the
# relevant journald units to CloudWatch Logs:
#
#   journald unit                 -> log group `/utexo/stage/enclave-hosts`
#   ---------------------------      stream `{instance_id}/<role>`
#   utexo-parent@{16,18,20}       -> {instance_id}/parent    (gRPC adapter — the noisy one)
#   utexo-enclave@{16,18,20}      -> {instance_id}/enclave   (host-side run/terminate lifecycle)
#   nitro-enclaves-allocator      -> {instance_id}/nitro     (CPU/mem pool)
#   vsock-proxy-*                 -> {instance_id}/nitro     (electrs / evm-rpc egress)
#
# ⚠️ SCOPE / TEE NOTE: this collects the HOST-SIDE `utexo-enclave@` unit (the
# systemd wrapper that runs/terminates the enclave) + the allocator + vsock
# proxies — NOT in-enclave application log lines, which are unreachable in prod
# by design. For an in-enclave post-mortem you need a temporary `--debug-mode`
# EIF (PCRs zeroed). The enclave/EIF is UNTOUCHED here → PCR0 unchanged, no
# rebuild, same trust posture as the listener awslogs.
#
# ⚠️ Parents ≠ listeners mechanically: listeners are docker (`awslogs` driver);
# parents/enclaves are systemd/journald, so awslogs does not apply. We use the
# CloudWatch Agent journald collector with a `units` selector (supports the
# `utexo-parent@*` wildcard). Requires a recent agent (journald support was added
# to amazon-cloudwatch-agent); this script installs `latest`.
#
# ── IAM (attach ONCE to the hosts' instance role `ec2-ssm-role`) ──────────────
# Least-privilege WRITE policy `utexo-stage-enclave-hosts-logs-write`:
#   {
#     "Version": "2012-10-17",
#     "Statement": [{
#       "Sid": "EnclaveHostsLogsWrite",
#       "Effect": "Allow",
#       "Action": [
#         "logs:CreateLogGroup",
#         "logs:CreateLogStream",
#         "logs:PutLogEvents",
#         "logs:PutRetentionPolicy",
#         "logs:DescribeLogStreams",
#         "logs:DescribeLogGroups"
#       ],
#       "Resource": [
#         "arn:aws:logs:eu-central-1:867958227014:log-group:/utexo/stage/enclave-hosts",
#         "arn:aws:logs:eu-central-1:867958227014:log-group:/utexo/stage/enclave-hosts:*"
#       ]
#     }]
#   }
# (Mirror of the listener logging IAM. A dev READ policy — like
#  `utexo-stage-listener-logs-read` — can be added later for console access.)
#
# Usage (root):
#   AWS_REGION=eu-central-1 LOG_GROUP=/utexo/stage/enclave-hosts \
#   bash host-prep-observability.sh
set -euo pipefail

REGION="${AWS_REGION:-eu-central-1}"
LOG_GROUP="${LOG_GROUP:-/utexo/stage/enclave-hosts}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
CWA_DIR=/opt/aws/amazon-cloudwatch-agent
CWA_CTL="$CWA_DIR/bin/amazon-cloudwatch-agent-ctl"
CWA_CONF="$CWA_DIR/etc/utexo-enclave-hosts.json"

log(){ echo "[host-prep-obs $(date -u +%H:%M:%S)] $*"; }

# --- 1. install amazon-cloudwatch-agent if absent --------------------------
if [ ! -x "$CWA_CTL" ]; then
  log "installing amazon-cloudwatch-agent (latest .deb) from S3 $REGION"
  DEB=/tmp/amazon-cloudwatch-agent.deb
  curl -fsSL -o "$DEB" \
    "https://amazoncloudwatch-agent-${REGION}.s3.${REGION}.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb"
  export DEBIAN_FRONTEND=noninteractive
  dpkg -i -E "$DEB" || { apt-get -f install -y -qq; dpkg -i -E "$DEB"; }
  rm -f "$DEB"
else
  log "amazon-cloudwatch-agent already present"
fi
# journald collection requires a recent agent — surface the version for the log.
"$CWA_CTL" -version 2>/dev/null | sed 's/^/[host-prep-obs] cwagent /' || true

# --- 2. render the agent config (journald -> CloudWatch Logs) --------------
# `units` accepts wildcards; `priority` omitted => default `info` and above
# (drops debug spam). One entry per role so streams stay readable.
log "writing $CWA_CONF (log group $LOG_GROUP, retention ${RETENTION_DAYS}d)"
install -d "$(dirname "$CWA_CONF")"
umask 022
cat > "$CWA_CONF" <<EOF
{
  "agent": { "run_as_user": "root" },
  "logs": {
    "logs_collected": {
      "journald": {
        "collect_list": [
          {
            "log_group_name": "${LOG_GROUP}",
            "log_stream_name": "{instance_id}/parent",
            "units": ["utexo-parent@*"],
            "retention_in_days": ${RETENTION_DAYS}
          },
          {
            "log_group_name": "${LOG_GROUP}",
            "log_stream_name": "{instance_id}/enclave",
            "units": ["utexo-enclave@*"],
            "retention_in_days": ${RETENTION_DAYS}
          },
          {
            "log_group_name": "${LOG_GROUP}",
            "log_stream_name": "{instance_id}/nitro",
            "units": ["nitro-enclaves-allocator", "vsock-proxy-*"],
            "retention_in_days": ${RETENTION_DAYS}
          }
        ]
      }
    }
  }
}
EOF

# --- 3. load config + (re)start the agent ----------------------------------
# `fetch-config -s` appends this config and starts/reloads the agent. The
# systemd unit `amazon-cloudwatch-agent` is enabled by the package (survives
# reboot). `-a append-config` keeps any pre-existing agent config intact.
log "applying config via amazon-cloudwatch-agent-ctl (append + start)"
"$CWA_CTL" -a append-config -m ec2 -s -c "file:$CWA_CONF"
systemctl enable amazon-cloudwatch-agent >/dev/null 2>&1 || true

# --- 4. self-test ----------------------------------------------------------
sleep 3
log "agent status:"
"$CWA_CTL" -a status -m ec2 2>/dev/null | grep -E '"status"|"version"|"starttime"' || true

# Confirm the target units actually exist on this host (so we know the selector
# matches something). Non-fatal: a requester with fewer CIDs is still valid.
FOUND=$(systemctl list-units --type=service --all --no-legend \
          'utexo-parent@*' 'utexo-enclave@*' 'nitro-enclaves-allocator.service' 'vsock-proxy-*' 2>/dev/null \
          | awk '{print $1}' | paste -sd' ' -)
log "matched units on this host: ${FOUND:-<none — check unit names>}"

# Optional (needs the IAM write policy above): confirm the stream landed.
if command -v aws >/dev/null 2>&1; then
  log "checking CloudWatch for streams under $LOG_GROUP (needs logs:DescribeLogStreams)"
  aws logs describe-log-streams --log-group-name "$LOG_GROUP" \
      --order-by LastEventTime --descending --max-items 5 --region "$REGION" \
      --query 'logStreams[].logStreamName' --output text 2>&1 \
    | sed 's/^/[host-prep-obs] stream: /' || \
    log "NOTE: describe-log-streams failed — attach utexo-stage-enclave-hosts-logs-write to the instance role, then re-run."
fi

log "host-prep-observability DONE — parents/enclave/nitro journald -> $LOG_GROUP"
