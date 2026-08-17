#!/usr/bin/env bash
# Host-prep for the enclave evm-rpc egress path (run as root, e.g. via SSM).
#
# Stands up, idempotently and reboot-safe, the host side of the in-enclave EVM
# FundsIn verification (evm-rpc feature, #60):
#
#   enclave http://127.0.0.1:3444  (alloy RootProvider::new_http, plaintext, no key)
#     -> in-enclave vsock forwarder -> vsock port 8002
#     -> [this host] vsock-proxy-evmrpc.service  (raw Vsock<->TCP)
#     -> 127.0.0.1:8547  nginx TLS/key shim (adds TLS + /v2/<key> + Host)
#     -> https://<alchemy-arbitrum-one>/v2/<key>   (chain 42161)
#
# Unlike vsock-proxy-electrs (single raw hop, because electrs is reached as
# `ssl://` so the enclave does TLS itself), evm-rpc is `http://` with no key, so
# TLS termination + the API-key path MUST be added host-side by nginx.
#
# SECURITY: the Alchemy API key is read on THIS host from an SSM SecureString and
# written only into a 0600 root:root nginx conf. It is never placed in the repo,
# in the SSM command text, or printed. Pass the PARAM NAME (not the secret) via env.
#
# Usage (root):
#   EVM_RPC_UPSTREAM_PARAM=/utexo/stage/enclave/evm-rpc-upstream \
#   AWS_REGION=eu-central-1 bash host-prep-evmrpc.sh
#
# The SSM param value must be the FULL upstream URL incl. key, e.g.
#   https://arb-mainnet.g.alchemy.com/v2/<key>
set -euo pipefail

PARAM="${EVM_RPC_UPSTREAM_PARAM:?EVM_RPC_UPSTREAM_PARAM required (SSM SecureString name holding the full https://host/v2/<key> URL)}"
REGION="${AWS_REGION:-eu-central-1}"
LOCAL_PORT="${LOCAL_PORT:-8547}"   # nginx loopback listen (== vsock-proxy remote)
VSOCK_PORT="${VSOCK_PORT:-8002}"   # must match enclave EVM_RPC_VSOCK_PORT default

log(){ echo "[host-prep-evmrpc $(date -u +%H:%M:%S)] $*"; }

# --- 1. fetch upstream URL from SSM (secret; never echoed) ------------------
log "reading upstream URL from SSM param $PARAM"
UPSTREAM="$(aws ssm get-parameter --name "$PARAM" --with-decryption \
             --query Parameter.Value --output text --region "$REGION")"
case "$UPSTREAM" in
  https://*) : ;;
  *) log "ERROR: upstream must be an https:// URL"; exit 1 ;;
esac
NOSCHEME="${UPSTREAM#https://}"          # host/v2/<key>
UP_HOST="${NOSCHEME%%/*}"                # host only (SNI + Host header)
[ -n "$UP_HOST" ] || { log "ERROR: could not parse upstream host"; exit 1; }
log "upstream host parsed: $UP_HOST (key redacted)"

# --- 2. install nginx if absent --------------------------------------------
if ! command -v nginx >/dev/null 2>&1; then
  log "installing nginx"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nginx
else
  log "nginx already present ($(nginx -v 2>&1))"
fi
# Drop the default :80 welcome site to keep the host minimal (we only serve loopback).
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# --- 3. render nginx shim (0600; secret lives only here) -------------------
log "writing /etc/nginx/conf.d/evm-rpc.conf"
umask 077
cat > /etc/nginx/conf.d/evm-rpc.conf <<EOF
# Managed by deploy/host-prep-evmrpc.sh — enclave evm-rpc loopback TLS/key shim.
# Enclave -> vsock 8002 -> 127.0.0.1:${LOCAL_PORT} (here) -> https://${UP_HOST}/v2/<key>.
server {
    listen 127.0.0.1:${LOCAL_PORT};
    server_name _;
    client_max_body_size 64k;

    location / {
        proxy_pass https://${NOSCHEME};
        proxy_ssl_server_name on;
        proxy_set_header Host ${UP_HOST};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_send_timeout 15s;
        proxy_read_timeout 20s;
    }
}
EOF
chmod 600 /etc/nginx/conf.d/evm-rpc.conf
umask 022

log "nginx -t"
nginx -t
systemctl enable --now nginx >/dev/null 2>&1 || true
systemctl reload nginx || systemctl restart nginx

# --- 4. vsock-proxy allowlist + systemd unit -------------------------------
log "writing /etc/nitro_enclaves/vsock-proxy-evmrpc.yaml"
install -d /etc/nitro_enclaves
cat > /etc/nitro_enclaves/vsock-proxy-evmrpc.yaml <<EOF
allowlist:
- {address: 127.0.0.1, port: ${LOCAL_PORT}}
EOF

log "writing /etc/systemd/system/vsock-proxy-evmrpc.service"
cat > /etc/systemd/system/vsock-proxy-evmrpc.service <<EOF
[Unit]
Description=vsock-proxy for enclave EVM RPC (evm-rpc FundsIn verify: vsock ${VSOCK_PORT} -> 127.0.0.1:${LOCAL_PORT} nginx -> Alchemy Arbitrum One)
After=network-online.target nitro-enclaves-allocator.service nginx.service
Wants=network-online.target
Requires=nginx.service

[Service]
Type=simple
ExecStart=/usr/bin/vsock-proxy ${VSOCK_PORT} 127.0.0.1 ${LOCAL_PORT} --config /etc/nitro_enclaves/vsock-proxy-evmrpc.yaml
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vsock-proxy-evmrpc.service >/dev/null 2>&1 || true
systemctl restart vsock-proxy-evmrpc.service
sleep 1

# --- 5. self-test: through the local nginx shim (NOT vsock; that needs the enclave)
log "self-test: eth_chainId + eth_blockNumber via 127.0.0.1:${LOCAL_PORT}"
CHAIN=$(curl -s --max-time 10 "http://127.0.0.1:${LOCAL_PORT}/" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' | jq -r '.result // empty')
BLK=$(curl -s --max-time 10 "http://127.0.0.1:${LOCAL_PORT}/" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | jq -r '.result // empty')
log "eth_chainId=${CHAIN:-<none>}  eth_blockNumber=${BLK:-<none>}"
[ "$CHAIN" = "0xa4b1" ] || { log "ERROR: chainId != 0xa4b1 (Arbitrum One 42161) — wrong upstream?"; exit 1; }
[ -n "$BLK" ] || { log "ERROR: no block number — nginx->Alchemy path is broken"; exit 1; }
log "OK: evm-rpc host shim healthy (chain 42161, head $((BLK)))"

# --- 6. status summary ------------------------------------------------------
systemctl --no-pager --lines=0 status nginx vsock-proxy-evmrpc.service 2>/dev/null | grep -E 'Active:|Loaded:' || true
log "host-prep-evmrpc DONE"
