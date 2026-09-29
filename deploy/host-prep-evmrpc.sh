#!/usr/bin/env bash
# Host-prep for the enclave evm-rpc egress path (run as root, e.g. via SSM).
#
# Stands up, idempotently and reboot-safe, the host side of the in-enclave EVM
# FundsIn verification (evm-rpc feature):
#
#   enclave https://<EVM_RPC_HOST> via 127.0.0.1:3444 (TLS ends in the enclave)
#     -> in-enclave vsock forwarder -> vsock port 8002
#     -> [this host] vsock-proxy-evmrpc.service  (raw Vsock<->TCP, ciphertext)
#     -> <EVM_RPC_HOST>:<EVM_RPC_TLS_PORT>
#
# EVM_RPC_HOST must equal the value baked into the enclave image.
#
# Usage (root):
#   EVM_RPC_HOST=<rpc host> [EVM_RPC_TLS_PORT=443] bash host-prep-evmrpc.sh
set -euo pipefail

HOST="${EVM_RPC_HOST:?EVM_RPC_HOST required (the host name baked into the enclave image)}"
PORT="${EVM_RPC_TLS_PORT:-443}"

log(){ echo "[host-prep-evmrpc $(date -u +%H:%M:%S)] $*"; }

# The enclave applies the same rules at boot.
if [ "${#HOST}" -gt 253 ] || ! [[ "$HOST" =~ ^[A-Za-z0-9-]([A-Za-z0-9.-]*[A-Za-z0-9-])?$ ]]; then
  log "ERROR: EVM_RPC_HOST is not a host name"; exit 1
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  log "ERROR: EVM_RPC_TLS_PORT is not 1-65535"; exit 1
fi

# --- 1. vsock-proxy environment + allowlist ---------------------------------
install -d /etc/nitro_enclaves
log "writing /etc/nitro_enclaves/vsock-proxy-evmrpc.env"
cat > /etc/nitro_enclaves/vsock-proxy-evmrpc.env <<ENV
EVM_RPC_HOST=${HOST}
EVM_RPC_TLS_PORT=${PORT}
ENV
log "writing /etc/nitro_enclaves/vsock-proxy-evmrpc.yaml"
cat > /etc/nitro_enclaves/vsock-proxy-evmrpc.yaml <<YAML
allowlist:
- {address: ${HOST}, port: ${PORT}}
YAML

# --- 2. systemd unit ---------------------------------------------------------
log "writing /etc/systemd/system/vsock-proxy-evmrpc.service"
cat > /etc/systemd/system/vsock-proxy-evmrpc.service <<'UNIT'
[Unit]
Description=vsock-proxy for enclave EVM RPC (evm-rpc FundsIn verify: vsock 8002 -> EVM_RPC_HOST:EVM_RPC_TLS_PORT)
After=network-online.target nitro-enclaves-allocator.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/nitro_enclaves/vsock-proxy-evmrpc.env
ExecStart=/usr/bin/vsock-proxy 8002 ${EVM_RPC_HOST} ${EVM_RPC_TLS_PORT} --config /etc/nitro_enclaves/vsock-proxy-evmrpc.yaml
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now vsock-proxy-evmrpc.service >/dev/null 2>&1 || true
systemctl restart vsock-proxy-evmrpc.service
sleep 1

# --- 3. self-test: eth_chainId direct to the pinned endpoint ----------------
log "self-test: eth_chainId via https://${HOST}:${PORT}/"
CHAIN=$(curl -s --max-time 10 "https://${HOST}:${PORT}/" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' | jq -r '.result // empty')
[ "$CHAIN" = "0xa4b1" ] || { log "ERROR: chainId != 0xa4b1 (Arbitrum One 42161) — wrong EVM_RPC_HOST, or it does not serve JSON-RPC at /?"; exit 1; }
log "OK: EVM_RPC_HOST reachable (chain 42161)"

# --- 4. status summary -------------------------------------------------------
systemctl --no-pager --lines=0 status vsock-proxy-evmrpc.service 2>/dev/null | grep -E 'Active:|Loaded:' || true
log "host-prep-evmrpc DONE"
