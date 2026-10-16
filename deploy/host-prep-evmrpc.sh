#!/usr/bin/env bash
# Host-prep for the enclave evm-rpc egress path (run as root, e.g. via SSM).
#
# Stands up, idempotently and reboot-safe, the host side of the in-enclave EVM
# FundsIn verification (evm-rpc feature):
#
#   enclave https://<EVM_RPC_HOST> via 127.0.0.1:<EVM_RPC_TLS_PORT> (TLS ends in the enclave)
#     -> in-enclave vsock forwarder -> vsock port 8002
#     -> [this host] vsock-proxy-evmrpc.service  (raw Vsock<->TCP, ciphertext)
#     -> <EVM_RPC_HOST>:<EVM_RPC_TLS_PORT>
#
# utexo-enclave@.service reads the same env file and passes the host and port
# to the enclave at launch.
#
# Usage (root):
#   EVM_RPC_HOST=<rpc host> [EVM_RPC_TLS_PORT=443] [EVM_RPC_PATH_FILE=<file>] bash host-prep-evmrpc.sh
#   EVM_RPC_CHECK_ONLY=1 performs only the authenticated read-only RPC check.
#   EVM_RPC_TLS_CA_DER_FILE pins the CA for the check, matching SetEndpoints.
set -euo pipefail

HOST="${EVM_RPC_HOST:?EVM_RPC_HOST required (the host name the enclave gets at launch)}"
PORT="${EVM_RPC_TLS_PORT:-443}"

log(){ echo "[host-prep-evmrpc $(date -u +%H:%M:%S)] $*"; }

# The enclave applies the same rules at launch.
if [ "${#HOST}" -gt 253 ] || ! [[ "$HOST" =~ ^[A-Za-z0-9-]([A-Za-z0-9.-]*[A-Za-z0-9-])?$ ]]; then
  log "ERROR: EVM_RPC_HOST is not a host name"; exit 1
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  log "ERROR: EVM_RPC_TLS_PORT is not 1-65535"; exit 1
fi

# Validate credentials before changing services. CHECK_ONLY performs no host setup.
log "self-test: authenticated eth_chainId and eth_blockNumber (RPC path redacted)"
EVM_RPC_HOST="$HOST" EVM_RPC_TLS_PORT="$PORT" python3 - <<'PYRPC'
import json, os, re, ssl, sys, urllib.request, urllib.error

def fail(message):
    print("ERROR: " + message, file=sys.stderr)
    sys.exit(1)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

try:
    path_file = os.environ.get("EVM_RPC_PATH_FILE")
    path = "/"
    if path_file:
        with open(path_file, encoding="ascii") as f:
            path = f.read(2051).rstrip("\r\n")
    if (len(path) > 2048 or not re.fullmatch(r"/[A-Za-z0-9/._~-]*", path)
            or path.startswith("//") or any(s in (".", "..") for s in path.split("/"))):
        fail("invalid RPC path file (contents redacted)")
    ca = os.environ.get("EVM_RPC_TLS_CA_DER_FILE")
    if ca:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with open(ca, "rb") as f:
            context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(f.read()))
    else:
        context = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context), NoRedirect())
    url = "https://{}:{}{}".format(os.environ["EVM_RPC_HOST"], os.environ["EVM_RPC_TLS_PORT"], path)
    results = {}
    for method in ("eth_chainId", "eth_blockNumber"):
        body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=[])).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type":"application/json"})
        with opener.open(req, timeout=10) as response:
            data = json.loads(response.read(65536))
        if "error" in data or not isinstance(data.get("result"), str):
            fail(method + " returned an RPC error (details redacted)")
        results[method] = int(data["result"], 16)
    expected = int(os.environ.get("EVM_CHAIN_ID", "42161"))
    if results["eth_chainId"] != expected:
        fail("RPC chain ID does not match EVM_CHAIN_ID")
    print("OK: chain {}, block {}".format(expected, results["eth_blockNumber"]))
except urllib.error.HTTPError as e:
    fail("RPC HTTP status {} (URL and response redacted)".format(e.code))
except Exception:
    fail("RPC check failed: check TLS, connectivity and credential file (details redacted)")
PYRPC
[ "${EVM_RPC_CHECK_ONLY:-0}" = "1" ] && exit 0

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

# --- 4. status summary -------------------------------------------------------
systemctl --no-pager --lines=0 status vsock-proxy-evmrpc.service 2>/dev/null | grep -E 'Active:|Loaded:' || true
log "host-prep-evmrpc DONE"
