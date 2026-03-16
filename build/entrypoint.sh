#!/bin/bash
set -e

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

# Loopback (required inside enclave for socat proxies)
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set dev lo up 2>/dev/null || true

log "Starting utexo-bridge-enclave"
exec /app/utexo-bridge-enclave
