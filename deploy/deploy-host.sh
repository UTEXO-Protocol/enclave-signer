#!/usr/bin/env bash
# Cold deployment of explicitly configured Mint/Burn instances.
# Default is preflight only. --apply restarts selected enclaves and loses volatile keys.
# Requires the whole deploy/ directory from the reviewed release checkout.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/deploy_host.py" "$@"
