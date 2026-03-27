#!/bin/bash
# =============================================================================
# Deploy utexo-bridge-signer to EC2 Nitro instance
# =============================================================================
# Copies the full repo to the EC2 instance, builds the enclave EIF,
# and optionally runs it.
#
# EC2 instance: ubuntu@18.219.168.199
# Remote path:  ~/utexo-bridge-signer
#
# If you cannot SSH in, your public key needs to be added to the instance.
# Contact @Renat Skitsan to get access.
#
# Usage:
#   ./deploy-to-ec2.sh                          # default: ubuntu@18.219.168.199
#   ./deploy-to-ec2.sh --host ubuntu@1.2.3.4    # override host
#   ./deploy-to-ec2.sh --key ~/.ssh/my-key.pem  # specify SSH key
#
# What it does:
#   1. rsync the project to ~/utexo-bridge-signer on the remote
#   2. Print follow-up commands for building/running the enclave + smoke tests
# =============================================================================
set -euo pipefail

TARGET="ubuntu@18.219.168.199"
SSH_KEY_ARG=""

while [ $# -gt 0 ]; do
    case $1 in
        --host) TARGET="$2"; shift 2 ;;
        --key)  SSH_KEY_ARG="-i $2"; shift 2 ;;
        *)      echo "Unknown arg: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REMOTE_DIR="~/utexo-bridge-signer"

echo "=== Deploying utexo-bridge-signer to $TARGET ==="
echo "  Local:  $PROJECT_ROOT"
echo "  Remote: $REMOTE_DIR"
echo ""

# Sync project (exclude build artifacts)
echo "--- rsync project to remote ---"
rsync -avz --progress \
    --exclude 'target/' \
    --exclude '.git/' \
    --exclude '*.eif' \
    -e "ssh $SSH_KEY_ARG" \
    "$PROJECT_ROOT/" "$TARGET:$REMOTE_DIR/"

echo ""
echo "=== Upload complete ==="
echo ""
echo "Now SSH in and run these commands:"
echo ""
echo "  ssh $SSH_KEY_ARG $TARGET"
echo ""
echo "# --- Build & run enclave ---"
echo "  cd $REMOTE_DIR"
echo "  ./build/build-enclave.sh"
echo ""
echo "# --- Terminate any running enclave ---"
echo "  nitro-cli terminate-enclave --all"
echo ""
echo "# --- Run enclave (debug mode, console visible) ---"
echo "  nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 \\"
echo "      --eif-path build/utexo-bridge-enclave.eif --debug-mode"
echo ""
echo "# --- Watch enclave console ---"
echo "  nitro-cli console --enclave-id \$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')"
echo ""
echo "# --- Build parent CLI (on host, not in enclave) ---"
echo "  cargo build --release -p utexo-bridge-parent --features vsock"
echo ""
echo "# --- Run smoke tests (vsock) ---"
echo "  PARENT_BIN=./target/release/utexo-bridge-parent ./build/smoke-test.sh --vsock"
echo ""
echo "# --- Or run individual commands ---"
echo "  ./target/release/utexo-bridge-parent --addr vsock://16:5000 init"
echo "  ./target/release/utexo-bridge-parent --addr vsock://16:5000 get-keys"
echo "  ./target/release/utexo-bridge-parent --addr vsock://16:5000 sign-raw-message --message 48656c6c6f"
