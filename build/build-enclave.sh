#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building UTEXO Bridge Enclave ==="

# Prerequisites
command -v docker &>/dev/null || { echo "Error: docker not found"; exit 1; }
command -v nitro-cli &>/dev/null || { echo "Error: nitro-cli not found (run on Nitro-enabled EC2)"; exit 1; }

# Build Docker image
echo "Building Docker image..."
docker build -f "$SCRIPT_DIR/Dockerfile.enclave" -t utexo-bridge-enclave:latest "$PROJECT_ROOT"

# Build EIF
echo "Building EIF..."
nitro-cli build-enclave \
    --docker-uri utexo-bridge-enclave:latest \
    --output-file "$SCRIPT_DIR/utexo-bridge-enclave.eif"

# Extract and display PCRs
echo "Extracting PCRs..."
PCR_OUTPUT=$(nitro-cli describe-eif --eif-path "$SCRIPT_DIR/utexo-bridge-enclave.eif")
echo "$PCR_OUTPUT" | jq '{PCR0: .Measurements.PCR0, PCR1: .Measurements.PCR1, PCR2: .Measurements.PCR2}'

echo ""
echo "=== Build Complete ==="
echo "EIF: $SCRIPT_DIR/utexo-bridge-enclave.eif"
echo ""
echo "To run (production, KMS attestation works):"
echo "  nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 --eif-path $SCRIPT_DIR/utexo-bridge-enclave.eif"
echo ""
echo "To run (debug, with console output — PCR0/1/2 are zeroed, KMS attestation disabled):"
echo "  nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 --eif-path $SCRIPT_DIR/utexo-bridge-enclave.eif --debug-mode"
echo ""
echo "To read enclave console output:"
echo "  nitro-cli console --enclave-id \$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')"
