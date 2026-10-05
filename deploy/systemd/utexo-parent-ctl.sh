#!/usr/bin/env bash
# Launch the parent gRPC adapter from the cluster dir, used by utexo-parent@.service.
# All tunables (GRPC_*, HEALTH_*, USE_VSOCK, ENCLAVE_VSOCK_*, HEADER_ELECTRUM_URL)
# come from the per-CID EnvironmentFile and are read by the parent binary itself.
set -uo pipefail

cd "${CLUSTER_DIR:?CLUSTER_DIR env required (set in /etc/utexo/parent-<cid>.env)}"
exec ./utexo-bridge-parent
