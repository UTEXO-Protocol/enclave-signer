#!/usr/bin/env bash
# Launch the parent gRPC adapter from the cluster dir, used by utexo-parent@.service.
# All tunables (GRPC_HOST/PORT, USE_VSOCK, ENCLAVE_VSOCK_CID/PORT) come from the
# per-CID EnvironmentFile and are read by the parent binary itself.
set -uo pipefail

cd "${CLUSTER_DIR:?CLUSTER_DIR env required (set in /etc/utexo/parent-<cid>.env)}"
exec ./utexo-bridge-parent
