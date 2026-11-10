#!/usr/bin/env bash
# Launch the parent gRPC adapter from the cluster dir, used by utexo-parent@.service.
# The parent binary reads its settings (GRPC_*, SIGNED_RESPONSE_*, HEALTH_*,
# USE_VSOCK, ENCLAVE_VSOCK_*, HEADER_*) from the per-CID EnvironmentFile. A
# setting that the file omits takes its default.
set -uo pipefail

cd "${CLUSTER_DIR:?CLUSTER_DIR env required (set in /etc/utexo/parent-<cid>.env)}"
exec ./utexo-bridge-parent
