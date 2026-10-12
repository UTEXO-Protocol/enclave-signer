#!/bin/sh
# Materialize CI secrets outside the Docker context. Never print their values.
# Only the parent needs one: the enclave has no private dependency.
set -eu
: "${PRIVATE_DEPS_DIR:?Set PRIVATE_DEPS_DIR to a directory outside the checkout}"
: "${FEDERATED_SIGNER_PROTO_DEPLOY_KEY:?Missing FEDERATED_SIGNER_PROTO_DEPLOY_KEY}"
umask 077
mkdir -p "$PRIVATE_DEPS_DIR"
chmod 700 "$PRIVATE_DEPS_DIR"
printf '%s\n' "$FEDERATED_SIGNER_PROTO_DEPLOY_KEY" > "$PRIVATE_DEPS_DIR/federated_key"
