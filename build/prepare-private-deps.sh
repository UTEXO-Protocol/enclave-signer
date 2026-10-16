#!/bin/sh
# Materialize CI secrets outside the Docker context. Never print their values.
# github_token reads the rgb-lib mirror (UTEXO-Protocol/rgb-lib-bfa) for both
# workspaces; federated_key reads the parent's proto.
set -eu
: "${PRIVATE_DEPS_DIR:?Set PRIVATE_DEPS_DIR to a directory outside the checkout}"
: "${FEDERATED_SIGNER_PROTO_DEPLOY_KEY:?Missing FEDERATED_SIGNER_PROTO_DEPLOY_KEY}"
: "${RGB_LIB_BFA_TOKEN:?Missing RGB_LIB_BFA_TOKEN}"
umask 077
mkdir -p "$PRIVATE_DEPS_DIR"
chmod 700 "$PRIVATE_DEPS_DIR"
printf '%s\n' "$FEDERATED_SIGNER_PROTO_DEPLOY_KEY" > "$PRIVATE_DEPS_DIR/federated_key"
printf '%s' "$RGB_LIB_BFA_TOKEN" > "$PRIVATE_DEPS_DIR/github_token"
