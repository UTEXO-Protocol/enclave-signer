#!/bin/sh
# Materialize CI secrets outside the Docker context. Never print their values.
set -eu
: "${PRIVATE_DEPS_DIR:?Set PRIVATE_DEPS_DIR to a directory outside the checkout}"
: "${RGB_CONSIGNMENT_PARSER_DEPLOY_KEY:?Missing RGB_CONSIGNMENT_PARSER_DEPLOY_KEY}"
: "${RGB_CONSENSUS_BFA_DEPLOY_KEY:?Missing RGB_CONSENSUS_BFA_DEPLOY_KEY}"
: "${RGB_OPS_BFA_DEPLOY_KEY:?Missing RGB_OPS_BFA_DEPLOY_KEY}"
: "${RGB_SCHEMAS_BFA_DEPLOY_KEY:?Missing RGB_SCHEMAS_BFA_DEPLOY_KEY}"
: "${FEDERATED_SIGNER_PROTO_DEPLOY_KEY:?Missing FEDERATED_SIGNER_PROTO_DEPLOY_KEY}"
umask 077
mkdir -p "$PRIVATE_DEPS_DIR"
chmod 700 "$PRIVATE_DEPS_DIR"
printf '%s\n' "$RGB_CONSIGNMENT_PARSER_DEPLOY_KEY" > "$PRIVATE_DEPS_DIR/consignment_key"
printf '%s\n' "$RGB_CONSENSUS_BFA_DEPLOY_KEY" > "$PRIVATE_DEPS_DIR/consensus_key"
printf '%s\n' "$RGB_OPS_BFA_DEPLOY_KEY" > "$PRIVATE_DEPS_DIR/ops_key"
printf '%s\n' "$RGB_SCHEMAS_BFA_DEPLOY_KEY" > "$PRIVATE_DEPS_DIR/schemas_key"
printf '%s\n' "$FEDERATED_SIGNER_PROTO_DEPLOY_KEY" > "$PRIVATE_DEPS_DIR/federated_key"
