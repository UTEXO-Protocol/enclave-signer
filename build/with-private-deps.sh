#!/bin/sh
# Run Cargo with private dependency credentials, without persisting credentials
# or Git/SSH config in a builder layer. PRIVATE_DEPS_DIR is outside the checkout.
# federated_key (deploy key) reads the parent's proto via the
# github-federated-signer SSH alias. The enclave workspace has no private dependency.
set -eu

scope=${1:?usage: with-private-deps.sh parent command [args...]}
shift
case "$scope" in parent) ;; *) echo "Invalid dependency scope: $scope" >&2; exit 2 ;; esac
[ "$#" -gt 0 ] || { echo "Missing build command" >&2; exit 2; }
PRIVATE_DEPS_DIR=${PRIVATE_DEPS_DIR:-/run/secrets}
export PRIVATE_DEPS_DIR
[ -s "$PRIVATE_DEPS_DIR/federated_key" ] || {
    echo "Missing private dependency secret: federated_key (read access to UTEXO-Protocol/federated-signer-proto)" >&2
    exit 1
}
umask 077
auth_dir=$(mktemp -d)
trap 'rm -rf "$auth_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export CARGO_NET_GIT_FETCH_WITH_CLI=true
export GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_GLOBAL="$auth_dir/gitconfig"
: > "$GIT_CONFIG_GLOBAL"

# IdentitiesOnly avoids GitHub accepting another repo's deploy key first.
cat >> "$auth_dir/ssh_config" <<EOF
Host github-federated-signer
    HostName github.com
    User git
    IdentityFile "$PRIVATE_DEPS_DIR/federated_key"
    IdentitiesOnly yes
    IdentityAgent none
EOF
ssh-keyscan github.com > "$auth_dir/known_hosts" 2>/dev/null
[ -s "$auth_dir/known_hosts" ] || { echo "Could not obtain GitHub SSH host keys" >&2; exit 1; }
export GIT_SSH_COMMAND="ssh -F '$auth_dir/ssh_config' -o UserKnownHostsFile='$auth_dir/known_hosts' -o StrictHostKeyChecking=yes -o BatchMode=yes"

"$@"
