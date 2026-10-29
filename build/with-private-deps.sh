#!/bin/sh
# Run Cargo with private dependency credentials, without persisting credentials
# or Git/SSH config in a builder layer. PRIVATE_DEPS_DIR is outside the checkout.
# lib_key (deploy key) reads UTEXO-Protocol/rgb-lib-bfa for both workspaces via
# the github-rgb-lib SSH alias. rgb_deps_token reads our mirrors of the RGB
# protocol crates (map-rgb-mirrors.sh). The parent also uses federated_key for the proto.
set -eu

scope=${1:?usage: with-private-deps.sh enclave|parent command [args...]}
shift
case "$scope" in enclave|parent) ;; *) echo "Invalid dependency scope: $scope" >&2; exit 2 ;; esac
[ "$#" -gt 0 ] || { echo "Missing build command" >&2; exit 2; }
PRIVATE_DEPS_DIR=${PRIVATE_DEPS_DIR:-/run/secrets}
export PRIVATE_DEPS_DIR
[ -s "$PRIVATE_DEPS_DIR/lib_key" ] || {
    echo "Missing private dependency secret: lib_key (read access to UTEXO-Protocol/rgb-lib-bfa)" >&2
    exit 1
}
[ -s "$PRIVATE_DEPS_DIR/rgb_deps_token" ] || {
    echo "Missing private dependency secret: rgb_deps_token (read access to the UTEXO-Protocol/<repo>-s-bfa mirrors of the RGB protocol crates; RGB_PRIVATE_DEPS_TOKEN in CI)" >&2
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
sh "$(dirname "$0")/map-rgb-mirrors.sh" "$PRIVATE_DEPS_DIR/rgb_deps_token" "$auth_dir/rgb-deps-credential"

# IdentitiesOnly avoids GitHub accepting another repo's deploy key first.
cat >> "$auth_dir/ssh_config" <<EOF
Host github-rgb-lib
    HostName github.com
    User git
    IdentityFile "$PRIVATE_DEPS_DIR/lib_key"
    IdentitiesOnly yes
    IdentityAgent none
EOF
if [ "$scope" = parent ] && [ -s "$PRIVATE_DEPS_DIR/federated_key" ]; then
    cat >> "$auth_dir/ssh_config" <<EOF
Host github-federated-signer
    HostName github.com
    User git
    IdentityFile "$PRIVATE_DEPS_DIR/federated_key"
    IdentitiesOnly yes
    IdentityAgent none
EOF
fi
ssh-keyscan github.com > "$auth_dir/known_hosts" 2>/dev/null
[ -s "$auth_dir/known_hosts" ] || { echo "Could not obtain GitHub SSH host keys" >&2; exit 1; }
export GIT_SSH_COMMAND="ssh -F '$auth_dir/ssh_config' -o UserKnownHostsFile='$auth_dir/known_hosts' -o StrictHostKeyChecking=yes -o BatchMode=yes"

"$@"
