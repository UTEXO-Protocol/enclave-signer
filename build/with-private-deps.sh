#!/bin/sh
# Run Cargo with private dependency credentials, without persisting credentials
# or Git/SSH config in a builder layer. PRIVATE_DEPS_DIR is outside the checkout.
# Both workspaces fetch rgb-lib from UTEXO-Protocol/rgb-lib-bfa with github_token
# (a deploy key reads one repo only). The parent also fetches
# federated-signer-proto, with federated_key or else with the same token.
set -eu

scope=${1:?usage: with-private-deps.sh parent|enclave command [args...]}
shift
case "$scope" in parent|enclave) ;; *) echo "Invalid dependency scope: $scope" >&2; exit 2 ;; esac
[ "$#" -gt 0 ] || { echo "Missing build command" >&2; exit 2; }
PRIVATE_DEPS_DIR=${PRIVATE_DEPS_DIR:-/run/secrets}
export PRIVATE_DEPS_DIR
[ -s "$PRIVATE_DEPS_DIR/github_token" ] || {
    echo "Missing private dependency secret: github_token (read access to UTEXO-Protocol/rgb-lib-bfa)" >&2
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

# The token is read by askpass, never interpolated into a URL or config.
git config --global --add url."https://x-access-token@github.com/UTEXO-Protocol/".insteadOf "https://github.com/UTEXO-Protocol/"
cat > "$auth_dir/askpass" <<'ASKPASS'
#!/bin/sh
cat "$PRIVATE_DEPS_DIR/github_token"
ASKPASS
chmod 700 "$auth_dir/askpass"
export GIT_ASKPASS="$auth_dir/askpass"

if [ "$scope" = parent ] && [ -s "$PRIVATE_DEPS_DIR/federated_key" ]; then
    # IdentitiesOnly avoids GitHub accepting another deploy key first.
    cat > "$auth_dir/ssh_config" <<EOF
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
elif [ "$scope" = parent ]; then
    # Without the deploy key, the token also reads the proto: rewrite its SSH alias.
    git config --global --add url."https://x-access-token@github.com/UTEXO-Protocol/".insteadOf "ssh://git@github-federated-signer/UTEXO-Protocol/"
fi

"$@"
