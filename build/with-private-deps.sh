#!/bin/sh
# Run Cargo with private dependency credentials, without persisting credentials
# or Git/SSH config in a builder layer. PRIVATE_DEPS_DIR is outside the checkout.
set -eu

scope=${1:?usage: with-private-deps.sh enclave|parent command [args...]}
shift
case "$scope" in enclave|parent) ;; *) echo "Invalid dependency scope: $scope" >&2; exit 2 ;; esac
[ "$#" -gt 0 ] || { echo "Missing build command" >&2; exit 2; }
PRIVATE_DEPS_DIR=${PRIVATE_DEPS_DIR:-/run/secrets}
export PRIVATE_DEPS_DIR
umask 077
auth_dir=$(mktemp -d)
trap 'rm -rf "$auth_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export CARGO_NET_GIT_FETCH_WITH_CLI=true
export GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_GLOBAL="$auth_dir/gitconfig"
: > "$GIT_CONFIG_GLOBAL"

if [ -s "$PRIVATE_DEPS_DIR/github_token" ]; then
    # Rewrite the actual Cargo SSH aliases, as well as older HTTPS URLs.
    # The token is read by askpass, never interpolated into a URL or config.
    for alias in github-rgb-consignment github-rgb-consensus github-rgb-ops github-rgb-schemas github-federated-signer; do
        git config --global --add url."https://x-access-token@github.com/UTEXO-Protocol/".insteadOf "ssh://git@$alias/UTEXO-Protocol/"
    done
    git config --global --add url."https://x-access-token@github.com/UTEXO-Protocol/".insteadOf "https://github.com/UTEXO-Protocol/"
    cat > "$auth_dir/askpass" <<'ASKPASS'
#!/bin/sh
cat "$PRIVATE_DEPS_DIR/github_token"
ASKPASS
    chmod 700 "$auth_dir/askpass"
    export GIT_ASKPASS="$auth_dir/askpass"
else
    # IdentitiesOnly avoids GitHub accepting another repo's deploy key first.
    for pair in github-rgb-consignment:consignment_key github-rgb-consensus:consensus_key github-rgb-ops:ops_key github-rgb-schemas:schemas_key github-federated-signer:federated_key; do
        alias=${pair%:*}
        key=${pair#*:}
        if [ "$key" = federated_key ] && [ "$scope" = enclave ]; then continue; fi
        [ -s "$PRIVATE_DEPS_DIR/$key" ] || {
            echo "Missing private dependency secret: $key (or supply github_token)" >&2
            exit 1
        }
        cat >> "$auth_dir/ssh_config" <<EOF
Host $alias
    HostName github.com
    User git
    IdentityFile "$PRIVATE_DEPS_DIR/$key"
    IdentitiesOnly yes
    IdentityAgent none
EOF
    done
    ssh-keyscan github.com > "$auth_dir/known_hosts" 2>/dev/null
    [ -s "$auth_dir/known_hosts" ] || { echo "Could not obtain GitHub SSH host keys" >&2; exit 1; }
    export GIT_SSH_COMMAND="ssh -F '$auth_dir/ssh_config' -o UserKnownHostsFile='$auth_dir/known_hosts' -o StrictHostKeyChecking=yes -o BatchMode=yes"
fi

"$@"
