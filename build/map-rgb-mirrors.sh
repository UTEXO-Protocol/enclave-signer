#!/bin/sh
# Maps the private RGB protocol crates of the [patch.crates-io] in Cargo.toml
# (ssh://git@github.com/rgb-tools-devs/<repo>.git) to our UTEXO-Protocol/<repo>-s-bfa
# mirrors in the global git config ($GIT_CONFIG_GLOBAL when set). A credential
# helper reads the token from a file, so it is never in a URL cargo can print.
# Usage: map-rgb-mirrors.sh <token-file> <helper-path>
set -eu

token_file=${1:?usage: map-rgb-mirrors.sh <token-file> <helper-path>}
helper=${2:?usage: map-rgb-mirrors.sh <token-file> <helper-path>}
[ -s "$token_file" ] || {
    echo "Missing RGB protocol crate mirror token: $token_file is missing or empty" >&2
    exit 1
}
# The helper quotes the path in single quotes.
case "$token_file" in *"'"*) echo "Token path must not contain a single quote: $token_file" >&2; exit 2 ;; esac

cat > "$helper" <<EOF
#!/bin/sh
[ "\$1" = get ] || exit 0
printf 'username=x-access-token\npassword=%s\n' "\$(cat '$token_file')"
EOF
chmod 700 "$helper"

for repo in rgb-consensus rgb-ops rgb-api rgb-schemas; do
    mirror="https://github.com/UTEXO-Protocol/${repo}-s-bfa.git"
    git config --global --add "url.$mirror.insteadOf" "ssh://git@github.com/rgb-tools-devs/${repo}.git"
    # The empty helper drops any system helper for the mirror.
    git config --global --add "credential.$mirror.helper" ""
    git config --global --add "credential.$mirror.helper" "$helper"
done
