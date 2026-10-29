#!/bin/sh
# CI only: adds the rgb-lib-bfa deploy key to SSH so Cargo
# (via CARGO_NET_GIT_FETCH_WITH_CLI=true) can fetch the private
# UTEXO-Protocol/rgb-lib-bfa mirror via the github-rgb-lib SSH alias, and maps
# the RGB protocol crates rgb-lib pins to our mirrors (map-rgb-mirrors.sh).
set -eu
: "${RGB_LIB_BFA_DEPLOY_KEY:?Missing RGB_LIB_BFA_DEPLOY_KEY}"
: "${RGB_PRIVATE_DEPS_TOKEN:?Missing RGB_PRIVATE_DEPS_TOKEN}"
mkdir -p ~/.ssh && chmod 700 ~/.ssh
ssh-keyscan -H github.com >> ~/.ssh/known_hosts
printf '%s\n' "$RGB_LIB_BFA_DEPLOY_KEY" > ~/.ssh/key_lib
chmod 600 ~/.ssh/key_lib
cat >> ~/.ssh/config << 'SSHCONF'
Host github-rgb-lib
  HostName github.com
  User git
  IdentityFile ~/.ssh/key_lib
  IdentitiesOnly yes
SSHCONF
chmod 600 ~/.ssh/config

deps_dir="$HOME/.rgb-private-deps"
(umask 077 && mkdir -p "$deps_dir" && printf '%s\n' "$RGB_PRIVATE_DEPS_TOKEN" > "$deps_dir/token")
sh "$(dirname "$0")/map-rgb-mirrors.sh" "$deps_dir/token" "$deps_dir/credential"
