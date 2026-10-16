#!/bin/sh
# CI only: adds the rgb-lib-bfa deploy key to SSH so Cargo
# (via CARGO_NET_GIT_FETCH_WITH_CLI=true) can fetch the private
# UTEXO-Protocol/rgb-lib-bfa mirror via the github-rgb-lib SSH alias.
set -eu
: "${RGB_LIB_BFA_DEPLOY_KEY:?Missing RGB_LIB_BFA_DEPLOY_KEY}"
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
