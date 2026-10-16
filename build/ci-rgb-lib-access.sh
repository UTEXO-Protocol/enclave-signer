#!/bin/sh
# CI only: lets system Git read the private UTEXO-Protocol/rgb-lib-bfa mirror
# with RGB_LIB_BFA_TOKEN. A credential helper reads the token from a file under
# RUNNER_TEMP, so it is never in a URL, a config value or a log.
set -eu
: "${RGB_LIB_BFA_TOKEN:?Missing RGB_LIB_BFA_TOKEN}"
: "${RUNNER_TEMP:?Set RUNNER_TEMP to a directory outside the checkout}"
umask 077
helper="$RUNNER_TEMP/rgb-lib-bfa-credential"
printf '%s' "$RGB_LIB_BFA_TOKEN" > "$helper.token"
cat > "$helper" <<HELPER
#!/bin/sh
[ "\$1" = get ] || exit 0
echo username=x-access-token
echo "password=\$(cat '$helper.token')"
HELPER
chmod 700 "$helper"
git config --global credential.https://github.com.helper "$helper"
