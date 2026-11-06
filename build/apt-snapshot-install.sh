#!/bin/sh
# Fetch from the caller's signed, pinned APT sources. Mount this helper only for
# the installation RUN; it is not needed in the final enclave image.
set -eu

if [ "$#" -eq 0 ]; then
    echo 'Usage: apt-snapshot-install.sh PACKAGE...' >&2
    exit 2
fi

retry_fetch() {
    attempt=1
    delay=30
    while :; do
        if "$@"; then
            return 0
        else
            status=$?
        fi
        # APT reports acquisition failures as 100. Do not retry a killed process
        # or hide persistent errors: the fourth failed attempt aborts the build.
        if [ "$status" -ne 100 ] || [ "$attempt" -ge 4 ]; then
            return "$status"
        fi
        echo "APT fetch attempt $attempt/4 failed; retrying in ${delay}s" >&2
        sleep "$delay"
        attempt=$((attempt + 1))
        delay=$((delay * 2))
    done
}

fetch() {
    # APT's delayed-item retries can spin after snapshot 503 responses. Retry
    # the command outside APT instead, with a bounded count and a real pause.
    retry_fetch apt-get \
        -o Acquire::Retries=0 \
        -o Acquire::http::Timeout=60 \
        -o Acquire::https::Timeout=60 \
        -o Acquire::http::Pipeline-Depth=0 \
        -o Acquire::https::Pipeline-Depth=0 \
        "$@"
}

# Do not accept a partially refreshed index. Retain downloaded archives across
# retries, then run package installation once, with networking disabled in APT.
fetch -o APT::Update::Error-Mode=any update
fetch install -y --no-install-recommends --download-only "$@"
apt-get install -y --no-install-recommends --no-download "$@"
