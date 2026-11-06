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

fetch_from_debian_cdn() (
    # Use only the already authenticated snapshot indexes. Never refresh from
    # the live CDN: that would allow the selected package versions to drift.
    plan=$(mktemp)
    trap 'rm -f "$plan"' EXIT
    apt-get -qq -o Acquire::ForceHash=SHA256 --print-uris \
        install -y --no-install-recommends "$@" > "$plan"

    count=0
    while read -r uri filename size hash extra; do
        # APT can print informational lines as well as quoted download URIs.
        case "$uri" in "'"*) ;; *) continue ;; esac
        uri=${uri#\'}
        uri=${uri%\'}
        case "$uri" in
            https://snapshot.debian.org/archive/debian/*/pool/*)
                archive=debian ;;
            https://snapshot.debian.org/archive/debian-security/*/pool/*)
                archive=debian-security ;;
            *) echo "Unsupported snapshot URI: $uri" >&2; exit 100 ;;
        esac
        # No shell evaluation of the plan; reject unsafe paths and weak hashes.
        case "$filename" in
            ''|.*|*[!a-zA-Z0-9._+%:~=-]*) exit 100 ;;
        esac
        digest=${hash#SHA256:}
        case "$digest" in ''|*[!a-fA-F0-9]*) exit 100 ;; esac
        [ "$hash" != "$digest" ] && [ "${#digest}" -eq 64 ] && [ -z "$extra" ] || exit 100
        relative=${uri#https://snapshot.debian.org/archive/}
        relative=${relative#*/}
        relative=${relative#*/}
        case "$relative" in pool/*.deb) ;; *) exit 100 ;; esac
        case "$relative" in *../*|*\?*|*\#*) exit 100 ;; esac

        echo "Snapshot unavailable; fetching $filename from official Debian CDN" >&2
        # apt-helper uses APT's TLS settings and rejects a hash mismatch. APT
        # checks the cached archives again before the offline installation.
        PATH="$PATH:/usr/lib/apt" apt-helper \
            -o Acquire::Retries=0 \
            -o Acquire::http::Timeout=60 \
            -o Acquire::https::Timeout=60 \
            download-file "https://deb.debian.org/$archive/$relative" \
            "/var/cache/apt/archives/partial/$filename" "$hash"
        mv "/var/cache/apt/archives/partial/$filename" "/var/cache/apt/archives/$filename"
        count=$((count + 1))
    done < "$plan"
    [ "$count" -gt 0 ] || exit 100
)

# Do not accept a partially refreshed index. Retain downloaded archives across
# retries, then run package installation once, with networking disabled in APT.
fetch -o APT::Update::Error-Mode=any update
if fetch install -y --no-install-recommends --download-only "$@"; then
    :
else
    status=$?
    [ "$status" -eq 100 ] || exit "$status"
    fetch_from_debian_cdn "$@"
fi
apt-get install -y --no-install-recommends --no-download "$@"
