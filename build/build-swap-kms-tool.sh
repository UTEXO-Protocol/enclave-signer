#!/bin/sh
# Build the official kmstool SDK with its checked cleanup fix and pinned CRT.
# Requires Linux, C/C++ compilers, CMake, Ninja, Git, Go, Perl and Rust/Cargo.
set -eu

if [ "$(uname -s)" != Linux ]; then
    echo "swap-kms-tool must be built on Linux (use a swap Dockerfile)." >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(dirname "$script_dir")
build_dir=${SWAP_KMS_BUILD_DIR:-/opt/swap-kms-build}
prefix=${SWAP_KMS_INSTALL_PREFIX:-/opt/swap-kms}
jobs=${SWAP_KMS_BUILD_JOBS:-4}
manifest="$script_dir/swap-kms-dependencies.tsv"
sdk_patch="$script_dir/patches/nitro-sdk-cleanup.patch"
mkdir -p "$build_dir/src" "$prefix/lib" "$prefix/include" "$prefix/share/swap-kms/licenses"

# AWS libraries are static; only libnsm and platform libc libraries are shared.
# Pin build paths in Cargo output as well as the enclave's release binary.
export GIT_TERMINAL_PROMPT=0
export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$build_dir=/swap-kms-build -C debuginfo=0"

# Keep the manifest on a separate descriptor: build tools must never consume
# dependency records as stdin or prompt for credentials in an unattended build.
while read -r name version commit url <&3; do
    case "$name" in ''|'#'*) continue ;; esac
    source_dir="$build_dir/src/$name"
    if [ ! -d "$source_dir/.git" ]; then
        git init -q "$source_dir"
        git -C "$source_dir" remote add origin "$url"
    fi
    if [ "$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || true)" != "$commit" ]; then
        git -C "$source_dir" fetch --depth 1 origin "$commit"
        git -C "$source_dir" checkout -q --detach FETCH_HEAD
    fi
    test "$(git -C "$source_dir" rev-parse HEAD)" = "$commit"
    if [ "$name" = aws-nitro-enclaves-sdk-c ]; then
        # Only this reviewed patch is permitted over the immutable SDK base.
        # Reused caches must match its complete canonical diff: never reset or
        # silently accept unrelated tracked edits in an existing checkout.
        if git -C "$source_dir" diff --quiet HEAD --; then
            git -C "$source_dir" apply --check "$sdk_patch"
            git -C "$source_dir" apply "$sdk_patch"
        fi
        git -C "$source_dir" diff --binary --full-index --no-ext-diff --no-color \
            --src-prefix=a/ --dst-prefix=b/ HEAD -- | cmp -s - "$sdk_patch" || {
            echo "SDK source differs from the exact reviewed cleanup patch" >&2
            exit 1
        }
        patch_sha=$(sha256sum "$sdk_patch")
        patch_sha=${patch_sha%% *}
        rest_sha=$(sha256sum "$source_dir/source/rest.c")
        rest_sha=${rest_sha%% *}
        mkdir -p "$prefix/share/swap-kms/patches"
        cp "$sdk_patch" "$prefix/share/swap-kms/patches/nitro-sdk-cleanup.patch"
        printf '{"upstream_commit":"%s","patch_sha256":"%s","effective_rest_c_sha256":"%s"}\n' \
            "$commit" "$patch_sha" "$rest_sha" > "$prefix/share/swap-kms/sdk-source.json"
    else
        git -C "$source_dir" diff --exit-code HEAD -- >/dev/null
    fi

    # Include upstream licensing and the exact provenance with the runtime.
    license_dir="$prefix/share/swap-kms/licenses/$name"
    mkdir -p "$license_dir"
    for license in "$source_dir"/LICENSE* "$source_dir"/NOTICE* "$source_dir"/COPYING*; do
        [ ! -f "$license" ] || cp "$license" "$license_dir/"
    done

    if [ "$name" = aws-nitro-enclaves-nsm-api ]; then
        # Use our resolved, checked-in workspace lock; NSM source is unchanged.
        cp "$script_dir/swap-kms-nsm.Cargo.lock" "$source_dir/Cargo.lock"
        # NSM 0.5.2 sets its official libnsm.so.0 SONAME. Preserve it in
        # the runtime; the unversioned symlink is only for build-time discovery.
        (cd "$source_dir" && CARGO_TARGET_DIR="$source_dir/target" cargo build \
            --locked --release --jobs "$jobs" -p nsm-lib --lib)
        cp "$source_dir/Cargo.lock" "$prefix/share/swap-kms/nsm-Cargo.lock"
        install -m 755 "$source_dir/target/release/libnsm.so" "$prefix/lib/libnsm.so.0"
        ln -sfn libnsm.so.0 "$prefix/lib/libnsm.so"
        install -m 644 "$source_dir/target/release/nsm.h" "$prefix/include/nsm.h"
        continue
    fi

    # A dedicated prefix prevents silently linking a distro OpenSSL instead of
    # the AWS-LC version used by the official SDK image.
    set -- -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$prefix" \
        -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    if [ "$name" = aws-lc ]; then
        set -- "$@" -DENABLE_SOURCE_MODIFICATION=OFF
    fi
    if [ "$name" = aws-c-io ]; then
        # CRT 1.0.0 declares sockaddr_vm in socket_impl.h before its
        # platform include. Supply the Linux headers via compiler options;
        # upstream sources remain byte-identical to the pinned commit.
        set -- "$@" -DUSE_VSOCK=ON \
            "-DCMAKE_C_FLAGS=-include sys/socket.h -include linux/vm_sockets.h"
    fi
    if [ "$name" = aws-nitro-enclaves-sdk-c ]; then
        # CRT 1.0 no longer injects its installed modules into callers'
        # global module path. The SDK still includes those official modules.
        # Its example also relied on a removed transitive hash-table
        # include. Use the official header explicitly without patching source.
        set -- "$@" "-DCMAKE_C_FLAGS=-I$prefix/include -include aws/common/hash_table.h" \
            "-DCMAKE_MODULE_PATH=$prefix/lib/cmake/aws-c-common/modules" \
            "-DLIBRARY_DIRECTORY=$prefix/lib"
    fi
    cmake -GNinja -S "$source_dir" -B "$build_dir/build/$name" "$@"
    cmake --build "$build_dir/build/$name" --parallel "$jobs" --target install
    if [ "$name" = aws-nitro-enclaves-sdk-c ]; then
        # The exported CMS functions' header is omitted by upstream install.
        # Install the pinned header verbatim; consumers need only this prefix.
        install -D -m 644 "$source_dir/include/aws/nitro_enclaves/internal/cms.h" \
            "$prefix/include/aws/nitro_enclaves/internal/cms.h"
        (cd "$prefix" && sha256sum include/aws/nitro_enclaves/internal/cms.h \
            > share/swap-kms/headers.sha256)
    fi
    if [ "$name" = aws-lc ]; then
        # The distro Go tool may expand go.sum while running code generators.
        # It is generated checksum metadata; retain the pinned upstream file
        # so a second build of this cache verifies the same clean source tree.
        git -C "$source_dir" restore --source=HEAD -- go.sum
    fi
done 3< "$manifest" </dev/null

cp "$manifest" "$prefix/share/swap-kms/dependencies.tsv"
if [ "${SWAP_KMS_DEPENDENCIES_ONLY:-0}" = 1 ]; then
    exit 0
fi

cmake -GNinja -S "$repo_dir/enclave/kms-tool" -B "$build_dir/build/swap-kms-tool" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$prefix" \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=ON
cmake --build "$build_dir/build/swap-kms-tool" --parallel "$jobs" --target install
ctest --test-dir "$build_dir/build/swap-kms-tool" --output-on-failure
strip "$prefix/bin/swap-kms-tool" "$prefix/lib/libnsm.so.0"
