#!/bin/sh
# Build the same unmodified SDK and CRT dependencies as kmstool_enclave_cli.
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
mkdir -p "$build_dir/src" "$prefix/lib" "$prefix/include" "$prefix/share/swap-kms/licenses"

# AWS libraries are static; only libnsm and platform libc libraries are shared.
# Pin build paths in Cargo output as well as the enclave's release binary.
export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$build_dir=/swap-kms-build -C debuginfo=0"

while read -r name version commit url; do
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
    git -C "$source_dir" diff --exit-code HEAD -- >/dev/null

    # Include upstream licensing and the exact provenance with the runtime.
    license_dir="$prefix/share/swap-kms/licenses/$name"
    mkdir -p "$license_dir"
    for license in "$source_dir"/LICENSE* "$source_dir"/NOTICE* "$source_dir"/COPYING*; do
        [ ! -f "$license" ] || cp "$license" "$license_dir/"
    done

    if [ "$name" = aws-nitro-enclaves-nsm-api ]; then
        # Upstream v0.4.0 has no lockfile; use our resolved, checked-in lock
        # without modifying the SDK or its dependency source code.
        cp "$script_dir/swap-kms-nsm.Cargo.lock" "$source_dir/Cargo.lock"
        # An explicit SONAME permits the runtime to load libnsm from its default
        # library directory instead of embedding this build prefix in DT_NEEDED.
        (cd "$source_dir" && CARGO_TARGET_DIR="$source_dir/target" cargo rustc \
            --locked --release --jobs "$jobs" -p nsm-lib --lib -- \
            -C link-arg=-Wl,-soname,libnsm.so)
        cp "$source_dir/Cargo.lock" "$prefix/share/swap-kms/nsm-Cargo.lock"
        install -m 755 "$source_dir/target/release/libnsm.so" "$prefix/lib/libnsm.so"
        install -m 644 "$source_dir/target/release/nsm.h" "$prefix/include/nsm.h"
        continue
    fi

    # A dedicated prefix prevents silently linking a distro OpenSSL instead of
    # the AWS-LC version used by the official SDK image.
    set -- -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$prefix" \
        -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    if [ "$name" = aws-c-io ]; then
        set -- "$@" -DUSE_VSOCK=ON
    fi
    if [ "$name" = aws-nitro-enclaves-sdk-c ]; then
        # GCC 10 diagnoses an upstream allocation-failure cleanup path in
        # rest.c. Keep the SDK source unchanged and retain the warning; this
        # exception is scoped to this diagnostic in the SDK, not our helper.
        set -- "$@" -DCMAKE_C_FLAGS=-Wno-error=maybe-uninitialized
    fi
    cmake -GNinja -S "$source_dir" -B "$build_dir/build/$name" "$@"
    cmake --build "$build_dir/build/$name" --parallel "$jobs" --target install
    if [ "$name" = aws-lc ]; then
        # The distro Go tool may expand go.sum while running code generators.
        # It is generated checksum metadata; retain the pinned upstream file
        # so a second build of this cache verifies the same clean source tree.
        git -C "$source_dir" restore --source=HEAD -- go.sum
    fi
done < "$manifest"

cp "$manifest" "$prefix/share/swap-kms/dependencies.tsv"
if [ "${SWAP_KMS_DEPENDENCIES_ONLY:-0}" = 1 ]; then
    exit 0
fi

cmake -GNinja -S "$repo_dir/enclave/kms-tool" -B "$build_dir/build/swap-kms-tool" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$prefix" \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DBUILD_SHARED_LIBS=OFF \
    -DNITRO_SDK_SOURCE_DIR="$build_dir/src/aws-nitro-enclaves-sdk-c"
cmake --build "$build_dir/build/swap-kms-tool" --parallel "$jobs" --target install
strip "$prefix/bin/swap-kms-tool" "$prefix/lib/libnsm.so"
