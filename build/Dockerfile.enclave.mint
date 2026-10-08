# syntax=docker/dockerfile:1.7
# Mint signer enclave image: EVM -> RGB only (vsock + rgb + mint-signer).
# Private Cargo dependencies require BuildKit secrets (see README, Building).
# Supply github_token, or one deploy key per repo; keys never enter image layers.
# Example: docker build --build-arg RGB_ASSET_ID="$RGB_ASSET_ID" \
#   --secret id=github_token,env=GITHUB_TOKEN -f build/Dockerfile.enclave.mint .
# Use the same Debian release for the builder and runtime.
FROM rust:1.96.1-slim-trixie@sha256:31ee7fc65186be7e0e0ccb3f2ca305f14e4739e7642a1ae65753aa5d7b874523 AS builder

# Pin packages to a signed snapshot. HTTP bootstraps ca-certificates.
RUN set -eux; \
    printf '%s\n' \
      'deb http://snapshot.debian.org/archive/debian/20261007T000000Z trixie main' \
      'deb http://snapshot.debian.org/archive/debian-security/20261007T000000Z trixie-security main' \
      > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/*; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99snapshot; \
    apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev git ca-certificates openssh-client make cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /build/

WORKDIR /build/enclave

# Deterministic compilation (PCR0 reproducibility), same as Dockerfile.enclave:
#   CARGO_INCREMENTAL=0   no incremental artifacts
#   --remap-path-prefix   strip the absolute build path from embedded paths
#   -C debuginfo=0 / strip=symbols  drop debug info + symbol tables
ENV CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/build=/src -C debuginfo=0 -C strip=symbols"
# `rgb` implies `spv` + `rgb-validation`. `--no-default-features` drops `ccd`
# (so this binary is RGB-only) and also drops the default `rgb-swap`, which is
# what lets the mint/burn flow be selected instead. The signer role implies
# `bfa-mint` -> `bfa-validation` -> `evm-rpc` (in-enclave FundsIn verification,
# alloy + tokio); it needs a second host vsock-proxy
# (EVM_RPC_VSOCK_PORT, default 8002).
#
# `mint-signer` (implies `bfa-mint` -> the mint/burn flow + BFA validation)
# builds the EVM -> RGB direction only: it signs the RGB mint PSBT after
# verifying the EVM lock, and signs create_utxo (`SignBtc`). It carries no
# `fundsOut` release rule at all - the burn signer is Dockerfile.enclave.burn.
# Two roles, two PCR0s, two seeds, two running enclaves.
RUN --mount=type=secret,id=github_token \
    --mount=type=secret,id=consensus_key \
    --mount=type=secret,id=ops_key \
    --mount=type=secret,id=schemas_key \
    sh /build/build/with-private-deps.sh enclave cargo build --release --locked --no-default-features --features vsock,rgb,mint-signer


# --- Runtime ---
# Pin the measured rootfs by digest. Update both stages together.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS runtime

# Remove package-manager logs and caches in the installation layer.
RUN set -eux; \
    printf '%s\n' \
      'deb http://snapshot.debian.org/archive/debian/20261007T000000Z trixie main' \
      'deb http://snapshot.debian.org/archive/debian-security/20261007T000000Z trixie-security main' \
      > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/*; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99snapshot; \
    apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates socat iproute2 libssl3t64 libstdc++6 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
        /var/cache/debconf /var/cache/ldconfig /var/log/* /tmp/*

WORKDIR /app
COPY --from=builder /build/target/release/utexo-bridge-enclave /app/utexo-bridge-enclave
COPY build/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/utexo-bridge-enclave /app/entrypoint.sh
# Reject missing libraries or incompatible symbol versions before EIF conversion.
RUN /lib64/ld-linux-x86-64.so.2 --list /app/utexo-bridge-enclave > /dev/null

# The mint signer restores its KMS-protected seed instead of peer cloning.

# Pinned bridge/indexer config - identical to Dockerfile.enclave; keep the two in
# lockstep. `rgb` implies `spv` + `rgb-validation`, so this is a release
# bridge-signing build and `SecurityPolicy::assert_valid_for_build` refuses to
# boot without these pins (enclave/src/policy.rs). Public
# identifiers, baked so PCR0 commits to them. Stage runs on Bitcoin MAINNET +
# Arbitrum One (chain_id 42161). Electrum is set at launch. The enclave pins its
# host to 127.0.0.1 and reaches it over the vsock forwarder (host runs
# `vsock-proxy 8001 <electrum host> <port>`); TLS terminates in-enclave.
# TWO-CONTRACT deployment: the EVM funds-out EIP-712 verifyingContract is the
# MultisigProxy (EVM_PROXY_CONTRACT_ADDRESS), which DIFFERS from the bridge
# *entry* contract that emits FundsIn (FUNDS_IN_CONTRACT, set below).
# The BFA asset id is a build arg with no default: each BFA contract id is per
# deployment. An empty value fails the build (`test -n` below).
#   --build-arg RGB_ASSET_ID=rgb:<the issued BFA contract id>
# Note the pin is single-valued, so this EIF signs for the BFA asset only.
ARG RGB_ASSET_ID=""
RUN test -n "$RGB_ASSET_ID"
ENV EVM_CHAIN_ID=42161 \
    EVM_PROXY_CONTRACT_ADDRESS=0xC985c12bbCECe96A13A72A62FD75d8aB9381ef5A \
    RGB_ASSET_ID=${RGB_ASSET_ID} \
    BITCOIN_NETWORK=bitcoin

# In-enclave EVM verification (evm-rpc). The enclave reaches the EVM RPC only
# through the vsock forwarder (host runs
# `vsock-proxy <EVM_RPC_VSOCK_PORT=8002> <rpc host> <tls port>`).
# FUNDS_IN_CONTRACT is set EXPLICITLY because it differs from
# EVM_PROXY_CONTRACT_ADDRESS - unset, it falls back to the proxy address and
# points FundsIn verification at the wrong contract.
# The mint signer also signs plain-BTC create_utxo PSBTs (`SignBtc`), which fail
# closed unless BTC_MAX_TOTAL_SATS is pinned. The gas-tx path is not compiled in.
# The Electrum URL and the EVM RPC host, CA and TLS port are not in the
# image. The operator sets them at launch (SetEndpoints), and the attestation
# commits them. See docs/tee-spec.md.
ENV EVM_MIN_CONFIRMATIONS=12 \
    FUNDS_IN_CONTRACT=0x6711f1a319B37847fa0234181C34D883774c4951 \
    TOKEN_CONTRACT=0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9 \
    BTC_MAX_TOTAL_SATS=1000000

# Production logging. This env is measured into PCR0 - do not flip it to `debug`
# for a production EIF.
ENV RUST_LOG=info
ENTRYPOINT ["/app/entrypoint.sh"]
