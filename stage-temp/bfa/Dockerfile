# syntax=docker/dockerfile:1.7
# Temporary stage BFA. Retained seeds arrive over vsock after startup.
# Keep the builder compatible with the AL2023 runtime.
FROM rust:1.96-slim-bullseye@sha256:c593596210f729542a92aced6a8b0812bcc8d04c5f1b238e663b800d0e2e17bd AS builder

# Use the signed Debian snapshot to avoid missing Bullseye packages.
# HTTP is required until ca-certificates is installed.
# Replace this temporary pin when the shared base-image update is ready.
RUN set -eux; \
    printf '%s\n' \
      'deb http://snapshot.debian.org/archive/debian/20260801T000000Z bullseye main' \
      'deb http://snapshot.debian.org/archive/debian-security/20260801T000000Z bullseye-security main' \
      > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/*; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99snapshot; \
    apt-get update && apt-get install -y \
    pkg-config libssl-dev git ca-certificates openssh-client \
    make python3 python3-pip \
    && pip3 install --no-cache-dir "cmake==3.31.6" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /build/

WORKDIR /build/enclave
ARG STAGE_BFA_MODE
ARG RGB_ASSET_ID="rgb:0xCZMKww-~LBSYFG-b_q5Vak-Yn1pgIc-P7UVc9m-EUOJ0mc"
ENV STAGE_BFA_MODE=${STAGE_BFA_MODE}
RUN case "$STAGE_BFA_MODE" in bootstrap) test -z "$RGB_ASSET_ID" ;; configured) test -n "$RGB_ASSET_ID" ;; *) exit 1 ;; esac

ENV CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/build=/src -C debuginfo=0 -C strip=symbols"
# Stage-only optimized profile enables seed import without changing the ordinary release guards.
RUN --mount=type=secret,id=github_token \
    --mount=type=secret,id=consignment_key \
    --mount=type=secret,id=consensus_key \
    --mount=type=secret,id=ops_key \
    --mount=type=secret,id=schemas_key \
    sh /build/build/with-private-deps.sh enclave cargo build --profile stage-bfa-temp --locked --no-default-features --features stage-bfa-temp


# --- Runtime ---
# Pinned by DIGEST: this rootfs is what ends up in the EIF, so its digest drives
# PCR0 directly. Bump tag + digest together, in step with Dockerfile.enclave.
FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal@sha256:8073d921f4ac1bf17fca94e16b0bc575e3fc17e4ccbe53b563160f02f0c7ccfc AS runtime

# Deterministic runtime rootfs (PCR0/PCR2 reproducibility). dnf/rpm write state
# with embedded timestamps and randomness (rpmdb, history, caches, logs);
# rewrite-timestamp normalises mtimes but not file contents. Scrub it in the SAME
# layer so the measured rootfs is stable. (rpmdb is not needed at runtime.)
RUN dnf install -y socat iproute \
    && dnf clean all \
    && rm -rf \
        /var/cache/dnf /var/cache/libdnf5 /var/cache/ldconfig \
        /var/lib/dnf /var/lib/rpm /var/lib/rpm-state \
        /var/log/* /tmp/* \
    && :

WORKDIR /app
COPY --from=builder /build/target/stage-bfa-temp/utexo-bridge-enclave /app/utexo-bridge-enclave
COPY build/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/utexo-bridge-enclave /app/entrypoint.sh

# Public stage pins. Seed material is supplied only after enclave startup.
ARG RGB_ASSET_ID="rgb:0xCZMKww-~LBSYFG-b_q5Vak-Yn1pgIc-P7UVc9m-EUOJ0mc"
ENV EVM_CHAIN_ID=42161 \
    EVM_PROXY_CONTRACT_ADDRESS=0x0584f124d56266c3583605a441545d48feea9b9e \
    FUNDS_IN_CONTRACT=0x9f447017ca5f413dc86d9d69c772e9dfe16fb823 \
    GAS_TX_ALLOWED_TO=0x9f447017ca5f413dc86d9d69c772e9dfe16fb823 \
    RGB_ASSET_ID=${RGB_ASSET_ID} \
    BITCOIN_NETWORK=bitcoin \
    ELECTRUM_URL=ssl://electrs-mainnet.utexo.com:50002 \
    EVM_RPC_URL=http://127.0.0.1:3444 \
    EVM_MIN_CONFIRMATIONS=12 \
    BTC_MAX_TOTAL_SATS=1000000 \
    BTC_MAX_UNOWNED_SATS=150000 \
    WITNESSED_SATOSHI_AMOUNT=1000 \
    RUST_LOG=info
ENTRYPOINT ["/app/entrypoint.sh"]
