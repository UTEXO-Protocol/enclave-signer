#!/usr/bin/env bash
# Provision the host-only KMS TLS relay. No seed or key policy is created here.
# Run once as root before deploying Mint; see docs/mint-release.md.
set -euo pipefail
REGION="${KMS_REGION:?KMS_REGION required}"
[[ "$REGION" =~ ^[a-z]{2}-[a-z]+-[0-9]+$ && "$REGION" != cn-* && "$REGION" != us-iso* ]] || { echo 'invalid KMS_REGION' >&2; exit 1; }
[ -x /usr/bin/vsock-proxy ] || { echo 'install Nitro vsock-proxy first' >&2; exit 1; }
ENV_FILE=/etc/nitro_enclaves/vsock-proxy-kms.env
CONFIG=/etc/nitro_enclaves/vsock-proxy-kms.yaml
UNIT=/etc/systemd/system/vsock-proxy-kms.service
# Do not redirect a shared live proxy as a side effect of preparing another signer.
if [ -e "$ENV_FILE" ] || [ -e "$CONFIG" ] || [ -e "$UNIT" ]; then
  grep -Fxq "KMS_REGION=$REGION" "$ENV_FILE" \
    && grep -Fxq -- "- {address: kms.${REGION}.amazonaws.com, port: 443}" "$CONFIG" \
    && grep -Fxq 'ExecStart=/usr/bin/vsock-proxy 8003 kms.${KMS_REGION}.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy-kms.yaml' "$UNIT" \
    || { echo 'existing KMS proxy differs/incomplete; reconcile it explicitly before deployment' >&2; exit 1; }
else
  install -d /etc/nitro_enclaves
  printf 'KMS_REGION=%s\n' "$REGION" > "$ENV_FILE"
  printf 'allowlist:\n- {address: kms.%s.amazonaws.com, port: 443}\n' "$REGION" > "$CONFIG"
  cat > "$UNIT" <<'UNIT'
[Unit]
Description=KMS TLS passthrough for Mint enclave (vsock 8003)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/nitro_enclaves/vsock-proxy-kms.env
ExecStart=/usr/bin/vsock-proxy 8003 kms.${KMS_REGION}.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy-kms.yaml
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 "$ENV_FILE" "$CONFIG" "$UNIT"
fi
systemctl daemon-reload
systemctl enable vsock-proxy-kms.service
# Start is a no-op for an active service; never restart a peer's shared proxy.
systemctl start vsock-proxy-kms.service
systemctl is-active --quiet vsock-proxy-kms.service
