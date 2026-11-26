# Sourced by build-enclave.sh. Public measured inputs only; no Stage fallback.
case "$DOCKERFILE" in
    Dockerfile.enclave.mint) ENCLAVE_FEATURES=vsock,mint-signer ;;
    Dockerfile.enclave.burn) ENCLAVE_FEATURES=vsock,burn-signer ;;
    *) echo 'Error: prod-mainnet supports only mint and burn recipes' >&2; exit 1 ;;
esac
: "${PROD_MAINNET_RGB_ASSET_ID:?Set PROD_MAINNET_RGB_ASSET_ID to the approved mainnet BFA asset}"
[[ "$PROD_MAINNET_RGB_ASSET_ID" =~ ^rgb:[A-Za-z0-9_~:.-]+$ ]] || {
    echo 'Error: invalid PROD_MAINNET_RGB_ASSET_ID' >&2; exit 1
}
for name in PROD_MAINNET_MULTISIG_CONTRACT PROD_MAINNET_BRIDGE_CONTRACT PROD_MAINNET_TOKEN_CONTRACT; do
    [[ "${!name:-}" =~ ^0x[0-9a-fA-F]{40}$ && ! "${!name:-}" =~ ^0x0{40}$ ]] || {
        echo "Error: $name must be an approved nonzero 20-byte address" >&2; exit 1
    }
done
BITCOIN_NETWORK=bitcoin
BTC_RELAY_MODE=required
EVM_CHAIN_ID=42161
EVM_PROXY_CONTRACT_ADDRESS="$PROD_MAINNET_MULTISIG_CONTRACT"
FUNDS_IN_CONTRACT="$PROD_MAINNET_BRIDGE_CONTRACT"
TOKEN_CONTRACT="$PROD_MAINNET_TOKEN_CONTRACT"
RGB_ASSET_ID="$PROD_MAINNET_RGB_ASSET_ID"
RUST_LOG=info,alloy_transport_http=off
if [ "$DOCKERFILE" = Dockerfile.enclave.mint ]; then
    : "${PROD_KMS_ALLOWED_ACCOUNT_IDS:?Set PROD_KMS_ALLOWED_ACCOUNT_IDS to the approved seed KMS account list}"
    KMS_ALLOWED_ACCOUNT_IDS="$PROD_KMS_ALLOWED_ACCOUNT_IDS"
else
    : "${PROD_MAINNET_GAS_TX_ALLOWED_SELECTORS:?Confirm production Multisig ABI selectors}"
    [[ "$PROD_MAINNET_GAS_TX_ALLOWED_SELECTORS" =~ ^0x[0-9a-fA-F]{8}(,0x[0-9a-fA-F]{8})*$ ]] || {
        echo 'Error: PROD_MAINNET_GAS_TX_ALLOWED_SELECTORS must be comma-separated 4-byte hex selectors' >&2; exit 1
    }
    GAS_TX_ALLOWED_TO="$EVM_PROXY_CONTRACT_ADDRESS"
    GAS_TX_MAX_FEE_PER_GAS=1000000000
    GAS_TX_MAX_VALUE_WEI=5000000000000000
    GAS_TX_ALLOWED_SELECTORS="$PROD_MAINNET_GAS_TX_ALLOWED_SELECTORS"
fi
