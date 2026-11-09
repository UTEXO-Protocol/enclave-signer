# Sourced by build-enclave.sh with BUILD_PROFILE=stage-signet.
# Public configuration only. Dependency credentials remain BuildKit secrets.
case "$DOCKERFILE" in
    Dockerfile.enclave.mint) ENCLAVE_FEATURES=vsock,mint-signer ;;
    Dockerfile.enclave.burn) ENCLAVE_FEATURES=vsock,burn-signer ;;
    *) echo 'Error: stage-signet supports only mint and burn recipes' >&2; exit 1 ;;
esac

# Dedicated inputs prevent reuse of an asset or token from another profile.
: "${STAGE_RGB_ASSET_ID:?Set STAGE_RGB_ASSET_ID to the new public-Signet BFA asset}"
: "${STAGE_TOKEN_CONTRACT:?Set STAGE_TOKEN_CONTRACT to the approved ERC-20 address}"
[[ "$STAGE_RGB_ASSET_ID" == rgb:?* ]] || { echo 'Error: invalid STAGE_RGB_ASSET_ID' >&2; exit 1; }
[[ "$STAGE_TOKEN_CONTRACT" =~ ^0x[0-9a-fA-F]{40}$ && "$STAGE_TOKEN_CONTRACT" != 0x0000000000000000000000000000000000000000 ]] || {
    echo 'Error: STAGE_TOKEN_CONTRACT must be a nonzero 20-byte address' >&2; exit 1
}

BITCOIN_NETWORK=signet
BTC_RELAY_MODE=none
EVM_CHAIN_ID=42161
EVM_PROXY_CONTRACT_ADDRESS=0x4ab64dd591778ab9b65fd81062703595dfe64552
FUNDS_IN_CONTRACT=0xe67c9eb5006512525f597c3fa6119891bd4efaa6
TOKEN_CONTRACT="$STAGE_TOKEN_CONTRACT"
RGB_ASSET_ID="$STAGE_RGB_ASSET_ID"
RUST_LOG=debug,alloy_transport_http=off

# MINT_WITNESS_SAT is 1500 in the mint recipe; the connector must match it.
if [ "$DOCKERFILE" = Dockerfile.enclave.burn ]; then
    : "${STAGE_GAS_TX_ALLOWED_SELECTORS:?Confirm the selectors against the new Multisig ABI}"
    [[ "$STAGE_GAS_TX_ALLOWED_SELECTORS" =~ ^0x[0-9a-fA-F]{8}(,0x[0-9a-fA-F]{8})*$ ]] || {
        echo 'Error: STAGE_GAS_TX_ALLOWED_SELECTORS must be comma-separated 4-byte hex selectors' >&2; exit 1
    }
    GAS_TX_ALLOWED_TO="$EVM_PROXY_CONTRACT_ADDRESS"
    GAS_TX_MAX_GAS_LIMIT=3000000
    GAS_TX_MAX_FEE_PER_GAS=1000000000
    GAS_TX_MAX_VALUE_WEI=5000000000000000
    GAS_TX_ALLOWED_SELECTORS="$STAGE_GAS_TX_ALLOWED_SELECTORS"
fi
