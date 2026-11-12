# Sourced by build-enclave.sh with BUILD_PROFILE=stage-mainnet.
# Stage infrastructure with Bitcoin mainnet and the full Production/SPV policy.
# Public configuration only. Dependency credentials remain BuildKit secrets.
case "$DOCKERFILE" in
    Dockerfile.enclave.mint) ENCLAVE_FEATURES=vsock,spv,mint-signer ;;
    Dockerfile.enclave.burn) ENCLAVE_FEATURES=vsock,spv,burn-signer ;;
    *) echo 'Error: stage-mainnet supports only mint and burn recipes' >&2; exit 1 ;;
esac

# No fallback to the Signet or default profile's asset/token.
: "${STAGE_MAINNET_RGB_ASSET_ID:?Set STAGE_MAINNET_RGB_ASSET_ID to the Bitcoin mainnet BFA asset}"
: "${STAGE_MAINNET_TOKEN_CONTRACT:?Set STAGE_MAINNET_TOKEN_CONTRACT to the approved ERC-20 address}"
[[ "$STAGE_MAINNET_RGB_ASSET_ID" =~ ^rgb:[A-Za-z0-9_~:.-]+$ ]] || {
    echo 'Error: invalid STAGE_MAINNET_RGB_ASSET_ID' >&2; exit 1
}
[[ "$STAGE_MAINNET_TOKEN_CONTRACT" =~ ^0x[0-9a-fA-F]{40}$ && "$STAGE_MAINNET_TOKEN_CONTRACT" != 0x0000000000000000000000000000000000000000 ]] || {
    echo 'Error: STAGE_MAINNET_TOKEN_CONTRACT must be a nonzero 20-byte address' >&2; exit 1
}

BITCOIN_NETWORK=bitcoin
BTC_RELAY_MODE=required
EVM_CHAIN_ID=42161
# Multisig verifies releases; BridgeProxy emits deposits.
EVM_PROXY_CONTRACT_ADDRESS=0x8ed92cd8c14b5ee2e006fcd7c24f000c87e72495
FUNDS_IN_CONTRACT=0xc16c969955343f0f7528bc0bccd09aaa7b5b4e34
TOKEN_CONTRACT="$STAGE_MAINNET_TOKEN_CONTRACT"
RGB_ASSET_ID="$STAGE_MAINNET_RGB_ASSET_ID"
RUST_LOG=debug,alloy_transport_http=off

# Finality and confirmation depth remain fixed in the recipes.
# The connector's MINT_WITNESS_SAT must equal the mint recipe's value.
if [ "$DOCKERFILE" = Dockerfile.enclave.burn ]; then
    : "${STAGE_MAINNET_GAS_TX_ALLOWED_SELECTORS:?Confirm the selectors against the deployed Multisig ABI}"
    [[ "$STAGE_MAINNET_GAS_TX_ALLOWED_SELECTORS" =~ ^0x[0-9a-fA-F]{8}(,0x[0-9a-fA-F]{8})*$ ]] || {
        echo 'Error: STAGE_MAINNET_GAS_TX_ALLOWED_SELECTORS must be comma-separated 4-byte hex selectors' >&2; exit 1
    }
    GAS_TX_ALLOWED_TO="$EVM_PROXY_CONTRACT_ADDRESS"
    GAS_TX_MAX_GAS_LIMIT=3000000
    GAS_TX_MAX_FEE_PER_GAS=1000000000
    GAS_TX_MAX_VALUE_WEI=5000000000000000
    GAS_TX_ALLOWED_SELECTORS="$STAGE_MAINNET_GAS_TX_ALLOWED_SELECTORS"
fi
