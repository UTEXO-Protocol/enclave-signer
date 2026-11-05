# Sourced by build-enclave.sh with BUILD_PROFILE=stage-signet.
# Public configuration only. Dependency credentials remain BuildKit secrets.
case "$DOCKERFILE" in
    Dockerfile.enclave.mint) ENCLAVE_FEATURES=vsock,mint-signer ;;
    Dockerfile.enclave.burn) ENCLAVE_FEATURES=vsock,burn-signer ;;
    *) echo 'Error: stage-signet supports only mint and burn recipes' >&2; exit 1 ;;
esac
[ -z "${ENCLAVE_DEBUG_FEATURES:-}" ] || {
    echo 'Error: stage-signet requires real attestation; leave debug features empty' >&2
    exit 1
}

# Dedicated inputs prevent reuse of an old asset/token/endpoint pin from another profile.
: "${STAGE_RGB_ASSET_ID:?Set STAGE_RGB_ASSET_ID to the new public-Signet BFA asset}"
: "${STAGE_TOKEN_CONTRACT:?Set STAGE_TOKEN_CONTRACT to the approved ERC-20 address}"
: "${STAGE_ENDPOINTS_SHA256:?Compute STAGE_ENDPOINTS_SHA256 with the matching CLI}"
[[ "$STAGE_RGB_ASSET_ID" == rgb:?* ]] || { echo 'Error: invalid STAGE_RGB_ASSET_ID' >&2; exit 1; }
[[ "$STAGE_TOKEN_CONTRACT" =~ ^0x[0-9a-fA-F]{40}$ && "$STAGE_TOKEN_CONTRACT" != 0x0000000000000000000000000000000000000000 ]] || {
    echo 'Error: STAGE_TOKEN_CONTRACT must be a nonzero 20-byte address' >&2; exit 1
}
[[ "$STAGE_ENDPOINTS_SHA256" =~ ^[0-9a-fA-F]{64}$ && "$STAGE_ENDPOINTS_SHA256" =~ [1-9a-fA-F] ]] || {
    echo 'Error: STAGE_ENDPOINTS_SHA256 must be a nonzero 32-byte hex digest' >&2; exit 1
}

BITCOIN_NETWORK=signet
BTC_RELAY_MODE=none
EVM_CHAIN_ID=42161
EVM_PROXY_CONTRACT_ADDRESS=0x4ab64dd591778ab9b65fd81062703595dfe64552
FUNDS_IN_CONTRACT=0xe67c9eb5006512525f597c3fa6119891bd4efaa6
TOKEN_CONTRACT="$STAGE_TOKEN_CONTRACT"
RGB_ASSET_ID="$STAGE_RGB_ASSET_ID"
ENDPOINTS_SHA256="$STAGE_ENDPOINTS_SHA256"
RUST_LOG=debug

if [ "$DOCKERFILE" = Dockerfile.enclave.mint ]; then
    # MINT_WITNESS_SAT is 1500 in the recipe; the connector must match it.
    RGB_MAX_UNOWNED_SATS=1500
else
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
