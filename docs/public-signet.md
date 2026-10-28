# Public Signet on Nitro

Use the existing mint/burn images with `spv` and `kms-persistence` omitted.
There is no separate staging feature or build profile:

| Image | Production features (default) | Public Signet features |
| --- | --- | --- |
| Mint | `vsock,rgb,mint-signer,kms-persistence` | `vsock,mint-signer` |
| Burn | `vsock,rgb,burn-signer` | `vsock,burn-signer` |

`rgb` continues to enable SPV. A mint build with SPV must explicitly include
`kms-persistence`; omitting it fails compilation. Without SPV, startup requires
public `BITCOIN_NETWORK=signet`, `BTC_RELAY_MODE=none`, nonzero chain/contract
pins and an asset ID. Ethereum/Arbitrum mainnet chain IDs are refused.

Both roles use real NSM attestation. Empty `InitializeKey` generates fresh
entropy inside the enclave; keys disappear when it stops. Seed/mnemonic import
and mock/debug attestation features are forbidden for this combination.
Do not enable Nitro debug mode. Keep these identities separate from production.

## Build and launch

Provide your test deployment's public pins, then use the existing build script:

```bash
export RGB_ASSET_ID='rgb:<issued BFA contract id>'
export EVM_CHAIN_ID='<test chain id>'
export EVM_PROXY_CONTRACT_ADDRESS='0x<proxy address>'
export FUNDS_IN_CONTRACT='0x<bridge address>'
export TOKEN_CONTRACT='0x<token address>'
export BITCOIN_NETWORK=signet BTC_RELAY_MODE=none
# Maximum non-enclave-owned input value in each mint PSBT, in satoshis.
export RGB_MAX_UNOWNED_SATS=1000
# Supply the existing BuildKit credential through PRIVATE_DEPS_DIR or
# RGB_LIB_BFA_DEPLOY_KEY, as for production builds.
ENCLAVE_FEATURES=vsock,mint-signer DOCKERFILE=Dockerfile.enclave.mint \
  OUT_DIR=build/signet-mint EIF_NAME=signet-mint.eif \
  IMAGE_TAG=utexo-signet-mint:latest build/build-enclave.sh
ENCLAVE_FEATURES=vsock,burn-signer DOCKERFILE=Dockerfile.enclave.burn \
  OUT_DIR=build/signet-burn EIF_NAME=signet-burn.eif \
  IMAGE_TAG=utexo-signet-burn:latest build/build-enclave.sh
```

These overrides are baked into the EIF and change its PCRs. Use distinct
output paths and retain each image's `PCR.json` and `IMAGE-ENV.json`.
Run each EIF normally with `nitro-cli run-enclave` (no `--debug-mode`).
Set endpoints and initialize through the existing parent CLI. The indexer
must serve public Signet over TLS; for example,
`ssl://node202.fra.mempool.space:60602` was used in the live test. Forward its
traffic on vsock port 8001 and your EVM TLS RPC on 8002. No header source or
KMS broker is needed. Health reports zero SPV diagnostics, so parent header
synchronization stops automatically. Header RPCs refuse requests.

Export the real key attestation with the existing command:

```bash
utexo-bridge-parent-cli --cid <cid> export-attestation \
  --allow-development-policy --pcr-file build/signet-burn/PCR.json \
  --out burn-attestation.json
```

Approve the image's nonzero PCRs independently. The Development policy does
not separately commit endpoint/configuration fields; the measured image pins
its baked configuration. It is deliberately rejected by production policy
verification.

## Validation boundary

Burns still undergo RGB consensus, asset, amount, recipient, burn-operation,
settlement and ancestry checks. Bitcoin witness confirmations come from the
TLS indexer at `SPV_MIN_CONFIRMATIONS` depth (mint image default 3, burn 6).
There are no Merkle/header proofs or BtcRelay agreement checks. Caller-supplied
relay proof bytes are not independently verified. Use compatible test contracts.
Mint signing retains its existing in-enclave EVM receipt/finality checks.

The live test created and confirmed actual RGB rights, mint and burn transactions
on public Signet in real Nitro enclaves. Its EVM RPC used a controlled TLS
fixture; it did not execute an external EVM bridge release. The shared vsock
half-close fix prevents completed indexer requests from exhausting proxy workers.
