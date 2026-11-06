# Stage Signet EIF builds

Use `BUILD_PROFILE=stage-signet` with `build/build-enclave.sh`, or select
`stage-signet` in the **Build EIF** workflow's `build_profile` input.
The profile builds Mint and Burn only. Tag builds and the `default` profile
continue to use the recipe defaults.

Mint and Burn disable APT's delayed-item retries and make up to four attempts
to fetch indexes and packages, with 30, 60 and 120 second pauses. This avoids
the retry loop described in [Debian bug #1152704](https://bugs.debian.org/1152704).
Completed downloads are retained between attempts. If package downloads still
fail, the helper tries the same files on the official `deb.debian.org` CDN.
The versions and required SHA256 hashes come only from the authenticated
snapshot indexes; no live CDN indexes are loaded. Missing files or hash
mismatches stop the build. Index failures have no CDN fallback.
The snapshot date and signature checks remain fixed; installation starts only
after all packages have downloaded and uses `--no-download`. This does not
recover an out-of-memory failure on the build runner.

## Set the release inputs

Set these GitHub Actions repository variables, or export them locally:

```sh
export STAGE_RGB_ASSET_ID='rgb:<new-public-signet-BFA-asset>'
export STAGE_TOKEN_CONTRACT='0x<approved-ERC20-address>'
export STAGE_ENDPOINTS_SHA256='<64-hex-digest>'
export STAGE_GAS_TX_ALLOWED_SELECTORS='0x<selector>,0x<selector>'
```

Use an asset issued on the BFA schema supported by this revision. Do not reuse
the old `BFA_RGB_ASSET_ID` variable for this profile. Verify the selectors against
the deployed Multisig ABI. `STAGE_GAS_TX_ALLOWED_SELECTORS` is required only for Burn.

Compute the endpoint digest with this revision's CLI, using the same endpoint
environment and CA file that will be supplied at launch:

```sh
utexo-bridge-parent-cli set-endpoints --print-sha256
```

This command does not contact an enclave. KMS inputs are excluded from the digest.
Both images can share the digest only when their chain endpoint inputs match.

Provide the existing `RGB_LIB_BFA_DEPLOY_KEY` and
`FEDERATED_SIGNER_PROTO_DEPLOY_KEY` secrets and the new
`RGB_PRIVATE_DEPS_TOKEN` secret. Keep credentials out of build arguments.

## Build

For Actions, choose `build_profile=stage-signet` and leave `debug_features` empty.
For local builds, configure Docker, Nitro CLI and private dependency access as
described in the repository README, then run:

```sh
BUILD_PROFILE=stage-signet DOCKERFILE=Dockerfile.enclave.mint \
  IMAGE_TAG=utexo-stage-signet-mint:local OUT_DIR=.artifacts/stage-signet/mint \
  EIF_NAME=utexo-bridge-enclave-mint.eif ./build/build-enclave.sh

BUILD_PROFILE=stage-signet DOCKERFILE=Dockerfile.enclave.burn \
  IMAGE_TAG=utexo-stage-signet-burn:local OUT_DIR=.artifacts/stage-signet/burn \
  EIF_NAME=utexo-bridge-enclave-burn.eif ./build/build-enclave.sh
```

The profile sets `BITCOIN_NETWORK=signet`, `BTC_RELAY_MODE=none`,
`EVM_CHAIN_ID=42161`, `RUST_LOG=debug`, the stage contract addresses and the
role-specific feature list without `rgb`/`spv`. It does not enable Nitro debug
mode, mock attestation or seed import.

Mint uses the recipe's `MINT_WITNESS_SAT=1500`; set the same value on the
connector. Its `RGB_MAX_UNOWNED_SATS` is 1500. The recipe's other limits remain
in effect, including `BTC_MAX_TOTAL_SATS=1000000` and the confirmation counts
(Mint 3, Burn 6). Review these before publishing a release.

The Burn profile pins gas destination to the stage Multisig and uses limits
of 3000000 gas, 1000000000 wei/gas and 5000000000000000 wei value.

## Locate and verify artifacts

Actions artifacts have a `-stage-signet` suffix. S3 bundles are written under:

```text
eif/<commit>/stage-signet/rgb-mint/
eif/<commit>/stage-signet/rgb-burn/
```

Verify the checksums, PCRs, `IMAGE-ENV.json` and `metadata.json` profile before
using a bundle. Archive the approved input values with that bundle; changing
repository variables at the same commit can produce a different measured image.
The upload workflow does not enforce write-once S3 storage.

The build profile does not configure deployment or KMS policies. In particular,
the current standard `verify-launch` expects a Production/SPV policy and must
be adapted before deploying an IndexerTrusted image through that launcher.
The current CLI requests EVM RPC at `/`; it does not read `EVM_RPC_PATH_FILE`.
