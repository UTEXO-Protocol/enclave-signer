# Stage EIF build profiles

Choose `stage-signet` or `stage-mainnet` in **Build EIF**, or set
`BUILD_PROFILE` with `build/build-enclave.sh`. Both profiles build Mint and Burn.
Tag builds and the `default` profile use the recipe defaults.

- `stage-signet`: public Bitcoin Signet, without SPV, relay disabled,
  Development policy.
- `stage-mainnet`: Bitcoin mainnet, with SPV, relay required,
  Production policy. Stage names the deployment environment, not the Bitcoin
  network. It does not enable debug attestation or relax mainnet checks.

Changes go through `dev` first, then are promoted to `stage`. A profile is not
a Git branch. Build the approved source revision with the matching profile.

Both recipes fix `SPV_MIN_CONFIRMATIONS=3` and `EVM_FINALITY_TAG=finalized`, so
the profile does not set them and the caller's environment cannot change them.

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

## Signet release inputs

Set these GitHub Actions repository variables, or export them locally:

```sh
export STAGE_RGB_ASSET_ID='rgb:<public-signet-BFA-asset>'
export STAGE_TOKEN_CONTRACT='0x<approved-ERC20-address>'
export STAGE_GAS_TX_ALLOWED_SELECTORS='0x<selector>,0x<selector>'
```

Use an asset issued on the BFA schema supported by this revision. Do not reuse
the `BFA_RGB_ASSET_ID` variable of the `default` profile. Verify the selectors against
the deployed Multisig ABI. `STAGE_GAS_TX_ALLOWED_SELECTORS` is required only for Burn.

Mint also needs `KMS_ALLOWED_ACCOUNT_IDS`, as every mint image does. The workflow
reads it from the repository variable of that name. A local build must export it.

Endpoints are launch configuration, not build inputs. Members can use different
endpoint hosts, ports and CA files with the same EIF for a given role and
release. Supply the approved values through `cli set-endpoints` after launch,
keeping each provider's API-key path in a restricted `EVM_RPC_PATH_FILE`.
Rotating that file requires a new launch, not a new image.

Provide the `RGB_LIB_BFA_DEPLOY_KEY` and `FEDERATED_SIGNER_PROTO_DEPLOY_KEY`
secrets. Keep credentials out of build arguments.

## Mainnet release inputs

Set separate repository variables (or export locally); there is no fallback to
`STAGE_*` Signet inputs or `BFA_RGB_ASSET_ID`:

```sh
export STAGE_MAINNET_RGB_ASSET_ID='rgb:A6Nr_ndv-Cx_t3_i-YfPXoL6-pT8ibp3-CR6LH5q-fQvTsp8'
export STAGE_MAINNET_TOKEN_CONTRACT='0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9'
export STAGE_MAINNET_GAS_TX_ALLOWED_SELECTORS='0xd8220faf,0x8f6b3031'
```

The asset above is the issued mainnet BFA.8 BUSDT contract for this Stage
release. The wrapper validates the input format; it does not fetch the RGB
contract or prove its network/schema. Confirm the asset against the issuance
manifest before building a different release.

Selectors are the on-chain `fundsOutCall` and `lzFundsOutCall` methods, not
internal enclave wire selectors. Verify them against the deployed Multisig ABI
before publishing. The selector variable is required only for Burn.
`KMS_ALLOWED_ACCOUNT_IDS` and the dependency secrets described above are also
required for the appropriate role.

`stage-mainnet.sh` fixes these measured settings:

```text
BITCOIN_NETWORK=bitcoin
BTC_RELAY_MODE=required
EVM_CHAIN_ID=42161
EVM_PROXY_CONTRACT_ADDRESS=0x8ed92cd8c14b5ee2e006fcd7c24f000c87e72495
FUNDS_IN_CONTRACT=0xc16c969955343f0f7528bc0bccd09aaa7b5b4e34
RUST_LOG=debug,alloy_transport_http=off
```

`EVM_PROXY_CONTRACT_ADDRESS` and Burn's `GAS_TX_ALLOWED_TO` point to **Multisig**;
`FUNDS_IN_CONTRACT` points to **BridgeProxy**. Both roles compile with `vsock,spv`
and exactly their own signer feature. Mint includes KMS persistence through
`mint-signer`. The recipes fix `SPV_MIN_CONFIRMATIONS=3` and
`EVM_FINALITY_TAG=finalized`. Debug logging does not enable dev features.

The mainnet BTC relay contract for the bridge/relayer is
`0x0f6BA373BcCc176c290b2dEE1A3cF87243588fC5`. Its address is not an enclave build
input: `BTC_RELAY_MODE=required` validates relay commitments against the enclave's
SPV records. Building this profile does not deploy or start the relayer.
The asset's reject list is encoded in its RGB contract, not a separate EIF input.

Mint retains `MINT_WITNESS_SAT=1500`, `BTC_MAX_TOTAL_SATS=1000000` and the other
recipe limits. Burn pins its gas destination to Multisig and caps gas at
3000000, fees at 1000000000 wei/gas and native value at 5000000000000000 wei.
Use a mainnet indexer at launch and configure Parent header synchronization
(`HEADER_ELECTRUM_URL`), mTLS and Mint KMS/storage before taking traffic; see
[operations](../../docs/operations.md) and
[KMS persistence](../../docs/kms-persistence.md).

## Build

For Actions, choose the intended `build_profile`: `stage-signet` or `stage-mainnet`.
For local builds, configure Docker, Nitro CLI and private dependency access as
[docs/building.md](../../docs/building.md) describes, then run:

```sh
BUILD_PROFILE=stage-signet DOCKERFILE=Dockerfile.enclave.mint \
  IMAGE_TAG=utexo-stage-signet-mint:local OUT_DIR=.artifacts/stage-signet/mint \
  EIF_NAME=utexo-bridge-enclave-mint.eif ./build/build-enclave.sh

BUILD_PROFILE=stage-signet DOCKERFILE=Dockerfile.enclave.burn \
  IMAGE_TAG=utexo-stage-signet-burn:local OUT_DIR=.artifacts/stage-signet/burn \
  EIF_NAME=utexo-bridge-enclave-burn.eif ./build/build-enclave.sh
```

For a local mainnet build, replace `stage-signet` with `stage-mainnet` in the
commands above (profile, image tag and output directory), and export the mainnet
release inputs.

The **Signet** profile sets `BITCOIN_NETWORK=signet`, `BTC_RELAY_MODE=none`,
`EVM_CHAIN_ID=42161`, `RUST_LOG=debug,alloy_transport_http=off`, the stage
contract addresses and the role-specific feature list without `spv`.
The log filter keeps debug logs but disables Alloy HTTP transport logs, which
can include private RPC paths or response bodies. It does not enable Nitro
debug mode, mock attestation or seed import.

`EVM_CHAIN_ID=42161` is Arbitrum One mainnet, so the stage burn signers sign
real mainnet releases. Without `spv` they trust the indexer, so a compromised
stage host can report forged burns and release up to the stage Bridge's
outflow limits. Keep the stage token without market value (see the "Builds
without `spv`" limit in [tee-spec.md](../../docs/tee-spec.md#10-known-limits)).

Mint uses the recipe's `MINT_WITNESS_SAT=1500`; set the same value on the
connector. The recipe's other limits remain in effect, including
`BTC_MAX_TOTAL_SATS=1000000`. The recipes fix the confirmation setting at 3;
Burn enforces it for witness transactions, while Mint does not read it for
signing. Review these limits before publishing a release.

The Burn profile pins gas destination to the stage Multisig and uses limits
of 3000000 gas, 1000000000 wei/gas and 5000000000000000 wei value.

## Locate and verify artifacts

Actions artifacts have a `-stage-signet` or `-stage-mainnet` suffix. S3 bundles
are separated by profile:

```text
eif/<commit>/stage-signet/rgb-mint/
eif/<commit>/stage-signet/rgb-burn/
eif/<commit>/stage-mainnet/rgb-mint/
eif/<commit>/stage-mainnet/rgb-burn/
```

Verify the checksums, PCRs, `IMAGE-ENV.json` and `metadata.json` profile before
using a bundle. Archive the approved input values with that bundle; changing
repository variables at the same commit can produce a different measured image.
The upload workflow does not enforce write-once S3 storage.

Use [Publish EIF Release](../../docs/github-releases.md) with the same profile
to publish the existing build and its PCRs.

Neither build profile configures deployment or KMS policies. The mainnet
profile uses the Production/SPV policy expected by `verify-launch`. The
Signet profile uses IndexerTrusted validation and needs a launcher adapted
for that policy.
The no-SPV policy is Development: its real attestation identifies the
image and key, but does not attest endpoint or KMS launch settings. Operators
approve those settings externally. Runtime TLS authenticates the configured
provider; it does not enforce that external approval or prove its answers.
