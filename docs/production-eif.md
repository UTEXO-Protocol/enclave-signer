# Production mainnet EIFs

`prod-mainnet` builds Mint and Burn for Bitcoin mainnet and Arbitrum One (42161).
The profile uses the role-specific release recipes, full mainnet SPV checks,
required BTC relay commitments, three Bitcoin confirmations and finalized EVM
receipts. It does not deploy infrastructure or activate signing identities.

## Measured build inputs

Set these variables in the GitHub Environment `production`, or export them for a
local build. There are no Stage/default asset or contract fallbacks:

- `PROD_MAINNET_RGB_ASSET_ID`: approved Bitcoin mainnet BFA contract ID.
- `PROD_MAINNET_MULTISIG_CONTRACT`: nonzero Multisig address; also Burn gas destination.
- `PROD_MAINNET_BRIDGE_CONTRACT`: nonzero BridgeProxy deposit-emitter address.
- `PROD_MAINNET_TOKEN_CONTRACT`: nonzero ERC-20 address.
- `PROD_MAINNET_GAS_TX_ALLOWED_SELECTORS`: comma-separated 4-byte on-chain selectors,
  required for Burn; check them against the deployed Multisig ABI.
- `PROD_KMS_ALLOWED_ACCOUNT_IDS`: comma-separated 12-digit seed KMS account IDs,
  required for Mint. Approve the whole list; changing it changes the Mint EIF.

Check the asset against its issuance manifest and supported schema. The profile
validates syntax, not on-chain deployments or the RGB contract. Moving AWS accounts
does not itself require issuing a different RGB asset. Contract and custody
approvals are separate from choosing the build profile.

The production profile fixes `RUST_LOG=info,alloy_transport_http=off`. Burn gas
ceilings are 3000000 gas, 1000000000 wei/gas and 5000000000000000 wei native value.
Review them against the intended routes before publishing. Recipe limits, including
Mint witness sats, remain in force; see [configuration](configuration.md).
Member RPC endpoints, private RPC paths, KMS key ARNs, TLS credentials and
`LZ_ROUTES` are launch settings, not production build inputs.

Local builds use the committed builder profile and existing build helper:

```bash
BUILD_PROFILE=prod-mainnet DOCKERFILE=Dockerfile.enclave.mint \
  OUT_DIR=.artifacts/prod-mainnet/mint EIF_NAME=utexo-bridge-enclave-mint.eif \
  ./build/build-enclave.sh

BUILD_PROFILE=prod-mainnet DOCKERFILE=Dockerfile.enclave.burn \
  OUT_DIR=.artifacts/prod-mainnet/burn EIF_NAME=utexo-bridge-enclave-burn.eif \
  ./build/build-enclave.sh
```

Export the approved inputs first. Host binaries still require the private proto
repository credential; the enclave build does not. See [building](building.md).

## GitHub and AWS prerequisites

Create the protected GitHub Environment `production`. Require reviewers, prevent
self-review where supported, and restrict workflow branches to the approved subset
of `dev`, `stage`, and `main`. Changes enter through `dev`; profile selection does
not require a separate Git branch. Production dispatches from other refs fail.
Do not store `PROD_*` credentials in repository-level settings where unreviewed
branches could access them. Production jobs read only explicitly named `PROD_*`
AWS settings and refuse incomplete configuration.

Environment variables for production artifact infrastructure:

- `PROD_AWS_ACCOUNT_ID`: expected account for artifact access.
- `PROD_AWS_REGION`: region containing the artifact bucket.
- `PROD_EIF_S3_BUCKET`: private production artifact bucket.

Environment secrets (role ARNs, not static AWS access keys):

- `PROD_AWS_OIDC_ROLE_ARN`: build artifact upload role.
- `PROD_EIF_RELEASE_READ_ROLE_ARN`: read-only artifact publication role.

`FEDERATED_SIGNER_PROTO_DEPLOY_KEY` supplies the existing parent build dependency.
Scope IAM OIDC trust to this repository's `production` environment and the AWS STS
audience. GitHub environment branch restrictions are essential: the environment
OIDC subject identifies the environment, not the source branch.

Keep upload and publication roles separate. Restrict S3 writes/reads to production
EIF paths. Terraform provisioning is a separate operation. These workflows do not
create a running TEE, KMS key or artifact bucket.

## Build and publish

1. **Build EIF:** select reviewed workflow code and `prod-mainnet`. Both roles must
   succeed. The workflow requires production AWS settings and uploads bundles to
   `eif/<commit>/prod-mainnet/rgb-mint/` and `rgb-burn/`. An upload failure fails
   the production build. Do not rerun a different set of measured inputs under an
   already approved commit/profile path; use a new source revision.
2. **Publish EIF Release:** select `prod-mainnet`, the approved source branch,
   full commit SHA, successful Build EIF run ID, and a new tag `prod-mainnet-vX.Y.Z`.
   The source commit must belong to the selected branch. Publication compares S3
   against that run's artifacts and the toolchain from the source revision.
   It uploads a draft, downloads and verifies every asset, then publishes a stable
   release and marks it latest. Stage releases remain prereleases and never change
   latest. GitHub latest is repository-wide; approve production versions in order.

## Deployment scope

`release-eif.yml` supports the existing `stage` and `release-test` environments.
It deploys one role and CID from the unprofiled `eif/<commit>/rgb-<role>/` path.
It does not deploy the `prod-mainnet` bundles published by this profile.
Production host provisioning and workflow deployment support remain separate work.

Before activating a production signer, configure its launch settings, approve its
PCRs and Mint KMS policy, verify live attestation and the complete identity map,
and register the approved identity. Mint rights and listeners are separate
activation steps. A published release alone is not proof of bridge readiness.

The release includes role archives, standalone PCR files, `release-manifest.json`,
`SHA256SUMS`, and the approved `toolchain.json`. The notes show the asset ID,
source revision and measurements. Publication does not prove a live deployment
or independently reproduced PCRs. See [operations](operations.md),
[Mint custody](mint-release.md) and [identity verification](verify-a-signer.md).
