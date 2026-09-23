# Temporary BFA stage

Branch: `stage-bfa-seed-import-temp`, based on `fix/clone-audit`.
All temporary code, recipes and scripts live here. The shared source has feature-gated entry points.
The only changed workflow is `.github/workflows/build-eif.yml` on this branch.

## Purpose

Keep the same three signer identities when the BFA asset ID changes the EIF.
Create three retained seeds once. Import one into each donor CID. Clone the matching requester.
Give the asset issuer the public key set. Rebuild with the issued asset ID, then restore the same seeds.

This is a **Development** custody model. An authorized SSM/KMS operator can read the seeds.
It is not proof that private keys were born inside Nitro.
Do not use it as a production audit closure.

## Build modes

Edit the public `config.json` before dispatch:

- `bootstrap`: empty `rgb_asset_id`. Allows key setup, cloning and validated vanilla `SignBtc` for UTXO preparation.
  Rejects bridge signing, raw EVM signing, CCD signing and federation proxy requests.
- `configured`: the issued BFA `rgb_asset_id`. Enables the existing BFA signing checks.

The mode is compiled into the binary. The asset is baked into the Docker environment.
Runtime environment changes cannot enable business signing in a bootstrap binary.
The optimized `stage-bfa-temp` Cargo profile keeps debug assertions enabled.
`stage-bfa-temp` enables `vsock`, `bfa-mint`, `allow-seed-import` and `allow-debug-pcrs`.
`dev-mode` and `mock-attestation` are forbidden. NSM attestation remains real.
The ordinary release profile still rejects seed import.

The recipe uses Bitcoin mainnet and Arbitrum One (42161).
`BTC_MAX_UNOWNED_SATS=10000` limits unowned outputs in BTC signing.
`RGB_MAX_UNOWNED_SATS=10000` sets the separate limit for RGB signing.
Both values are baked into the EIF. Rebuild and restore the retained stage seeds to apply changes.
The contract pins use the stage set supplied on 2026-09-22:
- `EVM_PROXY_CONTRACT_ADDRESS`: Multisig `0x0584f124d56266c3583605a441545d48feea9b9e`.
- `GAS_TX_ALLOWED_TO`: Multisig `0x0584f124d56266c3583605a441545d48feea9b9e`. Gas transactions call the Multisig proxy.
- `FUNDS_IN_CONTRACT`: BridgeProxy `0x9f447017ca5f413dc86d9d69c772e9dfe16fb823`.

The current build mode is `configured` with asset `rgb:0xCZMKww-~LBSYFG-b_q5Vak-Yn1pgIc-P7UVc9m-EUOJ0mc`.
Restore the retained stage seeds after deployment and compare all signer keys.
The FundsIn event signature is `FundsIn(address,uint256,uint64)`.
Verify the new asset's genesis `bridgeLocation` before enabling bridge operations.
The backend RGB network ID is a separate setting. Configure it during the listener rollout.

## Manual build

1. Push this branch after review.
2. Open the existing **Build EIF** workflow.
3. Select **stage-bfa-seed-import-temp** in **Run workflow**.
4. Leave `debug_features` empty. `allow-debug-pcrs` is already enabled.
5. Retain the complete artifact and its manifest hash.

The workflow tests the stage profile, forbidden feature combinations and file-only CLI input.
It produces a matched EIF, Parent and CLI bundle.
It does not deploy services or accept seeds.
Artifacts use `stage-bfa-temp-<sha>-<run>-<attempt>`.
S3 uses `stage-temp/bfa/<sha>/<mode>/<run>-<attempt>/`.
Check the existing OIDC role trust and S3 prefix permissions before dispatch.
No default-branch change is needed for this existing workflow's branch dispatch.

For a local build, set `PRIVATE_DEPS_DIR` or `GITHUB_TOKEN`, then run:

```bash
bash stage-temp/bfa/scripts/build.sh
```

Use the pinned Nitro CLI version from the workflow. Build Parent and CLI with the same source revision.
CI adds their checksums and `metadata.json`. `BUNDLE-SHA256SUMS` covers all bundle files.
Debug runtime PCRs are zero. Retain the EIF measurements separately; zero PCRs do not identify a release.

## Retained keys

Use a dedicated SSM prefix `/utexo/stage-temp/bfa/<keyset-name>` and a protected KMS key.
Give the key operator access to that prefix. CI, the hub and listeners do not need seed access.
Restrict parameter deletion and KMS key deletion. Verify recovery before issuing the asset.
Retain an approved encrypted backup under the team's key custody procedure.

Run once from the authorized operator environment:

```bash
python3 stage-temp/bfa/scripts/seed_store.py \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" --account-id "$STAGE_ACCOUNT_ID" \
  --prefix "$KEYSET_PREFIX" create --kms-key-id "$KMS_KEY_ID" \
  > keyset-versions.jsonl
```

The script checks the AWS account. It stores separate seeds for CID 16, 18 and 20.
Each SecureString holds the seed and its donor cloning secret. Values go through stdin, not argv.
Existing parameters are never overwritten. The output contains only names, CIDs and versions.
After a partial failure, preserve existing parameters. Use `create --cid <missing-CID>` only for a missing record.
Never create a replacement keyset just because an import failed.

On the donor host, import each exact recorded version:

```bash
python3 stage-temp/bfa/scripts/seed_store.py \
  --region "$AWS_REGION" --account-id "$STAGE_ACCOUNT_ID" --prefix "$KEYSET_PREFIX" \
  restore --cid 16 --version "$SIGNER_16_VERSION" --cli "$BUNDLE/utexo-bridge-parent-cli"
```

Repeat for CID 18 and 20. The EC2 identity must have the required SSM/KMS access.
The script uses private files under `/dev/shm`, then removes them.
Do not enable shell tracing, AWS debug logging or core dumps for key operations.
Secrets still exist in authorized host process memory during import.

The direct CLI command is `init-stage-seed --seed-file <file> --cloning-secret-file <file>`.
It sends seed and cloning secret in one `InitializeKey` call.
The files must be private regular files, not symlinks.
A second initialization is refused. The stage gate also refuses random `init` and mnemonic import.

## Host switch

Download the bundle into `/home/ubuntu/stage-temp-solution-bfa/<build>/`.
Copy this branch's `stage-temp/bfa/scripts/` into a separate scripts folder on the host.
Obtain the approved `BUNDLE-SHA256SUMS` hash from the trusted build artifact.

```bash
python3 scripts/deploy_host.py "$BUNDLE" --manifest-sha256 "$MANIFEST_SHA256"
```

The default is preflight only. It checks every bundle file, EIF measurements, all three CIDs and TLS paths.
Pause business traffic, preserve the current identity report and confirm retained key recovery before applying:

```bash
sudo python3 scripts/deploy_host.py "$BUNDLE" --manifest-sha256 "$MANIFEST_SHA256" \
  --apply --traffic-paused
```

The script uses the existing `utexo-enclave@` and `utexo-parent@` units and wrappers.
It writes only `stage-bfa-temp.conf` drop-ins and `/etc/utexo/stage-temp-solution-bfa/<timestamp>/` configs.
It preserves Parent TLS, ACLs, ports and network routing values.
It sets the temporary EIF, matching Parent directory and debug runtime.
It does not change proxies, listeners or hub data.
A successful switch leaves keys empty. Import or clone before routing traffic.
If it fails after stopping services, keep traffic paused and inspect the saved configs.

## Clone and identity gates

Use the matching CLI on the requester with the current mTLS client certificate and donor endpoint:

```bash
"$BUNDLE/utexo-bridge-parent-cli" --addr vsock://16:5000 clone \
  --cloning-secret-file "$CLONE_SECRET_FILE" \
  --donor-grpc "$DONOR_GRPC" --donor-evm "$DONOR_EVM"
```

Use the retained cloning secret for the corresponding donor. Deliver it through the existing protected-file path.
Never pass the seed to `clone`. Repeat for CID 18 and 20.
Both hosts must use the same mode, asset, Bitcoin network and EIF.
The CLI must report that all 13 identity fields match.
Keep signed attestation verification separate from a public key comparison.

Capture a public report on each host:

```bash
python3 scripts/identity.py capture --cli "$BUNDLE/utexo-bridge-parent-cli" > identity.json
python3 scripts/identity.py compare donor.json requester.json --same-image
```

Before issuance, restart and restore all three donor seeds once. Compare with the saved bootstrap report.
After the final asset rebuild, compare bootstrap and configured reports without `--same-image`.
All key fields must match. Asset and image policy fields change by design.
Then compare donor and requester with `--same-image` and retain the CLI clone result.

## Hub, listener and rollback

Give the issuer the ordered fingerprints, vanilla/colored xpubs and agreed thresholds.
An enclave can provide keys without a listener. Creating funded colorable UTXOs through the hub needs working cosigners.
Use the new BFA hub. Keep the old hub untouched.
Configure the new hub and its listener wallets for the retained keyset before issuance.

After issuance, preserve hub DB, wallets, descriptors, UTXOs and consignments on every EIF rebuild.
Restoring seeds does not restore wallet history or bridgeRight state.
Do not reset a live BFA wallet when its keys stay the same.
Do not replace the keyset without a proven bridgeRight migration.

To roll back an image, apply its approved bundle with the same script, then restore the same seeds and verify keys.
A normal production EIF cannot import these retained seeds. Rolling back binaries alone does not restore identity.
Never discard the last working retained-key configuration before checking recovery.
The RGB crate pins remain those of the audit branch. Live compatibility with the issuer's rgb-lib beta.41 BFA asset
still needs a real consignment and accepted mint/burn test before this deployment is operational.
