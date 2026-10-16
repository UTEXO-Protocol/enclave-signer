# Deploy Mint and Burn on existing Nitro hosts

This procedure uses `deploy/deploy-host.sh` from the same commit as the EIFs.
It supports 1-4 Mint/Burn enclaves per x86_64 Ubuntu host, with at most one Mint.
Run host commands as root. Python 3.9+, AWS CLI, Nitro CLI, OpenSSL, systemd,
`ip`, `ss`, `flock` and `/usr/bin/vsock-proxy` must be installed.

**`--apply` is a cold restart. Burn keys in memory are lost.** Remove these
signers from traffic and confirm their recovery/replacement procedure first.
Mint recovers through its existing KMS/S3 seed and approved address pin.
Configuration backups do not contain enclave keys. There is no automatic init,
clone, traffic switch or key rollback.

## 1. Build and approve both bundles

Build the reviewed commit through `build-eif.yml`. Record the full commit SHA,
approved image settings, EIF SHA-256 and PCR0/PCR1/PCR2 for each role.
The artifact bucket must contain:

```text
eif/<commit>/rgb-burn/
eif/<commit>/rgb-mint/
```

Each directory contains `utexo-bridge-enclave-<role>.eif`, `PCR.json`,
`IMAGE-ENV.json`, `metadata.json`, `SHA256SUMS`, `utexo-bridge-parent`,
`utexo-bridge-parent-cli` and `HOST-SHA256SUMS`.
Use the matching Parent/CLI from each bundle. Keep artifact publishing restricted
to the reviewed build pipeline. Checksums prove consistency, not publisher trust.
The Mint seed bucket is separate from this artifact bucket.

## 2. Prepare each host's configuration

Create `/etc/utexo/deploy-config` with root ownership and mode `0700`.
Copy only the required pairs from `deploy/config.example/` into this directory.
The examples deliberately have empty required values and cannot be deployed as-is.

For each desired CID, prepare:

- `enclave-<CID>.env`: role, CPU/memory, RPC/SPV and Mint-only KMS launch values.
- `parent-<CID>.env`: private bind IP, unique gRPC/health ports, matching vsock CID,
  TLS paths, header source and Mint-only seed broker settings.
- `image-burn.env` / `image-mint.env`: approved baked-in settings for each role
  present on that host. Copy the complete approved release ENV values, not values
  obtained from an unapproved download.

Use literal `KEY=value` lines: no quotes, shell expansion or placeholder values.
The deployer sets the EIF, CLI, PCR, IMAGE_ENV and Parent CLUSTER_DIR paths.
Duplicate an example pair to add a CID, updating its filename, CID and ports.
Remove unused example pairs; every `enclave-*.env` file is a deployment target.

For two local Burn identities and one Mint identity, with a full standby host:

```text
Host A: Burn 1 CID 16; Burn 2 CID 18; Mint CID 24 (primary)
Host B: Burn 1 CID 16; Burn 2 CID 18; Mint CID 24 (standby)
```

CIDs and ports may repeat on different hosts. Each host needs its own TLS server
certificates and private-IP bind. In a 3-of-4 federation, the other two Burn
identities belong to external operators; standby replicas add no votes. Route
each identity through one active copy at a time.

List any old instances to remove in `retire-cids`, for example `20` on one line.
Include enabled old instances even if currently stopped. Omit this file on a
fresh host. Unknown running/enabled CIDs cause preflight failure.

Prepare these dependencies before preflight:

1. Configure `/etc/nitro_enclaves/allocator.yaml` explicitly with `cpu_count`
   and `memory_mib`. On an 8-vCPU host, keep at least two vCPU for the host;
   use even CPU allocations per enclave. Three enclaves at 2 vCPU/3072 MiB
   need a pool of at least 6 vCPU/9216 MiB. Reserve at least 2048 MiB host RAM.
   Changing the allocator on a live host is a separate maintenance operation.
2. Install [Parent mTLS](parent-mtls.md) certificates and ACLs. The server SAN
   must include the private bind IP. Allow `ubuntu` to read the files; keep
   private keys `0600`. Certificates must have at least 24 hours remaining.
3. Install the EVM RPC CA as DER and the authenticated path (for example
   `/v3/<provider-key>`) in the configured files. RPC path: `0600`, readable by
   `ubuntu`. Use `/` for an endpoint without a provider path. Do not put provider
   credentials in the EIF or git. All CIDs on a host share RPC/Electrum relays.
4. Set both Electrum URLs to the same `ssl://host:port`. If the provider uses an
   allowlist, add this host's egress IP. Permit HTTPS to the EVM RPC, S3 and KMS
   endpoints. Preflight verifies Electrum TLS; actual SPV sync is checked later.
5. For Mint, configure [KMS persistence](kms-persistence.md), the EC2 IAM role,
   KMS attestation conditions for the approved Mint PCRs and S3 object access.
   `KMS_ALLOWED_CIDS` must contain only this host's Mint CID; broker port is 8004.
   Leave `KMS_EXPECTED_EVM_ADDRESS` empty only for first bootstrap with no seed
   object. For recovery, use the previously verified address and existing object.
   Preflight checks object existence/access, not attested KMS crypto permissions.

Protect configuration files with mode `0600`. Do not put any KMS variables in
Burn configs. Use `RUST_LOG=debug` for this stage rollout; it does not enable
Nitro debug mode, zero PCRs or seed import.

## 3. Run preflight on every host

From the reviewed source checkout, replace the following values:

```bash
export GIT_SHA=<full-approved-commit-sha>
export BUCKET=<artifact-bucket>
export AWS_REGION=<host-region>
export CLUSTER_DIR=/opt/utexo/releases
export DEPLOY_CONFIG_DIR=/etc/utexo/deploy-config
bash deploy/deploy-host.sh
```

Without `--apply`, no service is stopped and no runtime config is replaced.
Preflight downloads temporary bundles, verifies their hashes, metadata, image
settings and EIF measurements, and checks host resources, TLS files, ports,
authenticated RPC chain/response and Mint seed object presence. Temporary bundle
files are deleted on exit. Fix every failure before proceeding on either host.

For GitHub Actions, set repository variables `AWS_REGION`, `EIF_S3_BUCKET`,
`CLUSTER_DIR`, `DEPLOY_CONFIG_DIR`, and secrets `AWS_DEPLOY_OIDC_ROLE_ARN` and
`STAGE_INSTANCE_IDS`. The deploy role needs SSM SendCommand/GetCommandInvocation;
the hosts need artifact S3 GetObject. Dispatch **Release EIF (deploy)** with the
approved SHA and `apply=false`. The workflow ships deploy sources from that SHA.

## 4. Apply the cold deployment

After all hosts pass preflight and the identity recovery plan is approved:

```bash
bash deploy/deploy-host.sh --apply
```

Or dispatch the workflow with `apply=true` and exactly one instance ID.
Multi-host preflight is supported, but multi-host cold apply is rejected.
Recover/clone the deployed host and verify all identities and readiness before
touching another host. The workflow does not do this recovery automatically.

For the first Mint bootstrap, deploy Host A first, initialize Mint and record its
verified address. Put that address in both hosts' source configs and Host A's
installed launch config. Only then deploy Host B and recover the same S3 seed.
Do not initialize Mint independently on both hosts. Authorize both EC2 roles for
the same seed and approved Mint PCRs.

A failed apply has no automatic rollback. For existing Burn identities, keep a
matching live donor until its replica is verified. A new EIF with different PCRs
may be incompatible with cloning; agree the migration procedure before restart.

The deployer preserves prior config files under
`$CLUSTER_DIR/config-backups/<timestamp>/`, installs immutable role bundles under
`$CLUSTER_DIR/$GIT_SHA/{burn,mint}/`, stops declared old units, writes per-CID
configurations and disables retired units. It installs Electrum/EVM TLS relays
on ports 8001/8002; the KMS relay on 8003 runs only on the Mint host.

Each enclave receives `SetEndpoints` and `verify-launch` before its Parent starts.
PCR0/PCR1/PCR2 are checked again against the running instances. A startup failure
stops the newly configured instances. Do not interpret `PROCESSES STARTED` as
readiness or identity approval.

## 5. Initialize or recover, then approve traffic

1. Follow [key management](../README.md#keys) for each Burn identity.
   For the example above, initialize two local identities on Host A and clone each
   to its corresponding CID on Host B. The other two federation members are
   operated externally. The same identity must match on both local hosts.
   Prepare the clone-operator mTLS certificate and donor ACL before remote cloning.
2. Initialize/recover Mint through [KMS persistence](kms-persistence.md).
   After the first init, record its verified address in the approved identity map
   and set `KMS_EXPECTED_EVM_ADDRESS` in both the source config and installed
   `/etc/utexo/enclave-<CID>.env` for its next restart. Do not restart to set the pin.
3. For every Parent, require HTTP 200 from its local `/health` endpoint and inspect
   header-sync status. An empty key or unsynced Burn chain must remain out of routing.
4. Verify each host's **complete** approved identity map:

```bash
ENCLAVE_ENV_DIR=/etc/utexo CIDS="16 18 24" \
EXPECTED_EVM="16=0x<burn-1-address> 18=0x<burn-2-address> 24=0x<mint-address>" \
bash deploy/verify-identity.sh
```

Use the same approved identity map on both hosts for these three identities. The script rejects missing
or extra approvals. Burn exports attestation bundles using its role-specific
PCR/ENV files. Mint address comparison is structural, not an offline attestation;
retain its separate launch/KMS evidence. See [signer verification](verify-a-signer.md).

5. Verify each listener's mTLS connection to the intended Parent and only then
   enable its route. `--liveness` is diagnostic and must never authorize routing.

## Failed deployment or rollback

Keep routes disabled. Inspect the failed SSM command, systemd journal and
`nitro-cli describe-enclaves`. For rollback, select the previously approved source
commit, role bundles and backed-up configs, review endpoint/KMS compatibility and
run preflight again. Restoring files does not restore volatile Burn keys. Recover
from a surviving matching signer or follow the approved replacement/registration
procedure. Recover Mint using its original KMS key, seed context and identity pin.
