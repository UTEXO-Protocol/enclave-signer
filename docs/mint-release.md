# Mint release configuration and validation

`Release EIF (deploy)` deploys an already published Mint or Burn image. For Mint,
it reads an **operator-provisioned JSON file on each target host**. The file binds
settings to a role and CID; it is not executed as a shell script. The workflow
sends only its path and the explicit bootstrap/recovery mode over SSM.

This does not initialize an identity, approve new PCRs, register keys or enable
Bridge traffic. Those are separate acceptance steps in [operations.md](operations.md)
and issue #249. Deploying an enclave clears its in-memory keys.

## Prerequisites (before running release)

1. Publish the approved matching `rgb-mint` EIF, Parent/CLI and manifests to S3.
   Approve its measurements and policy; do not use debug mode. Confirm the image's
   `KMS_ALLOWED_ACCOUNT_IDS` includes the key's account.
2. Provision a dedicated symmetric KMS key, protected seed bucket in the same
   region, and an EC2 instance role using the [KMS policy requirements](kms-persistence.md#aws-permissions).
   Scope storage permissions to this signer. Require recipient attestation and
   the exact context (`application`, `flow`, `seed_id`, `bitcoin_network`).
   `GenerateDataKey` is allowed only during first bootstrap; recovery needs
   `Decrypt`. Preserve S3 versions and reject overwrite/unconditional writes.
   No deploy script changes these policies.
3. Configure IMDSv2, HTTPS egress to KMS/S3, Nitro capacity, RPC proxies/CA,
   per-CID mTLS certificates and ACLs. The Parent service user is `ubuntu`; its
   AWS credentials must come from the intended instance role. Do not put static
   AWS credentials in the release JSON or the service user's AWS files.
4. On each host, provision the KMS relay once as root:

   ```bash
   KMS_REGION=eu-central-1 bash deploy/host-prep-kms.sh
   ```

   This creates `vsock-proxy-kms.service`: vsock 8003 to the regional KMS HTTPS
   endpoint, with TLS still terminating inside the enclave. It refuses a
   different/incomplete existing configuration and does not restart an active
   matching service. An existing differently named proxy must be reconciled
   explicitly; never run two relays on port 8003.
5. Reserve **one Mint Parent/broker per host**, on vsock 8004. Burn Parents do not
   receive custody settings. Mint replicas go on separate hosts. Deployment
   rejects other per-CID Parent configs containing broker settings, including
   stale configs; archive retired configs only after checking they are unused.

## Per-signer configuration

Create `/etc/utexo/release-config/mint-24.json` on each target host, under a
root-owned directory. Make the file root-owned, mode `0600`. Replace the sample
key, bucket, seed id and local paths with approved inputs:

```json
{
  "signer_role": "mint",
  "enclave_cid": 24,
  "settings": {
    "KMS_KEY_ARN": "arn:aws:kms:eu-central-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    "KMS_REGION": "eu-central-1",
    "KMS_SEED_ID": "mint-signer-1",
    "KMS_S3_BUCKET": "example-mint-seeds",
    "KMS_S3_KEY": "mint/signer-1/seed.kms",
    "KMS_EXPECTED_EVM_ADDRESS": "",
    "ELECTRUM_URL": "ssl://approved-electrum.example:60602",
    "EVM_RPC_TLS_CA_DER_FILE": "/etc/utexo/rpc-ca.der",
    "EVM_RPC_PATH_FILE": "/etc/utexo/private-rpc-path"
  }
}
```

The blank address is for first bootstrap only. Before recovery, replace it with
this signer's approved `0x` EVM address obtained from verified bootstrap evidence.
Never obtain an approval pin by trusting an arbitrary live `get-keys` response.
`KMS_SEED_ID` and storage path identify the same signer on every replica.

The JSON takes precedence over caller settings. When selected, it supplies the
complete KMS configuration; missing fields cannot inherit stale caller values.
Unknown/duplicate keys, a mismatched role/CID, symlinks, writable or non-root-owned
files and shell syntax are rejected. Values are plain strings, not shell
expressions. No tokens, private keys or seed material belong in this file; RPC
credentials remain in a restricted file referenced by path.

Supported CIDs are 16, 18, 20, 24. CID 24 uses Parent 50055 and loopback health
50065. This does not increase the Nitro enclave or CPU/memory limits of a host.

## First bootstrap

1. Select **one target host**, the approved artifact SHA, `signer_role=mint`,
   `enclave_cid=24`, `deployment_config=/etc/utexo/release-config/mint-24.json`,
   and **`mint_mode=bootstrap`** in `Release EIF (deploy)`.
2. Before modifying services, deploy validates the custody configuration, checks
   the matching proxy is active and lists the exact S3 prefix as `ubuntu`.
   An existing object or denied/failed lookup stops deployment. It neither
   creates nor decrypts an object. KMS attestation authorization and conditional
   S3 writes are finally exercised by `init`, not proved by this preflight.
3. After successful launch-role/PCR verification, run Mint `init` following
   [KMS persistence](kms-persistence.md). Record and verify the public identity.
   Verify the ciphertext was saved, then set the approved address in every
   replica's release JSON. Never copy a plaintext seed.
4. Remove bootstrap `GenerateDataKey` permission and test recovery on a separate
   replica before funding/activating the identity.

## Recovery or update

Use `mint_mode=recovery` (default), with the approved nonzero address pin.
Deployment requires an existing, readable, nonempty ciphertext object. It writes
KMS launch values and the matching Parent storage settings for this CID only;
`KMS_ALLOWED_CIDS` is restricted to that CID. It preserves peer services/configs.
After launch verification, invoke `init` to recover and attest the same identity.
A failed KMS call, absent object or wrong address must never trigger fresh init.

For a new Mint image, approve its PCRs in the key policy/verifiers first. Preserve
the key ARN, seed id, network, storage object and approved identity. Rollback
requires retained compatible artifacts and permitted old PCRs, followed by
recovery of the same identity. No automatic rollback or traffic activation is
performed. A Burn image upgrade has a different identity lifecycle; follow
[restart and upgrade](operations.md#restart-and-upgrade), not the Mint procedure.

## Isolated validation before using working Stage

Local regression tests run the deployment against stub AWS/Nitro/systemd tools:

```bash
python3 -m unittest discover -s build/tests -v
```

For hardware acceptance, configure the GitHub environment **`release-test`**
with variables `RELEASE_TEST_AWS_REGION`, `RELEASE_TEST_EIF_S3_BUCKET`,
`RELEASE_TEST_CLUSTER_DIR` and secret `RELEASE_TEST_DEPLOY_OIDC_ROLE_ARN`.
These separate names prevent fallback to repository-level Stage settings. Restrict this role's SSM permissions to the disposable
instances and its OIDC trust to `environment:release-test`; it must have no
access to working Stage instances or seed storage. Set required reviewers for
this environment. These AWS/GitHub prerequisites are administrator work, not
created by the workflow. Stage continues using its existing environment.

Create a separate disposable namespace/VPC and fresh
Nitro host(s), role, KMS key and seed bucket. Do not select working Stage instance
IDs, its KMS key/object or its Bridge/listeners. Keep the target instance list
explicit and select `deployment_environment=release-test`. This environment
rejects a blank instance list and never falls back to `STAGE_INSTANCE_IDS`. The
selected environment's region may be different from Stage's.

- Deploy a Burn peer, record its identity/config/service state, then deploy Mint
  at another CID using the same supported release path. Preserve the Burn peer.
- Exercise incomplete config, missing/wrong proxy, denied S3, bootstrap with an
  existing object and recovery with a missing object/pin; verify no selected or
  peer service was stopped. Run failure cases against the isolated hosts only.
- Bootstrap one Mint identity; verify persistence and attestation. Recover it on
  the second host and compare the full approved keyset. Reject wrong PCR/context
  and wrong expected address without writing/replacing the seed.
- Record source SHA, artifact checksums/PCRs, role/CID mapping and outcomes. Mock
  tests do not establish real IAM/KMS/Nitro correctness.
- Backend routing, xpub/on-chain registration, genuine Mint/Burn transactions,
  opposite-role rejection and verifier compatibility remain separate #249 tests.
- Retire only the disposable resources once evidence is saved. Never destroy
  working signer resources or copy their ciphertext into the test namespace.
