# KMS seed persistence

The `kms-persistence` capability uses AWS KMS to generate a 64-byte seed and S3 to
persist its encrypted `CiphertextBlob`. On initialization the enclave loads the
saved blob, decrypts it with KMS recipient attestation, and passes the seed to
its existing key derivation. Signing stays inside the enclave; it does not use
KMS Sign.

The application selects a supported `CustodyFlow` at build time. Neither a
host request nor an environment variable selects the custody flow. Each flow
requires its own context, seed ID, S3 object and KMS permissions; unsupported
build combinations are rejected at compile time. Preserve the original context
when recovering existing ciphertext.

Only a confirmed missing S3 object with no expected identity pin permits
`GenerateDataKey(NumberOfBytes=64)`. The parent writes with `If-None-Match: *`,
then reads the committed object. Concurrent initializers recover that same
winner. Storage errors, invalid ciphertext and decryption failures never fall
back to a new seed. Replicas recover the saved seed instead of using peer cloning.

The [native adapter](../enclave/kms-tool) uses the official AWS Nitro Enclaves
SDK for TLS, AWS request signing, NSM attestation and recipient decryption.
Credentials pass through private pipes; plaintext seed material stays inside
KMS and the enclave. The durable object is `CiphertextBlob`, not the ephemeral
`CiphertextForRecipient` encrypted to one invocation's recipient key.

## Enclave configuration

Set these public Docker build arguments for `Dockerfile.enclave.rgb` or the
combined `Dockerfile.enclave`; `build/build-enclave.sh` also forwards them:

| Setting | Value |
| --- | --- |
| `KMS_KEY_ARN` | Full symmetric `ENCRYPT_DECRYPT` KMS key ARN; no alias. |
| `KMS_REGION` | Region matching that key, for example `eu-central-1`. |
| `KMS_SEED_ID` | Stable signer ID: 1–128 ASCII letters, digits, `.`, `_`, `-`. |
| `KMS_EXPECTED_EVM_ADDRESS` | Empty for first bootstrap; then the verified EVM address, 40 hex digits with optional `0x`. |

Keep the key ARN, seed ID and Bitcoin network unchanged when recovering an
existing identity. A configured address pin rejects a different recovered seed
and makes missing storage fail before generation. There is no creation switch.
Configuration changes affect the image measurement and require updating KMS
permissions. These endpoint settings support the standard AWS commercial partition.

## Parent integration

The existing [Rust parent](../parent/src/seed_persistence.rs) returns AWS
credentials and reads/conditionally creates one S3 object. It never receives
the plaintext seed. Configure persistence on the parent process that serves
this signer:

```bash
export AWS_REGION=eu-central-1
export KMS_SEED_ID=mainnet-signer-1
export KMS_S3_BUCKET=YOUR_SEED_BUCKET
export KMS_S3_KEY=signers/signer-1/seed.kms
export USE_VSOCK=true
export ENCLAVE_VSOCK_CID=18
./utexo-bridge-parent
```

With storage settings absent, the parent retains its existing behavior. The
official AWS Rust SDK obtains and refreshes credentials; use a dedicated EC2
instance role with IMDSv2. The custody listener admits `ENCLAVE_VSOCK_CID` by
default. `KMS_ALLOWED_CIDS` can explicitly allow comma-separated replica
CIDs sharing the same logical signer. Every allowed CID receives the **full
role**, so give it only this signer's KMS/S3 permissions. A CID is a routing
address, not attested image identity.

Enable the custody listener in only one parent process per host. The enclave
connects to parent CID `3`, vsock port `8004`. Local development can instead set
`KMS_BROKER_TCP=127.0.0.1:3446` with `USE_VSOCK=false`.

In another terminal, or through your existing host supervisor, run AWS's
standard `vsock-proxy` for the same KMS region. Its configuration and invocation
follow the repository's existing egress-proxy pattern:

```bash
export AWS_REGION=eu-central-1
cat > kms-vsock-proxy.yaml <<EOF_KMS
allowlist:
- {address: kms.${AWS_REGION}.amazonaws.com, port: 443}
EOF_KMS
vsock-proxy 8003 "kms.${AWS_REGION}.amazonaws.com" 443 --config kms-vsock-proxy.yaml
```

Permit outbound HTTPS to KMS/S3 and role access to IMDS. KMS TLS terminates in
the enclave; the proxy only forwards bytes. The standard proxy restricts the
destination, not source CIDs; isolation and process supervision belong to the
host deployment. Do not run a second listener on `8003` or `8004`. KMS-enabled Helios
uses `8005`/`8006` when enabled. No systemd units or deployment automation are
provided by this feature.

## AWS permissions and persistence

Use a dedicated KMS key and protected S3 bucket. Configure the signer role and
resource policies with these permissions:

| Permission | Scope and restriction |
| --- | --- |
| `kms:GenerateDataKey` | The configured KMS key, during first bootstrap only. |
| `kms:Decrypt` | The same key, for recovery. |
| `s3:GetObject`, `s3:PutObject` | The exact seed object; require HTTPS and `If-None-Match: *` for writes. |
| `s3:ListBucket` | The containing bucket, so an absent object is distinguishable from access denial. |

Both KMS operations must require recipient attestation with the approved
production PCR0 from `nitro-cli describe-eif --eif-path YOUR_IMAGE.eif` and
exactly these public encryption-context fields:

```json
{"application":"utexo-enclave-signer","flow":"COMPILED_FLOW","seed_id":"YOUR_SEED_ID","bitcoin_network":"bitcoin"}
```

Replace `COMPILED_FLOW` with the application's compiled
[`CustodyFlow` value](../enclave/src/kms.rs) and `YOUR_SEED_ID` with `KMS_SEED_ID`.
The enclave supplies this context automatically; policies must match it exactly.

Use the actual network: `bitcoin`, `testnet`, `signet`, or `regtest`. Reject
unattested requests, wrong PCRs and changed/missing/extra context, including when
another identity policy grants broader access. Keep the signer role free of
unrelated policies, policy-management privileges, object/version deletion and
KMS key deletion permissions. Do not authorize debug images or zero PCRs.
See AWS's [recipient-attestation conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-attestation.html)
and [conditional S3 writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html).

Enable bucket versioning, block public access, and retain an independently
verified backup of the ciphertext and its key/context metadata. Exclude the
object from expiration/replication rules that remove or replace it. S3 does not
make the seed recoverable if the KMS key is deleted. The untrusted parent can
withhold or falsely acknowledge storage, so independently verify the object and
recovery before funding the signer.

## Bootstrap, restart and recovery

1. Build a new signer's EIF without an address pin. Configure the parent, relay,
   key and bucket policies for its actual CID, PCR0 and context.
2. Run the enclave without debug mode and issue
   `utexo-bridge-parent-cli --addr vsock://18:5000 init`. Supply no seed or cloning
   secret. Verify the public identity/attestation and independently back up the
   saved S3 ciphertext. This does not import a legacy ephemeral seed.
3. Rebuild with the verified `KMS_EXPECTED_EVM_ADDRESS`. Update the key's
   approved PCR0 for the pinned image, start it, and verify identical keys after
   initialization and restart. During a rollout, approved PCR0 may be a list in
   both the allow and deny conditions; retire the bootstrap measurement afterward.
4. Before funding, remove `kms:GenerateDataKey` from the key's allow statement
   and add an unconditional deny for that action for the signer role. Keep
   `kms:Decrypt` for the pinned image. Test restore on a fresh parent. Subsequent
   upgrades authorize the new measured image for decryption of the same seed.

A timeout leaves initialization inactive; a conditional PUT may still complete.
Retry after service recovery to load the committed winner. Custody calls are
bounded and per-CID quotas/rate limits reject excess work. Never delete the blob,
change its seed ID/key, or remove the address pin to fix a funded signer.
Recover the original ciphertext/version from backup, using an administrator and
a protected recovery object if necessary. If a never-funded bootstrap was
poisoned, quarantine it and provision a new signer namespace; do not reuse any
identity from that failed attempt. Shared ciphertext preserves keys but does
not coordinate replicas or authorize concurrent application-level signing.

Before production use, test real AWS recipient-attestation denials,
conditional-write races and restart/backup
recovery on Nitro hardware; local builds do not prove those service boundaries.
