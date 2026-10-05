# Mint signer KMS seed persistence

The `mint-signer` feature enables `kms-persistence`, using AWS KMS to generate a
64-byte seed and S3 to persist its encrypted `CiphertextBlob`. On initialization
the enclave loads the saved blob, decrypts it with KMS recipient attestation,
and passes the seed to its existing key derivation. Signing stays inside the enclave; it does not use
KMS Sign.

The measured mint image selects `CustodyFlow::RgbMint`, whose encryption-context
value is `rgb-mint`. Neither a host request nor an environment variable selects
the custody flow. Builds enabling `kms-persistence` without `mint-signer` are
rejected at compile time. Burn signers retain their existing OS-entropy and
cloning lifecycle.

The address pin selects one of two initialization modes:

| Address pin | Saved object | Result |
| --- | --- | --- |
| Absent | Absent | Generate a seed, then create the object conditionally. |
| Absent | Present | Refuse initialization. |
| Set | Present | Decrypt the seed and check its derived address. |
| Set | Absent | Refuse initialization. |

The parent writes with `If-None-Match: *`, then reads the saved object.
During bootstrap, the enclave accepts only the ciphertext that this call generated.
If another initializer created a different object first, initialization fails before decryption.
Verify the successful signer's address before you use it as the recovery pin.
Storage errors and decryption failures never cause fallback to a new seed.
Replicas recover the saved seed with the pin. They do not use peer cloning.

The enclave cannot independently prove that S3 has no object. The untrusted
parent reports storage results. Verify persistence and recovery before funding the signer.

The [KMS client](../enclave/src/kms/mod.rs) runs inside the signer process.
The AWS SDK signs and sends `GenerateDataKey` and `Decrypt` requests.
The NSM API creates an attestation document with a one-use RSA-2048 recipient key.
RustCrypto decrypts the returned CMS envelope. It uses RSAES-OAEP-SHA-256 for
key transport and AES-256-CBC for content encryption.

TLS uses rustls with the `aws-lc` provider and bundled Amazon Trust Services roots.
The parent broker supplies credentials for each call. Plaintext seed material
stays inside KMS and the enclave. S3 stores the durable `CiphertextBlob`.
`CiphertextForRecipient` is temporary and bound to one recipient key.

## Enclave configuration

Set these public values at launch, in `SetEndpoints` (`cli set-endpoints`, or
`/etc/utexo/enclave.env` with `deploy/deploy-host.sh`). The image does not
carry them, and the attested policy commits them:

| Setting | Value |
| --- | --- |
| `KMS_KEY_ARN` | Full symmetric `ENCRYPT_DECRYPT` KMS key ARN; no alias. |
| `KMS_REGION` | Region matching that key, for example `eu-central-1`. |
| `KMS_SEED_ID` | Stable signer ID: 1–128 ASCII letters, digits, `.`, `_`, `-`. |
| `KMS_EXPECTED_EVM_ADDRESS` | Empty for first bootstrap; then the verified EVM address, 40 hex digits with optional `0x`. |

Keep the key ARN, `rgb-mint` flow context, seed ID and Bitcoin network unchanged
when recovering an existing identity. A configured address pin rejects a
different recovered seed and makes missing storage fail before generation; no
pin makes an existing object fail before decryption. There is no creation switch.
A development image built with `allow-seed-import` and launched with all KMS
values empty is import-only: `init` needs a mnemonic, and an empty `init` fails.
A verifier checks them with `attest-verify --expect-kms-key-arn`,
`--expect-kms-region`, `--expect-kms-seed-id` and `--expect-kms-evm-address`. These endpoint settings support the standard AWS commercial partition.

## Parent integration

The existing [Rust parent](../parent/src/seed_persistence.rs) returns AWS
credentials and reads/conditionally creates one S3 object. It never receives
the plaintext seed. Configure persistence on the parent process that serves
this mint signer:

```bash
export AWS_REGION=eu-central-1
export KMS_SEED_ID=mint-mainnet-signer-1
export KMS_S3_BUCKET=YOUR_SEED_BUCKET
export KMS_S3_KEY=mint/signer-1/seed.kms
export USE_VSOCK=true
export ENCLAVE_VSOCK_CID=18
./utexo-bridge-parent
```

This example adds custody settings to the normal parent configuration.
Configure gRPC mTLS as described in [Parent mTLS](parent-mtls.md).
With storage settings absent, the parent does not start the custody broker.
The AWS SDK obtains and refreshes credentials. Use a dedicated EC2 instance
role with IMDSv2. The custody listener admits `ENCLAVE_VSOCK_CID` by
default. `KMS_ALLOWED_CIDS` can explicitly allow comma-separated replica
CIDs sharing the same logical signer. Every allowed CID receives the **full
role**, so give it only this signer's KMS/S3 permissions. A CID is a routing
address, not attested image identity.

Enable the custody listener in only one parent process per host. The enclave
connects to parent CID `3`, vsock port `8004`. Local development can instead set
`KMS_BROKER_TCP=127.0.0.1:3446` with `USE_VSOCK=false`.

In another terminal, or through your existing host supervisor, run AWS's
standard `vsock-proxy` for the same KMS region. The enclave pins
`kms.<region>.amazonaws.com` to `127.0.0.2` and forwards port 443 to vsock port
`8003` (`KMS_VSOCK_PORT` overrides it), so TLS still validates the real KMS
certificate and the proxy only relays bytes:

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
host deployment. Do not run a second listener on `8003` or `8004`.

The deployment scripts pass enclave KMS settings at launch. They do not provision the KMS relay, broker storage settings, or AWS policies.

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
{"application":"utexo-enclave-signer","flow":"rgb-mint","seed_id":"YOUR_SEED_ID","bitcoin_network":"bitcoin"}
```

The flow is the compiled [`CustodyFlow::RgbMint`](../enclave/src/kms/mod.rs)
value. Replace `YOUR_SEED_ID` with `KMS_SEED_ID`. The enclave supplies this
context automatically; policies must match it exactly.

Use the actual network: `bitcoin`, `testnet`, `signet`, or `regtest`. Reject
unattested requests, wrong PCRs and changed/missing/extra context, including when
another identity policy grants broader access. Keep the signer role free of
unrelated policies, policy-management privileges, object/version deletion and
KMS key deletion permissions. Do not authorize debug images or zero PCRs.
See AWS's [recipient-attestation conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-attestation.html)
and [conditional S3 writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html).

A conditional Allow does not restrict permissions from other applicable Allow statements.
For example, the default KMS key policy can delegate access to IAM policies.
Add explicit Deny statements for the signer principal to enforce these restrictions.

Use separate Deny statements for each required context field. AWS combines
different condition keys with AND, even with `StringNotEquals`. One statement
with several keys could therefore miss a request with only one incorrect field.
See [AWS condition evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html).

The following statements are policy fragments, not a complete key policy.
Add them to a policy's `Statement` array. Replace all placeholders before use.
Test missing attestation, debug PCRs, and incorrect or missing context on Nitro.
This source review does not verify a deployed policy or prior hardware test results:

```json
[
{"Sid":"DenyUnlessAttestedImage","Effect":"Deny","Principal":{"AWS":"SIGNER_ROLE_ARN"},
 "Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*",
 "Condition":{"StringNotEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":"PRODUCTION_PCR0"}}},
{"Sid":"DenyUnlessSeedId","Effect":"Deny","Principal":{"AWS":"SIGNER_ROLE_ARN"},
 "Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*",
 "Condition":{"StringNotEquals":{"kms:EncryptionContext:seed_id":"YOUR_SEED_ID"}}},
{"Sid":"DenyExtraContextKeys","Effect":"Deny","Principal":{"AWS":"SIGNER_ROLE_ARN"},
 "Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*",
 "Condition":{"ForAnyValue:StringNotEquals":{"kms:EncryptionContextKeys":["application","flow","seed_id","bitcoin_network"]}}},
{"Sid":"DenyPlantedCiphertext","Effect":"Deny","Principal":{"AWS":"*"},
 "Action":["kms:Encrypt","kms:ReEncrypt*","kms:CreateGrant"],"Resource":"*"}
]
```

Repeat the `DenyUnlessSeedId` shape for `application`, `flow` and
`bitcoin_network`. The last statement denies `kms:Encrypt`, `kms:ReEncrypt*`
and grants to every principal: anyone allowed those calls could produce a
ciphertext for a seed they know under the mint context, and the pinned
enclave would decrypt it. After bootstrap, add an unconditional Deny of
`kms:GenerateDataKey` for the signer role.

Enable bucket versioning, block public access, and retain an independently
verified backup of the ciphertext and its key/context metadata. Exclude the
object from expiration/replication rules that remove or replace it. S3 does not
make the seed recoverable if the KMS key is deleted. The untrusted parent can
withhold or falsely acknowledge storage, so independently verify the object and
recovery before funding the signer.

## Bootstrap, restart and recovery

1. Launch a new mint signer without an address pin.
   Configure the parent and relay for its CID.
   Configure the key and bucket policies for its PCR0 and encryption context.
2. Run the enclave without debug mode.
   Send `utexo-bridge-parent-cli --addr vsock://18:5000 init`.
   Supply no seed or cloning secret.
   Verify the public identity and attestation.
   Independently back up the saved S3 ciphertext.
   This procedure does not import a legacy seed.
3. Set `KMS_EXPECTED_EVM_ADDRESS` to the verified address at the next launch.
   Initialize the restarted enclave.
   Verify that its keys match the original keys.
   An unpinned restart rejects an existing object with "saved seed exists".
   During an image rollout, authorize approved PCR0 values in both Allow and Deny conditions.
   Remove the old measurement when the rollout is complete.
4. Before funding, remove `kms:GenerateDataKey` from the key's Allow statement.
   Add an unconditional Deny for that action for the signer role.
   Keep `kms:Decrypt` for the pinned image.
   Test recovery on a fresh parent.
   For later upgrades, authorize the new measured image to decrypt the same seed.

If the enclave's initialization deadline expires before activation, it returns to `Initial`.
A conditional PUT can still complete. A caller timeout alone does not prove
that initialization failed. The enclave can activate before a response is lost.
After service recovery, read the committed object, verify its identity, and
relaunch with that address pinned. Custody calls are
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
