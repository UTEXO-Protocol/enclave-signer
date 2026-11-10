# Mint signer KMS seed persistence

A mint signer gets its seed from AWS KMS and keeps an encrypted copy in S3.
So a restarted or a new mint enclave recovers the same seed, when the KMS key
policy approves its image. Burn signers do not use KMS; they
[clone](cloning.md).

## How it works

- KMS makes the 64-byte seed (`GenerateDataKey`). S3 keeps its
  `CiphertextBlob`. On initialization the enclave loads the blob, decrypts it
  through KMS (`Decrypt`) and derives its keys from the seed, as every build
  does.
- Both KMS calls use recipient attestation: the NSM makes an attestation
  document with a one-use RSA-2048 key, and KMS encrypts its answer to that
  key as a CMS envelope (RSAES-OAEP-SHA-256, AES-256-CBC). The plaintext
  seed exists only in KMS and in the enclave.
- Signing stays inside the enclave. It does not use KMS `Sign`.
- The KMS client runs inside the enclave
  ([`enclave/src/kms/mod.rs`](../enclave/src/kms/mod.rs)). TLS to KMS ends in
  the enclave, with bundled Amazon Trust Services roots. The parent supplies
  AWS credentials for each call and reads and writes the S3 object. It never
  gets the plaintext seed.
- The mint image compiles in the custody flow `rgb-mint`
  (`CUSTODY_FLOW`), which is part of the KMS encryption context. No request
  and no environment variable selects the flow. A build with
  `kms-persistence` and without `mint-signer` does not compile.

The address pin `KMS_EXPECTED_EVM_ADDRESS` selects the mode of an
initialization:

| Address pin | Saved object | Result |
| --- | --- | --- |
| Absent | Absent | Make a seed, then create the object conditionally. |
| Absent | Present | Refuse. |
| Set | Present | Decrypt the seed and check its derived address. |
| Set | Absent | Refuse. |

There is no creation switch. A storage error or a decryption failure never
falls back to a new seed.

At the first bootstrap the parent writes with `If-None-Match: *` and then
reads the saved object. The enclave accepts only the ciphertext that this
call made. If another initializer created another object first, the
initialization fails before any decryption.

The enclave cannot prove that S3 holds no object: the untrusted parent
reports the storage results. Verify the persistence and a recovery before
you fund the signer.

## Launch values

Set these public values at launch, in `SetEndpoints`
([configuration.md](configuration.md#launch-values)). The image does not
carry them. A `Production` policy commits them, and a verifier checks them
with the `--expect-kms-*` flags of `attest-verify`.

| Setting | Value |
| --- | --- |
| `KMS_KEY_ARN` | Full ARN of a symmetric `ENCRYPT_DECRYPT` KMS key. No alias. |
| `KMS_REGION` | The region of that key, for example `eu-central-1`. The standard AWS commercial partition only. |
| `KMS_SEED_ID` | Stable signer id: 1 to 128 ASCII letters, digits, `.`, `_`, `-`. |
| `KMS_EXPECTED_EVM_ADDRESS` | Empty for the first bootstrap. Then the verified EVM address, 40 hex digits with optional `0x`. |

To recover an identity, keep the key ARN, the seed id and the Bitcoin network
unchanged.

The mint image also carries `KMS_ALLOWED_ACCOUNT_IDS`: the 12-digit AWS
account ids that the key may live in, comma-separated. It is a build
argument, so PCR0 measures it.

- `SetEndpoints` refuses a key ARN outside the list. So the host cannot name
  a key in its own account.
- A malformed list stops the enclave at boot. With no list, a release image
  refuses every key; a dev or test build skips the check.
- A new list needs a new PCR0, which the key policy must approve.
- The check pins the account, not the key. It does not replace
  `attest-verify --expect-kms-key-arn`.

A development image built with `allow-seed-import` and launched with all KMS
values empty is import-only: use `init-mnemonic` or `init-seed`. A plain
`init` fails.

## Parent setup

The parent ([`parent/src/seed_persistence.rs`](../parent/src/seed_persistence.rs))
returns AWS credentials to the enclave and reads or conditionally creates
one S3 object. Configure it on the parent that serves this mint signer, next
to its normal settings:

```bash
export AWS_REGION=eu-central-1
export KMS_SEED_ID=mint-mainnet-signer-1
export KMS_S3_BUCKET=YOUR_SEED_BUCKET
export KMS_S3_KEY=mint/signer-1/seed.kms
export USE_VSOCK=true
export ENCLAVE_VSOCK_CID=18
./utexo-bridge-parent
```

- Without the storage settings, the parent starts no custody broker. With
  only some of them, the parent does not start. The `KMS_SEED_ID` of the
  parent must equal the launch value of the enclave.
- The AWS SDK gets and refreshes the credentials. Use a dedicated EC2
  instance role with IMDSv2.
- The broker serves the enclave on `ENCLAVE_VSOCK_CID`. `KMS_ALLOWED_CIDS`
  can name several replica CIDs of the same signer. It replaces the default,
  so list the primary CID too. Every allowed CID gets the **full role**: give
  the role only the KMS and S3 permissions of this signer. A CID is a routing
  address, not an attested identity.
- Run the broker in one parent process per host. The enclave connects to
  parent CID 3, vsock port 8004. Local development can use
  `KMS_BROKER_TCP=127.0.0.1:3446` with `USE_VSOCK=false`.

The enclave reaches KMS through a `vsock-proxy` on the host. It pins
`kms.<region>.amazonaws.com` to loopback and forwards port 443 to vsock port
8003 (`KMS_VSOCK_PORT`). The proxy relays bytes only. It restricts the
destination, not the source CID:

```bash
export AWS_REGION=eu-central-1
cat > kms-vsock-proxy.yaml <<EOF_KMS
allowlist:
- {address: kms.${AWS_REGION}.amazonaws.com, port: 443}
EOF_KMS
vsock-proxy 8003 "kms.${AWS_REGION}.amazonaws.com" 443 --config kms-vsock-proxy.yaml
```

Permit outbound HTTPS to KMS and S3, and role access to IMDS. Do not run a
second listener on 8003 or 8004.

`deploy/deploy-host.sh` writes the KMS values of its environment to
`/etc/utexo/enclave-<CID>.env`, and the launch sends them in `set-endpoints`. A
mint enclave refuses blank KMS values and is then terminated, so you cannot
add them by hand after the deploy. `release-eif.yml` passes no KMS value.
No deployment script sets up the KMS proxy, the storage settings of the
broker or the AWS policies.

## AWS permissions

Use a dedicated KMS key and a protected S3 bucket.

| Permission | Scope and restriction |
| --- | --- |
| `kms:GenerateDataKey` | The configured KMS key, during the first bootstrap only. |
| `kms:Decrypt` | The same key, for recovery. |
| `s3:GetObject`, `s3:PutObject` | The exact seed object. Require HTTPS, and `If-None-Match: *` for writes. |
| `s3:ListBucket` | The bucket, so that an absent object differs from a denied access. |

Both KMS operations must require recipient attestation with the approved
PCR0 of the mint image (`nitro-cli describe-eif --eif-path YOUR_IMAGE.eif`),
and exactly this encryption context:

```json
{"application":"utexo-enclave-signer","flow":"rgb-mint","seed_id":"YOUR_SEED_ID","bitcoin_network":"bitcoin"}
```

The enclave supplies the context itself. `bitcoin_network` is `bitcoin`,
`testnet`, `testnet4`, `signet` or `regtest`; a `signetcustom` image uses
`signet`.

Rules for the policies:

- Refuse a request without attestation, with wrong PCRs, or with a changed,
  missing or extra context field, also when another identity policy grants
  broader access.
- A conditional Allow does not restrict what another Allow grants. The
  default key policy can delegate access to IAM policies. So add explicit
  Deny statements for the signer principal.
- Use one Deny statement for each context field. AWS combines different
  condition keys with AND, so one statement with several keys misses a
  request with only one wrong field
  ([AWS condition evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html)).
- Keep the signer role free of other policies, of policy-management rights,
  and of the rights to delete the object, its versions or the KMS key.
- Do not authorize a debug image or zero PCRs.

See AWS's
[recipient-attestation conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-attestation.html)
and [conditional S3 writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html).

The statements below are fragments for the `Statement` array of a key
policy, not a complete policy. Replace every placeholder.

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
and grants to every principal: a party with those calls could make a
ciphertext of a seed that it knows under the mint context, and the pinned
enclave would decrypt it.

For the bucket: enable versioning, block public access, and keep an
independently verified backup of the ciphertext with its key and context
metadata. Keep the object out of expiration and replication rules that
remove or replace it. S3 does not make the seed recoverable if the KMS key
is deleted.

## Bootstrap, restart and upgrade

1. **Prepare.** Configure the parent and the KMS proxy for the CID. Configure
   the key and bucket policies for the PCR0 of the image and the encryption
   context. Launch the mint signer without an address pin.
2. **Bootstrap.** Run the enclave without debug mode. Send
   `utexo-bridge-parent-cli --addr vsock://18:5000 init`, with no seed and no
   cloning secret. Verify the public identity and the attestation. Back up
   the saved S3 ciphertext independently.
3. **Pin.** Set `KMS_EXPECTED_EVM_ADDRESS` to the verified address at the
   next launch, and initialize the restarted enclave. Check that its keys
   match the first ones. A launch without the pin refuses an existing object
   with "saved seed exists".
4. **Lock down, before funding.** Remove `kms:GenerateDataKey` from the Allow
   statement of the key, and add an unconditional Deny of it for the signer
   role. Keep `kms:Decrypt` for the pinned image. Test a recovery on a fresh
   parent.
5. **Upgrade.** Authorize the PCR0 of the new image in the Allow and the
   Deny conditions, next to the old one. Remove the old measurement when the
   rollout is complete.

Before production use, test the real denials of recipient attestation, the
conditional-write race and a recovery from backup on Nitro hardware. A local
build does not prove these service boundaries.

## Failures

- **A deadline during initialization.** If the deadline of the enclave
  passes before activation, the enclave returns to `Initial`. The conditional
  PUT can still complete, and the enclave can also activate before a reply
  is lost. So a caller timeout does not prove that the initialization
  failed. Read the committed object, verify its identity, and launch again
  with that address pinned.
- **A funded signer.** Never delete the blob, change its seed id or key, or
  remove the address pin to fix a funded signer. Recover the original
  ciphertext or version from the backup.
- **A poisoned bootstrap that was never funded.** Quarantine it and set up a
  new signer namespace. Do not reuse an identity of the failed attempt.
- **Replicas.** A shared ciphertext gives replicas the same keys. It does not
  coordinate them.
- **Load.** The custody calls are bounded, and quotas and rate limits per
  CID refuse excess work.
