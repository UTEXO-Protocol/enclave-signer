# RGB swaps: KMS seed generation and persistence

Every build with `rgb-swap` restores its signing seed through AWS KMS before
initialization can become `Active`. This includes `Dockerfile.enclave.rgb` and
the combined `Dockerfile.enclave`. The `rgb-mint-burn` and BFA mint/burn images
keep their existing generation, initialization, and cloning behavior.

KMS generates 64 random bytes with `GenerateDataKey(NumberOfBytes=64)` under a
dedicated symmetric encryption KMS key. These bytes are the seed passed to the
existing key derivation code. Transaction validation, derivation paths, and
signing algorithms are unchanged; no transaction uses KMS `Sign`.

## Official AWS dependency

The swap enclave invokes `/usr/local/bin/swap-kms-tool`, a small adapter linked
against the pinned [AWS Nitro Enclaves SDK for C](https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/cd61b6187c8b20867ba4368d1ae62c5790c0269a).
It uses the same official SDK and library codebases as AWS's `kmstool_enclave_cli`:
AWS-LC, s2n-tls, AWS Common Runtime libraries, json-c, and libnsm. The library
versions are deliberately newer than the upstream sample Dockerfile to include
published security fixes: AWS-LC 5.8.0, s2n-tls 1.7.10, CRT libraries 1.0.0,
json-c 0.19 with upstream post-release cleanup fixes (`2094974`), and NSM 0.5.2. The SDK handles
AWS request signing, TLS, recipient-key generation, NSM attestation, and CMS
recipient-envelope decryption. Rust retains seed persistence and signing logic.

The stock CLI exposes 16/32-byte data-key sizes and no encryption-context option.
Our adapter uses the SDK's REST API to send `GenerateDataKey(NumberOfBytes=64)`
and `Decrypt` with the existing context, then calls its CMS decryption routine.
A small [SDK request-lifecycle patch](../build/patches/nitro-sdk-cleanup.patch)
initializes cleanup pointers, handles partial allocation failures, and publishes
completion under the request mutex. This prevents invalid cleanup and lost or
spurious wakeups; the official TLS, SigV4, attestation, and CMS implementations
remain in use. The patch is maintained until an official SDK release includes
the fixes. Its exact diff is verified on every build, and the base commit, patch
hash, and effective source hash are recorded in image provenance. Native fault
tests exercise real SDK cleanup and synchronous/asynchronous completion.
The separate upstream connection-setup wait can still miss an early
notification. The helper's 12-second deadline bounds this availability failure;
initialization fails closed and can be retried.
Credentials and sensitive results cross a bounded
stdin/stdout pipe; they are not command-line arguments or process environment.
See [the helper](../enclave/kms-tool) and [build script](../build/build-swap-kms-tool.sh).

The helper is application-owned integration code with an explicit
[maintenance and upgrade policy](../enclave/kms-tool/README.md#ownership-and-upgrade-policy).
Rust owns configuration validation; C retains bounded IPC and KMS-response
validation. Generation returns ciphertext only. Its recipient seed is validated
and wiped inside the helper before storage is allowed; only decryption of the
committed S3 blob returns a seed to Rust.

The adapter retains one reference to the SDK's CRT bootstrap until the KMS
client is destroyed. This prevents a closed HTTP connection from destroying
its event loop before connection cleanup with the pinned SDK/CRT versions.
A linker wrapper adds that reference through the official bootstrap APIs;
it leaves the SDK's transport, cryptography, and normal releases unchanged.

[The dependency manifest](../build/swap-kms-dependencies.tsv) pins every upstream
source to an immutable reviewed Git commit. Both swap Dockerfiles
build static SDK/CRT libraries and ship the helper, `libnsm.so`, CA certificates,
and provenance under `/usr/share/swap-kms`. The builder uses glibc 2.31, older
than the AL2023 runtime's 2.34. Mint/burn images do not build or ship this helper.

The NSM build uses our checked-in
[`swap-kms-nsm.Cargo.lock`](../build/swap-kms-nsm.Cargo.lock), builds with
`--locked`, and includes that lock as `nsm-Cargo.lock` in the image provenance.
The main Rust workspace also continues to use its checked-in `Cargo.lock`
with `--locked`.

## Storage and trust boundaries

```mermaid
sequenceDiagram
    participant E as Swap enclave
    participant B as Parent seed broker
    participant S as S3
    participant K as AWS KMS
    E->>B: Load ciphertext for pinned seed ID
    B->>S: GetObject at configured bucket/key
    S-->>E: CiphertextBlob, via broker
    opt Missing object and explicit bootstrap image
        E->>K: GenerateDataKey + context + Recipient attestation
        K-->>E: CiphertextBlob + CiphertextForRecipient
        E->>B: Create ciphertext if absent
        B->>S: PutObject, If-None-Match: *
        B->>S: GetObject (committed winner)
        S-->>E: Committed CiphertextBlob, via broker
    end
    E->>K: Decrypt committed blob + same context + Recipient attestation
    K-->>E: CiphertextForRecipient
    E->>E: Unwrap in enclave, derive keys, check identity pin, become Active
```

Each KMS call supplies a fresh enclave RSA recipient key and its NSM attestation.
KMS returns the seed encrypted to that recipient instead of returning plaintext.
The durable S3 object is the raw KMS `CiphertextBlob`, **not** the ephemeral
`CiphertextForRecipient`. The latter cannot be used after its enclave recipient
key is lost. See the AWS [GenerateDataKey API](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)
and [Decrypt API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html).

The enclave authenticates HTTPS to the regional KMS hostname and signs its own
requests with temporary AWS credentials obtained from the parent broker. The
parent's KMS proxy only forwards TLS bytes. The broker handles credentials and
ciphertext; plaintext seed material stays inside KMS and the enclave.

The enclave cannot independently verify an S3 acknowledgement relayed by a
malicious parent. A parent can falsely claim that storage committed, hide an
object, or withhold service. Verify the stored object/version and backup using
a separate administrator session after bootstrap, then test recovery on a fresh
parent. This design protects seed confidentiality and checks recovered identity;
it cannot guarantee availability or durability against a dishonest storage
broker. The required restore address pin also rejects a different valid KMS
seed generated under the same context.

The ciphertext's authenticated encryption context is exactly:

```json
{
  "application": "utexo-enclave-signer",
  "flow": "rgb-swap",
  "seed_id": "YOUR_STABLE_SWAP_SIGNER_ID",
  "bitcoin_network": "bitcoin"
}
```

Use the enclave's Bitcoin network value (`bitcoin`, `testnet`, `signet`, or
`regtest`). These values are public configuration, not secrets. KMS requires the
same context when decrypting; a mismatched context cannot recover the seed.
[AWS encryption-context conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html#conditions-kms-encryption-context)
bind permissions to these values.

## Required configuration

Bake the following public settings into the swap EIF with the corresponding
Docker build arguments. `build/build-enclave.sh` forwards environment variables
with these names for swap image variants.

| EIF setting | Meaning |
| --- | --- |
| `SWAP_KMS_KEY_ARN` | Full ARN of a customer managed symmetric `ENCRYPT_DECRYPT` KMS key; no alias. |
| `SWAP_KMS_REGION` | Region of that key and its HTTPS endpoint. |
| `SWAP_KMS_SEED_ID` | Stable identity, unique to this logical swap signer: 1–128 ASCII letters, digits, dots, underscores, or hyphens. |
| `SWAP_KMS_ALLOW_CREATE` | `0` by default. Only `1` authorizes first-time generation when storage reports a missing object. |
| `SWAP_KMS_EXPECTED_EVM_ADDRESS` | Required EVM address pin for restore (`0x` plus 40 hex digits). Must be empty during bootstrap. Initialization fails if recovered keys differ. |

The broker uses `/etc/utexo/swap-kms.env` on the parent:

```ini
AWS_REGION=eu-central-1
SWAP_KMS_SEED_ID=swap-mainnet-signer-1
SWAP_KMS_S3_BUCKET=YOUR_DEDICATED_SEED_BUCKET
SWAP_KMS_S3_KEY=swaps/signer-1/seed.kms
SWAP_KMS_ALLOWED_CIDS=18
```

Set the actual region and assigned swap enclave CID; multiple authorized swap
CIDs can be comma-separated. The seed ID must match the EIF. The broker fixes
one bucket/key for its lifetime and rejects requests naming a different seed
ID. Use one broker configuration per logical signer identity; do not point
independent signer identities at one object. The supplied units cover one
broker on one parent.

Use a dedicated EC2 instance role with IMDSv2. Boto3 obtains and refreshes its
credentials through the normal provider chain. Do not place static access keys
in the EIF. The broker unit's `DynamicUser` and `ProtectHome` settings intentionally
do not depend on a login user's AWS profile.

**An allowlisted CID receives the full instance-role credentials.** CIDs are
reusable addresses, not authenticated image identities; another enclave assigned
that CID can request those credentials. The broker cannot narrow credentials
after obtaining them. Apply [the dedicated signer-role policy](../deploy/swap-signer-role-policy.json)
as an inline policy on the exact signer role. Its explicit denies restrict the
role to generation/decryption at one key, read/create at one object, and listing
one dedicated bucket even if a broader identity policy is accidentally attached.
It also denies role assumption, IAM changes and account-wide S3 protection
changes. Do not reuse a role that needs unrelated SSM, deployment or application
permissions. Review every policy and trust relationship on this role using an
administrator identity. KMS recipient attestation remains the image authorization
boundary; the CID allowlist only reduces local access to this narrow role.

| Enclave path | Parent vsock | Destination |
| --- | --- | --- |
| SDK helper, direct vsock | CID 3, port `8003` | Blind TLS relay to `kms.<region>.amazonaws.com:443` |
| `127.0.0.1:3446` | CID 3, port `8004` | Credential and ciphertext broker |

Keep the KMS relay separate from the existing EVM RPC/nginx path. Do not
terminate KMS TLS on the parent. This endpoint template targets the standard
AWS commercial partition; do not assume it supports other endpoint suffixes.
Ports 8003/8004 are reserved for the swap custody services. A swap build with
optional Helios uses execution/consensus defaults 8005/8006 and rejects an
explicit Helios override colliding with custody ports. Non-swap Helios defaults
remain 8003/8004. The broker rejects a
`SWAP_KMS_BROKER_PORT` override other than `8004`, matching the measured forwarder.

## KMS and S3 policies

Use [the deployment validator](../deploy/validate-swap-kms-deployment.py) to render
and check [the key policy](../deploy/swap-kms-key-policy.json),
[the bucket policy](../deploy/swap-seed-bucket-policy.json), and
[the signer-role policy](../deploy/swap-signer-role-policy.json) against approved
release artifacts. Do not apply the `REPLACE_*` templates directly. The tool
never creates or changes AWS resources.

The key template names separate key administrator and signer IAM roles. The
administrator must exist and retain policy-update access; do not use the
signer role as the administrator. `Resource: "*"` in a KMS key policy means the
specific key to which that policy is attached. The template intentionally
omits account-wide IAM delegation and grant creation. Review existing grants
and remove conflicting access before using an existing key. Keep the signing
role's other IAM permissions narrow; it needs no KMS policy administration.
[AWS key-policy semantics](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html)
explain these distinctions.

`GenerateDataKey` is allowed only for `REPLACE_BOOTSTRAP_PCR0`. `Decrypt` is
allowed for the bootstrap and restore PCR0 values. Both require the exact
context above. Explicit denies cover missing attestation, unapproved PCR0,
wrong or missing context, extra context keys, alternate encryption/data-key
APIs, and signer policy/grant changes. The latter prevent a parent from using
`Encrypt` to persist a seed it already knows. AWS supports recipient PCR
conditions on both operations; see [Nitro Enclaves condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html).
Never authorize all-zero debug-mode PCRs.

Use a dedicated private S3 general purpose bucket. **Versioning and all four
Block Public Access settings must be enabled; Object Ownership must be
`BucketOwnerEnforced` (ACLs disabled).** Exclude seed objects from lifecycle
expiration and archive transitions that make recovery unavailable. The bucket
template grants object access only at the configured key and requires
`If-None-Match: *` for every write there. It denies object and version deletion
and denies signer changes to bucket policy, versioning, lifecycle, Object Lock,
Block Public Access, ownership, ACLs, default encryption and replication. Object
ACL/version ACL, storage re-encryption, retention, legal-hold and tag changes are also denied to the
signer; changing a tag must not make a protected seed match an expiration rule. A
bucket-wide `ListBucket` permission lets a missing seed return `404` instead of
an ambiguous `403`; this is why the example uses a dedicated bucket. See
[GetObject permissions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html).
The bucket API's `PutPublicAccessBlock` permission is named
`s3:PutBucketPublicAccessBlock`, including deletion of that setting; account-level
settings are governed separately. See the [S3 API permission mapping](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html)
and [Object Ownership guidance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html).

Concurrent initializers adopt the ciphertext committed by the first successful
conditional write. Versioning alone does not enforce immutability: a delete
marker permits a new conditional write. Prevent deletion and lifecycle expiry,
and preserve a separate backup of the ciphertext, KMS key ARN, exact context,
and public identity. Bucket/KMS administrators remain trusted and can change
these protections. See [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
and [bucket-policy enforcement](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html).

The S3 object is already encrypted with KMS. Default S3 SSE-S3 can provide its
additional storage encryption. Do not configure S3 SSE-KMS using this
attestation-only key: S3 cannot supply the enclave recipient attestation. If
organization policy requires SSE-KMS, it needs a separately reviewed storage-key
and IAM design. The supplied role policy and validator intentionally support
SSE-S3: they deny KMS access to any second key. Do not expand the attestation-only
key policy to make S3 encryption work or silently bypass the deployment gate.

### Bind policy approval to the actual EIF

Create an independent release approval from
[`swap-kms-approval.example.json`](../deploy/swap-kms-approval.example.json).
Record the approver and review reference, real account/roles/key/context/storage,
and the SHA256, PCR0 and paths for every approved EIF and its `PCR.json`. A
release reviewer must inspect the source, build provenance and public settings
before signing off on these values. Do not generate an approval from an arbitrary
image just to make validation pass. Hashes cannot establish that an image was
reviewed, and a validator cannot identify every possible fixture key.

Run with trusted `nitro-cli` 1.4.5 or newer on the deployment/release host:

```bash
python3 deploy/validate-swap-kms-deployment.py \
  --approval releases/swap-approval.json --output-dir releases/policies-bootstrap
```

The tool rereads each actual EIF with `nitro-cli describe-eif`, checks CRC and
any image signature, recomputes the whole-file SHA256, compares actual PCR0/1/2
with the recorded build measurements and approved PCR0, and checks its Docker
environment metadata for the exact KMS key, region, seed ID, network, creation
mode and restore identity. Whole-file digest approval also binds the metadata;
Docker metadata alone is not proof of a trusted build. Placeholders, zero/debug
or obvious fixture PCRs, known fixture accounts/keys, unexpected KMS settings,
static credentials and inconsistent restore identities fail validation.
[AWS describes the actual-EIF measurements returned by this command](https://docs.aws.amazon.com/enclaves/latest/user/cmd-nitro-describe-eif.html).

Use `phase: "bootstrap"` with one bootstrap image for the first initialization;
`phase: "transition"` with that bootstrap and one or more restore images while
verifying recovery; and `phase: "restore"` with restore images only afterward.
The renderer keeps the Allow and Deny PCR lists identical in scope. In restore
phase it removes generation permission, adds an unconditional generation deny,
and removes every bootstrap PCR. Multiple restore images can overlap during an
upgrade only when their expected public identity is identical.

Apply the reviewed key policy to the approval's exact KMS key ARN, the bucket
policy to its exact bucket, and the role policy to its exact signer role through
your normal administrator deployment process. Fetch those effective policy
documents back into files with the same three filenames and revalidate them:

```bash
python3 deploy/validate-swap-kms-deployment.py \
  --approval releases/swap-approval.json --policy-dir releases/applied-policies
```

This rejects extra grants, changed principals/context/PCRs and omitted denials
in the supplied policy documents. It does not query AWS, inspect unrelated IAM
policies or establish that downloaded files came from the right AWS resources;
retain the AWS resource IDs and administrator verification with the release.
Before funding a signer, also run `--production-ready --live-evidence PATH`
against the final restore approval and applied policy documents. Evidence must
have the same `approval_reference` and a `checks` object containing each of
`approved_bootstrap_and_restore`, `restore_identity_after_restart`,
`missing_recipient_denied`, `unapproved_pcr_denied`, `debug_pcr_denied`,
`wrong_context_denied`, `overwrite_and_delete_denied`, and
`independent_backup_recovery`. Each value is
`{"passed": true, "evidence": "reference to retained AWS/Nitro test records"}`.
These references are reviewed live-test evidence, not a substitute for running
the tests. The tool requires every item and restore-only policy authority.

## Parent installation

On the Nitro parent, from a checked-out release of this repository:

```bash
sudo install -d -m 0755 /opt/utexo-swap-kms /etc/utexo /etc/nitro_enclaves
sudo python3.11 -m venv /opt/utexo-swap-kms/venv
sudo /opt/utexo-swap-kms/venv/bin/pip install -r deploy/requirements-swap-kms.txt
sudo install -m 0644 deploy/swap-seed-broker.py /opt/utexo-swap-kms/swap-seed-broker.py
sudo install -m 0644 deploy/systemd/utexo-swap-seed-broker.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/vsock-proxy-kms.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/vsock-proxy-kms.yaml /etc/nitro_enclaves/
```

Create the broker environment file shown above with mode `0600`, owned by root.
The broker dependency lock requires Python 3.10 or newer; install a supported
Python version (the example uses 3.11). Pip installs the complete exact-version,
SHA256-verified wheel lock, including transitive dependencies. Update that lock
only together with broker and custody E2E validation.
Replace `REPLACE_AWS_REGION` in **both** installed KMS proxy files with the EIF's
region. Ensure the installed `vsock-proxy` path is `/usr/bin/vsock-proxy` or
adjust the unit for that host. Permit outbound HTTPS to regional KMS and S3,
and instance-role access to IMDS.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vsock-proxy-kms.service utexo-swap-seed-broker.service
```

Start these services before issuing enclave initialization. The existing host
deployment script does not install this dedicated swap configuration. Missing
or invalid measured configuration, including a missing restore address pin,
prevents swap process startup. An unavailable broker/KMS/storage service makes
initialization fail; the operator can restore the service and retry `init`.
Both supplied services run as dynamic unprivileged users with empty capability
sets. Ports 8003/8004 are unprivileged; do not run the relay as root to work around
an installation or file-read-permission problem.

Initialization has one aggregate custody deadline of 25 seconds, within the
30-second request budget. Each broker exchange is capped at eight seconds and
each helper invocation at twelve seconds, shrinking to the remaining aggregate
time. The broker's AWS-operation response deadline is seven seconds. Each
conditional create performs at most one PUT and one GET, with no hidden SDK or
application retry loop. A stalled operation retains its bounded worker slot
until it actually exits, preventing retries from creating unlimited workers.
Timeouts leave the enclave uninitialized. A conditional PUT already in flight
can still commit after a timeout; retry `init` after connectivity recovers so the
next load recovers that durable winner. Never delete the object or generate a
replacement seed to resolve a timeout.

## Bootstrap, restart, and upgrade

1. Choose a **new** logical signer identity, dedicated object, and KMS key.
   Retain the key ARN. Do not use this procedure to replace an existing live
   signer: importing its old seed into KMS is not implemented, and a new seed
   produces different public keys. Plan an explicit signer rotation if an
   existing deployment must move from ephemeral keys.
2. Build the RGB swap EIF with public settings and `SWAP_KMS_ALLOW_CREATE=1`.
   Record the EIF, SHA256 and `build/PCR.json`. Install the broker and relay, then
   approve and validate the `bootstrap` phase policies before authorizing that
   measured image. At this phase only the bootstrap PCR0 permits decryption.
3. Run the measured production EIF without debug mode. Issue
   `utexo-bridge-parent-cli --addr vsock://18:5000 init`, with the actual CID.
   Supply no seed, mnemonic, or cloning secret. Initialization must commit a
   ciphertext and successfully decrypt that committed object before exposing
   active keys. Record and verify the returned public keys and their attestation.
   Independently confirm the S3 object's existence/version and preserve a backup;
   do not rely on the parent's success response as proof of durable storage.
4. Build the normal image with the same key ARN, region, seed ID, and network,
   `SWAP_KMS_ALLOW_CREATE=0`, and the verified EVM address in
   `SWAP_KMS_EXPECTED_EVM_ADDRESS`. Approve and validate the `transition` phase
   policies with both actual EIFs before starting it. Configuration
   changes, including the creation flag and address pin, change PCR0.
5. Start the normal EIF and issue `init`. Verify that all public keys match the
   bootstrap result. Restart the enclave, repeat `init`, and compare again.
   Finish bootstrap by approving, validating and applying the `restore` phase
   policies. This removes the bootstrap PCR0 and generation allow and installs
   an unconditional signer generation deny. Retire the bootstrap EIF, retain
   live validation evidence, and pass the production gate before funding.

Keep bootstrap and restore artifacts at distinct locations (for example,
`OUT_DIR=build/swap-bootstrap` and `OUT_DIR=build/swap-restore`). The EIF workflow
publishes under a git-SHA path, so its two phases need distinct release commits
or separately managed publication paths. Changing repository variables at the
same SHA must not overwrite an already published image or PCR manifest.

For each subsequent code/configuration upgrade, build a restore-only EIF,
approve and validate its PCR0 in a restore-only policy rollout, verify recovery of
the existing identity, and retire the old measurement after rollout. Preserve
the key ARN, seed ID, network context, and ciphertext. KMS automatic rotation
under the same key is separate from changing to a different key ARN; moving
the seed to a different key is not implemented here.

Normal restarts and replicas use the same persisted ciphertext. Swap cloning
requests are rejected, so a live donor enclave and cloning secret are no longer
needed for this flow. Persistence preserves signing keys only; it does not
introduce cross-instance coordination for application state or authorize
multiple replicas to sign concurrently.

### Recover a poisoned bootstrap before funding

The broker treats ciphertext as opaque. An allowlisted caller or a compromised
instance role can win the first conditional write with unusable data. KMS and
the enclave reject it, but the object intentionally cannot be overwritten or
deleted by the signer. This is an availability and deployment-control boundary.
Only assign bootstrap CIDs to the reviewed image, keep the dedicated role off
other workloads, and independently verify successful restore before registering
or funding the public identity.

If bootstrap fails on a committed blob, stop initializers and investigate with
an independent administrator. Preserve the object/version and deployment logs;
first distinguish a wrong key/context/policy or delayed write from invalid data.
If the signer has **never been funded or registered**, quarantine the failed
deployment and start a new logical seed ID, new KMS key and new dedicated bucket
or object under fresh bootstrap/restore approvals. Keep the old object and its
deletion protection intact, revoke the old role's access, and discard every
public identity from the abandoned attempt. This recovers service without
adding a permanent break-glass deletion exception.

For an existing funded or registered identity, never start a new bootstrap or
clear its object. Recover the original ciphertext/version from the independently
verified backup with administrator incident procedures, preserve its exact key
and context, and verify the pinned identity using a restore-only EIF. If an
unusable primary object must remain protected, configure a separately protected
recovery object containing the **same original ciphertext** and narrow the role
and bucket policy accordingly. Changing the seed ID, key or expected address
would create a different signer and is not recovery. KMS/S3 administrators remain
trusted; the signer receives no deletion or retention-bypass privilege.

## Local development without AWS

An explicit `allow-seed-import` debug build may start with every `SWAP_KMS_*`
setting absent and initialize from a supplied test seed/mnemonic. An empty
`InitializeKey` still fails: it never falls back to an ephemeral swap seed.
Partially supplied KMS configuration is an error. This development feature is
already prohibited by the release build guard and does not alter the production
lifecycle. The in-process test harness uses an injected seed source instead of
AWS. Local emulator tests live separately on `kms-testing`; they replace NSM
attestation and transport routing only in the test helper. Production images
use the SDK's real NSM and verified HTTPS transport.

## Required live validation before production use

Local unit tests do not exercise the NSM device, actual Recipient attestation,
AWS policy evaluation, Nitro vsock, or a real S3 conditional-write race. Run the
following against disposable infrastructure and record the results before
deploying a funded signer:

| Check | Required result |
| --- | --- |
| Bootstrap then restart with restore-only EIF | Same EVM/BTC/RGB public identity; S3 ciphertext unchanged. |
| Two bootstrap initializers for one object | Both recover the committed winner; one durable object. |
| Restore-only image and a missing seed | Initialization fails; no new data key or object. |
| Wrong seed ID/network/key, malformed ciphertext, or wrong expected address | Initialization fails before `Active`. |
| Missing credentials, denied S3 access, unreachable broker/KMS | Initialization fails; no random fallback. |
| Signer-role KMS calls without Recipient or with unapproved/debug PCR0 | Both generation and decryption are denied. |
| Wrong/missing/extra encryption context and alternate KMS encryption APIs | Requests are denied. |
| Attempted unconditional overwrite or object/version deletion | S3 denies it; original ciphertext remains. |
| Signer changes to public access, ownership, ACLs, encryption, retention, or another AWS resource | Explicit role/bucket denies reject them. |
| Unallowlisted enclave CID | Broker closes the connection before returning credentials. |
| Swap clone requests | Rejected. |
| `rgb-mint-burn` initialization, cloning, and signing regression checks | Existing behavior remains intact. |

Use the existing signing fixtures to confirm unchanged signature verification
after recovery. Do not log AWS credentials, recipient private keys, plaintext
seeds, or KMS response bodies during these checks.
