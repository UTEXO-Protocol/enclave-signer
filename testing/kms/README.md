# Local KMS persistence E2E

This tooling belongs only on `kms-testing`. The production implementation branch
is `codex/rgb-swap-kms-persistence`. Never merge the testing feature, local CA/PCR
hooks, emulator, or generated artifacts into that branch.

The suite launches actual enclave, seed-broker, and parent-service processes. The
enclave generates its seed through a local KMS API, commits the encrypted blob to
local S3, decrypts the committed blob, derives its normal keys, and signs through
the existing gas transaction path. It then repeats this across process restarts
and replicas. No AWS account, cloud resources, LocalStack token, Docker daemon,
or Nitro device is needed for this suite.

## Run

Prerequisites: Rust/Cargo 1.96, Python 3.12, Node.js 22 or newer, npm, and the
repository's normal native build dependencies (including CMake, Perl, and
protoc). Existing GitHub access must be able to fetch the private RGB and parent
protocol dependencies. The runner rewrites only this process's private SSH
aliases to HTTPS so Git's existing credential helper can be used; it does not
read or print GitHub tokens or change global Git configuration.

From the repository root:

```sh
python3.12 -m venv .artifacts/kms-e2e/venv
.artifacts/kms-e2e/venv/bin/python -m pip install \
  -r testing/kms/requirements.txt -c testing/kms/requirements.lock
npm ci --prefix testing/kms
.artifacts/kms-e2e/venv/bin/python testing/kms/run.py
```

The runner builds both enclave/client binaries and both parent/client binaries
with locked Cargo dependencies, starts the local services, runs the assertions,
and stops its processes even on failure. It returns nonzero on the first failure.
The emulator, clients, and broker bind only to loopback. It refuses occupied ports
instead of stopping another service. Defaults:

| Port | Local service |
| --- | --- |
| 3445 | Verified TLS endpoint for KMS and S3 |
| 3446 | Production seed broker's development TCP listener |
| 15000 | Moto IAM/STS and HTTP transport negative tests |
| 15001 | Test-only fixture, fault, and audit controls |
| Ephemeral | Enclave and parent TCP/gRPC listeners |

Use `--kms-port`, `--broker-port`, `--aws-port`, and `--control-port` for port
overrides; `--node /path/to/node` selects a Node executable. `CARGO_TARGET_DIR`
selects the enclave build cache and `KMS_E2E_PARENT_TARGET_DIR` selects the parent
cache. `--skip-build` reuses those binaries. The normal invocation builds the
testing feature itself; it does not enable `dev-mode` or `allow-seed-import`.

Reports, logs, a short-lived test TLS private key, and the Python environment live
under `.artifacts/kms-e2e/`, which is ignored by Git and Docker. Node dependencies
are also ignored. Fake AWS credentials are created in local Moto IAM/STS and held
only in process memory/environment. Inherited AWS credentials, profiles, proxy
settings, and external indexer settings are removed or replaced for the suite.
The JSON report is `.artifacts/kms-e2e/report.json`.

## What runs

- Bootstrap uses `GenerateDataKey(NumberOfBytes=64)`, attested Recipient CMS,
  conditional `PutObject`, and `Decrypt` of the committed winning ciphertext.
  The parent/broker never receive the response's plaintext seed.
- All public-key fields and a cryptographically verified EIP-1559 gas signature
  remain identical after restarting both enclave and broker and starting another
  replica. The actual parent gRPC `EVM_GAS_TX` route produces the same signature.
- Two bootstrap enclaves are synchronized after generation to force competing
  `IfNoneMatch="*"` writes. Both activate the same stored identity and signature.
- Missing recovery state, altered ciphertext, another valid ciphertext, and a
  wrong expected identity all fail initialization without generating a replacement.
- Native IAM read/write/KMS denial and malformed KMS response cases leave the
  enclave uninitialized. Clearing a transient fault allows retry in that same
  process. Recovery failures preserve the existing ciphertext and identity.
- Swaps reject cloning and raw seed import in the tested feature set.
- The concrete production policy templates are evaluated for bootstrap/recovery,
  wrong role/PCR/context, absent Recipient, extra context keys, prohibited key
  operations, HTTPS, conditional object creation, object scope, and deletion.
- Validly authorized requests with an incorrect SigV4 secret are rejected.
  Post-signing payload tampering is also rejected. The enclave rejects an
  untrusted CA, wrong TLS hostname, and plaintext HTTP endpoint.

The transaction exercised across process boundaries is an existing gas-key
EIP-1559 transaction. This suite validates swap seed custody and recovery; it
does not fabricate a Bitcoin/EVM chain or an RGB consignment. Existing RGB
validation/signing and mint/burn regression tests cover those rules separately.
No signing implementation is changed by this branch's test hooks.

## Open-source components and simulation boundary

[Moto 5.2.3](https://github.com/getmoto/moto/tree/5.2.3) (Apache-2.0) supplies IAM
users/roles, STS sessions, signature authentication, KMS random generation and
AES-GCM ciphertext, authenticated encryption context, and S3 storage and
conditional writes. IAM authorization is enabled after local fixture bootstrap;
the suite does not leave Moto's default authentication bypass enabled.

Moto does not implement Nitro Recipient responses and its resource-policy
condition coverage is limited. `emulator.py` therefore wraps its real KMS result
in CMS using RSA-OAEP SHA256/MGF1 SHA256 and AES-256-CBC, taking the recipient key
from the repository's explicitly mocked CBOR attestation. It removes `Plaintext`
and supplies the AWS `Decrypt.EncryptionAlgorithm` field omitted by Moto. It also
checks an incoming KMS payload hash against the body before native SigV4
authentication; Moto otherwise trusts that header without rehashing the body.
These are test adapter behaviors, not changes to the production KMS client.

The exact checked-in KMS and S3 resource policies, with fixture substitutions,
run through [@actsecurity/iam-simulate 0.1.177](https://github.com/act-security-labs/iam-simulate)
(AGPL-3.0-or-later) in a separate local Node process. The policy engine evaluates
Principal, action/resource, attestation PCR, context, and explicit deny conditions
in Strict mode after Moto's native signature/identity checks. Policy validation
errors abort the suite.

The pinned simulator's action metadata filter drops some valid dynamic KMS
context keys. The adapter validates the policy, recognizes only the known AWS
KMS context keys, and uses the same engine's public unfiltered entry point to
retain them. Audit entries identify retained context keys. Unknown ignored keys
or engine errors fail the test; production policies are not weakened to fit an
emulator.

Native processes use the gated `local-kms-e2e` feature for a local CA and mock PCR0
(`aa` repeated 48 bytes for bootstrap, `bb` for recovery). It retains the AWS
hostname, HTTPS-only transport, certificate/hostname validation, and disabled
redirects. Release compilation with this feature is prohibited. These mocks do
not validate AWS's Nitro trust chain, real NSM evidence, vsock transport, or AWS
service-policy enforcement. Those still require a real Nitro deployment.

The fixture control API deliberately permits out-of-band ciphertext replacement
and corruption to model a hostile or faulty storage host. That control is not an
AWS API or part of the production broker. Moto state lives for one suite run;
the suite restarts the signer and broker while the emulated S3 service stays up.

## Production fix found and backported

An immediate restart of the broker's development TCP listener failed because its
closed connections remained in `TIME_WAIT`. Enabling `SO_REUSEADDR` on that TCP
listener fixes the restart; the production vsock listener is unchanged.

- Testing commit: `45f3b10`.
- Backport to `codex/rgb-swap-kms-persistence`: `c9b71d9`.

No emulator dependencies, local trust hooks, or generated test artifacts are
included in that backport. RGB mint/burn and the signing implementations are
unchanged.

Linux release binaries for both flows and a real ARM64 validation EIF were also
built successfully. See [build evidence and reproduction commands](build-validation-notes.md)
for the pinned tools, artifact hashes, runtime compatibility checks, and limits.
