# Burn signer seed cloning

A burn signer makes its seed from OS entropy and keeps it in memory only. A
second burn enclave gets the same seed through the cloning handshake. The
handshake serves two jobs: a replica of a signer, and recovery after a
restart. A mint signer does not clone. It recovers its seed through
[KMS](kms-persistence.md).

A clone signs as the same EVM address as its donor. Clones are replicas of
one signing identity. They are not independent quorum members.

## What a clone needs

The handshake succeeds only between two enclaves that:

- run the same image: PCR0, PCR1 and PCR2 are equal;
- run under the same parent instance IAM role: PCR3 is equal and not all
  zero;
- have the same policy commitment, so the same attested launch values;
- name the same cluster key, the EVM address of the donor;
- hold the same cloning secret.

PCR0, PCR1 and PCR2 are the same for every instance of a published image, in
any AWS account. PCR3 binds the peer to the operator's role. An enclave on an
instance without an IAM role cannot clone. Recovery onto an instance with
another role fails by design. A production burn enclave on an instance
without an IAM role refuses `SetEndpoints`, so it signs nothing.

The cloning secret is an operator value, at least `MIN_CLONING_SECRET_BYTES`
long with at least `MIN_CLONING_SECRET_DISTINCT_BYTES` different byte values.
A donor learns it at run time, from `init --cloning-secret-file` or from a
completed clone. A burn signer that got `init` without the secret can never
donate. No supplied recipe puts the secret in an image; a release burn
binary still reads `UTEXO_CLONING_SECRET` from the image env at boot.

## The handshake

Three messages. Each side verifies the other's attestation document
([sequence diagram](diagrams/06-seq-cloning.md)).

1. **`InitiateCloning`** on the new enclave (the requester). It makes an
   ephemeral X25519 key and an attestation document that binds this key and
   an HMAC, under the cloning secret, of the key and the donor's EVM address.
   The requester enters `Cloning`. While a session is younger than
   `CLONING_SESSION_TTL`, the enclave refuses a second `InitiateCloning`.
   After that time a new one replaces the session. `SetClone` does not check
   the age.
2. **`GetClone`** on the donor, through the gRPC `Clone` RPC of the donor's
   parent. The donor checks the HMAC, the requester's attestation, the PCRs
   and its export cap. Then it records the attestation nonce and encrypts the
   seed to the requester's key. The donor stays `Active`.
3. **`SetClone`** on the requester. It verifies the donor's attestation and
   PCRs, decrypts the seed, and checks that the derived EVM address is the
   cluster key and that the donor committed to the same key bundle, policy
   and transcript. Only then does it install the keys and go `Active`.

The seed ciphertext is bound to both handshake keys, and the key exchange
refuses small-order points. A donor records a nonce only after the
authentication passed, so a refused handshake uses no space in the replay
guard. A failed `SetClone` leaves the requester in `Cloning`, and it changes
no keys. The secret of a completed session replaces a donor secret that was
loaded at boot. A replaced or dropped session erases its pending secret; the
expiry alone does not.

## The `clone` command

```bash
utexo-bridge-parent-cli --addr vsock://<CID>:5000 clone \
  --cloning-secret-file <file> \
  --donor-grpc https://<donor parent>:<port> \
  --donor-evm 0x<donor EVM address>
```

The command runs on the requester's host. It needs a client certificate with
the `clone-operator` role for the donor's parent
([parent-mtls.md](parent-mtls.md)). Use a fresh requester: initialization and
cloning are two ways into `Active`, and an enclave takes only one.

After its arguments parse, the command prints exactly one line
`CLONE_RESULT_V1=<result>` on stdout, among progress lines and the key
printout. It prints the detail on stderr. Automation must read the result
line, not the exit code alone. A usage error prints no result line and exits
with code 2.

| Result | Meaning | Exit code |
| --- | --- | --- |
| `success` | `SetClone` was acknowledged. The new enclave has the donor's EVM address and all 10 identity fields. | 0 |
| `recovered_success` | The `SetClone` reply was an error, lost or late. The read-back shows the donor's identity. | 0 |
| `identity_mismatch` | The new enclave has keys, but they differ from the donor's. | 1 |
| `not_initialized` | `SetClone` returned an error and the new enclave has no keys at the read-back. This is not a final state. Do not retry `SetClone` blindly. | 1 |
| `unknown` | The CLI could not read the identity back. Check the enclave with a read-only command. Do not retry `SetClone` automatically. | 1 |
| `preflight_error` | The command failed before it sent `SetClone`, for example no cloning secret or a donor bundle that does not match `--donor-evm`. | 1 |

After `SetClone` the CLI reads the identity back, also when the reply was
lost. It waits a short fixed time for `SetClone` and for the read-back
(`SET_WAIT` and `READ_WAIT` in `parent/src/bin/cli/clone_completion.rs`). A
timeout does not cancel `SetClone` and does not prove that it failed. After
a failed `clone`, wait for the session to expire or restart the requester.

## Limits

- **A clone can donate.** A completed clone keeps the cloning secret and can
  donate to another replica, also when its own donor is gone.
- **No revocation.** Blocking the original donor does not revoke its clones.
- **A new image cannot clone from an old one.** Their PCRs differ. A burn
  signer on a new image makes a new seed, so it has a new signing address.
- **The export cap is per enclave.** `CLONE_EXPORT_HARD_CAP` limits the seed
  exports of one enclave process. It is not a limit on the replicas of a
  cluster. Unset or zero means no cap, and no supplied image sets it. A set
  value that is not an unsigned integer stops the boot.
- **The replay guard is per donor.** Each donor refuses an attestation nonce
  that it recorded. Another donor accepts the same requester attestation. An
  entry leaves the guard when it expires or when the guard is full.
- **The seed stays in memory.** A donor keeps the seed so that it can encrypt
  it for each clone. A restart removes it: the enclave must clone again from
  a live donor.

These properties are accepted by design. The authorization of a clone rests
on the operator's secret, which is delivered at run time and is in no PCR.
