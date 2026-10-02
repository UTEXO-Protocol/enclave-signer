# Clone CLI completion results (v1)

F03-AF-05: a lost `SetClone` response does not prove that cloning failed. The
requester may already have installed its keys. The CLI sends `SetClone` once
and then reads the requester keys once, including after a response error.

## Automation contract

The `clone` command prints one final line on stdout:

```text
CLONE_RESULT_V1=recovered_success
```

Parse the complete line beginning with `CLONE_RESULT_V1=`. Other output is
human-readable and is not an automation interface. Exit codes remain compatible:
zero for verified success, one for all other completion results.

- `success` (exit 0): SetClone was acknowledged; the observed requester matches
  `--donor-evm` and all 13 fields of the donor bundle.
- `recovered_success` (exit 0): SetClone returned an error or exceeded its wait
  budget, but the same full identity check succeeded. No mutation is retried.
- `identity_mismatch` (exit 1): requester keys were readable but failed the
  expected EVM or full bundle comparison. Do not activate this requester.
- `not_initialized` (exit 1): SetClone returned an error and the requester
  explicitly answered `code=1, message="key not initialized"`. This is a
  snapshot of absent keys, covering Initial **or** Cloning; the existing wire
  API cannot distinguish those phases. It is not proof of durable failure or
  permission to retry a mutation.
- `unknown` (exit 1): the requester identity could not be established within
  the read budget, another error occurred, or SetClone is still pending while
  no keys are observed. This also covers contradictory observations such as an
  acknowledged SetClone followed by absent keys. Reconcile read-only before
  deciding what to do next; do not automatically repeat SetClone or initialize
  new keys.
- `preflight_error` (exit 1): the command failed before sending SetClone.
  InitiateCloning or the donor export may already have happened. This does not
  mean the requester is Initial or that the donor request can safely be retried.

Argument parsing failures, process termination, and output failures may produce
no marker. A missing or unrecognized marker must be treated as unknown by a
supervisor, regardless of any partial progress lines.

## Identity and timing

The donor comparison bundle is fetched before sending SetClone. The donor EVM
must match the operator-supplied address. After mutation, recovery requires no
additional donor RPC, and there is no second requester key read that could turn
an already verified success into a transport failure.

The comparison includes ten key-derived fields: EVM address/public key, Bitcoin
compressed public key/xpub/master fingerprint, vanilla/colored account xpubs,
gas-transaction EVM public key/address, and CCD Ed25519 public key. It also checks
chain ID, bridge contract, and RGB asset ID. The donor RPC is a reported-value
cross-check; the enclave's AF-08 attested commitment check remains the trust gate.

The CLI waits at most 750 ms for SetClone, then at most 750 ms for the read-only
observation (1.5 seconds of waiting, leaving headroom for the F03-IT-03 two-second
completion target). Blocking calls run on at most two dedicated threads so DNS,
TCP/vsock connection, partial reads, and a silent peer cannot extend those waits.
This helper belongs to the one-shot CLI: the process exits after reporting and
terminates remaining I/O workers. A deadline does **not** cancel a request already
received by the enclave; a pending request may still commit. Outcomes are
observations, not durable per-session receipts or guarantees across restart.

These changes affect the host CLI only. The enclave wire schema and EIF do not
change; install the rebuilt CLI to use v1 results.

## Validation

From `parent/`, run:

```sh
cargo test --locked --test test_clone_completion
```

The tests use real enclave state, key derivation, clone encryption, and request
handlers with mock NSM attestation. Faults cover response write failure, dropped
response, malformed protobuf, and a stalled response **after Active commit**;
they require matching donor keys, a single SetClone, a single key query, and
completion within two seconds. Every identity/config field is independently
changed to reject false recovery. Rejected SetClone, pending mutation, read
timeout, and unrelated enclave errors exercise non-success outcomes. The real
CLI is also run through the parent gRPC service to check exit codes and markers.
These tests do not replace Nitro/vsock stage validation.
