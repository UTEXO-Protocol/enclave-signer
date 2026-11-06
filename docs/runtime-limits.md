# Runtime limits

The enclave has time, memory and size limits. The operator can change them on a
running enclave. A change needs no new image, so the PCR values and the keys do
not change.

Each limit only sets when the enclave refuses a request, or how long it waits.
No limit changes what the enclave signs. The safety rules stay in the image (see
[What stays in the image](#what-stays-in-the-image)).

## Commands

The commands use the parent CLI. Give the address of each enclave. A change
applies to that enclave only.

```bash
utexo-bridge-parent-cli --addr vsock://16:5000 limits show
```

```bash
utexo-bridge-parent-cli --addr vsock://16:5000 limits set max_rgb_lib_ms=24000 total_request_timeout_secs=40
```

```bash
utexo-bridge-parent-cli --addr vsock://16:5000 limits set --file /etc/utexo/enclave-limits.conf
```

```bash
utexo-bridge-parent-cli --addr vsock://16:5000 limits reset
```

`limits show` prints the current value and the image value of each limit.
`limits set` changes the limits that it names, and the other limits keep their
values. `limits set --reset` goes back to the image values first. `limits reset`
goes back to the image values. Each command prints the table of `limits show`.

The next request uses the new values. A request that is in progress keeps the
values that it read.

## After a restart

A change stays until the enclave restarts. Then the enclave uses the image values.

To keep values, put them in `/etc/utexo/enclave-limits.conf`.
`ENCLAVE_LIMITS_FILE` can name another file. The file has one `NAME=VALUE` on each
line. The text after a `#` is a comment:

```text
# Long histories.
max_rgb_lib_ms=24000
total_request_timeout_secs=40
```

`deploy-host.sh` and `utexo-enclave-ctl.sh` send this file at each launch, before
`set-endpoints`. If the enclave refuses the file, it logs the refusal, it keeps the
image values, and the launch continues.

## Limits

| Limit | Image | Lowest | Highest | Sets |
|---|---|---|---|---|
| `total_request_timeout_secs` | 30 | 10 | 100 | Socket deadline of a request, from accept. |
| `io_idle_timeout_secs` | 10 | 2 | 60 | Longest block of one socket read or write. |
| `first_bytes_timeout_secs` | 10 | 1 | 60 | Time for the first bytes of an egress client. |
| `electrum_timeout_secs` | 15 | 1 | 90 | Time for one Electrum socket operation. |
| `esplora_timeout_secs` | 30 | 1 | 90 | Time for one Esplora call. |
| `max_rgb_lib_ms` | 18000 | 1000 | 75000 | Modeled rgb-lib time on one consignment. |
| `max_witness_check_cost` | 134217728 | 1048576 | 4294967296 | Steps to check transitions against witness txs. |
| `max_bundle_id_cost` | 262144 | 1024 | 16777216 | Steps to hash bundle ids. |
| `max_reject_walk_cost` | 67108864 | 1048576 | 2147483648 | Steps of the reject-list walk. |
| `max_message_bytes` | 25165824 | 1048576 | 268435456 | Size of one frame. |
| `max_wire_elements` | 524288 | 1024 | 16777216 | Protobuf field occurrences in a request. |
| `max_consignment_bytes` | 10485760 | 1024 | 134217728 | Size of a consignment. |
| `max_merkle_proofs` | 16384 | 1 | 1048576 | Merkle proofs of a request. |
| `max_total_proof_bytes` | 8388608 | 1024 | 134217728 | Size of all the proofs of a request. |
| `max_psbt_bytes` | 1048576 | 1024 | 16777216 | Size of a PSBT or a fascia. |
| `max_gas_tx_bytes` | 1048576 | 1024 | 16777216 | Size of an unsigned gas transaction. |
| `max_rlp_items` | 1024 | 16 | 1048576 | RLP items of a gas transaction. |
| `max_funds_out_call_data_bytes` | 98304 | 1024 | 16777216 | Size of the calldata of a fundsOut. |
| `max_headers_per_submit` | 10000 | 1 | 1048576 | Headers in one `SubmitHeaders`. |
| `max_headers_per_minute` | 100000 | 1 | 16777216 | Headers in one minute. |

The image env can lower `max_consignment_bytes`, `max_merkle_proofs` and
`max_total_proof_bytes`. Then `limits show` prints those values as the image
values.

The lowest values keep the enclave reachable, so the operator can always send a
new `limits set`.

## Rules for a change

The enclave checks all the new values first. If one check fails, the enclave
refuses the request and changes nothing.

- Each value must be in its range.
- `max_rgb_lib_ms` must be at most three quarters of `total_request_timeout_secs`.
  A request that passes the deadline does all its work, and then it cannot send
  its reply. So 30 s of rgb-lib needs a deadline of at least 40 s.
- `io_idle_timeout_secs` must be at most `total_request_timeout_secs`.
- The densest consignment at `max_consignment_bytes` must fit the heap of a frame
  (`enclave/src/memory.rs`). So a larger consignment needs a larger
  `max_message_bytes`.
- Two dense PSBTs at `max_psbt_bytes` must fit the heap of a frame.
- A release build must have enough usable memory for four requests at the new
  limits, and the baseline. A larger frame can need a larger `run-enclave --memory`
  value, which needs a new launch.

## What the attestation shows

The attestation does not cover these values. Two enclaves with the same PCR values
can have different limits. Anyone who can reach the enclave from the parent
instance can change them. The gRPC service of the parent does not expose
`SetLimits`, so a gRPC client cannot change them.

## What stays in the image

These values stay in the image, because they decide what the enclave signs:

- the SPV depth, the SPV tip age and the header rules
- `EVM_FINALITY_TAG`
- the fee limits, the sats budgets, the gas limits and the mint witness amount
- the replay windows and their capacity
- the pins: chain ids, contracts, the asset, the endpoints hash

These values also stay constants:

- `WORKER_THREADS` and `MAX_QUEUED_CONNECTIONS`: the enclave sets up the accept
  loop at boot.
- `MAX_RLP_DEPTH`: it keeps the decoder from using all of the stack.
- Small fixed formats, such as a mnemonic, a KMS reply and an attestation document.
- The KMS and seed recovery timeouts.

## The parent

The parent waits 110 s for a `Sign`. That is 10 s more than the highest
`total_request_timeout_secs`, because the enclave must give up first. So a change of
the deadline needs no change on the parent. The parent waits 40 s for each other
request, because these requests do not validate a consignment.

The parent has its own frame limit (`parent/src/framing.rs`). A value of
`max_message_bytes` above 24 MiB has no effect until the parent limit also changes.
