# Runtime limits

The enclave has time, memory and size limits. The operator can change them on a
running enclave. A change needs no new image, so the PCR values and the keys do
not change.

Each limit only sets when the enclave refuses a request, or how long it waits.
The safety rules stay in the image (see
[What stays in the image](#what-stays-in-the-image)). The mint replay guard is a
limit because it is not a safety rule (see
[The mint replay guard](#the-mint-replay-guard)).

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
| `total_request_timeout_secs` | 90 | 10 | 86400 | Socket deadline of a request, from accept. |
| `io_idle_timeout_secs` | 10 | 2 | 3600 | Longest block of one socket read or write. |
| `first_bytes_timeout_secs` | 10 | 1 | 3600 | Time for the first bytes of an egress client. |
| `electrum_timeout_secs` | 15 | 1 | 3600 | Time for one Electrum socket operation. |
| `esplora_timeout_secs` | 30 | 1 | 3600 | Time for one Esplora call. |
| `evm_rpc_timeout_secs` | 15 | 1 | 3600 | Time for one EVM RPC call. |
| `max_rgb_lib_ms` | 30000 | 1000 | 86400000 | Modeled rgb-lib time on one consignment. |
| `max_witness_check_cost` | 134217728 | 1048576 | 2^50 | Steps to check transitions against witness txs. |
| `max_bundle_id_cost` | 262144 | 1024 | 2^50 | Steps to hash bundle ids. |
| `max_reject_walk_cost` | 67108864 | 1048576 | 2^50 | Steps of the reject-list walk. |
| `max_reject_list_entries` | 20000 | 1 | 2^32 | Entries of a reject list. |
| `reject_list_page_entries` | 1000 | 1 | 2^20 | Entries in one RPC call that reads a reject list. |
| `max_message_bytes` | 25165824 | 1048576 | 2^32 - 1 | Size of one frame. |
| `max_wire_elements` | 524288 | 1024 | 2^32 | Protobuf field occurrences in a request. |
| `max_consignment_bytes` | 10485760 | 1024 | 2^32 | Size of a consignment. |
| `max_merkle_proofs` | 16384 | 1 | 2^32 | Merkle proofs of a request. |
| `max_total_proof_bytes` | 8388608 | 1024 | 2^32 | Size of all the proofs of a request. |
| `max_psbt_bytes` | 1048576 | 1024 | 2^32 | Size of a PSBT or a fascia. |
| `max_gas_tx_bytes` | 1048576 | 1024 | 2^32 | Size of an unsigned gas transaction. |
| `max_rlp_items` | 1024 | 16 | 2^20 | RLP items of a gas transaction. |
| `max_funds_out_call_data_bytes` | 98304 | 1024 | 2^32 | Size of the calldata of a fundsOut. |
| `max_headers_per_submit` | 10000 | 1 | 2^32 | Headers in one `SubmitHeaders`. |
| `max_headers_per_minute` | 100000 | 1 | 2^40 | Headers in one minute. |
| `mint_replay_ttl_secs` | 3600 | 120 | 31622400 | Time that the mint signer refuses a second request for a deposit. |
| `mint_replay_max_entries` | 100000 | 1024 | 2^32 | Deposits in the mint replay guard. |
| `mint_max_inputs` | 16 | 1 | 2^20 | Inputs of a mint transaction, before the enclave decodes a fascia. |
| `mint_max_outputs` | 16 | 1 | 2^20 | Outputs of a mint transaction, before the enclave decodes a fascia. |

The image env can lower `max_consignment_bytes`, `max_merkle_proofs` and
`max_total_proof_bytes`. Then `limits show` prints those values as the image
values.

The lowest values keep the enclave reachable, so the operator can always send a
new `limits set`. The highest values are very wide on purpose, because validation
takes longer as histories grow. They only stop a typing error and an overflow. The
rules below protect the enclave.

## Rules for a change

The enclave checks all the new values first. If one check fails, the enclave
refuses the request and changes nothing.

- Each value must be in its range.
- `max_rgb_lib_ms` must be at most three quarters of `total_request_timeout_secs`.
  A request that passes the deadline does all its work, and then it cannot send
  its reply. So 30 s of rgb-lib needs a deadline of at least 40 s.
- `io_idle_timeout_secs` must be at most `total_request_timeout_secs`.
- `mint_replay_ttl_secs` must be above `total_request_timeout_secs`, so an entry
  outlives the request that made it.
- The densest consignment at `max_consignment_bytes` must fit the heap of a frame
  (`enclave/src/memory.rs`). So a larger consignment needs a larger
  `max_message_bytes`.
- A densest consignment and a reject list at `max_reject_list_entries` must fit
  the heap of a frame together. At the image values, the list limit stops at about
  33,000 entries. Each MiB less of `max_consignment_bytes` gives room for about
  250,000 more entries.
- Two dense PSBTs at `max_psbt_bytes` must fit the heap of a frame.
- A release build must have enough usable memory for four requests at the new
  limits, and the baseline. A larger frame can need a larger `run-enclave --memory`
  value, which needs a new launch.

## The reject list

The enclave refuses each burn of an asset whose list is over
`max_reject_list_entries`. The list is append-only, so it cannot get shorter. Raise
the limit before the list reaches it.

Each page is one RPC call, and the calls use the time of the request deadline. At
about a second for each page, a long list also needs a larger
`total_request_timeout_secs`. `reject_list_page_entries` does not change what the
enclave reads.

## The mint replay guard

The mint signer refuses a second request for a deposit for `mint_replay_ttl_secs`.
The PSBT is not part of the key. So the guard also refuses a mint that the listener
builds again with other inputs or a higher fee.

This guard is not the safety control of a mint. Each signature for one mint spends
the same UTXO, so at most one can reach the chain
([mint-flow.md](mint-flow.md), section 6). A restart clears the guard. So a change
gives the host nothing that it does not have already. The guard reads the two limits
at each call, so a change applies to the entries that it holds.

Keep `SIGNED_RESPONSE_TTL_SECS` on the parent at the same value or higher. If the
parent drops a reply first, the enclave refuses the retry until the window ends.

## Measured times

These times come from a debug-mode enclave on an `m6i.2xlarge` (Intel Xeon Platinum
8375C at 2.9 GHz, nitro-cli 1.4.5) on 2026-11-05, with 4096 MiB. `MemTotal` was
3943 MiB. The request is a history of 10,000 transfers with a proof on each. The
model gives it 19.95 s.

| Requests at once | 2 vCPUs (1 core) | 4 vCPUs (2 cores) |
|---|---|---|
| 1 | 14.3 s | 14.3 s |
| 2 | 26.8 s | 14.9 s |
| 4 | 52.8 s | 27.1 s |

The default launch has 2 vCPUs, and these are two threads of one core. So four
requests take 3.7 times as long as one. On every shape measured, the time of one
request was at or below the model.

An honest history at the 10 MiB limit models at about 23 s. Four of them at once take
about 65 s on 2 vCPUs, so they fit the deadline of the image, 90 s. A forged request
can model at the 30 s of `max_rgb_lib_ms`. Four of these at once can take about 110 s
on 2 vCPUs, and they lose their replies. On 4 vCPUs they take about 57 s.

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
- the replay guard of the clone handshake and the rate of rights refills
- the pins: chain ids, contracts, the asset, the KMS accounts

These values also stay constants:

- `WORKER_THREADS` and `MAX_QUEUED_CONNECTIONS`: the enclave sets up the accept
  loop at boot.
- `MAX_RLP_DEPTH`: it keeps the decoder from using all of the stack.
- `MAX_STORED_HEADERS`: at the mainnet block rate, the chain reaches it in about
  19 years.
- The rates of the cost model (`validation/cost.rs`) and of the memory model
  (`memory.rs`). They describe the code of the image, so they change with the code.
  `max_rgb_lib_ms` and the request deadline already cover a slower CPU.
- Small fixed formats, such as a mnemonic, a KMS reply and an attestation document.
- The KMS and seed recovery timeouts.

## The parent

The parent reads `total_request_timeout_secs` from the enclave every 5 s, and it
waits 10 s longer for each reply. The enclave must give up first. Its failed write
rolls the replay key back. A parent that gives up first leaves a committed key and a
response that nobody read. So a change of the deadline needs no change on the
parent. For up to 5 s after a change, the parent can use the old value.

Two timeouts above the parent do not follow the deadline: `GRPC_REQUEST_TIMEOUT_SECS`
on the parent (default 120 s), and the timeout of the backend (2 minutes). A deadline
above 110 s also needs a change of these two values.

The parent has its own frame limit (`parent/src/framing.rs`). A value of
`max_message_bytes` above 24 MiB has no effect until the parent limit also changes.
