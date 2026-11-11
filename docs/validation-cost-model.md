# Validation cost model

This document is for a maintainer of the burn signer's work caps. An
operator needs only [runtime-limits.md](runtime-limits.md). The burn flow is
in [burn-flow.md](burn-flow.md).

## Why a model

The request deadline does not stop a worker, and parts of rgb-lib's work on
a consignment grow faster than the file. So the burn signer computes the cost
of a parsed transfer before rgb-lib runs, and refuses a transfer above a
limit. The code is `enclave/src/networks/rgb/validation/cost.rs`.

## What the model counts

| Limit | Cost of a consignment | Honest burn of 2810 mints |
|-------|-----------------------|---------------------------|
| `max_witness_check_cost` | Per bundle: transitions x (transaction bytes + Tapret partner leaf bytes) + seals x transaction inputs | 8,539,773 steps, about 6 percent of the image value |
| `max_bundle_id_cost` | Per bundle: (transitions + 1) x input map entries | 11,242 steps, about 4 percent |
| `max_reject_walk_cost` | For an asset with a reject list: the steps of a walk from each origin on its own | 14,050 steps, under 0.1 percent |
| `max_rgb_lib_ms` | The modeled time of validation and inspection, below | 6.1 s, about 20 percent |

The modeled time is a weighted sum. The weights are the constants of
`cost.rs`:

- validation: file bytes, outputs created or spent, genesis leaf hashes, and
  the steps of the three costs above;
- inspection: file bytes, outputs, operations and witness steps.

Why each term is there:

- **Outputs.** rgb-consensus hashes every output of an operation into the
  operation id, several times per operation. So an output costs rgb-lib far
  more than its bytes: a mint right in a propagate is 14 bytes.
- **Genesis leaves.** rgb-consensus hashes every genesis global and
  assignment again for each operation that it validates. So the cost of an
  operation grows with the genesis of the pinned asset.
- **Inspection.** rgb-lib's validation returns no amounts. The burn signer
  reads them with `inspect_consignment`, which decodes the file again and
  hashes each operation id again. It costs about as much per output as
  validation.
- **Walk.** The count walks each origin on its own. rgb-lib shares one walk
  across origins. So the count is a model of rgb-lib's steps: it counts a
  shared history once per origin, and where nothing is shared it can fall
  short by up to a factor of two.

## Measurements

Release mode, Intel Xeon Platinum 8375C at 2.90 GHz (the CPU of the burn
hosts), 2026-11-10, two runs of each shape. Source `34721c5eb5d4`, rgb-lib
`5010eefa355b`, rgb-consensus `d4bbbce212e4`, Rust 1.96.1. The honest burns
use the pinned genesis of 10 mint rights, and the forged histories a genesis
of 1 right, unless the row names more. The pin has since moved to rgb-lib
`2f7b21d8637b`, and no shape was measured on it yet
([when to measure again](#when-to-measure-again)).

| Consignment | Size | Outputs | Model (s) | Validation (s) | Inspection (s) | Largest total / model | Allowance (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Honest burn, 2810 mints | 2.0 MB | 11k | 6.100 | 3.079–3.086 | 1.846–1.851 | 0.809 | 10 |
| Honest burn, 2810 mints, 3 transfers a line | 6.0 MB | 28k | 17.910 | 10.149–10.165 | 5.571–5.574 | 0.879 | 35 |
| Honest burn, 2810 mints, genesis of 255 rights | 2.1 MB | 11k | 16.487 | 13.448–13.541 | 1.865–1.871 | 0.934 | 35 |
| Forged chain of 2000 one-right propagates | 0.9 MB | 4k | 2.471 | 0.931–0.933 | 0.850–0.852 | 0.722 | 5 |
| The same chain, genesis of 255 rights | 0.9 MB | 4k | 10.145 | 8.587–8.610 | 0.873–0.878 | 0.935 | 20 |
| Forged fan-out to 65,535 outputs | 1.5 MB | 66k | 10.505 | 5.097–5.122 | 5.030–5.054 | 0.969 | 25 |
| Forged burn of 65,535 rights | 7.7 MB | 131k | 29.855 | 8.736–8.769 | 9.474–9.526 | 0.613 | 40 |
| Forged chain of 13 propagates of 65,535 rights (refused) | 11.9 MB | 852k | 123.122 | 47.664–47.899 | 55.380–55.675 | 0.841 | 210 |
| Forged bundle of 64 burns, transaction of 49,900 dummy inputs, at the witness cap | 2.4 MB | 130 | 7.213 | 1.898–1.904 | 1.282–1.299 | 0.444 | 10 |
| Forged bundle of 512 burns, just over the bundle id cap (refused) | 0.1 MB | 1k | 1.581 | 1.337–1.362 | 0.135–0.135 | 0.947 | 5 |
| Forged bundle of 2048 burns (refused) | 0.4 MB | 4k | 20.472 | 17.677–18.010 | 0.536–0.537 | 0.906 | 40 |
| Forged fan-out of 65,535 after 500 transfers, with a reject list, near the walk cap | 1.7 MB | 67k | 16.078 | 5.446–5.455 | 5.261–5.294 | 0.669 | 25 |

- The model is validation plus inspection. On every shape, validation,
  inspection and their sum are within the model. The largest sum is 96.9
  percent of its model.
- The allowance is twice the largest measured sum, rounded up to five
  seconds. [The smaller-host profile](runtime-limits.md#smaller-production-host)
  uses it. The ratios use the timings before rounding.
- The model values of the two refused bundles are diagnostic: the bundle id
  cap refuses both before the time budget applies. The chain of 13 propagates
  is refused too. The inspection times of these three rows measure work that
  the gate prevents: the burn signer inspects a consignment only after its
  validation passed.
- The resolvers of the timing test are in memory. So the times are the CPU
  work of rgb-lib, with no RPC, no enclave overhead and no other request at
  the same time. [runtime-limits.md](runtime-limits.md#measured-times) has
  times from a real enclave. On every shape measured there, one request took
  at most its modeled time.

The ignored `caps::timings` test measures the twelve shapes. The `caps` tests
also check the chain from a genesis of 255 rights and the read of the last
bundle of a wide burn. Run them in release mode:

```bash
cargo test --release -p utexo-bridge-enclave --no-default-features --features spv,burn-signer --lib caps -- --ignored --nocapture --test-threads=1
```

Each `RGB_COST` line is a JSON record of one shape: the validation and
inspection times, their sum, the model terms, the work counts and the
decision of the gate. The test checks that a valid fixture passes rgb-lib,
and that an unmined forged fixture reaches the witness phase.

## What the model refuses in an honest history

- **The time budget** refuses a history past its modeled time. On the pinned
  genesis that is about 10 MB of plain transfers, about the size limit. A
  history of 10,000 transfers with an SPV proof on each (8.9 MB) passes at
  19.95 s. On a genesis of 255 rights the genesis hashes add 3.9 ms to each
  operation. A one-right propagate then models at about 5 ms, so the budget
  refuses a history past about 5,900 operations, whatever its size.
- **The walk cap**, for an asset with a reject list, can refuse an
  exact-amount burn. With no change there is no split, so each input is an
  origin, and the count walks each one on its own. Thousands of inputs that
  were paid off one long chain of payments reach the cap. A burn with change
  has one origin.

The operator can raise each limit on a running enclave.

## What the model does not prove

- The measurements cover one CPU model. The closest shape leaves about 3
  percent of its modeled time, and repeated runs do not prove an upper
  bound. A shape that costs rgb-lib more per byte, output, operation or
  genesis leaf than the measured ones runs past its modeled time. So does a
  busy or slower CPU.
- The budget is rgb-lib's alone. The enclave's own parse, gate and reads of
  the transfer run outside it.

## When to measure again

Measure again when the rgb-lib or rgb-consensus pin changes, or when
`cost.rs` changes. Use the pinned dependencies and compiler, the release
profile, and the CPU used by the burn enclaves. Run the command above at
least twice with one test thread and no concurrent build or benchmark.
Keep scratch files in RAM, as they are in the enclave. Record the source
revision, dependency pins, compiler, CPU, load, CPU affinity, scratch storage
and number of runs with the results.

Compare validation plus inspection with the Model column, using the exact
`model_total_ns` from the same fixture to avoid rounding errors. Also keep
the two phases separately. A row refused by a structural cap does not have
an admitted time budget; its printed time model is diagnostic. Host timings
with in-memory resolvers measure CPU work, not live RPC latency, enclave
overhead or simultaneous requests. Measure concurrency separately before
choosing a request deadline.

If every admitted shape fits its model, no change of coefficients or limits
is needed for that measured CPU and load. A smaller host or a different
concurrent workload still needs its own allowance and verification.
If a shape takes `k` times its model, runtime limits can account for the
observed slowdown without rebuilding the image: lower `max_rgb_lib_ms` to
admit less work for the same wall-time budget, or increase
`total_request_timeout_secs` to allow the same work more time. The modeled
budget does not turn into a stopwatch, and increasing it admits more work.
Include the enclave's own work, RPCs and concurrency when choosing the
deadline. Apply and persist the settings as described in
[runtime-limits.md](runtime-limits.md#commands).

For a recalibrated model, change the `NS_PER_*` and `INSPECT_NS_*` constants
in `cost.rs`, repeat every shape, and update this table. Those coefficients
are image code: deploying them needs a new EIF and new approved PCRs. Record
any remaining overrun; a passing result on another CPU does not resolve it.
