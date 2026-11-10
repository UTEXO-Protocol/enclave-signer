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

Release mode, Apple M1 Pro, 2026-10-30, load under 4, two runs each, on
rgb-lib 1ae1c160. Nothing here was measured on the pinned rgb-lib, which
shares the reject walk across origins, so the walk times below overstate it.
The honest burns use the pinned genesis of 10 mint rights, and the forged
histories a genesis of 1 right, unless the row names more. The model column
is validation plus inspection.

```bash
cargo test --release -p utexo-bridge-enclave --no-default-features --features spv,burn-signer --lib caps -- --ignored --nocapture --test-threads=1
```

| Consignment | Size | Outputs | Model | rgb-lib validation | rgb-lib inspection |
|-------------|------|---------|-------|--------------------|--------------------|
| Honest burn, 2810 mints | 2.0 MB | 11k | 6.1 s | 2.7 to 2.8 s | 1.9 to 2.2 s |
| Honest burn, 2810 mints, 3 transfers a line | 6.0 MB | 28k | 17.9 s | 8.8 to 9.2 s | 5.7 to 5.8 s |
| Honest burn, 2810 mints, genesis of 255 rights | 2.1 MB | 11k | 16.5 s | 12.5 to 13.4 s | 2.0 s |
| Forged chain of 2000 one-right propagates | 0.9 MB | 4k | 2.5 s | 0.94 to 0.97 s | 0.87 to 0.89 s |
| The same chain, genesis of 255 rights | 0.9 MB | 4k | 10.1 s | 7.83 to 7.86 s | 0.88 to 0.89 s |
| Forged fan-out to 65,535 outputs | 1.5 MB | 66k | 10.5 s | 4.69 to 4.70 s | 4.65 to 4.67 s |
| Forged burn of 65,535 rights | 7.7 MB | 131k | 29.9 s | 9.0 to 9.3 s | 9.7 to 9.8 s |
| Forged chain of 13 propagates of 65,535 rights (refused) | 11.9 MB | 852k | 123.1 s | 44.3 s | 51.3 s |
| Forged bundle of 64 burns, transaction of 49,900 dummy inputs, at the witness cap | 2.4 MB | 130 | 7.2 s | 1.94 to 1.95 s | 1.96 to 1.97 s |
| Forged bundle of 512 burns, just over the bundle id cap (refused) | 0.1 MB | 1k | - | 1.16 s | 0.14 s |
| Forged bundle of 2048 burns (refused) | 0.4 MB | 4k | - | 15.5 to 15.8 s | 0.55 to 0.56 s |
| Forged fan-out of 65,535 after 500 transfers, with a reject list, near the walk cap | 1.7 MB | 67k | 16.1 s | 9.5 to 9.6 s, of which the walk 4.4 to 4.7 s | 4.86 s |

End to end, the 2810-mint burn took 5.0 to 6.3 s, and 15.9 to 16.2 s with 3
transfers a line. That includes the enclave's own parse, gate and reads of
the validated transfer, which run outside the rgb-lib budget.

Measured rates of rgb-lib: validation about 0.8 to 1.1 us per byte, 35 to
55 us per output and 13.7 us per genesis leaf for each operation; inspection
about 0.5 us per byte, 46 to 60 us per output and up to 130 us per operation.
The weights of the model are these rates, rounded up.

[runtime-limits.md](runtime-limits.md#measured-times) has times from a real
enclave. On every shape measured there, one request took at most its modeled
time.

## What the model refuses in an honest history

- **The time budget** refuses a history past its modeled time. On the pinned
  genesis that is about 10 MB of plain transfers, about the size limit. A
  history of 10,000 transfers with an SPV proof on each (8.9 MB) passes at
  19.95 s. On a genesis of 255 rights each operation models at 3.9 ms, so the
  budget refuses a history past about 5,900 operations, whatever its size.
- **The walk cap**, for an asset with a reject list, can refuse an
  exact-amount burn. With no change there is no split, so each input is an
  origin, and the count walks each one on its own. Thousands of inputs that
  were paid off one long chain of payments reach the cap. A burn with change
  has one origin.

The operator can raise each limit on a running enclave.

## What the model does not prove

- The weights come from timings on one machine. Their margin is about the
  spread between runs: 8 percent on the closest shape, the inspection of the
  honest 2810-mint burn. A shape that costs rgb-lib more per byte, output,
  operation or genesis leaf than the measured ones runs past its modeled
  time. So does a busy or slower CPU.
- The budget is rgb-lib's alone. The enclave's own work on the transfer took
  1.1 to 1.6 s more on the 2810-mint burn with 3 transfers a line.

## When to measure again

Measure again when the rgb-lib or rgb-consensus pin changes, or when
`cost.rs` changes. Run the command above, compare each shape with its modeled
time, and update the weights, this table and the limits if a shape runs past
its model.
