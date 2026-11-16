# Burn vector provenance

The tests keep expected protocol bytes fixed. Separate reference calculations
check those values without calling the production encoder under test. The
references below identify the input sources, calculation sources and scope.

## Sources and inputs

Use the test source, [Cargo.lock](../Cargo.lock) and
[rust-toolchain.toml](../rust-toolchain.toml) from one repository revision.
Parent checks use their separate [parent/Cargo.lock](../parent/Cargo.lock).
Git fixes the source revision; the lockfile fixes dependency versions and
registry checksums. Record that revision with a verification result.

| Values | Complete inputs and reference calculation | What the check establishes |
| --- | --- | --- |
| Destination V1 | [Destination JSON](burn-destination-vectors.json) contains each recipient's original bytes, chain, endpoint, encoded words and expected hash. [Destination tests](../enclave/src/networks/evm/burn_destination/tests.rs) use a manual ABI reference, separately from the production Alloy record type. The [record format](burn-destination.md) owns the formula. | The fixed encodings and hashes match both implementations for these inputs. |
| Deposit ids | The two fixed cases in [event tests](../enclave/src/networks/evm/events/tests.rs) specify the bridge, EVM chain, token, RGB network, lock word and net amount. A separate Alloy tuple encoder checks the expected ids against the production manual encoder on those same inputs. | The fixed ids match the deposit formula for the stated network and lock word. |
| Burn ids | The two fixed cases in [validation tests](../enclave/src/networks/evm/validation/tests.rs) specify all fields. The existing `contract_burn_id` Alloy tuple encoder and the production manual encoder check the same fixed expected ids. | The formula agrees for the stated bridge, token, amount and source identity. |
| Witness-bound LockId | `lock_id_matches_the_upstream_vectors` in [RGB validation tests](../enclave/src/networks/rgb/validation/tests.rs) keeps the two published upstream results and full operation/transaction bytes. The pinned [rgb-ops source](https://docs.rs/crate/rgb-ops/0.11.2-rc.2/source/src/containers/claim.rs) defines the commitment tag and `lock_id_vectors`. | The selected dependency's commitment matches the published vectors. Internal transaction-byte order and display order are checked explicitly. |
| Direct and LayerZero digests | [Signing tests](../enclave/src/networks/evm/signing/tests.rs) give the domain, signed fields, nonce and deadline. `test_digest_matches_alloy_eip712` and `test_lz_digest_matches_independent_encoder_for_every_field` use separately declared Alloy types against the manual production encoder. | Agreement of EIP-712 encoding for the stated fields, including field mutations in the LayerZero case. |
| Relay records | [Relay tests](../enclave/src/networks/evm/crosscheck/tests.rs) define `h0`, `mined`, `chain_to` and `relay_model`. They reproduce the five fixed records in [btc_relay_records.txt](../enclave/tests/fixtures/btc_relay_records.txt). | The production record packing and the local reference model agree with the fixed bytes for deterministic regtest headers. |

The selected contract-format sources are immutable references:

- [Bridge identity formulas](https://github.com/UTEXO-Protocol/bridge-smart-contracts/blob/d4bc2363a3c84433d59afd7386ba2eb6508757d8/ethereum/src/Bridge.sol).
- [MultisigProxy release types and domain](https://github.com/UTEXO-Protocol/bridge-smart-contracts/blob/d4bc2363a3c84433d59afd7386ba2eb6508757d8/ethereum/src/MultisigProxy.sol).
- [StoredBlockHeaderTestnet record layout](https://github.com/UTEXO-Protocol/bridge-smart-contracts/blob/d4bc2363a3c84433d59afd7386ba2eb6508757d8/ethereum/src/btc_relay/structs/StoredBlockHeaderTestnet.sol).

The references identify format definitions. They do not assert that the tests
execute Solidity or read an approved deployment.

## Input and execution scope

The fixed deposit and burn cases use the enclave's RGB network. Contract
examples using network `96` and enclave examples using `827166` have different
inputs and therefore different expected ids. They are not evidence that three
implementations ran the same case. The reference calculation in each local
test uses exactly that test's inputs.

A deposit formula accepts a lock word. That alone does not prove that the
word comes from a particular mint and witness transaction. The LockId tests
check that separate commitment. The fixed digest examples check mathematics;
their addresses, deadlines and settlement fields are not a complete accepted
Burn request or evidence of a deployment.

The existing [shared Burn fixture](../enclave/tests/support/bfa_burn.rs)
constructs the current direct and LayerZero formats: RGB source identity,
empty source address, canonical ids-only settlement and the route's fields.
Its separately declared Alloy release types recompute the digest of the same
intent used by the real handler. [Parent tests](../parent/tests/test_grpc_burn.rs)
check signer recovery from the returned signature and that changing the nonce
changes the recovered signer. These native handler/transport checks use
controlled dependencies and do not execute a contract payout.

The relay input recipe is in the linked test functions: a mined checkpoint,
checkpoint work, linked headers, timestamp progression, Merkle-root override
and selected record heights. The model shares the Bitcoin header primitives
and chain data with the production path. It is a reference for record packing,
not an independent Bitcoin consensus implementation or an execution of the
Solidity library. Expected relay bytes remain fixed.

## Repeat the checks

Run from the repository root. The EVM suite includes the fixed-value and
reference comparisons listed above:

```sh
cargo test --locked -p utexo-bridge-enclave --no-default-features \
  --features spv,burn-signer,mock-attestation,allow-seed-import \
  --lib networks::evm::
```

Run the upstream LockId cases separately:

```sh
cargo test --locked -p utexo-bridge-enclave --no-default-features \
  --features spv,burn-signer,mock-attestation,allow-seed-import \
  --lib -- --exact networks::rgb::validation::tests::lock_id_matches_the_upstream_vectors
```

For the current Parent-to-handler request formats:

```sh
cargo test --locked --manifest-path parent/Cargo.toml --test test_grpc_burn
```

[Building](building.md) describes the toolchain and dependency access. The
[CI workflow](../.github/workflows/ci.yml) owns the supported feature matrix
and discovers these tests normally. No test rewrites an expected value.
