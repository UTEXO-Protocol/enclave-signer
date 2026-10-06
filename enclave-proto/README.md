# enclave-proto (vendored)

This crate contains the enclave wire protocol. Its local copy of the schema
requires no credentials or private dependencies.

Current caveat: the root `Cargo.toml` pins the RGB crates to private BFA
mirrors over SSH, so an enclave build does need those deploy keys today. That
is a separate dependency; this crate stays credential-free.

This is a *slice*, not a copy: only the `enclave` protobuf package is here.
The bridge / node / orchestrator / parent / signer packages are not vendored —
`parent/` still consumes the full crate from upstream, over SSH.

## `enclave.proto` is NOT compiled

This crate has no `build.rs` or `prost-build` dependency. `src/lib.rs` includes
the committed, pre-generated `enclave.rs`. The separate `enclave/build.rs`
sets compiler configuration flags. It does not generate protobuf code.

That is deliberate: generating at build time would put `protoc` in the enclave
builder image and make PCR0 depend on which `protoc` / `prost-build` version
built it, so the same commit would no longer reproduce the same measurement.

Changes to `proto/enclave.proto` do not change the compiled Rust types.
The provenance test detects changes that do not match the recorded hashes.
The file documents the schema. It is not a code-generation input in this crate.

To change the wire protocol: change it upstream, regenerate there, then re-sync
BOTH files here and update the Provenance tables below.
`tests/vendored_provenance.rs` fails the test suite if the files and the tables
disagree, or if the commit recorded below drifts from the `rev` that
`parent/Cargo.toml` pins.

## Known upstream comment differences

The vendored files remain byte-for-byte copies of the pinned upstream revision.
Some upstream comments describe older behavior. Use the Rust handlers and the
[technical specification](../docs/tee-spec.md) for current behavior.

| Wire item | Current behavior in this repository |
| --- | --- |
| `InitializeKeyRequest` | Empty seed and mnemonic use KMS on mint builds. Other builds generate a seed from OS entropy. |
| `cloning_secret` | An empty field leaves a donor secret loaded at boot unchanged. KMS builds reject a non-empty field. |
| `EvmSignatureResponse.call_data` | The enclave returns the input calldata unchanged. It signs decoded typed fields, not a hash of raw calldata. |
| `SignBtcRequest` | The enclave derives output ownership and applies value budgets. There is no `BTC_ALLOWED_SCRIPTS` setting. |
| `SubmitHeadersRequest` | Bounded chain replacements are permitted. The parent denies client gRPC submissions. Its internal sync sends headers directly. |
| `HealthResponse.ready` | Mint readiness does not require `spv_synced`. Other builds with an SPV release path require it. |
| `HealthResponse.phase` | KMS builds can also report `initializing`. |
| `GetAttestedPublicKeyResponse` | Before keys exist, `public_keys` is empty, the document has no public key, and `user_data` commits only the policy bytes. |

Correct these comments upstream, then synchronize both vendored files and their
recorded provenance. Do not change only the local generated comments.

## Provenance

| | |
|---|---|
| Upstream | https://github.com/UTEXO-Protocol/federated-signer-proto |
| Commit | `2b81a2eaadb99daa68c4428ea38f80ae3f40805d` (merge of PR #35, "chore(proto): drop mint_ancestors") |
| Commit date | 2026-10-08T12:17:24Z |

This is the same commit `parent/Cargo.toml` still pins as a git dependency, so
both crates compile against one schema version. Keep them in lockstep.

| File | Upstream path | Status |
|---|---|---|
| `src/enclave.rs` | `rust-gen/src/enclave/enclave.rs` | verbatim, do not edit |
| `proto/enclave.proto` | `proto/enclave/enclave.proto` | verbatim, source of truth |
| `src/lib.rs` | — | local shim (`include!`), replaces upstream's `mod.rs` |

Verify against upstream (needs read access to the private repo):

```bash
REV=2b81a2eaadb99daa68c4428ea38f80ae3f40805d
git clone https://github.com/UTEXO-Protocol/federated-signer-proto /tmp/fsp
git -C /tmp/fsp checkout "$REV"
diff /tmp/fsp/rust-gen/src/enclave/enclave.rs enclave-proto/src/enclave.rs
diff /tmp/fsp/proto/enclave/enclave.proto     enclave-proto/proto/enclave.proto
```

Or compare local blob hashes with the recorded upstream hashes below:

```bash
git hash-object enclave-proto/src/enclave.rs enclave-proto/proto/enclave.proto
```

| File | Upstream blob hash |
|---|---|
| `rust-gen/src/enclave/enclave.rs` | `e8f2ac3d051518c2f0d3605601adfd6eb788a681` |
| `proto/enclave/enclave.proto` | `03c6966a2998785d0d92af35384b21631f11c5e5` |

## Why only `prost`

`enclave.proto` declares **no gRPC services** and **imports nothing** — not even
`google.protobuf`. The generated code references only `::prost`.

That matters for the TEE. When the enclave shared the full proto crate with the
parent, it inherited `tonic` (with the `server` and `channel` features) and with
it hyper, tower, and h2 — a gRPC server stack the enclave never uses, linked
into the binary measured by PCR0. This slice drops all of it. The enclave speaks
its own length-prefixed protobuf framing over vsock (`enclave/src/framing.rs`);
gRPC terminates at the parent.

## Why pre-generated code is committed

`src/enclave.rs` is committed instead of generated during the build.
The build script in the enclave crate does not change this file.

- **Reproducibility.** `protoc` / buf plugin versions affect the generated Rust.
  Generating at build time would make the enclave binary — and therefore PCR0 —
  depend on a toolchain version that `Cargo.lock` does not capture. Committing
  the output removes that input entirely.
- **Auditability.** The exact code compiled into the TEE is reviewable in-tree,
  not reconstructed by a plugin at build time.

## Re-syncing to a newer upstream commit

Regeneration lives upstream (it needs `buf` and the Go toolchain). Never
hand-edit `src/enclave.rs`.

```bash
REV=<40-hex>            # new upstream commit
UP=<path-to-upstream-checkout>
git -C "$UP" checkout "$REV"
cp "$UP/rust-gen/src/enclave/enclave.rs" enclave-proto/src/enclave.rs
cp "$UP/proto/enclave/enclave.proto"     enclave-proto/proto/enclave.proto
```

Then update **both** sides together, or the parent and enclave will disagree
about the wire format:

1. the provenance table above,
2. the `rev = "..."` pin in `parent/Cargo.toml`.

A schema update can change the enclave binary and its measurements.
Rebuild the EIF after an update. Publish its new reference PCRs.
