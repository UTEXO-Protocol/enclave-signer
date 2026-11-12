# enclave-proto (vendored)

This crate contains the enclave wire protocol. Its local copy of the schema
requires no credentials or private dependencies.

Current caveat: the enclave takes rgb-lib from the private
`UTEXO-Protocol/rgb-lib-bfa` mirror (deploy key `lib_key`), so an enclave
build needs that key; the RGB protocol crates are public. rgb-lib is a
separate dependency; this crate stays credential-free.

This is a *slice*, not a copy: only the `enclave` protobuf package is here.
The bridge / node / orchestrator / parent / signer packages are not vendored —
`parent/` consumes the full crate from upstream, over SSH.

## `enclave.proto` is NOT compiled

This crate has no `build.rs` or `prost-build` dependency. `src/lib.rs` includes
the committed, pre-generated `enclave.rs`. The separate `enclave/build.rs`
sets compiler configuration flags. It does not generate protobuf code.

That is deliberate: generating at build time would put `protoc` in the enclave
builder image and make PCR0 depend on which `protoc` / `prost-build` version
built it, so one commit could give different measurements on different
builders.

Changes to `proto/enclave.proto` do not change the compiled Rust types.
The provenance test detects changes that do not match the recorded hashes.
The file documents the schema. It is not a code-generation input in this crate.

To change the wire protocol or a comment: change it upstream, regenerate there,
then re-sync BOTH files here and update the Provenance tables below.
`tests/vendored_provenance.rs` fails the test suite if the files and the tables
disagree, or if the commit recorded below drifts from the `rev` that
`parent/Cargo.toml` pins.

## Provenance

| | |
|---|---|
| Upstream | https://github.com/UTEXO-Protocol/federated-signer-proto |
| Commit | `65c3054c147a98f36e9899cdda7e2cee48de3c78` (branch `chore/reserve-unused-fields`, "Reserve fields the enclave does not read") |
| Commit date | 2026-11-12T09:20:37Z |

This is the commit `parent/Cargo.toml` pins as a git dependency, so both
crates compile against one schema version. Keep them in lockstep.

| File | Upstream path | Status |
|---|---|---|
| `src/enclave.rs` | `rust-gen/src/enclave/enclave.rs` | verbatim, do not edit |
| `proto/enclave.proto` | `proto/enclave/enclave.proto` | verbatim, source of truth |
| `src/lib.rs` | — | local shim (`include!`) in place of upstream's `mod.rs` |

Verify against upstream (needs read access to the private repo):

```bash
REV=65c3054c147a98f36e9899cdda7e2cee48de3c78
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
| `rust-gen/src/enclave/enclave.rs` | `3c0cf7dae816ebf3c04cc5cdc68cee84b952a188` |
| `proto/enclave/enclave.proto` | `a6a2c767c3b37f88fca504d806b73ab604e17379` |

## Why only `prost`

`enclave.proto` declares **no gRPC services** and **imports nothing** — not even
`google.protobuf`. The generated code references only `::prost`.

That matters for the TEE. The full proto crate, which the parent uses, depends
on `tonic` (with the `server` and `channel` features) and with it hyper, tower,
and h2 — a gRPC server stack the enclave never uses. This slice keeps that stack
out of the binary measured by PCR0. The enclave speaks its own length-prefixed
protobuf framing over vsock (`enclave/src/framing.rs`); gRPC terminates at the
parent.

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
2. the `rev = "..."` pin in `parent/Cargo.toml`,
3. the `federated-signer-proto` `source` line in `parent/Cargo.lock`.

After a re-sync, run the enclave tests. The test
`framing::tests::the_shape_walk_knows_every_repeated_field_of_the_proto` fails
when a request message gets a new `repeated` field that the wire shape check in
`enclave/src/framing.rs` does not count.

A schema update can change the enclave binary and its measurements.
Rebuild the EIF after an update. Publish its new reference PCRs.

The generated oneof decoders panic with a source location in `src/enclave.rs`.
So a comment-only update keeps the enclave binary only if every code line keeps
its line number: keep each upstream comment block at its line count.
