# enclave-proto (vendored)

The wire protocol the Nitro enclave speaks, vendored so **the enclave builds
with no credentials and no private dependencies**. Anyone can clone this repo
and reproduce the EIF and its PCR measurements without access to any private
UTEXO repository.

This is a *slice*, not a copy: only the `enclave` protobuf package is here.
The bridge / node / orchestrator / parent / signer packages are not vendored —
`parent/` still consumes the full crate from upstream, over SSH.

## `enclave.proto` is NOT compiled

There is no `build.rs` and no `prost-build` anywhere in this repo. `src/lib.rs`
is `include!("enclave.rs")`, and **`enclave.rs` is committed pre-generated**.

That is deliberate: generating at build time would put `protoc` in the enclave
builder image and make PCR0 depend on which `protoc` / `prost-build` version
built it, so the same commit would no longer reproduce the same measurement.

The consequence is that **`proto/enclave.proto` is inert - editing it changes
nothing.** The build still succeeds and the Rust types are unchanged. It is kept
here as the human-readable source of truth for the schema, not as a build input.

To change the wire protocol: change it upstream, regenerate there, then re-sync
BOTH files here and update the Provenance tables below.
`tests/vendored_provenance.rs` fails the build if the files and the tables
disagree, or if the commit recorded below drifts from the `rev` that
`parent/Cargo.toml` pins.

## Provenance

| | |
|---|---|
| Upstream | https://github.com/UTEXO-Protocol/federated-signer-proto |
| Commit | `31bbfa5c6accb764ff3cddcca418c18c01e890fd` ("feat(enclave): add the RGB inflation destination", branch `bfa`) |
| Commit date | 2026-09-01T13:54:41+03:00 |

This is the same commit `parent/Cargo.toml` still pins as a git dependency, so
both crates compile against one schema version. Keep them in lockstep.

| File | Upstream path | Status |
|---|---|---|
| `src/enclave.rs` | `rust-gen/src/enclave/enclave.rs` | verbatim, do not edit |
| `proto/enclave.proto` | `proto/enclave/enclave.proto` | verbatim, source of truth |
| `src/lib.rs` | — | local shim (`include!`), replaces upstream's `mod.rs` |

Verify against upstream (needs read access to the private repo):

```bash
REV=31bbfa5c6accb764ff3cddcca418c18c01e890fd
git clone https://github.com/UTEXO-Protocol/federated-signer-proto /tmp/fsp
git -C /tmp/fsp checkout "$REV"
diff /tmp/fsp/rust-gen/src/enclave/enclave.rs enclave-proto/src/enclave.rs
diff /tmp/fsp/proto/enclave/enclave.proto     enclave-proto/proto/enclave.proto
```

Or check the upstream blob hashes without a clone:

```bash
git hash-object enclave-proto/src/enclave.rs enclave-proto/proto/enclave.proto
```

| File | Upstream blob hash |
|---|---|
| `rust-gen/src/enclave/enclave.rs` | `02a99884b1c4f0893ac7af82d0a755319a441353` |
| `proto/enclave/enclave.proto` | `63b2255efdfddc610e2d08db0c76004e69e6279d` |

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

`src/enclave.rs` is checked in rather than generated during the build, and no
crate in this workspace has a `build.rs`. That is deliberate:

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

Re-syncing changes the enclave binary and therefore **PCR0**. Treat it as a
measurement-affecting change: rebuild the EIF and republish the reference PCRs.
