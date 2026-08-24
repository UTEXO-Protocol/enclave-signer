# enclave-proto (vendored)

The wire protocol the Nitro enclave speaks, vendored so **the enclave builds
with no credentials and no private dependencies**. Anyone can clone this repo
and reproduce the EIF and its PCR measurements without access to any private
UTEXO repository.

This is a *slice*, not a copy: only the `enclave` protobuf package is here.
The bridge / node / orchestrator / parent / signer packages are not vendored —
`parent/` still consumes the full crate from upstream, over SSH.

## Provenance

| | |
|---|---|
| Upstream | https://github.com/UTEXO-Protocol/federated-signer-proto |
| Commit | `359a421245cf5b78078426c2b98a3a92bb63ab07` ("Merge branch 'main' into vs/signer-groups-support") |
| Commit date | 2026-08-17T22:27:11+03:00 |

This is the same commit `parent/Cargo.toml` still pins as a git dependency, so
both crates compile against one schema version. Keep them in lockstep.

| File | Upstream path | Status |
|---|---|---|
| `src/enclave.rs` | `rust-gen/src/enclave/enclave.rs` | verbatim, do not edit |
| `proto/enclave.proto` | `proto/enclave/enclave.proto` | verbatim, source of truth |
| `src/lib.rs` | — | local shim (`include!`), replaces upstream's `mod.rs` |

Verify against upstream (needs read access to the private repo):

```bash
REV=359a421245cf5b78078426c2b98a3a92bb63ab07
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
| `rust-gen/src/enclave/enclave.rs` | `bfb9857f6a24cd85d2a9324ea1e19ad6a7291f5a` |
| `proto/enclave/enclave.proto` | `9060c2dbebfad3eb0025f72e297dfd3884b2bd81` |

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
