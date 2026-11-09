# enclave-signer

This service signs for the UTEXO bridge. It runs inside an
[AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/).

The enclave makes its own keys. It checks each bridge operation itself. It
signs only when all checks pass. The host is not trusted.

The bridge has two primary flows:

| Flow | Direction | User does | Enclave signs | Signer image |
|------|-----------|-----------|---------------|--------------|
| **Mint** | EVM -> RGB | Locks ERC-20 tokens on EVM | A Bitcoin PSBT that mints RGB units | `mint-signer` |
| **Burn** | RGB -> EVM | Burns RGB units on Bitcoin | An EIP-712 `fundsOut` release, and its gas transaction | `burn-signer` |

Each flow has its own enclave image, its own seed and its own PCR0. A mint
signer refuses burn requests. A burn signer refuses mint requests.

Read these first:

- [`docs/mint-flow.md`](docs/mint-flow.md) - the mint flow, step by step.
- [`docs/burn-flow.md`](docs/burn-flow.md) - the burn flow, step by step.

Reference material:

- [`docs/tee-spec.md`](docs/tee-spec.md) - the full specification: trust
  model, signing rules, limits.
- [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md) - how to prove
  that a signing key belongs to attested enclave code. The `attest-verify` CLI.
- [`docs/verify-a-signer.md`](docs/verify-a-signer.md) - how anyone checks a
  published burn-signer attestation bundle and the on-chain signer list.
- [`docs/kms-persistence.md`](docs/kms-persistence.md) - how the mint signer
  keeps its seed with AWS KMS and S3.
- [`docs/parent-mtls.md`](docs/parent-mtls.md) - the required mTLS between
  the parent and its clients. RPC roles. Host rollout.
- [`docs/clone-cli-results.md`](docs/clone-cli-results.md) - result codes of
  the `clone` CLI command.
- [`docs/diagrams/`](docs/diagrams/README.md) - Mermaid diagrams.
- [`enclave-proto/README.md`](enclave-proto/README.md) - where the wire
  schema comes from, and how to sync it.

## Architecture

1. The listener (`federated-signer-node`) sends a signing request to the
   parent over gRPC with mTLS.
2. The parent runs on the EC2 host. It is not trusted. It sends the request
   to the enclave over vsock.
3. The enclave holds the keys. It checks the request and signs, or refuses.
4. The enclave reaches the Bitcoin indexer (Electrum or Esplora) and the EVM
   JSON-RPC through host vsock proxies. TLS ends inside the enclave. A release
   image accepts only an `ssl://` or `https://` indexer URL. An `spv` image
   reads no indexer to sign. A burn signer built without `spv`, on public
   Signet only, takes witness status and depth from the pinned indexer.
5. The parent sends Bitcoin block headers to the enclave. On mainnet, the
   enclave checks proof of work and maintains its own header chain.
   On testnet4 it also applies the 20-minute rule and BIP94. On the testnets
   min-difficulty blocks count as confirmations and freshness, for testing
   convenience: testnets carry no production value. On every network it
   refuses a header more than 2 hours ahead of its clock. Signet
   and regtest use weaker checks. See the specification.

See the [component diagram](docs/diagrams/01-components.md) and the
[deployment diagram](docs/diagrams/02-deployment.md).

## Crates and binaries

| Crate | Binary | Description |
|-------|--------|-------------|
| `enclave/` | `utexo-bridge-enclave` | Runs inside the Nitro Enclave. Keys, checks, signing, SPV chain, cloning, attestation. |
| `enclave-proto/` | - | Vendored `enclave` protobuf package. Pre-generated Rust, no `build.rs`. |
| `attestation-verify/` | - | Nitro attestation verifier (COSE_Sign1, cert chain to the AWS root, PCRs). Also the encoding of the security-policy commitment. The enclave and the parent both use it. |
| `parent/` | `utexo-bridge-parent` | gRPC server on the EC2 host. Translates `ParentService` RPCs to the enclave wire protocol. Syncs Bitcoin headers. |
| `parent/` | `utexo-bridge-parent-cli` | Direct enclave client: endpoints, key init, cloning, keys, last saved block, manual signing, health. |
| `parent/` | `attest-verify` | Gets an attested public key through the parent and verifies it end to end. |

`parent/` is a **separate cargo workspace** with its own `Cargo.lock`. See
[Proto source](#proto-source) for the reason.

## Mint flow (EVM -> RGB)

The user locks tokens on EVM. The bridge mints the same value of RGB units to
the user. The mint signer signs the Bitcoin transaction that does the mint.

Before it signs, the mint signer:

1. Gets the EVM deposit receipt itself. The receipt must be a success, be at
   or below the RPC head selected by `EVM_FINALITY_TAG` (`finalized`), and
   have the canonical block hash at its height.
2. Finds the one `BridgeFundsIn` event from the pinned `FUNDS_IN_CONTRACT` whose
   `operationId` is the request's. Other deposits in the transaction are ignored.
   The `operationId`, amount and commission must match the request.
3. Reads the mint from the fascia rgb-lib wrote for the PSBT's tx (`fascia`),
   with no consignment: rgb-lib strips the RGB data from the PSBT. The fascia
   must be of that tx, and its first `OP_RETURN` must commit exactly the
   bundles the fascia discloses: one bundle of the pinned `RGB_ASSET_ID`,
   holding one mint whose id is recomputed. The txid and the sighash types
   cannot change. The mint consumes one `mintRight`, passes no right on, and
   pays exactly `amount - commission` units to one seal: the user's blinded
   seal, or an output of the mint tx (a witness invoice).
4. Checks the parent fascia (`parent_fascia`): the tx that made the spent right
   was a propagate of one right that put that right alone on its own output,
   and the PSBT spends that output, its only input. So every signature for
   this mint spends the same UTXO.
5. Binds the deposit: a `FundsIn` for the mint's lockId and the deposit id it
   derives, before its `beforeBlock` and covered by the `EVM_FINALITY_TAG` head,
   read from a node on the pinned chain. The lockId is `LockId(opid, txid)` of
   the mint and the PSBT's tx, so the mint tx must never change after the lock
   (no RBF, rebuild or batching): a retry signs the same PSBT. The only fee
   bump left is a CPFP child that spends an output of the mint tx, and none is
   implemented: a stuck mint tx is rebroadcast as it is
   ([mint flow](docs/mint-flow.md) section 1).
6. Binds the recipient. The v2 Bridge deposit names the mint's lockId, which
   commits to the user's seal and, for a witness seal, to the script of the
   user's output. If a deposit has an RGB invoice, the mint's one blinded
   seal must equal that invoice ([mint flow](docs/mint-flow.md) section 11).
7. Checks the Bitcoin fee and the sats paid out: none for a blinded mint,
   exactly `MINT_WITNESS_SAT` to the user's output for a witness mint.
8. Signs Taproot key-path inputs with keys from the colored BIP-86 account.
   A Tapret or script-tree root can be part of the output-key tweak.

The mint signer validates no RGB history. A bad history makes the mint
invalid for every receiver, so it is liveness only. Full detail:
[`docs/mint-flow.md`](docs/mint-flow.md).

## Burn flow (RGB -> EVM)

The user burns RGB units on Bitcoin. The bridge releases the locked tokens on
EVM. The burn signer signs the `fundsOut` release. `MultisigProxy` needs M of
N signatures.

Before it signs, the burn signer:

1. Validates the RGB consignment with one call of rgb-lib's
   `validate_consignment_with_resolver` (full RGB consensus over the whole
   history), after the asset bind and caps on the work it would do. Each
   mint in the history is confirmed only against the deposit it derives. The
   last transition must be a BFA `burn`. If the genesis names a reject list
   (an `IRgbRejectList` contract on `EVM_CHAIN_ID`), the enclave reads it
   over the pinned EVM RPC when rgb-lib asks during this validation, before
   step 2, and rgb-lib refuses a burn whose terminal operations (the burn,
   and any companion transfer of its bundle) descend from a rejected output.
   The mint signer reads no list. Any read failure refuses, so burn hosts
   need the EVM RPC proxy (`vsock-proxy 8002`) for such an asset.
2. Checks that each Bitcoin transaction of the consignment is in its own
   header chain, at least `SPV_MIN_CONFIRMATIONS` blocks deep (3).
   The chain tip must be less than 2 hours old.
3. Decodes the `fundsOut` calldata. The encoding must be canonical. Chain,
   contract and deadline must be correct.
4. Checks `sourceChainId`, `sourceAddress` and `burnId`.
5. Checks the BtcRelay finality proof against its own header chain.
6. Binds the release to the burn: amount (`burnedAsset`), `sourceBurnTxId`,
   destination (`burnReason`: a left-padded EVM address, or the hash of a
   destination record, see [docs/burn-destination.md](docs/burn-destination.md))
   and `settlementData` (exactly the deposits of the history's mints).
7. Signs the EIP-712 `TeeFundsOut` (or `TeeLzFundsOut`) digest over the
   decoded fields.

The burn signer also signs the gas transaction that sends the release to EVM
(`SignRawDigest`). An attested allowlist limits that transaction.

Full detail: [`docs/burn-flow.md`](docs/burn-flow.md).

## Keys

The mint signer and the burn signer get their seed in different ways:

- **Mint signer** (`kms-persistence`): the enclave makes or recovers its seed
  through attested AWS KMS. It keeps the encrypted seed in S3. Mint replicas
  recover the same seed. Peer cloning is off. See
  [`docs/kms-persistence.md`](docs/kms-persistence.md).
- **Burn signer**: the enclave makes a BIP-39 mnemonic from OS entropy.
  Replicas get the seed through the attested cloning handshake.

Both keep the 64-byte seed in a `SecretBox` (zeroized on drop). The enclave
never exports the plaintext seed. For mint signers, KMS also handles the
plaintext seed during generation and decryption. Mnemonic or raw-seed import
exists only with
`allow-seed-import` (dev builds).

Key paths:

| Key | Path | Use |
|-----|------|-----|
| EVM bridge key | `m/44'/60'/0'/0/0` | Signs `fundsOut` (burn). Its address is the cluster identity. |
| EVM gas-tx key | `m/44'/60'/0'/0/1` | Signs the outer gas transaction (burn). |
| BIP-84 BTC key | `m/84'/0'/0'/0/0` | Public key only. Signs nothing. |
| Vanilla taproot account | `m/86'/<coin>'/0'` (coin 0 mainnet, 1 other) | Plain-BTC `SignBtc` only. |
| Colored taproot account | `m/86'/<rgb_coin>'/0'` (827166 mainnet, 827167 other) | Mint PSBTs only. |
| Concordium key | `m/44'/919'/0'/0'/0'` (Ed25519, SLIP-0010) | `SignCcd`. |

The enclave returns the master fingerprint and both account xpubs. The bridge
wallet uses them for its watch-only descriptors. A cloned enclave must derive
the same EVM address before it goes `Active`.

## Attested security policy

The enclave resolves one `SecurityPolicy` when the operator sets the
endpoints at launch. The policy comes from build flags, image pins and the
endpoints. It is `Production { ... }` or `Development { reason }`.

- A release `spv` build refuses to boot if its pins do not make a valid
  `Production` policy.
- It also refuses endpoints that do not make a valid `Production` policy.
- A release build without `spv` never makes a `Production` policy. With the
  public-Signet pins it boots and signs on `Development { IndexerTrusted }`,
  which commits no policy field.
- The policy goes into the attestation `user_data`, with the signer role.
- `attest-verify` builds the expected policy and fails on any difference. It
  expects `Production`, so it refuses a build without `spv`.

See [`docs/pubkey-attestation.md`](docs/pubkey-attestation.md).

## gRPC bridge (parent)

- The parent implements `parent.ParentService` from `federated-signer-proto`
  (`proto/enclave/parent.proto`): `Sign`, `PublicKey`, `Initialize`, `Clone`,
  `GetLastSavedBlock`, `SubmitHeaders`, `AttestedPublicKey`.
- mTLS is required. A client certificate ACL gives each caller a role
  (`listener`, `clone-operator`, `observer`). See
  [`docs/parent-mtls.md`](docs/parent-mtls.md).
- `Sign` routes by `data_type`: `TRANSACTION` -> enclave `Sign`,
  `EVM_GAS_TX` -> `SignRawDigest`, `BTC_UTXO` -> `SignBtc`,
  `RGB_RIGHTS_REFILL` -> `SignRightsRefill` (no source proof).
- `SubmitHeaders` answers `PERMISSION_DENIED` to every caller. The parent's
  header sync writes headers through the direct enclave protocol. Other direct
  enclave clients can also submit headers. The sync reads headers from
  `HEADER_ELECTRUM_URL` and sends them to its enclave.
- The parent opens one new TCP or vsock connection per enclave RPC. It reads the
  request deadline of the enclave and waits 10 s longer, so the enclave gives up
  first ([`docs/runtime-limits.md`](docs/runtime-limits.md)).
- `Clone` and `AttestedPublicKey` each have a per-minute budget shared by all
  clients. A call over the budget gets `RESOURCE_EXHAUSTED` before it reaches
  the enclave.
- The parent runs at most `GRPC_MAX_CONCURRENT_SIGN` `Sign` requests at once. A
  `Sign` above that gets `UNAVAILABLE` at once, and the parent does not queue it.
- `GET /health` on a loopback port tells if the enclave can sign now. See
  [Readiness endpoint](#readiness-endpoint).

## Enclave requests

Wire format: `[4-byte little-endian length][protobuf EnclaveRequest]`. One
request per connection. Frame limit 24 MiB. Schema:
[`enclave-proto/proto/enclave.proto`](enclave-proto/proto/enclave.proto).

| Request | Phase | Signer | Description |
|---------|-------|--------|-------------|
| `SetEndpoints` | any | all | Sets the chain endpoints (and the KMS values on mint). Once per boot. |
| `SetLimits`, `GetLimits` | any | all | Change or read the time, memory and size limits ([`docs/runtime-limits.md`](docs/runtime-limits.md)). |
| `InitializeKey` | Initial | all | Mint: recover or create the KMS seed. Burn: make a seed from OS entropy, with an optional donor `cloning_secret`. |
| `GetPublicKey` | Active | all | EVM address and keys, gas-tx key, BTC key and xpubs, fingerprint, CCD key, boot pins. |
| `GetAttestedPublicKey` | any, after `SetEndpoints` | all | The same bundle, plus an NSM attestation document bound to the nonce, the bundle and the policy. Before keys exist it attests the policy only. |
| `Sign` | Active | mint, burn | Bridge signing. Mint signer: EVM -> RGB only. Burn signer: RGB -> EVM only. |
| `SignBtc` | Active | mint | Plain-BTC PSBT on the vanilla account. Off unless the attested policy turns it on. |
| `SignRightsRefill` | Active | mint | The mint wallet sends one `mintRight` to 2..255 of its own Colored outputs. No units move. At most 12 per hour pass the PSBT gate. See [`docs/mint-flow.md`](docs/mint-flow.md#8-rights-refill-signrightsrefill). |
| `SignRawDigest` | Active | burn | Gas transaction under the attested allowlist. |
| `SignCcd` | Active | `ccd` builds | Ed25519 over a 32-byte hash. |
| `SubmitHeaders` | any | RGB builds | Bitcoin headers (<= 10 000 per call, <= 100 000 per 60 s). The parent denies this gRPC method to clients. Direct enclave callers can still submit headers. |
| `GetLastSavedBlock` | any | RGB builds | Header-chain tip (the checkpoint when empty). |
| `InitiateCloning` | Initial or expired Cloning | burn | Starts a requester session or replaces an expired session. |
| `GetClone` | Active | burn | Donor side. Verifies the requester attestation and seals the seed. |
| `SetClone` | Cloning | burn | Requester installs the sealed seed and goes `Active`. |
| `SignRawMessage` | - | - | Refused in every build. |
| `Health` | any | all | Readiness: endpoints set and key loaded. Builds with the RGB -> EVM path also require a ready header chain. |

The "Signer" column is for the mint/burn images. Other builds (combined,
CCD) keep both directions where their features allow it.

Error codes in `ErrorResponse`, with the gRPC status the parent gives each:

- `1` all other errors (`INTERNAL`).
- `2` not ready (`UNAVAILABLE`).
- `3` cross-check or SPV failure, or a `GetClone` donor without keys
  (`FAILED_PRECONDITION`).
- `GetClone` only: `4` invalid input (`INVALID_ARGUMENT`), `5` refused
  credential, attestation, PCR or pubkey (`PERMISSION_DENIED`), `6` replayed
  attestation nonce (`ALREADY_EXISTS`), `7` seed-export hard cap
  (`RESOURCE_EXHAUSTED`).
- `8` the deposit receipt is above the selected EVM finality head
  (`FAILED_PRECONDITION`, with the fixed message prefix
  `evm event pending finality:`). The bridge waits and retries.

## Prerequisites

- **Rust 1.96.1** - pinned in `rust-toolchain.toml`. The exact patch version
  matters for reproducible PCR0.
- **Read access to the private RGB repos.** rgb-lib comes from our private
  mirror of the RGB-Tools release, `UTEXO-Protocol/rgb-lib-bfa`, through the
  `github-rgb-lib` SSH alias (deploy key `lib_key`). The RGB protocol crates it
  pins come from the `[patch.crates-io]` of `Cargo.toml` and
  `parent/Cargo.toml`: public `https://github.com/rgb-protocol/<repo>` at the
  full revs of rgb-lib's own `[patch]`. The build scripts require the
  `rgb_deps_token` secret (`build/map-rgb-mirrors.sh`), although it maps no
  URL. The parent also needs read access to `federated-signer-proto` through
  the `github-federated-signer` SSH alias. CI wires them in
  `.github/workflows/ci.yml` (secrets `RGB_LIB_BFA_DEPLOY_KEY`,
  `RGB_PRIVATE_DEPS_TOKEN` and `FEDERATED_SIGNER_PROTO_DEPLOY_KEY`). Repository
  access alone does not prove that a build reproduces the approved PCR0.
- **Docker + `nitro-cli`** for the EIF. Any x86_64 Linux host with Docker can
  build an EIF and read its PCRs; Nitro hardware is needed only to run it.

```bash
git clone git@github.com:UTEXO-Protocol/enclave-signer
cd enclave-signer
cargo build                                   # enclave workspace
cargo build --manifest-path parent/Cargo.toml # parent workspace
```

## Building

### Feature sets

The production images are the mint signer and the burn signer. Each image
has one role, its own PCR0 and its own seed. Use `--no-default-features`:

```bash
# Mint signer (EVM -> RGB)
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,spv,mint-signer

# Burn signer (RGB -> EVM)
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,spv,burn-signer
```

The tree has other builds too. They are not the production bridge:

```bash
# Concordium only
cargo build --release -p utexo-bridge-enclave --no-default-features --features vsock,ccd

# Local TCP dev build (debug profile, seed import allowed)
cargo build -p utexo-bridge-enclave --no-default-features --features allow-seed-import,spv,mint-signer,ccd
```

Compile-time guards in `enclave/src/lib.rs`: RGB without `spv` is limited to
real-attestation mint/burn builds for public Signet;
exactly one of `mint-signer` / `burn-signer` whenever `rgb-validation` is on;
`kms-persistence` requires `mint-signer`;
`allow-seed-import`, `mock-attestation` and `allow-debug-pcrs` do not compile in
a release profile, and neither does `ccd` with `mint-signer` or `burn-signer`.
CI asserts every guard fires.

### Enclave image (EIF)

The mint image carries the KMS account list (`KMS_ALLOWED_ACCOUNT_IDS`). The
mint enclave gets the other KMS values at launch. See
[mint KMS setup](docs/kms-persistence.md) for the parent and policy requirements.

Every enclave image needs, at build time, the deploy key of
`UTEXO-Protocol/rgb-lib-bfa` (`RGB_LIB_BFA_DEPLOY_KEY`) and the
`RGB_PRIVATE_DEPS_TOKEN` token, which the scripts require although the
RGB protocol crates are public, or `lib_key` and `rgb_deps_token` files in
`PRIVATE_DEPS_DIR`. `build-enclave.sh` passes them as the BuildKit secrets
`lib_key` and `rgb_deps_token`, and `build/with-private-deps.sh enclave` reads
them for the cargo build only. They are never in a layer, the image or PCR0.

```bash
RGB_ASSET_ID="rgb:<approved-bfa-contract-id>" KMS_ALLOWED_ACCOUNT_IDS="<12-digit AWS account id>" \
  DOCKERFILE=Dockerfile.enclave.mint ./build/build-enclave.sh   # mint signer
RGB_ASSET_ID="rgb:<approved-bfa-contract-id>" DOCKERFILE=Dockerfile.enclave.burn ./build/build-enclave.sh   # burn signer
DOCKERFILE=Dockerfile.enclave.ccd       ./build/build-enclave.sh
```

`Dockerfile.enclave.mint` and `Dockerfile.enclave.burn` build the BFA signer images.
Each signer role enables `rgb-validation`.

Run the two roles as separate enclaves with independent seeds. Mint signers use
KMS persistence. Burn signers use OS entropy or peer cloning with matching PCRs.

Set `RGB_ASSET_ID` when you use the build helper. For a direct Docker build,
pass `--build-arg RGB_ASSET_ID=rgb:<contract-id>`. Use the approved BFA contract
id for mint and burn images. There is no default asset id.

The helper and Dockerfile reject an empty value. They do not validate the id
or reject a value that contains only spaces. The image contains the asset pin.
A runtime environment override is not the provisioning procedure.

The mint image also needs `KMS_ALLOWED_ACCOUNT_IDS`: the 12-digit AWS account
ids of the seed KMS key, comma-separated. The helper refuses a missing or
malformed list before Docker starts. `make build_enclave_mint` takes it from the
environment too. The image contains the list, so PCR0 measures it. The burn
image does not take it.

The EIF workflow gets the asset from the repository variable `BFA_RGB_ASSET_ID`.
It gets the account list from the repository variable `KMS_ALLOWED_ACCOUNT_IDS`,
and the mint build fails when that variable is unset.
It records the asset pin from the built image as `rgb_asset_id` in `metadata.json`.
This file accompanies the EIF in the Actions artifact and S3 bundle.

The BFA schema id is
`rgb:sch:3I0xZVEQnQxYVk7vDnh5uNtQyUfsmThw6dX9n_Gvb5o#mama-swing-album`
(rgb-schemas b3f88f2, rgb-lib bfa.6). `assert_bfa_genesis` refuses any other
id, so an asset issued on another schema does not validate, and its units
cannot move to an asset on this schema. Mint locks are keyed by lockId, not
OpId: a mint locked by OpId does not validate. Set `RGB_ASSET_ID` (and the
repository variable `BFA_RGB_ASSET_ID`) to the id of a BFA contract issued on
this schema, for both the mint and the burn image.

To reproduce a published EIF, use its recorded asset id, not the current
repository variable. If a bundle lacks this field, get the build value from
the release owner. Include `metadata.json` when distributing
a release. An internal S3 upload alone does not make these inputs public.

Before deploying, record the image/EIF checksum, approved asset, measured PCRs,
registered key, and Parent endpoint together. Verify a genuine BFA request
succeeds and an opposite-flow request is rejected.

Every image resolves the private rgb-lib mirror: supply the `lib_key`
secret. The scripts also require `rgb_deps_token`, though the protocol crates
come from public repos. `build/with-private-deps.sh` refuses to start cargo
without either. Its `rgb-tools-devs` to `-s-bfa` mirror mapping matches no
URL: every `[patch]` entry points at a public `rgb-protocol` repo.
`Dockerfile.parent` also resolves `federated-signer-proto`: its deploy key as
`federated_key`. Credentials are mounted as BuildKit secrets during Cargo's
build step; they are not copied into image layers.

```bash
# Both values must already be exported; neither is a build argument.
docker build --secret id=lib_key,env=RGB_LIB_BFA_DEPLOY_KEY \
  --secret id=rgb_deps_token,env=RGB_PRIVATE_DEPS_TOKEN \
  --secret id=federated_key,src=<absolute-path> \
  -f build/Dockerfile.parent -t utexo-bridge-parent .
```

`make build_parent*` and `make build_enclave*` pass `lib_key` and
`rgb_deps_token` by default. A `DOCKER_AUTH_ARGS` value replaces that
default, so to pass the parent's deploy key set all three, adding
`--secret id=federated_key,src=<absolute-path>`. CD and EIF workflows use the
`RGB_LIB_BFA_DEPLOY_KEY`, `RGB_PRIVATE_DEPS_TOKEN` and
`FEDERATED_SIGNER_PROTO_DEPLOY_KEY` secrets configured for Rust CI. The
workflow's automatic `GITHUB_TOKEN` is used for image publishing, not
cross-repository dependency access.

The script builds the Docker image with `SOURCE_DATE_EPOCH` set to the commit
time, converts it with `nitro-cli build-enclave`, and writes the EIF,
`PCR.json` and `SHA256SUMS` to `build/`. Reproducibility inputs: pinned
toolchain, digest-pinned base images, `--locked`, `CARGO_INCREMENTAL=0`,
path-prefix remapping, pre-generated proto code. All three EIF recipes use
digest-pinned Debian 13 Trixie images for both build and runtime stages.
The builder uses Rust `1.96.1`, matching `rust-toolchain.toml`.
Both stages install packages from the signed Debian snapshot
`20261007T000000Z` over HTTPS. APT checks repository signatures.
The expiry check is disabled because a fixed snapshot must remain usable after
its Release metadata expires. CMake comes from this snapshot instead of PyPI.
Only the parent and dev image recipes use live APT repositories.
CI pins `nitro-cli` and its kernel/init blobs to `1.4.5`. Docker, Buildx and
BuildKit versions are not pinned in CI, so PCR reproducibility still requires
verification.

Each runtime checks the binary with its dynamic loader before EIF conversion.
This rejects missing libraries and incompatible symbol versions.
A change of a base image changes the enclave measurements. Build new EIFs and
approve their PCRs before you update attestation allowlists or KMS policies.

`.github/workflows/build-eif.yml` builds the `rgb-mint` and `rgb-burn`
variants on a plain runner with `nitro-cli 1.4.5` and uploads EIF + PCRs + host
binaries to `s3://<bucket>/eif/<git_sha>/rgb-mint/` and `rgb-burn/`.
`release-eif.yml` takes a `signer_role` (`mint` or `burn`): `deploy/deploy-host.sh`
fetches `eif/<git_sha>/rgb-<role>/utexo-bridge-enclave-<role>.eif` and runs it on one CID.
The workflow passes no `ENCLAVE_CID`, so it uses the default, CID 16.
The `cd-*.yml` workflows push container images for
the parent and the **dev** enclave images only (`utexo-bridge-enclave-mint`
and `utexo-bridge-enclave-burn`, both from `Dockerfile.enclave-dev.bfa` with a
`SIGNER_ROLE` build arg).

The production Dockerfiles bake the bridge pins as `ENV` (`EVM_CHAIN_ID`,
`EVM_PROXY_CONTRACT_ADDRESS`, `RGB_ASSET_ID`, `FUNDS_IN_CONTRACT`,
`TOKEN_CONTRACT`, `GAS_TX_ALLOWED_TO`, `BTC_MAX_TOTAL_SATS`, ...), so they are
measured into PCR0. The mint image also bakes `KMS_ALLOWED_ACCOUNT_IDS`, so a
rebuild of the EIF gets the same PCR0 only with the same list. The cloning
secret is never baked. The chain endpoints and the other KMS values are not in
the image: a rebuild gets the same PCR0 without knowing them (build access: see
Building).

## Running

### Local development (TCP)

```bash
# Enclave on 127.0.0.1:5000
RUST_LOG=debug,alloy_transport_http=off cargo run -p utexo-bridge-enclave

# Parent gRPC server (GRPC_PORT defaults to 5000; pick another port when both run on one host)
RUST_LOG=debug GRPC_PORT=50051 GRPC_ALLOW_INSECURE_LOOPBACK=true \
  cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent

# Or: parent reachable from other hosts, plaintext, no mTLS (see "insecure-dev" below)
RUST_LOG=debug GRPC_HOST=0.0.0.0 GRPC_PORT=50051 \
  cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent --features insecure-dev

# CLI (shell function works in bash and zsh)
cli() { cargo run --manifest-path parent/Cargo.toml --bin utexo-bridge-parent-cli -- "$@"; }
cli set-endpoints   # once, before any signature
cli init
cli get-keys
cli --help
```

The default enclave build is `ccd`. It takes no chain endpoints and refuses
`get-last-saved-block`. On an RGB role build, `set-endpoints` also needs
`--electrum-url`, `--evm-rpc-host`, `--evm-rpc-tls-port` and
`--evm-rpc-ca-der-file`. See [Production (Nitro)](#production-nitro).

`--addr host:port` or `--addr vsock://<cid>:<port>` selects the enclave.

`insecure-dev` (parent cargo feature, dev only): the parent serves plaintext gRPC
with no client auth on any `GRPC_HOST`, and `clone` / `attest-verify` accept
`http://` to any host. Any `GRPC_TLS_*` setting is an error. A release build with
this feature does not compile. Dev image: `make build_parent_dev`.
Initialize once: use `cli init --cloning-secret-file <file>` instead of
`cli init` to configure a donor. Use a fresh requester for `cli clone`; initialization
and cloning are alternative ways to enter `Active`. Signing subcommands require
complete proofs and configured pins; see their `--help` and the spec.

A successful clone retains the verified session's cloning secret and can act
as a donor for a replacement without another `init`. The export cap applies
per enclave; it does not limit the total number of replicas across a cluster.
There is no cap unless `CLONE_EXPORT_HARD_CAP` is set.

### Production (Nitro)

`--memory` must be at least 4096 MiB, a whole number of GiB. The enclave
needs 3072 MiB of usable memory (`enclave/src/memory.rs`), and the kernel and
the root file system keep part of the launch value. nitro-cli gives an enclave
whole hugepages, 1 GiB pages first. A value that is not a whole number of GiB
can take a further 1 GiB page, so the deploy scripts refuse it.

Each deployment invocation configures exactly one enclave, so it needs
`ENCLAVE_MEMORY` (4096 MiB by default). The default CID is `16`; set
`ENCLAVE_CID=18` or `20` to deploy another supported CID. Run the command again
for each additional enclave. `memory_mib` in
`/etc/nitro_enclaves/allocator.yaml` sets the pool when the allocator starts,
at boot or on a restart of `nitro-enclaves-allocator.service`. The allocator
refuses to change the pool while an enclave runs, and the enclave units
require its service. So a restart of that service stops and restarts every
enclave of the host, and a restart removes the in-memory keys. Change the pool
only when every enclave of the host can stop, for example right before a cold
deploy or a reboot.

The pool comes out of the memory of the parent instance. Make sure that the
instance keeps enough memory for its system and the parents. When the
allocator cannot reserve the pool, its service fails, and no enclave of the
host starts. A new start of the allocator service does not start the enclave
units. Set `memory_mib` to a value that the instance can hold. Then reboot the
host, or start the `utexo-parent@` units. Each parent unit also starts its
enclave unit and the allocator service.

Both deploy scripts read `memory_mib` and the hugepages that the kernel holds.
`deploy-host.sh` refuses a pool smaller than the launch value of the one
enclave it deploys, before it downloads or stops anything. It does not count
pages that another enclave of the host holds. `systemctl restart` stops the old enclave before
`start` runs. So run `utexo-enclave-ctl.sh check <cid>` before each step of a
rolling restart. It makes the same checks and changes nothing. `start` refuses
only when the free hugepages cannot hold its own enclave.

`check` reads its values from `/etc/utexo/enclave.env`, the file that systemd
gives to `start`. Each invocation checks one enclave; there is no enclave-count
or CID-list setting. A key that is not in the file gets its default. A drop-in
or the systemd manager can still give `start` a value for such a key, but
`deploy-host.sh` writes all three keys. `check`
refuses a file that it cannot read, so run it as root or as a user that can
read the file. `check` reads only these plain lines:

- `KEY=value`. The key has only ASCII letters, digits and `_`, and its first
  character is not a digit. The key and the `=` can have blanks around them.
  The value has no backslash. A value can have one pair of the same quotes
  around it, and no other quote.
- A comment line. Its first character that is not a blank is `#` or `;`, and
  it does not end with a backslash.
- A blank line.

A plain line has only tabs and printable ASCII. It can end with a carriage
return, but it has no other carriage return. A plain line has at most 4096
bytes, and the file has at most 65536 bytes. systemd does not start the unit
with some much larger values and files. On plain lines, `check` reads the
same values as systemd. It refuses a file with other lines, because systemd
joins, splits, changes or ignores some of them, or refuses the file. If `check` refuses
the file, write it again with plain lines only.

A new launch value needs one `MemTotal` reading before release. Run one image
at that value with `ENCLAVE_DEBUG_MODE=1`, and make sure that
`nitro-cli describe-enclaves` shows that value in `MemoryMiB`. On
`nitro-cli console`, the "memory check passed" line gives `total_mib`, which
must be at least 3072.

```bash
nitro-cli run-enclave --cpu-count 2 --memory 4096 --enclave-cid 16 \
  --eif-path build/utexo-bridge-enclave.eif

# Host-side proxies (allowlist each upstream)
vsock-proxy 8001 <electrum-host> 50002          # ELECTRUM_URL upstream
vsock-proxy 8002 <EVM_RPC_HOST> 443             # EVM JSON-RPC over TLS to the pinned host (see deploy/host-prep-evmrpc.sh)

# Set the endpoints once. The enclave refuses a second set, and signs nothing
# and opens no chain connection before it. A restart needs a new set.
cli --addr vsock://16:5000 set-endpoints --electrum-url ssl://<electrum-host>:50002 \
  --evm-rpc-host <EVM_RPC_HOST> --evm-rpc-tls-port 443 --evm-rpc-ca-der-file ca.der \
  --kms-key-arn <KMS_KEY_ARN> --kms-region <KMS_REGION> --kms-seed-id <KMS_SEED_ID>   # mint only

GRPC_HOST=0.0.0.0 GRPC_PORT=50051 USE_VSOCK=true ENCLAVE_VSOCK_CID=16 \
  GRPC_TLS_CERT_FILE=server.pem GRPC_TLS_KEY_FILE=server.key \
  GRPC_TLS_CLIENT_CA_FILE=client-ca.pem GRPC_TLS_ACL_FILE=clients.acl \
  ./utexo-bridge-parent
```

`deploy/deploy-host.sh` installs the systemd template units and starts one
enclave and its parent. The supported CIDs are 16 / 18 / 20, with parents on
ports 50051 / 50052 / 50053. It verifies the EIF checksum and PCR0 against the
S3 manifest before and after start.
A restart removes the in-memory keys. Initialize or clone each enclave again.
Mint signers recover their saved KMS seed through `InitializeKey`. They require
the verified address pin and do not support peer cloning.

### Runtime limits

The operator can change the time, memory and size limits of a running enclave
with `utexo-bridge-parent-cli limits`. A change needs no new image, so the PCR
values and the keys do not change. The attestation does not cover these values.
[`docs/runtime-limits.md`](docs/runtime-limits.md) has the commands and the rules.

### Lost `SetEndpoints` reply

`deploy/systemd/utexo-enclave-ctl.sh start` terminates the enclave it
launched if `set-endpoints` or the launch check fails. That enclave has no key
yet. Run `start` again.

After a manual `set-endpoints` with no reply, do not send it again blindly:
the enclave refuses a second set. Read the enclave state first:

```bash
cli --addr vsock://16:5000 health   # read "Endpoints set" and "Key loaded"; exit code 1 only means "not ready"
```

| `Endpoints set` | `Key loaded` | Action |
| --- | --- | --- |
| false | any | The set did not take effect. A refused set keeps the slot empty. Send `set-endpoints` again. |
| true | false | The set took effect. Run `verify-launch` with the same values. On a mismatch, terminate the enclave and start it again. It has no key to lose. |
| true | true | The set took effect. Do not run `verify-launch`: it refuses an enclave with keys. Do not restart: a restart removes the keys. Check the attested values with `attest-verify`, the release PCRs and the `--expect-*` values of this launch, through the parent with an `observer` certificate. On a mismatch, stop and report. |

### Debug mode

`nitro-cli run-enclave ... --debug-mode` zeroes PCR0/1/2, so attestation
against pinned PCRs fails. Use it only to read logs:

```bash
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
nitro-cli describe-enclaves
nitro-cli terminate-enclave --enclave-id <id>
```

## Environment variables

### Enclave

Bridge pins (all three required for a `Production` policy):

| Variable | Default | Description |
|----------|---------|-------------|
| `EVM_CHAIN_ID` | `0` | Pinned chain id. Must match the destination chain and the direct-route `destinationChainId`. |
| `EVM_PROXY_CONTRACT_ADDRESS` | zero | MultisigProxy address: EIP-712 `verifyingContract` and the `to` of the payable `lzFundsOutCall` carve-out. Attested as `bridge_contract`. |
| `RGB_ASSET_ID` | empty | Pinned RGB contract id. Enforced on every bridge PSBT, and on `fundsOut` when the bridge is configured. |
| `FUNDS_IN_CONTRACT` | falls back to the proxy | Attested emitter of `FundsIn` / `BridgeFundsIn`. It must resolve to a non-zero address in production. |
| `TOKEN_CONTRACT` | zero | The ERC-20 the Bridge releases (`Bridge.TOKEN`). A `burnId` preimage input: the enclave recomputes `burnId` from it and refuses a mismatch. Attested; must be non-zero in production. |
| `BTC_RELAY_MODE` | `required` | With `spv` enabled, `required` checks both `fundsOut` commitment words against the enclave's BtcRelay records and refuses zero words. `none` requires both words to be zero and still checks heights, anchor and freshness. With `spv` disabled, the signer instead requires empty RGB `merkle_proofs` and an empty release `proof`. A production policy refuses to boot on `none`. Any other value is treated as `required` with a boot warning. |

Value bounds (fail closed while unset in a production build):

| Variable | Default | Description |
|----------|---------|-------------|
| `BTC_MAX_TOTAL_SATS` | `0` | Cap on total input value of one plain-BTC (`SignBtc`) transaction. Non-zero also flips `allow_vanilla_psbt` in the attested policy. |
| `BTC_MAX_UNOWNED_SATS` | `0` | Plain-BTC output budget for scripts the enclave does not prove it controls. Outputs repaying a signed input or landing on the enclave's own BIP-86 key-path addresses (singlesig change, `create_utxo` allocations) are proven and do not count. |
| `GAS_TX_ALLOWED_TO` | unset | Only `to` a gas tx may target. |
| `GAS_TX_MAX_GAS_LIMIT` | `0` | Ceiling on `gasLimit`. |
| `GAS_TX_MAX_FEE_PER_GAS` | `0` | Ceiling (wei) on `maxFeePerGas` / `maxPriorityFeePerGas` / legacy `gasPrice`. |
| `GAS_TX_ALLOWED_SELECTORS` | empty | Comma-separated 4-byte selectors a gas tx may call. Empty calldata is refused. Malformed entries are dropped with a warning. |
| `GAS_TX_MAX_VALUE_WEI` | unset | Ceiling on native `value`; only `lzFundsOutCall` to the pinned proxy may carry value. |

The gas-tx rule is part of the attested policy. Unset pins commit as zero.

Mint signer KMS custody is set at launch (see the launch table below).
With `KMS_EXPECTED_EVM_ADDRESS` set, initialization recovers the saved ciphertext
and checks the derived address. Without the pin, initialization creates a seed
only when storage reports no saved object. It rejects an existing object.
There is no separate creation-mode setting. See the [deployment and recovery
procedure](docs/kms-persistence.md) for parent storage and relay configuration.

Data sources and transport:

| Variable | Default | Description |
|----------|---------|-------------|
| `BITCOIN_NETWORK` | `bitcoin` | `bitcoin`, `testnet3` (or `testnet`), `testnet4`, `signet`, `signetcustom`, `regtest`. Selects the SPV rules and checkpoint, the RGB chain-network, coin types and xpub prefix. An unknown value stops the boot. Baked into the image. Attested. A production policy on EVM chain 1 or 42161 requires `bitcoin`. |
| `ESPLORA_VSOCK_PORT` | `8001` | Host vsock-proxy port for the Electrum or Esplora indexer. Only a burn signer built without `spv` reads it, but the mint and burn images pin the URL and start its forwarder. |
| `EVM_RPC_VSOCK_PORT` | `8002` | Host vsock-proxy port for the EVM RPC. |
| `KMS_VSOCK_PORT` | `8003` | Mint signer: host vsock-proxy port for AWS KMS. |
| `EVM_FINALITY_TAG` | `finalized` | Attested receipt acceptance tag: `latest`, `safe`, or `finalized`. Invalid values reject startup. A production policy also refuses `latest`. Every image sets `finalized`. |
| `SPV_MIN_CONFIRMATIONS` | `3` | Attested minimum depth of each Bitcoin witness tx, by SPV on the burn path. Zero or a non-number stops the boot. Every image sets 3; no mint check reads it. |
| `MINT_WITNESS_SAT` | `1500` | Mint signer: the exact sats a witness mint pays to the user's output. Unset or empty gives 1500; a non-number or a value outside 546 to 10000 stops the boot (every image parses it). It must equal the connector's `MINT_WITNESS_SAT`; the deploy checks that ([mint flow](docs/mint-flow.md) M8). Baked into the mint image (1500), so PCR0 measures it; not attested. |
| `ENCLAVE_LISTEN_ADDR` | `127.0.0.1:5000` | TCP listen address, non-vsock builds only. |
| `RUST_LOG` | unset | Log filter. |

EVM deposit receipts must be at or below the head returned by
`eth_getBlockByNumber(EVM_FINALITY_TAG, false)` and match the canonical block
hash at their height. The enclave revalidates the selected head snapshot to
detect a reorg during verification.

| Tag | Arbitrum acceptance |
|-----|---------------------|
| `latest` | Current L2 tip; lowest latency, with sequencer and L1 reorg risk. Development builds only: a production policy refuses it at boot. |
| `safe` | Batch posted and covered by L1's safe head, with residual L1 reorg risk. |
| `finalized` | Batch covered by L1's finalized head. Default, and the value of every image. |

Values must use the exact lowercase spelling. See
[Arbitrum finality guidance](https://docs.arbitrum.io/how-arbitrum-works/reference/finality-and-reorgs).
The enclave refuses signing until the deposit meets the selected tag and
whenever required RPC data is unavailable or invalid. Retry a pending deposit
after the selected head covers it. Production verification requires
`--expect-evm-finality-tag` to match the approved image value.

Chain endpoints and KMS values, set once at launch with `cli set-endpoints`
(`SetEndpoints`), are outside the image in both SPV and no-SPV builds. Hosts,
ports and the RPC CA, including any digest of them, are not EIF build inputs.
Members using the same role, release and build profile can use the same EIF
with different launch endpoints. Rebuilding that image and comparing PCR0/1/2
does not require the members' endpoint configuration. The public build inputs
and private dependency access described under Building are still required.
A mint image also carries `KMS_ALLOWED_ACCOUNT_IDS`, so members can share one
mint image only if this list has the AWS account of the key of each member.

A Production policy separately commits the Electrum host, the EVM RPC host,
the SHA-256 of the CA and the four KMS values in attestation `user_data`.
Full production-policy verification still needs independently approved values
for those fields; it is more than checking image PCRs. Development policy,
including no-SPV / IndexerTrusted, does not commit these fields. Operators must
approve its launch endpoints and KMS inputs externally. Release enclaves validate
their format and use TLS to authenticate the selected endpoints, but do not
authenticate an operator approval or prove the provider's data is correct.

Endpoint changes take effect on a new enclave launch; an active enclave refuses
a second `SetEndpoints`. Reuse the same EIF and image PCR allowlist for endpoint
changes. Key recovery and clone policy matching still apply: a burn donor with
a different attested endpoint policy cannot clone into the new launch.

For a provider such as Alchemy or Infura, put the absolute RPC path (for example
`/v2/<key>`) in a restricted file and pass `EVM_RPC_PATH_FILE` at launch. The
CLI and enclave accept only absolute ASCII paths up to 2048 bytes, without
authorities, queries, fragments, percent escapes or dot segments. Omit the file
to request `/`; an empty supplied file is rejected. The CLI accepts a trailing
line ending. The client sends the path over TLS to the configured host and CA,
and does not follow redirects. RPC transport errors and endpoint debug output
omit the path. The enclave turns `alloy_transport_http` logging off at any `RUST_LOG`
level: Alloy HTTP logs can include the full URL and provider responses.

The path and API key are absent from the EIF, image metadata, public attestation
and KMS context. A verifier needs no provider credential. To rotate a key,
replace the restricted file and restart using the same public endpoint values.
No image rebuild, PCR allowlist change or KMS context change is needed. The
parent supplies this file, so the key is not hidden from a compromised parent.
The no-SPV endpoint-approval limitation described above still applies.

`deploy/deploy-host.sh` also takes `EVM_RPC_PATH_FILE`. It keeps a copy in
`/etc/utexo/evm-rpc-path`, with mode 0600 and the service user as owner, and
writes that path in `/etc/utexo/enclave.env`. A deploy without the variable keeps
the copy, so a new deploy does not lose the key. To rotate a key on such a host,
replace the copy and restart the enclave. To go back to the path `/`, delete the
copy and deploy again.

A build requires the values it uses and refuses the others:

| Value (CLI flag / env) | Build | Description |
|------------------------|-------|-------------|
| `--electrum-url` / `ELECTRUM_URL` | `rgb-validation` | `ssl://host:port` (Electrum) or `https://host[:port]` (Esplora, for the custom dev signet). TLS terminates inside the enclave. The forwarder listens on that port and pins `host` to loopback in `/etc/hosts`. A test, debug, `mock-attestation` or `allow-seed-import` build also accepts plaintext `tcp://host:port` and `http://host[:port]`; a release image refuses them. |
| `--evm-rpc-host` / `EVM_RPC_HOST` | `rgb-validation` | TLS host name of the EVM RPC. No scheme, path, port or IP literal. |
| `--evm-rpc-tls-port` / `EVM_RPC_TLS_PORT` | `rgb-validation` | TLS port, 1-65535, not the Electrum port. The forwarder listens on it. |
| `--evm-rpc-ca-der-file` / `EVM_RPC_TLS_CA_DER_FILE` | `rgb-validation` | DER of the only CA the EVM RPC TLS trusts. |
| `--evm-rpc-path-file` / `EVM_RPC_PATH_FILE` | `rgb-validation`, optional | Restricted file containing an absolute RPC path such as `/v2/<key>`, up to 2048 bytes. Omission uses `/`; an empty supplied file is rejected. |
| `--kms-key-arn` / `KMS_KEY_ARN` | `kms-persistence` | Full symmetric KMS key ARN; aliases are rejected. |
| `--kms-region` / `KMS_REGION` | `kms-persistence` | Commercial AWS region matching the key ARN. The KMS forwarder listens on `127.0.0.2:443`. |
| `--kms-seed-id` / `KMS_SEED_ID` | `kms-persistence` | Stable signer identity used in the KMS encryption context and storage namespace. |
| `--kms-expected-evm-address` / `KMS_EXPECTED_EVM_ADDRESS` | `kms-persistence`, optional | Identity pin: 40 hex digits with optional `0x`. Pin the verified signer before funding; missing ciphertext then fails without replacement. |

Limits and dev knobs:

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONSIGNMENT_BYTES` | 10 MiB | Consignment size limit. Sized for a history of 10,000 transitions, each with an SPV proof. It sets the image value of the runtime limit `max_consignment_bytes`. The enclave reads it from the image env at boot, so PCR0 measures it. No supplied image sets it. It can only lower the default: a larger value stops the boot, because at the image frame the request memory model holds only up to 10 MiB. Unset, unparseable or zero gives the default. On a running enclave, `utexo-bridge-parent-cli limits set max_consignment_bytes=<bytes>` changes the limit for that enclave, from 1 KiB to 2^32 bytes. The enclave refuses a value at which the densest consignment does not fit the memory of a frame, so a larger value needs a larger `max_message_bytes`. A refused change keeps the old value. The next request uses a new value. A restart goes back to the image value. Then `utexo-enclave-ctl.sh start` sends `/etc/utexo/enclave-limits.conf` again, if that file is readable, and a refused file leaves the image values. The attested policy commits neither value. See [runtime limits](docs/runtime-limits.md). |
| `MAX_MERKLE_PROOFS` | `16384` | Proof-count limit per request. A burn needs one proof for each witness tx in its history. |
| `MAX_TOTAL_PROOF_BYTES` | 8 MiB | Aggregate proof-bytes limit per request. |
| `SPV_CHECKPOINT` | unset | Dev builds only: `height:hash:bits:time[:chainwork]` moves the SPV anchor forward. `bits` and `time` are those of that block. The median-time-past rule reads `time`, and on mainnet and the testnets the `nBits` checks read both. Without `chainwork` (Core's `getblockheader` value), the enclave refuses every RGB-source release under `BTC_RELAY_MODE=required`. `none` needs no chainwork. A production-shaped build refuses to boot when set. |
| `UTEXO_CLONING_SECRET` | unset | Dev fallback for the donor cloning secret, read from the image env at boot. Ignored with `kms-persistence`, which rejects cloning. Otherwise prefer `init --cloning-secret-file` at runtime. |
| `CLONE_EXPORT_SOFT_CAP` | unset | Seed exports per enclave process before a warning. It does not block exports. Unset or zero turns it off. |
| `CLONE_EXPORT_HARD_CAP` | unset | Seed exports per enclave process. A restart resets the count. Unset or zero means no cap. No supplied image sets it. |

### Parent

The parent reads these from its environment at start, so a change needs a
restart. They are not in the enclave image, and the attested policy does not
commit them. A number that does not parse takes the default with no log, unless
the row says otherwise. `deploy-host.sh` rewrites `/etc/utexo/parent-<CID>.env`
on each run, so a value set by hand in that file is lost. It writes no
`GRPC_MAX_CONCURRENT*`, `GRPC_REQUEST_TIMEOUT_SECS` or `SIGNED_RESPONSE_*`
value, so a deployed parent uses their defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `GRPC_HOST` | `127.0.0.1` | Bind address. The deploy script defaults to the private EC2 address. |
| `GRPC_PORT` | `5000` | gRPC port. Deployments use 50051-50053. |
| `GRPC_MAX_CONCURRENT` | `128` | Requests in progress over all connections. The parent refuses a request above the limit and does not queue it. `0` acts as `1`. |
| `GRPC_MAX_CONCURRENT_SIGN` | `8` | `Sign` requests in progress. A `Sign` above the limit gets `UNAVAILABLE` at once. `0` acts as `1`. The `MemoryMax=1G` of the parent unit counts on the default, so review it before you raise this value. |
| `GRPC_MAX_CONCURRENT_PER_CONN` | `32` | Requests in progress on one connection, and the HTTP/2 stream limit. `0` acts as `1`. |
| `GRPC_REQUEST_TIMEOUT_SECS` | `120` | Longest run of one gRPC request. Keep it above the request deadline of the enclave plus 10 s. The connection deadline is 300 s plus this value plus 10 s ([parent mTLS](docs/parent-mtls.md)). `0` acts as `1`. |
| `ENCLAVE_ADDR` | `127.0.0.1:5000` | Enclave TCP address (dev). |
| `USE_VSOCK` | `false` | `true` / `1` selects vsock (Linux only). |
| `ENCLAVE_VSOCK_CID` | `16` | Enclave CID. |
| `ENCLAVE_VSOCK_PORT` | `5000` | Enclave vsock port. |
| `SIGNED_RESPONSE_TTL_SECS` | `3600` | How long the parent keeps the reply of an EVM->RGB bridge sign and answers a retry of the same request from it. The enclave refuses such a retry for `mint_replay_ttl_secs`, by default one hour, so keep the two aligned. With `0`, no retry gets a kept reply. |
| `SIGNED_RESPONSE_MAX_ENTRIES` | `1024` | Count limit of kept replies. `0` still keeps one reply. |
| `SIGNED_RESPONSE_MAX_BYTES` | `16777216` | Byte limit over all kept replies. The parent does not keep a larger reply. `0` keeps none. |
| `HEALTH_HOST` | `127.0.0.1` | Bind host for `GET /health`. Keep on loopback - unlike `GRPC_HOST`, do not set to `0.0.0.0` |
| `HEALTH_PORT` | `5001` | Port for `GET /health` |
| `GRPC_CLONE_MAX_PER_MINUTE` | `30` | `Clone` calls per minute for all clients, `1..=10000`. Out of range stops the parent at boot. |
| `GRPC_ATTEST_MAX_PER_MINUTE` | `6` | `AttestedPublicKey` calls per minute for all clients, `1..=10000`. Each call makes one NSM attestation in the enclave. Out of range stops the parent at boot. |
| `HEADER_ELECTRUM_URL` | unset | `ssl://host:port` (WebPKI roots, host name checked), or `tcp://` to a loopback IP. The parent's header sync reads Bitcoin headers here. Unset: `header_sync.state` is `unconfigured`. Malformed: the parent still serves, `header_sync.state` is `unconfigured` and `last_error` says why. Deploy passes it through; it does not copy `ELECTRUM_URL`, whose enclave-side rules differ. |
| `HEADER_SYNC_INTERVAL_SECS` | `10` | Seconds between header sync steps, `1..=600`. A malformed value stops the parent at boot. |
| `RUST_LOG` | unset | Log filter. |

#### Readiness endpoint

Use `GET /health` to check readiness before you continue a rollout.
`deploy/deploy-host.sh` performs a cold deployment. It does not initialize keys
or implement a rolling restart.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5001/health
```

- `200` - endpoints are set and the signing key is loaded. Builds with the
  RGB -> EVM path also require a fresh header chain with at least
  `SPV_MIN_CONFIRMATIONS` headers above the checkpoint
  (`assert_chain_ready`). Mint signers do
  not require SPV readiness, although they report `spv_synced`.
- `503` - the enclave is not ready, cannot be reached, or does not answer
  within the five-second probe timeout.

A `200` response does not prove that a signing request will succeed. The
request must still pass its policy, data-source, and validation checks.

The body includes readiness, key, phase, and SPV diagnostic fields.
Use them to investigate a failed deployment. It also includes the parent's
header-sync status. Example fragment:

```json
{"header_sync": {"state": "synced", "source_tip": 412345, "enclave_tip": 412345, "lag_blocks": 0, "tip_age_secs": 41, "last_ok_unix": 1790000000, "last_error": null}}
```

`state` is `synced`, `syncing`, `stalled` (three failed steps in a row), `off`
(a build with no header chain) or `unconfigured` (no `HEADER_ELECTRUM_URL`).
The header-sync state does not change the HTTP code. A rollout can check it
separately when the selected signer needs Bitcoin headers. The deploy script
sets ports `50061`, `50062`, and `50063` for the three parents. The parent
Docker image uses the same probe in its `HEALTHCHECK`.

This operations probe binds to loopback by default. `HEALTH_HOST` can change
the address. Keep the endpoint inaccessible from other hosts.

The same answer is available from the CLI, for debugging from the host shell:

```bash
utexo-bridge-parent-cli --addr vsock://16 health
```

## Testing

```bash
cargo test                                                              # enclave workspace, default features
cargo test -p attestation-verify --features mock                          # dependency tests need their own invocation
cargo test -p utexo-bridge-enclave --no-default-features --features spv,mint-signer,mock-attestation,allow-seed-import
cargo test -p utexo-bridge-enclave --no-default-features --features spv,burn-signer,mock-attestation,allow-seed-import
cargo test -p utexo-bridge-enclave --no-default-features --features spv,mint-signer --test test_evm_event_live
cargo test -p utexo-bridge-enclave --features mock-attestation,allow-seed-import
cargo test --manifest-path parent/Cargo.toml                            # gRPC bridge + attest-verify e2e
python3 -m unittest discover -s build/tests -v
python3 -m unittest discover -s deploy/lambda/sns-to-slack -v
```

Coverage: key derivation and fingerprints, framing, EIP-712 digests checked against
contract fixtures, calldata canonicalisation, gas-tx allowlist, consignment
fixtures per flow, PSBT binding and fee gate, SPV chain / reorg / Merkle,
attestation verification incl. crafted cert chains, cloning handshake, wire
roundtrips over TCP, gRPC translation with a mock enclave, vendored-proto
provenance. Mint and burn wire suites validate real BFA data and verify the
returned signatures. The mint suite also checks failed-delivery retries.
`build/smoke-test.sh` checks a live enclave's lifecycle and public identity;
it can initialize a fresh enclave and set its endpoints. The separate
`build/grpc-smoke-test.sh` checks the burn parent's transport and role refusals.
Neither smoke script substitutes for a successful signing regression.
Mint initialization needs KMS configured; SPV-enabled burn readiness needs the
parent's header sync to have caught up.

CI runs the mock verifier tests, Lambda tests, the mint VSOCK deadline guard,
and the parent CLI timeout against Linux `vsock_loopback`. To run the latter
locally on Linux:

```bash
sudo modprobe vsock_loopback
cargo test --manifest-path parent/Cargo.toml --features vsock --test test_cli_vsock_timeout
```

Large RGB histories and capacity/timing tests remain explicitly ignored in
ordinary PR runs. Use **Actions → CI → Run workflow → run_stress** for the
release-mode suite, or run:

```bash
cargo test --release -p utexo-bridge-enclave --no-default-features --features spv,burn-signer --lib networks::rgb::validation::tests -- --ignored --nocapture --test-threads=1
```

Live EVM event checks are explicitly ignored because they require an RPC and a
known deposit. Configure the variables documented in
`enclave/tests/test_evm_event_live.rs`, then run the command there with
`-- --ignored`. An explicit live run fails if its configuration is missing.
An ordinary CI run reports these tests as ignored, not as passed.

## Feature flags

`rgb-validation` needs exactly one signer role (`mint-signer` or `burn-signer`),
or the build fails. `spv` turns it on too, so it has the same need.
The default set is `ccd`.

| Feature | Implies | Description |
|---------|---------|-------------|
| `ccd` | - | Concordium stack (Ed25519 is always compiled; this gates the handlers). Does not compile in release with `mint-signer` or `burn-signer`. |
| `kms-persistence` | - | Attested KMS seed generation/recovery with encrypted S3 persistence. Requires `mint-signer`; custody context is `rgb-mint`. |
| `mint-signer` | `rgb-validation`, `kms-persistence` | Mint/burn signer role: EVM -> RGB only (mint PSBT, `SignBtc`, `SignRightsRefill`). Reads its mints and refills from the rgb-lib fascia of each tx, which needs the `strict_encoding` dependency. Exactly one role per mint/burn build. |
| `burn-signer` | `rgb-validation` | Mint/burn signer role: RGB -> EVM only (`fundsOut`, gas tx). Exactly one role per mint/burn build. |
| `spv` | `rgb-validation` | In-enclave Bitcoin header chain and witness inclusion proofs. |
| `rgb-validation` | RGB crates, EVM client | In-enclave consignment validation and BFA checks. Uses SPV or indexer confirmations. Binds BFA mint claims to verified `FundsIn` locks by lockId, over JSON-RPC with TLS to a pinned host and CA. Without it the enclave refuses every RGB source and every bridge PSBT. |
| `vsock` | - | vsock listener and forwarders (Linux). |
| `allow-seed-import` | - | Mnemonic / raw-seed import. Dev only, does not compile in release. |
| `mock-attestation` | - | Raw-CBOR attestation with zero PCRs. Dev only, does not compile in release. |
| `allow-debug-pcrs` | - | Removes the all-zero PCR rejection from the attestation verifier. Dev only, does not compile in release. |

## Proto source

| | Enclave | Parent |
|---|---|---|
| Schema | `enclave-proto/`, vendored in-tree | `federated-signer-proto`, git dep over SSH |
| Packages | `enclave` only | `bridge` / `node` / `orchestrator` / `parent` / `signer` |
| Workspace | repo root | `parent/` (own root + lockfile) |

Cargo materialises every git source in a workspace before it knows which
crates a `-p` build compiles. Keeping `parent/` out of the root workspace is
what keeps its private proto dep out of the enclave dependency graph. Build
the parent with `--manifest-path parent/Cargo.toml`, never `-p`.

The generated Rust is committed because `protoc` / prost-build versions change
the output and would otherwise enter PCR0. Both sides pin the same upstream
commit; `enclave-proto/tests/vendored_provenance.rs` fails when they drift.
Re-syncing changes PCR0. Procedure in
[`enclave-proto/README.md`](enclave-proto/README.md).

## Security model

- **Untrusted host.** Requests from the parent, listener and backend are checked
  inside the enclave. Concordium source validation trusts the listener;
  see the spec for network-specific limits.
- **On-chain RGB witnesses.** RGB consensus counts a witness tx as valid only
  if it is mined at least `SPV_MIN_CONFIRMATIONS` deep, so an off-chain
  transfer in the history fails validation. The burn signer proves this with
  the request's Merkle proofs against its own header chain. The mint signer
  checks no witness: it reads the mint from the fascia, and a bad history makes
  the mint invalid for every receiver.
- **Pinned EVM RPC trust (accepted by design).** TLS ends inside the enclave and
  authenticates the configured RPC hostname against the pinned CA. The host
  relay cannot alter authenticated responses without detection. The enclave
  checks successful receipts, unique expected events from the pinned contract,
  operation IDs, amounts, coverage by the selected finality head and canonical
  block hashes.
  These checks do not prove EVM consensus: an approved provider can return a
  self-consistent false deposit history. Trust in the provider's data is an
  explicit design assumption. Verifiers must compare the attested host and CA
  SHA-256 with independently approved values. See the
  [EVM RPC trust boundary](docs/tee-spec.md#2-trust-boundary-and-threat-model).
- **Attested posture.** Build flags and pins resolve to one `SecurityPolicy`
  committed into the attestation. Policy matching checks only the committed fields.
  The Electrum/Esplora scheme is not committed: a release image accepts only
  TLS (`ssl://`, `https://`), so PCR0 covers it. Endpoint ports are not
  committed. See the [policy scope](docs/tee-spec.md#4-security-policy).
- **Fail closed.** Missing feature, missing pin, missing receipt, missing
  proof, zero inputs signed: refuse, never sign with less verification.
- **Limits.** Bitcoin freshness, reorg/retention caps and connection limits
  are compiled in. `SPV_MIN_CONFIRMATIONS`, `EVM_FINALITY_TAG` and
  request-size caps are read from environment; image-baked values are measured
  with the EIF.
- **Key custody.** Seed and keys in `SecretBox`, zeroized on drop.
  `#![deny(unsafe_code)]`. With `kms-persistence`, seeds persist as KMS ciphertext
  in S3. The parent receives no plaintext seed. KMS handles the seed during
  generation and decryption. Derived signing keys stay in enclave memory.
- **Cloning (without KMS persistence).** X25519 + HKDF-SHA256 + ChaCha20-Poly1305, mutual attestation
  with PCR equality, shared secret, replay guard recorded only after
  authentication.
- **Release hardening.** `opt-level = "z"`, LTO, stripped, `panic = "abort"`,
  single codegen unit. Dev features are `compile_error!` in release.

Known limitations are listed in
[`docs/tee-spec.md`](docs/tee-spec.md#13-implementation-status).
