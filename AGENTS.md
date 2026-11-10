# Repository instructions

These instructions apply to the whole repository and to every contributor or
coding agent. They define how to change the project. They do not claim that
every requirement below is already implemented.

## Start with the current branch

- Read the relevant code, tests and documents before changing behavior.
  Check the target branch and the working-tree diff. Preserve unrelated work.
- Treat PR discussions as design history, not as proof of current behavior.
  A merged PR can be superseded, and a closed PR can have landed through another
  PR. Check the current code before carrying a historical rule forward.
- Keep the change within the requested scope. Trace it through its callers,
  adapters, configuration and deployment before calling it complete.
- If code, a spec and a requirement disagree, state the difference. Fix it in
  the authorized scope or record the remaining work. Do not hide it by weakening
  a check, removing a test, or describing planned behavior as implemented.
- Keep this file focused on lasting rules. Put current versions, default
  values, deployment addresses and known limits in their owning code and docs.

## Project map and required reading

The enclave holds keys and checks signing requests. The EC2 parent translates
requests and relays bytes; it is outside the enclave trust boundary.

| Area | Code or configuration | Read with the change |
| --- | --- | --- |
| Enclave validation, signing and lifecycle | `enclave/src/` | [Technical specification](docs/tee-spec.md) |
| Mint signing, plain BTC and rights refill | `enclave/src/networks/rgb/`, `enclave/src/networks/evm/`, `enclave/src/keys.rs` | [Mint flow](docs/mint-flow.md) |
| Burn validation and EVM releases | `enclave/src/networks/rgb/`, `enclave/src/networks/evm/` | [Burn flow](docs/burn-flow.md) |
| Destination records and route bindings | EVM validation and shared vectors | [Record format](docs/burn-destination.md) |
| Attestation and public verification | `attestation-verify/`, enclave attestation, parent verifier | [Attested keys](docs/pubkey-attestation.md), [verify a signer](docs/verify-a-signer.md) |
| Mint seed recovery | Enclave KMS and parent storage broker | [KMS persistence](docs/kms-persistence.md) |
| Burn seed cloning | `enclave/src/cloning.rs`, the parent `clone` command | [Cloning](docs/cloning.md) |
| Parent transport and authorization | `parent/src/` | [Parent mTLS](docs/parent-mtls.md) |
| Runtime limits | `enclave/src/limits.rs`, `enclave/src/memory.rs`, `parent/src/limits.rs` | [Runtime limits](docs/runtime-limits.md) |
| Work caps of consignment validation | `enclave/src/networks/rgb/validation/cost.rs` | [Cost model](docs/validation-cost-model.md) |
| Wire schema | `enclave-proto/`, `parent/Cargo.toml` | [Proto provenance and sync procedure](enclave-proto/README.md) |
| Build, CI and deployment | `build/`, `deploy/`, `.github/workflows/` | [Building](docs/building.md), [configuration](docs/configuration.md), [operations](docs/operations.md), [stage profile](build/profiles/README.md) |
| Architecture and request sequences | Related handlers and adapters | [Diagram index](docs/diagrams/README.md) |

The root Cargo workspace contains the enclave, vendored enclave protocol and
shared attestation verifier. `parent/` is a separate workspace with its own
manifest and lockfile. Do not add the parent to the enclave workspace:
that would pull the parent's dependency graph into enclave build resolution.

## Keep code, specs, docs and comments in sync

A behavior change is incomplete until its affected descriptions agree with it.

- Update the relevant spec, README sections, flow guide, diagrams, CLI help,
  configuration tables, examples and tests in the same PR as the behavior.
  Search for old names, defaults, feature lists, flags and claims across the
  repository, including Dockerfiles, workflows and scripts. The
  [documentation index](docs/README.md) lists the documents.
- State a fact in one document and link to it from the others. A runtime
  limit has its value in `docs/runtime-limits.md`, and a setting in
  `docs/configuration.md`. Another document names the limit or the setting;
  it does not repeat the value.
- For a new or changed setting, document its source, default, valid values,
  scope, failure behavior and when it takes effect. State whether it is baked
  into the image, supplied at launch, or mutable at runtime, and whether the
  attestation policy commits to it.
- For a signing or wire change, update the request/response description,
  validation order, error mapping, compatible clients and rollout procedure.
- For a trust change, update the threat model, enforcement boundaries, policy
  coverage, public verification recipe and known limits together.
- Keep implemented behavior, required behavior, accepted risks and planned work
  distinct. A code review does not prove what is deployed. Do not change a
  document's reviewed date or claim a deployment was checked without doing it.
- Read nearby comments and module docs after editing code. Correct or remove
  stale explanations, dead references, old TODOs and obsolete follow-up notes.
  Search other call sites and test comments for the same claim.
- Comments should explain a reason, invariant, unit, protocol constraint or
  non-obvious failure case. Avoid narrating obvious code or leaving a history
  of abandoned implementations in the source.
- Code, comments, docs, the README and PR descriptions describe the current
  behavior. Do not write what was added, removed, renamed or retired, or how
  the code worked before; git keeps that history. Do not name a feature, flow,
  setting or file that the code does not have. A PR description states the
  behavior after the change, not earlier versions or attempts.
- A comment does not write out a value that the code defines elsewhere, that
  `limits set` can change, or that an image setting sets, nor a number
  computed from them. Name the constant, the runtime limit or the image
  setting instead. A measured figure keeps its number when it names the input
  it was measured at.
- The tree has no audit finding ids, review labels, scan finding numbers, or
  issue and pull request numbers. This applies to comments, docs, specs, the
  README, log and error texts, test names, file names and test data. Such ids
  look like `F<nn>-AF-<nn>`, `AF-<nn>`, a letter-and-number label such as
  `I-<nn>` or `TH-<n>`, "finding <n>" or `#<n>`. Do not point to an audit or
  a review in place of a reason. State the rule and its reason in words, and
  name a test by what it checks. Git history and the tracker keep the link to
  a finding. A reference to another repository names that repository and the
  file, not a pull request number. Search the diff for these forms before
  each commit.
- These identifiers name a public fact or a rule of the specs, so they stay:
  CVE and RUSTSEC ids, RFC, BIP and EIP numbers, upstream bug links, tool error
  codes such as the nitro-cli `E<nn>` codes, and the rule ids that
  `docs/mint-flow.md` and `docs/tee-spec.md` define and the code cites (for
  example `M6`, `RR10`, `PP1`).
- Preserve the provenance of generated and vendored files. Correct stale
  upstream comments upstream and re-sync the files; do not hand-edit a
  verbatim copy. Until then, keep its documented comment differences accurate
  in `enclave-proto/README.md`.
- Check that documented commands, flags, paths and links exist on the target
  branch. Examples must use compatible roles, networks, schemas and modes.

## Use simple technical English

- Use short, direct sentences. Name the actor, action and condition:
  "The enclave rejects an unknown selector."
- Use the same term for the same thing. Distinguish the parent, listener,
  enclave, operator, RPC provider and verifier.
- State what a check proves and what it does not prove. Avoid vague claims
  such as "secure", "trustless" or "fully verified" without their scope.
- Explain abbreviations when needed. Keep exact identifiers, units and protocol
  names where they prevent ambiguity. Prefer familiar words over jargon,
  marketing language and decorative wording.
- Write comments, errors, docs, commit messages and PR descriptions this way.
  Describe the final behavior, not the conversation or an abandoned approach.

## Trust boundary and signer roles

- Treat the parent, listener, backend and direct vsock callers as untrusted.
  Every signing authorization check must run inside the enclave. Parent mTLS,
  routing and ACLs do not protect against a compromised parent.
- Do not trust caller flags such as "event valid", "finalized" or
  "consignment valid". Derive the evidence required by the selected flow.
  Document any deliberate source-trust exception.
- Refuse missing pins, required proofs, unsupported routes and disabled
  capabilities. Do not turn parse errors, missing data or unavailable
  dependencies into a less strict signing path.
- Keep mint and burn capabilities, seeds and images separate. A mint signer
  must not gain a burn or gas-signing path; a burn signer must not gain a
  mint or plain-BTC path through an adapter or feature combination.
- Do not make key derivation or the shape of the attested key bundle depend on
  a feature or role. Gate the request path instead.
- Check the actual feature graph and release recipes. The default development
  feature set is not the production configuration. Keep the attested role and
  the direction cfgs set by `enclave/build.rs` consistent; reject a build that
  claims one role but enables another's path.
- Keep dev-only seed import, mock attestation, all-zero peer PCR allowances
  and insecure transport out of release enclave binaries. Preserve
  compile-time rejection tests, including role-specific and no-SPV combinations.
- A stage or no-SPV profile changes specified validation assumptions. It does
  not automatically authorize weaker seed custody, raw signing or mock
  attestation.
- An RGB build without `spv` has no SPV proof. Its burn signer trusts the
  indexer for Bitcoin witness status. Limit such a build to public Signet and a
  Development policy. It must not resolve to a Production policy or claim
  SPV-verified data.

## Common EIFs and independent federation RPCs

For one signer role, release and build profile, federation members must be
able to run one reproducible EIF with the same publicly verifiable image
measurements (PCR0/PCR1/PCR2), while using different EVM RPC connections.

- Supply member-specific RPC hosts, ports, CA pins, paths and API keys at
  runtime. Do not require one measured image per provider or member.
- RPC API keys are secrets even when carried in a URL path. Keep credentials
  out of the EIF, build arguments, image metadata, logs and public attestation
  data, including public policy commitments derived from secret-bearing URLs.
- Never include a credential or member-specific endpoint in a digest baked
  into the EIF. Excluding only the API key is insufficient if the host or CA
  still makes each member's image different.
- Key rotation must not require an EIF rebuild or changes to image PCR
  allowlists. A restart or a new launch configuration may still be required.
  Changing an approved endpoint can require a new policy approval and
  attestation, while leaving the common image unchanged.
- Preserve in-enclave TLS hostname verification, CA pinning, refusal of EVM RPC
  redirects, chain-ID checks and strict path validation. Credentials must not
  change the approved authority or network. Host proxies relay bytes; they do
  not terminate the enclave's authenticated connection. In the enclave, a
  forwarder for a TLS endpoint must accept only a connection that starts with a
  TLS handshake.
- Separate image identity from runtime endpoint policy. Preserve independent
  verification of the approved host and CA with
  `--expect-evm-rpc-host` and `--expect-evm-rpc-ca-sha256`.
  Do not learn expected values from the signer being checked.
- An attested policy authenticates only the endpoint fields it commits. It
  does not approve those fields, prove a connection occurred, or prove the
  provider's data is honest. EVM RPC data received over TLS remains an explicit
  trust assumption.
- Apply the same image/runtime separation to SPV and no-SPV / IndexerTrusted
  profiles. Endpoint approval belongs to the independently approved deployment
  configuration; do not introduce an operator signing-key system as part of
  endpoint configuration. Preserve runtime TLS and launch validation.
  Where the attested policy commits no endpoint fields, it cannot show which
  endpoints a signer uses. Document that limit; do not describe PCR verification
  or successful TLS as endpoint approval.
- Keep secret rotation distinct from public release changes such as signer
  code, asset pins and protocol rules, which can legitimately change image
  measurements. Deployment measurements such as PCR3 can differ between
  members; preserve the separate rules that use them.

These are design requirements, not a claim that every existing build meets
them. If a branch still measures member-specific endpoints or credentials,
report that conflict and keep it visible until the implementation is fixed.

## Attestation, identity and key custody

- Keep policy encoding canonical, versioned and shared between the enclave
  and verifiers. A policy-field change needs matching producers, consumers,
  golden vectors, CLI expectations and docs. Do not silently change bytes
  under an existing format version.
- Preserve the full real-attestation checks: AWS certificate trust, certificate
  constraints and validity, COSE algorithm and signature form, expected PCRs,
  nonce, public-key bundle and policy commitment.
- Keep real and mock modes explicit and incompatible with the wrong expected
  policy. Mock tests do not prove real Nitro, KMS or deployment behavior.
- Get expected PCRs, identities and launch policy from independently approved
  release inputs. Verifier success must compare the required fields, not
  merely print authenticated values.
- Distinguish attested identity, current readiness, nonce freshness, on-chain
  membership and original key history. An offline bundle is not proof that a
  signer is live now, that a key has never been copied, or that its RPC works.
- Treat each clone cluster as one signing identity. Replicas sharing a seed
  are not independent federation votes. Preserve clone checks for image PCRs,
  parent-role PCR3, the policy commitment, the runtime cloning secret, peer
  keys and replay.
- Keep mint KMS recovery separate from burn cloning. Storage, KMS or identity
  failures must not silently create a replacement seed. Preserve conditional
  creation, encryption context and recovered-address checks. Without an
  expected address, existing ciphertext must be refused; first bootstrap may
  activate only the ciphertext generated by that call.
- Keep member-specific KMS settings, such as the key ARN, in independently
  approved launch configuration, not inputs that produce a different EIF per
  member. The KMS account list is the exception: keep it in the mint image,
  because PCR0 measures it and the host then cannot name a key in an unlisted
  account. Members can share one mint image only if the list has the account of
  each member's key.
- In production custody, the parent may relay credentials and ciphertext but
  must not receive the plaintext seed. Keep secrets redacted and zeroized.
  Do not log sensitive URLs, transport errors or debug structures that contain
  credentials.
- Authenticate before committing replay nonces or installing keys. Reserve
  provisional state atomically and roll it back on failure. Validate setup
  inputs before key installation. Failures must leave a retryable, defined
  state without replacing an active identity.

## Signing and cross-chain bindings

- Check launch state, active keys and role before expensive validation. Trace
  the whole path from parent input through dispatch, validation, signing and
  the returned response. Reject unexpected request and reply variants.
- Decode each signing intent once where practical. Carry typed, validated
  facts to the signer instead of re-decoding attacker-controlled bytes or
  discarding the source validator's result.
- Bind the exact asset, chain, contract, operation/deposit ID, amount,
  recipient, route, deadline and transaction to the evidence required by
  that flow. A caller's summary or index is not a substitute for identity.
- Pin and check ABI selectors, event topics, field widths and canonical
  encoding against the relevant contract revision. Test direct and LayerZero
  routes separately; keep their destination and payload bindings equivalent
  where the protocol requires it.
- Decode the LayerZero `extraOptions` of a release before signing it, and allow
  only known gas-only forms. A native drop, compose option or `lzReceive` value
  moves native tokens that the burn did not name.
- Select an EVM deposit by the protocol's identity and require an unambiguous
  match. Do not assume the first receipt log is the intended deposit.
  Preserve successful-receipt, finality-head and canonical-block checks.
- Derive deposit and burn identifiers from validated data. Bind settlement
  ancestry, order and destination records to the same validated operation.
  Use the shared destination vectors across components; do not reconstruct a
  length-sensitive record from padded calldata.
- A burn on RGB is permanent. Never change a published burn destination version
  or remove the enclave's check for it, V0 included. A new format needs a new
  version.
- Treat gas transaction signing as its own restricted capability. Validate the
  unsigned transaction, digest, destination, selector, value, gas and fee
  limits. Never add arbitrary EVM digest or raw-message signing.
- Preserve the difference between an EIP-712 release and its outer gas
  transaction. Do not claim the gas transaction is bound to a specific release
  unless code actually enforces that relationship.
- Use checked arithmetic and explicit units for amounts, fees, sizes, indices
  and time. Reject overflow, truncation, invalid lengths and non-canonical
  encodings before signing. Do not panic or assert on malformed request data;
  a panic can abort the enclave.
- Fresh PSBT signing must reject a request that signs no eligible input. A
  retry of an identical request may get the reply kept from the first signing;
  that is not a new signing operation.

## RGB, Bitcoin and PSBT rules

- Follow the selected flow's validation model. Burn checks RGB consensus and
  its required history; mint uses its fascia, parent-right and EVM-deposit
  bindings. Do not claim mint validates history it does not read.
- Use the pinned canonical RGB schema and type definitions. Do not trust a
  consignment to supply the rules against which it will be validated.
- Validate a consignment only with rgb-lib's
  `validate_consignment_with_resolver`, and confirm a mint claim only against a
  lock the enclave bound. Refuse on a resolver error or an rgb-lib warning.
  `clippy.toml` bans the direct calls; update the bans when an RGB crate renames
  those methods.
- Bind the asset before any external read that a consignment selects. A
  consignment of another asset must not choose what the enclave reads.
- Bind consensus results to the exact terminal operation and Bitcoin witness
  used for signing. A matching summary alone does not prove the signed
  transaction is the validated operation.
- Prove key and output ownership from scripts, derivation and allowed accounts.
  Being able to sign one leaf of a Taproot tree is not proof of exclusive
  custody. Keep colored, vanilla and foreign-input handling distinct.
- Keep the exact mint amount, recipient seal, right propagation, parent
  transaction and PSBT commitment rules together. For refill, preserve custody
  of the rights and its separate limits. Do not generalize away documented
  witness-recipient or fee-input limitations.
- A mint's lock names one Bitcoin transaction: `LockId` commits the mint OpId
  and the txid. After the lock, no path may change that transaction by RBF, a
  rebuild or batching. A retry uses the same PSBT. Only a CPFP child can raise
  the fee.
- Derive fees and output budgets from the transaction actually signed.
  Signature merging must not change ownership classification or bypass
  caps, sighash rules or output-key checks.
  Keep market-fee selection separate from deterministic signing limits. Do
  not use live fee estimates: they can strand an already funded request.
- For SPV builds, verify Merkle inclusion and position, enforce path-depth
  limits and refuse a path node that is a 64-byte transaction. Check header
  ancestry, network rules, difficulty, chainwork, timestamps, confirmations and
  freshness as required by that network. Test reorgs and boundary cases.
- The SPV checkpoint is a trust anchor. A release build uses only the
  compiled-in value. The parent and the operator must not be able to set it.
- Preserve the validated chain view until key use, or revalidate under the
  required lock. A reorg between validation and signing must not invalidate
  the proof the signature relies on.
- Do not discard historical headers that supported consignments still need.
  Bound retention explicitly and describe what happens at the cap.
- Keep mainnet, testnet, Signet, regtest and indexer-trusted assumptions
  explicit. Network labels and attested values must match enforced behavior.
  Never describe TLS or test-network checks as a proof of Bitcoin consensus.

## Limits, deadlines, concurrency and retries

- Bound frame bytes, field sizes, collection counts and aggregate work before
  allocation, decoding or expensive validation. Check arithmetic used for caps.
- Account for all simultaneously live copies: encoded input, decoded objects,
  queues, worker concurrency, caches and temporary files. Enclave scratch
  files can use RAM. A per-field cap is not a process-memory bound.
- Bound request-controlled text before it reaches a log line or an error reply.
  A long log line can hold heap after its request ends.
- Measure a cost model or memory model again when the code or dependency it
  describes changes.
- Carry a request deadline through queueing, connection setup, reads, writes,
  RPC retries and expensive work. A socket timeout alone does not cancel a
  handler or prove that signing stopped.
- Order timeouts around a state commit so that the committing side gives up
  first. On a signing exchange, the parent must wait longer than the enclave's
  request deadline. Otherwise the enclave can commit a replay key for a reply
  that nobody reads.
- Put limits on the actual untrusted entry path, including direct vsock and
  every production caller of a helper. Per-client limits do not replace a
  global connection or work budget.
- Do not count a health probe, such as the `PublicKey` call of the signer node,
  against a limit on expensive work. A failed probe can make a client reconnect,
  which cancels its requests on the old connection.
- Define state changes and rollback for validation failure, timeouts, signing
  failure, serialization failure and lost responses. Document the response
  write or persistence point that commits an operation.
- Distinguish on-chain replay protection, a local dedup cache, a clone nonce
  guard and a retry response cache. State their scope, capacity, expiry and
  restart behavior. An in-memory guard is not durable replay prevention.
  Bind cached signed replies to the exact request. The same operation ID with
  different content is not an identical retry. Test caller cancellation and a
  lost reply, including whether later callers recover the original result.
- Keep signed replies for retries in the parent; the enclave keeps none. A
  reply store in the enclave takes enclave memory that the memory model must
  count, and a change to it needs a new image. An identical retry that the
  parent cannot answer reaches the enclave's replay guard.
- Bound and clean up sessions, nonces, cache entries and proxy connections.
  Authentication failures must not exhaust legitimate replay or session state.
  Preserve half-close and EOF behavior in relays.
- Retry only errors the protocol treats as temporary, such as pending
  finality. Malformed or unauthorized requests must not become endless retries.
  Between the enclave and the parent, identify a retryable state by
  `ErrorResponse.code`, not its text. A text or prefix that a caller matches is
  a contract. Find its consumers, including other repositories, before you
  change it.
- A time, memory or size limit can be runtime configuration only if no accepted
  value lets a compromised parent do more than delay or drop a request or
  restart the enclave. Such a limit needs no attestation. Keep values that
  safety depends on in the image, such as the SPV depth, the finality tag, fee
  limits, and the chain, contract and asset pins. A profile or build argument
  must not change the SPV depth or the finality tag.
- A limit that the operator can change needs a runtime check for each relation
  its image value meets, such as a per-call network timeout within the request
  deadline, or the consignment scratch files within the memory margin.

## Schema, ABI and dependency changes

- Follow `enclave-proto/README.md`: change and generate the schema upstream,
  then sync both the schema and generated Rust with their provenance.
  Updating only `enclave.proto` does not change compiled types.
- Keep the parent's upstream proto revision, vendored hashes, both lockfiles
  and compatibility tests aligned. Preserve fields through every adapter.
  Test unknown enum values, missing required data and cross-route replies.
- A repeated field in a request message must be reachable by the request shape
  check: `enclave/src/framing.rs` for the enclave wire,
  `parent/src/request_shape.rs` for the parent gRPC API.
- Do not renumber or repurpose wire fields, change canonical encodings or
  move key derivation paths without an explicit compatibility and rollout plan.
  Document exact hash formulas, domain tags, field widths and order, byte order
  and shared test vectors; a type name alone is not a format definition.
- Check dependency changes for behavior, ABI and schema changes, not just
  compilation. An RGB schema change can require a new asset and a redemption
  or migration plan for existing holders.
  Check Rust requirements and native-library compatibility between builder
  and runtime images too; a successful link does not prove the binary starts.
- Keep the root `[patch.crates-io]` at the crates and revs of the pinned
  rgb-lib's own patches. Cargo ignores a dependency's patches, so another rev
  can change the RGB consensus code the enclave runs.
- Keep the root and parent dependency patches and release profiles aligned
  where they intentionally match. Update related fixtures, schema IDs,
  scanners, CI helpers and docs together.
- Pin build inputs through the repository's manifests and lockfiles. Do not
  restore obsolete APIs or optional bypasses to make an upgrade compile.
  Keep security exceptions narrow, documented and attributable to the
  dependency that still requires them.

## Reproducible builds and deployment

- Preserve the pinned Rust toolchain, locked dependencies, base-image digests,
  package snapshots, build timestamps, path remapping and committed generated
  code used for EIF builds. Changes to these inputs can change measurements.
- Do not restore a tool or input of a measured build from a CI cache. Pin a
  tool cloned from Git to its commit, not only its tag.
- A measured value reaches an image only through a recipe default, a named
  profile or a named release input. A variable in the caller's environment, such
  as `RUST_LOG`, must not change the image.
- Keep build credentials in temporary secret mounts or scoped credential
  helpers. Do not place them in URLs, build arguments, layers or artifacts.
  Keep parent-only private dependencies out of enclave resolution.
- Public reproducibility needs accessible source and recorded non-secret build
  inputs. Do not claim a build is public or credential-free while required
  dependencies remain private. Report that limitation.
- Keep infrastructure identifiers such as account IDs, bucket names and instance
  IDs out of this public repository. Read them from repository variables or
  secrets, or from the environment outside CI, and use placeholders in examples.
- Record the actual source revision, role/profile, asset and other measured
  inputs, tool versions, image environment, checksums and PCRs with a release.
  Current repository variables are not a record of an older build.
- Keep dev container publishing, EIF building, artifact uploading and live
  deployment distinct. An uploaded artifact is not proof of deployment or
  public availability. Prevent different profiles from sharing an artifact
  name or silently replacing an approved release.
- Validate configuration and required files before changing host services.
  The runtime limits file is not a required file: if a launch cannot apply it,
  the enclave keeps the image values, because a limit only refuses or delays
  work. The launch must report that case.
  Require the launch policy and the complete approved identity map before
  routing traffic. Liveness checks and partial bundle exports are insufficient.
  Check host and allocator capacity before stopping working enclaves.
  Distinguish measured usable memory from requested memory and estimates.
  A deploy for one vsock CID must not touch the services of another CID.
- A host script that runs as root must not run, read, chmod or chown a path the
  service user controls. Do that step as the service user.
- Preserve TLS/ACL rules and transport timeouts on clients as well as servers.
  Keep error classes, CLI exit codes and retry behavior consistent.
- For changed measurements, identify required release approvals and updates to
  verifier expectations or KMS policy. For runtime-only changes, avoid
  introducing a rebuild requirement.
- Treat workflow inputs, PR content and downloaded artifacts as untrusted.
  Apply trust checks to every trigger, including manual dispatch. Do not
  expose secrets, write tokens or private build artifacts to untrusted PR
  code or fork-readable caches. Keep privileged action inputs pinned and shell
  arguments quoted. Pass untrusted values to scripts through `env`, not as
  `${{ }}` text. Do not relax TLS, authentication or release feature guards to
  make CI pass.

## Tests and validation

Use the target branch's [CI workflow](.github/workflows/ci.yml) for the supported
feature matrix and setup. Use the pinned toolchain. The root and parent
workspaces need separate checks.

Common checks, from the repository root:

```sh
cargo fmt --all -- --check
cargo fmt --all --manifest-path parent/Cargo.toml -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --manifest-path parent/Cargo.toml --all-targets -- -D warnings
cargo test --workspace
cargo test --manifest-path parent/Cargo.toml
python3 -m unittest discover -s build/tests -v
python3 -m unittest discover -s deploy/lambda/sns-to-slack -v
```

Run the checks relevant to the change. For role-specific work, also run the
matching mint/burn feature sets and release checks from CI; default-feature
tests alone are insufficient. Use `--no-default-features` when selecting a
production role. Do not combine mutually exclusive features with
`--all-features`.

- Confirm that CI actually runs new tests under their required features and
  cfgs. Compiling a test or using a filter that matches zero tests is not
  coverage. A negative compile check must fail on the intended guard, not on
  an unrelated missing dependency.
- Keep a release-only runtime refusal testable. Pass the build mode in as an
  input, as `BuildContext` does. Unit tests do not compile code behind
  `not(test)`, and debug test runs do not compile code behind
  `not(debug_assertions)`.
- A regression test must reach the affected production call path, exercise the
  reported failure and fail if the check is removed. Start from a valid fixture
  and change the one property under test so an earlier error cannot hide a bug.
- Use real RGB/BFA and PSBT fixtures where parser, consensus or custody behavior
  matters. Synthetic boundary tests complement them; a mock consensus flag
  does not establish real validation.
- Use independent contract/protocol vectors for selectors, hashes, encodings
  and identifiers. Do not use the implementation under test to manufacture
  both the input and the expected answer.
- Cover missing data, wrong role/network/identity, malformed input, overflow,
  boundary values, reordered or duplicate records, dependency failures,
  concurrency and retry behavior where relevant.
- Exercise public CLI and transport paths for error codes, policy checks,
  timeouts and secret redaction. Include real-format attestation fixtures
  and release compile guards where the change touches them.
- For endpoint work, show that key rotation and independently approved member
  endpoints use an unchanged EIF, while wrong host, CA, chain and policy fail.
- Preserve existing regression tests when rebasing, merging or moving modules.
  Do not delete an assertion, ignore a test or weaken a fixture to resolve a
  conflict. Reconcile the intended rule and test the result.
- For measured build changes, validate the build and reported measurements.
  For docs-only changes, check links, commands and statements against the
  current tree; do not claim runtime behavior was tested.
- Report checks actually run, their results, and any missing dependencies or
  hardware. Mock, local, hardware and deployed checks are different evidence.

## Before opening or updating a PR

- Review the whole final diff, including comments, docs, generated provenance,
  manifests, lockfiles, feature gates and scripts.
- Confirm that the spec, implementation, tests and deployment instructions
  describe the same behavior, or clearly identify the remaining gap.
- Lead the PR description with the concrete problem and resulting behavior.
  Include relevant tests, trust or compatibility changes and rollout needs.
- Cite related issues or PRs in the PR description, not in the tree, where
  they explain the requirement. Do not keep stale titles, descriptions or
  claims from an earlier version of the work.
- State what remains unimplemented or unverified. Do not claim that guidance,
  a passing mock test or an attestation alone fixes a deployment.
