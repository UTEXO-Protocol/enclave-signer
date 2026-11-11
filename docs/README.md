# Documentation

Start with the flow that you work on. Then use the reference for the topic at
hand.

## Understand the signer

| Document | What it gives |
|----------|---------------|
| [mint-flow.md](mint-flow.md) | How the mint signer checks and signs a mint (EVM -> RGB), check by check. Also plain-BTC signing and the rights refill. |
| [burn-flow.md](burn-flow.md) | How the burn signer checks and signs a release (RGB -> EVM), check by check. Also the gas transaction. |
| [tee-spec.md](tee-spec.md) | The specification: trust model, architecture, security policy, keys, requests, SPV rules and known limits. |
| [diagrams/](diagrams/README.md) | The same paths as Mermaid diagrams, in code order. |

## Integrate with it

| Document | What it gives |
|----------|---------------|
| [burn-destination.md](burn-destination.md) | The format of the destination that a burn names, with test vectors. |
| [tee-spec.md, section 6](tee-spec.md#6-requests) | The enclave requests and the error codes. |
| [enclave-proto/README.md](../enclave-proto/README.md) | Where the wire schema comes from, and how to sync it. |

## Verify a signer

| Document | What it gives |
|----------|---------------|
| [verify-a-signer.md](verify-a-signer.md) | How anyone checks a published attestation bundle and the on-chain signer list. |
| [pubkey-attestation.md](pubkey-attestation.md) | What an attestation proves, the exact encodings and the `attest-verify` CLI. |

## Run it

| Document | What it gives |
|----------|---------------|
| [building.md](building.md) | Build the binaries and the enclave image. Reproducible measurements. The stage Signet profile is in [build/profiles/README.md](../build/profiles/README.md). |
| [github-releases.md](github-releases.md) | Publish a verified Stage Signet build and its PCRs for cosigners. |
| [configuration.md](configuration.md) | The settings: image settings, launch values, parent settings. |
| [operations.md](operations.md) | Launch, launch check, readiness, restart. |
| [runtime-limits.md](runtime-limits.md) | The limits that an operator can change on a running enclave. |
| [parent-mtls.md](parent-mtls.md) | mTLS, client roles, and every path into the enclave. |
| [kms-persistence.md](kms-persistence.md) | Seed custody of the mint signer, with AWS KMS and S3. |
| [cloning.md](cloning.md) | Seed cloning between burn signers. |

## Maintain it

| Document | What it gives |
|----------|---------------|
| [validation-cost-model.md](validation-cost-model.md) | The model and the measurements behind the work caps of the burn signer. |
| [AGENTS.md](../AGENTS.md) | The repository rules for a change. |

## Conventions

- **One home for each fact.** A rule, a value or a limit is stated in one
  document. The other documents link to it.
- **Values.** A runtime limit has its value in
  [runtime-limits.md](runtime-limits.md), and a setting in
  [configuration.md](configuration.md). A protocol constant has its value in
  the flow or the specification section that defines it. Elsewhere a document
  names the setting or the constant.
- **Current behavior only.** A document says what the code does now. It tells
  no history and no plan.
- **Rule ids are stable.** The code cites ids such as `M6`, `PP1`, `RR10`
  and `P6`. Keep an id with its rule when you edit a document. The code also
  cites sections 5, 6, 8 and 11 of [mint-flow.md](mint-flow.md) by number.
