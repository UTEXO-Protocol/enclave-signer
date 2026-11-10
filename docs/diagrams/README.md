# Diagrams

Views of the implementation that [the specification](../tee-spec.md)
describes, reviewed 2026-11-02. They do not prove the deployed configuration.
For the two flows, read the text first: [mint flow](../mint-flow.md) and
[burn flow](../burn-flow.md). The signing sequences show production
validation; a dev-only bypass is not an authorization guarantee.

| File | What it shows |
|---|---|
| [`01-components.md`](01-components.md) | Crate-level component structure across `enclave`, `parent`, `attestation-verify`, and the external infrastructure (NSM, Electrum, vsock-proxy). |
| [`02-deployment.md`](02-deployment.md) | Deployment (stage layout, `deploy/deploy-host.sh`): Orchestrator -> EC2 (parent) -> Nitro Enclave -> vsock-proxy -> Electrum, EVM RPC and KMS (mint), with trust zones. |
| [`03-seq-sign-evm.md`](03-seq-sign-evm.md) | **Burn** (RGB -> EVM) on the burn signer: mint-ancestry deposits, RGB validation, SPV gate, calldata checks, release-to-burn binds (both routes), BtcRelay proof, EIP-712 signature. |
| [`04-seq-sign-psbt.md`](04-seq-sign-psbt.md) | **Mint** (EVM → RGB) on the mint signer, in code order: role check, replay precheck, deposit receipt, the fascia core (F1-F6), mint rules (M1-M5, M7), F7 key path, parent proof (PP1-PP7), fee, M8 sats, M6 deposit bind, recipient, Taproot key-path signing on the colored BIP-86 account. No consignment. |
| [`05-seq-attested-pubkey.md`](05-seq-attested-pubkey.md) | External verifier ↔ enclave attested-pubkey protocol (`attest-verify` CLI, NSM, COSE_Sign1, cert-chain to AWS Nitro root, PCR + nonce + bundle-and-policy commitment). |
| [`06-seq-cloning.md`](06-seq-cloning.md) | Three-message enclave-to-enclave seed cloning (X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + HMAC + PCR equality). Builds without `kms-persistence` only. |
| [`07-seq-initialize-keys.md`](07-seq-initialize-keys.md) | First-time key initialization from OS entropy (BIP-39 → BIP-32 → BIP-44/86 derivation). Builds without `kms-persistence` only. |
| [`08-seq-spv-submit-headers.md`](08-seq-spv-submit-headers.md) | Parent-driven SPV header sync into the in-enclave chain, with bounded-reorg / weaker-chain rejection. |
| [`09-state-phase.md`](09-state-phase.md) | Enclave key-state machine `Phase{Initial, Initializing, Cloning, Active}` (`Initializing` only with `kms-persistence`). Signing is enabled only in `Active`, which is terminal. |
| [`10-signing-gate.md`](10-signing-gate.md) | **Burn** signing gate: each check as a fail-closed decision, on both release routes (`fundsOut`, `lzFundsOut`). |

## Editing

- Edit a Mermaid block together with its Rust handler and the document that
  states the rule.
- Name a setting or a limit; do not write its value. The values are in
  [configuration.md](../configuration.md) and
  [runtime-limits.md](../runtime-limits.md).
- Do not put a raw semicolon in a sequence-diagram message or note: it ends
  the message, and the block does not parse. Use a comma, or write `#59;`.
- Check the result in a viewer that renders Mermaid. A plain Markdown viewer
  shows only the source.
