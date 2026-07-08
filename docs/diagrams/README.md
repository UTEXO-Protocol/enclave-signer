# Diagrams

Architecture / sequence / state / flow diagrams referenced from
[`docs/audit/ENCLAVE_SIGNER_CONTEXT.md`](../audit/ENCLAVE_SIGNER_CONTEXT.md) and
[`docs/tee-spec.md`](../tee-spec.md).

Mermaid in Markdown — GitHub, GitLab, VS Code, and most modern Markdown renderers
display these inline; no separate render step.

| File | What it shows |
|---|---|
| [`01-components.md`](01-components.md) | Crate-level component structure across `enclave`, `parent`, `attestation-verify`, and the external infrastructure (NSM, Esplora, vsock-proxy). |
| [`02-deployment.md`](02-deployment.md) | Production deployment: Orchestrator → EC2 (parent) → Nitro Enclave → vsock-proxy → Esplora, with trust zones called out. |
| [`03-seq-sign-evm.md`](03-seq-sign-evm.md) | EIP-712 signing path (RGB → EVM unlock): build-skew guard, in-enclave RGB validation, cross-checks, SPV gate, signature. |
| [`04-seq-sign-psbt.md`](04-seq-sign-psbt.md) | PSBT signing path (EVM → RGB lock): bridge-mode authorisation (independent FundsIn verification #60/#77, consignment binding), then taproot script-path (Schnorr) + SegWit v0 P2WSH (ECDSA), both anchored to `witness_utxo.script_pubkey`. |
| [`05-seq-attested-pubkey.md`](05-seq-attested-pubkey.md) | External verifier ↔ enclave attested-pubkey protocol (`attest-verify` CLI, NSM, COSE_Sign1, cert-chain to AWS Nitro root, PCR + nonce + bundle commitment). |
| [`06-seq-cloning.md`](06-seq-cloning.md) | Three-message enclave-to-enclave seed cloning (X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + HMAC + PCR equality). |
| [`07-seq-initialize-keys.md`](07-seq-initialize-keys.md) | First-time key initialisation from OS entropy (BIP-39 → BIP-32 → BIP-84/86 derivation). |
| [`08-seq-spv-submit-headers.md`](08-seq-spv-submit-headers.md) | Listener-driven SPV header sync into the in-enclave chain, with bounded-reorg / weaker-chain rejection. |
| [`09-state-phase.md`](09-state-phase.md) | Enclave key-state machine `Phase{Initial, Cloning, Active}` — signing enabled only in `Active`, which is terminal. |
| [`10-signing-gate.md`](10-signing-gate.md) | `fundsOut` signing gate: TEE validation predicates as a fail-closed decision flow, with status annotations. |

## Editing

Edit the Mermaid code block inside each `.md`. Live-preview with the Markdown
preview in your editor (VS Code's built-in preview, or any Mermaid-capable viewer),
or by opening the file on GitHub. Migrated from PlantUML on 2026-06-01.
