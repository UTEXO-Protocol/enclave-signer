# Diagrams

Views of the implementation described in [the spec](../tee-spec.md), reviewed
2026-09-08. Each file contains Mermaid source for a Mermaid-capable Markdown
viewer. Signing sequences describe production validation; dev-only bypasses
are not authorization guarantees.

| File | What it shows |
|---|---|
| [`01-components.md`](01-components.md) | Crate-level component structure across `enclave`, `parent`, `attestation-verify`, and the external infrastructure (NSM, Esplora, vsock-proxy). |
| [`02-deployment.md`](02-deployment.md) | Production deployment: Orchestrator → EC2 (parent) → Nitro Enclave → vsock-proxy → Esplora, with trust zones called out. |
| [`03-seq-sign-evm.md`](03-seq-sign-evm.md) | `fundsOut` signing path (RGB → EVM unlock) via the unified `Sign` request: in-enclave RGB validation, SPV gate, canonical-ABI destination checks, BtcRelay proof anchoring, fundsOut binding, typed EIP-712 signature. |
| [`04-seq-sign-psbt.md`](04-seq-sign-psbt.md) | Bridge PSBT path (EVM → RGB): provider-based deposit verification, consignment anchoring with per-output legs and the invoice recipient bind, fee sanity, then taproot script-path (Schnorr) signing scoped to the colored account. Plain-BTC signing is the separate `SignBtc` request. |
| [`05-seq-attested-pubkey.md`](05-seq-attested-pubkey.md) | External verifier ↔ enclave attested-pubkey protocol (`attest-verify` CLI, NSM, COSE_Sign1, cert-chain to AWS Nitro root, PCR + nonce + bundle-and-policy commitment). |
| [`06-seq-cloning.md`](06-seq-cloning.md) | Three-message enclave-to-enclave seed cloning (X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + HMAC + PCR equality). |
| [`07-seq-initialize-keys.md`](07-seq-initialize-keys.md) | First-time key initialisation from OS entropy (BIP-39 → BIP-32 → BIP-84/86 derivation). |
| [`08-seq-spv-submit-headers.md`](08-seq-spv-submit-headers.md) | Listener-driven SPV header sync into the in-enclave chain, with bounded-reorg / weaker-chain rejection. |
| [`09-state-phase.md`](09-state-phase.md) | Enclave key-state machine `Phase{Initial, Cloning, Active}` — signing enabled only in `Active`, which is terminal. |
| [`10-signing-gate.md`](10-signing-gate.md) | `fundsOut` signing gate: TEE validation predicates as a fail-closed decision flow, with per-flow amount rules. |

## Editing

Edit the Mermaid block alongside the corresponding Rust handler and spec.
Use a Mermaid-capable preview; plain Markdown renderers show the source block.
