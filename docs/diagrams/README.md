# Diagrams

Views of the implementation described in [the spec](../tee-spec.md), reviewed
2026-10-02. For the two production flows, read the text first:
[mint flow](../mint-flow.md) and [burn flow](../burn-flow.md). Each file contains Mermaid source for a Mermaid-capable Markdown
viewer. Signing sequences describe production validation; dev-only bypasses
are not authorization guarantees.

| File | What it shows |
|---|---|
| [`01-components.md`](01-components.md) | Crate-level component structure across `enclave`, `parent`, `attestation-verify`, and the external infrastructure (NSM, Electrum, vsock-proxy). |
| [`02-deployment.md`](02-deployment.md) | Deployment (stage layout, `deploy/deploy-host.sh`): Orchestrator -> EC2 (parent) -> Nitro Enclave -> vsock-proxy -> Electrum and EVM RPC, with trust zones. |
| [`03-seq-sign-evm.md`](03-seq-sign-evm.md) | **Burn** (RGB → EVM) on the burn signer: mint-ancestry deposits, RGB validation, SPV gate, calldata checks, release-to-burn binds (pools route), BtcRelay proof, EIP-712 signature. |
| [`04-seq-sign-psbt.md`](04-seq-sign-psbt.md) | **Mint** (EVM → RGB) on the mint signer, in code order: replay precheck, deposit receipt, mint ancestry, RGB validation, PSBT bind, fee, recipient, BIP-86 key-path signing on the colored account. |
| [`05-seq-attested-pubkey.md`](05-seq-attested-pubkey.md) | External verifier ↔ enclave attested-pubkey protocol (`attest-verify` CLI, NSM, COSE_Sign1, cert-chain to AWS Nitro root, PCR + nonce + bundle-and-policy commitment). |
| [`06-seq-cloning.md`](06-seq-cloning.md) | Three-message enclave-to-enclave seed cloning (X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + HMAC + PCR equality). |
| [`07-seq-initialize-keys.md`](07-seq-initialize-keys.md) | First-time key initialisation from OS entropy (BIP-39 → BIP-32 → BIP-84/86 derivation). |
| [`08-seq-spv-submit-headers.md`](08-seq-spv-submit-headers.md) | Parent-driven SPV header sync into the in-enclave chain, with bounded-reorg / weaker-chain rejection. |
| [`09-state-phase.md`](09-state-phase.md) | Enclave key-state machine `Phase{Initial, Cloning, Active}` — signing enabled only in `Active`, which is terminal. |
| [`10-signing-gate.md`](10-signing-gate.md) | **Burn** signing gate: each check as a fail-closed decision, with the LayerZero-route gap marked. |

## Editing

Edit the Mermaid block alongside the corresponding Rust handler and spec.
Use a Mermaid-capable preview; plain Markdown renderers show the source block.
