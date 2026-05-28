# Diagrams

PlantUML sources for the architecture / sequence diagrams referenced in
[`docs/audit/ENCLAVE_SIGNER_CONTEXT.md`](../audit/ENCLAVE_SIGNER_CONTEXT.md).

| Source                                                             | Rendered (SVG / PNG)                                            | What it shows                                                                                                                                                          |
|--------------------------------------------------------------------|-----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`01-components.puml`](01-components.puml)                         | [svg](components.svg) | [png](components.png)                   | Crate-level component structure across `enclave`, `parent`, `attestation-verify`, and the external infrastructure they touch (NSM, Esplora, vsock-proxy).              |
| [`02-deployment.puml`](02-deployment.puml)                         | [svg](deployment.svg) | [png](deployment.png)                   | Production deployment: Orchestrator host -> EC2 (parent) -> Nitro Enclave (enclave + RGB validator + header chain) -> vsock-proxy -> Esplora, with trust zones called out. |
| [`03-seq-sign-evm.puml`](03-seq-sign-evm.puml)                     | [svg](seq-sign-evm.svg) | [png](seq-sign-evm.png)               | EIP-712 signing path (RGB -> EVM unlock): build-skew guard, in-enclave RGB validation, cross-checks, SPV gate, signature.                                               |
| [`04-seq-sign-psbt.puml`](04-seq-sign-psbt.puml)                   | [svg](seq-sign-psbt.svg) | [png](seq-sign-psbt.png)             | PSBT signing path (EVM -> RGB lock): taproot script-path (Schnorr) + SegWit v0 P2WSH (ECDSA), both anchored to `witness_utxo.script_pubkey`.                            |
| [`05-seq-attested-pubkey.puml`](05-seq-attested-pubkey.puml)       | [svg](seq-attested-pubkey.svg) | [png](seq-attested-pubkey.png) | External verifier <-> enclave attested-pubkey protocol (`attest-verify` CLI, NSM, COSE_Sign1, cert-chain to AWS Nitro root, PCR + nonce + bundle commitment).            |
| [`06-seq-cloning.puml`](06-seq-cloning.puml)                       | [svg](seq-cloning.svg) | [png](seq-cloning.png)                 | Three-message enclave-to-enclave seed cloning (X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + HMAC + PCR equality).                                                        |
| [`07-seq-initialize-keys.puml`](07-seq-initialize-keys.puml)       | [svg](seq-initialize-keys.svg) | [png](seq-initialize-keys.png) | First-time key initialisation from OS entropy (BIP-39 -> BIP-32 -> BIP-84/86 derivation).                                                                                |
| [`08-seq-spv-submit-headers.puml`](08-seq-spv-submit-headers.puml) | [svg](seq-submit-headers.svg) | [png](seq-submit-headers.png)   | Listener-driven SPV header sync into the in-enclave chain, including bounded-reorg / weaker-chain rejection.                                                           |
| [`09-state-phase.puml`](09-state-phase.puml)                       | [svg](state-phase.svg) | [png](state-phase.png)                 | Enclave key-state machine `Phase{Initial, Cloning, Active}` -- signing enabled only in `Active`, which is terminal.                                                     |
| [`10-signing-gate.puml`](10-signing-gate.puml)                     | [svg](signing-gate.svg) | [png](signing-gate.png)               | `fundsOut` signing gate: the TEE validation predicates (P1-P11) as a fail-closed decision flow, with current gaps annotated.                                           |

> Output filenames come from the `@startuml <name>` token inside each source, not the `NN-` filename prefix.

## Rendering

```bash
# Install once
brew install plantuml

# Re-render all (SVG + PNG already committed alongside the sources)
plantuml -tsvg docs/diagrams/*.puml
plantuml -tpng docs/diagrams/*.puml
```

Or paste the source into <https://www.plantuml.com/plantuml> for a one-off render.
