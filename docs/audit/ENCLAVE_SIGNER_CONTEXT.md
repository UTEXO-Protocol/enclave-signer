# enclave-signer Context

`utexo-bridge-enclave-signer` is the **cryptographic root of trust** for the UTEXO
RGB ↔ EVM bridge. It holds one BIP-39 HD seed inside an **AWS Nitro Enclave** (TEE) and
produces signatures in two directions:

- **RGB → EVM (unlock)** — EIP-712 signatures over `fundsOut(...)` calldata authorising
  the `MultisigProxy` contract to release tokens after a validated RGB transfer/burn.
- **EVM → RGB (lock)** — PSBT signatures (taproot script-path + SegWit-v0 P2WSH) that
  finalise the federated Bitcoin transaction returning RGB-coloured UTXOs.

Plus:
- a raw-keccak-then-sign helper with the EIP-191 envelope (`SignRawMessage`, `fundsIn`
  authorisation),
- a **`SignRawDigest`** RPC (added in PR #48, `bd4158a`) that signs an arbitrary 32-byte
  digest with a **dedicated EVM gas-tx key** derived at `m/44'/60'/0'/0/1` — used to
  sign the outer Ethereum transaction that carries the bridge call; security note
  TEE-XC-09 in `cross-flow-findings.md`,
- a not-yet-wired federation-signature proxy.

The hard goal is non-functional: **the parent EC2 host is untrusted.** Operators with
shell on the EC2, network attackers, and a malicious "Go Listener" must not be able to
forge a signature, exfiltrate the seed, or smuggle in a wrong-network / wrong-amount /
replayed payload.

## Trust model

| Actor | Trusted? |
|---|---|
| AWS Nitro hypervisor + NSM (root CA off-machine) | ✅ |
| The compiled enclave binary at a specific PCR0/1/2 | ✅ |
| External verifier's local machine | ✅ |
| Parent EC2 host process | ❌ |
| Go Listener / Orchestrator | ❌ (validated, not trusted) |
| Network between Listener ↔ Parent ↔ Enclave | ❌ |
| Esplora indexer | ❌ (must be authenticated by SPV / RGB validation) |

## Components (enclave crate)

- `server.rs` — handler dispatch + `ServerContext{state, bridge_config, rgb_validator, header_chain}`.
- `state.rs` — `Phase{Initial, Cloning, Active(KeyManager)}` + `NonceReplayGuard`.
- `keys.rs` — BIP-39/32/44'/84'/86' derivation (EVM auth `m/44'/60'/0'/0/0`, **EVM gas-tx `m/44'/60'/0'/0/1`**, BTC legacy `m/84'/0'/0'/0/0`, BIP-86 vanilla/colored); `sign_evm`, `sign_evm_gas_tx`, `sign_psbt`.
- `signing/` — `evm.rs` (EIP-712), `psbt.rs` (P2WSH), `taproot.rs` (BIP-341 script-path), all anchored to `witness_utxo.script_pubkey`.
- `validation/` — `evm_crosscheck.rs`, `psbt_crosscheck.rs`, `rgb.rs` (rgbstd + Esplora), `spv_crosscheck.rs`.
- `spv/` — `chain.rs` (HeaderChain, bounded reorg), `checkpoint.rs` (compile-time anchors → PCR0), `merkle.rs`, `validation.rs` (linkage/PoW/nBits), `types.rs`.
- `attestation.rs` / `cloning.rs` — NSM facade + X25519 + HKDF-SHA256 + ChaCha20-Poly1305 handshake.
- `config.rs` — `BridgeConfig` (env-pinned chain_id / bridge_contract / rgb_asset_id, bound into attestation `user_data`).
- `framing.rs` / `main.rs` — length-prefixed protobuf wire (one connection = one request), vsock/TCP listener.
- Shared `attestation-verify` crate — COSE_Sign1 + AWS Nitro cert chain + PCR verification (used by cloning *and* the external `attest-verify` CLI).

## Flows under audit (entry points)

| Flow | Entry point | Docs |
|---|---|---|
| Sign EVM (`fundsOut` unlock) | `handle_sign_evm` | `step 1/2 - sign_evm.md` |
| Cloning handshake | `handle_initiate/get/set_clone` | `step 1/2 - cloning.md` |
| Sign PSBT (RGB lock) | `handle_sign_psbt` | `step 1/2 - sign_psbt.md` |
| SubmitHeaders (SPV sync) | `handle_submit_headers` (+ `GetLastSavedBlock`) | `step 1/2 - submit_headers.md` |
| Attested public key | `handle_get_attested_public_key` + `attest-verify` CLI | `step 1/2 - attested_pubkey.md` |
| Initialize keys | `handle_initialize` | `step 1/2 - initialize_keys.md` |

Cross-cutting items (transport/framing/build) and the spec-conformance summary live in
`cross-flow-findings.md`. Minor surfaces not given their own flow: `SignRawMessage`
(TEE-XC-01), **`SignRawDigest`** (new in PR #48 — TEE-XC-09), `GetPublicKey`
(read-only), `ProxyFederation` (stub, NOT_READY).

## Scope & asset assumption

- **In scope:** the TEE validator/signer + its parent adapter, this repo only.
- **Out of scope (separate repo):** the Solidity `Bridge`/`MultisigProxy`/`CommissionManager`/
  `BtcRelay`, the on-chain `burnId` replay consumption and lock-record check (spec Sec 8/11),
  and the M-of-N federation quorum. The TEE is **one signer**; end-to-end severity for
  several findings depends on the on-chain quorum + lock-record (tracked as Layer-2).
- **Asset:** the production EVM-side bridged token is **USDT0**; the RGB side is the
  bridge's IFA-schema RGB asset (pinned as `RGB_ASSET_ID`). Amount checks assume a 1:1
  RGB-unit ↔ USDT0-unit mapping. Do not introduce fee-on-transfer/rebasing/malicious-token
  invariants for the normal flow.

## Build / feature posture

- **Production:** `--features spv,rgb-validation` (`spv` implies `rgb-validation`).
- **Must NOT ship in release:** `dev-mode` (skips all cross-checks), `mock-attestation`
  (zero-PCR docs), `allow-seed-import` (chosen-seed import). None currently has a
  `compile_error!` release guard — see TEE-IK-01 / TEE-CL-02 in `cross-flow-findings.md`.
- PCR0/1/2 are pinned at build time from `build/Dockerfile.enclave`; any source change →
  different PCRs → external verifiers reject.

## Key design choices (and why)

1. **One-shot, length-prefixed protobuf wire** — one connection = one request = one response = close. No framing ambiguity, minimal attack surface.
2. **Authorisation anchored to the on-chain commitment** (`witness_utxo.script_pubkey`), never to coordinator hint fields (`bip32_derivation`, `tap_key_origins`). Adversarially tested.
3. **In-enclave RGB validation** (`rgbstd` + Esplora resolver) — the listener's `consignment_valid` boolean is not trusted.
4. **In-enclave SPV** anchored at a compile-time checkpoint (so checkpoint bytes are in PCR0); coverage + depth + chain-net + staleness gates.
5. **Fail-closed on build/feature skew** — if a request carries `merkle_proofs[]` but the binary lacks `spv`, refuse.
6. **Attested-pubkey protocol** — fresh-nonce challenge-response; COSE_Sign1 binds `{evm_uncompressed_pub, sha256(canonical_bundle)}` to the PCRs.
7. **Cloning** — same-PCR-only seed transfer via X25519 → HKDF-SHA256 → ChaCha20-Poly1305, HMAC(cloning_secret, pubkey) authorisation, fresh ephemeral key per session.
8. **State machine** — `Initial → Active` (entropy / cloning) is one-shot; `Active` is terminal (no re-init, no rotation in place).
