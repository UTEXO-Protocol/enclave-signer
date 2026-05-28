# UTEXO Bridge Enclave-Signer -- Project Review

_Date: 2026-05-24 -- refreshed 2026-05-28 against HEAD `c51d6fb`_

> **Refresh note (2026-05-28).** Five PRs landed on `dev` after the original
> review (#40, #42, #43, #44, #47). Their effect on the findings below is
> recorded inline with **[RESOLVED]** / **[PARTIAL]** / **[OPEN]** banners.
> Headline: the two host-trust gaps that mattered most for funds theft are
> closed -- the `consignment_valid` bypass (#47) and the host-supplied burn
> amount (#44/#47, amount now bound to the validated consignment). The EIP-712
> domain name/version (#2 of the top-line list) is **still open**. Line numbers
> in finding headers are as-of the original review unless a banner says otherwise.

## Part 1 -- Goal & Solution Architecture

### Goal

`utexo-bridge-enclave-signer` is the cryptographic root of trust for the **UTEXO RGB <-> EVM bridge**. It holds a single BIP-39 HD seed inside an **AWS Nitro Enclave** (TEE) and produces signatures for two directions:

- **RGB -> EVM (unlock direction)**: EIP-712 typed-data signatures over `fundsOut(...)` calldata that authorise a `MultisigProxy` contract on an EVM chain to release tokens once a corresponding RGB transfer has been validated.
- **EVM -> RGB (lock direction)**: PSBT signatures (taproot script-path + segwit-v0 P2WSH) that finalise the federated Bitcoin transaction returning RGB-coloured UTXOs.

Plus a raw-keccak-then-sign helper for `fundsIn` authorisation and a not-yet-wired federation-signature proxy.

The non-functional goal is harder than the functional one: **the parent EC2 host is untrusted**. Operators with shell on the EC2, network attackers, and a malicious "Go Listener" must not be able to forge a signature, exfiltrate the seed, or smuggle in a wrong-network / wrong-amount / replayed payload.

### Trust model

| Actor                                              | Trusted?                                                       |
|----------------------------------------------------|----------------------------------------------------------------|
| AWS Nitro hypervisor + NSM (root CA off-machine)   | [OK]                                                           |
| The compiled enclave binary at a specific PCR0/1/2 | [OK]                                                           |
| Verifier's local machine                           | [OK]                                                           |
| Parent EC2 host process                            | [NO]                                                           |
| Go Listener / Orchestrator                         | [NO] (validated, not trusted)                                  |
| Network between Listener <-> Parent <-> Enclave    | [NO]                                                           |
| Esplora indexer                                    | [NO] (responses must be authenticated by SPV / RGB validation) |

### Components

```
        +-----------------------------------------------------------------+
        | Go federated-signer-node (Listener)                             |
        |  - receives signing intents from Orchestrator                   |
        |  - enriches with EVM logs + RGB consignment + SPV proofs        |
        |  - issues gRPC EnclaveService.Sign / PublicKey / SubmitHeaders  |
        +-------------------------------+---------------------------------+
                                        |  gRPC (parentadapter.proto)
   +------------------------------------v--------------------------------+
   | EC2 host  (UNTRUSTED)                                               |
   |                                                                     |
   |  utexo-bridge-parent  (tonic gRPC, 127.0.0.1)                       |
   |   - thin translator: gRPC -> enclave wire protocol                  |
   |   - drives cloning handshake (3 round-trips)                        |
   |   - 30s timeout, spawn_blocking around TCP/vsock I/O                |
   |                                                                     |
   |  utexo-bridge-parent-cli      attest-verify CLI                     |
   |                                                                     |
   |  vsock-proxy : 8001 -> Esplora API   (out-of-enclave network)       |
   |                                                                     |
   |  +----------------------------------------------------------------+ |
   |  | AWS Nitro Enclave  (TRUSTED, PCR-pinned)                       | |
   |  |                                                                | |
   |  |  utexo-bridge-enclave                                          | |
   |  |   - one TCP/vsock connection = one length-prefixed protobuf    | |
   |  |     request -> one response (single-threaded accept loop)       | |
   |  |                                                                | |
   |  |   server.rs   -- handler dispatch                               | |
   |  |   state.rs    -- Phase {Initial, Cloning, Active(KeyManager)}   | |
   |  |                 + nonce replay guard                           | |
   |  |   keys.rs     -- BIP-39/32/84/86 derivation; sign_evm,sign_psbt | |
   |  |   signing/    -- EIP-712, P2WSH segwit-v0, taproot script-path  | |
   |  |   validation/ -- evm_crosscheck, psbt_crosscheck, rgb, spv      | |
   |  |   spv/        -- header chain + checkpoint + merkle verifier    | |
   |  |   attestation.rs / cloning.rs -- NSM + X25519+HKDF+CCP handshake| |
   |  |   vsock_forwarder.rs -- localhost:3443 -> vsock CID 3:8001       | |
   |  |                                                                | |
   |  |  External verifier surface:                                    | |
   |  |   GetAttestedPublicKey(nonce) -> bundle + COSE_Sign1 doc        | |
   |  |     binding {pubkey, sha256(bundle)} to PCRs                   | |
   |  +----------------------------------------------------------------+ |
   +---------------------------------------------------------------------+
```

### Key design choices (and why they matter)

1. **Wire is one-shot, length-prefixed protobuf.** No framing ambiguity, no pipelining. Each connection => one request => one response => close. Drastically reduces attack surface.
2. **Anchor PSBT signing to the on-chain commitment** (`witness_utxo.script_pubkey`), not to coordinator hint fields (`bip32_derivation`, `tap_key_origins`). Both signing paths (`signing/psbt.rs`, `signing/taproot.rs`) check `sha256(witness_script) == p2wsh_program` and `control_block.verify_taproot_commitment(...) == output_key` *before* trusting any hint. Adversarial PSBT tests are in-tree.
3. **In-enclave RGB validation**: `validation/rgb.rs` deserialises the `Transfer`, builds an Esplora resolver (over the vsock forwarder), and runs `rgbstd`'s full validation pipeline inside the TEE. The Listener's `consignment_valid` boolean is no longer trusted on its own.
4. **In-enclave SPV**: `spv/chain.rs` keeps an in-memory header chain anchored at a compile-time `Checkpoint` (so checkpoint bytes end up in PCR0). `validation/spv_crosscheck.rs` requires (a) set-equality between consignment witness txids and supplied Merkle proofs, (b) >=6 confirmations for each, (c) chain-net match, (d) tip-not-stale (<=2h old).
5. **Fail-closed on feature mismatch**: if the binary was built without `--features spv` but a request carries `merkle_proofs[]`, `handle_sign_evm` rejects. Catches the "Listener upgraded, enclave didn't" footgun.
6. **Attested-pubkey protocol** (`docs/pubkey-attestation.md`): external verifier sends a 32-byte nonce; enclave responds with a `PublicKeysResponse` plus a COSE_Sign1 NSM doc whose `public_key` = `evm_uncompressed_pub` and `user_data` = `sha256(canonical_bundle)`. The shared `attestation-verify` crate is the single source of truth for both peer-attestation (in the cloning handshake) and external verifier (`attest-verify` CLI).
7. **Cloning handshake** for cluster bring-up of additional enclaves with the same seed: three messages relayed by the parent, using **X25519(ephemeral) -> HKDF-SHA256 -> ChaCha20-Poly1305**, with PCR-match and **HMAC(cloning_secret, encryption_pubkey)** binding to authorise the request. The fresh ephemeral key per session is what makes the fixed all-zero nonce safe.
8. **State machine**: `Phase::{Initial -> Active}` or `Initial -> Cloning -> Active`. Re-initialisation from `Active` is rejected. `Initial -> Active` happens only via `InitializeKey` (entropy) or via the gated cloning path; raw seed/mnemonic import requires the `allow-seed-import` feature, which is disabled in production builds.

---

## Part 2 -- Security & Architecture Code Review

Severity legend: **C**ritical | **H**igh | **M**edium | **L**ow | **I**nfo. "Critical" = signature-forge or seed-leak; "High" = bypass of a cross-check or strong DoS; "Medium" = robustness, lurking footgun, or hardening gap; "Low" = nits with safety relevance; "Info" = observation.

---

### Cryptography, key management & signing

#### [M] Master fingerprint is computed from the master xpriv (`keys.rs:98`)

`master.fingerprint(&secp)` returns the fingerprint of the **master** key, but BIP-32 cosigners conventionally identify themselves by the **account-level** fingerprint when participating in multisig descriptors. The current code happens to work because `find_taproot_sign_jobs` compares against the same value the enclave reports, and the resolve-path-and-rederive check (`taproot.rs:97-105`) makes mis-identification harmless. Still, anyone wiring an external descriptor from `master_fingerprint()` and a BIP-86 child path will get a non-standard descriptor. *Fix:* document this explicitly in `KeyManager::master_fingerprint()` and `PublicKeysResponse.master_fingerprint`, or compute the account fingerprint instead.

#### [M] EIP-712 domain has hard-coded `name = "Tricorn"`, `version = "1"` (`server.rs:493`)

If the deployed `MultisigProxy` contract ever uses a different name/version, the digest mismatch is silent -- `ecrecover` simply returns the wrong address and the contract rejects. There is a TODO at `signing/evm.rs:3` admitting this isn't yet aligned with the contract team. *Fix:* take name/version from `SignEvmRequest` (cross-check against an enclave-side allowlist), or at minimum add an integration test that derives the digest using the Solidity contract's `_hashTypedDataV4` and asserts byte-for-byte equality.

> **[OPEN] still unaddressed (2026-05-28).** `build_evm_domain` (now `server.rs:552-557`) still hardcodes `name = "Tricorn"`, `version = "1"`. #43 pinned `chain_id` / bridge contract / `rgb_asset_id` from env and bound them into the attestation -- which hardens the *other* two domain fields (`chainId`, `verifyingContract`) -- but the name/version pair was deliberately not touched. This remains item #2 of the top-line list below.

#### [M] `SignRawMessage` is unbounded keccak-then-sign with the EVM key (`server.rs:431-455`)

The handler rejects empty messages but otherwise hashes any bytes and signs with the bridge's primary EVM key. There is **no domain separation**, no length cap (beyond the 4 MB framing limit), no allowlist of `fundsIn`-shaped messages. A future caller -- or a Listener compromise -- could ask the TEE to sign anything that happens to collide with an EIP-712 / EIP-2612 / unsigned-tx hash and obtain a valid signature over an unrelated payload. The proto comment says *"single TEE signature (1-of-n) to prove the smart contract was called through the Tricorn backend"*, but the enclave does not enforce that shape. *Fix:* require a structured prefix (e.g., personal-sign style `"\x19UTEXO Signed Message:\n" || len`) or a typed-data envelope, and gate behind a selector check analogous to `FUNDS_OUT_SELECTORS`.

> **[PARTIAL] #42 (2026-05-26).** `handle_sign_raw_message` (now `server.rs:483-515`) applies the EIP-191 personal-sign envelope -- `keccak256("\x19Ethereum Signed Message:\n" || len || msg)` -- before signing. The `0x19` first byte is disjoint from every Ethereum tx envelope (legacy RLP `0xc0+`, typed `0x01..=0x7f`), so the **transaction-collision half of this finding is closed**: a signature from this RPC can no longer be replayed as a tx signature. A regression test asserts raw-keccak recovery does *not* match. **Still open:** no length cap and no `fundsIn`-shape allowlist -- the RPC will still EIP-191-sign arbitrary bytes. On-chain consumers must hash with the same EIP-191 preimage (OZ `ECDSA.toEthSignedMessageHash`).

#### [M] `sign_evm` produces a raw 65-byte ECDSA without EIP-2 low-S normalisation (`keys.rs:267-279`)

`k256` returns signatures with the canonical low-S already by default for `sign_prehash_recoverable`, so today this is fine -- but it isn't a documented invariant in the code. *Fix:* add an explicit `signature.normalize_s()` (or assert it's already normalised) and a unit test that crafts a forced high-S signature and verifies the enclave returns low-S. EVM contracts that reject high-S would otherwise silently break on a `k256` upgrade that changes defaults.

#### [L] `sign_schnorr_no_aux_rand` is intentional but should be commented for reviewers (`taproot.rs:177`)

Deterministic Schnorr (BIP-340) is correct for an enclave (no need for fresh entropy per signature, easier to test, prevents nonce-reuse if RNG fails). The choice is right, but the rationale is currently implicit. *Fix:* one-line comment "deterministic per BIP-340 Sec 3.4 to avoid RNG dependency inside the enclave."

#### [L] `KeyManager::seed` is held in `SecretBox<[u8; 64]>` but `expose_seed()` returns `&[u8; 64]` (`keys.rs:211`)

The accessor leaks an unwrapped reference; the only current caller (`with_seed` in `state.rs:248`) hands it straight to `cloning::encrypt_seed_for_peer`, which is fine. But the function name + return type would make it tempting to plumb the seed into a logger or error message in a future change. *Fix:* take a closure (`fn with_seed<F: FnOnce(&[u8; 64])>`) like `with_donor_cloning_secret` already does, so the seed reference cannot escape.

#### [L] EVM master fingerprint logged at INFO on every initialise (`server.rs:191-197`)

Fingerprints, addresses, and xpubs are public -- but enclave logs are read by anyone with NSM debug access and routinely pasted into bug reports. Logging the xpubs makes future seed-export bugs easier to triage but the bar is "anything seed-derived" being treated cautiously. *Info:* worth a top-of-file comment in `server.rs` saying which fields are deliberately log-safe, so future contributors know the answer is "only what's already in `PublicKeysResponse`."

#### [I] Strong test coverage of adversarial PSBT shapes (`keys.rs:738-1333`)

The boss's "fabricated `witness_script`" hole, the "sliding-window pubkey match" hole, the "lying `tap_key_origins`" hole, and the "control block from a different tree" hole all have explicit adversarial tests that assert `count == 0`. This is the single most reassuring piece of the codebase -- the signing-authorisation path has been thought about *adversarially*.

---

### Attestation (NSM + COSE + cert chain)

#### [M] Certificate chain validation does not check `BasicConstraints`/`KeyUsage`/`pathLen` (`attestation-verify/src/lib.rs:297-356`)

`verify_certificate_chain` verifies that each cert in the bundle is byte-equal to the embedded root at index 0, signs the next cert, and is within its validity window. It does **not** check `BasicConstraints.cA = true` on intermediates, `keyCertSign` in `KeyUsage`, or `pathLenConstraint`. In practice AWS Nitro's root + intermediates carry these (the root cert visible at `attestation-verify/src/lib.rs:228-241` has `cA:TRUE`, `pathLen:absent`, `keyUsage:keyCertSign,cRLSign`), so the chain we encounter today is well-formed. But a verifier that doesn't *enforce* these is one CA misconfig away from accepting a leaf cert as an intermediate. *Fix:* enforce `BasicConstraints.cA = true` and `KeyUsage.keyCertSign` for every cert except the leaf; reject if `pathLenConstraint` is exceeded.

#### [M] Mock attestation is `--features mock-attestation` on the *enclave* crate (`enclave/Cargo.toml:101`)

If a release build accidentally enables this feature, the enclave will produce raw CBOR docs with all-zero PCRs and `verify_peer_attestation` in the cloning handshake will accept them -- i.e., cloning becomes "any caller in possession of the operator secret can claim to be a TEE." The Dockerfile (`build/Dockerfile.enclave:37`) does not name this feature, so today the production image is safe. *Fix:* add a `compile_error!("mock-attestation must never ship in release")` gated on `not(debug_assertions)` inside `enclave/src/attestation.rs`, similar to `Checkpoint::assert_real_in_release`. Belt-and-braces.

#### [L] PCR comparison and nonce comparison are not constant-time (`attestation-verify/src/lib.rs:183-208`)

`pcrs.get(&idx)... actual.as_slice() != expected_bytes` and `nonce.as_slice() != exp` are vanilla `PartialEq` -- branch-on-first-mismatch. For attestation verification these values are public and the verifier learns the answer anyway, so the timing-leak threat model is weak. *Fix:* swap to `subtle::ConstantTimeEq` for hygiene; cost is negligible and it removes a class of "did anyone think about this" review questions forever.

#### [L] `verify_attestation` does not check `attestation.timestamp` against wall clock (`attestation-verify/src/lib.rs:258-288`)

If the verifier passes `expected_nonce = Some(...)` we're protected against replay because the nonce binds the doc to one request. But if a caller ever passes `expected_nonce = None` (the donor side does this at `server.rs:680, 754` -- relying on the `replay_guard` for freshness), there is no upper bound on how old the doc can be. The `replay_guard` is bounded at 10k entries (`state.rs:55`) and reset on every enclave restart, so an attacker who can deliver a stale donor attestation between an enclave restart and the next genuine one could in principle replay it. *Fix:* either always require a fresh nonce (preferred) or also reject attestations whose `timestamp` is more than e.g. 5 minutes old (NSM doc carries it in milliseconds since epoch).

#### [I] Both the AWS root CA bytes and the COSE sig-structure construction are correct

PEM -> DER decode happens once with `OnceLock`, the COSE Sig_structure1 layout (RFC 8152 Sec 4.4 ordering: `"Signature1", protected, external_aad=h"", payload`) is right, and the P-384 raw-r||s vs DER signature path is the documented quirk and handled at `attestation-verify/src/lib.rs:360-372`.

---

### Cross-check validation & SPV

#### [H] Calldata extraction uses *fixed* offsets based on the 6-arg `fundsOut` shape, but the comment at `validation/evm_crosscheck.rs:107-109` describes a 4-arg `fundsOut`

The selector whitelist contains exactly one entry: `0x1ad880b2` = `fundsOut(address,address,uint256,uint256,string,string)`. The offset comment immediately above says *"fundsOut(address token, address recipient, uint256 amount, uint256 commission, ...)"* -- which is consistent with offsets 68 (amount) and 100 (commission). So the code is correct *for that selector*. The risk is the planned migration: the TODO mentions two new selectors (`0xe005bc3f` and `0x179bef59`) that will have **different argument layouts**, and the comment block above says "per-selector offset tables will land alongside." If those new selectors are added to `FUNDS_OUT_SELECTORS` without a per-selector offset table, the enclave will read garbage 32-byte words from offsets 68/100 and the amount cross-check becomes meaningless. *Fix:* lift the offsets into a per-selector struct *now*, before the second selector lands, so adding a new selector forces the contributor to provide an offset table. (This is a process fix rather than a code fix -- the current code does what it claims for the one selector it accepts.)

> **[RESOLVED] #44 (2026-05-26).** The second selector (`0x179bef59`, the 8-arg mint/burn shape) landed *with* per-selector dispatch rather than a shared offset table: the legacy amount@68 / commission@100 reads are now guarded behind `selector == FUNDS_OUT_SELECTOR_POOLS_LEGACY` (`evm_crosscheck.rs:141-172`), and the new selector reads `amount` from its own `MINTBURN_AMOUNT_OFFSET = 36` inside `validate_funds_out_burn` (`evm_crosscheck.rs:289`). So the "read garbage from 68/100 on a new selector" footgun is closed in the way this finding recommended. The selectors are named constants with layout documented in the doc-comments (`evm_crosscheck.rs:13-37`). (Note the listener-dev selector here is `0x179bef59`; `0xe005bc3f` was not added.)

#### [M] `extract_uint256_as_u64` silently rejects amounts > `u64::MAX` (`validation/evm_crosscheck.rs:149-168`)

A perfectly legitimate consignment with an RGB amount of `2^64` would be rejected as `"uint256 value exceeds u64 range"`. RGB protocol uses `u64` internally so this is unlikely in practice, but the wire types (`uint256` in calldata, `uint64` in `calldata_amount` / `rgb_amount` proto fields) are mismatched. *Fix:* document the assumption that bridge amounts always fit in `u64`, or move to `u128` in the proto so the validator is symmetric with the wire format.

#### [M] `validate_evm_request` `consignment_valid` is short-circuited when raw bytes are present (`validation/evm_crosscheck.rs:57-73`)

When `feature = "rgb-validation"` is on and `req.consignment` is non-empty, the Listener's boolean isn't checked at all -- the comment says "in-enclave validation already ran in handle_sign_evm." That's true *for the happy path*, but if `rgb_validator` was `None` at startup (`server.rs:343` warns and continues), then `validated_consignment` stays `None`, the crosscheck skips the boolean, **and** the `#[cfg(feature = "spv")]` block does require a validated consignment -- so the SPV-on build fails closed. The SPV-off + rgb-validation-on + validator-not-configured combination silently signs without RGB validation **and** without the boolean check. *Fix:* if `rgb_validator` is `None` *and* `req.consignment` is non-empty, fall through to the `consignment_valid` check rather than treating the consignment as validated. Or fail-closed on construction failure (the right answer): `panic!` at startup if RGB validation is requested but the validator can't be built.

> **[RESOLVED] #47 (2026-05-26).** The `consignment_valid` carve-out is gone. `validate_evm_request` now requires non-empty consignment bytes for any fundsOut selector regardless of the flag (`evm_crosscheck.rs:107-113`), and default builds (no `rgb-validation`) refuse fundsOut outright (`evm_crosscheck.rs:95-103`). The handler half is closed too: for either fundsOut selector, `handle_sign_evm` now hard-requires `validated_consignment.is_some()` and returns `CrossCheck` otherwise (`server.rs:390-404`) -- so the exact SPV-off + validator-`None` combination this finding described now fails closed. A regression test reproduces the reported `consignment_valid:true` + empty-bytes PoC (`evm_crosscheck.rs:492`). The flag is now non-load-bearing in both directions (tests at `:492`, `:510`).

#### [M] `assert_chain_not_stale`'s "future skew" branch returns `Ok(())` for *any* in-bounds future tip without also checking past-bound (`validation/spv_crosscheck.rs:151-161`)

If `tip_time > now_unix` by less than 2 h, the function returns `Ok(())` early -- never reaching the past-age branch. That's fine because the tip can't be both in the future *and* in the past, but it means the function is structurally asymmetric: testing that the future-only path correctly returns `Ok` doesn't tell you anything about whether the past-only path runs. Existing tests cover both, so this is a maintainability finding, not a correctness one. *Fix:* compute `delta = tip_time as i64 - now_unix as i64`, check both bounds against `|delta|`.

#### [M] SPV `MIN_CONFIRMATIONS = 6` is hardcoded for all networks (`validation/spv_crosscheck.rs:41`)

The comment justifies hardcoding (env-var would let a hostile operator set it to 0). Fine. But `6` is appropriate for *mainnet*; the UTEXO custom signet has 30-second blocks (`spv/checkpoint.rs:151`), where 6 confirmations is only 3 minutes -- likely too low if the threat is a Listener-driven freeze attack on signet. *Fix:* make the constant a function of `Network`: 6 for mainnet, e.g. 30 for the UTEXO 30-second signet (or whatever the operations team determines).

#### [M] `submit_headers` reorg-work computation can overestimate work after a reorg-vs-checkpoint corner case (`spv/chain.rs:256-269`)

The code computes `existing_work` over `self.headers[truncate_idx..]` and `new_work` over the staged batch, then requires strict inequality. This is correct for the standard case. Edge: if the listener pushes a batch that starts exactly at `checkpoint.height + 1` and `reorg_depth == self.headers.len()`, `truncate_idx == 0` and we compare against the full chain -- also correct. The subtle one: with `MAX_REORG_DEPTH = 100` and `RETARGET_INTERVAL = 2016`, a reorg can never cross a retarget boundary, so the work comparison is always against headers with identical `bits` and `Work` per header reduces to "more blocks wins" -- which is what the test asserts. There's no bug, but the *invariant* (no cross-retarget reorgs) is implicit. *Fix:* assert it explicitly in `submit_headers` so a future operator who bumps `MAX_REORG_DEPTH > 2016` is forced to think about retargeting.

#### [M] Mainnet, signet, and testnet3 checkpoints are **placeholders** (`spv/checkpoint.rs:46-74`)

`MAINNET_CHECKPOINT.is_real = false`, same for signet + testnet3. `Checkpoint::assert_real_in_release` panics on a release build with a placeholder -- good. Debug/test builds run with all-zero checkpoint hashes, which means the first batch's first header is required to chain to `prev_blockhash = 0x00...00`, i.e. only block 1 of any chain can be submitted as the first batch in dev. The README and the dev Dockerfile aren't strict about this. *Action:* this is a release blocker, already tracked in the code comments. Worth surfacing here so it doesn't get lost.

#### [L] `verify_one_proof` rejects `block_height > tip` via two paths (header lookup returns None, **or** `checked_sub` underflow) (`validation/spv_crosscheck.rs:211-229`)

Belt-and-braces. The header-lookup path always wins because `header_at(height > tip)` returns `None`. Not a bug -- but the test `rejects_block_height_beyond_tip` asserts on either error message, which is a brittle way to express "we don't care which guard fires." *Fix:* drop the `checked_sub` redundancy (we've already proven `block_height <= tip` via the lookup) and simplify the error.

#### [L] Esplora resolver errors are reported as `CrossCheck` (`validation/rgb.rs:204-230`)

Network errors talking to Esplora -- server down, vsock-proxy not running, TCP RST -- bubble up as `EnclaveError::CrossCheck("RGB consignment validation failed: ...")`. That is technically fail-closed (the request is rejected) but it conflates "your consignment is bad" with "infra is broken." External callers seeing a 503-style error will retry; ones seeing a "consignment invalid" error will give up. *Fix:* split into `Spv(...)` for infra errors (transient) and `CrossCheck(...)` for actually-invalid consignments (terminal).

#### [I] Cross-network replay is defended twice: rgbstd's `ValidationConfig.chain_net` *and* `assert_chain_net` at the SPV boundary

Belt-and-braces; the second check at `validation/spv_crosscheck.rs:185` exists explicitly so that "a future configuration change that loosens rgbstd validation ... can never accidentally let a wrong-network consignment reach the signing path." This is exactly the right paranoia.

---

### Cloning handshake

#### [M] `requester_attestation` does not include a *donor*-supplied nonce, only a requester-fresh one (`server.rs:614, 622`)

The requester generates its own nonce (`fresh_nonce()`), embeds it in the attestation doc, and ships pubkey+digest+attestation to the donor. The donor checks the doc against its **own** replay guard (`server.rs:688`). This works *per donor* -- each donor sees each nonce at most once, so a parent can't replay the same `GetCloneRequest` against the same donor twice. But the parent can fan one attestation out to *multiple* donors simultaneously (different EC2s in the cluster), since the requester doesn't know which donor it'll be matched against. That's harmless today because the seed is the same across all donors in a cluster, but it does mean "one attested clone request -> N sealings" is achievable. *Fix:* If you ever want a one-to-one matchmaking property, add a donor-identifying field (e.g. `cluster_public_key`) into the attestation's `user_data` alongside the digest.

#### [M] HKDF `info` binds donor+requester pubkeys, but ChaCha20-Poly1305 AAD is empty (`cloning.rs:142, 191-200`)

Each handshake derives a fresh per-key+nonce pair via X25519+HKDF, and the all-zero ChaCha20-Poly1305 nonce is then safe (key is single-use). The AEAD AAD is empty. Belt-and-braces: passing the same pubkey-pair (or a handshake-id, or a version tag) as AAD would catch any future code path that accidentally reused a derived key. Cost is zero. *Fix:* set AAD = `b"utexo-cloning-v1" || donor_pub || requester_pub`.

#### [M] Cloning secret is taken from `UTEXO_CLONING_SECRET` env var (`main.rs:37-43`)

Pre-shared operator secret. If it leaks, an attacker who gets a verified attestation from any genuine TEE in the cluster can issue valid clone requests (mint a new TEE, swap to it, ...). It is wrapped in `SecretBox` and not logged. *Fix*: as a defence in depth, hash the secret in PCR2 so a leaked secret combined with a substituted enclave image still fails the PCR check.

#### [L] `verify_cloning_digest` is constant-time (`cloning.rs:116-123`)

Good -- uses `subtle::ConstantTimeEq`. Worth noting that this and `attestation-verify`'s `verify_attestation` are the only two places where comparison time matters, and only one of them is constant-time. See the attestation finding above.

#### [L] `CloneSession` uses `StaticSecret` not `EphemeralSecret` (`cloning.rs:53`)

Justified in the doc-comment -- we need to hold the secret across two messages. `StaticSecret` with `zeroize` feature *does* zero on drop, so this is correct. The hazard: `StaticSecret` allows clone, and `decrypt_seed_from_peer` borrows `&self`, so the secret stays around until the `CloneSession` is dropped. The lifecycle is fine (`complete_cloning` consumes the `Phase::Cloning` variant atomically), but a future contributor who adds `#[derive(Clone)]` to `CloneSession` would silently break the "one secret per handshake" invariant. *Fix:* add a `// !Clone -- see commentary in cloning.rs` comment, or hide `CloneSession` behind a sealed trait.

#### [L] `cloning_secret` is `String` (UTF-8) (`cloning.rs:108`)

HMAC keys are bytes, but the API takes `&str`. Today this means the operator must pick a UTF-8 secret, no embedded NULs unless they smuggle them through quoting. *Fix:* take `&[u8]` so high-entropy random-bytes secrets work without base64 wrapping.

#### [I] PCR-equality check on cloning is enforced

Both `handle_get_clone` (`server.rs:678-680`) and `handle_set_clone` (`server.rs:752-754`) call `attestation::get_own_pcrs()` and verify the peer's PCRs match -- i.e., **only the same enclave image can clone**. This is the most important property for the cloning flow and it's correctly enforced.

---

### Transport, framing, server dispatch

#### [M] `framing::read_message` allocates `vec![0u8; len]` up to 4 MB before any decode (`framing.rs:25`)

An attacker who can dial the enclave can send a 4-byte header with `len = 0x3FFFFFFE` and force a 4 MB heap allocation per connection. The enclave runs single-threaded so this isn't an OOM amplification today, but it does mean each malicious connection costs ~4 MB of transient heap. *Fix:* read in chunks with a smaller working buffer and grow lazily, OR drop the cap to something tighter than 4 MB (the biggest legitimate message is probably the SubmitHeaders batch of ~500 x 80 bytes = 40 KB plus protobuf overhead -- even consignments fit comfortably in ~500 KB).

#### [M] `EnclaveError::error_code` collapses everything except `CrossCheck`/`Spv`/`NotReady` to code `1` (`error.rs:78-86`)

PSBT signing errors, key-not-initialised, attestation verify failures, certificate errors, identity mismatches, nonce replays, digest mismatches -- all `code = 1`. The Listener can't distinguish "I sent garbage" from "your seed is unset" from "my replay nonce was already used." That's defensive for *information disclosure* but bad for operability and for *triggering an alert* on serious states like PCR mismatch. *Fix:* keep the gRPC `Status` codes broad at the parent boundary, but assign distinct numeric codes to the security-relevant errors (PCR mismatch, identity mismatch, nonce replay) so the Listener can alarm on them.

#### [L] Error messages occasionally include adversary-controlled input (`spv_crosscheck.rs:91-95, 213-215, 226-228`)

`"merkle proof for txid {} does not match any consignment witness txid"` etc. embed hex-encoded attacker inputs in the error string. That string then flows to `tracing::warn!` and out via the gRPC status message. The bytes are well-bounded (32-byte hashes), so log-injection is not a concern, but values like `chain_net` in `assert_chain_net` come from rgbstd-parsed strings. *Fix:* sanity-bound any string interpolated into error messages (e.g., truncate to N chars). Today's risk is purely aesthetic but it's a hygiene rule worth observing in an enclave.

#### [L] `handle_connection` swallows errors with `tracing::error!` (`server.rs:45-49`)

A panic inside a handler would kill the entire enclave (because the accept loop is single-threaded). `panic = "abort"` is set in `Cargo.toml`, so a single bad request can take the enclave down. *Fix:* wrap `process_connection` in `std::panic::catch_unwind` so an isolated bug in a handler logs a warning instead of taking down all signing.

#### [L] `vsock_forwarder` exposes a TCP listener on `127.0.0.1:3443` (`vsock_forwarder.rs:18`)

Inside the enclave, "localhost" is only reachable from inside the enclave, so this is fine. But the forwarder happily forwards *any* TCP traffic on that port to the host's vsock-proxy, which then forwards to Esplora. There is no authentication, no port allowlist, no request inspection. If a future enclave component (e.g., the RGB validator getting a bug that lets it dial arbitrary URLs) wanted to exfiltrate data, this forwarder is a covert channel out. *Fix:* document that the forwarder is for trusted in-enclave use only, and ideally restrict the listening interface to a Unix socket so only the validator can dial it. (TCP-on-127.0.0.1 is the current choice because rgbstd's Esplora client takes a URL.)

#### [I] Bridge boundary checks are properly in place: parent binds to `127.0.0.1` (`config.rs:25`), 30 s timeout on enclave RPCs (`grpc_server.rs:11`), `set_read_timeout` on the dev TCP path (`grpc_server.rs:58`).

---

### State machine, lifecycle, replay

#### [M] `NonceReplayGuard` caps at 10 000 entries and **rejects** new entries once full (`state.rs:73-79`)

Comment justifies this as a DoS guard. But a hostile parent can -- over the lifetime of a long-running enclave -- fill the guard by relaying 10 000 attestations (each carrying a different nonce). Once full, *every* subsequent cloning operation fails. That's a DoS against cloning. The defence works against memory exhaustion but trades one DoS for another. *Fix:* either bound by time-window rather than count (drop entries older than e.g. 1 hour), or be explicit that enclave restart is the supported reset and document it.

#### [M] `enter_cloning` requires `Phase::Initial`, but `Phase::Cloning -> Phase::Cloning` is not supported (`state.rs:223-228`)

If the parent issues `InitiateCloning` twice, the second one fails with `AlreadyInitialized`. The error message is misleading (the state isn't *Active*, it's *Cloning*). A more user-friendly behaviour is "abort the in-flight handshake and start a new one." *Fix:* either allow `Cloning -> Cloning` (replacing the session, which is safe because nothing has been committed yet) or rename the error variant.

#### [L] `handle_initiate_cloning` enters the Cloning phase *after* generating an NSM attestation (`server.rs:611-622`)

If `attestation::get_attestation` returns Err (NSM transient failure), we've burned a fresh X25519 keypair and learned a nonce that the donor hasn't seen. Not a security issue -- the parent gets an error back and the state is still `Initial` -- but if NSM errors are intermittent, the parent might retry and end up holding multiple half-finished sessions in its head. *Fix:* nothing; the symmetric design (no state mutation on error) is the right one.

#### [I] `Phase::Initial -> Active`, `Cloning -> Active`, `Active -> Active rejected` all have explicit tests (`state.rs:368-449`). The state machine is well-covered.

---

### Build, deployment, attestation chain of custody

#### [M] `[patch.crates-io]` pins RGB deps to *branch* `master`, not a specific revision (`Cargo.toml:13-17`)

`Cargo.lock` does pin commits, so reproducible builds work *as long as no one runs `cargo update`*. But an unattended `cargo update -p rgb-consensus` would pull whatever is at `master` at that moment, change PCR0, and silently invalidate every external attestation. *Fix:* pin to a specific tag or commit in `Cargo.toml`, and add a `cargo deny` / CI check that fails on lock-file drift in those crates.

#### [M] `rgb-consignment` is fetched over SSH from a private repo (`enclave/Cargo.toml:59`)

Production builds need an SSH key in the build environment. The Dockerfile uses `--mount=type=ssh` correctly (no key bytes in image layers). But this means the bytes in PCR0 depend on a private repo that operators outside Anthropic-the-team cannot independently rebuild. External verifiers who want to independently re-derive the expected PCR0 cannot do so. *Action:* either publish the parser repo, or document explicitly that "PCR0 is a *team-attested* value, not an independently-derivable one." Today's setup is fine for an in-house operator but not for "anyone can verify."

#### [L] `Dockerfile.enclave` uses `FROM rust:1.89-slim AS builder` (`build/Dockerfile.enclave:13`)

Floating tag. A future `rust:1.89-slim` push (security update) will silently change PCR0. *Fix:* pin to a digest (`FROM rust:1.89-slim@sha256:...`).

#### [I] The `dev-mode` feature (which skips cross-checks entirely) is correctly partitioned at compile time (`server.rs:351, 416`)

If someone accidentally enables it in release, every cross-check disappears at once. *Fix:* `compile_error!` on `all(feature = "dev-mode", not(debug_assertions))` so it cannot ship.

---

### Architecture observations (no severity)

1. **Single source of truth for attestation verification** (the `attestation-verify` crate) is the right factoring. Both the donor side of the cloning handshake and the external `attest-verify` CLI hit the same code path. The mock-path is feature-gated and structurally separated.
2. **Authorisation = on-chain commitment, not coordinator hint fields.** Both PSBT signing paths reject anything that isn't anchored to `witness_utxo.script_pubkey` (P2WSH) or `output_key` (taproot). The adversarial test suite forces every reviewer to think about this property.
3. **Fail-closed on build skew** (the `#[cfg(not(feature = "spv"))] if !req.merkle_proofs.is_empty()` block at `server.rs:310`) is the right pattern. It should be the default for every optional security feature: if the Listener built with a check, the enclave must either run it or refuse.
4. **Cross-checks happen in `validation/`, signing happens in `signing/`, key handling in `keys.rs`, transport in `framing.rs` + `main.rs`.** Each module has one job. The handler in `server.rs` is the policy layer that wires them together, and reading the handlers tells you exactly what the security argument is.
5. **State machine + replay guard live in `state.rs`** with a mutex around `Phase`. Concurrency is currently irrelevant (single accept thread) but the locking is correct *if* a future change adds parallelism. The mutex-based design is forward-compatible.
6. **The Listener is treated as untrusted throughout.** No code path says "if `consignment_valid == true`, skip RGB validation." That's the right contract.
7. **What's not in the codebase but probably should be:** a written attacker model file (`docs/threat-model.md`), a list of "if these compile-time features are on/off, what does the security boundary look like," and a CI job that builds every legal feature combination and runs all the tests. The README has good fragments of this; consolidating it would make external audits easier.
8. **The `MultisigProxy` EIP-712 domain name + version is a glaring TODO.** This is the one place where the bridge's signature validity depends on string equality with a Solidity contract you don't yet have a fixture for. Fix it before mainnet.

### Top-line prioritisation

If I had to fix three things before mainnet, in order:

1. ~~**Lift the calldata offsets into a per-selector table** before any second selector is added to `FUNDS_OUT_SELECTORS` (`validation/evm_crosscheck.rs:25`).~~ **DONE in #44** -- the mint/burn selector landed with per-selector dispatch (see banner above).
2. **Pin the EIP-712 domain to the actual deployed contract** with a contract-derived fixture test (`signing/evm.rs:3`). **Still open** -- `build_evm_domain` (`server.rs:552`) hardcodes `"Tricorn"`/`"1"`; #43 pinned chainId + verifyingContract but not name/version. *This is now the top pre-mainnet signing item.*
3. **Replace placeholder mainnet/signet checkpoints and pin the RGB-deps revision** so PCR0 becomes stable and externally re-derivable (`spv/checkpoint.rs:46`, `Cargo.toml:13`). **Unchanged** by the recent commits.

New since the original list, also pre-mainnet (from `docs/spec-conformance.md`): **bind the RGB `OpId` end-to-end** and **bind the EVM recipient to the validated consignment** -- after #44/#47/#43 closed the amount + chain/contract gaps, recipient and `OpId` are the remaining host-supplied semantic fields.

Everything else is hardening or operability -- the core signing-authorisation invariants are enforced and adversarially tested, and as of #44/#47 the unlock amount is bound to the validated consignment rather than to a host-supplied field.
