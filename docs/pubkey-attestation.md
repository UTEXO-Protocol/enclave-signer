# Attested Public Key — Verifying the Bridge Signing Pubkey Belongs to the TEE

External parties (bridge contract operator, auditors, downstream services) can
prove that the EVM address signing bridge transactions was produced by code
running inside an AWS Nitro Enclave with a specific measurement (PCR0/1/2),
without trusting the parent host process.

## Trust statement

After successful verification, the verifier knows:

> "AWS Nitro hardware (which I trust like a TLS root CA) certifies that, at
> time T (within nonce-freshness), an enclave running code with PCR0=X,
> PCR1=Y, PCR2=Z produced public key K, and the full key bundle B **plus the
> enclave's resolved security policy P** commit to user_data."

The security policy `P` (audit C-01) is the enclave's single, explicit posture —
signing modes, the chain/contract/asset pins, the attestation mode, and the
allowed data sources — resolved once at boot. Committing it into `user_data`
lets a verifier check the whole posture as one attested value instead of
inferring it from build flags or configuration guesses.

The chain of trust is:

```
AWS Nitro Root CA  (public, hardcoded)
       │ signs
AWS region intermediate(s)
       │ signs
This EC2 instance's NSM signing cert
       │ signs (P-384 ECDSA, COSE_Sign1)
Attestation document { pcrs, public_key, user_data, nonce, timestamp, ... }
```

## Protocol

```
verifier                                 parent gRPC                      enclave (Nitro)
   │                                          │                                 │
   │ 1. nonce ← rand(32)                      │                                 │
   │ 2. AttestedPublicKey(nonce) ────────────▶│                                 │
   │                                          │ 3. GetAttestedPublicKey(nonce) ▶│
   │                                          │                                 │ 4. NSM produces COSE_Sign1 doc
   │                                          │                                 │    binding {nonce,
   │                                          │                                 │            public_key=evm_uncompressed_pub,
   │                                          │                                 │            user_data=sha256(bundle || policy)}
   │                                          │                                 │    to PCR0/1/2
   │                                          │ ◀── (public_keys, doc) ─────────│
   │ ◀── AttestedPublicKeyResponse ───────────│                                 │
   │                                                                            │
   │ 5. Verify chain → AWS root, COSE sig, validity, PCRs, nonce equal,
   │    public_key == evm_uncompressed_pub,
   │    user_data == sha256(bundle || expected_policy).                         │
```

## Bindings

The NSM attestation document carries two caller-controlled fields. The enclave
populates them as:

| NSM field    | Bound value                                                                                 |
|--------------|---------------------------------------------------------------------------------------------|
| `public_key` | `evm_uncompressed_pub` — the bridge's primary signing key (64 bytes, X\|\|Y)              |
| `user_data`  | `sha256(canonical_bundle \|\| policy_commitment)` — 32-byte commitment over the key bundle *and* the resolved security policy |
| `nonce`      | the 32-byte nonce supplied by the verifier                                                 |

A lightweight verifier can stop at `public_key` (e.g. an EVM contract that
only cares about the signing address). A thorough verifier rebuilds the
canonical bundle **and the expected security policy** and checks `user_data` to
confirm the BTC keys, xpubs, and fingerprint were not swapped by the parent host
process *and* that the enclave's posture matches what was expected.

### Canonical bundle encoding

Length-prefixed (u32 big-endian) concatenation of every field of
`PublicKeysResponse`, in proto field order. Strings encoded as UTF-8 bytes.
`chain_id` is encoded as 8-byte big-endian (length prefix is the constant 8).

```
canonical_bundle =
    u32_be(len(evm_address))           || evm_address
    u32_be(len(btc_compressed_pub))    || btc_compressed_pub
    u32_be(len(btc_xpub))              || btc_xpub_utf8
    u32_be(len(master_fingerprint))    || master_fingerprint
    u32_be(len(account_xpub_vanilla))  || account_xpub_vanilla_utf8
    u32_be(len(account_xpub_colored))  || account_xpub_colored_utf8
    u32_be(len(evm_uncompressed_pub))  || evm_uncompressed_pub
    u32_be(8)                          || chain_id_be8
    u32_be(len(bridge_contract))       || bridge_contract       // 20 bytes (zeros = unset)
    u32_be(len(rgb_asset_id))          || rgb_asset_id_utf8
```

The last three fields are bridge config pinned at enclave boot from env
(`EVM_CHAIN_ID`, `EVM_PROXY_CONTRACT_ADDRESS`, `RGB_ASSET_ID`). They commit the
enclave to a specific chain / contract / asset triple — a misconfigured or
maliciously-redirected enclave is observable through this commitment. (The
attestation-bundle/proto field keeps the legacy name `bridge_contract`; its
value is the MultisigProxy from `EVM_PROXY_CONTRACT_ADDRESS`.)
Production deployments MUST set all three; the commitment for a dev /
mock build with no env is `chain_id=0`, `bridge_contract=20 zero bytes`,
`rgb_asset_id=""`.

The verifier MUST use the same field set, the same order, and the same
length-prefix encoding. The reference encoder is `canonical_pubkey_bundle`
in [`enclave/src/server.rs`](../enclave/src/server.rs) and the reference
decoder/checker is `canonical_bundle` in
[`parent/src/attest_verify.rs`](../parent/src/attest_verify.rs).

### Security policy commitment (audit C-01)

The canonical bundle above is followed by the enclave's resolved security
policy, and `user_data = sha256(canonical_bundle || policy_commitment)`. The
policy is the single source of truth for the enclave's posture — resolved once
at boot in [`enclave/src/policy.rs`](../enclave/src/policy.rs) and serialized by
[`attestation-verify/src/policy.rs`](../attestation-verify/src/policy.rs), which
both the enclave and every verifier share so the bytes are identical.

```
policy_commitment =
    u8(POLICY_COMMITMENT_V2 = 2)                    // version tag
    // Production (release, fully-pinned bridge signer):
    u8(0x01)                                        // production discriminant
    u8(allow_vanilla_psbt)                          // plain-BTC path enabled?
    u8(attestation_mode)                            // 1 = real NSM (0 = mock)
    u8(evm_source)                                  // 0 disabled | 1 raw-rpc | 2 helios
    u8(btc_source)                                  // 1 = SPV-verified
    chain_id_be8 || bridge_contract(20)
    u32_be(len(rgb_asset_id)) || rgb_asset_id_utf8
    // Helios trust root (audit M-06):
    u8(0x00) | u8(0x01) || evm_checkpoint(32)       // pinned beacon block root
    // Gas-tx (SignRawDigest) rule (audit C-02):
    gas_tx_allowed_to(20)                           // all-zero = gas path unpinned
    gas_tx_max_gas_limit_be8                        // gasLimit ceiling (0 = unset)
    gas_tx_max_fee_per_gas_be16                     // per-gas fee ceiling, wei (0 = unset)
    gas_tx_max_value_wei_be16                       // native-value ceiling, wei (0 = unset)
    u32_be(len(selectors)) || selector(4)...        // sorted + deduped 4-byte selectors
    // Development (debug/test/dev-feature/non-bridge/unpinned build):
    u8(0x00)                                        // development discriminant
```

A production enclave commits the full production tuple; a dev/mock enclave
commits just `[version, 0x00]`. Because the posture flags (`allow_vanilla_psbt`,
`evm_source`, …) and the gas-tx rule are not on the wire, a verifier reconstructs
the **expected** policy and requires the commitment to match — so an enclave that
shipped with a downgraded posture (vanilla signing on, raw instead of
Helios-verified RPC, an unpinned or wrong gas-tx rule, a dev build) fails
verification rather than being silently trusted.

The gas-tx rule (audit C-02) is the `SignRawDigest` allowlist: the pinned
destination, the `gasLimit`/fee ceilings that bound fee-griefing, the
native-value ceiling that bounds the payable `lzFundsOutCall` carve-out, and the
4-byte calldata selectors the gas EOA may invoke. Committing it makes the
enclave's gas-signing policy externally verifiable instead of a self-protection
pin the operator has to trust; `attest-verify` declares the expected rule via
`--expect-gas-tx-to` / `--expect-gas-max-gas-limit` / `--expect-gas-max-fee-per-gas`
/ `--expect-gas-max-value-wei` / `--expect-gas-selectors`.

An unset `GAS_TX_MAX_VALUE_WEI` commits as `0`, which is exactly the posture it
enforces (no non-zero value is signable) — so "unpinned" is itself attested, the
same way an unset destination commits as all-zero. `None` and `Some(0)` therefore
produce identical bytes; one enforced rule cannot yield two attestations.

The Helios checkpoint (audit M-06) pins WHICH weak-subjectivity beacon block root
the enclave trust-rooted EVM verification on, so two enclaves with identical PCRs
but different checkpoints commit different `user_data`; `attest-verify` declares
it via `--expect-helios-checkpoint`, required with `--expect-evm-source helios`.

## Where the expected PCRs come from

PCRs are not self-attested: the verifier needs to know them out of band.
PCR0 = enclave image hash, PCR1 = kernel + boot, PCR2 = app. Changing one
byte of the enclave binary changes PCR0 deterministically.

Sourcing options, in increasing order of rigor:

1. **Release artifact / Git tag.** Print PCRs from `nitro-cli build-enclave`
   into the release notes. Operators paste into `--pcr0/1/2`.
2. **Config file** loaded by the verifier. Same trust as #1, fewer typos.
3. **On-chain registry.** Bridge contract stores accepted PCRs;
   governance/multisig updates them. Verifiers pull from chain. Most
   rigorous, hardest to upgrade.

This repo currently relies on (1).

## Verification recipe (manual)

Given `(public_keys_bundle, attestation_doc, nonce_sent, expected_pcrs)`:

1. Parse `attestation_doc` as `COSE_Sign1` (CBOR array of length 4).
2. Parse the inner CBOR payload as `AttestationDocument`.
3. Verify the certificate chain in `cabundle`:
    - `cabundle[0]` must equal the AWS Nitro root CA bytewise (DER).
    - For each `i`, `cabundle[i]` must sign `cabundle[i+1]` (DER ECDSA).
    - `cabundle[last]` must sign `signing_cert` (the cert in the doc).
    - Every cert must be inside its validity window.
4. Verify the COSE signature: P-384 ECDSA over
   `Sig_structure1 = ["Signature1", protected, h"", payload]`. Per RFC 8152
   §8.1 the COSE signature is raw `r||s` (96 bytes for P-384), not DER.
5. PCR check: `doc.pcrs[0/1/2]` must each equal `expected_pcrs.{pcr0,pcr1,pcr2}`
   bytewise.
6. Nonce check: `doc.nonce == nonce_sent`.
7. Pubkey check: `doc.public_key == public_keys_bundle.evm_uncompressed_pub`.
8. Commitment check: build the expected policy (from the expected posture +
   the wire pins) and confirm
   `doc.user_data == sha256(canonical_bundle(public_keys_bundle) || expected_policy)`.

If all eight checks pass, the bridge's EVM address (`keccak256(evm_uncompressed_pub)[12..]`)
is bound to the running TEE measurement *and* the enclave's attested posture
equals the expected production policy.

## Verification recipe (with `attest-verify`)

The `attest-verify` CLI in this repo runs the full recipe.

```bash
# Production verification (against a real Nitro enclave). By default it expects a
# production policy with plain-BTC signing DISABLED and the raw-RPC EVM data
# source (what the shipped image uses).
attest-verify \
    --endpoint http://parent.example:50051 \
    --pcr0 <96-hex-chars> \
    --pcr1 <96-hex-chars> \
    --pcr2 <96-hex-chars>

# Require the trustless Helios data source (fails if the enclave is only on raw
# RPC), and/or expect the plain-BTC path enabled:
attest-verify --endpoint http://parent.example:50051 \
    --pcr0 <..> --pcr1 <..> --pcr2 <..> \
    --expect-evm-source helios --expect-vanilla-psbt

# Dev / CI verification (against an enclave built with --features mock-attestation).
# --mock implies the expected policy is Development.
attest-verify --endpoint http://127.0.0.1:50051 --mock
```

Exit codes:

| Code | Meaning                                                         |
|------|-----------------------------------------------------------------|
| 0    | All eight checks passed                                         |
| 1    | Verification failed (stderr explains why)                       |
| 2    | Usage / IO / connection error                                   |

## Threat model

Trusted: AWS Nitro root CA private key (off-machine), the running enclave
image (PCR-pinned), the verifier's own machine.

NOT trusted: the parent host process, the network between parent and
verifier, any TLS-terminating proxy, any operator with shell on the EC2
instance. None of them can forge an attestation document because none
holds the AWS Nitro per-instance signing key.

Defended:
- **Replay** — the verifier-supplied nonce is signed into the doc and checked
  for equality on response. An old doc is rejected.
- **Pubkey swap by parent** — `public_key` is inside the signed payload.
- **BTC key / xpub swap** — `user_data` commits to the full bundle. A parent
  cannot change one field of `PublicKeysResponse` without breaking the
  commitment match.
- **Posture downgrade (audit C-01)** — `user_data` also commits to the resolved
  security policy (signing modes, pins, attestation mode, data sources). An
  enclave that shipped with a weaker posture than expected — plain-BTC signing
  enabled, a raw instead of Helios-verified EVM source, or a dev build — fails
  the commitment match against the verifier's expected policy.
- **Fork to a different enclave image** — PCR mismatch on verify.
- **Stale code (vulnerable image)** — operator publishes accepted PCRs;
  outdated images won't match.

NOT defended (out of scope for attestation):
- AWS hardware key compromise (same trust assumption as TLS roots).
- Bugs in the enclave code _after_ measurement (PCRs only attest the
  binary; runtime correctness is a separate problem solved by code review,
  fuzzing, audits).

## Code references

- Enclave-side handler: [`enclave/src/server.rs`](../enclave/src/server.rs)
  (`handle_get_attested_public_key`).
- Parent gRPC handler: [`parent/src/grpc_server.rs`](../parent/src/grpc_server.rs)
  (`attested_public_key`).
- Verifier crate: [`attestation-verify/src/lib.rs`](../attestation-verify/src/lib.rs).
- Verifier library (`verify_attested_pubkey`, `ExpectedPolicy`): [`parent/src/attest_verify.rs`](../parent/src/attest_verify.rs).
- CLI binary: [`parent/src/bin/attest_verify.rs`](../parent/src/bin/attest_verify.rs).
- Security policy (audit C-01): resolved in [`enclave/src/policy.rs`](../enclave/src/policy.rs);
  shared canonical encoding in [`attestation-verify/src/policy.rs`](../attestation-verify/src/policy.rs).
- Wire definitions:
  - Enclave wire: [`proto/enclave.proto`](../proto/enclave.proto)
    (`GetAttestedPublicKeyRequest`/`Response`).
  - Parent gRPC: [`proto/parentadapter.proto`](../proto/parentadapter.proto)
    (`AttestedPublicKey` RPC).
- Tests:
  - Enclave handler: [`enclave/tests/test_attested_pubkey.rs`](../enclave/tests/test_attested_pubkey.rs).
  - End-to-end gRPC: [`parent/tests/test_grpc_bridge.rs`](../parent/tests/test_grpc_bridge.rs)
    (`grpc_attested_public_key_*`).
