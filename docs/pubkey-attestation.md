# Verify an attested signing key

Attestation binds a public-key bundle to measured enclave code and its declared
security policy. The verifier must trust AWS Nitro and approve the expected
PCR0, PCR1, and PCR2 measurements.

## Trust statement

Successful verification shows that measured code answered the verifier's nonce
with this key bundle and policy. The measured code controls how keys are
created, recovered, or cloned. The attestation document alone does not prove
where a private key was first created.

The policy covers selected settings. These include signer role, bridge pins,
plain-BTC permission, gas limits, data sources, and mint KMS configuration.
The enclave resolves the policy once, at `SetEndpoints`. The verifier compares
its expected policy with the authenticated response.

### What attestation does NOT prove

Real verification proves only that **approved, measured code (PCR0/1/2 = X/Y/Z)
answered a fresh-nonce request with these public bytes**. It does
**not** establish any of the following, and consumers MUST NOT rely on them:

- **Key origin.** The document does not prove where or when the private key
  was created. The code can attest a generated, recovered, or cloned key.
- **Exclusive custody.** The same seed can exist in several enclaves. Burn
  replicas can use peer cloning. Mint replicas can recover the same KMS seed.
- **No previous copy.** Attestation cannot prove that no party previously held
  or copied the private key.

Trust requires both approved measurements and a fresh-nonce response.
Review the measured code to establish its key-custody rules. See the
[key management specification](tee-spec.md#5-key-management).

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

The NSM attestation document carries three caller-supplied fields. The enclave
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

Concatenate all fields of `PublicKeysResponse` in proto field order.
Prefix each field with its length as a big-endian u32. Encode strings as UTF-8.
`chain_id` is encoded as 8-byte big-endian (length prefix is the constant 8).

```
canonical_bundle =
    u32_be(len(evm_address))                 || evm_address
    u32_be(len(btc_compressed_pub))          || btc_compressed_pub
    u32_be(len(btc_xpub))                    || btc_xpub_utf8
    u32_be(len(master_fingerprint))          || master_fingerprint
    u32_be(len(account_xpub_vanilla))        || account_xpub_vanilla_utf8
    u32_be(len(account_xpub_colored))        || account_xpub_colored_utf8
    u32_be(len(evm_uncompressed_pub))        || evm_uncompressed_pub
    u32_be(8)                                || chain_id_be8
    u32_be(len(bridge_contract))             || bridge_contract       // 20 bytes (zeros = unset)
    u32_be(len(rgb_asset_id))                || rgb_asset_id_utf8
    u32_be(len(evm_gas_tx_uncompressed_pub)) || evm_gas_tx_uncompressed_pub   // 64 bytes
    u32_be(len(evm_gas_tx_address))          || evm_gas_tx_address            // 20 bytes
    u32_be(len(ccd_ed25519_pub))             || ccd_ed25519_pub               // 32 bytes
```

Thirteen fields. `chain_id`, `bridge_contract` and `rgb_asset_id` are bridge
config pinned at enclave boot from env (`EVM_CHAIN_ID`,
`EVM_PROXY_CONTRACT_ADDRESS`, `RGB_ASSET_ID`). They commit the enclave to a
specific chain / contract / asset triple — a misconfigured or
maliciously-redirected enclave is observable through this commitment. (The
attestation-bundle/proto field keeps the legacy name `bridge_contract`; its
value is the MultisigProxy from `EVM_PROXY_CONTRACT_ADDRESS`.)
Production deployments MUST set all three; the commitment for a dev /
mock build with no env is `chain_id=0`, `bridge_contract=20 zero bytes`,
`rgb_asset_id=""`. The gas-tx key and the Concordium key are derived in every
build, so the bundle has the same shape regardless of features.

The CLI reconstructs policy using the chain/contract/asset pins from the
response. These values are always authenticated (they are inside the signed
commitment); to also compare them against the operator's intended deployment,
pass `--expect-chain-id`, `--expect-bridge-contract` and/or
`--expect-rgb-asset-id`. When set, verification fails unless the enclave attests
exactly those pins, so onboarding can reject a valid attestation of the *wrong*
chain, contract or RGB asset. When omitted, the pins are authenticated but not
compared (legacy behaviour) — the caller must then compare them out of band.

The verifier MUST use the same field set, the same order, and the same
length-prefix encoding. The reference encoder is `canonical_pubkey_bundle`
in [`enclave/src/server/keys.rs`](../enclave/src/server/keys.rs) and the reference
decoder/checker is `canonical_bundle` in
[`parent/src/attest_verify.rs`](../parent/src/attest_verify.rs).

### Security policy commitment

The canonical bundle above is followed by the enclave's resolved security
policy, and `user_data = sha256(canonical_bundle || policy_commitment)`. The
policy is the single source of truth for the enclave's posture - resolved once
at launch (`SetEndpoints`) in [`enclave/src/policy.rs`](../enclave/src/policy.rs) and serialized by
[`attestation-verify/src/policy.rs`](../attestation-verify/src/policy.rs), which
both the enclave and every verifier share so the bytes are identical.

```
policy_commitment =
    u8(POLICY_COMMITMENT_V9 = 9)                    // version tag
    // Production (release, fully-pinned bridge signer):
    u8(0x01)                                        // production discriminant
    u8(allow_vanilla_psbt)                          // plain-BTC path enabled?
    u8(signer_role)                                 // 0 combined | 1 mint | 2 burn (from build features)
    u8(attestation_mode)                            // 1 = real NSM (0 = mock)
    u8(evm_source)                                  // 0 disabled | 1 plaintext rpc (dev) | 2 retired | 3 pinned TLS rpc
    u8(btc_source)                                  // 1 = SPV-verified
    chain_id_be8 || bridge_contract(20)
    u32_be(len(rgb_asset_id)) || rgb_asset_id_utf8
    funds_in_contract(20)                           // authorized event emitter
    u32_be(len(electrum_host)) || electrum_host     // Electrum host set at launch
    u8(evm_rpc_tls_present)                         // 0 absent; 1 followed by:
      u32_be(len(host)) || host || ca_sha256(32)    //   EVM RPC host, SHA-256 of the CA DER, set at launch
    // Gas-tx (SignRawDigest) rule:
    gas_tx_allowed_to(20)                           // all-zero = gas path unpinned
    gas_tx_max_gas_limit_be8                        // gasLimit ceiling (0 = unset)
    gas_tx_max_fee_per_gas_be16                     // per-gas fee ceiling, wei (0 = unset)
    gas_tx_max_value_wei_be16                       // native-value ceiling, wei (0 = unset)
    u32_be(len(selectors)) || selector(4)...        // sorted + deduped 4-byte selectors
    token_contract(20)                              // released ERC-20 (burnId preimage input), V5
    u8(kms_present)                                 // 0 absent; 1 followed by (set at launch, V7):
      u32_be(len(key_arn)) || key_arn || u32_be(len(region)) || region
      || u32_be(len(seed_id)) || seed_id
      || u8(address_present) [|| expected_evm_address(20)]
    // Development (debug/test/dev-feature/non-bridge/unpinned build):
    u8(0x00)                                        // development discriminant
```

V9 removes V8's confirmation-count field and binds a fixed deposit rule: every
EVM `FundsIn` receipt must be at or below the RPC's `safe` head, with its block
hash matching the canonical block at that height. Safe-chain membership has no
configuration switch or fallback to a confirmation count. The pinned
RPC remains trusted for these responses; this is not an EVM consensus proof.

The version change makes V8 depth-only commitments incompatible with V9, even
when all configurable values match. Verifiers reject V8 policy bytes, and clone
peers reject the different policy commitment. Deploy V9 enclave images and
verifiers together with updated approved EIF measurements.

The tuple omits the Bitcoin network, concrete sats budgets, the Electrum/Esplora
URL scheme and port, and the EVM RPC TLS port. The scheme needs no field: a
release image accepts only `ssl://` or `https://` for the Electrum/Esplora
URL, so PCR0 covers it. Only a dev build (and thus a development policy)
accepts `tcp://` or `http://`. Matching policies do not prove specific
endpoint ports.

Image-baked values remain measured in the EIF. The endpoints are not in the
image; the operator sets them and the KMS values once at launch
(`SetEndpoints`). The policy commits only the fields listed above. Until
the set, `GetAttestedPublicKey` is refused. The response carries the policy bytes
that `user_data` commits (`attested_policy`), so a verifier can decode them.

A production enclave commits the full production tuple. A dev/mock enclave
commits only `[version, 0x00]`, without individual policy settings. The response
contains this encoding in `attested_policy`. The verifier authenticates and
decodes those bytes.
It then constructs the expected policy from its own settings and the authenticated
bridge pins. The policies must match. Do not use the response itself to decide
which policy is acceptable.

The gas-tx rule is the `SignRawDigest` allowlist: the pinned
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

## Where the expected PCRs come from

The attestation document contains signed PCR values. A verifier must obtain
its expected values from a trusted source outside that response.

PCR0 measures the image. PCR1 measures the kernel and bootstrap. PCR2 measures
the application. Rebuild the EIF to determine whether a change affects them.
A file checksum and a PCR measurement are different values.

This repository publishes measurements with EIF artifacts. Verify those
artifacts before you use their PCRs. A trusted configuration or registry can
also distribute approved measurements. Its security depends on how updates
are authorized, not on where the values are stored.

## Verification recipe (manual)

Given `(public_keys_bundle, attestation_doc, nonce_sent, expected_pcrs)`:

1. Parse `attestation_doc` as `COSE_Sign1` (CBOR array of length 4).
   Require ES384 (`alg = -35`) in the protected header.
2. Parse the inner CBOR payload as `AttestationDocument`.
3. Verify the certificate chain in `cabundle`:
    - `cabundle[0]` must equal the AWS Nitro root CA bytewise (DER).
    - For each `i`, `cabundle[i]` must sign `cabundle[i+1]` (DER ECDSA).
    - `cabundle[last]` must sign `signing_cert` (the cert in the doc).
    - Check certificate validity against the local clock, with the implementation
      tolerance of 60 seconds.
    - Require CA `BasicConstraints` on each issuer. Check path-length limits.
    - If an issuer has `KeyUsage`, require `keyCertSign`.
    - If the signing certificate has `KeyUsage`, require `digitalSignature`.
4. Verify the COSE signature: P-384 ECDSA over
   `Sig_structure1 = ["Signature1", protected, h"", payload]`. Per RFC 8152
   §8.1 the COSE signature is raw `r||s` (96 bytes for P-384), not DER.
5. Reject all-zero PCR0/1/2. Compare each PCR with its expected value, byte for byte.
   The unsafe `allow-debug-pcrs` feature disables only the all-zero rejection.
6. Nonce check: `doc.nonce == nonce_sent`.
7. Pubkey check: `doc.public_key == public_keys_bundle.evm_uncompressed_pub`.
8. Commitment check: confirm
   `doc.user_data == sha256(canonical_bundle(public_keys_bundle) || attested_policy)`,
   decode `attested_policy`, and confirm it equals the expected policy (from
   the expected posture + the wire pins).

The verifier returns the document timestamp but does not enforce a maximum
document age. Freshness depends on a new unpredictable nonce and the caller's
request timing. Do not reuse nonces.

If all eight checks pass, the bridge's EVM address (`keccak256(evm_uncompressed_pub)[12..]`)
is bound to the running TEE measurement *and* the enclave's attested posture
equals the expected production policy.

## Verification recipe (with `attest-verify`)

The `attest-verify` CLI in this repo runs the full recipe. Configure the client
CA/certificate/key environment from [Parent mTLS](parent-mtls.md) first; an
`observer` certificate is sufficient for verification.
To check a published bundle offline (`--from-file`), see
[Verify a burn signer](verify-a-signer.md).

```bash
# Production verification (against a real Nitro enclave). By default it expects a
# production policy with plain-BTC signing DISABLED and the pinned-TLS EVM data
# source (`--expect-evm-source tls`, what the shipped image uses), which needs the
# Electrum host, the EVM RPC host and the CA the operator set at launch. Compute
# the CA hash from the same DER the operator set:
#   openssl x509 -in ca.pem -outform der | openssl dgst -sha256 -hex
attest-verify \
    --endpoint https://parent.example:50051 \
    --pcr0 <96-hex-chars> \
    --pcr1 <96-hex-chars> \
    --pcr2 <96-hex-chars> \
    --expect-signer-role burn \
    --expect-funds-in-contract 0x6711f1a319B37847fa0234181C34D883774c4951 \
    --expect-token-contract 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9 \
    --expect-electrum-host <electrum host> \
    --expect-evm-rpc-host <rpc host> \
    --expect-evm-rpc-ca-sha256 <64-hex-chars>

# --expect-signer-role is required: `mint` for the mint signer image
# (Dockerfile.enclave.mint), `burn` for the burn signer
# (Dockerfile.enclave.burn), `combined` for a swap image. A burn signer that
# attests `mint` fails verification. A role attests the other role's path as
# off whatever its env says: a burn signer never attests plain-BTC signing
# (omit --expect-vanilla-psbt), a mint signer never attests a gas rule (omit
# the --expect-gas-* flags). A mint signer also needs --expect-kms-key-arn,
# --expect-kms-region and --expect-kms-seed-id, and --expect-kms-evm-address
# when the operator set one.

# Gas signing: also supply the image's exact expected rule when configured:
# --expect-gas-tx-to <hex20> --expect-gas-max-gas-limit <units>
# --expect-gas-max-fee-per-gas <wei> --expect-gas-max-value-wei <wei>
# --expect-gas-selectors <comma-separated-hex4>
# Omitted flags expect an unpinned gas rule, not values discovered from the enclave.

# Deployment pins: compare the attested chain/contract/asset against the
# operator's intended deployment (otherwise they are authenticated but not
# compared). Verification fails on any mismatch:
# --expect-chain-id <u64> --expect-bridge-contract <hex20> \
# --expect-rgb-asset-id <asset>   # empty string pins "no RGB asset"

# Expect the plain-BTC path enabled:
attest-verify --endpoint https://parent.example:50051 \
    --pcr0 <..> --pcr1 <..> --pcr2 <..> --expect-signer-role mint \
    --expect-funds-in-contract <hex20> --expect-token-contract <hex20> \
    --expect-electrum-host <electrum host> \
    --expect-kms-key-arn <arn> --expect-kms-region <region> --expect-kms-seed-id <id> \
    --expect-evm-rpc-host <rpc host> --expect-evm-rpc-ca-sha256 <64-hex-chars> \
    --expect-vanilla-psbt

# Dev / CI verification (against an enclave built with --features mock-attestation).
# --mock implies the expected policy is Development.
# For this loopback plaintext example, remove PARENT_TLS_* and explicitly
# enable GRPC_ALLOW_INSECURE_LOOPBACK=true on the loopback-bound Parent.
attest-verify --endpoint http://127.0.0.1:50051 --mock
```

Exit codes:

| Code | Meaning                                                         |
|------|-----------------------------------------------------------------|
| 0    | All eight checks passed                                         |
| 1    | Verification failed, or the endpoint could not be reached (stderr explains why) |
| 2    | Command-line usage error                                        |

## Launch check at deploy

Before keys exist, `GetAttestedPublicKey` returns a policy-only answer:
`public_keys` is empty, the document has no `public_key`, and `user_data` is
`sha256("utexo/attested-policy/v1\0" || policy_bytes)`. The parent gRPC
`AttestedPublicKey` still refuses an answer without keys.

`deploy/deploy-host.sh` runs `utexo-bridge-parent-cli verify-launch` on each
enclave after `set-endpoints`. It verifies the document for a fresh nonce
against `PCR.json`, and compares every attested policy field with the deploy
inputs: the image role, `IMAGE-ENV.json` (the env of the measured image, from
the build) and the `set-endpoints` values. On a mismatch it names the field,
the expected value and the attested value. The enclave is then terminated,
all enclaves stop, and the deploy exits 1 before a parent starts.

`ENCLAVE_DEBUG_MODE=1` skips this check, because the PCRs are zero.

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
- **Posture downgrade** — `user_data` also commits to the resolved
  security policy (signing modes, pins, attestation mode, data sources). An
  enclave that shipped with a weaker posture than expected — plain-BTC signing
  enabled, a different EVM source, or a dev build — fails
  the commitment match against the verifier's expected policy.
- **Fork to a different enclave image** — PCR mismatch on verify.
- **Unapproved image** — verification rejects measurements outside the expected
  PCR set. An old or vulnerable image still passes if its PCRs remain approved.

NOT defended (out of scope for attestation):

- AWS hardware key compromise (same trust assumption as TLS roots).
- Bugs in the enclave code _after_ measurement (PCRs only attest the
  binary; runtime correctness is a separate problem solved by code review,
  fuzzing, audits).
- **Key origin / exclusivity.** The document does not prove where the private
  key was generated, that it lives in only one enclave, or that no cloned or
  imported copy exists — seed cloning is an explicit feature, so the same key
  can run in multiple same-measurement enclaves. Constraints on how keys are
  generated, sealed and cloned come from reviewing the PCR-pinned code, not from
  the attestation document itself. See *What attestation does NOT prove* above.

## Code references

- Enclave-side handler: [`enclave/src/server/keys.rs`](../enclave/src/server/keys.rs)
  (`handle_get_attested_public_key`).
- Parent gRPC handler: [`parent/src/grpc_server.rs`](../parent/src/grpc_server.rs)
  (`attested_public_key`).
- Verifier crate: [`attestation-verify/src/lib.rs`](../attestation-verify/src/lib.rs).
- Verifier library (`verify_attested_pubkey`, `ExpectedPolicy`): [`parent/src/attest_verify.rs`](../parent/src/attest_verify.rs).
- CLI binary: [`parent/src/bin/attest_verify.rs`](../parent/src/bin/attest_verify.rs).
- Security policy: resolved in [`enclave/src/policy.rs`](../enclave/src/policy.rs);
  shared canonical encoding in [`attestation-verify/src/policy.rs`](../attestation-verify/src/policy.rs).
- Wire definitions:
  - Enclave wire: [`enclave-proto/proto/enclave.proto`](../enclave-proto/proto/enclave.proto)
    (`GetAttestedPublicKeyRequest`/`Response`).
  - Parent gRPC: `proto/enclave/parent.proto` in the upstream
    `federated-signer-proto` repo (`ParentService.AttestedPublicKey`).
- Tests:
  - Enclave handler: [`enclave/tests/test_attested_pubkey.rs`](../enclave/tests/test_attested_pubkey.rs).
  - End-to-end gRPC: [`parent/tests/test_grpc_bridge.rs`](../parent/tests/test_grpc_bridge.rs)
    (`grpc_attested_public_key_*`).
